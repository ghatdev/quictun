//! Split connection state for parallel crypto workers.
//!
//! [`SplitConnectionState`] separates TX state (shareable via `Arc`) from
//! RX state (single-owner). Crypto workers can encrypt in parallel using
//! `Arc<TxState>` without touching RX state.
//!
//! Created from [`LocalConnectionState::into_split()`].

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use bytes::BytesMut;
use quinn_proto::ConnectionId;
use quinn_proto::crypto::{HeaderKey, PacketKey};
use smallvec::SmallVec;
use tracing::warn;

use crate::bitmap::Bitmap;
use crate::local::generate_ack_ranges_from_bitmap;
use crate::{
    DecryptedInPlace, DecryptedPacket, EncryptResult, KEY_UPDATE_THRESHOLD, ParseError,
    decrypt_payload, decrypt_payload_in_place, encrypt_ack_packet, encrypt_packet, unprotect_header,
};

/// TX state shareable across crypto worker threads via `Arc`.
///
/// All methods take `&self` — no mutual exclusion needed on the fast path.
/// Key update swaps keys via `ArcSwap` (lock-free read).
pub struct TxState {
    pn_counter: AtomicU64,
    largest_acked: AtomicU64,
    tx_packet_key: ArcSwap<Box<dyn PacketKey>>,
    tx_header_key: Arc<Box<dyn HeaderKey>>,
    remote_cid: ConnectionId,
    tag_len: usize,
    key_phase: AtomicBool,
}

// SAFETY: PacketKey and HeaderKey are Send+Sync (confirmed in quinn-proto).
// All fields use atomic types or Arc for thread-safe access.
unsafe impl Send for TxState {}
unsafe impl Sync for TxState {}

impl TxState {
    /// Atomically assign the next packet number.
    #[inline]
    pub fn next_pn(&self) -> u64 {
        self.pn_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Atomically assign `count` sequential packet numbers.
    /// Returns the first PN in the range.
    #[inline]
    pub fn next_pn_batch(&self, count: u64) -> u64 {
        self.pn_counter.fetch_add(count, Ordering::Relaxed)
    }

    /// Current largest acknowledged PN (for PN encoding).
    #[inline]
    pub fn largest_acked(&self) -> u64 {
        self.largest_acked.load(Ordering::Relaxed)
    }

    /// Update largest_acked if the new value is larger.
    #[inline]
    pub fn update_largest_acked(&self, new_val: u64) {
        // fetch_max is available on AtomicU64.
        self.largest_acked.fetch_max(new_val, Ordering::Relaxed);
    }

    /// Current key phase bit.
    #[inline]
    pub fn key_phase(&self) -> bool {
        self.key_phase.load(Ordering::Relaxed)
    }

    /// Remote connection ID.
    #[inline]
    pub fn remote_cid(&self) -> &ConnectionId {
        &self.remote_cid
    }

    /// AEAD tag length.
    #[inline]
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// Load current TX packet key (lock-free).
    #[inline]
    pub fn load_packet_key(&self) -> arc_swap::Guard<Arc<Box<dyn PacketKey>>> {
        self.tx_packet_key.load()
    }

    /// Reference to the TX header key (never changes).
    #[inline]
    pub fn header_key(&self) -> &dyn HeaderKey {
        &**self.tx_header_key
    }

    /// Arc clone of the TX header key (for sharing with crypto workers).
    #[inline]
    pub fn header_key_arc(&self) -> Arc<Box<dyn HeaderKey>> {
        Arc::clone(&self.tx_header_key)
    }

    /// Encrypt a datagram payload using shared state. No `&mut self` needed.
    pub fn encrypt_datagram(
        &self,
        payload: &[u8],
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        let pn = self.next_pn();
        let key_guard = self.tx_packet_key.load();
        encrypt_packet(
            payload,
            &self.remote_cid,
            pn,
            self.largest_acked(),
            self.key_phase(),
            &***key_guard,
            &**self.tx_header_key,
            self.tag_len,
            buf,
        )
    }
}

/// RX state — single-owner, sequential processing only.
///
/// Handles replay detection, key phase negotiation, and ACK generation.
/// Only the I/O thread's sequential receiver should access this.
pub struct RxState {
    rx_packet_key: Arc<Box<dyn PacketKey>>,
    rx_header_key: Arc<Box<dyn HeaderKey>>,
    received: Bitmap,
    largest_rx_pn: u64,
    rx_since_last_ack: u32,
    ack_interval: u32,
    peer_key_phase: bool,
    pending_rx_key: Option<Box<dyn PacketKey>>,
    local_cid: ConnectionId,
    local_cid_len: usize,
}

impl RxState {
    /// Clone of the current RX packet key (for decrypt workers).
    pub fn packet_key(&self) -> Arc<Box<dyn PacketKey>> {
        Arc::clone(&self.rx_packet_key)
    }

    /// Clone of the RX header key (for decrypt workers).
    pub fn header_key(&self) -> Arc<Box<dyn HeaderKey>> {
        Arc::clone(&self.rx_header_key)
    }

    /// Current largest received PN (for PN decoding in workers).
    pub fn largest_rx_pn(&self) -> u64 {
        self.largest_rx_pn
    }

    /// Local CID length (for header parsing).
    pub fn local_cid_len(&self) -> usize {
        self.local_cid_len
    }

    /// Local CID.
    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Check if an ACK should be sent.
    pub fn needs_ack(&self) -> bool {
        self.rx_since_last_ack >= self.ack_interval
    }

    /// Generate ACK ranges from the received bitmap.
    pub fn generate_ack_ranges(&mut self) -> SmallVec<[Range<u64>; 8]> {
        let ranges = generate_ack_ranges_from_bitmap(&self.received, self.largest_rx_pn);
        self.rx_since_last_ack = 0;
        if let Some(first_range) = ranges.first() {
            let new_base = first_range.start.saturating_sub(256);
            if new_base > self.received.base() {
                self.received.advance_base(new_base);
            }
        }
        ranges
    }

    /// Decrypt a packet (full path: header unprotect, key phase, replay, AEAD, state update).
    ///
    /// Used when the I/O thread processes packets sequentially (single-thread mode
    /// or after a decrypt worker completes).
    pub fn decrypt_packet_with_buf(
        &mut self,
        packet: &mut [u8],
        tag_len: usize,
        scratch: &mut BytesMut,
        key_update: &KeyUpdateState,
        tx_state: &TxState,
    ) -> Result<DecryptedPacket, ParseError> {
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            tag_len,
            &**self.rx_header_key,
            self.largest_rx_pn,
        )?;

        if hdr.key_phase != self.peer_key_phase {
            self.peer_key_phase = hdr.key_phase;
            self.handle_key_update_rx(hdr.key_phase, key_update, tx_state);
        }

        if self.received.test(hdr.pn) {
            return Err(ParseError::DuplicatePacket);
        }

        let result = decrypt_payload(packet, &hdr, &**self.rx_packet_key, scratch)?;

        self.received.set(hdr.pn);
        if hdr.pn > self.largest_rx_pn {
            self.largest_rx_pn = hdr.pn;
        }
        self.rx_since_last_ack += 1;

        Ok(result)
    }

    /// Decrypt a packet in-place (zero-copy).
    pub fn decrypt_packet_in_place(
        &mut self,
        packet: &mut [u8],
        tag_len: usize,
        key_update: &KeyUpdateState,
        tx_state: &TxState,
    ) -> Result<DecryptedInPlace, ParseError> {
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            tag_len,
            &**self.rx_header_key,
            self.largest_rx_pn,
        )?;

        if hdr.key_phase != self.peer_key_phase {
            self.peer_key_phase = hdr.key_phase;
            self.handle_key_update_rx(hdr.key_phase, key_update, tx_state);
        }

        if self.received.test(hdr.pn) {
            return Err(ParseError::DuplicatePacket);
        }

        let result = decrypt_payload_in_place(packet, &hdr, &**self.rx_packet_key)?;

        self.received.set(hdr.pn);
        if hdr.pn > self.largest_rx_pn {
            self.largest_rx_pn = hdr.pn;
        }
        self.rx_since_last_ack += 1;

        Ok(result)
    }

    /// Sequential replay check + state update after a decrypt worker completes.
    ///
    /// The worker only did AEAD open. The I/O thread must still check replay
    /// and update RX state (bitmap, largest_rx_pn, rx_since_last_ack).
    ///
    /// Returns `true` if the packet is valid (not a duplicate).
    pub fn accept_decrypted_pn(&mut self, pn: u64) -> bool {
        if self.received.test(pn) {
            return false;
        }
        self.received.set(pn);
        if pn > self.largest_rx_pn {
            self.largest_rx_pn = pn;
        }
        self.rx_since_last_ack += 1;
        true
    }

    /// Check key phase on a decrypted packet header (after worker decrypted it).
    pub fn check_key_phase(
        &mut self,
        key_phase: bool,
        key_update: &KeyUpdateState,
        tx_state: &TxState,
    ) {
        if key_phase != self.peer_key_phase {
            self.peer_key_phase = key_phase;
            self.handle_key_update_rx(key_phase, key_update, tx_state);
        }
    }

    fn handle_key_update_rx(
        &mut self,
        new_phase: bool,
        key_update: &KeyUpdateState,
        tx_state: &TxState,
    ) {
        if let Some(new_rx) = self.pending_rx_key.take() {
            self.rx_packet_key = Arc::new(new_rx);
            tracing::debug!("key update: RX rotated (peer responded to our initiation)");
        } else {
            let mut next_keys = key_update
                .next_keys
                .lock()
                .expect("key update mutex poisoned");
            if let Some((new_rx, new_tx)) = next_keys.pop_front() {
                self.rx_packet_key = Arc::new(new_rx);
                tx_state.tx_packet_key.store(Arc::new(new_tx));
                tracing::debug!("key update: rotated to new keys (peer-initiated)");
            } else {
                key_update.key_exhausted.store(true, Ordering::Relaxed);
                warn!("key update: no pre-computed keys available, connection must be closed");
                return;
            }
        }
        tx_state.key_phase.store(new_phase, Ordering::Relaxed);
        key_update
            .packets_since_key_update
            .store(0, Ordering::Relaxed);
    }
}

/// Key update coordination state — shared between TX initiation and RX handling.
pub struct KeyUpdateState {
    next_keys: Mutex<VecDeque<(Box<dyn PacketKey>, Box<dyn PacketKey>)>>,
    packets_since_key_update: AtomicU64,
    key_exhausted: AtomicBool,
}

impl KeyUpdateState {
    /// Returns `true` if keys are exhausted and the connection must be closed.
    pub fn is_key_exhausted(&self) -> bool {
        self.key_exhausted.load(Ordering::Relaxed)
    }

    /// Check if key update should be initiated (called by I/O thread before PN assignment).
    ///
    /// If the threshold is reached, swaps TX key, stores pending RX key, and flips key phase.
    pub fn maybe_initiate_key_update(
        &self,
        count: u64,
        tx_state: &TxState,
        rx_state: &mut RxState,
    ) {
        let prev = self
            .packets_since_key_update
            .fetch_add(count, Ordering::Relaxed);
        if prev + count >= KEY_UPDATE_THRESHOLD && prev < KEY_UPDATE_THRESHOLD {
            self.initiate_key_update(tx_state, rx_state);
        }
    }

    fn initiate_key_update(&self, tx_state: &TxState, rx_state: &mut RxState) {
        let mut next_keys = self
            .next_keys
            .lock()
            .expect("key update mutex poisoned");
        if let Some((new_rx, new_tx)) = next_keys.pop_front() {
            rx_state.pending_rx_key = Some(new_rx);
            tx_state.tx_packet_key.store(Arc::new(new_tx));
            let old_phase = tx_state.key_phase.load(Ordering::Relaxed);
            tx_state.key_phase.store(!old_phase, Ordering::Relaxed);
            self.packets_since_key_update.store(0, Ordering::Relaxed);
            tracing::debug!("key update: TX rotated, awaiting peer response");
        } else {
            self.key_exhausted.store(true, Ordering::Relaxed);
            warn!("key update: no pre-computed keys available, connection must be closed");
        }
    }
}

/// Split connection state: `Arc<TxState>` (shareable) + `RxState` (exclusive).
///
/// Created via [`LocalConnectionState::into_split()`].
pub struct SplitConnectionState {
    pub tx: Arc<TxState>,
    pub rx: RxState,
    pub key_update: Arc<KeyUpdateState>,
}

impl SplitConnectionState {
    /// Encrypt a standalone ACK packet.
    pub fn encrypt_ack(&mut self, buf: &mut [u8]) -> Result<EncryptResult, ParseError> {
        let ack_ranges = self.rx.generate_ack_ranges();
        let pn = self.tx.next_pn();
        let key_guard = self.tx.tx_packet_key.load();
        encrypt_ack_packet(
            &ack_ranges,
            &self.tx.remote_cid,
            pn,
            self.tx.largest_acked(),
            self.tx.key_phase(),
            &***key_guard,
            &**self.tx.tx_header_key,
            self.tx.tag_len,
            buf,
        )
    }
}

// ── Conversion from LocalConnectionState ────────────────────────────────

use crate::local::LocalConnectionState;

impl LocalConnectionState {
    /// Split into shareable TX + exclusive RX state for the parallel crypto pipeline.
    ///
    /// Consumes `self`. The original `LocalConnectionState` cannot be used after this.
    pub fn into_split(self) -> SplitConnectionState {
        let LocalConnectionState {
            rx_packet_key,
            tx_packet_key,
            rx_header_key,
            tx_header_key,
            tag_len,
            next_keys,
            pending_rx_key,
            key_phase,
            peer_key_phase,
            packets_since_key_update,
            local_cid,
            remote_cid,
            local_cid_len,
            key_exhausted,
            pn_counter,
            largest_acked,
            largest_rx_pn,
            received,
            rx_since_last_ack: _,
            ack_interval,
        } = self;

        let tx = Arc::new(TxState {
            pn_counter: AtomicU64::new(pn_counter),
            largest_acked: AtomicU64::new(largest_acked),
            tx_packet_key: ArcSwap::from_pointee(tx_packet_key),
            tx_header_key: Arc::new(tx_header_key),
            remote_cid,
            tag_len,
            key_phase: AtomicBool::new(key_phase),
        });

        let rx = RxState {
            rx_packet_key: Arc::new(rx_packet_key),
            rx_header_key: Arc::new(rx_header_key),
            received,
            largest_rx_pn,
            rx_since_last_ack: 0,
            ack_interval,
            peer_key_phase,
            pending_rx_key,
            local_cid,
            local_cid_len,
        };

        let key_update = Arc::new(KeyUpdateState {
            next_keys: Mutex::new(next_keys),
            packets_since_key_update: AtomicU64::new(packets_since_key_update),
            key_exhausted: AtomicBool::new(key_exhausted),
        });

        SplitConnectionState {
            tx,
            rx,
            key_update,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalConnectionState;
    use quinn_proto::crypto;
    use std::collections::VecDeque;

    /// Helper: create a pair of LocalConnectionState (client + server).
    ///
    /// Uses quinn-proto's initial key derivation with a dummy CID.
    fn make_pair() -> (LocalConnectionState, LocalConnectionState) {
        // Derive initial keys using quinn-proto's QUIC Initial cipher.
        let suite = quinn_proto::crypto::rustls::initial_suite_from_provider(
            &std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .expect("initial suite");
        let dst_cid = ConnectionId::new(&[0xAA; 8]);

        // QUIC Initial keys: client's local = server's remote, and vice versa.
        let client_keys = suite.keys(&dst_cid, rustls::Side::Client, rustls::quic::Version::V1);
        let server_keys = suite.keys(&dst_cid, rustls::Side::Server, rustls::quic::Version::V1);

        // Wrap rustls keys into quinn-proto Keys (same wrapping as quinn-proto's initial_keys).
        let keys_client = crypto::Keys {
            header: crypto::KeyPair {
                local: Box::new(client_keys.local.header),
                remote: Box::new(client_keys.remote.header),
            },
            packet: crypto::KeyPair {
                local: Box::new(client_keys.local.packet),
                remote: Box::new(client_keys.remote.packet),
            },
        };
        let keys_server = crypto::Keys {
            header: crypto::KeyPair {
                local: Box::new(server_keys.local.header),
                remote: Box::new(server_keys.remote.header),
            },
            packet: crypto::KeyPair {
                local: Box::new(server_keys.local.packet),
                remote: Box::new(server_keys.remote.packet),
            },
        };

        let cid_client = ConnectionId::new(&[0x01; 8]);
        let cid_server = ConnectionId::new(&[0x02; 8]);

        let client = LocalConnectionState::new(
            keys_client,
            VecDeque::new(),
            cid_client.clone(),
            cid_server.clone(),
            false,
        );
        let server = LocalConnectionState::new(
            keys_server,
            VecDeque::new(),
            cid_server,
            cid_client,
            true,
        );
        (client, server)
    }

    #[test]
    fn split_encrypt_decrypt_roundtrip() {
        let (client, server) = make_pair();
        let split_client = client.into_split();
        let mut split_server = server.into_split();

        let payload = b"hello world";
        let mut buf = vec![0u8; 2048];

        // Encrypt via TxState (no &mut self).
        let result = split_client
            .tx
            .encrypt_datagram(payload, &mut buf)
            .expect("encrypt");

        // Decrypt via RxState (sequential).
        let mut scratch = BytesMut::with_capacity(2048);
        let decrypted = split_server
            .rx
            .decrypt_packet_with_buf(
                &mut buf[..result.len],
                split_server.tx.tag_len(),
                &mut scratch,
                &split_server.key_update,
                &split_server.tx,
            )
            .expect("decrypt");

        assert_eq!(decrypted.datagrams.len(), 1);
        assert_eq!(&decrypted.datagrams[0][..], payload);
    }

    #[test]
    fn split_concurrent_encrypt() {
        let (client, _server) = make_pair();
        let split = client.into_split();
        let tx = Arc::clone(&split.tx);

        // Spawn 4 threads, each encrypts 1000 packets.
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let tx = Arc::clone(&tx);
                std::thread::spawn(move || {
                    let mut pns = Vec::with_capacity(1000);
                    let mut buf = vec![0u8; 2048];
                    for _ in 0..1000 {
                        let result = tx
                            .encrypt_datagram(b"test", &mut buf)
                            .expect("encrypt");
                        pns.push(result.pn);
                    }
                    pns
                })
            })
            .collect();

        let mut all_pns: Vec<u64> = Vec::new();
        for handle in handles {
            all_pns.extend(handle.join().expect("thread join"));
        }

        // All 4000 PNs must be unique.
        all_pns.sort();
        all_pns.dedup();
        assert_eq!(all_pns.len(), 4000, "all PNs must be unique");
    }

    #[test]
    fn split_ack_roundtrip() {
        let (client, server) = make_pair();
        let mut split_client = client.into_split();
        let mut split_server = server.into_split();

        // Server encrypts some data so client has packets to ACK.
        let mut buf = vec![0u8; 2048];
        let mut scratch = BytesMut::with_capacity(2048);
        for _ in 0..10 {
            let result = split_server
                .tx
                .encrypt_datagram(b"data", &mut buf)
                .expect("encrypt");
            split_client
                .rx
                .decrypt_packet_with_buf(
                    &mut buf[..result.len],
                    split_client.tx.tag_len(),
                    &mut scratch,
                    &split_client.key_update,
                    &split_client.tx,
                )
                .expect("decrypt");
        }

        // Client sends standalone ACK.
        let result = split_client.encrypt_ack(&mut buf).expect("encrypt_ack");

        // Server decrypts ACK-only packet.
        let decrypted = split_server
            .rx
            .decrypt_packet_with_buf(
                &mut buf[..result.len],
                split_server.tx.tag_len(),
                &mut scratch,
                &split_server.key_update,
                &split_server.tx,
            )
            .expect("decrypt ack");

        assert!(decrypted.datagrams.is_empty(), "ACK-only: no datagrams");
        assert!(decrypted.ack.is_some(), "ACK frame should be present");
    }
}

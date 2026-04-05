//! Thread-safe connection state for parallel decrypt workers.
//!
//! [`SharedConnectionState`] wraps RX keys, replay protection, and key phase
//! in atomic/lock primitives so that `decrypt_in_place(&self)` can be called
//! from any thread — enabling N parallel decrypt workers.
//!
//! Created from [`LocalConnectionState::into_shared()`].

use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use quinn_proto::ConnectionId;
use quinn_proto::crypto::{HeaderKey, PacketKey};
use smallvec::SmallVec;
use tracing::warn;

use crate::bitmap::Bitmap;
use crate::local::generate_ack_ranges_from_bitmap;
use crate::split::{KeyUpdateState, TxState};
use crate::{
    DecryptedInPlace, ParseError, decrypt_payload_in_place, unprotect_header,
};

// ── AtomicReplayWindow ───────────────────────────────────────────────────

/// Thread-safe replay window with lock-free PN reads for header decode.
///
/// `largest_rx_pn` is mirrored as an atomic for lock-free reads by
/// `unprotect_header()`. The bitmap + canonical `largest_rx_pn` are
/// protected by a `parking_lot::Mutex` (~10-20ns uncontended).
pub struct AtomicReplayWindow {
    /// Lock-free read for PN decode (updated inside lock).
    largest_rx_pn: AtomicU64,
    /// Last PN at the time of the most recent ACK generation.
    last_acked_pn: AtomicU64,
    /// Protects bitmap + canonical largest_rx_pn.
    inner: Mutex<ReplayInner>,
}

struct ReplayInner {
    bitmap: Bitmap,
    largest_rx_pn: u64,
}

impl AtomicReplayWindow {
    fn new(largest_rx_pn: u64, bitmap: Bitmap) -> Self {
        Self {
            largest_rx_pn: AtomicU64::new(largest_rx_pn),
            last_acked_pn: AtomicU64::new(u64::MAX),
            inner: Mutex::new(ReplayInner {
                bitmap,
                largest_rx_pn,
            }),
        }
    }

    /// Lock-free read of the largest received PN (for header PN decode).
    #[inline]
    pub fn largest_rx_pn(&self) -> u64 {
        self.largest_rx_pn.load(Ordering::Acquire)
    }

    /// Test and accept a packet number. Returns `true` if not a duplicate.
    ///
    /// Acquires the mutex (~10-20ns), tests the bitmap, sets the bit,
    /// and updates `largest_rx_pn` if needed.
    pub fn test_and_accept(&self, pn: u64) -> bool {
        let mut inner = self.inner.lock();
        if inner.bitmap.test(pn) {
            return false;
        }
        inner.bitmap.set(pn);
        if pn > inner.largest_rx_pn {
            inner.largest_rx_pn = pn;
            self.largest_rx_pn.store(pn, Ordering::Release);
        }
        true
    }

    /// Check if an ACK should be sent (timer-driven).
    pub fn needs_ack(&self) -> bool {
        let last = self.last_acked_pn.load(Ordering::Relaxed);
        last == u64::MAX || self.largest_rx_pn.load(Ordering::Relaxed) > last
    }

    /// Generate ACK ranges from the bitmap. Called from the timer thread only.
    pub fn generate_ack_ranges(&self) -> SmallVec<[Range<u64>; 8]> {
        let mut inner = self.inner.lock();
        let largest = inner.largest_rx_pn;
        let ranges = generate_ack_ranges_from_bitmap(&inner.bitmap, largest);
        self.last_acked_pn.store(largest, Ordering::Relaxed);
        if let Some(first_range) = ranges.first() {
            let new_base = first_range.start.saturating_sub(256);
            if new_base > inner.bitmap.base() {
                inner.bitmap.advance_base(new_base);
            }
        }
        ranges
    }
}

// ── SharedConnectionState ────────────────────────────────────────────────

/// Fully thread-safe QUIC 1-RTT connection state.
///
/// `decrypt_in_place(&self)` can be called from any thread. Designed for
/// N parallel decrypt workers in the container pipeline.
pub struct SharedConnectionState {
    // RX keys (ArcSwap for lock-free read, rotated on key phase change).
    rx_packet_key: ArcSwap<Box<dyn PacketKey>>,
    rx_header_key: Arc<Box<dyn HeaderKey>>,

    // TX state (reused from split.rs — already thread-safe).
    pub tx: Arc<TxState>,

    // Replay protection.
    pub replay: AtomicReplayWindow,

    // Key phase (CAS-based rotation).
    peer_key_phase: AtomicBool,
    pending_rx_key: Mutex<Option<Box<dyn PacketKey>>>,

    // Key update coordination.
    pub key_update: Arc<KeyUpdateState>,

    // Identity (immutable after construction).
    local_cid: ConnectionId,
    local_cid_len: usize,
    tag_len: usize,
}

// SAFETY: All mutable state is protected by atomics, ArcSwap, or Mutex.
// PacketKey and HeaderKey are Send+Sync (confirmed in quinn-proto).
unsafe impl Send for SharedConnectionState {}
unsafe impl Sync for SharedConnectionState {}

impl SharedConnectionState {
    /// Decrypt a 1-RTT packet fully in-place. Thread-safe (`&self`).
    ///
    /// Steps:
    /// 1. Read `largest_rx_pn` (atomic, lock-free) for PN decode
    /// 2. Header unprotect (pure computation)
    /// 3. Check key phase — if changed, try next-gen key first
    /// 4. AEAD decrypt (~500ns, pure computation)
    /// 5. Replay check + accept (~10-20ns mutex)
    /// 6. If key phase changed and AEAD succeeded, commit rotation (CAS)
    ///
    /// AEAD runs before replay check so the mutex isn't held during crypto.
    /// Duplicate packets waste ~500ns of crypto — acceptable at <0.1% rate.
    pub fn decrypt_in_place(
        &self,
        packet: &mut [u8],
    ) -> Result<DecryptedInPlace, ParseError> {
        // 1. Lock-free PN read for header decode.
        let largest = self.replay.largest_rx_pn();

        // 2. Header unprotect.
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            self.tag_len,
            &**self.rx_header_key,
            largest,
        )?;

        // 3. Check key phase BEFORE AEAD to detect peer rotation.
        let current_phase = self.peer_key_phase.load(Ordering::Acquire);
        let phase_changed = hdr.key_phase != current_phase;

        // 4. AEAD decrypt — if key phase changed, try next-gen key.
        let result = if phase_changed {
            self.decrypt_with_next_key(packet, &hdr)?
        } else {
            let key_guard = self.rx_packet_key.load();
            decrypt_payload_in_place(packet, &hdr, &***key_guard)?
        };

        // 5. Replay check + accept (~10-20ns mutex).
        if !self.replay.test_and_accept(hdr.pn) {
            return Err(ParseError::DuplicatePacket);
        }

        // 6. If key phase changed and AEAD succeeded, commit the rotation.
        if phase_changed {
            self.handle_key_phase_change(hdr.key_phase);
        }

        Ok(result)
    }

    /// Try decrypting with the next generation key (peer-initiated key rotation).
    ///
    /// AEAD decrypt modifies the buffer in-place, so we save a copy before
    /// trying the next-gen key. This only happens during key rotation (~once
    /// per 7M packets), so the copy cost is negligible.
    fn decrypt_with_next_key(
        &self,
        packet: &mut [u8],
        hdr: &crate::packet::ShortHeader,
    ) -> Result<DecryptedInPlace, ParseError> {
        // Save payload so we can retry if the first key fails.
        let saved = packet[hdr.payload_offset..].to_vec();

        // First check if we have a pending RX key (we initiated the rotation).
        {
            let pending = self.pending_rx_key.lock();
            if let Some(key) = &*pending {
                if let Ok(result) = decrypt_payload_in_place(packet, hdr, &**key) {
                    return Ok(result);
                }
                // Restore payload for next attempt.
                packet[hdr.payload_offset..].copy_from_slice(&saved);
            }
        }

        // Peer-initiated: peek next generation key.
        {
            let keys = match self.key_update.next_keys() {
                Ok(guard) => guard,
                Err(_) => {
                    self.key_update.set_key_exhausted();
                    return Err(ParseError::CryptoError);
                }
            };
            if let Some((next_rx, _)) = keys.front() {
                if let Ok(result) = decrypt_payload_in_place(packet, hdr, &**next_rx) {
                    return Ok(result);
                }
                // Restore payload for next attempt.
                packet[hdr.payload_offset..].copy_from_slice(&saved);
            }
        }

        // Neither next-gen key works — fall back to current key.
        let key_guard = self.rx_packet_key.load();
        decrypt_payload_in_place(packet, hdr, &***key_guard)
    }

    fn handle_key_phase_change(&self, new_phase: bool) {
        let old_phase = !new_phase;
        tracing::debug!(old_phase, new_phase, "key phase change detected");
        // CAS: only one thread wins the rotation.
        if self
            .peer_key_phase
            .compare_exchange(old_phase, new_phase, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // Winner: swap RX key.
            let mut pending = self.pending_rx_key.lock();
            if let Some(new_key) = pending.take() {
                self.rx_packet_key.store(Arc::new(new_key));
                tracing::debug!("key update: RX rotated (peer responded to our initiation)");
            } else {
                // Peer-initiated rotation: pop from key_update.
                let mut keys = match self.key_update.next_keys() {
                    Ok(guard) => guard,
                    Err(_) => {
                        self.key_update.set_key_exhausted();
                        return;
                    }
                };
                if let Some((new_rx, new_tx)) = keys.pop_front() {
                    self.rx_packet_key.store(Arc::new(new_rx));
                    self.tx.store_packet_key(Arc::new(new_tx));
                    tracing::debug!("key update: rotated to new keys (peer-initiated)");
                } else {
                    self.key_update.set_key_exhausted();
                    warn!("key update: no pre-computed keys available, connection must be closed");
                    return;
                }
            }
            self.tx.set_key_phase(new_phase);
            self.key_update.reset_packets_since_update();
        }
        // Losers: no-op, key already swapped by winner.
    }

    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    pub fn local_cid_len(&self) -> usize {
        self.local_cid_len
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    pub fn is_key_exhausted(&self) -> bool {
        self.key_update.is_key_exhausted()
    }

    /// Encrypt a standalone ACK packet using shared state. Thread-safe (`&self`).
    ///
    /// Called by the I/O thread (core 0) periodically when `replay.needs_ack()`.
    /// Generates ACK ranges from the replay window and encrypts them.
    ///
    /// `ack_delay_us`: queuing delay to carry in the ACK frame (microseconds),
    /// provided by the engine from the OWD tracker.
    pub fn encrypt_ack(&self, ack_delay_us: u64, buf: &mut [u8]) -> Result<crate::EncryptResult, ParseError> {
        let ack_ranges = self.replay.generate_ack_ranges();
        let pn = self.tx.next_pn();
        let key_guard = self.tx.load_packet_key();
        crate::encrypt_ack_packet(
            &ack_ranges,
            ack_delay_us,
            self.tx.remote_cid(),
            pn,
            self.tx.largest_acked(),
            self.tx.key_phase(),
            &***key_guard,
            self.tx.header_key(),
            self.tag_len,
            buf,
        )
    }

    /// Process an ACK frame received from the peer. Thread-safe (`&self`).
    ///
    /// Updates `largest_acked` in TxState atomically.
    pub fn process_ack(&self, ack: &crate::AckFrame) {
        self.tx.update_largest_acked(ack.largest_acked);
    }

    /// Check if key update should be initiated and do so if threshold reached.
    ///
    /// Called by the I/O thread (e.g., container dispatcher) periodically.
    /// Pops next-gen keys, stores pending RX key, swaps TX key, flips key phase.
    pub fn maybe_initiate_key_update(&self, count: u64) {
        let prev = self
            .key_update
            .packets_since_update()
            .fetch_add(count, Ordering::Relaxed);
        if prev + count >= crate::KEY_UPDATE_THRESHOLD && prev < crate::KEY_UPDATE_THRESHOLD {
            let mut next_keys = match self.key_update.next_keys() {
                Ok(guard) => guard,
                Err(_) => {
                    self.key_update.set_key_exhausted();
                    return;
                }
            };
            if let Some((new_rx, new_tx)) = next_keys.pop_front() {
                let mut pending = self.pending_rx_key.lock();
                *pending = Some(new_rx);
                self.tx.store_packet_key(Arc::new(new_tx));
                let old_phase = self.tx.key_phase();
                self.tx.set_key_phase(!old_phase);
                self.key_update.reset_packets_since_update();
                tracing::debug!("key update: TX rotated, awaiting peer response");
            } else {
                self.key_update.set_key_exhausted();
                warn!("key update: no pre-computed keys available, connection must be closed");
            }
        }
    }
}

// ── Conversion from LocalConnectionState ─────────────────────────────────

use crate::local::LocalConnectionState;

impl LocalConnectionState {
    /// Convert into a fully thread-safe `SharedConnectionState` for parallel decrypt.
    ///
    /// Consumes `self`. Uses `into_split()` internally then wraps RX state.
    pub fn into_shared(self) -> SharedConnectionState {
        let mut split = self.into_split();
        let tag_len = split.tx.tag_len();
        let local_cid = *split.rx.local_cid();
        let local_cid_len = split.rx.local_cid_len();
        let largest_rx_pn = split.rx.largest_rx_pn();
        let peer_kp = split.rx.peer_key_phase();
        let rx_pkt_key = split.rx.take_packet_key();
        let rx_hdr_key = split.rx.take_header_key();
        let bitmap = split.rx.take_bitmap();
        let pending = split.rx.take_pending_rx_key();

        SharedConnectionState {
            rx_packet_key: ArcSwap::from(rx_pkt_key),
            rx_header_key: rx_hdr_key,
            tx: split.tx,
            replay: AtomicReplayWindow::new(largest_rx_pn, bitmap),
            peer_key_phase: AtomicBool::new(peer_kp),
            pending_rx_key: Mutex::new(pending),
            key_update: split.key_update,
            local_cid,
            local_cid_len,
            tag_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto;
    use std::collections::VecDeque;

    /// Helper: create a pair of LocalConnectionState (client + server).
    fn make_pair() -> (LocalConnectionState, LocalConnectionState) {
        let suite = quinn_proto::crypto::rustls::initial_suite_from_provider(
            &Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .expect("initial suite");
        let dst_cid = ConnectionId::new(&[0xAA; 8]);

        let client_keys = suite.keys(&dst_cid, rustls::Side::Client, rustls::quic::Version::V1);
        let server_keys = suite.keys(&dst_cid, rustls::Side::Server, rustls::quic::Version::V1);

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
    fn shared_decrypt_roundtrip() {
        let (client, server) = make_pair();
        let split_client = client.into_split();
        let shared_server = server.into_shared();

        let payload = b"hello shared world";
        let mut buf = vec![0u8; 2048];

        let result = split_client
            .tx
            .encrypt_datagram(payload, &mut buf, None)
            .expect("encrypt");

        let decrypted = shared_server
            .decrypt_in_place(&mut buf[..result.len])
            .expect("decrypt");

        assert_eq!(decrypted.datagrams.len(), 1);
        let range = &decrypted.datagrams[0];
        assert_eq!(&buf[range.clone()], payload);
    }

    #[test]
    fn shared_concurrent_decrypt() {
        let (client, server) = make_pair();
        let split_client = client.into_split();
        let shared_server = Arc::new(server.into_shared());

        // Pre-encrypt 4000 packets.
        let mut encrypted: Vec<Vec<u8>> = Vec::with_capacity(4000);
        for _ in 0..4000 {
            let mut buf = vec![0u8; 2048];
            let result = split_client
                .tx
                .encrypt_datagram(b"test", &mut buf, None)
                .expect("encrypt");
            buf.truncate(result.len);
            encrypted.push(buf);
        }

        // Split into 4 chunks and decrypt in parallel.
        let chunks: Vec<Vec<Vec<u8>>> = encrypted
            .chunks(1000)
            .map(|c| c.to_vec())
            .collect();

        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                let shared = Arc::clone(&shared_server);
                std::thread::spawn(move || {
                    let mut count = 0;
                    for mut pkt in chunk {
                        if shared.decrypt_in_place(&mut pkt).is_ok() {
                            count += 1;
                        }
                    }
                    count
                })
            })
            .collect();

        let total: usize = handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .sum();

        assert_eq!(total, 4000, "all packets must decrypt successfully");
    }

    #[test]
    fn shared_replay_rejection() {
        let (client, server) = make_pair();
        let split_client = client.into_split();
        let shared_server = server.into_shared();

        let mut buf = vec![0u8; 2048];
        let result = split_client
            .tx
            .encrypt_datagram(b"data", &mut buf, None)
            .expect("encrypt");

        let mut pkt1 = buf[..result.len].to_vec();
        let mut pkt2 = buf[..result.len].to_vec();

        // First decrypt succeeds.
        assert!(shared_server.decrypt_in_place(&mut pkt1).is_ok());

        // Second decrypt of same packet fails (replay).
        let err = shared_server.decrypt_in_place(&mut pkt2);
        assert!(matches!(err, Err(ParseError::DuplicatePacket)));
    }

    #[test]
    fn shared_ack_generation() {
        let (client, server) = make_pair();
        let split_client = client.into_split();
        let shared_server = server.into_shared();

        // Encrypt + decrypt 10 packets.
        for _ in 0..10 {
            let mut buf = vec![0u8; 2048];
            let result = split_client
                .tx
                .encrypt_datagram(b"data", &mut buf, None)
                .expect("encrypt");
            shared_server
                .decrypt_in_place(&mut buf[..result.len])
                .expect("decrypt");
        }

        // ACK should be needed.
        assert!(shared_server.replay.needs_ack());

        // Generate ACK ranges.
        let ranges = shared_server.replay.generate_ack_ranges();
        assert!(!ranges.is_empty());
        assert_eq!(ranges[0], 0..10);

        // After ACK generation, needs_ack should return false.
        assert!(!shared_server.replay.needs_ack());
    }

    #[test]
    fn shared_encrypt_ack_roundtrip() {
        let (client, server) = make_pair();
        let split_client = client.into_split();
        let shared_server = server.into_shared();

        // Encrypt + decrypt 10 packets so server has data to ACK.
        for _ in 0..10 {
            let mut buf = vec![0u8; 2048];
            let result = split_client
                .tx
                .encrypt_datagram(b"data", &mut buf, None)
                .expect("encrypt");
            shared_server
                .decrypt_in_place(&mut buf[..result.len])
                .expect("decrypt");
        }

        // Server generates and encrypts an ACK packet.
        assert!(shared_server.replay.needs_ack());
        let mut ack_buf = vec![0u8; 256];
        let result = shared_server.encrypt_ack(0, &mut ack_buf).expect("encrypt_ack");
        assert!(result.len > 0);
        assert!(result.len <= 256);

        // After ACK generation, needs_ack should return false.
        assert!(!shared_server.replay.needs_ack());
    }
}

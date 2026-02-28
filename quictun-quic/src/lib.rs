//! quictun-quic: Optimized QUIC 1-RTT data plane for DATAGRAM tunneling.
//!
//! Replaces quinn-proto for 1-RTT short header packets after handshake.
//! Designed for multi-core (all atomic state, `Arc`-shared) but tested
//! single-threaded first (Phase 1).
//!
//! quinn-proto still handles handshake (long headers). Once `Event::Connected`
//! fires, keys are extracted via `Connection::take_1rtt_keys()` and handed to
//! `ConnectionState` for the data plane.

pub mod ack;
pub mod bbr;
pub mod frame;
pub mod ordered_queue;
pub mod packet;

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use quinn_proto::ConnectionId;
use quinn_proto::crypto::{self, HeaderKey, PacketKey};
use smallvec::SmallVec;
use tracing::warn;

use ack::{AtomicBitmap, generate_ack_ranges};
use bbr::{BbrState, SentTracker};
use frame::AckFrame;

/// UnsafeCell wrapper that implements Sync for single-threaded access.
///
/// Phase 1 runs on a single DPDK polling thread, so no actual concurrent access occurs.
/// Phase 2 will need Mutex or RwLock when multiple cores share ConnectionState.
struct SyncUnsafeCell<T>(UnsafeCell<T>);

// SAFETY: Phase 1 is single-threaded. The DPDK engine loop is the only accessor.
// Phase 2 must replace this with Mutex/RwLock for multi-core.
unsafe impl<T> Sync for SyncUnsafeCell<T> {}
unsafe impl<T> Send for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    fn new(val: T) -> Self {
        Self(UnsafeCell::new(val))
    }

    /// Get a shared reference to the inner value.
    ///
    /// SAFETY: Caller must ensure no mutable references exist.
    #[inline(always)]
    unsafe fn get(&self) -> &T {
        unsafe { &*self.0.get() }
    }

    /// Get a mutable reference to the inner value.
    ///
    /// SAFETY: Caller must ensure exclusive access.
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

/// Maximum ACK ranges to include in a single packet.
const MAX_ACK_RANGES: usize = 8;

/// Send an ACK every N received packets.
const DEFAULT_ACK_INTERVAL: u32 = 2;

/// Trigger key update after this many packets (well below AES-GCM 2^23 limit).
const KEY_UPDATE_THRESHOLD: u64 = 7_000_000;

/// Parse/decrypt/encrypt error.
#[derive(Debug)]
pub enum ParseError {
    BufferTooShort,
    NotShortHeader,
    InvalidFixedBit,
    UnexpectedFrameType(u8),
    CryptoError,
    NoKeysAvailable,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short"),
            Self::NotShortHeader => write!(f, "not a short header"),
            Self::InvalidFixedBit => write!(f, "invalid fixed bit"),
            Self::UnexpectedFrameType(t) => write!(f, "unexpected frame type 0x{t:02x}"),
            Self::CryptoError => write!(f, "AEAD decryption failed"),
            Self::NoKeysAvailable => write!(f, "no keys available"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Result of decrypting a 1-RTT packet.
pub struct DecryptedPacket {
    /// DATAGRAM payloads extracted from the packet.
    pub datagrams: SmallVec<[Bytes; 4]>,
    /// ACK frame if present in the packet.
    pub ack: Option<AckFrame>,
    /// The decoded packet number.
    pub pn: u64,
}

/// Result of encrypting a datagram into a 1-RTT packet.
pub struct EncryptResult {
    /// Bytes written to the output buffer.
    pub len: usize,
    /// Assigned packet number.
    pub pn: u64,
}

/// QUIC 1-RTT connection state for the data plane.
///
/// Created from quinn-proto keys after handshake completes. Handles
/// encrypt/decrypt/ACK/CC for DATAGRAM-only tunnel traffic.
///
/// All state is atomic or behind minimal locks — designed for `Arc`-sharing
/// across cores in Phase 2.
pub struct ConnectionState {
    // Current crypto keys (UnsafeCell: Phase 1 is single-threaded, no contention).
    rx_packet_key: SyncUnsafeCell<Box<dyn PacketKey>>,
    tx_packet_key: SyncUnsafeCell<Box<dyn PacketKey>>,
    rx_header_key: Box<dyn HeaderKey>,
    tx_header_key: Box<dyn HeaderKey>,
    tag_len: usize,

    // Key update (pre-computed generations)
    next_keys: SyncUnsafeCell<VecDeque<(Box<dyn PacketKey>, Box<dyn PacketKey>)>>,
    key_phase: AtomicBool,
    peer_key_phase: AtomicBool,
    packets_since_key_update: AtomicU64,

    // Identity
    local_cid: ConnectionId,
    remote_cid: ConnectionId,
    local_cid_len: usize,

    // TX state
    pn_counter: AtomicU64,
    /// Largest acked PN (for PN encoding efficiency).
    largest_acked: AtomicU64,

    // RX state
    largest_rx_pn: AtomicU64,
    received: AtomicBitmap,

    // Congestion control + loss detection
    pub bbr: BbrState,
    pub sent: SentTracker,

    // ACK generation
    rx_since_last_ack: AtomicU32,
    ack_interval: u32,
}

impl ConnectionState {
    /// Create from quinn-proto keys after handshake.
    ///
    /// - `keys`: 1-RTT keys extracted via `conn.take_1rtt_keys()`
    /// - `key_generations`: pre-computed from `conn.produce_next_1rtt_keys()` calls
    /// - `is_server`: determines which key in each KeyPair is TX vs RX
    pub fn new(
        keys: crypto::Keys,
        key_generations: VecDeque<crypto::KeyPair<Box<dyn PacketKey>>>,
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        is_server: bool,
    ) -> Arc<Self> {
        let tag_len = keys.packet.local.tag_len();

        // KeyPair.local = our encryption key, KeyPair.remote = our decryption key.
        // This naming is from quinn-proto's perspective — "local" is what WE use.
        // The local key encrypts, the remote key decrypts.
        let (tx_packet_key, rx_packet_key) = (keys.packet.local, keys.packet.remote);
        let (tx_header_key, rx_header_key) = (keys.header.local, keys.header.remote);

        // Pre-computed key generations: each KeyPair has (local=our_tx, remote=our_rx)
        let mut next_keys = VecDeque::with_capacity(key_generations.len());
        for kp in key_generations {
            next_keys.push_back((kp.remote, kp.local));
        }

        // Server starts with key_phase=false; initial phase matches.
        let _ = is_server;

        Arc::new(Self {
            rx_packet_key: SyncUnsafeCell::new(rx_packet_key),
            tx_packet_key: SyncUnsafeCell::new(tx_packet_key),
            rx_header_key,
            tx_header_key,
            tag_len,
            next_keys: SyncUnsafeCell::new(next_keys),
            key_phase: AtomicBool::new(false),
            peer_key_phase: AtomicBool::new(false),
            packets_since_key_update: AtomicU64::new(0),
            local_cid,
            remote_cid,
            local_cid_len: local_cid.len(),
            pn_counter: AtomicU64::new(0),
            largest_acked: AtomicU64::new(0),
            largest_rx_pn: AtomicU64::new(0),
            received: AtomicBitmap::new(),
            bbr: BbrState::new(),
            sent: SentTracker::new(),
            rx_since_last_ack: AtomicU32::new(0),
            ack_interval: DEFAULT_ACK_INTERVAL,
        })
    }

    /// Decrypt an incoming 1-RTT packet.
    ///
    /// Performs: header unprotection → PN decode → AEAD decrypt → frame parse.
    /// Handles key phase changes (key update detection).
    ///
    /// `packet` is modified in-place (header unprotection + decryption).
    pub fn decrypt_packet(&self, packet: &mut [u8]) -> Result<DecryptedPacket, ParseError> {
        let pkt_len = packet.len();
        if pkt_len < 1 + self.local_cid_len + 4 + self.tag_len {
            return Err(ParseError::BufferTooShort);
        }

        // Header protection removal needs the sample, which starts at
        // pn_offset + 4 (maximum PN length).
        let pn_offset = 1 + self.local_cid_len;
        // The sample starts 4 bytes after pn_offset (RFC 9001 §5.4.2)
        let sample_offset = pn_offset + 4;
        if pkt_len < sample_offset + self.rx_header_key.sample_size() {
            return Err(ParseError::BufferTooShort);
        }

        // Remove header protection
        self.rx_header_key.decrypt(pn_offset, packet);

        // Parse the unprotected short header
        let largest_pn = self.largest_rx_pn.load(Ordering::Relaxed);
        let hdr = packet::parse_short_header(packet, self.local_cid_len, largest_pn)?;

        // Check key phase and potentially rotate keys
        let current_peer_phase = self.peer_key_phase.load(Ordering::Relaxed);
        if hdr.key_phase != current_peer_phase {
            self.handle_key_update_rx(hdr.key_phase);
        }

        // AEAD decrypt: header is AAD, payload includes the AEAD tag
        let header_bytes = &packet[..hdr.payload_offset];
        let mut payload = BytesMut::from(&packet[hdr.payload_offset..]);

        // SAFETY: Phase 1 is single-threaded (single DPDK polling loop).
        let rx_key = unsafe { self.rx_packet_key.get() };
        rx_key
            .decrypt(hdr.pn, header_bytes, &mut payload)
            .map_err(|_| ParseError::CryptoError)?;

        // Update RX state
        self.received.set(hdr.pn);
        // Update largest_rx_pn atomically (fetch_max)
        let _ = self.largest_rx_pn.fetch_max(hdr.pn, Ordering::Relaxed);
        self.rx_since_last_ack.fetch_add(1, Ordering::Relaxed);

        // Convert to Bytes for zero-copy slicing of datagram payloads.
        let decrypted = payload.freeze();

        // Parse frames from decrypted payload
        let mut datagrams: SmallVec<[Bytes; 4]> = SmallVec::new();
        let mut ack_frame = None;
        let mut pos = 0;
        let decrypted_len = decrypted.len();

        while pos < decrypted_len {
            let frame_type = decrypted[pos];
            match frame_type {
                // PADDING (0x00) — skip
                0x00 => {
                    pos += 1;
                }
                // PING (0x01) — no payload
                0x01 => {
                    pos += 1;
                }
                // ACK (0x02 or 0x03)
                0x02 | 0x03 => {
                    let (ack, rest) = frame::parse_ack(&decrypted[pos..])?;
                    ack_frame = Some(ack);
                    pos = decrypted_len - rest.len();
                }
                // DATAGRAM (0x30 no len, 0x31 with len)
                0x30 | 0x31 => {
                    let remaining = &decrypted[pos..];
                    let (data, rest) = frame::parse_datagram(remaining)?;
                    // Zero-copy: slice into the frozen Bytes (no heap allocation).
                    let data_start = pos + (data.as_ptr() as usize - remaining.as_ptr() as usize);
                    let data_end = data_start + data.len();
                    datagrams.push(decrypted.slice(data_start..data_end));
                    pos = decrypted_len - rest.len();
                }
                // CONNECTION_CLOSE (0x1c, 0x1d) — just stop parsing
                0x1c | 0x1d => break,
                other => {
                    // Unknown frame type: skip rest of packet (best-effort)
                    warn!(frame_type = other, "unknown frame type, skipping rest of packet");
                    break;
                }
            }
        }

        Ok(DecryptedPacket {
            datagrams,
            ack: ack_frame,
            pn: hdr.pn,
        })
    }

    /// Handle a key phase change from the peer.
    fn handle_key_update_rx(&self, new_phase: bool) {
        // SAFETY: Phase 1 is single-threaded.
        let next_keys = unsafe { self.next_keys.get_mut() };
        if let Some((new_rx, new_tx)) = next_keys.pop_front() {
            unsafe {
                *self.rx_packet_key.get_mut() = new_rx;
                *self.tx_packet_key.get_mut() = new_tx;
            }
            self.peer_key_phase.store(new_phase, Ordering::Relaxed);
            self.key_phase.store(new_phase, Ordering::Relaxed);
            self.packets_since_key_update.store(0, Ordering::Relaxed);
            tracing::debug!("key update: rotated to new keys (peer-initiated)");
        } else {
            warn!("key update requested but no pre-computed keys available");
        }
    }

    /// Initiate a key update (our side).
    fn initiate_key_update(&self) {
        // SAFETY: Phase 1 is single-threaded.
        let next_keys = unsafe { self.next_keys.get_mut() };
        if let Some((new_rx, new_tx)) = next_keys.pop_front() {
            unsafe {
                *self.rx_packet_key.get_mut() = new_rx;
                *self.tx_packet_key.get_mut() = new_tx;
            }
            let old = self.key_phase.load(Ordering::Relaxed);
            self.key_phase.store(!old, Ordering::Relaxed);
            self.peer_key_phase.store(!old, Ordering::Relaxed);
            self.packets_since_key_update.store(0, Ordering::Relaxed);
            tracing::debug!("key update: rotated to new keys (self-initiated)");
        } else {
            warn!("key update: no pre-computed keys available, cannot rotate");
        }
    }

    /// Encrypt a datagram payload into a complete 1-RTT QUIC packet.
    ///
    /// Assigns a PN via atomic fetch_add. Optionally piggybacks ACK frames.
    /// `buf` must be large enough for header + frames + AEAD tag.
    ///
    /// Returns the bytes written and assigned PN.
    pub fn encrypt_datagram(
        &self,
        payload: &[u8],
        ack_ranges: Option<&[Range<u64>]>,
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        // Check key update threshold
        let pkt_count = self.packets_since_key_update.fetch_add(1, Ordering::Relaxed);
        if pkt_count >= KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter.fetch_add(1, Ordering::Relaxed);
        let largest_acked = self.largest_acked.load(Ordering::Relaxed);
        let key_phase = self.key_phase.load(Ordering::Relaxed);

        // Build short header
        let (header_len, _pn_len) = packet::build_short_header(
            &self.remote_cid,
            pn,
            largest_acked,
            key_phase,
            false, // spin bit: not used
            buf,
        );

        // Build frames into the payload area (after header)
        let mut frame_pos = header_len;

        // Piggyback ACK if provided
        if let Some(ranges) = ack_ranges {
            if !ranges.is_empty() {
                let ack_len = frame::build_ack(ranges, 0, &mut buf[frame_pos..]);
                frame_pos += ack_len;
            }
        }

        // DATAGRAM frame (no length field — last frame in packet).
        // Skip if payload is empty (ACK-only packet).
        if !payload.is_empty() {
            let dg_len = frame::build_datagram_no_len(payload, &mut buf[frame_pos..]);
            frame_pos += dg_len;
        } else if frame_pos == header_len {
            // No ACK and no datagram — add PING frame so packet isn't empty
            buf[frame_pos] = 0x01; // PING
            frame_pos += 1;
        }

        // Total plaintext = header + frames
        // AEAD encrypt in-place: encrypts buf[header_len..frame_pos] and appends tag
        let total_with_tag = frame_pos + self.tag_len;
        // Ensure buf is large enough
        if buf.len() < total_with_tag {
            return Err(ParseError::BufferTooShort);
        }
        // Zero the tag area (encrypt writes into it)
        buf[frame_pos..total_with_tag].fill(0);

        // SAFETY: Phase 1 is single-threaded.
        let tx_key = unsafe { self.tx_packet_key.get() };
        tx_key.encrypt(pn, &mut buf[..total_with_tag], header_len);

        // Apply header protection (must be done AFTER AEAD encryption)
        let pn_offset = 1 + self.remote_cid.len();
        self.tx_header_key.encrypt(pn_offset, &mut buf[..total_with_tag]);

        // Note: BBR tracking disabled in Phase 1. Inner TCP has its own CC.
        // Re-enable for Phase 2 multi-core.

        Ok(EncryptResult {
            len: total_with_tag,
            pn,
        })
    }

    /// Check if an ACK should be sent (every N received packets).
    pub fn needs_ack(&self) -> bool {
        self.rx_since_last_ack.load(Ordering::Relaxed) >= self.ack_interval
    }

    /// Generate ACK ranges from the received bitmap.
    pub fn generate_ack_ranges(&self) -> SmallVec<[Range<u64>; 8]> {
        let largest = self.largest_rx_pn.load(Ordering::Relaxed);
        let ranges = generate_ack_ranges(&self.received, largest, MAX_ACK_RANGES);
        // Reset the counter after generating ACK
        self.rx_since_last_ack.store(0, Ordering::Relaxed);
        // Advance bitmap base to the start of the oldest range we reported.
        // All PNs below this are implicitly acknowledged and don't need scanning.
        if let Some(last_range) = ranges.last() {
            if last_range.start > 0 {
                self.received.advance_base(last_range.start);
            }
        }
        ranges
    }

    /// Check if CC allows sending.
    ///
    /// Phase 1: always true — inner TCP handles its own congestion control.
    /// BBR CC is reserved for Phase 2 multi-core where it prevents head-of-line
    /// blocking across competing connections.
    pub fn can_send(&self) -> bool {
        true
    }

    /// Update the largest acknowledged PN (called when processing our sent ACKs).
    pub fn update_largest_acked(&self, pn: u64) {
        self.largest_acked.fetch_max(pn, Ordering::Relaxed);
    }

    /// Process an ACK frame received from the peer.
    pub fn process_ack(&self, ack: &AckFrame, _now_ns: u64) {
        self.update_largest_acked(ack.largest_acked);
        // Note: BBR tracking disabled in Phase 1.
    }

    /// Get the local CID (for CID matching on incoming packets).
    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Get the remote CID (for building outer UDP/IP headers).
    pub fn remote_cid(&self) -> &ConnectionId {
        &self.remote_cid
    }

    /// Get the local CID length (for header parsing).
    pub fn local_cid_len(&self) -> usize {
        self.local_cid_len
    }

    /// Get the AEAD tag length.
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

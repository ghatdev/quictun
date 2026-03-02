//! quictun-quic: Optimized QUIC 1-RTT data plane for DATAGRAM tunneling.
//!
//! Replaces quinn-proto for 1-RTT short header packets after handshake.
//! Thread-safe: all state is atomic or behind `parking_lot` locks for
//! `Arc`-sharing across cores in multi-core mode.
//!
//! quinn-proto still handles handshake (long headers). Once `Event::Connected`
//! fires, keys are extracted via `Connection::take_1rtt_keys()` and handed to
//! `ConnectionState` for the data plane.

pub mod ack;
pub mod bbr;
pub mod frame;
pub mod ordered_queue;
pub mod packet;

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock};
use quinn_proto::ConnectionId;
use quinn_proto::crypto::{self, HeaderKey, PacketKey};
use smallvec::SmallVec;
use tracing::warn;

use ack::{AtomicBitmap, generate_ack_ranges};
use bbr::{BbrState, SentTracker};
use frame::AckFrame;

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

/// Result of decrypting a 1-RTT packet fully in-place (zero-copy).
///
/// Datagram byte ranges refer to offsets within the original `packet` buffer
/// passed to `decrypt_packet_in_place`.
pub struct DecryptedInPlace {
    /// Byte ranges of DATAGRAM payloads within the packet buffer.
    pub datagrams: SmallVec<[Range<usize>; 4]>,
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
/// Thread-safe: packet keys use `RwLock` (read-heavy, ~3.4M reads/sec,
/// write every 7M packets for key rotation). Pre-computed keys use `Mutex`.
/// All counters are atomic. Designed for `Arc`-sharing across cores.
pub struct ConnectionState {
    // Current crypto keys (RwLock: read-heavy, write only on key rotation).
    rx_packet_key: RwLock<Box<dyn PacketKey>>,
    tx_packet_key: RwLock<Box<dyn PacketKey>>,
    rx_header_key: Box<dyn HeaderKey>,
    tx_header_key: Box<dyn HeaderKey>,
    tag_len: usize,

    // Key update (pre-computed generations)
    next_keys: Mutex<VecDeque<(Box<dyn PacketKey>, Box<dyn PacketKey>)>>,
    /// New RX key saved by initiate_key_update(), applied when peer responds.
    pending_rx_key: Mutex<Option<Box<dyn PacketKey>>>,
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

    /// Whether ACK tracking is enabled. Phase 1: false (CC disabled, no consumer).
    /// Phase 2: true (multi-core BBR needs ACK feedback).
    ack_enabled: bool,
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
            rx_packet_key: RwLock::new(rx_packet_key),
            tx_packet_key: RwLock::new(tx_packet_key),
            rx_header_key,
            tx_header_key,
            tag_len,
            next_keys: Mutex::new(next_keys),
            pending_rx_key: Mutex::new(None),
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
            ack_enabled: false,
        })
    }

    /// Decrypt an incoming 1-RTT packet (allocates a new BytesMut per call).
    ///
    /// Prefer `decrypt_packet_with_buf` in hot paths to reuse a scratch buffer.
    pub fn decrypt_packet(&self, packet: &mut [u8]) -> Result<DecryptedPacket, ParseError> {
        let mut scratch = BytesMut::with_capacity(packet.len());
        self.decrypt_packet_with_buf(packet, &mut scratch)
    }

    /// Decrypt an incoming 1-RTT packet, reusing a caller-provided BytesMut.
    ///
    /// Performs: header unprotection → PN decode → AEAD decrypt → frame parse.
    /// Handles key phase changes (key update detection).
    ///
    /// `packet` is modified in-place (header unprotection + decryption).
    /// `scratch` is cleared and reused (O(1) reset, avoids malloc/free per packet).
    pub fn decrypt_packet_with_buf(
        &self,
        packet: &mut [u8],
        scratch: &mut BytesMut,
    ) -> Result<DecryptedPacket, ParseError> {
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

        // Check key phase and potentially rotate keys.
        // CAS ensures only one thread triggers rotation in multi-core.
        let current_peer_phase = self.peer_key_phase.load(Ordering::Acquire);
        if hdr.key_phase != current_peer_phase {
            if self
                .peer_key_phase
                .compare_exchange(
                    current_peer_phase,
                    hdr.key_phase,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.handle_key_update_rx(hdr.key_phase);
            }
            // If CAS failed, another thread already rotated — use new keys.
        }

        // AEAD decrypt: reuse scratch buffer (clear + extend reuses allocation).
        let header_bytes = &packet[..hdr.payload_offset];
        scratch.clear();
        scratch.extend_from_slice(&packet[hdr.payload_offset..]);

        {
            let rx_key = self.rx_packet_key.read();
            rx_key
                .decrypt(hdr.pn, header_bytes, scratch)
                .map_err(|_| ParseError::CryptoError)?;
        }

        // Update RX state
        self.received.set(hdr.pn);
        // Update largest_rx_pn atomically (fetch_max)
        let _ = self.largest_rx_pn.fetch_max(hdr.pn, Ordering::Relaxed);
        if self.ack_enabled {
            self.rx_since_last_ack.fetch_add(1, Ordering::Relaxed);
        }

        // Convert to Bytes for zero-copy slicing of datagram payloads.
        let decrypted = scratch.split().freeze();

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

    /// Decrypt an incoming 1-RTT packet fully in-place (zero heap allocation).
    ///
    /// The entire decrypt happens on the provided `packet` buffer:
    /// header unprotection, AEAD decrypt, and frame parsing all in-place.
    /// Returns byte ranges into `packet` for each DATAGRAM payload.
    ///
    /// This is the fastest decrypt path — no BytesMut, no memcpy.
    pub fn decrypt_packet_in_place(
        &self,
        packet: &mut [u8],
    ) -> Result<DecryptedInPlace, ParseError> {
        let pkt_len = packet.len();
        if pkt_len < 1 + self.local_cid_len + 4 + self.tag_len {
            return Err(ParseError::BufferTooShort);
        }

        let pn_offset = 1 + self.local_cid_len;
        let sample_offset = pn_offset + 4;
        if pkt_len < sample_offset + self.rx_header_key.sample_size() {
            return Err(ParseError::BufferTooShort);
        }

        // Remove header protection (in-place)
        self.rx_header_key.decrypt(pn_offset, packet);

        // Parse the unprotected short header
        let largest_pn = self.largest_rx_pn.load(Ordering::Relaxed);
        let hdr = packet::parse_short_header(packet, self.local_cid_len, largest_pn)?;

        // Key phase rotation (CAS for multi-core safety)
        let current_peer_phase = self.peer_key_phase.load(Ordering::Acquire);
        if hdr.key_phase != current_peer_phase {
            if self
                .peer_key_phase
                .compare_exchange(
                    current_peer_phase,
                    hdr.key_phase,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.handle_key_update_rx(hdr.key_phase);
            }
        }

        // AEAD decrypt in-place: header is AAD, payload+tag is decrypted in-place.
        let payload_offset = hdr.payload_offset;
        let plain_len = {
            let (header, payload) = packet.split_at_mut(payload_offset);
            let rx_key = self.rx_packet_key.read();
            rx_key
                .decrypt_in_place(hdr.pn, header, payload)
                .map_err(|_| ParseError::CryptoError)?
        };

        // Update RX state
        self.received.set(hdr.pn);
        let _ = self.largest_rx_pn.fetch_max(hdr.pn, Ordering::Relaxed);
        if self.ack_enabled {
            self.rx_since_last_ack.fetch_add(1, Ordering::Relaxed);
        }

        // Parse frames from decrypted payload (in-place, return ranges).
        let decrypted_end = payload_offset + plain_len;
        let decrypted = &packet[payload_offset..decrypted_end];
        let mut datagrams: SmallVec<[Range<usize>; 4]> = SmallVec::new();
        let mut ack_frame = None;
        let mut pos = 0;
        let decrypted_len = decrypted.len();

        while pos < decrypted_len {
            let frame_type = decrypted[pos];
            match frame_type {
                0x00 => {
                    pos += 1;
                }
                0x01 => {
                    pos += 1;
                }
                0x02 | 0x03 => {
                    let (ack, rest) = frame::parse_ack(&decrypted[pos..])?;
                    ack_frame = Some(ack);
                    pos = decrypted_len - rest.len();
                }
                0x30 | 0x31 => {
                    let remaining = &decrypted[pos..];
                    let (data, rest) = frame::parse_datagram(remaining)?;
                    // Compute absolute offset within the original packet buffer.
                    let data_start =
                        payload_offset + pos + (data.as_ptr() as usize - remaining.as_ptr() as usize);
                    let data_end = data_start + data.len();
                    datagrams.push(data_start..data_end);
                    pos = decrypted_len - rest.len();
                }
                0x1c | 0x1d => break,
                other => {
                    warn!(frame_type = other, "unknown frame type, skipping rest of packet");
                    break;
                }
            }
        }

        Ok(DecryptedInPlace {
            datagrams,
            ack: ack_frame,
            pn: hdr.pn,
        })
    }

    /// Handle a key phase change from the peer.
    ///
    /// Called after CAS on peer_key_phase succeeds — only one thread enters.
    /// If we initiated (pending_rx_key available), use the saved RX key.
    /// If the peer initiated, pop a new key pair from next_keys.
    fn handle_key_update_rx(&self, new_phase: bool) {
        let pending = self.pending_rx_key.lock().take();
        if let Some(new_rx) = pending {
            // We initiated this key update — TX key was already rotated.
            // Apply the saved RX key now that the peer has responded.
            *self.rx_packet_key.write() = new_rx;
            tracing::debug!("key update: RX rotated (peer responded to our initiation)");
        } else {
            // Peer initiated — pop a new pair and update both keys.
            let mut next_keys = self.next_keys.lock();
            if let Some((new_rx, new_tx)) = next_keys.pop_front() {
                *self.rx_packet_key.write() = new_rx;
                *self.tx_packet_key.write() = new_tx;
                tracing::debug!("key update: rotated to new keys (peer-initiated)");
            } else {
                warn!("key update requested but no pre-computed keys available");
                return;
            }
        }
        self.key_phase.store(new_phase, Ordering::Release);
        self.packets_since_key_update.store(0, Ordering::Relaxed);
    }

    /// Initiate a key update (our side).
    ///
    /// Multi-core safety: only the thread whose fetch_add transitions
    /// pkt_count to exactly KEY_UPDATE_THRESHOLD triggers rotation.
    ///
    /// Only updates TX key and flips key_phase. The new RX key is saved
    /// as pending — applied when the peer responds with the new phase.
    /// peer_key_phase is NOT updated (the peer hasn't rotated yet).
    fn initiate_key_update(&self) {
        let mut next_keys = self.next_keys.lock();
        if let Some((new_rx, new_tx)) = next_keys.pop_front() {
            // Save new RX key for when peer responds.
            *self.pending_rx_key.lock() = Some(new_rx);
            // Update TX key immediately — start sending with new key.
            *self.tx_packet_key.write() = new_tx;
            let old = self.key_phase.load(Ordering::Relaxed);
            self.key_phase.store(!old, Ordering::Release);
            // DO NOT flip peer_key_phase — peer still sends with old phase.
            self.packets_since_key_update.store(0, Ordering::Relaxed);
            tracing::debug!("key update: TX rotated, awaiting peer response");
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
        // Check key update threshold.
        // Multi-core: exact equality ensures only one thread triggers rotation.
        let pkt_count = self.packets_since_key_update.fetch_add(1, Ordering::Relaxed);
        if pkt_count == KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter.fetch_add(1, Ordering::Relaxed);
        let largest_acked = self.largest_acked.load(Ordering::Relaxed);
        let key_phase = self.key_phase.load(Ordering::Acquire);

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

        // Ensure minimum packet size for header protection sample.
        // Header protection needs sample_size() bytes starting at pn_offset + 4.
        // After AEAD, total = frame_pos + tag_len. Must be >= pn_offset + 4 + sample_size.
        let pn_offset = 1 + self.remote_cid.len();
        let min_total = pn_offset + 4 + self.tx_header_key.sample_size();
        let total_with_tag = frame_pos + self.tag_len;
        if total_with_tag < min_total {
            let pad_needed = min_total - total_with_tag;
            // PADDING frames are 0x00 bytes (RFC 9000 §19.1).
            buf[frame_pos..frame_pos + pad_needed].fill(0x00);
            frame_pos += pad_needed;
        }

        // Total plaintext = header + frames (+ padding)
        // AEAD encrypt in-place: encrypts buf[header_len..frame_pos] and appends tag
        let total_with_tag = frame_pos + self.tag_len;
        // Ensure buf is large enough
        if buf.len() < total_with_tag {
            return Err(ParseError::BufferTooShort);
        }

        {
            let tx_key = self.tx_packet_key.read();
            tx_key.encrypt(pn, &mut buf[..total_with_tag], header_len);
        }

        // Apply header protection (must be done AFTER AEAD encryption)
        self.tx_header_key.encrypt(pn_offset, &mut buf[..total_with_tag]);

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

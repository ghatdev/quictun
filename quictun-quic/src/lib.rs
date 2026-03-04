//! quictun-quic: Optimized QUIC 1-RTT data plane for DATAGRAM tunneling.
//!
//! Replaces quinn-proto for 1-RTT short header packets after handshake.
//!
//! Two connection state types:
//! - [`ConnectionState`]: Thread-safe (`Arc`-shared, atomic/RwLock). For DPDK multi-core.
//! - [`LocalConnectionState`]: Single-owner (`&mut self`). For tokio single-task loop.
//!
//! Both share the same packet encrypt/decrypt core via free functions in this module.

pub mod ack;
pub mod bitmap;
pub mod frame;
pub mod local;
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
use frame::AckFrame;

/// Maximum ACK ranges to include in a single packet.
const MAX_ACK_RANGES: usize = 8;

/// Send an ACK every N received packets.
///
/// Higher values reduce CPU overhead from ACK-only packet encryption and
/// sending, which is critical at high packet rates (>100K pps). Too low
/// (e.g., 2) causes the receiver to spend most CPU encrypting ACK-onlys,
/// starving the data receive path and causing UDP buffer overflow.
const DEFAULT_ACK_INTERVAL: u32 = 64;

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

// ── Shared free functions for packet encrypt/decrypt ─────────────────────
//
// These are the pure "mechanical" operations, shared by both ConnectionState
// (DPDK, multi-core) and LocalConnectionState (tokio, single-task).

/// Unprotect header and parse short header fields.
///
/// Returns the parsed header. The caller must handle key phase rotation
/// before calling [`decrypt_payload`].
pub fn unprotect_header(
    packet: &mut [u8],
    cid_len: usize,
    tag_len: usize,
    rx_header_key: &dyn HeaderKey,
    largest_rx_pn: u64,
) -> Result<packet::ShortHeader, ParseError> {
    let pkt_len = packet.len();
    if pkt_len < 1 + cid_len + 4 + tag_len {
        return Err(ParseError::BufferTooShort);
    }
    let pn_offset = 1 + cid_len;
    let sample_offset = pn_offset + 4;
    if pkt_len < sample_offset + rx_header_key.sample_size() {
        return Err(ParseError::BufferTooShort);
    }
    rx_header_key.decrypt(pn_offset, packet);
    packet::parse_short_header(packet, cid_len, largest_rx_pn)
}

/// AEAD-decrypt the payload and parse QUIC frames.
///
/// `packet` must have had header protection removed and header parsed.
/// `scratch` is reused across calls (cleared internally).
pub fn decrypt_payload(
    packet: &[u8],
    hdr: &packet::ShortHeader,
    rx_packet_key: &dyn PacketKey,
    scratch: &mut BytesMut,
) -> Result<DecryptedPacket, ParseError> {
    let header_bytes = &packet[..hdr.payload_offset];
    scratch.clear();
    scratch.extend_from_slice(&packet[hdr.payload_offset..]);

    rx_packet_key
        .decrypt(hdr.pn, header_bytes, scratch)
        .map_err(|_| ParseError::CryptoError)?;

    let decrypted = scratch.split().freeze();
    parse_frames_bytes(decrypted, hdr.pn)
}

/// AEAD-decrypt the payload in-place and parse QUIC frames.
///
/// Returns byte ranges into `packet` for each DATAGRAM payload.
pub fn decrypt_payload_in_place(
    packet: &mut [u8],
    hdr: &packet::ShortHeader,
    rx_packet_key: &dyn PacketKey,
) -> Result<DecryptedInPlace, ParseError> {
    let payload_offset = hdr.payload_offset;
    let plain_len = {
        let (header, payload) = packet.split_at_mut(payload_offset);
        rx_packet_key
            .decrypt_in_place(hdr.pn, header, payload)
            .map_err(|_| ParseError::CryptoError)?
    };

    let decrypted_end = payload_offset + plain_len;
    let decrypted = &packet[payload_offset..decrypted_end];
    parse_frames_in_place(decrypted, payload_offset, hdr.pn)
}

/// Build and encrypt a complete 1-RTT QUIC packet.
///
/// Writes the short header, frames (ACK + DATAGRAM), AEAD tag, and header
/// protection into `buf`. Returns bytes written and the PN used.
pub fn encrypt_packet(
    payload: &[u8],
    ack_ranges: Option<&[Range<u64>]>,
    remote_cid: &ConnectionId,
    pn: u64,
    largest_acked: u64,
    key_phase: bool,
    tx_packet_key: &dyn PacketKey,
    tx_header_key: &dyn HeaderKey,
    tag_len: usize,
    buf: &mut [u8],
) -> Result<EncryptResult, ParseError> {
    let (header_len, _pn_len) = packet::build_short_header(
        remote_cid,
        pn,
        largest_acked,
        key_phase,
        false, // spin bit
        buf,
    );

    let mut frame_pos = header_len;

    if let Some(ranges) = ack_ranges {
        if !ranges.is_empty() {
            let ack_len = frame::build_ack(ranges, 0, &mut buf[frame_pos..]);
            frame_pos += ack_len;
        }
    }

    if !payload.is_empty() {
        let dg_len = frame::build_datagram_no_len(payload, &mut buf[frame_pos..]);
        frame_pos += dg_len;
    } else if frame_pos == header_len {
        buf[frame_pos] = 0x01; // PING
        frame_pos += 1;
    }

    // Ensure minimum packet size for header protection sample.
    let pn_offset = 1 + remote_cid.len();
    let min_total = pn_offset + 4 + tx_header_key.sample_size();
    let total_with_tag = frame_pos + tag_len;
    if total_with_tag < min_total {
        let pad_needed = min_total - total_with_tag;
        buf[frame_pos..frame_pos + pad_needed].fill(0x00);
        frame_pos += pad_needed;
    }

    let total_with_tag = frame_pos + tag_len;
    if buf.len() < total_with_tag {
        return Err(ParseError::BufferTooShort);
    }

    tx_packet_key.encrypt(pn, &mut buf[..total_with_tag], header_len);
    tx_header_key.encrypt(pn_offset, &mut buf[..total_with_tag]);

    Ok(EncryptResult {
        len: total_with_tag,
        pn,
    })
}

/// Parse frames from a decrypted payload (Bytes variant, zero-copy slicing).
fn parse_frames_bytes(decrypted: Bytes, pn: u64) -> Result<DecryptedPacket, ParseError> {
    let mut datagrams: SmallVec<[Bytes; 4]> = SmallVec::new();
    let mut ack_frame = None;
    let mut pos = 0;
    let decrypted_len = decrypted.len();

    while pos < decrypted_len {
        let frame_type = decrypted[pos];
        match frame_type {
            0x00 | 0x01 => pos += 1,
            0x02 | 0x03 => {
                let (ack, rest) = frame::parse_ack(&decrypted[pos..])?;
                ack_frame = Some(ack);
                pos = decrypted_len - rest.len();
            }
            0x30 | 0x31 => {
                let remaining = &decrypted[pos..];
                let (data, rest) = frame::parse_datagram(remaining)?;
                let data_start =
                    pos + (data.as_ptr() as usize - remaining.as_ptr() as usize);
                let data_end = data_start + data.len();
                datagrams.push(decrypted.slice(data_start..data_end));
                pos = decrypted_len - rest.len();
            }
            0x1c | 0x1d => break,
            other => {
                warn!(frame_type = other, "unknown frame type, skipping rest of packet");
                break;
            }
        }
    }

    Ok(DecryptedPacket {
        datagrams,
        ack: ack_frame,
        pn,
    })
}

/// Parse frames from a decrypted payload in-place (returns byte ranges).
fn parse_frames_in_place(
    decrypted: &[u8],
    payload_offset: usize,
    pn: u64,
) -> Result<DecryptedInPlace, ParseError> {
    let mut datagrams: SmallVec<[Range<usize>; 4]> = SmallVec::new();
    let mut ack_frame = None;
    let mut pos = 0;
    let decrypted_len = decrypted.len();

    while pos < decrypted_len {
        let frame_type = decrypted[pos];
        match frame_type {
            0x00 | 0x01 => pos += 1,
            0x02 | 0x03 => {
                let (ack, rest) = frame::parse_ack(&decrypted[pos..])?;
                ack_frame = Some(ack);
                pos = decrypted_len - rest.len();
            }
            0x30 | 0x31 => {
                let remaining = &decrypted[pos..];
                let (data, rest) = frame::parse_datagram(remaining)?;
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
        pn,
    })
}

/// Coarse monotonic timestamp in nanoseconds (shared epoch across threads).
pub fn coarse_now_ns() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

// ── ConnectionState (thread-safe, for DPDK multi-core) ───────────────────

/// QUIC 1-RTT connection state for the data plane.
///
/// Created from quinn-proto keys after handshake completes. Handles
/// encrypt/decrypt/ACK for DATAGRAM-only tunnel traffic.
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
        let (tx_packet_key, rx_packet_key) = (keys.packet.local, keys.packet.remote);
        let (tx_header_key, rx_header_key) = (keys.header.local, keys.header.remote);

        let next_keys = prepare_key_generations(key_generations);

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
            rx_since_last_ack: AtomicU32::new(0),
            ack_interval: DEFAULT_ACK_INTERVAL,
        })
    }

    /// Decrypt an incoming 1-RTT packet (allocates a new BytesMut per call).
    pub fn decrypt_packet(&self, packet: &mut [u8]) -> Result<DecryptedPacket, ParseError> {
        let mut scratch = BytesMut::with_capacity(packet.len());
        self.decrypt_packet_with_buf(packet, &mut scratch)
    }

    /// Decrypt an incoming 1-RTT packet, reusing a caller-provided BytesMut.
    pub fn decrypt_packet_with_buf(
        &self,
        packet: &mut [u8],
        scratch: &mut BytesMut,
    ) -> Result<DecryptedPacket, ParseError> {
        let largest_pn = self.largest_rx_pn.load(Ordering::Relaxed);
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            self.tag_len,
            &*self.rx_header_key,
            largest_pn,
        )?;

        // Key phase rotation (CAS for multi-core safety).
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

        let result = {
            let rx_key = self.rx_packet_key.read();
            decrypt_payload(packet, &hdr, &**rx_key, scratch)?
        };

        // Update RX state.
        self.received.set(hdr.pn);
        let _ = self.largest_rx_pn.fetch_max(hdr.pn, Ordering::Relaxed);
        self.rx_since_last_ack.fetch_add(1, Ordering::Relaxed);

        Ok(result)
    }

    /// Decrypt an incoming 1-RTT packet fully in-place (zero heap allocation).
    pub fn decrypt_packet_in_place(
        &self,
        packet: &mut [u8],
    ) -> Result<DecryptedInPlace, ParseError> {
        let largest_pn = self.largest_rx_pn.load(Ordering::Relaxed);
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            self.tag_len,
            &*self.rx_header_key,
            largest_pn,
        )?;

        // Key phase rotation (CAS for multi-core safety).
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

        let result = {
            let rx_key = self.rx_packet_key.read();
            decrypt_payload_in_place(packet, &hdr, &**rx_key)?
        };

        // Update RX state.
        self.received.set(hdr.pn);
        let _ = self.largest_rx_pn.fetch_max(hdr.pn, Ordering::Relaxed);
        self.rx_since_last_ack.fetch_add(1, Ordering::Relaxed);

        Ok(result)
    }

    /// Handle a key phase change from the peer.
    fn handle_key_update_rx(&self, new_phase: bool) {
        let pending = self.pending_rx_key.lock().take();
        if let Some(new_rx) = pending {
            *self.rx_packet_key.write() = new_rx;
            tracing::debug!("key update: RX rotated (peer responded to our initiation)");
        } else {
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
    fn initiate_key_update(&self) {
        let mut next_keys = self.next_keys.lock();
        if let Some((new_rx, new_tx)) = next_keys.pop_front() {
            *self.pending_rx_key.lock() = Some(new_rx);
            *self.tx_packet_key.write() = new_tx;
            let old = self.key_phase.load(Ordering::Relaxed);
            self.key_phase.store(!old, Ordering::Release);
            self.packets_since_key_update.store(0, Ordering::Relaxed);
            tracing::debug!("key update: TX rotated, awaiting peer response");
        } else {
            warn!("key update: no pre-computed keys available, cannot rotate");
        }
    }

    /// Encrypt a datagram payload into a complete 1-RTT QUIC packet.
    pub fn encrypt_datagram(
        &self,
        payload: &[u8],
        ack_ranges: Option<&[Range<u64>]>,
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        let pkt_count = self.packets_since_key_update.fetch_add(1, Ordering::Relaxed);
        if pkt_count == KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter.fetch_add(1, Ordering::Relaxed);
        let largest_acked = self.largest_acked.load(Ordering::Relaxed);
        let key_phase = self.key_phase.load(Ordering::Acquire);

        let tx_key = self.tx_packet_key.read();
        encrypt_packet(
            payload,
            ack_ranges,
            &self.remote_cid,
            pn,
            largest_acked,
            key_phase,
            &**tx_key,
            &*self.tx_header_key,
            self.tag_len,
            buf,
        )
    }

    /// Check if an ACK should be sent (every N received packets).
    pub fn needs_ack(&self) -> bool {
        self.rx_since_last_ack.load(Ordering::Relaxed) >= self.ack_interval
    }

    /// Generate ACK ranges from the received bitmap.
    pub fn generate_ack_ranges(&self) -> SmallVec<[Range<u64>; 8]> {
        let largest = self.largest_rx_pn.load(Ordering::Relaxed);
        let ranges = generate_ack_ranges(&self.received, largest, MAX_ACK_RANGES);
        self.rx_since_last_ack.store(0, Ordering::Relaxed);
        // Advance base past fully-ACKed regions to keep the scan window small.
        if let Some(first_range) = ranges.first() {
            let new_base = first_range.start.saturating_sub(256);
            if new_base > self.received.base() {
                self.received.advance_base(new_base);
            }
        }
        ranges
    }

    /// Always returns true — no congestion control in tunnel mode.
    pub fn can_send(&self) -> bool {
        true
    }

    /// Update the largest acknowledged PN.
    pub fn update_largest_acked(&self, pn: u64) {
        self.largest_acked.fetch_max(pn, Ordering::Relaxed);
    }

    /// Process an ACK frame received from the peer.
    pub fn process_ack(&self, ack: &AckFrame) {
        self.update_largest_acked(ack.largest_acked);
    }

    /// Get the local CID.
    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Get the remote CID.
    pub fn remote_cid(&self) -> &ConnectionId {
        &self.remote_cid
    }

    /// Get the local CID length.
    pub fn local_cid_len(&self) -> usize {
        self.local_cid_len
    }

    /// Get the AEAD tag length.
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

/// Convert quinn-proto key generations to (rx, tx) pairs.
pub fn prepare_key_generations(
    key_generations: VecDeque<crypto::KeyPair<Box<dyn PacketKey>>>,
) -> VecDeque<(Box<dyn PacketKey>, Box<dyn PacketKey>)> {
    let mut next_keys = VecDeque::with_capacity(key_generations.len());
    for kp in key_generations {
        next_keys.push_back((kp.remote, kp.local));
    }
    next_keys
}

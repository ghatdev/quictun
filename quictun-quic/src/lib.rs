//! quictun-quic: Optimized QUIC 1-RTT data plane for DATAGRAM tunneling.
//!
//! Replaces quinn-proto for 1-RTT short header packets after handshake.
//!
//! [`LocalConnectionState`]: Single-owner (`&mut self`). Used by both tokio and DPDK.
//!
//! Packet encrypt/decrypt core is implemented as free functions in this module,
//! called by `LocalConnectionState` methods.

pub mod ack;
pub mod bitmap;
pub mod frame;
pub mod local;
pub mod packet;

use std::collections::VecDeque;
use std::ops::Range;

use bytes::{Bytes, BytesMut};
use quinn_proto::ConnectionId;
use quinn_proto::crypto::{self, HeaderKey, PacketKey};
use smallvec::SmallVec;
use tracing::warn;

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
    DuplicatePacket,
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
            Self::DuplicatePacket => write!(f, "duplicate packet number"),
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
    /// True if a CONNECTION_CLOSE frame was received.
    pub close_received: bool,
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
    /// True if a CONNECTION_CLOSE frame was received.
    pub close_received: bool,
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
// These are the pure "mechanical" operations, called by LocalConnectionState.

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
#[allow(clippy::too_many_arguments)]
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

    if let Some(ranges) = ack_ranges
        && !ranges.is_empty()
    {
        let ack_len = frame::build_ack(ranges, 0, &mut buf[frame_pos..]);
        frame_pos += ack_len;
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
    let mut close_received = false;
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
                let data_start = pos + (data.as_ptr() as usize - remaining.as_ptr() as usize);
                let data_end = data_start + data.len();
                datagrams.push(decrypted.slice(data_start..data_end));
                pos = decrypted_len - rest.len();
            }
            0x1c | 0x1d => {
                close_received = true;
                break;
            }
            other => {
                warn!(
                    frame_type = other,
                    "unknown frame type, skipping rest of packet"
                );
                break;
            }
        }
    }

    Ok(DecryptedPacket {
        datagrams,
        ack: ack_frame,
        pn,
        close_received,
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
    let mut close_received = false;
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
            0x1c | 0x1d => {
                close_received = true;
                break;
            }
            other => {
                warn!(
                    frame_type = other,
                    "unknown frame type, skipping rest of packet"
                );
                break;
            }
        }
    }

    Ok(DecryptedInPlace {
        datagrams,
        ack: ack_frame,
        pn,
        close_received,
    })
}

/// Convert an 8-byte CID slice to a u64 key for fast HashMap lookup.
///
/// CIDs are always 8 bytes in quictun. For shorter slices, zero-pads.
#[inline(always)]
pub fn cid_to_u64(cid: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = cid.len().min(8);
    buf[..len].copy_from_slice(&cid[..len]);
    u64::from_ne_bytes(buf)
}

/// Coarse monotonic timestamp in nanoseconds (shared epoch across threads).
pub fn coarse_now_ns() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
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

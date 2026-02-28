//! QUIC DATAGRAM and ACK frame parse/build + varint codec.
//!
//! Implements RFC 9221 (DATAGRAM) and RFC 9000 §19.3 (ACK) / §16 (varint).

use std::ops::Range;

use smallvec::SmallVec;

use crate::ParseError;

// ── QUIC variable-length integer (RFC 9000 §16) ────────────────────────

/// Read a QUIC varint from `buf`. Returns `(value, bytes_consumed)`.
pub fn read_varint(buf: &[u8]) -> Result<(u64, usize), ParseError> {
    if buf.is_empty() {
        return Err(ParseError::BufferTooShort);
    }
    let first = buf[0];
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(ParseError::BufferTooShort);
    }
    let mut val = (first & 0x3F) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Ok((val, len))
}

/// Write a QUIC varint into `buf`. Returns bytes written (1, 2, 4, or 8).
pub fn write_varint(val: u64, buf: &mut [u8]) -> usize {
    if val < (1 << 6) {
        buf[0] = val as u8;
        1
    } else if val < (1 << 14) {
        buf[0] = 0x40 | (val >> 8) as u8;
        buf[1] = val as u8;
        2
    } else if val < (1 << 30) {
        buf[0] = 0x80 | (val >> 24) as u8;
        buf[1] = (val >> 16) as u8;
        buf[2] = (val >> 8) as u8;
        buf[3] = val as u8;
        4
    } else {
        buf[0] = 0xC0 | (val >> 56) as u8;
        buf[1] = (val >> 48) as u8;
        buf[2] = (val >> 40) as u8;
        buf[3] = (val >> 32) as u8;
        buf[4] = (val >> 24) as u8;
        buf[5] = (val >> 16) as u8;
        buf[6] = (val >> 8) as u8;
        buf[7] = val as u8;
        8
    }
}

/// Compute the encoded length of a varint value.
pub fn varint_len(val: u64) -> usize {
    if val < (1 << 6) {
        1
    } else if val < (1 << 14) {
        2
    } else if val < (1 << 30) {
        4
    } else {
        8
    }
}

// ── DATAGRAM frame (RFC 9221) ──────────────────────────────────────────

/// DATAGRAM frame type without length field (payload extends to packet end).
const DATAGRAM_NO_LEN: u8 = 0x30;
/// DATAGRAM frame type with length field.
const DATAGRAM_WITH_LEN: u8 = 0x31;

/// Parse a DATAGRAM frame from `payload`. Returns `(datagram_data, remaining)`.
///
/// Handles both type 0x30 (no length, extends to end) and 0x31 (with length).
pub fn parse_datagram(payload: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    if payload.is_empty() {
        return Err(ParseError::BufferTooShort);
    }

    let frame_type = payload[0];
    let rest = &payload[1..];

    match frame_type {
        DATAGRAM_NO_LEN => {
            // Entire remaining payload is the datagram data; no more frames follow.
            Ok((rest, &[]))
        }
        DATAGRAM_WITH_LEN => {
            let (len, consumed) = read_varint(rest)?;
            let data_start = consumed;
            let data_end = data_start + len as usize;
            if rest.len() < data_end {
                return Err(ParseError::BufferTooShort);
            }
            Ok((&rest[data_start..data_end], &rest[data_end..]))
        }
        _ => Err(ParseError::UnexpectedFrameType(frame_type)),
    }
}

/// Build a DATAGRAM frame (type 0x30, no length — fills rest of packet).
///
/// Returns bytes written.
pub fn build_datagram_no_len(data: &[u8], buf: &mut [u8]) -> usize {
    buf[0] = DATAGRAM_NO_LEN;
    buf[1..1 + data.len()].copy_from_slice(data);
    1 + data.len()
}

/// Build a DATAGRAM frame (type 0x31, with length).
///
/// Returns bytes written.
pub fn build_datagram_with_len(data: &[u8], buf: &mut [u8]) -> usize {
    buf[0] = DATAGRAM_WITH_LEN;
    let n = write_varint(data.len() as u64, &mut buf[1..]);
    buf[1 + n..1 + n + data.len()].copy_from_slice(data);
    1 + n + data.len()
}

// ── ACK frame (RFC 9000 §19.3) ─────────────────────────────────────────

/// ACK frame type (no ECN counters).
const ACK_TYPE: u8 = 0x02;

/// Parsed ACK frame.
pub struct AckFrame {
    pub largest_acked: u64,
    pub ack_delay: u64,
    /// Acknowledged PN ranges, each `start..end` (inclusive start, exclusive end).
    pub ranges: SmallVec<[Range<u64>; 8]>,
}

/// Parse an ACK frame from `payload` (starting at the type byte).
///
/// Returns `(AckFrame, remaining_payload)`.
pub fn parse_ack(payload: &[u8]) -> Result<(AckFrame, &[u8]), ParseError> {
    if payload.is_empty() {
        return Err(ParseError::BufferTooShort);
    }

    let frame_type = payload[0];
    if frame_type != ACK_TYPE && frame_type != 0x03 {
        return Err(ParseError::UnexpectedFrameType(frame_type));
    }

    let mut pos = 1;
    let rest = &payload[pos..];

    // Largest Acknowledged
    let (largest_acked, n) = read_varint(rest)?;
    pos += n;

    // ACK Delay
    let (ack_delay, n) = read_varint(&payload[pos..])?;
    pos += n;

    // ACK Range Count
    let (range_count, n) = read_varint(&payload[pos..])?;
    pos += n;

    // First ACK Range
    let (first_range, n) = read_varint(&payload[pos..])?;
    pos += n;

    let mut ranges: SmallVec<[Range<u64>; 8]> = SmallVec::new();
    // First range: [largest_acked - first_range, largest_acked + 1)
    let range_start = largest_acked.saturating_sub(first_range);
    ranges.push(range_start..largest_acked + 1);

    let mut smallest = range_start;

    for _ in 0..range_count {
        // Gap
        let (gap, n) = read_varint(&payload[pos..])?;
        pos += n;

        // ACK Range
        let (ack_range, n) = read_varint(&payload[pos..])?;
        pos += n;

        // Gap means gap+1 unacknowledged packets before smallest
        let range_end = smallest.saturating_sub(gap + 2);
        let range_start = range_end.saturating_sub(ack_range);
        ranges.push(range_start..range_end + 1);
        smallest = range_start;
    }

    // Skip ECN counts if frame_type == 0x03
    if frame_type == 0x03 {
        for _ in 0..3 {
            let (_, n) = read_varint(&payload[pos..])?;
            pos += n;
        }
    }

    Ok((
        AckFrame {
            largest_acked,
            ack_delay,
            ranges,
        },
        &payload[pos..],
    ))
}

/// Build an ACK frame into `buf`.
///
/// `ranges` must be sorted descending by start (largest PN range first).
/// Returns bytes written.
pub fn build_ack(ranges: &[Range<u64>], ack_delay: u64, buf: &mut [u8]) -> usize {
    debug_assert!(!ranges.is_empty());

    let mut pos = 0;
    buf[pos] = ACK_TYPE;
    pos += 1;

    let first = &ranges[0];
    let largest_acked = first.end - 1;
    let first_range = largest_acked - first.start;

    pos += write_varint(largest_acked, &mut buf[pos..]);
    pos += write_varint(ack_delay, &mut buf[pos..]);
    pos += write_varint((ranges.len() - 1) as u64, &mut buf[pos..]); // range count
    pos += write_varint(first_range, &mut buf[pos..]); // first ACK range

    let mut prev_smallest = first.start;

    for range in &ranges[1..] {
        let range_end = range.end - 1;
        // Gap: prev_smallest - range_end - 2
        let gap = prev_smallest.saturating_sub(range_end + 2);
        let ack_range = range_end - range.start;
        pos += write_varint(gap, &mut buf[pos..]);
        pos += write_varint(ack_range, &mut buf[pos..]);
        prev_smallest = range.start;
    }

    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let cases: &[u64] = &[0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, u64::MAX >> 2];
        for &val in cases {
            let mut buf = [0u8; 8];
            let written = write_varint(val, &mut buf);
            let (decoded, consumed) = read_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
            assert_eq!(consumed, written);
            assert_eq!(consumed, varint_len(val));
        }
    }

    #[test]
    fn datagram_no_len_roundtrip() {
        let data = b"hello tunnel";
        let mut buf = [0u8; 64];
        let written = build_datagram_no_len(data, &mut buf);
        let (parsed, remaining) = parse_datagram(&buf[..written]).unwrap();
        assert_eq!(parsed, data);
        assert!(remaining.is_empty());
    }

    #[test]
    fn datagram_with_len_roundtrip() {
        let data = b"hello tunnel";
        let mut buf = [0u8; 64];
        let written = build_datagram_with_len(data, &mut buf);
        let (parsed, remaining) = parse_datagram(&buf[..written]).unwrap();
        assert_eq!(parsed, data);
        assert!(remaining.is_empty());
    }

    #[test]
    fn ack_single_range_roundtrip() {
        let ranges = vec![10..15u64]; // acks 10,11,12,13,14
        let mut buf = [0u8; 64];
        let written = build_ack(&ranges, 100, &mut buf);
        let (ack, remaining) = parse_ack(&buf[..written]).unwrap();
        assert_eq!(ack.largest_acked, 14);
        assert_eq!(ack.ack_delay, 100);
        assert_eq!(ack.ranges.len(), 1);
        assert_eq!(ack.ranges[0], 10..15);
        assert!(remaining.is_empty());
    }

    #[test]
    fn ack_multiple_ranges_roundtrip() {
        // Ranges must be sorted descending: [20..25, 10..15]
        let ranges = vec![20..25u64, 10..15u64];
        let mut buf = [0u8; 64];
        let written = build_ack(&ranges, 50, &mut buf);
        let (ack, remaining) = parse_ack(&buf[..written]).unwrap();
        assert_eq!(ack.largest_acked, 24);
        assert_eq!(ack.ack_delay, 50);
        assert_eq!(ack.ranges.len(), 2);
        assert_eq!(ack.ranges[0], 20..25);
        assert_eq!(ack.ranges[1], 10..15);
        assert!(remaining.is_empty());
    }
}

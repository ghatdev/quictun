//! QUIC 1-RTT short header parse/build and packet number encode/decode.
//!
//! Implements RFC 9000 §17.3 (short header) and Appendix A (PN decoding).

use quinn_proto::ConnectionId;

use crate::ParseError;

/// Parsed 1-RTT short header (after header unprotection).
pub struct ShortHeader {
    pub key_phase: bool,
    pub spin: bool,
    pub dst_cid: ConnectionId,
    pub pn: u64,
    pub pn_len: usize,
    pub payload_offset: usize,
}

/// Parse a 1-RTT short header from a packet whose header protection has
/// already been removed.
///
/// `local_cid_len`: length of our connection ID (known from handshake).
/// `largest_pn`: largest packet number received so far (for PN decoding).
pub fn parse_short_header(
    packet: &[u8],
    local_cid_len: usize,
    largest_pn: u64,
) -> Result<ShortHeader, ParseError> {
    // Minimum: 1 (first byte) + cid_len + 1 (min PN) + 16 (AEAD tag)
    let min_len = 1 + local_cid_len + 1 + 16;
    if packet.len() < min_len {
        return Err(ParseError::BufferTooShort);
    }

    let first = packet[0];
    // Bit 7 must be 0 (short header), Bit 6 must be 1 (fixed bit)
    if first & 0x80 != 0 {
        return Err(ParseError::NotShortHeader);
    }
    if first & 0x40 == 0 {
        return Err(ParseError::InvalidFixedBit);
    }

    let spin = first & 0x20 != 0;
    let key_phase = first & 0x04 != 0;
    let pn_len = ((first & 0x03) + 1) as usize; // 1-4 bytes

    // Extract destination CID
    let cid_end = 1 + local_cid_len;
    if packet.len() < cid_end + pn_len {
        return Err(ParseError::BufferTooShort);
    }
    let dst_cid = ConnectionId::new(&packet[1..cid_end]);

    // Extract truncated PN
    let pn_start = cid_end;
    let mut truncated_pn: u64 = 0;
    for i in 0..pn_len {
        truncated_pn = (truncated_pn << 8) | packet[pn_start + i] as u64;
    }

    let pn = decode_pn(truncated_pn, pn_len * 8, largest_pn);
    let payload_offset = pn_start + pn_len;

    Ok(ShortHeader {
        key_phase,
        spin,
        dst_cid,
        pn,
        pn_len,
        payload_offset,
    })
}

/// Decode a truncated packet number to full PN (RFC 9000 Appendix A).
pub fn decode_pn(truncated_pn: u64, pn_nbits: usize, largest_pn: u64) -> u64 {
    let expected = largest_pn.wrapping_add(1);
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate = (expected & !pn_mask) | truncated_pn;
    if candidate + pn_hwin <= expected && candidate + pn_win < (1u64 << 62) {
        candidate + pn_win
    } else if candidate > expected + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

/// Encode a full PN to truncated form (RFC 9000 §17.1).
///
/// Returns `(truncated_pn, pn_len)` where `pn_len` is 1-4.
pub fn encode_pn(full_pn: u64, largest_acked: u64) -> (u64, usize) {
    let num_unacked = full_pn.saturating_sub(largest_acked);
    if num_unacked < (1 << 7) {
        (full_pn & 0xFF, 1)
    } else if num_unacked < (1 << 15) {
        (full_pn & 0xFFFF, 2)
    } else if num_unacked < (1 << 23) {
        (full_pn & 0xFF_FFFF, 3)
    } else {
        (full_pn & 0xFFFF_FFFF, 4)
    }
}

/// Build a 1-RTT short header into `buf`.
///
/// Returns the header length (bytes written). The caller must then write
/// the AEAD payload starting at `buf[header_len..]`.
///
/// NOTE: header protection is NOT applied here — the caller must apply it
/// after AEAD encryption (which needs the full header as AAD).
pub fn build_short_header(
    dst_cid: &ConnectionId,
    pn: u64,
    largest_acked: u64,
    key_phase: bool,
    spin: bool,
    buf: &mut [u8],
) -> (usize, usize) {
    let (truncated_pn, pn_len) = encode_pn(pn, largest_acked);

    // First byte: 0|1|S|R|R|K|PP
    let mut first: u8 = 0x40; // fixed bit
    if spin {
        first |= 0x20;
    }
    if key_phase {
        first |= 0x04;
    }
    first |= (pn_len as u8 - 1) & 0x03;
    buf[0] = first;

    // Destination CID
    let cid = dst_cid.as_ref();
    buf[1..1 + cid.len()].copy_from_slice(cid);

    // Packet number (big-endian, pn_len bytes)
    let pn_start = 1 + cid.len();
    for i in 0..pn_len {
        buf[pn_start + i] = (truncated_pn >> (8 * (pn_len - 1 - i))) as u8;
    }

    let header_len = pn_start + pn_len;
    (header_len, pn_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pn_encode_decode_roundtrip() {
        // Test various PN values with different largest_acked
        let cases = [
            (0u64, 0u64),
            (1, 0),
            (100, 50),
            (256, 200),
            (0x1_0000, 0xFFF0),
            (0x100_0000, 0xFF_FFF0),
            (0x1_0000_0000u64, 0xFFFF_FFF0),
        ];
        for (full_pn, largest_acked) in cases {
            let (truncated, pn_len) = encode_pn(full_pn, largest_acked);
            let decoded = decode_pn(truncated, pn_len * 8, largest_acked);
            assert_eq!(
                decoded, full_pn,
                "roundtrip failed: pn={full_pn}, acked={largest_acked}, trunc={truncated}, len={pn_len}"
            );
        }
    }

    #[test]
    fn pn_decode_rfc_examples() {
        // RFC 9000 Appendix A examples
        assert_eq!(decode_pn(0xa82f30ea, 32, 0xa82f30e9), 0xa82f30ea);
        assert_eq!(decode_pn(0x9b32, 16, 0xa82f30ea), 0xa82f9b32);
    }

    #[test]
    fn build_parse_roundtrip() {
        let cid = ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]);
        let pn = 42u64;
        let largest_acked = 40u64;
        let key_phase = true;
        let spin = false;

        let mut buf = [0u8; 128];
        let (header_len, _pn_len) =
            build_short_header(&cid, pn, largest_acked, key_phase, spin, &mut buf);

        // Now parse it back (without header protection, which is fine for this test)
        let parsed = parse_short_header(&buf[..header_len + 16], cid.len(), largest_acked)
            .expect("parse should succeed");

        assert_eq!(parsed.dst_cid, cid);
        assert_eq!(parsed.pn, pn);
        assert_eq!(parsed.key_phase, key_phase);
        assert_eq!(parsed.spin, spin);
        assert_eq!(parsed.payload_offset, header_len);
    }
}

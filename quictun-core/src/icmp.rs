//! ICMP echo reply generation and error messages.
//!
//! All operations work on raw IPv4 packets (starting at IP header, no Ethernet).

use std::net::Ipv4Addr;

const IPPROTO_ICMP: u8 = 1;

/// ICMP type constants.
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_DEST_UNREACHABLE: u8 = 3;

/// Convert an ICMP echo request to an echo reply in-place.
///
/// `packet` starts at the IPv4 header.
/// Swaps src/dst IPs and changes type from 8→0. Fixes checksums.
///
/// Returns `true` if the packet was an echo request and was converted.
pub fn echo_reply_inplace(packet: &mut [u8]) -> bool {
    if packet.len() < 28 {
        // Min: 20 IP + 8 ICMP
        return false;
    }
    if packet[0] >> 4 != 4 || packet[9] != IPPROTO_ICMP {
        return false;
    }

    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl + 8 {
        return false;
    }

    let icmp_start = ihl;
    if packet[icmp_start] != ICMP_ECHO_REQUEST {
        return false;
    }

    // Swap src ↔ dst IP.
    let mut src_ip = [0u8; 4];
    let mut dst_ip = [0u8; 4];
    src_ip.copy_from_slice(&packet[12..16]);
    dst_ip.copy_from_slice(&packet[16..20]);
    packet[12..16].copy_from_slice(&dst_ip);
    packet[16..20].copy_from_slice(&src_ip);

    // Recompute IP header checksum.
    packet[10] = 0;
    packet[11] = 0;
    let ip_cksum = internet_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // Change ICMP type: 8 (request) → 0 (reply).
    // Incremental ICMP checksum update: only the type byte changed.
    let old_cksum = u16::from_be_bytes([packet[icmp_start + 2], packet[icmp_start + 3]]);
    packet[icmp_start] = ICMP_ECHO_REPLY;

    // RFC 1624: HC' = ~(~HC + ~m + m') where m changes from 0x0800 to 0x0000.
    let old_type_word = (ICMP_ECHO_REQUEST as u16) << 8 | packet[icmp_start + 1] as u16;
    let new_type_word = (ICMP_ECHO_REPLY as u16) << 8 | packet[icmp_start + 1] as u16;
    let new_cksum = incremental_update(old_cksum, old_type_word, new_type_word);
    packet[icmp_start + 2..icmp_start + 4].copy_from_slice(&new_cksum.to_be_bytes());

    true
}

/// Build an ICMP Time Exceeded message.
///
/// `trigger_packet` is the original IPv4 packet that caused the error.
/// `src_ip` is our local IP (source of the ICMP error).
///
/// Returns the complete IPv4 + ICMP packet, or None if trigger is too short.
pub fn build_time_exceeded(trigger_packet: &[u8], src_ip: Ipv4Addr) -> Option<Vec<u8>> {
    build_icmp_error(ICMP_TIME_EXCEEDED, 0, trigger_packet, src_ip, 0)
}

/// Build an ICMP Destination Unreachable (port unreachable) message.
pub fn build_dest_unreachable(trigger_packet: &[u8], src_ip: Ipv4Addr, code: u8) -> Option<Vec<u8>> {
    build_icmp_error(ICMP_DEST_UNREACHABLE, code, trigger_packet, src_ip, 0)
}

/// Build an ICMP Fragmentation Needed (Type 3, Code 4) message.
///
/// Sets the next-hop MTU in the ICMP header per RFC 792/RFC 1191.
pub fn build_frag_needed(trigger_packet: &[u8], src_ip: Ipv4Addr, mtu: u16) -> Option<Vec<u8>> {
    let header_rest = (mtu as u32).to_be_bytes();
    // Rest-of-header: bytes [24..28] = [0, 0, mtu_hi, mtu_lo]
    let rest = u32::from_be_bytes([0, 0, header_rest[2], header_rest[3]]);
    build_icmp_error(ICMP_DEST_UNREACHABLE, 4, trigger_packet, src_ip, rest)
}

/// Build a generic ICMP error message.
///
/// Per RFC 792: ICMP error includes IP header + first 8 bytes of original datagram.
/// `header_rest` is the 4-byte "rest of header" field at ICMP bytes [4..8] (e.g., next-hop MTU).
fn build_icmp_error(
    icmp_type: u8,
    icmp_code: u8,
    trigger_packet: &[u8],
    src_ip: Ipv4Addr,
    header_rest: u32,
) -> Option<Vec<u8>> {
    // Need at least IP header of trigger.
    if trigger_packet.len() < 20 {
        return None;
    }

    // Include IP header + first 8 bytes of payload (per RFC 792).
    let trigger_ihl = (trigger_packet[0] & 0x0f) as usize * 4;
    let include_len = (trigger_ihl + 8).min(trigger_packet.len());
    let trigger_data = &trigger_packet[..include_len];

    // ICMP error: 8 bytes header + trigger data.
    let icmp_len = 8 + trigger_data.len();
    let ip_total = 20 + icmp_len;
    let mut pkt = vec![0u8; ip_total];

    // IPv4 header.
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&[0x40, 0x00]); // DF
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_ICMP;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    // Destination = original packet's source.
    pkt[16..20].copy_from_slice(&trigger_packet[12..16]);

    // IP checksum.
    let ip_cksum = internet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP header.
    pkt[20] = icmp_type;
    pkt[21] = icmp_code;
    // Checksum at [22..24] = 0 initially.
    // Rest-of-header (unused/next-hop MTU) at [24..28].
    pkt[24..28].copy_from_slice(&header_rest.to_be_bytes());
    pkt[28..28 + trigger_data.len()].copy_from_slice(trigger_data);

    // ICMP checksum over entire ICMP message.
    let icmp_cksum = internet_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

    Some(pkt)
}

/// RFC 1071 Internet checksum.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// RFC 1624 incremental checksum update.
fn incremental_update(old_cksum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: i32 = !(old_cksum) as u16 as i32;
    sum += !(old_val) as u16 as i32;
    sum += new_val as i32;
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum < 0 {
        sum += 0x10000;
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
        let payload = b"ping data";
        let icmp_len = 8 + payload.len();
        let ip_total = 20 + icmp_len;
        let mut pkt = vec![0u8; ip_total];

        // IPv4 header.
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IPPROTO_ICMP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());

        let ip_cksum = internet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // ICMP echo request.
        pkt[20] = ICMP_ECHO_REQUEST;
        pkt[21] = 0; // code
        pkt[24..26].copy_from_slice(&id.to_be_bytes());
        pkt[26..28].copy_from_slice(&seq.to_be_bytes());
        pkt[28..28 + payload.len()].copy_from_slice(payload);

        let icmp_cksum = internet_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

        pkt
    }

    fn verify_checksum(data: &[u8]) -> bool {
        internet_checksum(data) == 0
    }

    #[test]
    fn test_echo_reply_basic() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let mut pkt = build_echo_request(src, dst, 0x1234, 1);

        assert!(verify_checksum(&pkt[..20]));
        assert!(verify_checksum(&pkt[20..]));

        assert!(echo_reply_inplace(&mut pkt));

        // IPs should be swapped.
        assert_eq!(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]), dst);
        assert_eq!(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]), src);

        // Type should be 0 (reply).
        assert_eq!(pkt[20], ICMP_ECHO_REPLY);

        // Checksums valid.
        assert!(verify_checksum(&pkt[..20]));
        assert!(verify_checksum(&pkt[20..]));

        // ID and sequence preserved.
        assert_eq!(u16::from_be_bytes([pkt[24], pkt[25]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[26], pkt[27]]), 1);
    }

    #[test]
    fn test_echo_reply_non_icmp() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        assert!(!echo_reply_inplace(&mut pkt));
    }

    #[test]
    fn test_echo_reply_too_short() {
        let mut pkt = vec![0u8; 10];
        assert!(!echo_reply_inplace(&mut pkt));
    }

    #[test]
    fn test_time_exceeded() {
        let trigger_src = Ipv4Addr::new(10, 0, 0, 2);
        let trigger_dst = Ipv4Addr::new(8, 8, 8, 8);
        let trigger = build_echo_request(trigger_src, trigger_dst, 1, 1);

        let local_ip = Ipv4Addr::new(192, 168, 100, 10);
        let icmp_pkt = build_time_exceeded(&trigger, local_ip).expect("should build");

        // Verify structure.
        assert_eq!(icmp_pkt[0] >> 4, 4); // IPv4
        assert_eq!(icmp_pkt[9], IPPROTO_ICMP);
        assert_eq!(Ipv4Addr::new(icmp_pkt[12], icmp_pkt[13], icmp_pkt[14], icmp_pkt[15]), local_ip);
        // Destination = trigger's source.
        assert_eq!(Ipv4Addr::new(icmp_pkt[16], icmp_pkt[17], icmp_pkt[18], icmp_pkt[19]), trigger_src);

        // ICMP type = Time Exceeded.
        assert_eq!(icmp_pkt[20], ICMP_TIME_EXCEEDED);

        // Checksums valid.
        let ihl = (icmp_pkt[0] & 0x0f) as usize * 4;
        assert!(verify_checksum(&icmp_pkt[..ihl]));
        assert!(verify_checksum(&icmp_pkt[ihl..]));
    }

    #[test]
    fn test_frag_needed() {
        let trigger_src = Ipv4Addr::new(10, 0, 0, 2);
        let trigger_dst = Ipv4Addr::new(8, 8, 8, 8);
        let trigger = build_echo_request(trigger_src, trigger_dst, 1, 1);

        let local_ip = Ipv4Addr::new(192, 168, 100, 10);
        let mtu: u16 = 1280;
        let icmp_pkt = build_frag_needed(&trigger, local_ip, mtu).expect("should build");

        // ICMP type = Dest Unreachable, code = 4 (Frag Needed).
        assert_eq!(icmp_pkt[20], ICMP_DEST_UNREACHABLE);
        assert_eq!(icmp_pkt[21], 4);

        // Next-hop MTU at bytes [26..28].
        let got_mtu = u16::from_be_bytes([icmp_pkt[26], icmp_pkt[27]]);
        assert_eq!(got_mtu, mtu);

        // Bytes [24..26] should be zero (unused upper half).
        assert_eq!(icmp_pkt[24], 0);
        assert_eq!(icmp_pkt[25], 0);

        // Checksums valid.
        let ihl = (icmp_pkt[0] & 0x0f) as usize * 4;
        assert!(verify_checksum(&icmp_pkt[..ihl]));
        assert!(verify_checksum(&icmp_pkt[ihl..]));
    }

    #[test]
    fn test_dest_unreachable() {
        let trigger_src = Ipv4Addr::new(10, 0, 0, 2);
        let trigger_dst = Ipv4Addr::new(8, 8, 8, 8);
        let trigger = build_echo_request(trigger_src, trigger_dst, 1, 1);

        let local_ip = Ipv4Addr::new(192, 168, 100, 10);
        let icmp_pkt = build_dest_unreachable(&trigger, local_ip, 3).expect("should build");

        assert_eq!(icmp_pkt[20], ICMP_DEST_UNREACHABLE);
        assert_eq!(icmp_pkt[21], 3); // code = port unreachable

        let ihl = (icmp_pkt[0] & 0x0f) as usize * 4;
        assert!(verify_checksum(&icmp_pkt[..ihl]));
        assert!(verify_checksum(&icmp_pkt[ihl..]));
    }
}

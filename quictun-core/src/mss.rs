//! TCP MSS clamping on SYN/SYN-ACK packets.
//!
//! Rewrites the MSS TCP option in-place and fixes the TCP checksum
//! via RFC 1624 incremental update. Works on raw IPv4 packets
//! (starting from the IP header, no Ethernet).

/// TCP protocol number.
const IPPROTO_TCP: u8 = 6;

/// Clamp the TCP MSS option in a SYN or SYN-ACK packet.
///
/// `packet` must start at the IPv4 header (no Ethernet header).
/// `max_mss` is the maximum MSS to allow. If the packet's MSS is
/// already <= max_mss, no change is made.
///
/// Returns `true` if the MSS was clamped (packet modified).
pub fn clamp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    // Minimum IPv4 header (20) + minimum TCP header (20).
    if packet.len() < 40 {
        return false;
    }

    // IPv4 version check.
    if packet[0] >> 4 != 4 {
        return false;
    }

    // Protocol must be TCP.
    if packet[9] != IPPROTO_TCP {
        return false;
    }

    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return false;
    }

    let tcp_start = ihl;
    let tcp = &packet[tcp_start..];

    // TCP flags byte is at offset 13. SYN = bit 1 (0x02).
    let flags = tcp[13];
    let is_syn = flags & 0x02 != 0;
    if !is_syn {
        return false;
    }

    // TCP data offset (header length) in 32-bit words.
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset < 20 || packet.len() < tcp_start + data_offset {
        return false;
    }

    // Scan TCP options for MSS (kind=2, len=4).
    let opts = &packet[tcp_start + 20..tcp_start + data_offset];
    let mss_offset = find_mss_option(opts);
    let Some(opt_off) = mss_offset else {
        return false;
    };

    // Absolute offset of MSS value (2 bytes) in packet.
    let mss_val_off = tcp_start + 20 + opt_off + 2;
    if mss_val_off + 2 > packet.len() {
        return false;
    }

    let old_mss = u16::from_be_bytes([packet[mss_val_off], packet[mss_val_off + 1]]);
    if old_mss <= max_mss {
        return false;
    }

    // Rewrite MSS value.
    packet[mss_val_off..mss_val_off + 2].copy_from_slice(&max_mss.to_be_bytes());

    // Fix TCP checksum incrementally (RFC 1624).
    let tcp_cksum_off = tcp_start + 16;
    let old_cksum = u16::from_be_bytes([packet[tcp_cksum_off], packet[tcp_cksum_off + 1]]);
    let new_cksum = incremental_checksum_update(old_cksum, old_mss, max_mss);
    packet[tcp_cksum_off..tcp_cksum_off + 2].copy_from_slice(&new_cksum.to_be_bytes());

    true
}

/// Find the byte offset of the MSS option (kind=2, len=4) within TCP options.
///
/// Returns the offset relative to the start of the options slice.
fn find_mss_option(opts: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        match kind {
            0 => return None, // End of options
            1 => {
                i += 1; // NOP
            }
            2 => {
                // MSS option: kind=2, len=4, value=2 bytes
                if i + 4 <= opts.len() && opts[i + 1] == 4 {
                    return Some(i);
                }
                return None; // malformed
            }
            _ => {
                // Skip other options (kind, len, data...).
                if i + 1 >= opts.len() {
                    return None;
                }
                let len = opts[i + 1] as usize;
                if len < 2 {
                    return None; // malformed
                }
                i += len;
            }
        }
    }
    None
}

/// RFC 1624 incremental checksum update: replace one 16-bit word.
///
/// Given old checksum HC, old value m, new value m', computes:
///   HC' = ~(~HC + ~m + m')
fn incremental_checksum_update(old_cksum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: i32 = (!old_cksum) as i32;
    sum += (!old_val) as i32;
    sum += new_val as i32;
    // Fold carry.
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
    use std::net::Ipv4Addr;

    /// Build a minimal TCP SYN packet with MSS option.
    fn build_tcp_syn(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, mss: u16) -> Vec<u8> {
        let tcp_hdr_len = 24u8; // 20 base + 4 MSS option
        let ip_total_len = 20 + tcp_hdr_len as u16;
        let mut pkt = vec![0u8; ip_total_len as usize];

        // IPv4 header.
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&dst_ip.octets());

        // TCP header.
        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes()); // src port
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes()); // dst port
        tcp[12] = (tcp_hdr_len / 4) << 4; // data offset
        tcp[13] = 0x02; // SYN flag

        // MSS option: kind=2, len=4, value.
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&mss.to_be_bytes());

        // Compute TCP checksum.
        let tcp_cksum = compute_tcp_checksum(src_ip, dst_ip, &pkt[20..]);
        pkt[20 + 16..20 + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

        pkt
    }

    fn compute_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        let mut sum: u32 = 0;
        sum += u16::from_be_bytes([src[0], src[1]]) as u32;
        sum += u16::from_be_bytes([src[2], src[3]]) as u32;
        sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
        sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
        sum += 6u32; // TCP protocol
        sum += tcp_segment.len() as u32;
        for chunk in tcp_segment.chunks(2) {
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
        let c = !(sum as u16);
        if c == 0 { 0xFFFF } else { c }
    }

    fn verify_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, pkt: &[u8]) -> bool {
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let tcp = &pkt[ihl..];
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        let mut sum: u32 = 0;
        sum += u16::from_be_bytes([src[0], src[1]]) as u32;
        sum += u16::from_be_bytes([src[2], src[3]]) as u32;
        sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
        sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
        sum += 6u32;
        sum += tcp.len() as u32;
        for chunk in tcp.chunks(2) {
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
        sum == 0xffff
    }

    #[test]
    fn test_clamp_mss_basic() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = build_tcp_syn(src, dst, 1460);

        assert!(verify_tcp_checksum(src, dst, &pkt));
        assert!(clamp_mss(&mut pkt, 1360));

        // Verify MSS was clamped.
        let mss_val = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss_val, 1360);

        // Verify checksum still valid.
        assert!(verify_tcp_checksum(src, dst, &pkt));
    }

    #[test]
    fn test_clamp_mss_no_change() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = build_tcp_syn(src, dst, 1360);
        let original = pkt.clone();

        assert!(!clamp_mss(&mut pkt, 1460));
        assert_eq!(pkt, original);
    }

    #[test]
    fn test_clamp_mss_non_syn() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = build_tcp_syn(src, dst, 1460);
        // Clear SYN flag.
        pkt[20 + 13] = 0x10; // ACK only
        let original = pkt.clone();

        assert!(!clamp_mss(&mut pkt, 1360));
        assert_eq!(pkt, original);
    }

    #[test]
    fn test_clamp_mss_syn_ack() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = build_tcp_syn(src, dst, 1460);
        // Set SYN+ACK.
        pkt[20 + 13] = 0x12;
        // Recompute checksum after flag change.
        pkt[20 + 16] = 0;
        pkt[20 + 17] = 0;
        let cksum = compute_tcp_checksum(src, dst, &pkt[20..]);
        pkt[20 + 16..20 + 18].copy_from_slice(&cksum.to_be_bytes());

        assert!(clamp_mss(&mut pkt, 1360));
        let mss_val = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss_val, 1360);
        assert!(verify_tcp_checksum(src, dst, &pkt));
    }

    #[test]
    fn test_clamp_mss_too_short() {
        let mut pkt = vec![0u8; 10];
        assert!(!clamp_mss(&mut pkt, 1360));
    }

    #[test]
    fn test_non_tcp_protocol() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = build_tcp_syn(src, dst, 1460);
        pkt[9] = 17; // UDP
        let original = pkt.clone();
        assert!(!clamp_mss(&mut pkt, 1360));
        assert_eq!(pkt, original);
    }
}

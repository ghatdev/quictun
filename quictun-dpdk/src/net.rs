use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::checksum;

// ── Header sizes ──────────────────────────────────────────────────

const ETH_HLEN: usize = 14;
const IPV4_HLEN: usize = 20; // no options
const UDP_HLEN: usize = 8;

/// Total Eth + IPv4 + UDP header size.
pub const HEADER_SIZE: usize = ETH_HLEN + IPV4_HLEN + UDP_HLEN; // 42

// ── EtherTypes ────────────────────────────────────────────────────

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

// ── ARP constants ─────────────────────────────────────────────────

const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const ARP_PACKET_LEN: usize = 28; // fixed for Ethernet + IPv4

// ── Checksum mode ────────────────────────────────────────────────

/// Checksum offload strategy for TX packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumMode {
    /// Skip UDP checksum entirely (write 0x0000). Valid for IPv4 (RFC 768).
    /// Use `--no-udp-checksum` for benchmarking. IP checksum still computed in software.
    None,
    /// All checksums computed in software (SIMD-optimized).
    Software,
    /// NIC offloads UDP checksum only; IP checksum computed in software.
    /// (e.g., virtio-user: hw_udp_cksum=true, hw_ip_cksum=false)
    HardwareUdpOnly,
    /// NIC offloads both IPv4 header and UDP checksums.
    /// (e.g., physical NICs with full offload support)
    HardwareFull,
}

// ── Identity & ARP table ──────────────────────────────────────────

/// Network identity for this DPDK port.
///
/// Only contains local identity. Remote addresses are resolved via ARP table
/// and tracked per-connection in `ConnectionEntry`.
#[derive(Clone)]
pub struct NetIdentity {
    pub local_mac: [u8; 6],
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
}

/// ARP stale threshold in seconds. Entries older than this are considered stale.
const ARP_STALE_SECS: u64 = 60;

/// A learned ARP entry with a timestamp.
#[derive(Clone)]
struct ArpEntry {
    mac: [u8; 6],
    last_confirmed: Instant,
}

/// ARP table with static and dynamic entries.
///
/// Static entries (from `--dpdk-gateway-mac`) never expire.
/// Learned entries expire after `ARP_STALE_SECS`.
#[derive(Clone)]
pub struct ArpTable {
    static_entries: HashMap<Ipv4Addr, [u8; 6]>,
    entries: HashMap<Ipv4Addr, ArpEntry>,
}

impl ArpTable {
    pub fn new() -> Self {
        Self {
            static_entries: HashMap::new(),
            entries: HashMap::new(),
        }
    }

    /// Insert a static entry (e.g., from --dpdk-gateway-mac). Never expires.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        self.static_entries.insert(ip, mac);
    }

    /// Learn a MAC from an incoming packet.
    pub fn learn(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        self.entries.insert(ip, ArpEntry {
            mac,
            last_confirmed: Instant::now(),
        });
    }

    /// Look up the MAC for an IP. Static entries checked first, then dynamic.
    /// Returns `None` if the dynamic entry is older than `ARP_STALE_SECS`.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<[u8; 6]> {
        if let Some(&mac) = self.static_entries.get(&ip) {
            return Some(mac);
        }
        if let Some(entry) = self.entries.get(&ip) {
            if entry.last_confirmed.elapsed().as_secs() < ARP_STALE_SECS {
                return Some(entry.mac);
            }
        }
        None
    }

    /// Return IPs with dynamic entries older than `threshold_secs` (for ARP refresh).
    pub fn stale_entries(&self, threshold_secs: u64) -> Vec<Ipv4Addr> {
        self.entries
            .iter()
            .filter(|(ip, entry)| {
                // Don't refresh IPs that have static entries.
                !self.static_entries.contains_key(ip)
                    && entry.last_confirmed.elapsed().as_secs() >= threshold_secs
            })
            .map(|(ip, _)| *ip)
            .collect()
    }
}

// ── Parsed packet types ───────────────────────────────────────────

/// A parsed incoming UDP packet (zero-copy references into the mbuf data).
pub struct ParsedUdp<'a> {
    pub src_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    /// ECN codepoint from IP TOS field (low 2 bits).
    pub ecn: Option<quinn_proto::EcnCodepoint>,
}

/// A parsed ARP packet.
pub struct ParsedArp {
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub is_request: bool,
}

/// A parsed non-UDP IPv4 packet (TCP, ICMP, etc.) for router mode.
pub struct ParsedIpv4<'a> {
    pub src_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub ip_header_len: usize,
    /// Full IP packet starting from IP header (i.e., `data[ETH_HLEN..]`).
    pub payload: &'a [u8],
}

/// Result of parsing an Ethernet frame.
pub enum ParsedPacket<'a> {
    Udp(ParsedUdp<'a>),
    /// Non-UDP IPv4 packet (TCP, ICMP, etc.) — only returned by `parse_packet_extended`.
    Ipv4Raw(ParsedIpv4<'a>),
    Arp(ParsedArp),
}

// ── Parsing ───────────────────────────────────────────────────────

/// Parse an Ethernet frame into a UDP packet or ARP packet.
///
/// Returns `None` for frames we don't handle (non-IPv4, non-UDP, etc.).
pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < ETH_HLEN {
        return None;
    }

    let src_mac: [u8; 6] = data[6..12].try_into().expect("slice len checked above");
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4_udp(data, src_mac),
        ETHERTYPE_ARP => parse_arp(data, src_mac),
        _ => None,
    }
}

fn parse_ipv4_udp<'a>(data: &'a [u8], src_mac: [u8; 6]) -> Option<ParsedPacket<'a>> {
    if data.len() < ETH_HLEN + IPV4_HLEN {
        return None;
    }

    let ip = &data[ETH_HLEN..];

    // Version (4 bits) + IHL (4 bits).  We only handle IPv4 with IHL >= 5.
    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HLEN || data.len() < ETH_HLEN + ihl + UDP_HLEN {
        return None;
    }

    // Protocol field: 17 = UDP.
    if ip[9] != 17 {
        return None;
    }

    // Extract ECN from TOS byte (low 2 bits of ip[1]).
    let ecn = quinn_proto::EcnCodepoint::from_bits(ip[1] & 0x03);

    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let udp = &data[ETH_HLEN + ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;

    if udp_len < UDP_HLEN || data.len() < ETH_HLEN + ihl + udp_len {
        return None;
    }

    let payload = &udp[UDP_HLEN..udp_len];

    Some(ParsedPacket::Udp(ParsedUdp {
        src_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
        ecn,
    }))
}

fn parse_arp(data: &[u8], src_mac: [u8; 6]) -> Option<ParsedPacket<'_>> {
    if data.len() < ETH_HLEN + ARP_PACKET_LEN {
        return None;
    }

    let arp = &data[ETH_HLEN..];

    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    let oper = u16::from_be_bytes([arp[6], arp[7]]);

    if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }

    let sender_mac: [u8; 6] = arp[8..14].try_into().expect("slice len checked above");
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    // target MAC at [18..24]
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);

    let _ = src_mac; // already have sender_mac from ARP body

    Some(ParsedPacket::Arp(ParsedArp {
        sender_mac,
        sender_ip,
        target_ip,
        is_request: oper == ARP_OP_REQUEST,
    }))
}

// ── Packet building ───────────────────────────────────────────────

/// Build a complete Eth/IPv4/UDP packet into `buf`.
///
/// Returns the total frame length.  `buf` must be large enough
/// (HEADER_SIZE + payload.len()).
///
/// - `ecn`: ECN codepoint to set in IP TOS (low 2 bits). 0 = Not-ECT.
/// - `ip_id`: IP identification field (wrapping u16 counter).
/// - `checksum_mode`: how to compute UDP (and optionally IPv4) checksum.
pub fn build_udp_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    buf: &mut [u8],
    ecn: u8,
    ip_id: u16,
    checksum_mode: ChecksumMode,
) -> usize {
    let total_len = HEADER_SIZE + payload.len();
    assert!(buf.len() >= total_len);

    // ── Ethernet header (14 bytes) ──
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // ── IPv4 header (20 bytes) ──
    let ip = &mut buf[ETH_HLEN..ETH_HLEN + IPV4_HLEN];
    let ip_total_len = (IPV4_HLEN + UDP_HLEN + payload.len()) as u16;

    ip[0] = 0x45; // version=4, IHL=5 (20 bytes)
    ip[1] = ecn & 0x03; // DSCP=0, ECN from argument
    ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&[0x40, 0x00]); // flags=DF, fragment_offset=0
    ip[8] = 64; // TTL
    ip[9] = 17; // protocol=UDP
    ip[10..12].copy_from_slice(&[0x00, 0x00]); // checksum placeholder
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());

    // IPv4 header checksum: HardwareFull lets the NIC compute it; otherwise software.
    if checksum_mode != ChecksumMode::HardwareFull {
        let cksum = ipv4_checksum(ip);
        ip[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    // ── UDP header (8 bytes) ──
    let udp_offset = ETH_HLEN + IPV4_HLEN;
    let udp_len = (UDP_HLEN + payload.len()) as u16;

    buf[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&[0x00, 0x00]); // checksum placeholder

    // ── Payload ──
    buf[HEADER_SIZE..total_len].copy_from_slice(payload);

    // ── UDP checksum ──
    match checksum_mode {
        ChecksumMode::None => {
            // Leave 0x0000 — valid for IPv4 (RFC 768: "no checksum").
        }
        ChecksumMode::Software => {
            let cksum = checksum::udp_checksum(src_ip, dst_ip, &buf[udp_offset..total_len]);
            buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&cksum.to_be_bytes());
        }
        ChecksumMode::HardwareUdpOnly | ChecksumMode::HardwareFull => {
            // Write pseudo-header seed; NIC adds the UDP segment sum.
            let seed = checksum::udp_pseudo_header_checksum(src_ip, dst_ip, udp_len);
            buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&seed.to_be_bytes());
        }
    }

    total_len
}

/// Write Eth/IP/UDP headers for a packet whose payload is already at `buf[HEADER_SIZE..]`.
///
/// Unlike `build_udp_packet`, this does NOT copy the payload — it only writes the
/// 42-byte header and computes checksums. The caller must ensure the QUIC payload
/// is already at `buf[HEADER_SIZE..HEADER_SIZE + payload_len]`.
pub fn build_udp_packet_inplace(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    buf: &mut [u8],
    ecn: u8,
    ip_id: u16,
    checksum_mode: ChecksumMode,
) -> usize {
    let total_len = HEADER_SIZE + payload_len;
    debug_assert!(buf.len() >= total_len);

    // ── Ethernet header (14 bytes) ──
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // ── IPv4 header (20 bytes) ──
    let ip = &mut buf[ETH_HLEN..ETH_HLEN + IPV4_HLEN];
    let ip_total_len = (IPV4_HLEN + UDP_HLEN + payload_len) as u16;

    ip[0] = 0x45;
    ip[1] = ecn & 0x03;
    ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
    ip[6..8].copy_from_slice(&[0x40, 0x00]);
    ip[8] = 64;
    ip[9] = 17;
    ip[10..12].copy_from_slice(&[0x00, 0x00]);
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());

    // IPv4 header checksum: HardwareFull lets the NIC compute it; otherwise software.
    if checksum_mode != ChecksumMode::HardwareFull {
        let cksum = ipv4_checksum(ip);
        ip[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    // ── UDP header (8 bytes) ──
    let udp_offset = ETH_HLEN + IPV4_HLEN;
    let udp_len = (UDP_HLEN + payload_len) as u16;

    buf[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&[0x00, 0x00]);

    // ── UDP checksum (payload already at buf[HEADER_SIZE..total_len]) ──
    match checksum_mode {
        ChecksumMode::None => {}
        ChecksumMode::Software => {
            let cksum = checksum::udp_checksum(src_ip, dst_ip, &buf[udp_offset..total_len]);
            buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&cksum.to_be_bytes());
        }
        ChecksumMode::HardwareUdpOnly | ChecksumMode::HardwareFull => {
            let seed = checksum::udp_pseudo_header_checksum(src_ip, dst_ip, udp_len);
            buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&seed.to_be_bytes());
        }
    }

    total_len
}

/// Build an ARP reply Ethernet frame.
///
/// Returns the complete frame as a `Vec<u8>`.
pub fn build_arp_reply(request: &ParsedArp, local_mac: [u8; 6], local_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![0u8; ETH_HLEN + ARP_PACKET_LEN];

    // Ethernet header.
    frame[0..6].copy_from_slice(&request.sender_mac); // dst = requester
    frame[6..12].copy_from_slice(&local_mac); // src = us
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    // ARP body.
    let arp = &mut frame[ETH_HLEN..];
    arp[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    arp[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    arp[4] = 6; // hardware address length
    arp[5] = 4; // protocol address length
    arp[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    arp[8..14].copy_from_slice(&local_mac); // sender hardware address
    arp[14..18].copy_from_slice(&local_ip.octets()); // sender protocol address
    arp[18..24].copy_from_slice(&request.sender_mac); // target hardware address
    arp[24..28].copy_from_slice(&request.sender_ip.octets()); // target protocol address

    frame
}

/// Build an ARP request Ethernet frame.
///
/// Used to resolve the peer's MAC before QUIC handshake.
pub fn build_arp_request(local_mac: [u8; 6], local_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![0u8; ETH_HLEN + ARP_PACKET_LEN];

    // Ethernet header: broadcast.
    frame[0..6].copy_from_slice(&[0xff; 6]); // broadcast
    frame[6..12].copy_from_slice(&local_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    // ARP body.
    let arp = &mut frame[ETH_HLEN..];
    arp[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    arp[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes());
    arp[8..14].copy_from_slice(&local_mac);
    arp[14..18].copy_from_slice(&local_ip.octets());
    arp[18..24].copy_from_slice(&[0x00; 6]); // unknown target MAC
    arp[24..28].copy_from_slice(&target_ip.octets());

    frame
}

// ── Extended parsing (router mode) ─────────────────────────────────

/// Parse an Ethernet frame, returning `Ipv4Raw` for non-UDP IPv4 packets.
///
/// Unlike `parse_packet`, this does NOT discard non-UDP IPv4 frames.
/// Used by router mode to handle return traffic (TCP, ICMP, etc.).
pub fn parse_packet_extended(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < ETH_HLEN {
        return None;
    }

    let src_mac: [u8; 6] = data[6..12].try_into().expect("slice len checked above");
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4_extended(data, src_mac),
        ETHERTYPE_ARP => parse_arp(data, src_mac),
        _ => None,
    }
}

/// Parse IPv4: UDP → ParsedUdp, other protocols → ParsedIpv4 (raw).
fn parse_ipv4_extended<'a>(data: &'a [u8], src_mac: [u8; 6]) -> Option<ParsedPacket<'a>> {
    if data.len() < ETH_HLEN + IPV4_HLEN {
        return None;
    }

    let ip = &data[ETH_HLEN..];

    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HLEN || data.len() < ETH_HLEN + ihl {
        return None;
    }

    let protocol = ip[9];
    let ttl = ip[8];
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    if protocol == 17 {
        // UDP — parse as before.
        if data.len() < ETH_HLEN + ihl + UDP_HLEN {
            return None;
        }
        let ecn = quinn_proto::EcnCodepoint::from_bits(ip[1] & 0x03);
        let udp = &data[ETH_HLEN + ihl..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;

        if udp_len < UDP_HLEN || data.len() < ETH_HLEN + ihl + udp_len {
            return None;
        }
        let payload = &udp[UDP_HLEN..udp_len];
        Some(ParsedPacket::Udp(ParsedUdp {
            src_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
            ecn,
        }))
    } else {
        // Non-UDP: TCP, ICMP, etc.
        Some(ParsedPacket::Ipv4Raw(ParsedIpv4 {
            src_mac,
            src_ip,
            dst_ip,
            protocol,
            ttl,
            ip_header_len: ihl,
            payload: &data[ETH_HLEN..],
        }))
    }
}

/// Rewrite an Ethernet + IPv4 frame in-place for plaintext forwarding.
///
/// - Replaces src/dst MAC
/// - Decrements TTL
/// - Fixes IP header checksum incrementally
///
/// Returns `false` if TTL would reach 0 (should send ICMP Time Exceeded instead).
pub fn build_ipv4_forward_inplace(
    data: &mut [u8],
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
) -> bool {
    if data.len() < ETH_HLEN + IPV4_HLEN {
        return false;
    }

    let ttl = data[ETH_HLEN + 8];
    if ttl <= 1 {
        return false;
    }

    // Rewrite Ethernet header.
    data[0..6].copy_from_slice(dst_mac);
    data[6..12].copy_from_slice(src_mac);

    // Decrement TTL.
    let new_ttl = ttl - 1;
    data[ETH_HLEN + 8] = new_ttl;

    // Incremental IP checksum update for TTL change (RFC 1624).
    // TTL is at byte offset 8 in IP header. It's the high byte of the u16 word at offset 8.
    let old_word = u16::from_be_bytes([ttl, data[ETH_HLEN + 9]]);
    let new_word = u16::from_be_bytes([new_ttl, data[ETH_HLEN + 9]]);
    let old_cksum = u16::from_be_bytes([data[ETH_HLEN + 10], data[ETH_HLEN + 11]]);

    let mut sum: i32 = !(old_cksum) as u16 as i32;
    sum += !(old_word) as u16 as i32;
    sum += new_word as i32;
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum < 0 {
        sum += 0x10000;
    }
    let new_cksum = !(sum as u16);
    data[ETH_HLEN + 10..ETH_HLEN + 12].copy_from_slice(&new_cksum.to_be_bytes());

    true
}

// ── Checksums ─────────────────────────────────────────────────────

/// RFC 1071 Internet checksum over an IPv4 header.
///
/// Delegates to the optimized `checksum` module.
fn ipv4_checksum(header: &[u8]) -> u16 {
    checksum::internet_checksum(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_checksum() {
        // Example from RFC 1071: checksum of a simple header.
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[8] = 64; // TTL
        hdr[9] = 17; // UDP
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        hdr[12..16].copy_from_slice(&src.octets());
        hdr[16..20].copy_from_slice(&dst.octets());
        let total_len: u16 = 20 + 8 + 10;
        hdr[2..4].copy_from_slice(&total_len.to_be_bytes());

        let cksum = ipv4_checksum(&hdr);
        // Verify the checksum: recomputing over the header with checksum should yield 0.
        hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
        assert_eq!(ipv4_checksum(&hdr), 0);
    }

    #[test]
    fn test_build_and_parse_udp() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip = Ipv4Addr::new(192, 168, 100, 10);
        let dst_ip = Ipv4Addr::new(192, 168, 100, 11);
        let payload = b"hello quictun";

        let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
        let len = build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            4433,
            5000,
            payload,
            &mut buf,
            0,
            0,
            ChecksumMode::Software,
        );

        assert_eq!(len, HEADER_SIZE + payload.len());

        let parsed = parse_packet(&buf[..len]).expect("should parse");
        match parsed {
            ParsedPacket::Udp(udp) => {
                assert_eq!(udp.src_mac, src_mac);
                assert_eq!(udp.src_ip, src_ip);
                assert_eq!(udp.dst_ip, dst_ip);
                assert_eq!(udp.src_port, 4433);
                assert_eq!(udp.dst_port, 5000);
                assert_eq!(udp.payload, payload);
                assert_eq!(udp.ecn, None); // ECN=0 means Not-ECT
            }
            _ => panic!("expected UDP packet"),
        }
    }

    #[test]
    fn test_ecn_round_trip() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let payload = b"ecn test";

        // ECT(0) = 0b10 = 2
        let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
        let len = build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            1000,
            2000,
            payload,
            &mut buf,
            0x02,
            42,
            ChecksumMode::Software,
        );

        let parsed = parse_packet(&buf[..len]).expect("should parse");
        match parsed {
            ParsedPacket::Udp(udp) => {
                assert_eq!(udp.ecn, Some(quinn_proto::EcnCodepoint::Ect0));
            }
            _ => panic!("expected UDP packet"),
        }

        // CE = 0b11 = 3
        let len = build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            1000,
            2000,
            payload,
            &mut buf,
            0x03,
            43,
            ChecksumMode::Software,
        );
        let parsed = parse_packet(&buf[..len]).expect("should parse");
        match parsed {
            ParsedPacket::Udp(udp) => {
                assert_eq!(udp.ecn, Some(quinn_proto::EcnCodepoint::Ce));
            }
            _ => panic!("expected UDP packet"),
        }
    }

    #[test]
    fn test_udp_checksum() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip = Ipv4Addr::new(192, 168, 100, 10);
        let dst_ip = Ipv4Addr::new(192, 168, 100, 11);
        let payload = b"checksum test payload";

        let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
        let len = build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            4433,
            5000,
            payload,
            &mut buf,
            0,
            1,
            ChecksumMode::Software,
        );

        // UDP checksum should be non-zero.
        let udp_offset = ETH_HLEN + IPV4_HLEN;
        let cksum = u16::from_be_bytes([buf[udp_offset + 6], buf[udp_offset + 7]]);
        assert_ne!(cksum, 0, "UDP checksum should be non-zero");

        // Verify: packet still parses correctly.
        let parsed = parse_packet(&buf[..len]).expect("should parse with checksum");
        assert!(matches!(parsed, ParsedPacket::Udp(_)));
    }

    #[test]
    fn test_checksum_mode_none() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip = Ipv4Addr::new(192, 168, 100, 10);
        let dst_ip = Ipv4Addr::new(192, 168, 100, 11);
        let payload = b"no checksum";

        let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
        let len = build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            4433,
            5000,
            payload,
            &mut buf,
            0,
            1,
            ChecksumMode::None,
        );

        // UDP checksum field should be 0x0000.
        let udp_offset = ETH_HLEN + IPV4_HLEN;
        let cksum = u16::from_be_bytes([buf[udp_offset + 6], buf[udp_offset + 7]]);
        assert_eq!(cksum, 0, "UDP checksum should be zero in None mode");

        // IPv4 checksum should still be computed.
        let ip_cksum = u16::from_be_bytes([buf[ETH_HLEN + 10], buf[ETH_HLEN + 11]]);
        assert_ne!(ip_cksum, 0, "IPv4 checksum should be non-zero");

        // Packet should still parse.
        let parsed = parse_packet(&buf[..len]).expect("should parse");
        assert!(matches!(parsed, ParsedPacket::Udp(_)));
    }

    #[test]
    fn test_checksum_mode_hw_offload() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip = Ipv4Addr::new(192, 168, 100, 10);
        let dst_ip = Ipv4Addr::new(192, 168, 100, 11);
        let payload = b"hw offload";

        let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
        let len = build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            4433,
            5000,
            payload,
            &mut buf,
            0,
            1,
            ChecksumMode::HardwareFull,
        );

        // IPv4 checksum should be 0x0000 (NIC computes).
        let ip_cksum = u16::from_be_bytes([buf[ETH_HLEN + 10], buf[ETH_HLEN + 11]]);
        assert_eq!(ip_cksum, 0, "IPv4 checksum should be zero (HW offload)");

        // UDP checksum should contain the pseudo-header seed (non-zero).
        let udp_offset = ETH_HLEN + IPV4_HLEN;
        let udp_cksum = u16::from_be_bytes([buf[udp_offset + 6], buf[udp_offset + 7]]);
        assert_ne!(udp_cksum, 0, "pseudo-header seed should be non-zero");

        // Verify the seed matches what udp_pseudo_header_checksum computes.
        let udp_len = (UDP_HLEN + payload.len()) as u16;
        let expected_seed = checksum::udp_pseudo_header_checksum(src_ip, dst_ip, udp_len);
        assert_eq!(udp_cksum, expected_seed);

        // Packet should still parse (structure is valid even without final checksum).
        assert_eq!(len, HEADER_SIZE + payload.len());
    }

    #[test]
    fn test_ip_id_nonzero() {
        let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let payload = b"id test";

        let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
        build_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            dst_ip,
            1000,
            2000,
            payload,
            &mut buf,
            0,
            0x1234,
            ChecksumMode::Software,
        );

        // IP identification at bytes [ETH_HLEN + 4 .. ETH_HLEN + 6]
        let ip_id = u16::from_be_bytes([buf[ETH_HLEN + 4], buf[ETH_HLEN + 5]]);
        assert_eq!(ip_id, 0x1234);
    }

    #[test]
    fn test_arp_round_trip() {
        let local_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let local_ip = Ipv4Addr::new(192, 168, 100, 10);
        let target_ip = Ipv4Addr::new(192, 168, 100, 11);

        // Build and parse ARP request.
        let request_frame = build_arp_request(local_mac, local_ip, target_ip);
        let parsed = parse_packet(&request_frame).expect("should parse ARP");
        match parsed {
            ParsedPacket::Arp(arp) => {
                assert!(arp.is_request);
                assert_eq!(arp.sender_mac, local_mac);
                assert_eq!(arp.sender_ip, local_ip);
                assert_eq!(arp.target_ip, target_ip);
            }
            _ => panic!("expected ARP"),
        }
    }
}

//! NAT conntrack table with port allocation and incremental checksum updates.
//!
//! Per-core design: each worker core owns its own `NatTable` (no locking).
//! Supports TCP, UDP, and ICMP with protocol-specific timeouts.

use std::net::Ipv4Addr;
use std::time::Instant;

use rustc_hash::FxHashMap;

/// IP protocol numbers.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

/// Timeouts per protocol.
const TCP_TIMEOUT_SECS: u64 = 300;
const UDP_TIMEOUT_SECS: u64 = 30;
const ICMP_TIMEOUT_SECS: u64 = 10;

/// First port in the NAT port range.
const NAT_PORT_START: u16 = 1024;
/// Last port (inclusive) in the NAT port range.
const NAT_PORT_END: u16 = 65534;

/// Forward lookup key: identifies a unique connection from a peer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatForwardKey {
    pub proto: u8,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// Reverse lookup key: identifies return traffic by protocol + NAT port.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct NatReverseKey {
    proto: u8,
    nat_port: u16,
    /// Remote IP (the internet host's IP) — needed to disambiguate when
    /// multiple connections share the same nat_port for different destinations.
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

/// A single NAT connection tracking entry.
pub struct NatEntry {
    pub forward_key: NatForwardKey,
    pub nat_port: u16,
    pub peer_cid: u64,
    pub peer_tunnel_ip: Ipv4Addr,
    pub last_seen: Instant,
    reverse_key: NatReverseKey,
}

/// Result of a forward NAT lookup (SNAT).
pub struct SnatResult {
    /// The allocated NAT source port.
    pub nat_port: u16,
    /// The peer's tunnel IP (for reverse path).
    pub peer_tunnel_ip: Ipv4Addr,
    /// The peer's connection ID (for encryption on reverse path).
    pub peer_cid: u64,
}

/// Result of a reverse NAT lookup (DNAT).
pub struct DnatResult {
    /// Original source IP of the peer (to restore as destination).
    pub orig_src_ip: Ipv4Addr,
    /// Original source port of the peer.
    pub orig_src_port: u16,
    /// Original destination IP the peer wanted.
    pub orig_dst_ip: Ipv4Addr,
    /// Original destination port.
    pub orig_dst_port: u16,
    /// Peer CID for encrypting the return packet.
    pub peer_cid: u64,
    /// Peer tunnel IP for routing.
    pub peer_tunnel_ip: Ipv4Addr,
}

/// NAT connection tracking table.
///
/// Designed to be owned by a single core (no Mutex).
pub struct NatTable {
    forward: FxHashMap<NatForwardKey, usize>,
    reverse: FxHashMap<NatReverseKey, usize>,
    entries: Vec<Option<NatEntry>>,
    free_indices: Vec<usize>,
    next_port: u16,
    port_start: u16,
    port_end: u16,
    /// The local (NAT) IP address used as the source for outbound packets.
    pub local_ip: Ipv4Addr,
}

impl NatTable {
    /// Create a new NAT table using the full port range.
    ///
    /// `local_ip` is the IP address used as source for SNAT'd packets.
    pub fn new(local_ip: Ipv4Addr) -> Self {
        Self {
            forward: FxHashMap::default(),
            reverse: FxHashMap::default(),
            entries: Vec::new(),
            free_indices: Vec::new(),
            next_port: NAT_PORT_START,
            port_start: NAT_PORT_START,
            port_end: NAT_PORT_END,
            local_ip,
        }
    }

    /// Create a NAT table with a restricted port range.
    ///
    /// Used in multi-core router mode where each worker gets a disjoint range.
    pub fn with_port_range(local_ip: Ipv4Addr, port_start: u16, port_end: u16) -> Self {
        Self {
            forward: FxHashMap::default(),
            reverse: FxHashMap::default(),
            entries: Vec::new(),
            free_indices: Vec::new(),
            next_port: port_start,
            port_start,
            port_end,
            local_ip,
        }
    }

    /// Look up or create a forward NAT mapping (SNAT).
    ///
    /// Returns the NAT source port to use for the outbound packet.
    pub fn lookup_or_create(
        &mut self,
        key: &NatForwardKey,
        peer_cid: u64,
        peer_tunnel_ip: Ipv4Addr,
        now: Instant,
    ) -> Option<SnatResult> {
        // Fast path: existing mapping.
        if let Some(&idx) = self.forward.get(key)
            && let Some(entry) = &mut self.entries[idx]
        {
            entry.last_seen = now;
            return Some(SnatResult {
                nat_port: entry.nat_port,
                peer_tunnel_ip: entry.peer_tunnel_ip,
                peer_cid: entry.peer_cid,
            });
        }

        // Allocate a new NAT port.
        let nat_port = self.allocate_port(key.proto, key.dst_ip, key.dst_port)?;

        let reverse_key = NatReverseKey {
            proto: key.proto,
            nat_port,
            remote_ip: key.dst_ip,
            remote_port: key.dst_port,
        };

        let entry = NatEntry {
            forward_key: *key,
            nat_port,
            peer_cid,
            peer_tunnel_ip,
            last_seen: now,
            reverse_key,
        };

        let idx = if let Some(free_idx) = self.free_indices.pop() {
            self.entries[free_idx] = Some(entry);
            free_idx
        } else {
            let idx = self.entries.len();
            self.entries.push(Some(entry));
            idx
        };

        self.forward.insert(*key, idx);
        self.reverse.insert(reverse_key, idx);

        Some(SnatResult {
            nat_port,
            peer_tunnel_ip,
            peer_cid,
        })
    }

    /// Look up a reverse NAT mapping (DNAT) for return traffic.
    ///
    /// `proto`, `dst_port` are from the incoming return packet (dst_port = our NAT port).
    /// `src_ip`, `src_port` are the remote host's address.
    pub fn lookup_reverse(
        &mut self,
        proto: u8,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        now: Instant,
    ) -> Option<DnatResult> {
        let key = NatReverseKey {
            proto,
            nat_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
        };
        let &idx = self.reverse.get(&key)?;
        let entry = self.entries[idx].as_mut()?;
        entry.last_seen = now;
        Some(DnatResult {
            orig_src_ip: entry.forward_key.src_ip,
            orig_src_port: entry.forward_key.src_port,
            orig_dst_ip: entry.forward_key.dst_ip,
            orig_dst_port: entry.forward_key.dst_port,
            peer_cid: entry.peer_cid,
            peer_tunnel_ip: entry.peer_tunnel_ip,
        })
    }

    /// Sweep expired entries.
    pub fn sweep(&mut self, now: Instant) {
        for idx in 0..self.entries.len() {
            let expired = if let Some(entry) = &self.entries[idx] {
                let timeout_secs = match entry.forward_key.proto {
                    IPPROTO_TCP => TCP_TIMEOUT_SECS,
                    IPPROTO_UDP => UDP_TIMEOUT_SECS,
                    IPPROTO_ICMP => ICMP_TIMEOUT_SECS,
                    _ => UDP_TIMEOUT_SECS,
                };
                now.duration_since(entry.last_seen).as_secs() >= timeout_secs
            } else {
                false
            };

            if expired {
                let entry = self.entries[idx].take().expect("checked above");
                self.forward.remove(&entry.forward_key);
                self.reverse.remove(&entry.reverse_key);
                self.free_indices.push(idx);
            }
        }
    }

    /// Number of active entries.
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Allocate a NAT port, avoiding collisions.
    fn allocate_port(&mut self, proto: u8, remote_ip: Ipv4Addr, remote_port: u16) -> Option<u16> {
        let range_size = (self.port_end - self.port_start + 1) as u32;
        for _ in 0..range_size {
            let port = self.next_port;
            self.next_port = if self.next_port >= self.port_end {
                self.port_start
            } else {
                self.next_port + 1
            };

            let candidate = NatReverseKey {
                proto,
                nat_port: port,
                remote_ip,
                remote_port,
            };
            if !self.reverse.contains_key(&candidate) {
                return Some(port);
            }
        }
        None // port exhaustion
    }
}

/// Compute disjoint NAT port ranges for `n_workers` cores.
///
/// Returns a vector of `(port_start, port_end)` tuples (inclusive).
pub fn compute_port_ranges(n_workers: usize) -> Vec<(u16, u16)> {
    let total = (NAT_PORT_END - NAT_PORT_START + 1) as usize;
    let per_worker = total / n_workers;
    let mut ranges = Vec::with_capacity(n_workers);
    for i in 0..n_workers {
        let start = NAT_PORT_START + (i * per_worker) as u16;
        let end = if i == n_workers - 1 {
            NAT_PORT_END
        } else {
            start + per_worker as u16 - 1
        };
        ranges.push((start, end));
    }
    ranges
}

/// Determine which worker owns a given NAT port.
///
/// Used by the dispatcher to route return traffic to the correct worker.
pub fn worker_for_port(port: u16, n_workers: usize) -> Option<usize> {
    if !(NAT_PORT_START..=NAT_PORT_END).contains(&port) {
        return None;
    }
    let total = (NAT_PORT_END - NAT_PORT_START + 1) as usize;
    let per_worker = total / n_workers;
    let offset = (port - NAT_PORT_START) as usize;
    let worker = offset / per_worker;
    // Last worker absorbs the remainder.
    Some(worker.min(n_workers - 1))
}

/// Apply SNAT to an IPv4 packet in-place.
///
/// Rewrites source IP to `nat_ip` and source port to `nat_port`.
/// Fixes IP and L4 checksums incrementally.
///
/// `packet` starts at the IPv4 header.
pub fn apply_snat(packet: &mut [u8], nat_ip: Ipv4Addr, nat_port: u16) {
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let proto = packet[9];
    let old_src_ip = [packet[12], packet[13], packet[14], packet[15]];
    let new_src_ip = nat_ip.octets();

    // Rewrite source IP.
    packet[12..16].copy_from_slice(&new_src_ip);

    // Fix IP header checksum.
    fix_ip_checksum_for_addr_change(packet, &old_src_ip, &new_src_ip);

    // Rewrite L4 source port and fix L4 checksum.
    if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        let l4_start = ihl;
        if packet.len() >= l4_start + 8 {
            let old_port = u16::from_be_bytes([packet[l4_start], packet[l4_start + 1]]);
            packet[l4_start..l4_start + 2].copy_from_slice(&nat_port.to_be_bytes());

            let cksum_off = if proto == IPPROTO_TCP {
                l4_start + 16
            } else {
                l4_start + 6
            };
            fix_l4_checksum(packet, cksum_off, &old_src_ip, &new_src_ip, old_port, nat_port, proto);
        }
    }
}

/// Apply DNAT to an IPv4 packet in-place.
///
/// Rewrites destination IP to `orig_src_ip` and destination port to `orig_src_port`.
/// This restores the original source of the peer as the new destination.
///
/// `packet` starts at the IPv4 header.
pub fn apply_dnat(packet: &mut [u8], orig_src_ip: Ipv4Addr, orig_src_port: u16) {
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let proto = packet[9];
    let old_dst_ip = [packet[16], packet[17], packet[18], packet[19]];
    let new_dst_ip = orig_src_ip.octets();

    // Rewrite destination IP.
    packet[16..20].copy_from_slice(&new_dst_ip);

    // Fix IP header checksum.
    fix_ip_checksum_for_addr_change(packet, &old_dst_ip, &new_dst_ip);

    // Rewrite L4 destination port and fix L4 checksum.
    if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        let l4_start = ihl;
        if packet.len() >= l4_start + 8 {
            let old_port = u16::from_be_bytes([packet[l4_start + 2], packet[l4_start + 3]]);
            packet[l4_start + 2..l4_start + 4].copy_from_slice(&orig_src_port.to_be_bytes());

            let cksum_off = if proto == IPPROTO_TCP {
                l4_start + 16
            } else {
                l4_start + 6
            };
            fix_l4_checksum(packet, cksum_off, &old_dst_ip, &new_dst_ip, old_port, orig_src_port, proto);
        }
    }
}

/// Incrementally fix IP header checksum after an address change.
fn fix_ip_checksum_for_addr_change(packet: &mut [u8], old_addr: &[u8; 4], new_addr: &[u8; 4]) {
    let old_cksum = u16::from_be_bytes([packet[10], packet[11]]);
    let mut sum: i32 = (!old_cksum) as i32;

    // Subtract old address words, add new address words.
    let old_w0 = u16::from_be_bytes([old_addr[0], old_addr[1]]);
    let old_w1 = u16::from_be_bytes([old_addr[2], old_addr[3]]);
    let new_w0 = u16::from_be_bytes([new_addr[0], new_addr[1]]);
    let new_w1 = u16::from_be_bytes([new_addr[2], new_addr[3]]);

    sum += (!old_w0) as i32;
    sum += new_w0 as i32;
    sum += (!old_w1) as i32;
    sum += new_w1 as i32;

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum < 0 {
        sum += 0x10000;
    }

    let new_cksum = !(sum as u16);
    packet[10..12].copy_from_slice(&new_cksum.to_be_bytes());
}

/// Incrementally fix L4 checksum after IP + port changes.
fn fix_l4_checksum(
    packet: &mut [u8],
    cksum_off: usize,
    old_addr: &[u8; 4],
    new_addr: &[u8; 4],
    old_port: u16,
    new_port: u16,
    proto: u8,
) {
    if cksum_off + 2 > packet.len() {
        return;
    }

    let old_cksum = u16::from_be_bytes([packet[cksum_off], packet[cksum_off + 1]]);

    // UDP checksum 0 means "no checksum" — leave it.
    if proto == IPPROTO_UDP && old_cksum == 0 {
        return;
    }

    let mut sum: i32 = (!old_cksum) as i32;

    // IP address change (pseudo-header).
    let old_w0 = u16::from_be_bytes([old_addr[0], old_addr[1]]);
    let old_w1 = u16::from_be_bytes([old_addr[2], old_addr[3]]);
    let new_w0 = u16::from_be_bytes([new_addr[0], new_addr[1]]);
    let new_w1 = u16::from_be_bytes([new_addr[2], new_addr[3]]);

    sum += (!old_w0) as i32;
    sum += new_w0 as i32;
    sum += (!old_w1) as i32;
    sum += new_w1 as i32;

    // Port change.
    sum += (!old_port) as i32;
    sum += new_port as i32;

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum < 0 {
        sum += 0x10000;
    }

    let new_cksum = !(sum as u16);
    // RFC 768: if computed checksum is 0, write 0xFFFF for UDP.
    let final_cksum = if proto == IPPROTO_UDP && new_cksum == 0 {
        0xFFFF
    } else {
        new_cksum
    };
    packet[cksum_off..cksum_off + 2].copy_from_slice(&final_cksum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_nat_forward_reverse_roundtrip() {
        let mut table = NatTable::new(Ipv4Addr::new(192, 168, 100, 10));
        let now = Instant::now();

        let key = NatForwardKey {
            proto: IPPROTO_TCP,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 54321,
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            dst_port: 443,
        };

        let result = table
            .lookup_or_create(&key, 42, Ipv4Addr::new(10, 0, 0, 2), now)
            .expect("should allocate");

        assert!(result.nat_port >= NAT_PORT_START);

        // Reverse lookup.
        let dnat = table
            .lookup_reverse(IPPROTO_TCP, result.nat_port, Ipv4Addr::new(8, 8, 8, 8), 443, now)
            .expect("reverse should exist");

        assert_eq!(dnat.orig_src_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(dnat.orig_src_port, 54321);
        assert_eq!(dnat.peer_cid, 42);
    }

    #[test]
    fn test_nat_idempotent_forward() {
        let mut table = NatTable::new(Ipv4Addr::new(192, 168, 100, 10));
        let now = Instant::now();

        let key = NatForwardKey {
            proto: IPPROTO_UDP,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 53,
        };

        let r1 = table.lookup_or_create(&key, 1, Ipv4Addr::new(10, 0, 0, 2), now).unwrap();
        let r2 = table.lookup_or_create(&key, 1, Ipv4Addr::new(10, 0, 0, 2), now).unwrap();
        assert_eq!(r1.nat_port, r2.nat_port);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_nat_sweep_expired() {
        let mut table = NatTable::new(Ipv4Addr::new(192, 168, 100, 10));
        let now = Instant::now();

        let key = NatForwardKey {
            proto: IPPROTO_ICMP,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 0,
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            dst_port: 0,
        };

        table.lookup_or_create(&key, 1, Ipv4Addr::new(10, 0, 0, 2), now);
        assert_eq!(table.len(), 1);

        // Sweep with time past ICMP timeout.
        let later = now + Duration::from_secs(ICMP_TIMEOUT_SECS + 1);
        table.sweep(later);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_nat_tcp_not_expired_early() {
        let mut table = NatTable::new(Ipv4Addr::new(192, 168, 100, 10));
        let now = Instant::now();

        let key = NatForwardKey {
            proto: IPPROTO_TCP,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 54321,
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            dst_port: 443,
        };

        table.lookup_or_create(&key, 1, Ipv4Addr::new(10, 0, 0, 2), now);

        // Sweep at 30s — should not expire TCP (300s timeout).
        let later = now + Duration::from_secs(30);
        table.sweep(later);
        assert_eq!(table.len(), 1);
    }

    /// Build a minimal UDP packet (IP header + UDP header) for checksum testing.
    fn build_udp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_total = 20 + udp_len;
        let mut pkt = vec![0u8; ip_total];

        // IPv4 header.
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IPPROTO_UDP;
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&dst_ip.octets());

        // IP checksum.
        let ip_cksum = compute_ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // UDP header.
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[28..28 + payload.len()].copy_from_slice(payload);

        // UDP checksum.
        let udp_cksum = compute_udp_checksum(src_ip, dst_ip, &pkt[20..]);
        pkt[26..28].copy_from_slice(&udp_cksum.to_be_bytes());

        pkt
    }

    fn compute_ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in header.chunks(2) {
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

    fn verify_ip_checksum(header: &[u8]) -> bool {
        compute_ip_checksum(header) == 0
    }

    fn compute_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        let mut sum: u32 = 0;
        sum += u16::from_be_bytes([src[0], src[1]]) as u32;
        sum += u16::from_be_bytes([src[2], src[3]]) as u32;
        sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
        sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
        sum += IPPROTO_UDP as u32;
        sum += udp_segment.len() as u32;
        for chunk in udp_segment.chunks(2) {
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

    fn verify_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, pkt: &[u8]) -> bool {
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let udp = &pkt[ihl..];
        let cksum = u16::from_be_bytes([udp[6], udp[7]]);
        if cksum == 0 {
            return true; // no checksum
        }
        // When checksum is correct, one's complement sum over entire UDP segment
        // (including checksum field) + pseudo-header = 0xFFFF.
        // compute_udp_checksum complements and maps 0→0xFFFF, so correct = 0xFFFF.
        compute_udp_checksum(src_ip, dst_ip, udp) == 0xFFFF
    }

    #[test]
    fn test_snat_checksum() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let nat_ip = Ipv4Addr::new(192, 168, 100, 10);
        let mut pkt = build_udp_packet(src, dst, 54321, 53, b"dns query");

        assert!(verify_ip_checksum(&pkt[..20]));
        assert!(verify_udp_checksum(src, dst, &pkt));

        apply_snat(&mut pkt, nat_ip, 2000);

        // Source IP should now be nat_ip.
        let new_src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        assert_eq!(new_src, nat_ip);

        // Source port should be 2000.
        let new_port = u16::from_be_bytes([pkt[20], pkt[21]]);
        assert_eq!(new_port, 2000);

        // Checksums should still be valid.
        assert!(verify_ip_checksum(&pkt[..20]));
        assert!(verify_udp_checksum(nat_ip, dst, &pkt));
    }

    #[test]
    fn test_dnat_checksum() {
        let src = Ipv4Addr::new(8, 8, 8, 8);
        let dst = Ipv4Addr::new(192, 168, 100, 10);
        let orig_peer = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = build_udp_packet(src, dst, 53, 2000, b"dns reply");

        assert!(verify_ip_checksum(&pkt[..20]));
        assert!(verify_udp_checksum(src, dst, &pkt));

        apply_dnat(&mut pkt, orig_peer, 54321);

        // Destination IP should now be the original peer.
        let new_dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        assert_eq!(new_dst, orig_peer);

        // Destination port should be restored.
        let new_port = u16::from_be_bytes([pkt[22], pkt[23]]);
        assert_eq!(new_port, 54321);

        // Checksums should still be valid.
        assert!(verify_ip_checksum(&pkt[..20]));
        assert!(verify_udp_checksum(src, orig_peer, &pkt));
    }

    #[test]
    fn test_port_range_nat() {
        let mut table = NatTable::with_port_range(Ipv4Addr::new(192, 168, 1, 1), 1024, 2023);
        let now = Instant::now();

        let key = NatForwardKey {
            proto: IPPROTO_TCP,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 54321,
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            dst_port: 443,
        };

        let result = table
            .lookup_or_create(&key, 1, Ipv4Addr::new(10, 0, 0, 2), now)
            .expect("should allocate");

        assert!(result.nat_port >= 1024 && result.nat_port <= 2023);
    }

    #[test]
    fn test_compute_port_ranges_2_workers() {
        let ranges = compute_port_ranges(2);
        assert_eq!(ranges.len(), 2);
        // Ranges should be disjoint and contiguous.
        assert_eq!(ranges[0].0, NAT_PORT_START);
        assert_eq!(ranges[0].1 + 1, ranges[1].0);
        assert_eq!(ranges[1].1, NAT_PORT_END);
    }

    #[test]
    fn test_compute_port_ranges_4_workers() {
        let ranges = compute_port_ranges(4);
        assert_eq!(ranges.len(), 4);
        for i in 0..3 {
            assert_eq!(ranges[i].1 + 1, ranges[i + 1].0);
        }
        assert_eq!(ranges[3].1, NAT_PORT_END);
    }

    #[test]
    fn test_worker_for_port() {
        let n = 2;
        let ranges = compute_port_ranges(n);
        // First port of first worker.
        assert_eq!(worker_for_port(ranges[0].0, n), Some(0));
        // Last port of first worker.
        assert_eq!(worker_for_port(ranges[0].1, n), Some(0));
        // First port of second worker.
        assert_eq!(worker_for_port(ranges[1].0, n), Some(1));
        // Last port (NAT_PORT_END) should be last worker.
        assert_eq!(worker_for_port(NAT_PORT_END, n), Some(1));
        // Port below range.
        assert_eq!(worker_for_port(1023, n), None);
    }
}

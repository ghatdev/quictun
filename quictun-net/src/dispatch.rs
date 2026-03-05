//! Dispatch table and per-worker channel bundles for multi-core quictun-net.
//!
//! Thread 0 (dispatcher) owns the `NetDispatchTable` and routes packets to
//! worker threads via crossbeam-channel. Workers own `LocalConnectionState`
//! per connection — no Mutex/atomics in the data plane.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use quictun_quic::local::LocalConnectionState;

/// Channel capacity (matches DPDK ring size).
const CHANNEL_CAPACITY: usize = 4096;

/// An outer (UDP) packet dispatched from dispatcher to worker.
pub struct OuterPacket {
    pub data: Vec<u8>,
    pub from: SocketAddr,
}

/// An inner (TUN) packet dispatched from dispatcher to worker.
pub struct InnerPacket {
    pub data: Vec<u8>,
}

/// Dispatcher → worker control message.
#[allow(clippy::large_enum_variant)]
pub enum ControlMessage {
    /// Assign a new connection to this worker.
    AddConnection {
        conn: LocalConnectionState,
        tunnel_ip: Ipv4Addr,
        allowed_ips: Vec<ipnet::Ipv4Net>,
        remote_addr: SocketAddr,
        keepalive_interval: Duration,
    },
    /// Graceful shutdown: send CONNECTION_CLOSE to all connections and exit.
    Shutdown,
}

/// Removed connection notification from worker to dispatcher.
pub struct RemovedConnection {
    pub cid: Vec<u8>,
    pub tunnel_ip: Ipv4Addr,
}

/// Per-worker channel bundle.
pub struct WorkerChannels {
    pub outer_tx: Sender<OuterPacket>,
    pub outer_rx: Receiver<OuterPacket>,
    pub inner_tx: Sender<InnerPacket>,
    pub inner_rx: Receiver<InnerPacket>,
    pub control: Mutex<Vec<ControlMessage>>,
}

impl Default for WorkerChannels {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerChannels {
    pub fn new() -> Self {
        let (outer_tx, outer_rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let (inner_tx, inner_rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        Self {
            outer_tx,
            outer_rx,
            inner_tx,
            inner_rx,
            control: Mutex::new(Vec::new()),
        }
    }
}

/// Dispatch table for routing packets to worker threads.
///
/// Single-owner on thread 0 — no locking needed for lookups.
pub struct NetDispatchTable {
    /// CID → worker_id (outer RX routing by destination connection ID).
    connections: HashMap<Vec<u8>, usize>,
    /// Tunnel IP → list of worker IDs (flow-hash when multiple connections share same IP).
    routes: HashMap<Ipv4Addr, Vec<usize>>,
    /// Connection count per worker (for least-loaded assignment).
    worker_load: Vec<u32>,
}

impl NetDispatchTable {
    /// Create a dispatch table for `n_workers` worker threads.
    pub fn new(n_workers: usize) -> Self {
        Self {
            connections: HashMap::new(),
            routes: HashMap::new(),
            worker_load: vec![0; n_workers],
        }
    }

    /// Register a CID → worker mapping.
    pub fn register_cid(&mut self, cid: &[u8], worker_id: usize) {
        self.connections.insert(cid.to_vec(), worker_id);
        self.worker_load[worker_id] += 1;
    }

    /// Add an IP route → worker mapping. Appends to the list if the IP already exists
    /// (multiple connections to the same tunnel IP → flow-hash distribution).
    pub fn add_route(&mut self, tunnel_ip: Ipv4Addr, worker_id: usize) {
        self.routes.entry(tunnel_ip).or_default().push(worker_id);
    }

    /// Look up worker by CID.
    #[inline]
    pub fn lookup_cid(&self, cid: &[u8]) -> Option<usize> {
        self.connections.get(cid).copied()
    }

    /// Look up worker(s) by destination IP.
    /// Returns a slice of worker IDs (1 for single-connection, N for flow-hash).
    #[inline]
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Option<&[usize]> {
        self.routes.get(&ip).map(|v| v.as_slice())
    }

    /// Return the worker with the fewest connections.
    pub fn least_loaded_worker(&self) -> usize {
        self.worker_load
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| *load)
            .map(|(idx, _)| idx)
            .unwrap_or(0)
    }

    /// Number of workers assigned to a given tunnel IP.
    #[cfg(test)]
    pub fn route_len(&self, ip: Ipv4Addr) -> usize {
        self.routes.get(&ip).map_or(0, |v| v.len())
    }

    /// Unregister a connection (CID + remove worker from IP route list).
    pub fn unregister(&mut self, cid: &[u8], tunnel_ip: Ipv4Addr) {
        if let Some(worker_id) = self.connections.remove(cid) {
            self.worker_load[worker_id] = self.worker_load[worker_id].saturating_sub(1);
            // Remove this worker from the IP route list.
            if let Some(workers) = self.routes.get_mut(&tunnel_ip) {
                workers.retain(|&w| w != worker_id);
                if workers.is_empty() {
                    self.routes.remove(&tunnel_ip);
                }
            }
        }
    }
}

/// Hash an IPv4 packet's 5-tuple (src_ip, dst_ip, proto, src_port, dst_port)
/// for flow-based load balancing. Same flow always maps to the same hash.
#[inline]
pub fn flow_hash_5tuple(packet: &[u8]) -> u32 {
    if packet.len() < 20 {
        return 0;
    }
    let src_ip = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
    let dst_ip = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
    let proto = packet[9] as u32;
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let (src_port, dst_port) = if (proto == 6 || proto == 17) && packet.len() >= ihl + 4 {
        (
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]) as u32,
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]) as u32,
        )
    } else {
        (0, 0)
    };

    // FNV-1a hash
    let mut h: u32 = 2_166_136_261;
    h ^= src_ip;
    h = h.wrapping_mul(16_777_619);
    h ^= dst_ip;
    h = h.wrapping_mul(16_777_619);
    h ^= proto;
    h = h.wrapping_mul(16_777_619);
    h ^= src_port;
    h = h.wrapping_mul(16_777_619);
    h ^= dst_port;
    h = h.wrapping_mul(16_777_619);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4/TCP packet with the given 5-tuple.
    fn make_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40]; // 20-byte IP header + 20-byte TCP header
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn flow_hash_deterministic() {
        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let h1 = flow_hash_5tuple(&pkt);
        let h2 = flow_hash_5tuple(&pkt);
        assert_eq!(h1, h2);
    }

    #[test]
    fn flow_hash_same_flow_same_hash() {
        let pkt1 = make_tcp_packet([192, 168, 1, 1], [10, 0, 0, 1], 5000, 443);
        let pkt2 = make_tcp_packet([192, 168, 1, 1], [10, 0, 0, 1], 5000, 443);
        assert_eq!(flow_hash_5tuple(&pkt1), flow_hash_5tuple(&pkt2));
    }

    #[test]
    fn flow_hash_different_flows_differ() {
        let pkt1 = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80);
        let pkt2 = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1001, 80);
        assert_ne!(flow_hash_5tuple(&pkt1), flow_hash_5tuple(&pkt2));
    }

    #[test]
    fn flow_hash_short_packet() {
        assert_eq!(flow_hash_5tuple(&[0u8; 10]), 0);
    }

    #[test]
    fn dispatch_table_multi_route() {
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let mut table = NetDispatchTable::new(3);

        // Register 3 CIDs for the same tunnel IP on 3 different workers.
        table.register_cid(b"cid0", 0);
        table.add_route(ip, 0);
        table.register_cid(b"cid1", 1);
        table.add_route(ip, 1);
        table.register_cid(b"cid2", 2);
        table.add_route(ip, 2);

        let workers = table.lookup_ip(ip).unwrap();
        assert_eq!(workers, &[0, 1, 2]);

        // Unregister worker 1 — should leave [0, 2].
        table.unregister(b"cid1", ip);
        let workers = table.lookup_ip(ip).unwrap();
        assert_eq!(workers, &[0, 2]);

        // Unregister all — route should be removed.
        table.unregister(b"cid0", ip);
        table.unregister(b"cid2", ip);
        assert!(table.lookup_ip(ip).is_none());
    }

    #[test]
    fn dispatch_table_single_route_unchanged() {
        let ip = Ipv4Addr::new(10, 0, 0, 3);
        let mut table = NetDispatchTable::new(2);
        table.register_cid(b"cid0", 0);
        table.add_route(ip, 0);

        let workers = table.lookup_ip(ip).unwrap();
        assert_eq!(workers, &[0]);
    }
}

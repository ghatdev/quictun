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
    /// Tunnel IP → worker_id (inner RX routing by destination IP).
    routes: HashMap<Ipv4Addr, usize>,
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

    /// Add an IP route → worker mapping.
    pub fn add_route(&mut self, tunnel_ip: Ipv4Addr, worker_id: usize) {
        self.routes.insert(tunnel_ip, worker_id);
    }

    /// Look up worker by CID.
    #[inline]
    pub fn lookup_cid(&self, cid: &[u8]) -> Option<usize> {
        self.connections.get(cid).copied()
    }

    /// Look up worker by destination IP.
    #[inline]
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Option<usize> {
        self.routes.get(&ip).copied()
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

    /// Unregister a connection (CID + IP route).
    pub fn unregister(&mut self, cid: &[u8], tunnel_ip: Ipv4Addr) {
        if let Some(worker_id) = self.connections.remove(cid) {
            self.worker_load[worker_id] = self.worker_load[worker_id].saturating_sub(1);
        }
        self.routes.remove(&tunnel_ip);
    }
}

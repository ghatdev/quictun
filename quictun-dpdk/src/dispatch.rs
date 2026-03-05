//! Dispatch table and per-worker ring bundles for multi-client DPDK.
//!
//! Core 0 (dispatcher) owns the `DpdkDispatchTable` and routes packets to
//! worker cores via SPSC rings. Workers own `LocalConnectionState` per connection.

use std::net::Ipv4Addr;
use std::sync::Mutex;

use anyhow::Result;
use rustc_hash::FxHashMap;
use quictun_quic::local::LocalConnectionState;
use quinn_proto::ConnectionId;

use quictun_quic::cid_to_u64;
use crate::ffi;
use crate::ring::SpscRing;

/// Default SPSC ring capacity (must be power of 2).
const RING_CAPACITY: u32 = 4096;

/// Entry in the dispatch table mapping a CID or IP to a worker.
#[derive(Clone, Copy)]
struct DispatchEntry {
    worker_id: usize,
}

/// Dispatch table for routing packets to worker cores.
///
/// Single-owner on core 0 — no locking needed for lookups.
pub struct DpdkDispatchTable {
    /// CID (as u64) → worker (outer RX routing by destination connection ID).
    connections: FxHashMap<u64, DispatchEntry>,
    /// Tunnel IP → worker (inner RX routing by destination IP).
    routes: FxHashMap<Ipv4Addr, DispatchEntry>,
    /// Connection count per worker (for least-loaded assignment).
    worker_load: Vec<u32>,
}

impl DpdkDispatchTable {
    /// Create a dispatch table for `n_workers` worker cores.
    pub fn new(n_workers: usize) -> Self {
        Self {
            connections: FxHashMap::default(),
            routes: FxHashMap::default(),
            worker_load: vec![0; n_workers],
        }
    }

    /// Register a CID → worker mapping (called at accept time).
    pub fn register_cid(&mut self, cid: &ConnectionId, worker_id: usize) {
        self.connections
            .insert(cid_to_u64(cid.as_ref()), DispatchEntry { worker_id });
        self.worker_load[worker_id] += 1;
    }

    /// Add an IP route (called after peer identification).
    pub fn add_route(&mut self, tunnel_ip: Ipv4Addr, worker_id: usize) {
        self.routes.insert(tunnel_ip, DispatchEntry { worker_id });
    }

    /// Look up worker by CID (raw bytes → u64 key).
    #[inline]
    pub fn lookup_cid(&self, cid: &[u8]) -> Option<usize> {
        self.connections.get(&cid_to_u64(cid)).map(|e| e.worker_id)
    }

    /// Look up worker by destination IP.
    #[inline]
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Option<usize> {
        self.routes.get(&ip).map(|e| e.worker_id)
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
    pub fn unregister(&mut self, cid: &ConnectionId, tunnel_ip: Ipv4Addr) {
        let key = cid_to_u64(cid.as_ref());
        if let Some(entry) = self.connections.remove(&key) {
            self.worker_load[entry.worker_id] = self.worker_load[entry.worker_id].saturating_sub(1);
        }
        self.routes.remove(&tunnel_ip);
    }
}

/// Per-worker ring bundle: 3 SPSC rings + a control channel.
///
/// - `outer_rx`: core 0 → worker (outer RX mbufs dispatched by CID)
/// - `inner_rx`: core 0 → worker (inner RX mbufs dispatched by dest IP)
/// - `inner_tx`: worker → core 0 (decrypted inner TX mbufs for inner port)
/// - `control`: rare messages (new connection assignments, removals)
pub struct WorkerRings {
    pub outer_rx: SpscRing,
    pub inner_rx: SpscRing,
    pub inner_tx: SpscRing,
    pub control: Mutex<Vec<ControlMessage>>,
}

impl WorkerRings {
    /// Create ring bundle for worker `idx`.
    pub fn new(idx: usize) -> Result<Self> {
        Ok(Self {
            outer_rx: SpscRing::new(&format!("outer_rx_{idx}"), RING_CAPACITY, 0)?,
            inner_rx: SpscRing::new(&format!("inner_rx_{idx}"), RING_CAPACITY, 0)?,
            inner_tx: SpscRing::new(&format!("inner_tx_{idx}"), RING_CAPACITY, 0)?,
            control: Mutex::new(Vec::new()),
        })
    }
}

/// Control message sent from dispatcher to worker (rare, via Mutex<Vec>).
pub enum ControlMessage {
    /// Assign a new connection to this worker.
    AddConnection {
        conn: LocalConnectionState,
        tunnel_ip: Ipv4Addr,
        remote_addr: std::net::SocketAddr,
        remote_mac: [u8; 6],
    },
    /// Remove a connection from this worker.
    RemoveConnection { cid: ConnectionId },
}

/// Per-connection state held by a worker core.
pub struct ConnectionEntry {
    pub conn: LocalConnectionState,
    pub tunnel_ip: Ipv4Addr,
    pub remote_addr: std::net::SocketAddr,
    pub remote_mac: [u8; 6],
}

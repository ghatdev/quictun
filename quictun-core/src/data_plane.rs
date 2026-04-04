//! Layer 2 I/O adapter trait and supporting types.
//!
//! Abstracts over platform-specific I/O: kernel TUN+UDP (mio), DPDK ports,
//! future io_uring. The engine (Layer 3) calls these methods without knowing
//! which I/O backend is in use.
//!
//! See docs/v2-design-seed.md §5 for the design rationale.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use ipnet::Ipv4Net;

// ── Event readiness ─────────────────────────────────────────────────────

/// Readiness flags from `poll()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Readiness {
    /// Outer (UDP / DPDK NIC) has data to read.
    pub outer: bool,
    /// Inner (TUN / TAP / virtio) has data to read.
    pub inner: bool,
    /// Shutdown signal received (SIGINT/SIGTERM or AtomicBool).
    pub signal: bool,
}

// ── Batch recv types ────────────────────────────────────────────────────

/// Maximum packet size for recv buffers.
pub const MAX_PACKET: usize = 2048;

/// Pre-allocated batch for outer (UDP) recv.
///
/// Used by `DataPlaneIoBatch::recv_outer_batch()` — adapter fills `bufs`
/// and sets `lens`/`addrs` for each received packet.
pub struct OuterRecvBatch {
    pub bufs: Vec<Vec<u8>>,
    pub lens: Vec<usize>,
    pub addrs: Vec<SocketAddr>,
}

impl OuterRecvBatch {
    pub fn new(capacity: usize) -> Self {
        Self {
            bufs: vec![vec![0u8; MAX_PACKET]; capacity],
            lens: vec![0; capacity],
            addrs: vec![SocketAddr::from(([0, 0, 0, 0], 0)); capacity],
        }
    }

    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }
}

// ── DataPlaneIo trait ───────────────────────────────────────────────────

/// Layer 2 I/O adapter interface.
///
/// Each implementation owns its platform-specific resources:
/// - **KernelAdapter**: mio poll + TUN fd + UDP socket + signal pipe
/// - **DpdkAdapter** (future): DPDK ports + TAP/virtio
/// - **UringAdapter** (future): io_uring submission queues
///
/// The engine loop calls `poll()` to wait for events, then `recv_*`/`send_*`
/// to move packets. Route methods manage OS-level routing (Layer 2 routing
/// table — distinct from the Layer 3 CID routing in `ConnectionManager`).
pub trait DataPlaneIo {
    // ── Event loop ─────────────────────────────────────────────

    /// Wait for I/O readiness events, up to `timeout`.
    fn poll(&mut self, timeout: Duration) -> io::Result<Readiness>;

    // ── Outer (UDP / DPDK NIC) ─────────────────────────────────

    /// Receive a single outer packet. Returns `(len, remote_addr)`.
    /// Returns `WouldBlock` when no more packets are available.
    fn recv_outer(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Send an encrypted packet to a remote peer.
    fn send_outer(&mut self, pkt: &[u8], remote: SocketAddr) -> io::Result<()>;

    // ── Inner (TUN / TAP / virtio) ─────────────────────────────

    /// Receive a single inner packet. Returns packet length.
    /// Returns `WouldBlock` when no more packets are available.
    fn recv_inner(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Send a decrypted packet to the local network.
    fn send_inner(&mut self, pkt: &[u8]) -> io::Result<()>;

    // ── OS routing (Layer 2) ───────────────────────────────────

    /// Add an OS-level route: tells kernel to send `dst` traffic to the TUN device.
    ///
    /// On Linux: netlink `RTM_NEWROUTE`.
    /// On macOS: PF_ROUTE `RTM_ADD`.
    /// On DPDK: no-op (routing is userspace).
    fn add_os_route(&mut self, dst: Ipv4Net) -> io::Result<()>;

    /// Remove an OS-level route.
    fn remove_os_route(&mut self, dst: Ipv4Net) -> io::Result<()>;
}

/// Batch receive extension for high-throughput adapters.
///
/// Provides batched recv methods. Send-side optimizations (GSO, GRO) are
/// adapter-internal — the hot loop accesses buffers directly for zero-copy.
pub trait DataPlaneIoBatch: DataPlaneIo {
    /// Batch receive outer (UDP) packets.
    ///
    /// On Linux: `recvmmsg` (up to `batch.capacity()` packets per syscall).
    /// On macOS: loops `recv_from` until WouldBlock.
    /// On DPDK: `rte_eth_rx_burst`.
    ///
    /// Returns number of packets received. Packet `i` is in
    /// `batch.bufs[i][..batch.lens[i]]` from `batch.addrs[i]`.
    fn recv_outer_batch(&mut self, batch: &mut OuterRecvBatch) -> io::Result<usize>;
}

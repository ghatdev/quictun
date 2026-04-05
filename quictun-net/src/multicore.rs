//! Per-connection multi-core engine (Phase 4).
//!
//! Architecture (from docs/v2-design-seed.md §3):
//!
//! ```text
//! ┌──────────────┐
//! │  I/O Thread   │  recvmmsg → CID parse → dispatch to worker
//! │               │  Also: handshake packets → MultiQuicState → promote
//! │               │  Maintains: CID→worker table, global route table
//! ├──────────────┤
//! │  Worker 0     │  Owns ConnectionManager with connections A, B
//! │               │  decrypt → is_allowed_source → write to TUN
//! │               │  encrypt → send to UDP
//! │  Worker 1     │  Owns ConnectionManager with connections C, D
//! │               │  (same as Worker 0 for its connections)
//! ├──────────────┤
//! │  TUN Reader   │  TUN read → global route lookup → dispatch to worker
//! │               │  Worker encrypts → sends via UDP
//! └──────────────┘
//! ```
//!
//! Workers read from crossbeam channels, process, and write directly to TUN/UDP
//! (both are thread-safe for concurrent writes).

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use crossbeam_channel::{self, Receiver, Sender};
use parking_lot::RwLock;
use quictun_core::data_plane::{DataPlaneIo, DataPlaneIoBatch, OuterRecvBatch};
use crate::engine::RunResult;
use quictun_core::manager::{
    ConnEntry, ConnectionManager, ManagerAction,
};
use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::MultiQuicState;
use quictun_core::routing::RouteAction;
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;
use rustc_hash::FxHashMap;
use tracing::{debug, info, warn};

use crate::adapter::KernelAdapter;
use crate::engine::NetConfig;

// ── Messages ────────────────────────────────────────────────────────────

/// Packet dispatched from I/O thread or TUN reader to a worker.
enum WorkerPacket {
    /// Encrypted outer packet to decrypt + forward to TUN.
    Outer { data: Vec<u8> },
    /// Plaintext inner packet to encrypt + send via UDP.
    Inner { data: Vec<u8> },
    /// New connection assigned to this worker.
    NewConnection {
        cid_key: u64,
        entry: ConnEntry<LocalConnectionState>,
    },
    /// Shutdown signal.
    Shutdown,
}

/// Notification from worker back to I/O thread.
enum WorkerNotification {
    /// A connection was removed (timeout, close, key exhaustion).
    ConnectionRemoved {
        cid_key: u64,
        #[allow(dead_code)]
        tunnel_ip: Ipv4Addr,
        allowed_ips: Vec<ipnet::Ipv4Net>,
    },
}

// ── Dispatch table ──────────────────────────────────────────────────────

/// Shared dispatch table for CID→worker and IP→worker routing.
///
/// Read by I/O thread (CID dispatch) and TUN reader (IP dispatch).
/// Written by I/O thread when connections are added/removed.
struct DispatchTable {
    /// CID key → worker index.
    cid_to_worker: FxHashMap<u64, usize>,
    /// Destination IP → (CID key, worker index) for TUN reader routing.
    /// Uses the ConnectionManager's routing table concept but maps to workers.
    ip_to_worker: Vec<(ipnet::Ipv4Net, usize)>,
    /// Number of connections per worker (for least-loaded assignment).
    worker_load: Vec<usize>,
}

impl DispatchTable {
    fn new(num_workers: usize) -> Self {
        Self {
            cid_to_worker: FxHashMap::default(),
            ip_to_worker: Vec::new(),
            worker_load: vec![0; num_workers],
        }
    }

    fn least_loaded_worker(&self) -> usize {
        self.worker_load
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| *load)
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    fn register(&mut self, cid_key: u64, allowed_ips: &[ipnet::Ipv4Net], worker_id: usize) {
        self.cid_to_worker.insert(cid_key, worker_id);
        for net in allowed_ips {
            self.ip_to_worker.push((*net, worker_id));
        }
        // Keep sorted by descending prefix length for longest-prefix match.
        self.ip_to_worker
            .sort_by(|a, b| b.0.prefix_len().cmp(&a.0.prefix_len()));
        self.worker_load[worker_id] += 1;
    }

    fn unregister(&mut self, cid_key: u64, allowed_ips: &[ipnet::Ipv4Net], worker_id: usize) {
        self.cid_to_worker.remove(&cid_key);
        self.ip_to_worker
            .retain(|(net, _)| !allowed_ips.contains(net));
        if self.worker_load[worker_id] > 0 {
            self.worker_load[worker_id] -= 1;
        }
    }

    fn lookup_worker_by_cid(&self, cid_key: u64) -> Option<usize> {
        self.cid_to_worker.get(&cid_key).copied()
    }

    fn lookup_worker_by_ip(&self, dst_ip: Ipv4Addr) -> Option<usize> {
        for (net, worker_id) in &self.ip_to_worker {
            if net.contains(&dst_ip) {
                return Some(*worker_id);
            }
        }
        None
    }
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Run the multi-core v2 engine.
///
/// `num_workers` = `config.threads - 1` (the I/O thread is the extra thread).
pub fn run_multicore(
    adapter: &mut KernelAdapter,
    multi_state: &mut MultiQuicState,
    config: &NetConfig,
) -> Result<RunResult> {
    let num_workers = (config.threads - 1).max(1);
    let channel_capacity = config.channel_capacity;

    info!(
        threads = config.threads,
        workers = num_workers,
        "v2 multi-core engine starting"
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let dispatch = Arc::new(RwLock::new(DispatchTable::new(num_workers)));

    // Create per-worker channels.
    let mut worker_txs: Vec<Sender<WorkerPacket>> = Vec::with_capacity(num_workers);
    let mut worker_rxs: Vec<Option<Receiver<WorkerPacket>>> = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let (tx, rx) = crossbeam_channel::bounded(channel_capacity);
        worker_txs.push(tx);
        worker_rxs.push(Some(rx));
    }

    // Notification channel: workers → I/O thread.
    let (notify_tx, notify_rx) =
        crossbeam_channel::bounded::<WorkerNotification>(channel_capacity);

    // Clone UDP socket for workers (dup fd — std::net::UdpSocket::try_clone).
    let udp_socket_for_workers = adapter.udp_socket().try_clone()
        .context("failed to clone UDP socket for workers")?;
    let udp_arc = Arc::new(udp_socket_for_workers);

    // TUN fd for workers (raw fd — concurrent write() is thread-safe).
    // We use dup() to get independent fds so each thread can write without
    // interfering with the I/O thread's mio registration.
    let tun_raw_fd = adapter.tun().as_raw_fd();

    // Spawn worker threads.
    let mut worker_handles = Vec::with_capacity(num_workers);
    for i in 0..num_workers {
        let rx = worker_rxs[i].take().expect("worker rx already taken");
        let notify = notify_tx.clone();
        let shutdown_flag = shutdown.clone();
        let udp = udp_arc.clone();
        let tunnel_ip = config.tunnel_ip;
        let idle_timeout = config.idle_timeout;
        let max_peers = config.max_peers;
        let ack_timer_ms = config.ack_timer_ms as u64;
        let cid_len = config.cid_len;
        let offload = config.offload;
        let gso_segs = config.gso_max_segments;

        // dup() the TUN fd for this worker.
        let worker_tun_fd = unsafe { libc::dup(tun_raw_fd) };
        if worker_tun_fd < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to dup TUN fd for worker");
        }

        let handle = std::thread::Builder::new()
            .name(format!("worker-{i}"))
            .spawn(move || {
                run_worker(
                    i,
                    rx,
                    notify,
                    &udp,
                    worker_tun_fd,
                    tunnel_ip,
                    idle_timeout,
                    max_peers,
                    ack_timer_ms,
                    cid_len,
                    offload,
                    gso_segs,
                    shutdown_flag,
                );
                // Close the dup'd fd.
                unsafe { libc::close(worker_tun_fd) };
            })
            .with_context(|| format!("failed to spawn worker-{i}"))?;
        worker_handles.push(handle);
    }

    // Spawn TUN reader thread.
    let reader_tun_fd = unsafe { libc::dup(tun_raw_fd) };
    if reader_tun_fd < 0 {
        return Err(io::Error::last_os_error())
            .context("failed to dup TUN fd for TUN reader");
    }
    let tun_reader_dispatch = dispatch.clone();
    let tun_reader_shutdown = shutdown.clone();
    let tun_reader_worker_txs = worker_txs.clone();
    let tunnel_ip = config.tunnel_ip;
    let tun_reader_offload = config.offload;

    let tun_reader_handle = std::thread::Builder::new()
        .name("tun-reader".into())
        .spawn(move || {
            run_tun_reader(
                reader_tun_fd,
                tun_reader_dispatch,
                tun_reader_worker_txs,
                tun_reader_shutdown,
                tunnel_ip,
                tun_reader_offload,
            );
            unsafe { libc::close(reader_tun_fd) };
        })
        .context("failed to spawn TUN reader")?;

    // Run I/O thread (this thread).
    let result = run_io_thread(
        adapter,
        multi_state,
        config,
        &worker_txs,
        &notify_rx,
        &dispatch,
        &shutdown,
    );

    // Signal shutdown and join threads.
    shutdown.store(true, Ordering::Release);
    for tx in &worker_txs {
        let _ = tx.send(WorkerPacket::Shutdown);
    }
    for handle in worker_handles {
        let _ = handle.join();
    }
    let _ = tun_reader_handle.join();

    result
}

// ── I/O thread ──────────────────────────────────────────────────────────

fn run_io_thread(
    adapter: &mut KernelAdapter,
    multi_state: &mut MultiQuicState,
    config: &NetConfig,
    worker_txs: &[Sender<WorkerPacket>],
    notify_rx: &Receiver<WorkerNotification>,
    dispatch: &Arc<RwLock<DispatchTable>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<RunResult> {
    let cid_len = config.cid_len;
    let mut recv_batch = OuterRecvBatch::new(config.batch_size);
    let mut response_buf = vec![0u8; 4096];
    let mut encrypt_buf = vec![0u8; 2048];

    loop {
        let timeout = Duration::from_millis(100); // 100ms poll tick
        let readiness = adapter.poll(timeout).context("poll failed")?;

        // ── Signal ──
        if readiness.signal {
            info!("received signal, shutting down");
            return Ok(RunResult::Shutdown);
        }

        // ── Process worker notifications ──
        while let Ok(notification) = notify_rx.try_recv() {
            match notification {
                WorkerNotification::ConnectionRemoved {
                    cid_key,
                    tunnel_ip: _,
                    allowed_ips,
                } => {
                    let mut table = dispatch.write();
                    let worker_id = table
                        .lookup_worker_by_cid(cid_key)
                        .unwrap_or(0);
                    table.unregister(cid_key, &allowed_ips, worker_id);
                    // Remove OS routes.
                    for net in &allowed_ips {
                        let _ = adapter.remove_os_route(*net);
                    }
                }
            }
        }

        // ── Outer (UDP) RX → dispatch to workers ──
        if readiness.outer {
            io_thread_handle_outer(
                adapter,
                multi_state,
                &mut recv_batch,
                &mut response_buf,
                cid_len,
                worker_txs,
                dispatch,
            )?;
        }

        // ── Drive handshakes ──
        if !multi_state.handshakes.is_empty() {
            io_thread_drive_handshakes(
                adapter,
                multi_state,
                &config.peers,
                config.max_peers,
                worker_txs,
                dispatch,
                &mut encrypt_buf,
                &mut response_buf,
            )?;
        }

        // ── Handshake timeouts ──
        let now = Instant::now();
        for hs in multi_state.handshakes.values_mut() {
            if let Some(t) = hs.connection.poll_timeout() {
                if now >= t {
                    hs.connection.handle_timeout(now);
                }
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            return Ok(RunResult::Shutdown);
        }
    }
}

fn io_thread_handle_outer(
    adapter: &mut KernelAdapter,
    multi_state: &mut MultiQuicState,
    batch: &mut OuterRecvBatch,
    response_buf: &mut Vec<u8>,
    cid_len: usize,
    worker_txs: &[Sender<WorkerPacket>],
    dispatch: &Arc<RwLock<DispatchTable>>,
) -> Result<()> {
    loop {
        let count = match adapter.recv_outer_batch(batch) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("recv_outer_batch failed"),
        };

        let table = dispatch.read();

        for i in 0..count {
            let n = batch.lens[i];
            if n == 0 {
                continue;
            }
            let first_byte = batch.bufs[i][0];
            let from = batch.addrs[i];

            if first_byte & 0x80 != 0 {
                // Long header → handshake (handled on I/O thread).
                let mut data = BytesMut::with_capacity(n);
                data.extend_from_slice(&batch.bufs[i][..n]);
                let now = Instant::now();
                let responses =
                    multi_state.handle_incoming(now, from, None, data, response_buf);
                for resp in &responses {
                    let _ = adapter.send_outer(resp, from);
                }
                continue;
            }

            // Short header → CID dispatch to worker.
            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&batch.bufs[i][1..1 + cid_len]);

            if let Some(worker_id) = table.lookup_worker_by_cid(cid_key) {
                let packet = WorkerPacket::Outer {
                    data: batch.bufs[i][..n].to_vec(),
                };
                // Try send — drop packet if channel full (backpressure).
                let _ = worker_txs[worker_id].try_send(packet);
            }
        }
    }
}

fn io_thread_drive_handshakes(
    adapter: &mut KernelAdapter,
    multi_state: &mut MultiQuicState,
    peers: &[PeerConfig],
    max_peers: usize,
    worker_txs: &[Sender<WorkerPacket>],
    dispatch: &Arc<RwLock<DispatchTable>>,
    _encrypt_buf: &mut [u8],
    response_buf: &mut Vec<u8>,
) -> Result<()> {
    // Drain transmits.
    drain_transmits_io(adapter, multi_state, response_buf)?;
    let result = multi_state.poll_handshakes();
    drain_transmits_io(adapter, multi_state, response_buf)?;

    // Promote completed handshakes.
    //
    // We use a temporary ConnectionManager just for promote_handshake's
    // identify_peer + eviction logic. We don't use it for connection storage
    // (workers own the connections).
    for ch in result.completed {
        let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        // Use promote_handshake logic manually since we don't have a single manager.
        let matched_peer = match peer::identify_peer(&hs.connection, peers) {
            Some(p) => p,
            None => {
                warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                let mut close_buf = vec![0u8; 128];
                let mut cs = conn_state;
                if let Ok(r) = cs.encrypt_connection_close(&mut close_buf) {
                    let _ = adapter.send_outer(&close_buf[..r.len], hs.remote_addr);
                }
                continue;
            }
        };

        let tunnel_ip = matched_peer.tunnel_ip;
        let allowed_ips = matched_peer.allowed_ips.clone();
        let keepalive_interval = matched_peer
            .keepalive
            .unwrap_or(Duration::from_secs(25));

        let cid_bytes: Vec<u8> = conn_state.local_cid()[..].to_vec();
        let cid_key = cid_to_u64(&cid_bytes);
        let now_inst = Instant::now();

        // Assign to least-loaded worker.
        let mut table = dispatch.write();

        // TODO: reconnect eviction in multi-core requires notifying the worker
        // that owns the old connection. For now, skip eviction — the worker's
        // sweep_timeouts will clean up the old connection on idle timeout.

        // Max peers check.
        let total_connections: usize = table.worker_load.iter().sum();
        if max_peers > 0 && total_connections >= max_peers {
            warn!(
                max_peers,
                remote = %hs.remote_addr,
                "max_peers reached, rejecting"
            );
            let mut close_buf = vec![0u8; 128];
            let mut cs = conn_state;
            if let Ok(r) = cs.encrypt_connection_close(&mut close_buf) {
                let _ = adapter.send_outer(&close_buf[..r.len], hs.remote_addr);
            }
            continue;
        }

        let worker_id = table.least_loaded_worker();
        table.register(cid_key, &allowed_ips, worker_id);
        drop(table);

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            worker = worker_id,
            "connection established (multi-core)"
        );

        // Add OS routes.
        for net in &allowed_ips {
            if let Err(e) = adapter.add_os_route(*net) {
                warn!(error = %e, dst = %net, "failed to add OS route");
            }
        }

        // Send the new connection to the worker.
        let entry = ConnEntry {
            conn: conn_state,
            tunnel_ip,
            allowed_ips,
            remote_addr: hs.remote_addr,
            keepalive_interval,
            last_tx: now_inst,
            last_rx: now_inst,
        };

        let _ = worker_txs[worker_id].send(WorkerPacket::NewConnection {
            cid_key,
            entry,
        });
    }

    Ok(())
}

fn drain_transmits_io(
    adapter: &mut KernelAdapter,
    state: &mut MultiQuicState,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let now = Instant::now();
    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, buf) else {
                break;
            };
            adapter
                .send_outer(&buf[..transmit.size], hs.remote_addr)
                .context("failed to send handshake transmit")?;
        }
    }
    Ok(())
}

// ── Worker thread ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments, unused_variables)]
fn run_worker(
    id: usize,
    rx: Receiver<WorkerPacket>,
    notify_tx: Sender<WorkerNotification>,
    udp: &std::net::UdpSocket,
    tun_fd: RawFd,
    tunnel_ip: Ipv4Addr,
    idle_timeout: Duration,
    max_peers: usize,
    ack_timer_ms: u64,
    cid_len: usize,
    offload_enabled: bool,
    gso_max_segments: usize,
    shutdown: Arc<AtomicBool>,
) {
    let mut manager = ConnectionManager::<LocalConnectionState>::new(
        tunnel_ip, false, max_peers, idle_timeout,
    );
    let mut encrypt_buf = vec![0u8; 2048];
    let mut scratch = BytesMut::with_capacity(2048);
    let tick = Duration::from_millis(ack_timer_ms.max(10));
    let mut next_ack = Instant::now() + Duration::from_millis(ack_timer_ms);

    // Linux-only batch state.
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; gso_max_segments * 2048];
    #[cfg(target_os = "linux")]
    let mut gso_pos: usize = 0;
    #[cfg(target_os = "linux")]
    let mut gso_segment_size: usize = 0;
    #[cfg(target_os = "linux")]
    let mut gso_count: usize = 0;
    #[cfg(target_os = "linux")]
    let mut gso_remote = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    #[cfg(target_os = "linux")]
    let mut gso_current_cid: Option<u64> = None;
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = crate::engine::GroTxPool::new();

    // Suppress unused-variable warnings on non-Linux.
    #[cfg(not(target_os = "linux"))]
    let _ = (offload_enabled, gso_max_segments);

    debug!(worker = id, "worker started");

    // ── Inline helpers (closures can't borrow everything, so use macros) ──

    /// Process a single packet. Returns `true` if shutdown was requested.
    macro_rules! process_packet {
        ($pkt:expr) => {
            match $pkt {
                WorkerPacket::Shutdown => break,

                WorkerPacket::NewConnection { cid_key, entry } => {
                    info!(worker = id, tunnel_ip = %entry.tunnel_ip, "received new connection");
                    manager.insert_connection(cid_key, entry);
                }

                WorkerPacket::Outer { data } => {
                    if cid_len > 0 && data.len() >= 1 + cid_len {
                        let mut data = data;
                        let cid_key = cid_to_u64(&data[1..1 + cid_len]);
                        let mut close_received = false;

                        if let Some(entry) = manager.get_mut(&cid_key) {
                            match entry.conn.decrypt_packet_with_buf(&mut data, &mut scratch) {
                                Ok(dec) => {
                                    entry.last_rx = Instant::now();
                                    if let Some(ref ack) = dec.ack {
                                        entry.conn.process_ack(ack);
                                    }
                                    close_received = dec.close_received;
                                    if !close_received {
                                        for dg in &dec.datagrams {
                                            if dg.len() < 20 {
                                                continue;
                                            }
                                            let src_ip = Ipv4Addr::new(dg[12], dg[13], dg[14], dg[15]);
                                            if !peer::is_allowed_source(&entry.allowed_ips, src_ip) {
                                                continue;
                                            }
                                            #[cfg(target_os = "linux")]
                                            if offload_enabled {
                                                gro_tx_pool.push_datagram(dg);
                                            } else {
                                                tun_write(tun_fd, dg);
                                            }
                                            #[cfg(not(target_os = "linux"))]
                                            tun_write(tun_fd, dg);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "worker decrypt failed");
                                }
                            }
                        } else {
                            warn!(cid_key, "worker: CID not found");
                        }

                        if close_received {
                            if let Some(removed) = manager.remove_connection(cid_key) {
                                let _ = notify_tx.send(WorkerNotification::ConnectionRemoved {
                                    cid_key,
                                    tunnel_ip: removed.tunnel_ip,
                                    allowed_ips: removed.allowed_ips,
                                });
                            }
                        }
                    }
                }

                WorkerPacket::Inner { data } => {
                    if data.len() >= 20 && data[0] >> 4 == 4 {
                        let dest_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                        let cid = match manager.lookup_route(dest_ip) {
                            RouteAction::ForwardToPeer(c) => c,
                            _ if manager.len() == 1 => {
                                match manager.keys().next() {
                                    Some(&c) => c,
                                    None => continue,
                                }
                            }
                            _ => continue,
                        };

                        #[cfg(target_os = "linux")]
                        {
                            // Flush GSO batch if CID changed or batch full.
                            if let Some(cur) = gso_current_cid {
                                if cur != cid
                                    || gso_count >= gso_buf.len() / 2048
                                    || gso_pos + 2048 > gso_buf.len()
                                {
                                    if gso_count > 0 {
                                        crate::engine_v2::flush_gso(
                                            udp, &gso_buf, gso_pos, gso_segment_size, gso_remote,
                                        );
                                        if let Some(prev) = manager.get_mut(&cur) {
                                            prev.last_tx = Instant::now();
                                        }
                                    }
                                    gso_pos = 0;
                                    gso_segment_size = 0;
                                    gso_count = 0;
                                }
                            }
                            if let Some(entry) = manager.get_mut(&cid) {
                                gso_current_cid = Some(cid);
                                gso_remote = entry.remote_addr;
                                match entry.conn.encrypt_datagram(&data, &mut gso_buf[gso_pos..]) {
                                    Ok(r) => {
                                        if gso_count == 0 {
                                            gso_segment_size = r.len;
                                        }
                                        gso_pos += r.len;
                                        gso_count += 1;
                                    }
                                    Err(e) => { warn!(error = %e, "encrypt failed"); }
                                }
                            }
                        }

                        #[cfg(not(target_os = "linux"))]
                        {
                            if let Some(entry) = manager.get_mut(&cid) {
                                match entry.conn.encrypt_datagram(&data, &mut encrypt_buf) {
                                    Ok(r) => {
                                        let _ = udp.send_to(&encrypt_buf[..r.len], entry.remote_addr);
                                        entry.last_tx = Instant::now();
                                    }
                                    Err(e) => { warn!(error = %e, "encrypt failed"); }
                                }
                            }
                        }
                    }
                }
            }
        };
    }

    // ── Main loop ────────────────────────────────────────────────────────

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Block for first packet (with timeout for timer processing).
        let first = match rx.recv_timeout(tick) {
            Ok(pkt) => pkt,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Run timers on timeout, then retry.
                let now = Instant::now();
                for action in manager.sweep_timeouts() {
                    match action {
                        ManagerAction::SendKeepalive { cid_key } => {
                            if let Some(entry) = manager.get_mut(&cid_key) {
                                if let Ok(r) = entry.conn.encrypt_datagram(&[], &mut encrypt_buf) {
                                    let _ = udp.send_to(&encrypt_buf[..r.len], entry.remote_addr);
                                    entry.last_tx = Instant::now();
                                }
                            }
                        }
                        ManagerAction::ConnectionRemoved { cid_key, tunnel_ip, allowed_ips, .. } => {
                            let _ = notify_tx.send(WorkerNotification::ConnectionRemoved {
                                cid_key, tunnel_ip, allowed_ips,
                            });
                        }
                    }
                }
                if now >= next_ack {
                    for cid_key in manager.connections_needing_ack() {
                        if let Some(entry) = manager.get_mut(&cid_key) {
                            if let Ok(r) = entry.conn.encrypt_ack(&mut encrypt_buf) {
                                let _ = udp.send_to(&encrypt_buf[..r.len], entry.remote_addr);
                            }
                        }
                    }
                    next_ack = now + Duration::from_millis(ack_timer_ms);
                }
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        // Process first packet.
        process_packet!(first);

        // Drain all queued packets.
        while let Ok(pkt) = rx.try_recv() {
            process_packet!(pkt);
        }

        // ── Flush accumulated batches ──
        #[cfg(target_os = "linux")]
        {
            if gso_count > 0 {
                crate::engine_v2::flush_gso(
                    udp, &gso_buf, gso_pos, gso_segment_size, gso_remote,
                );
                if let Some(cid) = gso_current_cid {
                    if let Some(entry) = manager.get_mut(&cid) {
                        entry.last_tx = Instant::now();
                    }
                }
                gso_pos = 0;
                gso_count = 0;
                gso_segment_size = 0;
                gso_current_cid = None;
            }

            if offload_enabled && !gro_tx_pool.is_empty() {
                for buf in gro_tx_pool.iter() {
                    tun_write(tun_fd, buf);
                }
                gro_tx_pool.reset();
            }
        }

        // ── Timers (inline) ──
        let now = Instant::now();
        for action in manager.sweep_timeouts() {
            match action {
                ManagerAction::SendKeepalive { cid_key } => {
                    if let Some(entry) = manager.get_mut(&cid_key) {
                        if let Ok(r) = entry.conn.encrypt_datagram(&[], &mut encrypt_buf) {
                            let _ = udp.send_to(&encrypt_buf[..r.len], entry.remote_addr);
                            entry.last_tx = Instant::now();
                        }
                    }
                }
                ManagerAction::ConnectionRemoved { cid_key, tunnel_ip, allowed_ips, .. } => {
                    let _ = notify_tx.send(WorkerNotification::ConnectionRemoved {
                        cid_key, tunnel_ip, allowed_ips,
                    });
                }
            }
        }
        if now >= next_ack {
            for cid_key in manager.connections_needing_ack() {
                if let Some(entry) = manager.get_mut(&cid_key) {
                    if let Ok(r) = entry.conn.encrypt_ack(&mut encrypt_buf) {
                        let _ = udp.send_to(&encrypt_buf[..r.len], entry.remote_addr);
                    }
                }
            }
            next_ack = now + Duration::from_millis(ack_timer_ms);
        }
    }

    // Graceful shutdown: send CONNECTION_CLOSE to all peers.
    for entry in manager.values_mut() {
        if let Ok(r) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
            let _ = udp.send_to(&encrypt_buf[..r.len], entry.remote_addr);
        }
    }
    debug!(worker = id, "worker stopped");
}

// ── TUN reader thread ───────────────────────────────────────────────────

fn run_tun_reader(
    tun_fd: RawFd,
    dispatch: Arc<RwLock<DispatchTable>>,
    worker_txs: Vec<Sender<WorkerPacket>>,
    shutdown: Arc<AtomicBool>,
    tunnel_ip: Ipv4Addr,
    offload_enabled: bool,
) {
    // With TUN offload, reads include a virtio_net_hdr prefix.
    #[cfg(target_os = "linux")]
    let hdr_len: usize = if offload_enabled { quictun_tun::VIRTIO_NET_HDR_LEN } else { 0 };
    #[cfg(not(target_os = "linux"))]
    let hdr_len: usize = 0;
    let _ = offload_enabled;

    let mut buf = [0u8; 65536]; // Large enough for GRO coalesced + virtio hdr
    debug!("TUN reader started");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let n = tun_read(tun_fd, &mut buf);
        match n {
            Ok(n) => {
                if n < hdr_len + 20 {
                    continue;
                }

                // Skip virtio header to find IP header.
                let ip_start = hdr_len;
                // Skip non-IPv4 packets.
                if buf[ip_start] >> 4 != 4 {
                    continue;
                }
                let dest_ip = Ipv4Addr::new(
                    buf[ip_start + 16], buf[ip_start + 17],
                    buf[ip_start + 18], buf[ip_start + 19],
                );

                // Skip packets destined to our own tunnel IP.
                if dest_ip == tunnel_ip {
                    continue;
                }

                let table = dispatch.read();

                // Look up which worker handles this destination.
                let worker_id = if let Some(wid) = table.lookup_worker_by_ip(dest_ip) {
                    wid
                } else if worker_txs.len() == 1 {
                    // Single worker fallback.
                    0
                } else {
                    continue;
                };

                drop(table);

                // Send only the IP payload (strip virtio header if present).
                let packet = WorkerPacket::Inner {
                    data: buf[ip_start..n].to_vec(),
                };
                let _ = worker_txs[worker_id].try_send(packet);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // TUN is non-blocking — brief sleep to avoid busy spin.
                std::thread::sleep(Duration::from_micros(100));
            }
            Err(e) => {
                warn!(error = %e, "TUN read error");
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    debug!("TUN reader stopped");
}

// ── Raw TUN fd helpers ──────────────────────────────────────────────────

/// Write a packet to TUN via raw fd (thread-safe, no SyncDevice needed).
fn tun_write(fd: RawFd, pkt: &[u8]) {
    let ret = unsafe {
        libc::write(fd, pkt.as_ptr() as *const libc::c_void, pkt.len())
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            warn!(error = %err, len = pkt.len(), "tun_write failed");
        }
    }
}

/// Read a packet from TUN via raw fd.
fn tun_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let ret = unsafe {
        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

//! Pipeline v2: I/O dispatcher + N full-pipeline workers with SharedConnectionState.
//!
//! Architecture:
//!   I/O thread (dispatcher):
//!     - recvmmsg → batch dispatch raw packets to workers
//!     - Handshakes, ACK timer, keepalives, timeouts
//!
//!   N worker threads (each has own TUN queue):
//!     - Receive raw batch → SharedConnectionState::decrypt_in_place → GRO → TUN write
//!     - TUN read → TxState::encrypt_datagram → UDP send directly
//!
//! Key differences from pipeline v1:
//!   - Workers do full decrypt + replay + TUN write (not just AEAD)
//!   - Multi-queue TUN: each worker writes to own queue
//!   - SharedConnectionState: any worker can decrypt
//!   - I/O thread freed from replay check + TUN write overhead
//!   - Batched dispatch: one channel message per recvmmsg batch (not per packet)
//!
//! Selected via `pipeline = true` + `percore = true` + `threads >= 2` in `[engine]`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll};
use rustc_hash::FxHashMap;
use tracing::{debug, info, warn};

use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::MultiQuicState;
use quictun_quic::cid_to_u64;
use quictun_quic::shared::SharedConnectionState;

use crate::engine::{
    EndpointSetup, HANDSHAKE_BUF_SIZE, MAX_PACKET, NetConfig, RunResult, TOKEN_SIGNAL, TOKEN_TUN,
    TOKEN_UDP, create_signal_pipe, create_udp_socket, drain_signal_pipe, drain_transmits,
    install_signal_handler, send_responses, set_nonblocking,
};
use quictun_tun::TunOptions;

// ── Types ────────────────────────────────────────────────────────────────

/// Batch of raw packets dispatched from I/O thread to a worker.
///
/// Uses a contiguous slab buffer instead of per-packet Vec allocation.
/// Recycled via the batch pool channel for zero steady-state allocation.
struct RawBatch {
    /// Contiguous buffer holding all packet data.
    slab: Vec<u8>,
    /// (offset, length, cid_key) for each packet in the slab.
    packets: Vec<(usize, usize, u64)>,
}

impl RawBatch {
    fn with_capacity(max_packets: usize) -> Self {
        Self {
            slab: Vec::with_capacity(max_packets * MAX_PACKET),
            packets: Vec::with_capacity(max_packets),
        }
    }

    fn reset(&mut self) {
        self.slab.clear();
        self.packets.clear();
    }

    fn push(&mut self, data: &[u8], cid_key: u64) {
        let offset = self.slab.len();
        self.slab.extend_from_slice(data);
        self.packets.push((offset, data.len(), cid_key));
    }

    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

/// Shared connection info passed to workers.
struct SharedConn {
    shared: Arc<SharedConnectionState>,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    cid_key: u64,
}

/// Per-connection state on the dispatcher.
struct DispatchConnEntry {
    shared: Arc<SharedConnectionState>,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    /// Updated by workers atomically.
    last_rx_epoch: Arc<AtomicU64>,
}

// ── Entry point ──────────────────────────────────────────────────────────

pub fn run_pipeline2(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });
    let n_workers = config.threads - 1;
    info!(
        threads = config.threads,
        workers = n_workers,
        "starting pipeline v2 engine"
    );

    // 1. Create UDP socket + multi-queue TUN.
    let udp_socket = create_udp_socket(local_addr, config.recv_buf, config.send_buf)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name.clone();
    tun_opts.multi_queue = n_workers > 1;
    #[cfg(target_os = "linux")]
    {
        tun_opts.offload = config.offload;
    }
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
    set_nonblocking(tun.as_raw_fd())?;

    // 2. Signal pipe.
    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;
    install_signal_handler(sig_write_fd)?;

    // 3. Handshake on main thread.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => MultiQuicState::new(server_config.clone()),
        EndpointSetup::Connector { .. } => MultiQuicState::new_connector(),
    };

    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        multi_state.connect(client_config, remote_addr)?;
        drain_transmits(&udp_socket, &mut multi_state)?;
    }

    // 4. mio poll for handshake phase.
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(config.poll_events);
    let udp_raw_fd = udp_socket.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&udp_raw_fd), TOKEN_UDP, Interest::READABLE)?;
    poll.registry().register(
        &mut SourceFd(&sig_read_fd),
        TOKEN_SIGNAL,
        Interest::READABLE,
    )?;

    let mut connections: FxHashMap<u64, DispatchConnEntry> = FxHashMap::default();
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();
    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut recv_buf = vec![0u8; MAX_PACKET];

    info!("waiting for handshake...");
    loop {
        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("poll failed during handshake"),
        }

        for event in events.iter() {
            if event.token() == TOKEN_SIGNAL {
                drain_signal_pipe(sig_read_fd);
                return Ok(RunResult::Shutdown);
            }
            if event.token() == TOKEN_UDP {
                loop {
                    match udp_socket.recv_from(&mut recv_buf) {
                        Ok((n, from)) => {
                            if n == 0 {
                                continue;
                            }
                            let mut data = bytes::BytesMut::with_capacity(n);
                            data.extend_from_slice(&recv_buf[..n]);
                            let now = Instant::now();
                            let responses =
                                multi_state.handle_incoming(now, from, None, data, &mut response_buf);
                            send_responses(&udp_socket, &responses, from)?;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e).context("recv_from during handshake"),
                    }
                }
            }
        }

        drain_transmits(&udp_socket, &mut multi_state)?;
        let result = multi_state.poll_handshakes();
        drain_transmits(&udp_socket, &mut multi_state)?;

        for ch in result.completed {
            let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
                continue;
            };
            let matched_peer = if config.peers.len() == 1 {
                &config.peers[0]
            } else {
                match peer::identify_peer(&hs.connection, &config.peers) {
                    Some(p) => p,
                    None => {
                        warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                        continue;
                    }
                }
            };

            let tunnel_ip = matched_peer.tunnel_ip;
            let allowed_ips = matched_peer.allowed_ips.clone();
            let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));
            let cid_bytes: Vec<u8> = conn_state.local_cid()[..].to_vec();
            let cid_key = cid_to_u64(&cid_bytes);
            let shared = Arc::new(conn_state.into_shared());
            let last_rx_epoch = Arc::new(AtomicU64::new(epoch_millis()));

            info!(
                remote = %hs.remote_addr,
                tunnel_ip = %tunnel_ip,
                local_cid = %hex::encode(&cid_bytes),
                "connection established (pipeline v2)"
            );

            ip_to_cid.insert(tunnel_ip, cid_key);
            connections.insert(
                cid_key,
                DispatchConnEntry {
                    shared,
                    tunnel_ip,
                    allowed_ips,
                    remote_addr: hs.remote_addr,
                    keepalive_interval,
                    last_tx: Instant::now(),
                    last_rx_epoch,
                },
            );
        }

        if !connections.is_empty() {
            break;
        }

        let now = Instant::now();
        for hs in multi_state.handshakes.values_mut() {
            hs.connection.handle_timeout(now);
        }
    }

    // 5. Build shared connection info for workers.
    let worker_conns: Vec<Arc<SharedConn>> = connections
        .iter()
        .map(|(&cid_key, entry)| {
            Arc::new(SharedConn {
                shared: Arc::clone(&entry.shared),
                tunnel_ip: entry.tunnel_ip,
                allowed_ips: entry.allowed_ips.clone(),
                remote_addr: entry.remote_addr,
                cid_key,
            })
        })
        .collect();

    // Last-RX epoch refs for workers.
    let last_rx_epochs: FxHashMap<u64, Arc<AtomicU64>> = connections
        .iter()
        .map(|(&k, v)| (k, Arc::clone(&v.last_rx_epoch)))
        .collect();

    // 6. Create channels: dispatcher→workers (raw batches), workers→dispatcher (recycled batches).
    let channel_cap = config.channel_capacity;
    let (batch_tx, batch_rx) = crossbeam_channel::bounded::<RawBatch>(channel_cap);
    let (recycle_tx, recycle_rx) = crossbeam_channel::bounded::<RawBatch>(channel_cap);

    // Pre-allocate batch pool.
    let batch_size = config.batch_size;
    for _ in 0..channel_cap {
        let _ = recycle_tx.try_send(RawBatch::with_capacity(batch_size));
    }

    let shutdown = Arc::new(AtomicBool::new(false));

    // 7. Spawn workers + run dispatcher.
    let offload = config.offload;
    let gso_max_segments = config.gso_max_segments;
    let cid_len = config.cid_len;

    // Pre-create TUN queues: worker 0 gets original fd, workers 1..N get clones.
    let mut tun_queues: Vec<tun_rs::SyncDevice> = Vec::with_capacity(n_workers);
    for i in 1..n_workers {
        let q = tun.try_clone().unwrap_or_else(|e| {
            panic!("TUN try_clone for worker {i} failed: {e}")
        });
        tun_queues.push(q);
    }

    let result = std::thread::scope(|s| {
        let mut worker_handles = Vec::with_capacity(n_workers);

        let udp_ref = &udp_socket;

        // Worker 0 gets the original TUN fd.
        {
            let batch_rx = batch_rx.clone();
            let recycle_tx = recycle_tx.clone();
            let shutdown_flag = Arc::clone(&shutdown);
            let conns = worker_conns.clone();
            let epochs = last_rx_epochs.clone();
            let handle = s.spawn(move || {
                run_worker(
                    0,
                    batch_rx,
                    recycle_tx,
                    udp_ref,
                    &tun,
                    conns,
                    epochs,
                    offload,
                    gso_max_segments,
                    shutdown_flag,
                )
            });
            worker_handles.push(handle);
        }

        // Workers 1..N get cloned queues.
        for (i, tun_queue) in tun_queues.iter().enumerate() {
            let batch_rx = batch_rx.clone();
            let recycle_tx = recycle_tx.clone();
            let shutdown_flag = Arc::clone(&shutdown);
            let conns = worker_conns.clone();
            let epochs = last_rx_epochs.clone();
            let handle = s.spawn(move || {
                set_nonblocking(tun_queue.as_raw_fd()).expect("set TUN nonblocking");
                run_worker(
                    i + 1,
                    batch_rx,
                    recycle_tx,
                    udp_ref,
                    tun_queue,
                    conns,
                    epochs,
                    offload,
                    gso_max_segments,
                    shutdown_flag,
                )
            });
            worker_handles.push(handle);
        }
        drop(batch_rx);
        drop(recycle_tx);

        // Dispatcher loop.
        let io_result = run_dispatcher(
            &udp_socket,
            &mut poll,
            sig_read_fd,
            &mut events,
            &mut connections,
            &config,
            is_connector,
            &batch_tx,
            &recycle_rx,
            cid_len,
        );

        drop(batch_tx);
        shutdown.store(true, Ordering::Release);

        for handle in worker_handles {
            let _ = handle.join();
        }

        io_result
    });

    result
}

// ── Dispatcher (I/O thread) ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn run_dispatcher(
    udp: &std::net::UdpSocket,
    poll: &mut Poll,
    sig_read_fd: i32,
    events: &mut Events,
    connections: &mut FxHashMap<u64, DispatchConnEntry>,
    config: &NetConfig,
    is_connector: bool,
    batch_tx: &Sender<RawBatch>,
    recycle_rx: &Receiver<RawBatch>,
    cid_len: usize,
) -> Result<RunResult> {
    let ack_timer_interval = Duration::from_millis(config.ack_timer_ms as u64);
    let mut next_ack_deadline = Instant::now() + ack_timer_interval;
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    #[cfg(target_os = "linux")]
    let batch_size = config.batch_size;
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_addrs =
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_work = quictun_core::batch_io::RecvMmsgWork::new(batch_size);

    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let had_connection = true; // We already have connection(s).

    loop {
        // Compute timeout. Use short timeout to keep dispatch responsive.
        let mut timeout = Duration::from_secs(5);
        for entry in connections.values() {
            let ka_rem = entry.keepalive_interval.saturating_sub(entry.last_tx.elapsed());
            timeout = timeout.min(ka_rem);
        }
        let ack_rem = next_ack_deadline.saturating_duration_since(Instant::now());
        timeout = timeout.min(ack_rem).min(Duration::from_millis(1));

        match poll.poll(events, Some(timeout)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("poll failed"),
        }

        let mut signal_received = false;
        let mut udp_readable = false;

        for event in events.iter() {
            match event.token() {
                TOKEN_SIGNAL => signal_received = true,
                TOKEN_UDP => udp_readable = true,
                _ => {}
            }
        }

        if signal_received {
            drain_signal_pipe(sig_read_fd);
            info!("received signal, shutting down pipeline v2");
            for entry in connections.values() {
                if let Ok(result) = entry.shared.tx.encrypt_datagram(&[], &mut encrypt_buf) {
                    let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                }
            }
            return Ok(RunResult::Shutdown);
        }

        // ── UDP RX → batch dispatch to workers ─────────────────────
        if udp_readable {
            #[cfg(target_os = "linux")]
            dispatch_udp_rx_linux(
                udp,
                connections,
                cid_len,
                &mut recv_bufs,
                &mut recv_lens,
                &mut recv_addrs,
                &mut recv_work,
                &mut response_buf,
                batch_tx,
                recycle_rx,
            )?;
        }

        // ── ACK timer ────────────────────────────────────────────
        if Instant::now() >= next_ack_deadline {
            send_acks(udp, connections, &mut encrypt_buf);
            next_ack_deadline = Instant::now() + ack_timer_interval;
        }

        // ── Keepalives ───────────────────────────────────────────
        for entry in connections.values_mut() {
            if entry.last_tx.elapsed() >= entry.keepalive_interval {
                if let Ok(result) = entry.shared.tx.encrypt_datagram(&[], &mut encrypt_buf) {
                    let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                    entry.last_tx = Instant::now();
                }
            }
        }

        // ── Idle timeout ─────────────────────────────────────────
        let now_epoch = epoch_millis();
        let idle_ms = config.idle_timeout.as_millis() as u64;
        let expired: Vec<u64> = connections
            .iter()
            .filter(|(_, e)| now_epoch.saturating_sub(e.last_rx_epoch.load(Ordering::Relaxed)) >= idle_ms)
            .map(|(&cid, _)| cid)
            .collect();
        for cid in &expired {
            if let Some(entry) = connections.remove(cid) {
                info!(tunnel_ip = %entry.tunnel_ip, "connection idle timeout");
            }
        }

        if is_connector && had_connection && connections.is_empty() {
            return Ok(RunResult::ConnectionLost);
        }
    }
}

// ── Dispatch UDP RX (batched) ───────────────────────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn dispatch_udp_rx_linux(
    udp: &std::net::UdpSocket,
    connections: &FxHashMap<u64, DispatchConnEntry>,
    cid_len: usize,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    _response_buf: &mut Vec<u8>,
    batch_tx: &Sender<RawBatch>,
    recycle_rx: &Receiver<RawBatch>,
) -> Result<()> {
    // Get a batch from pool, or create new if pool empty.
    let mut batch = recycle_rx
        .try_recv()
        .unwrap_or_else(|_| RawBatch::with_capacity(recv_bufs.len()));
    batch.reset();

    loop {
        let max_batch = recv_bufs.len();
        let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
            udp,
            recv_bufs,
            recv_lens,
            recv_addrs,
            max_batch,
            recv_work,
        ) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("recvmmsg failed"),
        };

        for i in 0..n_msgs {
            let n = recv_lens[i];
            if n == 0 {
                continue;
            }

            // Skip handshake packets.
            if recv_bufs[i][0] & 0x80 != 0 {
                continue;
            }

            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&recv_bufs[i][1..1 + cid_len]);

            if !connections.contains_key(&cid_key) {
                continue;
            }

            batch.push(&recv_bufs[i][..n], cid_key);
        }

        if n_msgs < max_batch {
            break;
        }
    }

    if !batch.is_empty() {
        // Non-blocking send; if channel full, drop the batch (backpressure).
        let _ = batch_tx.try_send(batch);
    }
    // Empty batch is dropped — next call will get one from pool or allocate.

    Ok(())
}

// ── Worker thread ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn run_worker(
    id: usize,
    batch_rx: Receiver<RawBatch>,
    recycle_tx: Sender<RawBatch>,
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    conns: Vec<Arc<SharedConn>>,
    last_rx_epochs: FxHashMap<u64, Arc<AtomicU64>>,
    offload: bool,
    _gso_max_segments: usize,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!(worker = id, "pipeline v2 worker started");

    // Build CID → connection lookup.
    let conn_map: FxHashMap<u64, Arc<SharedConn>> = conns
        .iter()
        .map(|c| (c.cid_key, Arc::clone(c)))
        .collect();

    // IP → connection lookup (for TUN RX encrypt path).
    let ip_map: FxHashMap<Ipv4Addr, Arc<SharedConn>> = conns
        .iter()
        .map(|c| (c.tunnel_ip, Arc::clone(c)))
        .collect();

    let single_conn = if conns.len() == 1 {
        Some(Arc::clone(&conns[0]))
    } else {
        None
    };

    // GRO TX pool for decrypt → TUN write.
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = GroTxPool::new();
    #[cfg(target_os = "linux")]
    let mut gro_table = if offload {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };

    // TUN offload buffers for TUN RX.
    #[cfg(target_os = "linux")]
    let mut tun_original_buf = if offload {
        vec![0u8; quictun_tun::VIRTIO_NET_HDR_LEN + 65535]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_bufs = if offload {
        vec![vec![0u8; 1500]; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_sizes = if offload {
        vec![0usize; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };

    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut decrypt_count: u64 = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Try to receive a batch (non-blocking first).
        let batch = match batch_rx.try_recv() {
            Ok(b) => Some(b),
            Err(crossbeam_channel::TryRecvError::Empty) => None,
            Err(crossbeam_channel::TryRecvError::Disconnected) => break,
        };

        let got_batch = batch.is_some();

        // Process batch if we got one.
        if let Some(mut batch) = batch {
            for &(offset, len, cid_key) in &batch.packets {
                let conn = if let Some(sc) = single_conn.as_ref() {
                    sc
                } else if let Some(c) = conn_map.get(&cid_key) {
                    c
                } else {
                    continue;
                };

                let pkt = &mut batch.slab[offset..offset + len];
                match conn.shared.decrypt_in_place(pkt) {
                    Ok(result) => {
                        if let Some(epoch_ref) = last_rx_epochs.get(&cid_key) {
                            epoch_ref.store(epoch_millis(), Ordering::Relaxed);
                        }
                        decrypt_count += 1;

                        if decrypt_count & 0xFFFF == 0 {
                            conn.shared.maybe_initiate_key_update(decrypt_count);
                            decrypt_count = 0;
                        }

                        for datagram in &result.datagrams {
                            let data = &pkt[datagram.start..datagram.end];
                            if data.len() < 20 {
                                continue;
                            }
                            let src_ip =
                                Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                            if !peer::is_allowed_source(&conn.allowed_ips, src_ip) {
                                continue;
                            }
                            if offload {
                                #[cfg(target_os = "linux")]
                                gro_tx_pool.push_datagram(data);
                            } else {
                                let _ = tun.send(data);
                            }
                        }
                    }
                    Err(_) => {}
                }
            }

            // Recycle the batch back to the pool.
            batch.reset();
            let _ = recycle_tx.try_send(batch);
        }

        // Flush GRO to TUN.
        #[cfg(target_os = "linux")]
        if offload && !gro_tx_pool.is_empty() {
            if let Some(gro) = &mut gro_table {
                match tun.send_multiple(gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN)
                {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        debug!(worker = id, error = %e, "TUN send_multiple failed");
                    }
                }
                gro_tx_pool.reset();
            }
        }

        // TUN RX (encrypt path) — non-blocking read, no mio poll needed.
        #[cfg(target_os = "linux")]
        if offload {
            worker_tun_rx_offload(
                tun,
                &ip_map,
                single_conn.as_ref(),
                udp,
                &mut tun_original_buf,
                &mut tun_split_bufs,
                &mut tun_split_sizes,
                &mut encrypt_buf,
            )?;
        } else {
            worker_tun_rx_simple(
                tun,
                &ip_map,
                single_conn.as_ref(),
                udp,
                &mut encrypt_buf,
            )?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            worker_tun_rx_simple(
                tun,
                &ip_map,
                single_conn.as_ref(),
                udp,
                &mut encrypt_buf,
            )?;
        }

        // If no work happened, block-wait briefly on batch channel to avoid busy spin.
        if !got_batch {
            match batch_rx.recv_timeout(Duration::from_micros(100)) {
                Ok(mut batch) => {
                    // Process this batch inline.
                    for &(offset, len, cid_key) in &batch.packets {
                        let conn = if let Some(sc) = single_conn.as_ref() {
                            sc
                        } else if let Some(c) = conn_map.get(&cid_key) {
                            c
                        } else {
                            continue;
                        };

                        let pkt = &mut batch.slab[offset..offset + len];
                        match conn.shared.decrypt_in_place(pkt) {
                            Ok(result) => {
                                if let Some(epoch_ref) = last_rx_epochs.get(&cid_key) {
                                    epoch_ref.store(epoch_millis(), Ordering::Relaxed);
                                }
                                decrypt_count += 1;
                                if decrypt_count & 0xFFFF == 0 {
                                    conn.shared.maybe_initiate_key_update(decrypt_count);
                                    decrypt_count = 0;
                                }
                                for datagram in &result.datagrams {
                                    let data = &pkt[datagram.start..datagram.end];
                                    if data.len() < 20 {
                                        continue;
                                    }
                                    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                                    if !peer::is_allowed_source(&conn.allowed_ips, src_ip) {
                                        continue;
                                    }
                                    if offload {
                                        #[cfg(target_os = "linux")]
                                        gro_tx_pool.push_datagram(data);
                                    } else {
                                        let _ = tun.send(data);
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                    batch.reset();
                    let _ = recycle_tx.try_send(batch);

                    // Flush GRO.
                    #[cfg(target_os = "linux")]
                    if offload && !gro_tx_pool.is_empty() {
                        if let Some(gro) = &mut gro_table {
                            let _ = tun.send_multiple(gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN);
                            gro_tx_pool.reset();
                        }
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    info!(worker = id, "pipeline v2 worker stopped");
    Ok(())
}

// ── Worker TUN RX with offload ──────────────────────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn worker_tun_rx_offload(
    tun: &tun_rs::SyncDevice,
    ip_map: &FxHashMap<Ipv4Addr, Arc<SharedConn>>,
    single_conn: Option<&Arc<SharedConn>>,
    udp: &std::net::UdpSocket,
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
    encrypt_buf: &mut [u8],
) -> Result<()> {
    loop {
        let n_pkts = match tun.recv_multiple(original_buf, split_bufs, split_sizes, 0) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv_multiple failed"),
        };

        for i in 0..n_pkts {
            let pkt_len = split_sizes[i];
            if pkt_len < 20 {
                continue;
            }
            let packet = &split_bufs[i][..pkt_len];
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            let conn = if let Some(sc) = single_conn {
                sc
            } else if let Some(c) = ip_map.get(&dest_ip) {
                c
            } else {
                continue;
            };

            match conn.shared.tx.encrypt_datagram(packet, encrypt_buf) {
                Ok(result) => {
                    let _ = udp.send_to(&encrypt_buf[..result.len], conn.remote_addr);
                }
                Err(_) => {}
            }
        }
    }
    Ok(())
}

/// Simple TUN RX without offload.
fn worker_tun_rx_simple(
    tun: &tun_rs::SyncDevice,
    ip_map: &FxHashMap<Ipv4Addr, Arc<SharedConn>>,
    single_conn: Option<&Arc<SharedConn>>,
    udp: &std::net::UdpSocket,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    let mut read_buf = vec![0u8; 2048];
    loop {
        match tun.recv(&mut read_buf) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }
                let dest_ip = Ipv4Addr::new(read_buf[16], read_buf[17], read_buf[18], read_buf[19]);
                let conn = if let Some(sc) = single_conn {
                    sc
                } else if let Some(c) = ip_map.get(&dest_ip) {
                    c
                } else {
                    continue;
                };
                match conn.shared.tx.encrypt_datagram(&read_buf[..n], encrypt_buf) {
                    Ok(result) => {
                        let _ = udp.send_to(&encrypt_buf[..result.len], conn.remote_addr);
                    }
                    Err(_) => {}
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }
    Ok(())
}

// ── ACK sending ─────────────────────────────────────────────────────────

fn send_acks(
    udp: &std::net::UdpSocket,
    connections: &FxHashMap<u64, DispatchConnEntry>,
    encrypt_buf: &mut [u8],
) {
    for entry in connections.values() {
        if entry.shared.replay.needs_ack() {
            let ack_ranges = entry.shared.replay.generate_ack_ranges();
            let tx = &entry.shared.tx;
            let pn = tx.next_pn();
            let key_guard = tx.load_packet_key();
            match quictun_quic::encrypt_ack_packet(
                &ack_ranges,
                tx.remote_cid(),
                pn,
                tx.largest_acked(),
                tx.key_phase(),
                &***key_guard,
                tx.header_key(),
                tx.tag_len(),
                encrypt_buf,
            ) {
                Ok(result) => {
                    let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                }
                Err(e) => {
                    warn!(error = %e, "ACK encrypt failed");
                }
            }
        }
    }
}

// ── GRO TX Pool ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
struct GroTxPool {
    bufs: Vec<Vec<u8>>,
    active: usize,
}

#[cfg(target_os = "linux")]
impl GroTxPool {
    fn new() -> Self {
        Self {
            bufs: Vec::new(),
            active: 0,
        }
    }

    fn push_datagram(&mut self, datagram: &[u8]) {
        let hdr_len = quictun_tun::VIRTIO_NET_HDR_LEN;
        let total = hdr_len + datagram.len();
        if self.active < self.bufs.len() {
            let buf = &mut self.bufs[self.active];
            buf.resize(total, 0);
            buf[..hdr_len].fill(0);
            buf[hdr_len..].copy_from_slice(datagram);
        } else {
            let mut buf = vec![0u8; total];
            buf[hdr_len..].copy_from_slice(datagram);
            self.bufs.push(buf);
        }
        self.active += 1;
    }

    fn as_mut_slice(&mut self) -> &mut [Vec<u8>] {
        &mut self.bufs[..self.active]
    }

    fn is_empty(&self) -> bool {
        self.active == 0
    }

    fn reset(&mut self) {
        self.active = 0;
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

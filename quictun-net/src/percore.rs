//! Per-core independent engine: each worker thread runs a full I/O + crypto pipeline.
//!
//! Architecture:
//!   - Handshake phase: single thread, main UDP socket
//!   - Data phase: N worker threads, each with dup'd UDP fd + TUN queue
//!     Worker loop: recvmmsg → decrypt → GRO → TUN write
//!                  TUN read → encrypt → GSO → sendmmsg
//!   - Main thread: ACK timer, keepalives, timeouts, signals
//!
//! Selected via `percore = true` + `threads >= 2` in `[engine]`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
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
#[cfg(target_os = "linux")]
use crate::engine::flush_gso_sync;
use quictun_tun::TunOptions;

const TOKEN_CONTROL: Token = Token(10);

/// Per-connection shared state for the per-core engine.
struct PercoreConnEntry {
    shared: Arc<SharedConnectionState>,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    /// Shared across workers: updated atomically by any thread on decrypt success.
    last_rx_epoch: Arc<AtomicU64>,
}

/// Immutable connection info broadcast to workers.
struct WorkerConn {
    shared: Arc<SharedConnectionState>,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    cid_key: u64,
    /// Shared with main thread for idle timeout tracking.
    last_rx_epoch: Arc<AtomicU64>,
}

pub fn run_percore(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });
    let n_workers = config.threads;
    info!(
        threads = n_workers,
        "starting per-core engine"
    );

    // 1. Create UDP socket + TUN device.
    let udp_socket = create_udp_socket(local_addr, config.recv_buf, config.send_buf)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name.clone();
    tun_opts.multi_queue = true;
    #[cfg(target_os = "linux")]
    {
        tun_opts.offload = config.offload;
    }
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
    set_nonblocking(tun.as_raw_fd())?;

    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;
    install_signal_handler(sig_write_fd)?;

    // 2. Handle handshake on main thread.
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

    // Poll for handshake completion.
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(64);
    let udp_raw_fd = udp_socket.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&udp_raw_fd), TOKEN_UDP, Interest::READABLE)?;
    poll.registry().register(
        &mut SourceFd(&sig_read_fd),
        TOKEN_SIGNAL,
        Interest::READABLE,
    )?;

    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut connections: FxHashMap<u64, PercoreConnEntry> = FxHashMap::default();
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();

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
                info!("received signal during handshake, shutting down");
                return Ok(RunResult::Shutdown);
            }
            if event.token() == TOKEN_UDP {
                // Receive and feed to handshake state machine.
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

        // Drive handshakes.
        drain_transmits(&udp_socket, &mut multi_state)?;
        let result = multi_state.poll_handshakes();
        drain_transmits(&udp_socket, &mut multi_state)?;

        for ch in result.completed {
            let Some((hs, conn_state, local_cids)) = multi_state.extract_connection(ch) else {
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
            let cid_bytes: Vec<u8> = hs.local_cid[..].to_vec();
            let cid_key = cid_to_u64(&cid_bytes);
            let _ = &local_cids; // All local CIDs available; primary used for connection table.
            let now_inst = Instant::now();

            let shared = Arc::new(conn_state.into_shared());
            let last_rx_epoch = Arc::new(AtomicU64::new(epoch_millis()));

            info!(
                remote = %hs.remote_addr,
                tunnel_ip = %tunnel_ip,
                cid = %hex::encode(&cid_bytes),
                "connection established (per-core)"
            );

            ip_to_cid.insert(tunnel_ip, cid_key);
            connections.insert(
                cid_key,
                PercoreConnEntry {
                    shared,
                    tunnel_ip,
                    allowed_ips,
                    remote_addr: hs.remote_addr,
                    keepalive_interval,
                    last_tx: now_inst,
                    last_rx_epoch,
                },
            );
        }

        // Once we have at least one connection, proceed to data phase.
        if !connections.is_empty() {
            break;
        }

        // Handle handshake timeouts.
        let now = Instant::now();
        for hs in multi_state.handshakes.values_mut() {
            hs.connection.handle_timeout(now);
        }
    }

    // 3. Build worker connection info.
    let worker_conns: Vec<Arc<WorkerConn>> = connections
        .iter()
        .map(|(&cid_key, entry)| {
            Arc::new(WorkerConn {
                shared: Arc::clone(&entry.shared),
                tunnel_ip: entry.tunnel_ip,
                allowed_ips: entry.allowed_ips.clone(),
                remote_addr: entry.remote_addr,
                cid_key,
                last_rx_epoch: Arc::clone(&entry.last_rx_epoch),
            })
        })
        .collect();

    // 4. Dup UDP fds and clone TUN queues for workers.
    let worker_udp_fds: Vec<RawFd> = (0..n_workers)
        .map(|_| dup_fd(udp_raw_fd))
        .collect::<Result<_>>()?;

    let shutdown = Arc::new(AtomicBool::new(false));

    // 5. Spawn workers.
    let cid_len = config.cid_len;
    let offload = config.offload;
    let batch_size = config.batch_size;
    let gso_max_segments = config.gso_max_segments;

    let result = std::thread::scope(|s| {
        let mut worker_handles = Vec::with_capacity(n_workers);

        for i in 0..n_workers {
            let udp_fd = worker_udp_fds[i];
            let shutdown_flag = Arc::clone(&shutdown);
            let conns = worker_conns.clone();
            let tun_clone = tun.try_clone().expect("TUN try_clone failed");

            let handle = s.spawn(move || {
                set_nonblocking(tun_clone.as_raw_fd()).expect("set TUN nonblocking");
                run_worker(
                    i,
                    udp_fd,
                    tun_clone,
                    conns,
                    cid_len,
                    offload,
                    batch_size,
                    gso_max_segments,
                    shutdown_flag,
                )
            });
            worker_handles.push(handle);
        }

        // 6. Main thread: ACK timer, keepalives, timeouts, signals.
        // Re-register poll for signal only (workers handle UDP + TUN).
        let control_result = run_control_loop(
            &udp_socket,
            &mut poll,
            sig_read_fd,
            &mut connections,
            &mut ip_to_cid,
            &config,
            &shutdown,
        );

        // Signal workers to stop.
        shutdown.store(true, Ordering::Release);

        // Wait for workers.
        for handle in worker_handles {
            let _ = handle.join();
        }

        // Close dup'd fds.
        for fd in &worker_udp_fds {
            unsafe { libc::close(*fd) };
        }

        control_result
    });

    result
}

// ── Control loop (main thread) ──────────────────────────────────────────

fn run_control_loop(
    udp: &std::net::UdpSocket,
    poll: &mut Poll,
    sig_read_fd: i32,
    connections: &mut FxHashMap<u64, PercoreConnEntry>,
    _ip_to_cid: &mut FxHashMap<Ipv4Addr, u64>,
    config: &NetConfig,
    shutdown: &AtomicBool,
) -> Result<RunResult> {
    let ack_timer_interval = Duration::from_millis(config.ack_timer_ms as u64);
    let mut next_ack_deadline = Instant::now() + ack_timer_interval;
    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut packet_counter: u64 = 0;

    loop {
        let mut timeout = ack_timer_interval;
        for entry in connections.values() {
            let ka_rem = entry
                .keepalive_interval
                .saturating_sub(entry.last_tx.elapsed());
            timeout = timeout.min(ka_rem);
        }

        let mut events = Events::with_capacity(4);
        poll.poll(&mut events, Some(timeout))?;

        for event in events.iter() {
            if event.token() == TOKEN_SIGNAL {
                drain_signal_pipe(sig_read_fd);
                info!("received signal, shutting down");

                // Send CONNECTION_CLOSE to all peers.
                for entry in connections.values() {
                    match entry.shared.tx.encrypt_datagram(&[], &mut encrypt_buf) {
                        Ok(result) => {
                            let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                        }
                        Err(_) => {}
                    }
                }
                return Ok(RunResult::Shutdown);
            }
        }

        // ACK timer.
        if Instant::now() >= next_ack_deadline {
            send_acks(udp, connections, &mut encrypt_buf);
            next_ack_deadline = Instant::now() + ack_timer_interval;
        }

        // Keepalives.
        for entry in connections.values_mut() {
            if entry.last_tx.elapsed() >= entry.keepalive_interval {
                match entry.shared.tx.encrypt_datagram(&[], &mut encrypt_buf) {
                    Ok(result) => {
                        let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                        entry.last_tx = Instant::now();
                    }
                    Err(e) => {
                        warn!(error = %e, "keepalive encrypt failed");
                    }
                }
            }
        }

        // Idle timeout check.
        let now_epoch = epoch_millis();
        let idle_ms = config.idle_timeout.as_millis() as u64;
        let expired: Vec<u64> = connections
            .iter()
            .filter(|(_, e)| {
                let last = e.last_rx_epoch.load(Ordering::Relaxed);
                now_epoch.saturating_sub(last) >= idle_ms
            })
            .map(|(&cid, _)| cid)
            .collect();

        for cid in &expired {
            if let Some(entry) = connections.remove(cid) {
                info!(
                    tunnel_ip = %entry.tunnel_ip,
                    "connection idle timeout, removed"
                );
            }
        }

        // Key rotation check (periodically).
        packet_counter += 1;
        if packet_counter % 100 == 0 {
            for entry in connections.values() {
                entry.shared.maybe_initiate_key_update(0);
            }
        }

        // If all connections dropped, return ConnectionLost.
        if connections.is_empty() {
            return Ok(RunResult::ConnectionLost);
        }
    }
}

// ── Worker thread ───────────────────────────────────────────────────────

fn run_worker(
    id: usize,
    udp_fd: RawFd,
    tun: tun_rs::SyncDevice,
    conns: Vec<Arc<WorkerConn>>,
    cid_len: usize,
    offload: bool,
    batch_size: usize,
    gso_max_segments: usize,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!(worker = id, "per-core worker started");

    let udp: std::net::UdpSocket = unsafe { std::net::UdpSocket::from_raw_fd(udp_fd) };
    // Prevent close on drop — main thread owns the fd lifetime.
    let udp_fd_raw = udp.as_raw_fd();

    // Build CID → connection lookup.
    let conn_map: FxHashMap<u64, Arc<WorkerConn>> = conns
        .iter()
        .map(|c| (c.cid_key, Arc::clone(c)))
        .collect();

    // IP → connection lookup (for TUN RX encrypt path).
    let ip_map: FxHashMap<Ipv4Addr, Arc<WorkerConn>> = conns
        .iter()
        .map(|c| (c.tunnel_ip, Arc::clone(c)))
        .collect();

    // Single connection fast path.
    let single_conn = if conns.len() == 1 {
        Some(Arc::clone(&conns[0]))
    } else {
        None
    };

    // mio poll.
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(64);

    poll.registry()
        .register(&mut SourceFd(&udp_fd_raw), TOKEN_UDP, Interest::READABLE)?;

    let tun_raw_fd = tun.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&tun_raw_fd), TOKEN_TUN, Interest::READABLE)?;

    // Buffers.
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    #[cfg(target_os = "linux")]
    let gso_buf_size = gso_max_segments * MAX_PACKET;
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; gso_buf_size];
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_addrs =
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_work = quictun_core::batch_io::RecvMmsgWork::new(batch_size);

    // GRO TX pool.
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = GroTxPool::new();
    #[cfg(target_os = "linux")]
    let mut gro_table = if offload {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };

    // TUN offload buffers.
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

    // Track packets for key rotation.
    let mut decrypt_count: u64 = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        poll.poll(&mut events, Some(Duration::from_millis(10)))?;

        let mut udp_readable = false;
        let mut tun_readable = false;

        for event in events.iter() {
            match event.token() {
                TOKEN_UDP => udp_readable = true,
                TOKEN_TUN => tun_readable = true,
                _ => {}
            }
        }

        // ── UDP RX (decrypt path) ────────────────────────────────────
        #[cfg(target_os = "linux")]
        if udp_readable {
            worker_udp_rx_linux(
                &udp,
                &tun,
                &conn_map,
                &single_conn,
                cid_len,
                &mut recv_bufs,
                &mut recv_lens,
                &mut recv_addrs,
                &mut recv_work,
                offload,
                &mut gro_tx_pool,
                &mut gro_table,
                &mut decrypt_count,
            )?;
        }

        // ── TUN RX (encrypt path) ───────────────────────────────────
        #[cfg(target_os = "linux")]
        if tun_readable {
            if offload {
                worker_tun_rx_offload(
                    &udp,
                    &tun,
                    &ip_map,
                    &single_conn,
                    &mut gso_buf,
                    &mut tun_original_buf,
                    &mut tun_split_bufs,
                    &mut tun_split_sizes,
                    gso_max_segments,
                )?;
            } else {
                worker_tun_rx(
                    &udp,
                    &tun,
                    &ip_map,
                    &single_conn,
                    &mut encrypt_buf,
                )?;
            }
        }
    }

    info!(worker = id, "per-core worker stopped");

    // Leak the UdpSocket to prevent close on drop (main thread manages the fd).
    std::mem::forget(udp);

    Ok(())
}

// ── Worker UDP RX (Linux, recvmmsg + decrypt) ───────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn worker_udp_rx_linux(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    conn_map: &FxHashMap<u64, Arc<WorkerConn>>,
    single_conn: &Option<Arc<WorkerConn>>,
    cid_len: usize,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    offload: bool,
    gro_tx_pool: &mut GroTxPool,
    gro_table: &mut Option<quictun_tun::GROTable>,
    decrypt_count: &mut u64,
) -> Result<()> {
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
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("recvmmsg failed"),
        };

        for i in 0..n_msgs {
            let n = recv_lens[i];
            if n == 0 {
                continue;
            }
            let first_byte = recv_bufs[i][0];

            // Skip handshake packets — main thread will handle on retransmit.
            if first_byte & 0x80 != 0 {
                continue;
            }

            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&recv_bufs[i][1..1 + cid_len]);

            let conn = if let Some(sc) = single_conn.as_ref() {
                sc
            } else if let Some(c) = conn_map.get(&cid_key) {
                c
            } else {
                continue;
            };

            match conn.shared.decrypt_in_place(&mut recv_bufs[i][..n]) {
                Ok(result) => {
                    // Update last_rx epoch for idle timeout.
                    conn.last_rx_epoch.store(epoch_millis(), Ordering::Relaxed);
                    *decrypt_count += 1;

                    // Key rotation check every ~64K packets.
                    if *decrypt_count & 0xFFFF == 0 {
                        conn.shared.maybe_initiate_key_update(*decrypt_count);
                        *decrypt_count = 0;
                    }

                    for datagram in &result.datagrams {
                        let data = &recv_bufs[i][datagram.start..datagram.end];
                        if data.len() < 20 {
                            continue;
                        }
                        let src_ip =
                            Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                        if !peer::is_allowed_source(&conn.allowed_ips, src_ip) {
                            debug!(src = %src_ip, "dropping: source IP not in allowed_ips");
                            continue;
                        }
                        if offload {
                            gro_tx_pool.push_datagram(data);
                        } else {
                            let _ = tun.send(data);
                        }
                    }
                }
                Err(_) => {
                    // Decrypt failure — drop silently.
                }
            }
        }

        // Flush GRO.
        if offload && !gro_tx_pool.is_empty() {
            if let Some(gro) = gro_table {
                match tun.send_multiple(gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Drop on WouldBlock — workers don't buffer.
                    }
                    Err(e) => {
                        debug!(error = %e, "TUN send_multiple failed");
                    }
                }
                gro_tx_pool.reset();
            }
        }

        if n_msgs < max_batch {
            return Ok(());
        }
    }
}

// ── Worker TUN RX with offload (encrypt + GSO send) ────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn worker_tun_rx_offload(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    ip_map: &FxHashMap<Ipv4Addr, Arc<WorkerConn>>,
    single_conn: &Option<Arc<WorkerConn>>,
    gso_buf: &mut [u8],
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
    max_segs: usize,
) -> Result<()> {
    loop {
        let n_pkts = match tun.recv_multiple(original_buf, split_bufs, split_sizes, 0) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv_multiple failed"),
        };

        // Group by connection and encrypt + GSO send.
        let mut batch_indices: SmallVec<[usize; 64]> = SmallVec::new();
        let mut batch_conn: Option<Arc<WorkerConn>> = None;

        for i in 0..n_pkts {
            let pkt_len = split_sizes[i];
            if pkt_len < 20 {
                continue;
            }
            let packet = &split_bufs[i][..pkt_len];
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            let conn = if let Some(sc) = single_conn.as_ref() {
                Arc::clone(sc)
            } else if let Some(c) = ip_map.get(&dest_ip) {
                Arc::clone(c)
            } else {
                continue;
            };

            // If connection changed, flush batch.
            if let Some(prev_conn) = batch_conn.as_ref() {
                if prev_conn.cid_key != conn.cid_key && !batch_indices.is_empty() {
                    flush_worker_gso(
                        udp, prev_conn, gso_buf, split_bufs, split_sizes,
                        &batch_indices, max_segs,
                    )?;
                    batch_indices.clear();
                }
            }
            batch_conn = Some(conn);
            batch_indices.push(i);

            if batch_indices.len() >= max_segs {
                flush_worker_gso(
                    udp,
                    batch_conn.as_ref().expect("batch_conn set"),
                    gso_buf,
                    split_bufs,
                    split_sizes,
                    &batch_indices,
                    max_segs,
                )?;
                batch_indices.clear();
            }
        }

        if let Some(conn) = batch_conn.as_ref() {
            if !batch_indices.is_empty() {
                flush_worker_gso(
                    udp, conn, gso_buf, split_bufs, split_sizes,
                    &batch_indices, max_segs,
                )?;
            }
        }
    }

    Ok(())
}

/// Encrypt a batch of payloads and send via GSO.
#[cfg(target_os = "linux")]
fn flush_worker_gso(
    udp: &std::net::UdpSocket,
    conn: &WorkerConn,
    gso_buf: &mut [u8],
    split_bufs: &[Vec<u8>],
    split_sizes: &[usize],
    indices: &[usize],
    _max_segs: usize,
) -> Result<()> {
    let tx = &conn.shared.tx;
    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;

    for &idx in indices {
        let payload = &split_bufs[idx][..split_sizes[idx]];
        match tx.encrypt_datagram(payload, &mut gso_buf[gso_pos..]) {
            Ok(result) => {
                if gso_count == 0 {
                    gso_segment_size = result.len;
                    gso_pos += result.len;
                    gso_count += 1;
                } else if result.len == gso_segment_size {
                    gso_pos += result.len;
                    gso_count += 1;
                } else {
                    // Flush accumulated, start new batch.
                    if gso_count > 0 {
                        flush_gso_sync(udp, gso_buf, gso_pos, gso_segment_size, conn.remote_addr)?;
                    }
                    gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                    gso_segment_size = result.len;
                    gso_pos = result.len;
                    gso_count = 1;
                }
            }
            Err(e) => {
                warn!(error = %e, "encrypt failed, dropping");
            }
        }
    }

    if gso_count > 0 {
        flush_gso_sync(udp, gso_buf, gso_pos, gso_segment_size, conn.remote_addr)?;
    }

    Ok(())
}

/// Simple TUN RX (no offload) — encrypt and send per-packet.
#[cfg(target_os = "linux")]
fn worker_tun_rx(
    udp: &std::net::UdpSocket,
    _tun: &tun_rs::SyncDevice,
    ip_map: &FxHashMap<Ipv4Addr, Arc<WorkerConn>>,
    single_conn: &Option<Arc<WorkerConn>>,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    // Non-offload TUN RX: read one packet at a time.
    let mut read_buf = vec![0u8; 2048];
    loop {
        match _tun.recv(&mut read_buf) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }
                let dest_ip = Ipv4Addr::new(read_buf[16], read_buf[17], read_buf[18], read_buf[19]);
                let conn = if let Some(sc) = single_conn.as_ref() {
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
            Err(e) => return Err(e).context("TUN read failed"),
        }
    }
    Ok(())
}

// ── ACK sending (main thread) ───────────────────────────────────────────

fn send_acks(
    udp: &std::net::UdpSocket,
    connections: &FxHashMap<u64, PercoreConnEntry>,
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

// ── GRO TX Pool (reuse from engine.rs) ──────────────────────────────────

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

fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error()).context("dup() failed");
    }
    Ok(new_fd)
}

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

//! Synchronous blocking engine using mio for event notification.
//!
//! Replaces tokio as the default non-DPDK data plane. No async runtime,
//! no tokio dependency. Single-thread poll loop over UDP + TUN + signal pipe.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use quinn_proto::ServerConfig;
use rustc_hash::FxHashMap;
use tracing::{debug, info, warn};

use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::MultiQuicState;
use quictun_core::routing::{RouteAction, RoutingTable};
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;
#[cfg(target_os = "linux")]
use quictun_proto::encrypt_packet;
#[cfg(target_os = "linux")]
use smallvec::SmallVec;
use quictun_tun::TunOptions;

/// Maximum QUIC packet size.
pub(crate) const MAX_PACKET: usize = 2048;

/// Handshake response buffer size.
pub(crate) const HANDSHAKE_BUF_SIZE: usize = 2048;

/// Maximum packets to buffer when TUN write returns WouldBlock.
const TUN_WRITE_BUF_CAPACITY: usize = 256;

/// Pool of reusable buffers for GRO TX coalescing.
///
/// Avoids per-datagram heap allocation on the decrypt→TUN path.
/// Inner Vecs are never dropped — only truncated and reused via `resize()`.
///
/// Each buffer is allocated with GRO_BUF_CAP capacity so that tun-rs GRO
/// can extend the first buffer in a coalescing group with subsequent packets'
/// payloads without hitting `InsufficientCap`.
#[cfg(target_os = "linux")]
pub(crate) struct GroTxPool {
    bufs: Vec<Vec<u8>>,
    active: usize,
}

/// Capacity per buffer for GRO coalescing. Must be large enough to hold
/// the maximum coalesced packet (virtio hdr + multiple TCP segments).
/// 65536 matches the max GRO/GSO packet size (16-bit gso_size field).
#[cfg(target_os = "linux")]
const GRO_BUF_CAP: usize = 65536;

#[cfg(target_os = "linux")]
impl GroTxPool {
    pub(crate) fn new() -> Self {
        Self {
            bufs: Vec::new(),
            active: 0,
        }
    }

    /// Add a datagram to the pool, prepending VIRTIO_NET_HDR_LEN zero bytes.
    pub(crate) fn push_datagram(&mut self, datagram: &[u8]) {
        let hdr_len = quictun_tun::VIRTIO_NET_HDR_LEN;
        let total = hdr_len + datagram.len();
        if self.active < self.bufs.len() {
            let buf = &mut self.bufs[self.active];
            // Ensure capacity for GRO coalescing (extend_from_slice by tun-rs).
            if buf.capacity() < GRO_BUF_CAP {
                buf.reserve(GRO_BUF_CAP - buf.capacity());
            }
            buf.resize(total, 0);
            buf[..hdr_len].fill(0);
            buf[hdr_len..].copy_from_slice(datagram);
        } else {
            let mut buf = Vec::with_capacity(GRO_BUF_CAP);
            buf.resize(total, 0);
            buf[hdr_len..].copy_from_slice(datagram);
            self.bufs.push(buf);
        }
        self.active += 1;
    }

    /// Return the active buffers as a mutable slice (for `send_multiple`).
    pub(crate) fn as_mut_slice(&mut self) -> &mut [Vec<u8>] {
        &mut self.bufs[..self.active]
    }

    /// Iterator over active buffers (for fallback WouldBlock buffering).
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.bufs[..self.active].iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.active == 0
    }

    /// Reset the pool without dropping inner Vecs.
    pub(crate) fn reset(&mut self) {
        self.active = 0;
    }
}

/// Ring buffer for TUN writes that couldn't complete due to WouldBlock.
///
/// Instead of dropping packets when the TUN device is temporarily full,
/// we buffer them and drain on the next poll iteration. This converts
/// packet loss into brief delay, which inner TCP handles gracefully
/// (delays don't trigger retransmits, but drops do).
struct TunWriteBuffer {
    packets: std::collections::VecDeque<Vec<u8>>,
}

impl TunWriteBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            packets: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    /// Try to flush all buffered packets to TUN. Stops on WouldBlock.
    /// Returns the number of packets successfully written.
    fn drain(&mut self, tun: &tun_rs::SyncDevice) -> usize {
        let mut written = 0;
        while let Some(pkt) = self.packets.front() {
            match tun.send(pkt) {
                Ok(_) => {
                    self.packets.pop_front();
                    written += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    debug!(error = %e, "TUN drain write failed, dropping packet");
                    self.packets.pop_front();
                }
            }
        }
        written
    }

    /// Write a packet to TUN, buffering on WouldBlock.
    fn write(&mut self, tun: &tun_rs::SyncDevice, data: &[u8]) {
        // If there are buffered packets, buffer this one too (preserve ordering).
        if !self.packets.is_empty() {
            self.push(data);
            return;
        }
        match tun.send(data) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.push(data);
            }
            Err(e) => {
                debug!(error = %e, "TUN write failed, dropping packet");
            }
        }
    }

    fn push(&mut self, data: &[u8]) {
        if self.packets.len() >= self.packets.capacity().max(TUN_WRITE_BUF_CAPACITY) {
            // Buffer full — drop oldest to make room (tail drop would delay newer data).
            self.packets.pop_front();
        }
        self.packets.push_back(data.to_vec());
    }

    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

// mio tokens
pub(crate) const TOKEN_UDP: Token = Token(0);
pub(crate) const TOKEN_TUN: Token = Token(1);
pub(crate) const TOKEN_SIGNAL: Token = Token(2);

/// Endpoint setup: connector or listener.
pub enum EndpointSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: quinn_proto::ClientConfig,
    },
    Listener {
        server_config: Arc<ServerConfig>,
    },
}

/// Configuration for the net engine.
#[derive(Clone)]
pub struct NetConfig {
    pub tunnel_ip: Ipv4Addr,
    pub tunnel_prefix: u8,
    pub tunnel_mtu: u16,
    pub tunnel_name: Option<String>,
    pub idle_timeout: Duration,
    pub cid_len: usize,
    pub peers: Vec<PeerConfig>,
    pub reconnect: bool,
    pub recv_buf: usize,
    pub send_buf: usize,
    pub threads: usize,
    pub offload: bool,
    pub batch_size: usize,
    pub gso_max_segments: usize,
    pub ack_interval: u32,
    pub ack_timer_ms: u32,
    pub tun_write_buf_capacity: usize,
    pub channel_capacity: usize,
    pub poll_events: usize,
    pub max_peers: usize,
    /// Server name for TLS SNI / hostname verification.
    /// Defaults to "quictun" for RPK mode. For X.509, should match the
    /// server certificate's SAN (DNS name or derive from endpoint).
    pub server_name: String,
    /// Use the v2 engine (shared event loop + ConnectionManager).
    pub engine_v2: bool,
}

/// Result of the engine run — tells the CLI whether to reconnect.
pub enum RunResult {
    Shutdown,
    ConnectionLost,
}

/// Per-connection state in the connection table.
struct ConnEntry {
    conn: LocalConnectionState,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
}

/// Main entry point for the synchronous blocking engine.
///
/// Routes to v2, pipeline, or single-thread based on config.
pub fn run(local_addr: SocketAddr, setup: EndpointSetup, config: NetConfig) -> Result<RunResult> {
    if config.engine_v2 {
        let result = crate::engine_v2::run_v2(local_addr, setup, config)?;
        match result {
            quictun_core::event_loop::RunResult::Shutdown => Ok(RunResult::Shutdown),
            quictun_core::event_loop::RunResult::ConnectionLost => Ok(RunResult::ConnectionLost),
        }
    } else if config.threads > 1 {
        crate::pipeline::run_pipeline(local_addr, setup, config)
    } else {
        run_single(local_addr, setup, config)
    }
}

/// Single-thread engine: mio poll loop over UDP + TUN + signal pipe.
fn run_single(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });

    // 1. Create UDP socket (non-blocking).
    let udp_socket = create_udp_socket(local_addr, config.recv_buf, config.send_buf)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    // NOTE: UDP GRO is NOT enabled because recvmmsg uses fixed 2048-byte buffers.
    // GRO would coalesce packets into buffers larger than 2048, causing truncation.
    // recvmmsg already provides batching (up to 64 packets per syscall).

    // 2. Create sync TUN device.
    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name;
    #[cfg(target_os = "linux")]
    {
        tun_opts.offload = config.offload;
    }
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;

    // Set TUN fd non-blocking.
    set_nonblocking(tun.as_raw_fd())?;

    // 3. Signal pipe (self-pipe trick).
    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;

    // Install signal handler.
    install_signal_handler(sig_write_fd)?;

    // 4. Create mio poll and register sources.
    let mut poll = Poll::new().context("failed to create mio::Poll")?;
    let mut events = Events::with_capacity(config.poll_events);

    let udp_raw_fd = udp_socket.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&udp_raw_fd), TOKEN_UDP, Interest::READABLE)?;

    let tun_raw_fd = tun.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&tun_raw_fd), TOKEN_TUN, Interest::READABLE)?;

    poll.registry().register(
        &mut SourceFd(&sig_read_fd),
        TOKEN_SIGNAL,
        Interest::READABLE,
    )?;

    // 5. Create MultiQuicState and initiate connection if connector.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => MultiQuicState::new(server_config.clone()),
        EndpointSetup::Connector { .. } => MultiQuicState::new_connector(),
    };
    multi_state.ack_interval = config.ack_interval;

    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        multi_state.connect(client_config, remote_addr, &config.server_name)?;

        // Drain initial handshake transmits.
        drain_transmits(&udp_socket, &mut multi_state)?;
    }

    // 6. Connection table + routing.
    let mut connections: FxHashMap<u64, ConnEntry> = FxHashMap::default();
    let mut routing_table = RoutingTable::new(config.tunnel_ip, false);
    let mut had_connection = false;

    // Buffers.
    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut scratch = BytesMut::with_capacity(2048);
    let mut tun_write_buf = TunWriteBuffer::with_capacity(config.tun_write_buf_capacity);

    // Linux: batch I/O buffers (sized from config).
    #[cfg(target_os = "linux")]
    let gso_buf_size = config.gso_max_segments * MAX_PACKET;
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; gso_buf_size];
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

    // Non-Linux: per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

    // Linux: TUN offload buffers (for recv_multiple / send_multiple).
    #[cfg(target_os = "linux")]
    let offload_enabled = config.offload;
    #[cfg(target_os = "linux")]
    let mut tun_original_buf = if offload_enabled {
        vec![0u8; quictun_tun::VIRTIO_NET_HDR_LEN + 65535]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_bufs = if offload_enabled {
        vec![vec![0u8; 1500]; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_sizes = if offload_enabled {
        vec![0usize; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut gro_table = if offload_enabled {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };
    // GRO TX buffer pool: reuses allocations across batches.
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = GroTxPool::new();

    // ACK timer state.
    let ack_timer_interval = Duration::from_millis(config.ack_timer_ms as u64);
    let mut next_ack_deadline = Instant::now() + ack_timer_interval;

    // Stats timer.
    let stats_interval = Duration::from_secs(30);
    let mut next_stats_deadline = Instant::now() + stats_interval;

    // 7. Main poll loop.
    loop {
        let timeout = compute_timeout(&connections, &mut multi_state, config.idle_timeout, next_ack_deadline);

        poll.poll(&mut events, Some(timeout))?;

        let mut signal_received = false;
        let mut udp_readable = false;
        let mut tun_readable = false;

        for event in events.iter() {
            match event.token() {
                TOKEN_SIGNAL => signal_received = true,
                TOKEN_UDP => udp_readable = true,
                TOKEN_TUN => tun_readable = true,
                _ => {}
            }
        }

        if signal_received {
            drain_signal_pipe(sig_read_fd);
            info!("received signal, shutting down");
            // Graceful shutdown: send CONNECTION_CLOSE to all connections.
            for entry in connections.values_mut() {
                if let Ok(result) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                    let _ = udp_socket.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                }
            }
            return Ok(RunResult::Shutdown);
        }

        // ── Drain buffered TUN writes ───────────────────────────────────
        if !tun_write_buf.is_empty() {
            tun_write_buf.drain(&tun);
        }

        // ── UDP RX ──────────────────────────────────────────────────────
        if udp_readable {
            #[cfg(target_os = "linux")]
            {
                handle_udp_rx_linux(
                    &udp_socket,
                    &tun,
                    &mut connections,
                    &mut routing_table,
                    config.cid_len,
                    &mut multi_state,
                    &mut recv_bufs,
                    &mut recv_lens,
                    &mut recv_addrs,
                    &mut recv_work,
                    &mut scratch,
                    &mut response_buf,
                    offload_enabled,
                    &mut gro_tx_pool,
                    &mut gro_table,
                    &mut tun_write_buf,
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                handle_udp_rx(
                    &udp_socket,
                    &tun,
                    &mut connections,
                    &mut routing_table,
                    config.cid_len,
                    &mut multi_state,
                    &mut recv_buf,
                    &mut scratch,
                    &mut response_buf,
                    &mut tun_write_buf,
                )?;
            }
        }

        // ── TUN RX ──────────────────────────────────────────────────────
        if tun_readable {
            #[cfg(target_os = "linux")]
            {
                if offload_enabled {
                    handle_tun_rx_linux_offload(
                        &udp_socket,
                        &tun,
                        &mut connections,
                        &routing_table,
                        &mut gso_buf,
                        &mut tun_original_buf,
                        &mut tun_split_bufs,
                        &mut tun_split_sizes,
                    )?;
                } else {
                    handle_tun_rx_linux(
                        &udp_socket,
                        &tun,
                        &mut connections,
                        &routing_table,
                        &mut gso_buf,
                        &mut encrypt_buf,
                    )?;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                handle_tun_rx(
                    &udp_socket,
                    &tun,
                    &mut connections,
                    &routing_table,
                    &mut encrypt_buf,
                )?;
            }
        }

        // ── Timeouts ────────────────────────────────────────────────────
        handle_timeouts(
            &udp_socket,
            &mut connections,
            &mut routing_table,
            &mut multi_state,
            config.idle_timeout,
            &mut encrypt_buf,
        )?;

        // ── Standalone ACK timer + stats (share single Instant::now()) ──
        let now = Instant::now();
        if now >= next_ack_deadline {
            send_acks(&udp_socket, &mut connections, &mut encrypt_buf);
            next_ack_deadline = now + ack_timer_interval;
        }

        // ── Drive handshakes ────────────────────────────────────────────
        drive_handshakes(
            &udp_socket,
            &mut multi_state,
            &mut connections,
            &mut routing_table,
            &config.peers,
            config.max_peers,
        )?;

        // ── Periodic stats (reuses `now` from ACK timer above) ──────────
        if now >= next_stats_deadline {
            info!(
                connections = connections.len(),
                routes = routing_table.len(),
                handshakes = multi_state.handshakes.len(),
                "periodic stats"
            );
            next_stats_deadline = now + stats_interval;
        }

        // Track whether we ever had a connection (for ConnectionLost detection).
        if !had_connection && !connections.is_empty() {
            had_connection = true;
        }

        // ── ConnectionLost detection (connector only) ────────────────────
        if is_connector
            && had_connection
            && connections.is_empty()
            && multi_state.handshakes.is_empty()
        {
            info!("all connections lost, returning ConnectionLost for reconnect");
            return Ok(RunResult::ConnectionLost);
        }
    }
}

// ── UDP socket creation ──────────────────────────────────────────────────

pub(crate) fn create_udp_socket(
    addr: SocketAddr,
    recv_buf: usize,
    send_buf: usize,
) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create UDP socket")?;

    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_send_buffer_size(send_buf);
    let _ = sock.set_recv_buffer_size(recv_buf);

    // Warn if kernel clamped the buffer sizes (common when rmem_max is too low).
    if let Ok(actual_recv) = sock.recv_buffer_size() {
        if actual_recv < recv_buf / 2 {
            warn!(
                requested = recv_buf,
                actual = actual_recv,
                "UDP recv buffer clamped by kernel — set net.core.rmem_max >= {} to avoid packet drops",
                recv_buf,
            );
        }
    }
    if let Ok(actual_send) = sock.send_buffer_size() {
        if actual_send < send_buf / 2 {
            warn!(
                requested = send_buf,
                actual = actual_send,
                "UDP send buffer clamped by kernel — set net.core.wmem_max >= {}",
                send_buf,
            );
        }
    }

    sock.bind(&addr.into())
        .with_context(|| format!("failed to bind UDP to {addr}"))?;

    Ok(sock.into())
}

pub(crate) fn set_nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("fcntl F_GETFL");
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK");
    }
    Ok(())
}

// ── Signal pipe ──────────────────────────────────────────────────────────

pub(crate) fn create_signal_pipe() -> Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("pipe() failed");
    }
    set_nonblocking(fds[0])?;
    set_nonblocking(fds[1])?;
    Ok((fds[0], fds[1]))
}

static SIGNAL_WRITE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

extern "C" fn signal_handler(_sig: libc::c_int) {
    let fd = SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1) };
    }
}

pub(crate) fn install_signal_handler(write_fd: i32) -> Result<()> {
    SIGNAL_WRITE_FD.store(write_fd, Ordering::Release);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;

        if libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) < 0 {
            return Err(io::Error::last_os_error()).context("sigaction SIGINT");
        }
        if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) < 0 {
            return Err(io::Error::last_os_error()).context("sigaction SIGTERM");
        }
    }
    Ok(())
}

pub(crate) fn drain_signal_pipe(read_fd: i32) {
    let mut buf = [0u8; 64];
    loop {
        let ret = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret <= 0 {
            break;
        }
    }
}

// ── Timeout computation ──────────────────────────────────────────────────

fn compute_timeout(
    connections: &FxHashMap<u64, ConnEntry>,
    multi_state: &mut MultiQuicState,
    idle_timeout: Duration,
    next_ack_deadline: Instant,
) -> Duration {
    let mut min_timeout = Duration::from_secs(5);

    for entry in connections.values() {
        let keepalive_remaining = entry
            .keepalive_interval
            .saturating_sub(entry.last_tx.elapsed());
        let idle_remaining = idle_timeout.saturating_sub(entry.last_rx.elapsed());
        min_timeout = min_timeout.min(keepalive_remaining).min(idle_remaining);
    }

    for hs in multi_state.handshakes.values_mut() {
        if let Some(deadline) = hs.connection.poll_timeout() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            min_timeout = min_timeout.min(remaining);
        }
    }

    // ACK timer.
    let ack_remaining = next_ack_deadline.saturating_duration_since(Instant::now());
    min_timeout = min_timeout.min(ack_remaining);

    // Ensure at least 1ms to avoid busy spin on zero timeout.
    min_timeout.max(Duration::from_millis(1))
}

/// Send standalone ACK packets for all connections that need them.
fn send_acks(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ConnEntry>,
    encrypt_buf: &mut [u8],
) {
    for entry in connections.values_mut() {
        if entry.conn.needs_ack() {
            match entry.conn.encrypt_ack(encrypt_buf) {
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

// ── Drain transmits from MultiQuicState ──────────────────────────────────

pub(crate) fn drain_transmits(udp: &std::net::UdpSocket, state: &mut MultiQuicState) -> Result<()> {
    let now = Instant::now();
    let mut buf = Vec::with_capacity(HANDSHAKE_BUF_SIZE);

    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut buf) else {
                break;
            };
            udp.send_to(&buf[..transmit.size], hs.remote_addr)?;
        }
    }
    Ok(())
}

// ── UDP RX (Linux — recvmmsg batch) ──────────────────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn handle_udp_rx_linux(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &mut RoutingTable,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
    offload: bool,
    gro_tx_pool: &mut GroTxPool,
    gro_table: &mut Option<quictun_tun::GROTable>,
    tun_write_buf: &mut TunWriteBuffer,
) -> Result<()> {
    // Loop recvmmsg until WouldBlock — required for edge-triggered epoll (mio).
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

            if first_byte & 0x80 != 0 {
                // Long header → handshake.
                let from = recv_addrs[i];
                let mut data = BytesMut::with_capacity(n);
                data.extend_from_slice(&recv_bufs[i][..n]);
                let now = Instant::now();
                let responses = multi_state.handle_incoming(now, from, None, data, response_buf);
                send_responses(udp, &responses, from)?;
                continue;
            }

            // Short header → CID routing.
            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&recv_bufs[i][1..1 + cid_len]);

            let close_received = if let Some(entry) = connections.get_mut(&cid_key) {
                match entry
                    .conn
                    .decrypt_packet_with_buf(&mut recv_bufs[i][..n], scratch)
                {
                    Ok(decrypted) => {
                        entry.last_rx = Instant::now();
                        if let Some(ref ack) = decrypted.ack {
                            entry.conn.process_ack(ack);
                        }
                        if !decrypted.close_received {
                            for datagram in &decrypted.datagrams {
                                if datagram.len() < 20 {
                                    continue;
                                }
                                let src_ip = Ipv4Addr::new(
                                    datagram[12],
                                    datagram[13],
                                    datagram[14],
                                    datagram[15],
                                );
                                if !peer::is_allowed_source(&entry.allowed_ips, src_ip) {
                                    debug!(src = %src_ip, "dropping packet: source IP not in allowed_ips");
                                    continue;
                                }
                                if offload {
                                    gro_tx_pool.push_datagram(datagram);
                                } else {
                                    tun_write_buf.write(tun, datagram);
                                }
                            }
                        }
                        decrypted.close_received
                    }
                    Err(e) => {
                        debug!(error = %e, "decrypt failed, dropping");
                        false
                    }
                }
            } else {
                false
            };
            if close_received && let Some(entry) = connections.remove(&cid_key) {
                routing_table.remove_peer_routes(cid_key);
                info!(
                    tunnel_ip = %entry.tunnel_ip,
                    cid = %hex::encode(cid_key.to_ne_bytes()),
                    "peer sent CONNECTION_CLOSE, removed"
                );
            }
        }

        // Flush accumulated GRO TX buffers.
        if offload && !gro_tx_pool.is_empty() {
            if let Some(gro) = gro_table {
                match tun.send_multiple(gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        for buf in gro_tx_pool.iter() {
                            tun_write_buf.push(buf);
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "TUN send_multiple failed");
                    }
                }
                gro_tx_pool.reset();
            }
        }

        // If we got fewer than batch size, the socket is drained.
        if n_msgs < max_batch {
            return Ok(());
        }
    }
}

// ── UDP RX (non-Linux — per-packet recv_from) ────────────────────────────

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn handle_udp_rx(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &mut RoutingTable,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_buf: &mut [u8],
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
    tun_write_buf: &mut TunWriteBuffer,
) -> Result<()> {
    loop {
        match udp.recv_from(recv_buf) {
            Ok((n, from)) => {
                if n == 0 {
                    continue;
                }

                if recv_buf[0] & 0x80 != 0 {
                    // Long header → handshake.
                    let mut data = BytesMut::with_capacity(n);
                    data.extend_from_slice(&recv_buf[..n]);
                    let now = Instant::now();
                    let responses =
                        multi_state.handle_incoming(now, from, None, data, response_buf);
                    send_responses(udp, &responses, from)?;
                } else {
                    // Short header → CID routing.
                    if cid_len > 0 && n > cid_len {
                        let cid_key = cid_to_u64(&recv_buf[1..1 + cid_len]);
                        let close_received = if let Some(entry) =
                            connections.get_mut(&cid_key)
                        {
                            match entry
                                .conn
                                .decrypt_packet_with_buf(&mut recv_buf[..n], scratch)
                            {
                                Ok(decrypted) => {
                                    entry.last_rx = Instant::now();
                                    if let Some(ref ack) = decrypted.ack {
                                        entry.conn.process_ack(ack);
                                    }
                                    if !decrypted.close_received {
                                        for datagram in &decrypted.datagrams {
                                            if datagram.len() < 20 {
                                                continue;
                                            }
                                            let src_ip = Ipv4Addr::new(
                                                datagram[12],
                                                datagram[13],
                                                datagram[14],
                                                datagram[15],
                                            );
                                            if !peer::is_allowed_source(&entry.allowed_ips, src_ip)
                                            {
                                                debug!(src = %src_ip, "dropping: source IP not in allowed_ips");
                                                continue;
                                            }
                                            tun_write_buf.write(tun, datagram);
                                        }
                                    }
                                    decrypted.close_received
                                }
                                Err(e) => {
                                    debug!(error = %e, "decrypt failed, dropping");
                                    false
                                }
                            }
                        } else {
                            false
                        };
                        if close_received && let Some(entry) = connections.remove(&cid_key) {
                            routing_table.remove_peer_routes(cid_key);
                            info!(
                                tunnel_ip = %entry.tunnel_ip,
                                cid = %hex::encode(cid_key.to_ne_bytes()),
                                "peer sent CONNECTION_CLOSE, removed"
                            );
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("UDP recv_from failed"),
        }
    }
    Ok(())
}

// ── TUN RX (Linux — GSO batching) ───────────────────────────────────────

#[cfg(target_os = "linux")]
fn handle_tun_rx_linux(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &RoutingTable,
    gso_buf: &mut [u8],
    encrypt_buf: &mut [u8],
) -> Result<()> {
    let max_segs = gso_buf.len() / MAX_PACKET;
    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;
    let mut current_cid: Option<u64> = None;
    let mut current_remote: Option<SocketAddr> = None;

    loop {
        let mut packet = [0u8; 1500];
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }

                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = match routing_table.lookup(dest_ip) {
                    RouteAction::ForwardToPeer(cid) => cid,
                    _ if connections.len() == 1 => {
                        match connections.keys().next() {
                            Some(&cid) => cid,
                            None => continue,
                        }
                    }
                    _ => {
                        debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                        continue;
                    }
                };

                // Flush current GSO batch if connection changed or batch full.
                if let Some(ref cur_cid) = current_cid {
                    if *cur_cid != cid
                        || gso_count >= max_segs
                        || gso_pos + MAX_PACKET > gso_buf.len()
                    {
                        if gso_count > 0 {
                            flush_gso_sync(
                                udp,
                                gso_buf,
                                gso_pos,
                                gso_segment_size,
                                current_remote.expect("remote set"),
                            )?;
                            if let Some(entry) = connections.get_mut(cur_cid) {
                                entry.last_tx = Instant::now();
                            }
                        }
                        gso_pos = 0;
                        gso_segment_size = 0;
                        gso_count = 0;
                    }
                }

                let entry = match connections.get_mut(&cid) {
                    Some(e) => e,
                    None => continue,
                };

                current_cid = Some(cid);
                current_remote = Some(entry.remote_addr);

                match entry.conn.encrypt_datagram(
                    &packet[..n],
                    &mut gso_buf[gso_pos..],
                ) {
                    Ok(result) => {
                        if gso_count == 0 {
                            gso_segment_size = result.len;
                            gso_pos += result.len;
                            gso_count += 1;
                        } else if result.len == gso_segment_size {
                            gso_pos += result.len;
                            gso_count += 1;
                        } else {
                            // Odd-sized: flush accumulated batch first, then
                            // start a new batch with this packet as the first
                            // segment (it may match future packets).
                            if gso_count > 0 {
                                flush_gso_sync(
                                    udp,
                                    gso_buf,
                                    gso_pos,
                                    gso_segment_size,
                                    entry.remote_addr,
                                )?;
                            }
                            // Move odd packet to start of buffer and start new batch.
                            gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                            gso_segment_size = result.len;
                            gso_pos = result.len;
                            gso_count = 1;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed, dropping packet");
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }

    // Flush remaining GSO batch.
    if gso_count > 0 {
        flush_gso_sync(
            udp,
            gso_buf,
            gso_pos,
            gso_segment_size,
            current_remote.expect("remote set"),
        )?;
        if let Some(ref cid) = current_cid {
            if let Some(entry) = connections.get_mut(&cid) {
                entry.last_tx = Instant::now();
            }
        }
    }

    let _ = encrypt_buf;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn flush_gso_sync(
    udp: &std::net::UdpSocket,
    gso_buf: &[u8],
    gso_pos: usize,
    gso_segment_size: usize,
    remote_addr: SocketAddr,
) -> Result<()> {
    loop {
        match quictun_core::batch_io::send_gso(
            udp,
            &gso_buf[..gso_pos],
            gso_segment_size as u16,
            remote_addr,
        ) {
            Ok(_) => {
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Wait for socket to become writable via poll(2).
                wait_writable(udp.as_raw_fd());
            }
            Err(e) => return Err(e).context("send_gso failed"),
        }
    }
}

/// Block until fd is writable using poll(2). Short timeout to avoid stalling.
#[cfg(target_os = "linux")]
pub(crate) fn wait_writable(fd: i32) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, 5) }; // 5ms max
    if ret < 0 {
        tracing::trace!(error = %io::Error::last_os_error(), "poll(POLLOUT) failed");
    }
}

// ── TUN RX (non-Linux — per-packet send) ─────────────────────────────────

#[cfg(not(target_os = "linux"))]
fn handle_tun_rx(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &RoutingTable,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    loop {
        let mut packet = [0u8; 1500];
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }

                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = match routing_table.lookup(dest_ip) {
                    RouteAction::ForwardToPeer(cid) => cid,
                    _ if connections.len() == 1 => {
                        match connections.keys().next() {
                            Some(&cid) => cid,
                            None => continue,
                        }
                    }
                    _ => continue,
                };

                let entry = match connections.get_mut(&cid) {
                    Some(e) => e,
                    None => continue,
                };

                match entry
                    .conn
                    .encrypt_datagram(&packet[..n], encrypt_buf)
                {
                    Ok(result) => {
                        udp.send_to(&encrypt_buf[..result.len], entry.remote_addr)?;
                        entry.last_tx = Instant::now();
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed, dropping packet");
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }
    Ok(())
}

// ── Timeout handling ─────────────────────────────────────────────────────

fn handle_timeouts(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &mut RoutingTable,
    multi_state: &mut MultiQuicState,
    idle_timeout: Duration,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    // Remove idle or key-exhausted connections.
    let expired: Vec<(u64, &'static str)> = connections
        .iter()
        .filter_map(|(&cid, e)| {
            if e.conn.is_key_exhausted() {
                Some((cid, "key exhausted"))
            } else if e.last_rx.elapsed() >= idle_timeout {
                Some((cid, "idle timeout"))
            } else {
                None
            }
        })
        .collect();

    for (cid, reason) in expired {
        if let Some(entry) = connections.remove(&cid) {
            routing_table.remove_peer_routes(cid);
            info!(
                tunnel_ip = %entry.tunnel_ip,
                cid = %hex::encode(cid.to_ne_bytes()),
                reason,
                "connection removed"
            );
        }
    }

    // Send keepalives.
    for entry in connections.values_mut() {
        if entry.last_tx.elapsed() >= entry.keepalive_interval {
            match entry.conn.encrypt_datagram(&[], encrypt_buf) {
                Ok(result) => {
                    udp.send_to(&encrypt_buf[..result.len], entry.remote_addr)?;
                    entry.last_tx = Instant::now();
                    debug!(pn = result.pn, remote = %entry.remote_addr, "sent keepalive");
                }
                Err(e) => {
                    warn!(error = %e, "keepalive encrypt failed");
                }
            }
        }
    }

    // Handshake timeouts.
    let now = Instant::now();
    for hs in multi_state.handshakes.values_mut() {
        hs.connection.handle_timeout(now);
    }

    Ok(())
}

// ── Handshake driving ────────────────────────────────────────────────────

fn drive_handshakes(
    udp: &std::net::UdpSocket,
    multi_state: &mut MultiQuicState,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &mut RoutingTable,
    peers: &[PeerConfig],
    max_peers: usize,
) -> Result<()> {
    if multi_state.handshakes.is_empty() {
        return Ok(());
    }

    // Drain transmits for all handshakes first.
    drain_transmits(udp, multi_state)?;

    // Poll for completed/failed handshakes.
    let result = multi_state.poll_handshakes();

    // Drain transmits again after polling (may have new packets).
    drain_transmits(udp, multi_state)?;

    // Promote completed handshakes.
    for ch in result.completed {
        let Some((hs, mut conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        // 1. Always identify peer (no single-peer skip — X.509 needs CN check).
        let matched_peer = match peer::identify_peer(&hs.connection, peers) {
            Some(p) => p,
            None => {
                warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                let mut close_buf = vec![0u8; 128];
                if let Ok(result) = conn_state.encrypt_connection_close(&mut close_buf) {
                    if let Err(e) = udp.send_to(&close_buf[..result.len], hs.remote_addr) {
                        warn!(error = %e, "failed to send CONNECTION_CLOSE for rejected peer");
                    }
                }
                continue;
            }
        };
        let tunnel_ip = matched_peer.tunnel_ip;
        let allowed_ips = matched_peer.allowed_ips.clone();
        let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));

        // 2. Reconnect: if this peer already has a connection, evict the old one.
        let old_cid = connections
            .iter()
            .find(|(_, e)| e.tunnel_ip == tunnel_ip)
            .map(|(&cid, _)| cid);
        if let Some(old) = old_cid {
            if let Some(entry) = connections.remove(&old) {
                routing_table.remove_peer_routes(old);
                info!(
                    tunnel_ip = %entry.tunnel_ip,
                    old_cid = %hex::encode(old.to_ne_bytes()),
                    "evicted stale connection (peer reconnected)"
                );
            }
        }

        // 3. Check max_peers (after eviction, so reconnects don't count double).
        if connections.len() >= max_peers {
            warn!(max_peers, remote = %hs.remote_addr, "max_peers reached, rejecting");
            let mut close_buf = vec![0u8; 128];
            if let Ok(result) = conn_state.encrypt_connection_close(&mut close_buf) {
                if let Err(e) = udp.send_to(&close_buf[..result.len], hs.remote_addr) {
                    warn!(error = %e, "failed to send CONNECTION_CLOSE for max_peers rejection");
                }
            }
            continue;
        }

        let cid_bytes: Vec<u8> = conn_state.local_cid()[..].to_vec();
        let primary_cid_key = cid_to_u64(&cid_bytes);
        let now_inst = Instant::now();

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            active = connections.len() + 1,
            "connection established"
        );

        routing_table.add_peer_routes(primary_cid_key, &allowed_ips);
        connections.insert(
            primary_cid_key,
            ConnEntry {
                conn: conn_state,
                tunnel_ip,
                allowed_ips,
                remote_addr: hs.remote_addr,
                keepalive_interval,
                last_tx: now_inst,
                last_rx: now_inst,
            },
        );
    }

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────

pub(crate) fn send_responses(
    udp: &std::net::UdpSocket,
    responses: &[Vec<u8>],
    addr: SocketAddr,
) -> Result<()> {
    for buf in responses {
        udp.send_to(buf, addr)?;
    }
    Ok(())
}

// ── TUN RX with offload (Linux — recv_multiple GSO splitting) ────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn handle_tun_rx_linux_offload(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ConnEntry>,
    routing_table: &RoutingTable,
    gso_buf: &mut [u8],
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
) -> Result<()> {
    let max_segs = gso_buf.len() / MAX_PACKET;

    loop {
        let n_pkts = match tun.recv_multiple(original_buf, split_bufs, split_sizes, 0) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv_multiple failed"),
        };

        // Collect valid payloads and group by CID.
        // Common case: all packets go to the same connection.
        let mut batch_payloads: SmallVec<[usize; 64]> = SmallVec::new(); // indices into split_bufs
        let mut batch_cid: Option<u64> = None;

        for i in 0..n_pkts {
            let pkt_len = split_sizes[i];
            if pkt_len < 20 {
                continue;
            }
            let packet = &split_bufs[i][..pkt_len];
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            let cid = match routing_table.lookup(dest_ip) {
                RouteAction::ForwardToPeer(cid) => cid,
                _ if connections.len() == 1 => {
                    *connections.keys().next().expect("single connection")
                }
                _ => {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                    continue;
                }
            };

            // If CID changed, flush the current batch first.
            if let Some(prev_cid) = batch_cid {
                if prev_cid != cid && !batch_payloads.is_empty() {
                    flush_offload_batch(
                        udp, connections, gso_buf, split_bufs, split_sizes,
                        &batch_payloads, prev_cid, max_segs,
                    )?;
                    batch_payloads.clear();
                }
            }
            batch_cid = Some(cid);
            batch_payloads.push(i);

            // Flush if batch full (max GSO segments).
            if batch_payloads.len() >= max_segs {
                flush_offload_batch(
                    udp, connections, gso_buf, split_bufs, split_sizes,
                    &batch_payloads, cid, max_segs,
                )?;
                batch_payloads.clear();
            }
        }

        // Flush remaining batch.
        if let Some(cid) = batch_cid {
            if !batch_payloads.is_empty() {
                flush_offload_batch(
                    udp, connections, gso_buf, split_bufs, split_sizes,
                    &batch_payloads, cid, max_segs,
                )?;
            }
        }
    }

    Ok(())
}

/// Flush a batch of TUN packets for a single connection via sequential encrypt + GSO send.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn flush_offload_batch(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ConnEntry>,
    gso_buf: &mut [u8],
    split_bufs: &[Vec<u8>],
    split_sizes: &[usize],
    indices: &[usize],
    cid: u64,
    max_segs: usize,
) -> Result<()> {
    let entry = match connections.get_mut(&cid) {
        Some(e) => e,
        None => return Ok(()),
    };

    let count = indices.len();

    // Collect payload references.
    let payloads: SmallVec<[&[u8]; 64]> = indices
        .iter()
        .map(|&i| &split_bufs[i][..split_sizes[i]])
        .collect();

    // Assign PNs.
    let prepared = entry.conn.prepare_batch(count);
    let actual_count = prepared.len(); // may be truncated at key update boundary

    // Sequential encrypt contiguously into gso_buf.
    let keys = entry.conn.seal_keys();
    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;

    for i in 0..actual_count {
        match encrypt_packet(
            payloads[i],
            keys.remote_cid,
            prepared[i].pn,
            prepared[i].largest_acked,
            prepared[i].key_phase,
            keys.tx_packet_key,
            keys.tx_header_key,
            keys.tag_len,
            &mut gso_buf[gso_pos..],
        ) {
            Ok(result) => {
                if gso_count == 0 {
                    gso_segment_size = result.len;
                    gso_pos += result.len;
                    gso_count += 1;
                } else if result.len == gso_segment_size {
                    gso_pos += result.len;
                    gso_count += 1;
                } else {
                    // Odd-sized packet: flush accumulated, start new batch.
                    if gso_count > 0 {
                        flush_gso_sync(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr)?;
                    }
                    gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                    gso_segment_size = result.len;
                    gso_pos = result.len;
                    gso_count = 1;
                }
            }
            Err(e) => {
                warn!(error = %e, "encrypt failed in batch, dropping packet");
            }
        }
    }

    if gso_count > 0 {
        flush_gso_sync(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr)?;
        entry.last_tx = Instant::now();
    }

    // If prepare_batch truncated at key update, process remainder.
    if actual_count < count {
        let remaining_indices: SmallVec<[usize; 64]> = indices[actual_count..].iter().copied().collect();
        flush_offload_batch(
            udp, connections, gso_buf, split_bufs, split_sizes,
            &remaining_indices, cid, max_segs,
        )?;
    }

    Ok(())
}


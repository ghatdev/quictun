//! Synchronous blocking engine using mio for event notification.
//!
//! Replaces tokio as the default non-DPDK data plane. No async runtime,
//! no tokio dependency. Single-thread poll loop over UDP + TUN + signal pipe.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use quinn_proto::ServerConfig;
use rustc_hash::FxHashMap;
use tracing::{debug, info, warn};

use crate::dispatch::{
    ControlMessage, InnerPacket, NetDispatchTable, OuterPacket, RemovedConnection, WorkerChannels,
};
use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::{BUF_SIZE, MultiQuicState};
use quictun_quic::cid_to_u64;
#[cfg(target_os = "linux")]
use quictun_quic::local::{PreparedPacket, SealKeys};
use quictun_quic::local::LocalConnectionState;
#[cfg(target_os = "linux")]
use quictun_quic::{EncryptResult, encrypt_packet};
use quictun_tun::TunOptions;
#[cfg(target_os = "linux")]
use smallvec::SmallVec;

/// Maximum QUIC packet size.
const MAX_PACKET: usize = 2048;

/// Get the number of available CPUs.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Handshake response buffer size.
const HANDSHAKE_BUF_SIZE: usize = 2048;

/// Maximum packets to buffer when TUN write returns WouldBlock.
const TUN_WRITE_BUF_CAPACITY: usize = 256;

/// Pool of reusable buffers for GRO TX coalescing.
///
/// Avoids per-datagram heap allocation on the decrypt→TUN path.
/// Inner Vecs are never dropped — only truncated and reused via `resize()`.
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

    /// Add a datagram to the pool, prepending VIRTIO_NET_HDR_LEN zero bytes.
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

    /// Return the active buffers as a mutable slice (for `send_multiple`).
    fn as_mut_slice(&mut self) -> &mut [Vec<u8>] {
        &mut self.bufs[..self.active]
    }

    /// Iterator over active buffers (for fallback WouldBlock buffering).
    fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.bufs[..self.active].iter()
    }

    fn is_empty(&self) -> bool {
        self.active == 0
    }

    /// Reset the pool without dropping inner Vecs.
    fn reset(&mut self) {
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
    fn new() -> Self {
        Self::with_capacity(TUN_WRITE_BUF_CAPACITY)
    }

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

    /// Try to flush all buffered packets via raw fd write (for workers).
    fn drain_raw(&mut self, tun_fd: RawFd) -> usize {
        let mut written = 0;
        while let Some(pkt) = self.packets.front() {
            let ret =
                unsafe { libc::write(tun_fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                debug!(error = %err, "TUN drain write (raw) failed, dropping packet");
            }
            self.packets.pop_front();
            if ret >= 0 {
                written += 1;
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

    /// Write a packet via raw fd, buffering on WouldBlock (for workers).
    fn write_raw(&mut self, tun_fd: RawFd, data: &[u8]) {
        if !self.packets.is_empty() {
            self.push(data);
            return;
        }
        let ret = unsafe { libc::write(tun_fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                self.push(data);
            } else {
                debug!(error = %err, "TUN write (raw) failed, dropping packet");
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
const TOKEN_UDP: Token = Token(0);
const TOKEN_TUN: Token = Token(1);
const TOKEN_SIGNAL: Token = Token(2);

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
    pub encrypt_threads: usize,
    pub parallel_threshold: usize,
    pub ack_interval: u32,
    pub tun_write_buf_capacity: usize,
    pub channel_capacity: usize,
    pub poll_events: usize,
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
/// Routes to single-thread or multi-thread path based on `config.threads`.
pub fn run(local_addr: SocketAddr, setup: EndpointSetup, config: NetConfig) -> Result<RunResult> {
    // Configure rayon thread pool for parallel encrypt.
    let encrypt_threads = if config.encrypt_threads == 0 {
        // Auto: use all available cores minus 1 (leave one for the main loop).
        num_cpus().saturating_sub(1).max(1)
    } else {
        config.encrypt_threads
    };
    rayon::ThreadPoolBuilder::new()
        .num_threads(encrypt_threads)
        .build_global()
        .ok(); // Ignore if already initialized.
    info!(encrypt_threads, "rayon thread pool configured");

    if config.threads > 1 {
        run_multi(local_addr, setup, config)
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
        multi_state.connect(client_config, remote_addr)?;

        // Drain initial handshake transmits.
        drain_transmits(&udp_socket, &mut multi_state)?;
    }

    // 6. Connection table.
    let mut connections: FxHashMap<u64, ConnEntry> = FxHashMap::default();
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();
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

    // 7. Main poll loop.
    loop {
        let timeout = compute_timeout(&connections, &mut multi_state, config.idle_timeout);

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
                    config.cid_len,
                    &mut multi_state,
                    &mut recv_bufs,
                    &mut recv_lens,
                    &mut recv_addrs,
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
                        &ip_to_cid,
                        &mut gso_buf,
                        &mut tun_original_buf,
                        &mut tun_split_bufs,
                        &mut tun_split_sizes,
                        config.parallel_threshold,
                    )?;
                } else {
                    handle_tun_rx_linux(
                        &udp_socket,
                        &tun,
                        &mut connections,
                        &ip_to_cid,
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
                    &ip_to_cid,
                    &mut encrypt_buf,
                )?;
            }
        }

        // ── Timeouts ────────────────────────────────────────────────────
        handle_timeouts(
            &udp_socket,
            &mut connections,
            &mut ip_to_cid,
            &mut multi_state,
            config.idle_timeout,
            &mut encrypt_buf,
        )?;

        // ── Drive handshakes ────────────────────────────────────────────
        drive_handshakes(
            &udp_socket,
            &mut multi_state,
            &mut connections,
            &mut ip_to_cid,
            &config.peers,
        )?;

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

fn create_udp_socket(
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

fn set_nonblocking(fd: i32) -> Result<()> {
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

fn create_signal_pipe() -> Result<(i32, i32)> {
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

fn install_signal_handler(write_fd: i32) -> Result<()> {
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

fn drain_signal_pipe(read_fd: i32) {
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

    // Ensure at least 1ms to avoid busy spin on zero timeout.
    min_timeout.max(Duration::from_millis(1))
}

// ── Drain transmits from MultiQuicState ──────────────────────────────────

fn drain_transmits(udp: &std::net::UdpSocket, state: &mut MultiQuicState) -> Result<()> {
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
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
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
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
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

                let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                    cid
                } else if connections.len() == 1 {
                    *connections
                        .keys()
                        .next()
                        .expect("single connection")
                } else {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                    continue;
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

                let ack_ranges = if entry.conn.needs_ack() {
                    Some(entry.conn.generate_ack_ranges())
                } else {
                    None
                };
                match entry.conn.encrypt_datagram(
                    &packet[..n],
                    ack_ranges.as_deref(),
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
fn flush_gso_sync(
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
fn wait_writable(fd: i32) {
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

// ── Parallel encrypt helpers ─────────────────────────────────────────────

/// Encrypt a batch of packets in parallel using rayon.
///
/// Each packet is written into a stride-spaced slot in `gso_buf`.
/// Returns per-packet `EncryptResult` with actual encrypted length.
#[cfg(target_os = "linux")]
fn seal_batch_parallel(
    payloads: &[&[u8]],
    prepared: &[PreparedPacket],
    ack_ranges: Option<&SmallVec<[std::ops::Range<u64>; 8]>>,
    keys: &SealKeys<'_>,
    gso_buf: &mut [u8],
    stride: usize,
) -> SmallVec<[EncryptResult; 64]> {
    use rayon::prelude::*;

    let count = payloads.len().min(prepared.len());

    // Split gso_buf into non-overlapping stride-sized chunks.
    // We'll use unsafe to get non-overlapping &mut [u8] slices for parallel access.
    let buf_ptr = gso_buf.as_mut_ptr();
    let buf_len = gso_buf.len();

    let results: Vec<EncryptResult> = (0..count)
        .into_par_iter()
        .map(|i| {
            let offset = i * stride;
            if offset + stride > buf_len {
                return EncryptResult { len: 0, pn: prepared[i].pn };
            }
            // SAFETY: Each thread writes to non-overlapping [offset..offset+stride].
            let chunk = unsafe {
                std::slice::from_raw_parts_mut(buf_ptr.add(offset), stride)
            };

            let ack = if i == 0 {
                ack_ranges.map(|r| r.as_slice())
            } else {
                None
            };

            match encrypt_packet(
                payloads[i],
                ack,
                keys.remote_cid,
                prepared[i].pn,
                prepared[i].largest_acked,
                prepared[i].key_phase,
                keys.tx_packet_key,
                keys.tx_header_key,
                keys.tag_len,
                chunk,
            ) {
                Ok(result) => result,
                Err(_) => EncryptResult { len: 0, pn: prepared[i].pn },
            }
        })
        .collect();

    SmallVec::from_vec(results)
}

/// Encrypt a batch of packets sequentially (small batches, avoids rayon overhead).
#[cfg(target_os = "linux")]
fn seal_batch_sequential(
    payloads: &[&[u8]],
    prepared: &[PreparedPacket],
    ack_ranges: Option<&SmallVec<[std::ops::Range<u64>; 8]>>,
    keys: &SealKeys<'_>,
    gso_buf: &mut [u8],
    stride: usize,
) -> SmallVec<[EncryptResult; 64]> {
    let count = payloads.len().min(prepared.len());
    let mut results = SmallVec::with_capacity(count);

    for i in 0..count {
        let offset = i * stride;
        if offset + stride > gso_buf.len() {
            break;
        }
        let chunk = &mut gso_buf[offset..offset + stride];
        let ack = if i == 0 {
            ack_ranges.map(|r| r.as_slice())
        } else {
            None
        };

        match encrypt_packet(
            payloads[i],
            ack,
            keys.remote_cid,
            prepared[i].pn,
            prepared[i].largest_acked,
            prepared[i].key_phase,
            keys.tx_packet_key,
            keys.tx_header_key,
            keys.tag_len,
            chunk,
        ) {
            Ok(result) => results.push(result),
            Err(e) => {
                warn!(error = %e, "encrypt failed in batch, dropping packet");
            }
        }
    }

    results
}

/// Compact stride-spaced encrypted packets and send via GSO.
///
/// After parallel encrypt, packets sit at stride-spaced offsets. GSO needs them
/// contiguous with uniform segment size. Handles the first-packet-different case
/// (when it has an ACK and differs in size from the rest).
#[cfg(target_os = "linux")]
fn compact_and_send_gso(
    udp: &std::net::UdpSocket,
    gso_buf: &mut [u8],
    results: &[EncryptResult],
    stride: usize,
    remote_addr: SocketAddr,
) -> Result<()> {
    if results.is_empty() {
        return Ok(());
    }

    // Filter out zero-length failures.
    let valid: SmallVec<[(usize, usize); 64]> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| r.len > 0)
        .map(|(i, r)| (i, r.len))
        .collect();

    if valid.is_empty() {
        return Ok(());
    }

    // Check if all valid packets have the same size.
    let first_len = valid[0].1;
    let all_same = valid.iter().all(|(_, len)| *len == first_len);

    if all_same && valid.len() == 1 {
        // Single packet — just send directly from its stride position.
        let offset = valid[0].0 * stride;
        let len = valid[0].1;
        loop {
            match udp.send_to(&gso_buf[offset..offset + len], remote_addr) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait_writable(udp.as_raw_fd());
                }
                Err(e) => return Err(e).context("send_to failed"),
            }
        }
    } else if all_same {
        // All same size — compact into contiguous positions and GSO send.
        let mut write_pos = 0;
        for &(idx, len) in &valid {
            let read_pos = idx * stride;
            if write_pos != read_pos {
                gso_buf.copy_within(read_pos..read_pos + len, write_pos);
            }
            write_pos += len;
        }
        flush_gso_sync(udp, gso_buf, write_pos, first_len, remote_addr)?;
    } else {
        // First packet has different size (ACK). Send it alone, then compact+GSO the rest.
        let first_offset = valid[0].0 * stride;
        let first_len = valid[0].1;
        loop {
            match udp.send_to(&gso_buf[first_offset..first_offset + first_len], remote_addr) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait_writable(udp.as_raw_fd());
                }
                Err(e) => return Err(e).context("send_to failed"),
            }
        }

        if valid.len() > 1 {
            let rest_len = valid[1].1; // All remaining should be same size.
            let mut write_pos = 0;
            for &(idx, len) in &valid[1..] {
                let read_pos = idx * stride;
                if write_pos != read_pos {
                    gso_buf.copy_within(read_pos..read_pos + len, write_pos);
                }
                write_pos += len;
            }
            flush_gso_sync(udp, gso_buf, write_pos, rest_len, remote_addr)?;
        }
    }

    Ok(())
}

// ── TUN RX (non-Linux — per-packet send) ─────────────────────────────────

#[cfg(not(target_os = "linux"))]
fn handle_tun_rx(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ConnEntry>,
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
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

                let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                    cid
                } else if connections.len() == 1 {
                    *connections
                        .keys()
                        .next()
                        .expect("single connection")
                } else {
                    continue;
                };

                let entry = match connections.get_mut(&cid) {
                    Some(e) => e,
                    None => continue,
                };

                let ack_ranges = if entry.conn.needs_ack() {
                    Some(entry.conn.generate_ack_ranges())
                } else {
                    None
                };
                match entry
                    .conn
                    .encrypt_datagram(&packet[..n], ack_ranges.as_deref(), encrypt_buf)
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
    ip_to_cid: &mut FxHashMap<Ipv4Addr, u64>,
    multi_state: &mut MultiQuicState,
    idle_timeout: Duration,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    // Remove idle connections.
    let expired: Vec<u64> = connections
        .iter()
        .filter(|(_, e)| e.last_rx.elapsed() >= idle_timeout)
        .map(|(&cid, _)| cid)
        .collect();

    for cid in expired {
        if let Some(entry) = connections.remove(&cid) {
            ip_to_cid.remove(&entry.tunnel_ip);
            info!(
                tunnel_ip = %entry.tunnel_ip,
                cid = %hex::encode(cid.to_ne_bytes()),
                "connection idle timeout, removed"
            );
        }
    }

    // Send keepalives.
    for entry in connections.values_mut() {
        if entry.last_tx.elapsed() >= entry.keepalive_interval {
            let ack_ranges = entry.conn.generate_ack_ranges();
            let ack_ref = if !ack_ranges.is_empty() {
                Some(ack_ranges.as_slice())
            } else {
                None
            };
            match entry.conn.encrypt_datagram(&[], ack_ref, encrypt_buf) {
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
    ip_to_cid: &mut FxHashMap<Ipv4Addr, u64>,
    peers: &[PeerConfig],
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
        let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        // Drain final transmits for this connection (before it was removed).
        // The connection is already removed from handshakes by extract_connection,
        // but we need to send any buffered packets.

        // Identify peer by certificate.
        let matched_peer = if peers.len() == 1 {
            // Single-peer fallback: skip identity check.
            &peers[0]
        } else {
            match peer::identify_peer(&hs.connection, peers) {
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
        let now_inst = Instant::now();

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            active = connections.len() + 1,
            "connection established"
        );

        ip_to_cid.insert(tunnel_ip, cid_key);
        connections.insert(
            cid_key,
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

fn send_responses(
    udp: &std::net::UdpSocket,
    responses: &[(usize, [u8; BUF_SIZE])],
    addr: SocketAddr,
) -> Result<()> {
    for (len, buf) in responses {
        udp.send_to(&buf[..*len], addr)?;
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
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
    gso_buf: &mut [u8],
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
    parallel_threshold: usize,
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

            let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                cid
            } else if connections.len() == 1 {
                *connections.keys().next().expect("single connection")
            } else {
                debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                continue;
            };

            // If CID changed, flush the current batch first.
            if let Some(prev_cid) = batch_cid {
                if prev_cid != cid && !batch_payloads.is_empty() {
                    flush_offload_batch(
                        udp, connections, gso_buf, split_bufs, split_sizes,
                        &batch_payloads, prev_cid, max_segs, parallel_threshold,
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
                    &batch_payloads, cid, max_segs, parallel_threshold,
                )?;
                batch_payloads.clear();
            }
        }

        // Flush remaining batch.
        if let Some(cid) = batch_cid {
            if !batch_payloads.is_empty() {
                flush_offload_batch(
                    udp, connections, gso_buf, split_bufs, split_sizes,
                    &batch_payloads, cid, max_segs, parallel_threshold,
                )?;
            }
        }
    }

    Ok(())
}

/// Flush a batch of TUN packets for a single connection via parallel or sequential encrypt.
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
    _max_segs: usize,
    parallel_threshold: usize,
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

    // Phase 1: Sequential — assign PNs and generate ACK.
    let (prepared, ack_ranges) = entry.conn.prepare_batch(count);
    let actual_count = prepared.len(); // may be truncated at key update boundary

    // Phase 2: Encrypt (parallel or sequential).
    let stride = MAX_PACKET;
    let keys = entry.conn.seal_keys();
    let payloads_slice = &payloads[..actual_count];

    let results = if actual_count >= parallel_threshold {
        seal_batch_parallel(payloads_slice, &prepared, ack_ranges.as_ref(), &keys, gso_buf, stride)
    } else {
        seal_batch_sequential(payloads_slice, &prepared, ack_ranges.as_ref(), &keys, gso_buf, stride)
    };

    // Phase 3: Compact + GSO send.
    let remote = entry.remote_addr;
    entry.last_tx = Instant::now();
    compact_and_send_gso(udp, gso_buf, &results, stride, remote)?;

    // If prepare_batch truncated at key update, process remainder.
    if actual_count < count {
        let remaining_indices: SmallVec<[usize; 64]> = indices[actual_count..].iter().copied().collect();
        flush_offload_batch(
            udp, connections, gso_buf, split_bufs, split_sizes,
            &remaining_indices, cid, _max_segs, parallel_threshold,
        )?;
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════
// Multi-thread dispatcher-worker engine
// ══════════════════════════════════════════════════════════════════════════

/// Duplicate a file descriptor. The caller owns the new fd.
fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error()).context("dup() failed");
    }
    Ok(new_fd)
}

/// Multi-thread engine: dispatcher thread 0 + N-1 worker threads.
fn run_multi(local_addr: SocketAddr, setup: EndpointSetup, config: NetConfig) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });
    let n_workers = config.threads - 1;
    info!(
        threads = config.threads,
        workers = n_workers,
        "starting multi-thread engine"
    );

    // 1. Create UDP socket, TUN device, signal pipe (same as single-thread).
    let udp_socket = create_udp_socket(local_addr, config.recv_buf, config.send_buf)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name.clone();
    #[cfg(target_os = "linux")]
    {
        tun_opts.offload = config.offload;
    }
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
    set_nonblocking(tun.as_raw_fd())?;

    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;
    install_signal_handler(sig_write_fd)?;

    // 2. Create MultiQuicState.
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
        // Open one connection per worker for load distribution.
        for _ in 0..n_workers {
            multi_state.connect(client_config.clone(), remote_addr)?;
        }
        drain_transmits(&udp_socket, &mut multi_state)?;
        info!(
            connections = n_workers,
            "connector: initiated {} connection(s) to {}", n_workers, remote_addr,
        );
    }

    // 3. Create per-worker channels.
    let channel_capacity = config.channel_capacity;
    let worker_channels: Vec<Arc<WorkerChannels>> = (0..n_workers)
        .map(|_| Arc::new(WorkerChannels::with_capacity(channel_capacity)))
        .collect();

    // 4. Worker→dispatcher removal channel (all workers share the sender).
    let (removal_tx, removal_rx) = crossbeam_channel::bounded::<RemovedConnection>(256);

    // 5. Create dispatch table.
    let mut dispatch_table = NetDispatchTable::new(n_workers);

    // 5. Shutdown signal.
    let shutdown = Arc::new(AtomicBool::new(false));

    // 6. Dup fds for workers.
    let udp_raw_fd = udp_socket.as_raw_fd();
    let tun_raw_fd = tun.as_raw_fd();

    let worker_udp_fds: Vec<RawFd> = (0..n_workers)
        .map(|_| dup_fd(udp_raw_fd))
        .collect::<Result<_>>()?;
    let worker_tun_fds: Vec<RawFd> = (0..n_workers)
        .map(|_| dup_fd(tun_raw_fd))
        .collect::<Result<_>>()?;

    // 7. Spawn workers + run dispatcher.
    let result = std::thread::scope(|s| {
        // Spawn worker threads.
        let mut worker_handles = Vec::with_capacity(n_workers);
        for i in 0..n_workers {
            let channels = Arc::clone(&worker_channels[i]);
            let shutdown_flag = Arc::clone(&shutdown);
            let removal = removal_tx.clone();
            let udp_fd = worker_udp_fds[i];
            let tun_fd = worker_tun_fds[i];
            let idle_timeout = config.idle_timeout;
            let cid_len = config.cid_len;
            let worker_offload = config.offload;

            let handle = s.spawn(move || {
                run_worker(
                    i,
                    channels,
                    udp_fd,
                    tun_fd,
                    idle_timeout,
                    cid_len,
                    removal,
                    shutdown_flag,
                    worker_offload,
                )
            });
            worker_handles.push(handle);
        }

        // Run dispatcher on this thread (thread 0).
        // Drop dispatcher's copy of removal_tx so channel closes when all workers exit.
        drop(removal_tx);

        let dispatch_result = run_dispatcher(
            &udp_socket,
            &tun,
            sig_read_fd,
            &mut multi_state,
            &mut dispatch_table,
            &worker_channels,
            &config,
            &shutdown,
            &removal_rx,
            is_connector,
        );

        // Signal shutdown to workers.
        shutdown.store(true, Ordering::Release);

        // Wait for all workers.
        for (i, handle) in worker_handles.into_iter().enumerate() {
            match handle.join() {
                Ok(Ok(())) => debug!(worker = i, "worker exited cleanly"),
                Ok(Err(e)) => warn!(worker = i, error = %e, "worker exited with error"),
                Err(_) => warn!(worker = i, "worker thread panicked"),
            }
        }

        dispatch_result
    });

    // Close dup'd fds.
    for fd in &worker_udp_fds {
        unsafe {
            libc::close(*fd);
        }
    }
    for fd in &worker_tun_fds {
        unsafe {
            libc::close(*fd);
        }
    }

    result
}

/// Dispatcher loop: reads UDP+TUN, dispatches to workers by CID/IP.
/// Handles handshakes, promotes completed connections to workers.
#[allow(clippy::too_many_arguments)]
fn run_dispatcher(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    sig_read_fd: i32,
    multi_state: &mut MultiQuicState,
    dispatch_table: &mut NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
    config: &NetConfig,
    _shutdown: &AtomicBool,
    removal_rx: &crossbeam_channel::Receiver<RemovedConnection>,
    is_connector: bool,
) -> Result<RunResult> {
    // Register with mio.
    let mut poll = Poll::new().context("failed to create mio::Poll")?;
    let mut events = Events::with_capacity(config.poll_events);

    let udp_raw_fd = udp.as_raw_fd();
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

    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut active_connections: usize = 0;
    let mut had_connection = false;

    // Linux: batch RX buffers (sized from config).
    #[cfg(target_os = "linux")]
    let dispatch_batch_size = config.batch_size;
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; dispatch_batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; dispatch_batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_addrs =
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); dispatch_batch_size];

    // Non-Linux: per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

    // Linux: TUN offload buffers for dispatcher.
    #[cfg(target_os = "linux")]
    let dispatch_offload = config.offload;
    #[cfg(target_os = "linux")]
    let mut dispatch_tun_original_buf = if config.offload {
        vec![0u8; quictun_tun::VIRTIO_NET_HDR_LEN + 65535]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut dispatch_tun_split_bufs = if config.offload {
        vec![vec![0u8; 1500]; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut dispatch_tun_split_sizes = if config.offload {
        vec![0usize; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };

    loop {
        // Handshake-only timeout (workers handle their own connection timeouts).
        let mut timeout = Duration::from_secs(5);
        for hs in multi_state.handshakes.values_mut() {
            if let Some(deadline) = hs.connection.poll_timeout() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                timeout = timeout.min(remaining);
            }
        }
        timeout = timeout.max(Duration::from_millis(1));

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
            info!("received signal, shutting down dispatcher");
            // Push Shutdown to all workers so they send CONNECTION_CLOSE.
            for wc in worker_channels {
                wc.control
                    .lock()
                    .expect("worker control mutex poisoned")
                    .push(ControlMessage::Shutdown);
            }
            return Ok(RunResult::Shutdown);
        }

        // ── UDP RX: dispatch by CID ──────────────────────────────────
        if udp_readable {
            #[cfg(target_os = "linux")]
            {
                dispatch_udp_rx_linux(
                    udp,
                    config.cid_len,
                    multi_state,
                    dispatch_table,
                    worker_channels,
                    &mut recv_bufs,
                    &mut recv_lens,
                    &mut recv_addrs,
                    &mut response_buf,
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                dispatch_udp_rx(
                    udp,
                    config.cid_len,
                    multi_state,
                    dispatch_table,
                    worker_channels,
                    &mut recv_buf,
                    &mut response_buf,
                )?;
            }
        }

        // ── TUN RX: dispatch by dest IP ──────────────────────────────
        if tun_readable {
            #[cfg(target_os = "linux")]
            {
                if dispatch_offload {
                    dispatch_tun_rx_offload(
                        tun,
                        dispatch_table,
                        worker_channels,
                        &mut dispatch_tun_original_buf,
                        &mut dispatch_tun_split_bufs,
                        &mut dispatch_tun_split_sizes,
                    )?;
                } else {
                    dispatch_tun_rx(tun, dispatch_table, worker_channels)?;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                dispatch_tun_rx(tun, dispatch_table, worker_channels)?;
            }
        }

        // ── Handshake timeouts ───────────────────────────────────────
        let now = Instant::now();
        for hs in multi_state.handshakes.values_mut() {
            hs.connection.handle_timeout(now);
        }

        // ── Drive handshakes → assign to workers ─────────────────────
        let promoted = dispatch_drive_handshakes(
            udp,
            multi_state,
            dispatch_table,
            worker_channels,
            &config.peers,
        )?;
        active_connections += promoted;
        if promoted > 0 {
            had_connection = true;
        }

        // ── Drain removal notifications from workers ─────────────────
        while let Ok(removed) = removal_rx.try_recv() {
            dispatch_table.unregister(removed.cid, removed.tunnel_ip);
            active_connections = active_connections.saturating_sub(1);
            debug!(
                cid = %hex::encode(removed.cid.to_ne_bytes()),
                tunnel_ip = %removed.tunnel_ip,
                "dispatcher unregistered connection"
            );
        }

        // ── ConnectionLost detection (connector only) ────────────────
        if is_connector
            && had_connection
            && active_connections == 0
            && multi_state.handshakes.is_empty()
        {
            info!("all connections lost, returning ConnectionLost for reconnect");
            for wc in worker_channels {
                wc.control
                    .lock()
                    .expect("worker control mutex poisoned")
                    .push(ControlMessage::Shutdown);
            }
            return Ok(RunResult::ConnectionLost);
        }
    }
}

// ── Dispatcher: UDP RX (Linux — recvmmsg) ────────────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn dispatch_udp_rx_linux(
    udp: &std::net::UdpSocket,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    dispatch_table: &NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    response_buf: &mut Vec<u8>,
) -> Result<()> {
    loop {
        let max_batch = recv_bufs.len();
        let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
            udp,
            recv_bufs,
            recv_lens,
            recv_addrs,
            max_batch,
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

            if recv_bufs[i][0] & 0x80 != 0 {
                // Long header → handshake (dispatcher handles).
                let from = recv_addrs[i];
                let mut data = BytesMut::with_capacity(n);
                data.extend_from_slice(&recv_bufs[i][..n]);
                let now = Instant::now();
                let responses = multi_state.handle_incoming(now, from, None, data, response_buf);
                send_responses(udp, &responses, from)?;
                continue;
            }

            // Short header → CID routing to worker.
            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_bytes = &recv_bufs[i][1..1 + cid_len];

            if let Some(worker_id) = dispatch_table.lookup_cid(cid_bytes) {
                let pkt = OuterPacket {
                    data: recv_bufs[i][..n].to_vec(),
                    from: recv_addrs[i],
                };
                let _ = worker_channels[worker_id].outer_tx.try_send(pkt);
            }
        }

        if n_msgs < max_batch {
            return Ok(());
        }
    }
}

// ── Dispatcher: UDP RX (non-Linux — per-packet) ──────────────────────────

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn dispatch_udp_rx(
    udp: &std::net::UdpSocket,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    dispatch_table: &NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
    recv_buf: &mut [u8],
    response_buf: &mut Vec<u8>,
) -> Result<()> {
    loop {
        match udp.recv_from(recv_buf) {
            Ok((n, from)) => {
                if n == 0 {
                    continue;
                }

                if recv_buf[0] & 0x80 != 0 {
                    let mut data = BytesMut::with_capacity(n);
                    data.extend_from_slice(&recv_buf[..n]);
                    let now = Instant::now();
                    let responses =
                        multi_state.handle_incoming(now, from, None, data, response_buf);
                    send_responses(udp, &responses, from)?;
                } else if cid_len > 0 && n > cid_len {
                    let cid_bytes = &recv_buf[1..1 + cid_len];
                    if let Some(worker_id) = dispatch_table.lookup_cid(cid_bytes) {
                        let pkt = OuterPacket {
                            data: recv_buf[..n].to_vec(),
                            from,
                        };
                        let _ = worker_channels[worker_id].outer_tx.try_send(pkt);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("UDP recv_from failed"),
        }
    }
    Ok(())
}

// ── Dispatcher: TUN RX ───────────────────────────────────────────────────

fn dispatch_tun_rx(
    tun: &tun_rs::SyncDevice,
    dispatch_table: &NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
) -> Result<()> {
    loop {
        let mut packet = [0u8; 1500];
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }
                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                dispatch_tun_packet_to_worker(
                    &packet[..n],
                    dest_ip,
                    dispatch_table,
                    worker_channels,
                );
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn dispatch_tun_rx_offload(
    tun: &tun_rs::SyncDevice,
    dispatch_table: &NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
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

            dispatch_tun_packet_to_worker(packet, dest_ip, dispatch_table, worker_channels);
        }
    }
    Ok(())
}

fn dispatch_tun_packet_to_worker(
    packet: &[u8],
    dest_ip: Ipv4Addr,
    dispatch_table: &NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
) {
    if let Some(workers) = dispatch_table.lookup_ip(dest_ip) {
        let worker_id = if workers.len() == 1 {
            workers[0]
        } else {
            let hash = crate::dispatch::flow_hash_5tuple(packet);
            (hash as usize) % workers.len()
        };
        let pkt = InnerPacket {
            data: packet.to_vec(),
        };
        let _ = worker_channels[worker_id].inner_tx.try_send(pkt);
    } else if worker_channels.len() == 1 {
        let pkt = InnerPacket {
            data: packet.to_vec(),
        };
        let _ = worker_channels[0].inner_tx.try_send(pkt);
    } else {
        debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
    }
}

// ── Dispatcher: drive handshakes → assign to workers ─────────────────────

/// Returns the number of connections promoted to workers.
fn dispatch_drive_handshakes(
    udp: &std::net::UdpSocket,
    multi_state: &mut MultiQuicState,
    dispatch_table: &mut NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
    peers: &[PeerConfig],
) -> Result<usize> {
    if multi_state.handshakes.is_empty() {
        return Ok(0);
    }

    drain_transmits(udp, multi_state)?;

    let result = multi_state.poll_handshakes();

    drain_transmits(udp, multi_state)?;

    let mut promoted = 0usize;
    for ch in result.completed {
        let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        let matched_peer = if peers.len() == 1 {
            &peers[0]
        } else {
            match peer::identify_peer(&hs.connection, peers) {
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

        // Assign to least-loaded worker.
        let worker_id = dispatch_table.least_loaded_worker();
        dispatch_table.register_cid(&cid_bytes, worker_id);
        dispatch_table.add_route(tunnel_ip, worker_id);

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            worker = worker_id,
            "connection established, assigned to worker"
        );

        worker_channels[worker_id]
            .control
            .lock()
            .expect("worker control mutex poisoned — worker panicked")
            .push(ControlMessage::AddConnection {
                conn: conn_state,
                tunnel_ip,
                allowed_ips,
                remote_addr: hs.remote_addr,
                keepalive_interval,
            });
        promoted += 1;
    }

    Ok(promoted)
}

// ══════════════════════════════════════════════════════════════════════════
// Worker thread
// ══════════════════════════════════════════════════════════════════════════

/// Maximum packets to drain per channel per iteration.
const WORKER_DRAIN_BATCH: usize = 64;

/// Worker loop: owns connections, processes packets from dispatcher channels.
#[allow(clippy::too_many_arguments)]
fn run_worker(
    worker_id: usize,
    channels: Arc<WorkerChannels>,
    udp_fd: RawFd,
    tun_fd: RawFd,
    idle_timeout: Duration,
    cid_len: usize,
    removal_tx: crossbeam_channel::Sender<RemovedConnection>,
    shutdown: Arc<AtomicBool>,
    #[allow(unused_variables)] offload: bool,
) -> Result<()> {
    info!(worker = worker_id, "worker started");

    // SAFETY: dup'd fds are valid and owned by this worker.
    // ManuallyDrop prevents double-close (run_multi closes dup'd fds).
    let udp_socket =
        std::mem::ManuallyDrop::new(unsafe { std::net::UdpSocket::from_raw_fd(udp_fd) });

    // Connection table (worker-local, no locking).
    let mut connections: FxHashMap<u64, ConnEntry> = FxHashMap::default();
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();

    let mut scratch = BytesMut::with_capacity(2048);
    let mut tun_write_buf = TunWriteBuffer::new();
    #[cfg(not(target_os = "linux"))]
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    // Linux: per-worker GSO batching state for TUN→UDP path.
    #[cfg(target_os = "linux")]
    let mut worker_gso_buf = vec![0u8; quictun_core::batch_io::GSO_BUF_SIZE];
    #[cfg(target_os = "linux")]
    let mut worker_gso_pos = 0usize;
    #[cfg(target_os = "linux")]
    let mut worker_gso_segment_size = 0usize;
    #[cfg(target_os = "linux")]
    let mut worker_gso_count = 0usize;
    #[cfg(target_os = "linux")]
    let mut worker_gso_remote: Option<SocketAddr> = None;

    // encrypt_buf still needed on Linux for keepalives and CONNECTION_CLOSE.
    #[cfg(target_os = "linux")]
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    // Reusable buffer for TUN writes with virtio-net header (avoids per-datagram alloc).
    #[cfg(target_os = "linux")]
    let mut vnet_buf: Vec<u8> = Vec::with_capacity(quictun_tun::VIRTIO_NET_HDR_LEN + 1500);

    // Adaptive sleep: start at 1μs, backoff to 100μs when idle.
    let mut idle_iters = 0u32;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut did_work = false;

        // ── Drain buffered TUN writes ────────────────────────────────
        if !tun_write_buf.is_empty() {
            let drained = tun_write_buf.drain_raw(tun_fd);
            if drained > 0 {
                did_work = true;
            }
        }

        // ── Poll control channel ─────────────────────────────────────
        let mut got_shutdown = false;
        if let Ok(mut ctrl) = channels.control.try_lock() {
            for msg in ctrl.drain(..) {
                match msg {
                    ControlMessage::AddConnection {
                        conn,
                        tunnel_ip,
                        allowed_ips,
                        remote_addr,
                        keepalive_interval,
                    } => {
                        let cid_bytes = conn.local_cid().to_vec();
                        let cid_key = cid_to_u64(&cid_bytes);
                        info!(
                            worker = worker_id,
                            tunnel_ip = %tunnel_ip,
                            cid = %hex::encode(&cid_bytes),
                            "worker received connection"
                        );
                        ip_to_cid.insert(tunnel_ip, cid_key);
                        let now_inst = Instant::now();
                        connections.insert(
                            cid_key,
                            ConnEntry {
                                conn,
                                tunnel_ip,
                                allowed_ips,
                                remote_addr,
                                keepalive_interval,
                                last_tx: now_inst,
                                last_rx: now_inst,
                            },
                        );
                        did_work = true;
                    }
                    ControlMessage::Shutdown => {
                        got_shutdown = true;
                    }
                }
            }
        }
        if got_shutdown {
            // Graceful shutdown: send CONNECTION_CLOSE to all connections.
            for entry in connections.values_mut() {
                if let Ok(result) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                    let _ = udp_socket.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                }
            }
            info!(worker = worker_id, "worker shutting down gracefully");
            break;
        }

        // ── Drain outer_rx (UDP packets from dispatcher) ─────────────
        for _ in 0..WORKER_DRAIN_BATCH {
            match channels.outer_rx.try_recv() {
                Ok(mut pkt) => {
                    did_work = true;
                    if pkt.data.len() < 1 + cid_len {
                        continue;
                    }
                    let cid_key = cid_to_u64(&pkt.data[1..1 + cid_len]);

                    let close_received = if let Some(entry) =
                        connections.get_mut(&cid_key)
                    {
                        match entry
                            .conn
                            .decrypt_packet_with_buf(&mut pkt.data, &mut scratch)
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
                                            debug!(src = %src_ip, "dropping: source IP not in allowed_ips");
                                            continue;
                                        }
                                        #[cfg(target_os = "linux")]
                                        if offload {
                                            let hdr_len = quictun_tun::VIRTIO_NET_HDR_LEN;
                                            vnet_buf.resize(hdr_len + datagram.len(), 0);
                                            vnet_buf[..hdr_len].fill(0);
                                            vnet_buf[hdr_len..].copy_from_slice(datagram);
                                            tun_write_buf.write_raw(tun_fd, &vnet_buf);
                                        } else {
                                            tun_write_buf.write_raw(tun_fd, datagram);
                                        }
                                        #[cfg(not(target_os = "linux"))]
                                        {
                                            tun_write_buf.write_raw(tun_fd, datagram);
                                        }
                                    }
                                }
                                decrypted.close_received
                            }
                            Err(e) => {
                                debug!(error = %e, "worker decrypt failed, dropping");
                                false
                            }
                        }
                    } else {
                        false
                    };
                    if close_received && let Some(entry) = connections.remove(&cid_key) {
                        ip_to_cid.remove(&entry.tunnel_ip);
                        let _ = removal_tx.try_send(RemovedConnection {
                            cid: cid_key,
                            tunnel_ip: entry.tunnel_ip,
                        });
                        info!(
                            worker = worker_id,
                            cid = %hex::encode(cid_key.to_ne_bytes()),
                            "peer sent CONNECTION_CLOSE, removed"
                        );
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // ── Drain inner_rx (TUN packets from dispatcher) ─────────────
        #[cfg(target_os = "linux")]
        {
            let max_segs = quictun_core::batch_io::GSO_MAX_SEGMENTS;
            for _ in 0..WORKER_DRAIN_BATCH {
                match channels.inner_rx.try_recv() {
                    Ok(pkt) => {
                        did_work = true;
                        if pkt.data.len() < 20 {
                            continue;
                        }

                        let dest_ip =
                            Ipv4Addr::new(pkt.data[16], pkt.data[17], pkt.data[18], pkt.data[19]);

                        let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                            cid
                        } else if connections.len() == 1 {
                            *connections
                                .keys()
                                .next()
                                .expect("single connection")
                        } else {
                            continue;
                        };

                        let entry = match connections.get_mut(&cid) {
                            Some(e) => e,
                            None => continue,
                        };

                        // Flush GSO batch if remote changed or batch full.
                        if let Some(ref cur_remote) = worker_gso_remote {
                            if *cur_remote != entry.remote_addr
                                || worker_gso_count >= max_segs
                                || worker_gso_pos + MAX_PACKET > worker_gso_buf.len()
                            {
                                if worker_gso_count > 0 {
                                    flush_gso_sync(
                                        &udp_socket,
                                        &worker_gso_buf,
                                        worker_gso_pos,
                                        worker_gso_segment_size,
                                        *cur_remote,
                                    )?;
                                }
                                worker_gso_pos = 0;
                                worker_gso_segment_size = 0;
                                worker_gso_count = 0;
                            }
                        }

                        worker_gso_remote = Some(entry.remote_addr);

                        let ack_ranges = if entry.conn.needs_ack() {
                            Some(entry.conn.generate_ack_ranges())
                        } else {
                            None
                        };
                        match entry.conn.encrypt_datagram(
                            &pkt.data,
                            ack_ranges.as_deref(),
                            &mut worker_gso_buf[worker_gso_pos..],
                        ) {
                            Ok(result) => {
                                if worker_gso_count == 0 {
                                    worker_gso_segment_size = result.len;
                                    worker_gso_pos += result.len;
                                    worker_gso_count += 1;
                                } else if result.len == worker_gso_segment_size {
                                    worker_gso_pos += result.len;
                                    worker_gso_count += 1;
                                } else {
                                    // Odd-sized: flush current, start new batch.
                                    if worker_gso_count > 0 {
                                        flush_gso_sync(
                                            &udp_socket,
                                            &worker_gso_buf,
                                            worker_gso_pos,
                                            worker_gso_segment_size,
                                            entry.remote_addr,
                                        )?;
                                    }
                                    worker_gso_buf.copy_within(
                                        worker_gso_pos..worker_gso_pos + result.len,
                                        0,
                                    );
                                    worker_gso_segment_size = result.len;
                                    worker_gso_pos = result.len;
                                    worker_gso_count = 1;
                                }
                                entry.last_tx = Instant::now();
                            }
                            Err(e) => {
                                warn!(error = %e, "worker encrypt failed, dropping");
                            }
                        }
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            // Flush remaining GSO batch after drain loop.
            if worker_gso_count > 0 {
                if let Some(remote) = worker_gso_remote {
                    flush_gso_sync(
                        &udp_socket,
                        &worker_gso_buf,
                        worker_gso_pos,
                        worker_gso_segment_size,
                        remote,
                    )?;
                }
                worker_gso_pos = 0;
                worker_gso_segment_size = 0;
                worker_gso_count = 0;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            for _ in 0..WORKER_DRAIN_BATCH {
                match channels.inner_rx.try_recv() {
                    Ok(pkt) => {
                        did_work = true;
                        if pkt.data.len() < 20 {
                            continue;
                        }

                        let dest_ip =
                            Ipv4Addr::new(pkt.data[16], pkt.data[17], pkt.data[18], pkt.data[19]);

                        let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                            cid
                        } else if connections.len() == 1 {
                            *connections
                                .keys()
                                .next()
                                .expect("single connection")
                        } else {
                            continue;
                        };

                        let entry = match connections.get_mut(&cid) {
                            Some(e) => e,
                            None => continue,
                        };

                        let ack_ranges = if entry.conn.needs_ack() {
                            Some(entry.conn.generate_ack_ranges())
                        } else {
                            None
                        };
                        match entry.conn.encrypt_datagram(
                            &pkt.data,
                            ack_ranges.as_deref(),
                            &mut encrypt_buf,
                        ) {
                            Ok(result) => {
                                let _ = udp_socket
                                    .send_to(&encrypt_buf[..result.len], entry.remote_addr);
                                entry.last_tx = Instant::now();
                            }
                            Err(e) => {
                                warn!(error = %e, "worker encrypt failed, dropping");
                            }
                        }
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => return Ok(()),
                }
            }
        }

        // ── Keepalives and idle timeouts ─────────────────────────────
        let mut expired = Vec::new();
        for (&cid, entry) in connections.iter_mut() {
            if entry.last_rx.elapsed() >= idle_timeout {
                expired.push(cid);
                continue;
            }
            if entry.last_tx.elapsed() >= entry.keepalive_interval {
                let ack_ranges = entry.conn.generate_ack_ranges();
                let ack_ref = if !ack_ranges.is_empty() {
                    Some(ack_ranges.as_slice())
                } else {
                    None
                };
                match entry.conn.encrypt_datagram(&[], ack_ref, &mut encrypt_buf) {
                    Ok(result) => {
                        let _ = udp_socket.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                        entry.last_tx = Instant::now();
                        debug!(worker = worker_id, pn = result.pn, "sent keepalive");
                    }
                    Err(e) => {
                        warn!(error = %e, "keepalive encrypt failed");
                    }
                }
            }
        }
        for cid in expired {
            if let Some(entry) = connections.remove(&cid) {
                ip_to_cid.remove(&entry.tunnel_ip);
                let _ = removal_tx.try_send(RemovedConnection {
                    cid,
                    tunnel_ip: entry.tunnel_ip,
                });
                info!(
                    worker = worker_id,
                    tunnel_ip = %entry.tunnel_ip,
                    cid = %hex::encode(cid.to_ne_bytes()),
                    "connection idle timeout, removed"
                );
            }
        }

        // ── Adaptive sleep ───────────────────────────────────────────
        if did_work {
            idle_iters = 0;
        } else {
            idle_iters = idle_iters.saturating_add(1);
            let sleep_us = if idle_iters < 100 { 1 } else { 100 };
            std::thread::sleep(Duration::from_micros(sleep_us));
        }
    }

    info!(worker = worker_id, "worker exiting");
    Ok(())
}

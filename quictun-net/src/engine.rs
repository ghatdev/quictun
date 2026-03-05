//! Synchronous blocking engine using mio for event notification.
//!
//! Replaces tokio as the default non-DPDK data plane. No async runtime,
//! no tokio dependency. Single-thread poll loop over UDP + TUN + signal pipe.

use std::collections::HashMap;
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
use tracing::{debug, info, warn};

use crate::dispatch::{
    ControlMessage, InnerPacket, NetDispatchTable, OuterPacket, RemovedConnection, WorkerChannels,
};
use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::{BUF_SIZE, MultiQuicState};
use quictun_quic::local::LocalConnectionState;
use quictun_tun::TunOptions;

/// Maximum QUIC packet size.
const MAX_PACKET: usize = 2048;

/// Handshake response buffer size.
const HANDSHAKE_BUF_SIZE: usize = 2048;

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
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
}

/// Main entry point for the synchronous blocking engine.
///
/// Routes to single-thread or multi-thread path based on `config.threads`.
pub fn run(local_addr: SocketAddr, setup: EndpointSetup, config: NetConfig) -> Result<RunResult> {
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
    // 1. Create UDP socket (non-blocking).
    let udp_socket = create_udp_socket(local_addr, config.recv_buf, config.send_buf)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    // NOTE: UDP GRO is NOT enabled because recvmmsg uses fixed 2048-byte buffers.
    // GRO would coalesce packets into buffers larger than 2048, causing truncation.
    // recvmmsg already provides batching (up to 64 packets per syscall).

    // 2. Create sync TUN device.
    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name;
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;

    // Set TUN fd non-blocking.
    set_nonblocking(tun.as_raw_fd())?;

    // 3. Signal pipe (self-pipe trick).
    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;

    // Install signal handler.
    install_signal_handler(sig_write_fd)?;

    // 4. Create mio poll and register sources.
    let mut poll = Poll::new().context("failed to create mio::Poll")?;
    let mut events = Events::with_capacity(64);

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
    let mut connections: HashMap<Vec<u8>, ConnEntry> = HashMap::new();
    let mut ip_to_cid: HashMap<Ipv4Addr, Vec<u8>> = HashMap::new();

    // Buffers.
    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut scratch = BytesMut::with_capacity(2048);

    // Linux: batch I/O buffers.
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; quictun_core::batch_io::GSO_BUF_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; quictun_core::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; quictun_core::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_addrs =
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); quictun_core::batch_io::BATCH_SIZE];

    // Non-Linux: per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

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
                )?;
            }
        }

        // ── TUN RX ──────────────────────────────────────────────────────
        if tun_readable {
            #[cfg(target_os = "linux")]
            {
                handle_tun_rx_linux(
                    &udp_socket,
                    &tun,
                    &mut connections,
                    &ip_to_cid,
                    &mut gso_buf,
                    &mut encrypt_buf,
                )?;
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

static mut SIGNAL_WRITE_FD: i32 = -1;

extern "C" fn signal_handler(_sig: libc::c_int) {
    let fd = unsafe { SIGNAL_WRITE_FD };
    if fd >= 0 {
        unsafe { libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1) };
    }
}

fn install_signal_handler(write_fd: i32) -> Result<()> {
    unsafe {
        SIGNAL_WRITE_FD = write_fd;

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
    connections: &HashMap<Vec<u8>, ConnEntry>,
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
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
) -> Result<()> {
    // Loop recvmmsg until WouldBlock — required for edge-triggered epoll (mio).
    loop {
        let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
            udp,
            recv_bufs,
            recv_lens,
            recv_addrs,
            quictun_core::batch_io::BATCH_SIZE,
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
            let cid_key: Vec<u8> = recv_bufs[i][1..1 + cid_len].to_vec();

            let close_received = if let Some(entry) = connections.get_mut(cid_key.as_slice()) {
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
                                if datagram.is_empty() {
                                    continue;
                                }
                                tun_write_sync(tun, datagram);
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
                    cid = %hex::encode(&cid_key),
                    "peer sent CONNECTION_CLOSE, removed"
                );
            }
        }

        // If we got fewer than BATCH_SIZE, the socket is drained.
        if n_msgs < quictun_core::batch_io::BATCH_SIZE {
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
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_buf: &mut [u8],
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
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
                        let cid_key: Vec<u8> = recv_buf[1..1 + cid_len].to_vec();
                        let close_received =
                            if let Some(entry) = connections.get_mut(cid_key.as_slice()) {
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
                                                if datagram.is_empty() {
                                                    continue;
                                                }
                                                tun_write_sync(tun, datagram);
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
                                cid = %hex::encode(&cid_key),
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
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &HashMap<Ipv4Addr, Vec<u8>>,
    gso_buf: &mut [u8],
    encrypt_buf: &mut [u8],
) -> Result<()> {
    let max_segs = quictun_core::batch_io::GSO_MAX_SEGMENTS;
    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;
    let mut current_cid: Option<Vec<u8>> = None;
    let mut current_remote: Option<SocketAddr> = None;

    loop {
        let mut packet = [0u8; 1500];
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }

                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                    cid.clone()
                } else if connections.len() == 1 {
                    connections
                        .keys()
                        .next()
                        .expect("single connection")
                        .clone()
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
                            if let Some(entry) = connections.get_mut(cur_cid.as_slice()) {
                                entry.last_tx = Instant::now();
                            }
                        }
                        gso_pos = 0;
                        gso_segment_size = 0;
                        gso_count = 0;
                    }
                }

                let entry = match connections.get_mut(cid.as_slice()) {
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
                            // Odd-sized: send individually.
                            let odd_end = gso_pos + result.len;
                            udp.send_to(&gso_buf[gso_pos..odd_end], entry.remote_addr)?;
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
            if let Some(entry) = connections.get_mut(cid.as_slice()) {
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
            Ok(_) => return Ok(()),
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
    unsafe { libc::poll(&mut pfd, 1, 5) }; // 5ms max
}

// ── TUN RX (non-Linux — per-packet send) ─────────────────────────────────

#[cfg(not(target_os = "linux"))]
fn handle_tun_rx(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &HashMap<Ipv4Addr, Vec<u8>>,
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

                let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                    cid.clone()
                } else if connections.len() == 1 {
                    connections
                        .keys()
                        .next()
                        .expect("single connection")
                        .clone()
                } else {
                    continue;
                };

                let entry = match connections.get_mut(cid.as_slice()) {
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
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &mut HashMap<Ipv4Addr, Vec<u8>>,
    multi_state: &mut MultiQuicState,
    idle_timeout: Duration,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    // Remove idle connections.
    let expired: Vec<Vec<u8>> = connections
        .iter()
        .filter(|(_, e)| e.last_rx.elapsed() >= idle_timeout)
        .map(|(cid, _)| cid.clone())
        .collect();

    for cid in expired {
        if let Some(entry) = connections.remove(&cid) {
            ip_to_cid.remove(&entry.tunnel_ip);
            info!(
                tunnel_ip = %entry.tunnel_ip,
                cid = %hex::encode(&cid),
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
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &mut HashMap<Ipv4Addr, Vec<u8>>,
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
        let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));

        let cid_bytes: Vec<u8> = hs.local_cid[..].to_vec();
        let now_inst = Instant::now();

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            active = connections.len() + 1,
            "connection established"
        );

        ip_to_cid.insert(tunnel_ip, cid_bytes.clone());
        connections.insert(
            cid_bytes,
            ConnEntry {
                conn: conn_state,
                tunnel_ip,
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

fn tun_write_sync(tun: &tun_rs::SyncDevice, buf: &[u8]) {
    // Best-effort TUN write: drop on WouldBlock (avoid blocking the loop).
    match tun.send(buf) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            debug!("TUN write would block, dropping packet");
        }
        Err(e) => {
            warn!(error = %e, "TUN write failed");
        }
    }
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
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
    set_nonblocking(tun.as_raw_fd())?;

    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;
    install_signal_handler(sig_write_fd)?;

    // 2. Create MultiQuicState.
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

    // 3. Create per-worker channels.
    let worker_channels: Vec<Arc<WorkerChannels>> = (0..n_workers)
        .map(|_| Arc::new(WorkerChannels::new()))
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
) -> Result<RunResult> {
    // Register with mio.
    let mut poll = Poll::new().context("failed to create mio::Poll")?;
    let mut events = Events::with_capacity(64);

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

    // Linux: batch RX buffers.
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; quictun_core::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; quictun_core::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_addrs =
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); quictun_core::batch_io::BATCH_SIZE];

    // Non-Linux: per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

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
            dispatch_tun_rx(tun, dispatch_table, worker_channels)?;
        }

        // ── Handshake timeouts ───────────────────────────────────────
        let now = Instant::now();
        for hs in multi_state.handshakes.values_mut() {
            hs.connection.handle_timeout(now);
        }

        // ── Drive handshakes → assign to workers ─────────────────────
        dispatch_drive_handshakes(
            udp,
            multi_state,
            dispatch_table,
            worker_channels,
            &config.peers,
        )?;

        // ── Drain removal notifications from workers ─────────────────
        while let Ok(removed) = removal_rx.try_recv() {
            dispatch_table.unregister(&removed.cid, removed.tunnel_ip);
            debug!(
                cid = %hex::encode(&removed.cid),
                tunnel_ip = %removed.tunnel_ip,
                "dispatcher unregistered connection"
            );
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
        let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
            udp,
            recv_bufs,
            recv_lens,
            recv_addrs,
            quictun_core::batch_io::BATCH_SIZE,
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

        if n_msgs < quictun_core::batch_io::BATCH_SIZE {
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

                if let Some(worker_id) = dispatch_table.lookup_ip(dest_ip) {
                    let pkt = InnerPacket {
                        data: packet[..n].to_vec(),
                    };
                    let _ = worker_channels[worker_id].inner_tx.try_send(pkt);
                } else if worker_channels.len() == 1 {
                    // Single worker: send everything to it (connector case).
                    let pkt = InnerPacket {
                        data: packet[..n].to_vec(),
                    };
                    let _ = worker_channels[0].inner_tx.try_send(pkt);
                } else {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }
    Ok(())
}

// ── Dispatcher: drive handshakes → assign to workers ─────────────────────

fn dispatch_drive_handshakes(
    udp: &std::net::UdpSocket,
    multi_state: &mut MultiQuicState,
    dispatch_table: &mut NetDispatchTable,
    worker_channels: &[Arc<WorkerChannels>],
    peers: &[PeerConfig],
) -> Result<()> {
    if multi_state.handshakes.is_empty() {
        return Ok(());
    }

    drain_transmits(udp, multi_state)?;

    let result = multi_state.poll_handshakes();

    drain_transmits(udp, multi_state)?;

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
                remote_addr: hs.remote_addr,
                keepalive_interval,
            });
    }

    Ok(())
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
) -> Result<()> {
    info!(worker = worker_id, "worker started");

    // SAFETY: dup'd fds are valid and owned by this worker.
    // ManuallyDrop prevents double-close (run_multi closes dup'd fds).
    let udp_socket =
        std::mem::ManuallyDrop::new(unsafe { std::net::UdpSocket::from_raw_fd(udp_fd) });

    // Connection table (worker-local, no locking).
    let mut connections: HashMap<Vec<u8>, ConnEntry> = HashMap::new();
    let mut ip_to_cid: HashMap<Ipv4Addr, Vec<u8>> = HashMap::new();

    let mut scratch = BytesMut::with_capacity(2048);
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    // Adaptive sleep: start at 1μs, backoff to 100μs when idle.
    let mut idle_iters = 0u32;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut did_work = false;

        // ── Poll control channel ─────────────────────────────────────
        let mut got_shutdown = false;
        if let Ok(mut ctrl) = channels.control.try_lock() {
            for msg in ctrl.drain(..) {
                match msg {
                    ControlMessage::AddConnection {
                        conn,
                        tunnel_ip,
                        remote_addr,
                        keepalive_interval,
                    } => {
                        let cid_bytes = conn.local_cid().to_vec();
                        info!(
                            worker = worker_id,
                            tunnel_ip = %tunnel_ip,
                            cid = %hex::encode(&cid_bytes),
                            "worker received connection"
                        );
                        ip_to_cid.insert(tunnel_ip, cid_bytes.clone());
                        let now_inst = Instant::now();
                        connections.insert(
                            cid_bytes,
                            ConnEntry {
                                conn,
                                tunnel_ip,
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
                    let cid_key: Vec<u8> = pkt.data[1..1 + cid_len].to_vec();

                    let close_received =
                        if let Some(entry) = connections.get_mut(cid_key.as_slice()) {
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
                                            if datagram.is_empty() {
                                                continue;
                                            }
                                            let ret = unsafe {
                                                libc::write(
                                                    tun_fd,
                                                    datagram.as_ptr() as *const libc::c_void,
                                                    datagram.len(),
                                                )
                                            };
                                            if ret < 0 {
                                                let err = io::Error::last_os_error();
                                                if err.kind() != io::ErrorKind::WouldBlock {
                                                    warn!(error = %err, "worker TUN write failed");
                                                }
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
                            cid: cid_key.clone(),
                            tunnel_ip: entry.tunnel_ip,
                        });
                        info!(
                            worker = worker_id,
                            cid = %hex::encode(&cid_key),
                            "peer sent CONNECTION_CLOSE, removed"
                        );
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // ── Drain inner_rx (TUN packets from dispatcher) ─────────────
        for _ in 0..WORKER_DRAIN_BATCH {
            match channels.inner_rx.try_recv() {
                Ok(pkt) => {
                    did_work = true;
                    if pkt.data.len() < 20 {
                        continue;
                    }

                    let dest_ip =
                        Ipv4Addr::new(pkt.data[16], pkt.data[17], pkt.data[18], pkt.data[19]);

                    let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                        cid.clone()
                    } else if connections.len() == 1 {
                        connections
                            .keys()
                            .next()
                            .expect("single connection")
                            .clone()
                    } else {
                        continue;
                    };

                    let entry = match connections.get_mut(cid.as_slice()) {
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
                            let _ =
                                udp_socket.send_to(&encrypt_buf[..result.len], entry.remote_addr);
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

        // ── Keepalives and idle timeouts ─────────────────────────────
        let mut expired = Vec::new();
        for (cid, entry) in connections.iter_mut() {
            if entry.last_rx.elapsed() >= idle_timeout {
                expired.push(cid.clone());
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
                    cid: cid.clone(),
                    tunnel_ip: entry.tunnel_ip,
                });
                info!(
                    worker = worker_id,
                    tunnel_ip = %entry.tunnel_ip,
                    cid = %hex::encode(&cid),
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

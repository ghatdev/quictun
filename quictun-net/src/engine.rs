//! Synchronous blocking engine using mio for event notification.
//!
//! Replaces tokio as the default non-DPDK data plane. No async runtime,
//! no tokio dependency. Single-thread poll loop over UDP + TUN + signal pipe.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use quinn_proto::ServerConfig;
use tracing::{debug, info, warn};

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
/// Creates TUN device, UDP socket, signal pipe, and runs the mio poll loop.
/// Returns `RunResult::Shutdown` on clean exit, `RunResult::ConnectionLost` if
/// all connections dropped (caller can reconnect).
pub fn run(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    // 1. Create UDP socket (non-blocking).
    let udp_socket = create_udp_socket(local_addr)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    // 2. Create sync TUN device.
    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name;
    let tun = quictun_tun::create_sync(&tun_opts)
        .context("failed to create sync TUN device")?;

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
    poll.registry().register(
        &mut SourceFd(&udp_raw_fd),
        TOKEN_UDP,
        Interest::READABLE,
    )?;

    let tun_raw_fd = tun.as_raw_fd();
    poll.registry().register(
        &mut SourceFd(&tun_raw_fd),
        TOKEN_TUN,
        Interest::READABLE,
    )?;

    poll.registry().register(
        &mut SourceFd(&sig_read_fd),
        TOKEN_SIGNAL,
        Interest::READABLE,
    )?;

    // 5. Create MultiQuicState and initiate connection if connector.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => {
            MultiQuicState::new(server_config.clone())
        }
        EndpointSetup::Connector { .. } => {
            MultiQuicState::new_connector()
        }
    };

    if let EndpointSetup::Connector { remote_addr, client_config } = setup {
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
    let mut recv_addrs = vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); quictun_core::batch_io::BATCH_SIZE];

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
            // Drain signal pipe.
            drain_signal_pipe(sig_read_fd);
            info!("received signal, shutting down");
            return Ok(RunResult::Shutdown);
        }

        // ── UDP RX ──────────────────────────────────────────────────────
        if udp_readable {
            #[cfg(target_os = "linux")]
            {
                handle_udp_rx_linux(
                    &udp_socket, &tun,
                    &mut connections, config.cid_len,
                    &mut multi_state,
                    &mut recv_bufs, &mut recv_lens, &mut recv_addrs,
                    &mut scratch, &mut response_buf,
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                handle_udp_rx(
                    &udp_socket, &tun,
                    &mut connections, config.cid_len,
                    &mut multi_state,
                    &mut recv_buf, &mut scratch, &mut response_buf,
                )?;
            }
        }

        // ── TUN RX ──────────────────────────────────────────────────────
        if tun_readable {
            #[cfg(target_os = "linux")]
            {
                handle_tun_rx_linux(
                    &udp_socket, &tun,
                    &mut connections, &ip_to_cid,
                    &mut gso_buf, &mut encrypt_buf,
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                handle_tun_rx(
                    &udp_socket, &tun,
                    &mut connections, &ip_to_cid,
                    &mut encrypt_buf,
                )?;
            }
        }

        // ── Timeouts ────────────────────────────────────────────────────
        handle_timeouts(
            &udp_socket,
            &mut connections, &mut ip_to_cid,
            &mut multi_state,
            config.idle_timeout,
            &mut encrypt_buf,
        )?;

        // ── Drive handshakes ────────────────────────────────────────────
        drive_handshakes(
            &udp_socket,
            &mut multi_state,
            &mut connections, &mut ip_to_cid,
            &config.peers,
        )?;
    }
}

// ── UDP socket creation ──────────────────────────────────────────────────

fn create_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create UDP socket")?;

    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);

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
        let keepalive_remaining = entry.keepalive_interval.saturating_sub(entry.last_tx.elapsed());
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

fn drain_transmits(
    udp: &std::net::UdpSocket,
    state: &mut MultiQuicState,
) -> Result<()> {
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
    let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
        udp, recv_bufs, recv_lens, recv_addrs, quictun_core::batch_io::BATCH_SIZE,
    ) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
        Err(e) => return Err(e).context("recvmmsg failed"),
    };

    for i in 0..n_msgs {
        let n = recv_lens[i];
        if n == 0 { continue; }
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
        if cid_len == 0 || n < 1 + cid_len { continue; }
        let cid_bytes = &recv_bufs[i][1..1 + cid_len];

        if let Some(entry) = connections.get_mut(cid_bytes) {
            match entry.conn.decrypt_packet_with_buf(&mut recv_bufs[i][..n], scratch) {
                Ok(decrypted) => {
                    entry.last_rx = Instant::now();
                    if let Some(ref ack) = decrypted.ack {
                        entry.conn.process_ack(ack);
                    }
                    for datagram in &decrypted.datagrams {
                        if datagram.is_empty() { continue; }
                        tun_write_sync(tun, datagram);
                    }
                }
                Err(e) => {
                    debug!(error = %e, "decrypt failed, dropping");
                }
            }
        }
    }

    Ok(())
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
                if n == 0 { continue; }

                if recv_buf[0] & 0x80 != 0 {
                    // Long header → handshake.
                    let mut data = BytesMut::with_capacity(n);
                    data.extend_from_slice(&recv_buf[..n]);
                    let now = Instant::now();
                    let responses = multi_state.handle_incoming(now, from, None, data, response_buf);
                    send_responses(udp, &responses, from)?;
                } else {
                    // Short header → CID routing.
                    if cid_len > 0 && n > cid_len {
                        let cid_bytes = &recv_buf[1..1 + cid_len];
                        if let Some(entry) = connections.get_mut(cid_bytes) {
                            match entry.conn.decrypt_packet_with_buf(&mut recv_buf[..n], scratch) {
                                Ok(decrypted) => {
                                    entry.last_rx = Instant::now();
                                    if let Some(ref ack) = decrypted.ack {
                                        entry.conn.process_ack(ack);
                                    }
                                    for datagram in &decrypted.datagrams {
                                        if datagram.is_empty() { continue; }
                                        tun_write_sync(tun, datagram);
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, "decrypt failed, dropping");
                                }
                            }
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
                if n < 20 { continue; }

                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                    cid.clone()
                } else if connections.len() == 1 {
                    connections.keys().next().expect("single connection").clone()
                } else {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                    continue;
                };

                // Flush current GSO batch if connection changed or batch full.
                if let Some(ref cur_cid) = current_cid {
                    if *cur_cid != cid || gso_count >= max_segs || gso_pos + MAX_PACKET > gso_buf.len() {
                        if gso_count > 0 {
                            flush_gso_sync(udp, gso_buf, gso_pos, gso_segment_size, current_remote.expect("remote set"))?;
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
        flush_gso_sync(udp, gso_buf, gso_pos, gso_segment_size, current_remote.expect("remote set"))?;
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
    quictun_core::batch_io::send_gso(
        udp,
        &gso_buf[..gso_pos],
        gso_segment_size as u16,
        remote_addr,
    ).context("send_gso failed")?;
    Ok(())
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
                if n < 20 { continue; }

                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                    cid.clone()
                } else if connections.len() == 1 {
                    connections.keys().next().expect("single connection").clone()
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
                    &packet[..n],
                    ack_ranges.as_deref(),
                    encrypt_buf,
                ) {
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
        connections.insert(cid_bytes, ConnEntry {
            conn: conn_state,
            tunnel_ip,
            remote_addr: hs.remote_addr,
            keepalive_interval,
            last_tx: now_inst,
            last_rx: now_inst,
        });
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

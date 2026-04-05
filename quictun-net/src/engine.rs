//! Shared utilities and entry point for the kernel-mode engine.
//!
//! The actual event loops live in engine_v2.rs (single-thread) and
//! multicore.rs (per-connection multi-core). This module provides:
//! - Types: EndpointSetup, NetConfig, RunResult
//! - GroTxPool for GRO TX coalescing (Linux)
//! - UDP socket, signal pipe, and fd helpers

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use mio::Token;
use quinn_proto::ServerConfig;
use tracing::warn;

use quictun_core::peer::PeerConfig;

/// Maximum QUIC packet size.
pub(crate) const MAX_PACKET: usize = 2048;

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
    pub server_name: String,
}

/// Result of the engine run — tells the CLI whether to reconnect.
pub enum RunResult {
    Shutdown,
    ConnectionLost,
}

/// Main entry point for the kernel-mode engine.
pub fn run(local_addr: SocketAddr, setup: EndpointSetup, config: NetConfig) -> Result<RunResult> {
    crate::engine_v2::run_v2(local_addr, setup, config)
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

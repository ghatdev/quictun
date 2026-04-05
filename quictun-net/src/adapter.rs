//! Kernel I/O adapter (Layer 2): mio + TUN + UDP + signal pipe.
//!
//! Implements [`DataPlaneIo`] and [`DataPlaneIoBatch`] for the kernel-mode
//! data plane. Owns all platform-specific resources: mio poll, UDP socket,
//! TUN device, signal pipe, and route management.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll};
use tracing::info;

use quictun_core::data_plane::{
    DataPlaneIo, DataPlaneIoBatch, OuterRecvBatch, Readiness,
};

use crate::engine::{
    create_signal_pipe, create_udp_socket, drain_signal_pipe, install_signal_handler,
    set_nonblocking, TOKEN_SIGNAL, TOKEN_TUN, TOKEN_UDP,
};

// ── Config for adapter creation ─────────────────────────────────────────

/// Configuration subset needed by the adapter (extracted from NetConfig).
pub struct AdapterConfig {
    pub local_addr: SocketAddr,
    pub tunnel_ip: Ipv4Addr,
    pub tunnel_prefix: u8,
    pub tunnel_mtu: u16,
    pub tunnel_name: Option<String>,
    pub recv_buf: usize,
    pub send_buf: usize,
    pub offload: bool,
    pub batch_size: usize,
    pub poll_events: usize,
}

// ── KernelAdapter ───────────────────────────────────────────────────────

/// Kernel-mode I/O adapter: mio + TUN + UDP + signal pipe.
pub struct KernelAdapter {
    poll: Poll,
    events: Events,
    udp_socket: std::net::UdpSocket,
    tun: tun_rs::SyncDevice,
    sig_read_fd: RawFd,
    _sig_write_fd: RawFd,
    signal_received: bool,

    // TUN interface info for route management.
    #[cfg(target_os = "linux")]
    tun_ifindex: u32,
    tun_ifname: String,

    // Linux batch I/O.
    #[cfg(target_os = "linux")]
    recv_work: quictun_core::batch_io::RecvMmsgWork,
    #[cfg(target_os = "linux")]
    offload_enabled: bool,

    // UDP GRO receive buffer (Linux only).
    #[cfg(target_os = "linux")]
    udp_gro_enabled: bool,
    #[cfg(target_os = "linux")]
    gro_recv_buf: Vec<u8>,
    /// Leftover GRO state: when a coalesced datagram has more segments than
    /// fit in one OuterRecvBatch, we save the remainder here and drain it on
    /// the next call. Without this, EPOLLET won't re-fire because the kernel
    /// already delivered the data — we just didn't consume all of it.
    #[cfg(target_os = "linux")]
    gro_remainder_offset: usize,
    #[cfg(target_os = "linux")]
    gro_remainder_total: usize,
    #[cfg(target_os = "linux")]
    gro_remainder_seg_size: usize,
    #[cfg(target_os = "linux")]
    gro_remainder_addr: std::net::SocketAddr,

    // Cached readiness from last poll.
    outer_ready: bool,
    inner_ready: bool,
}

impl KernelAdapter {
    /// Create a new kernel adapter with all resources initialized.
    pub fn new(config: &AdapterConfig) -> Result<Self> {
        // 1. UDP socket.
        let udp_socket = create_udp_socket(config.local_addr, config.recv_buf, config.send_buf)?;
        info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

        // 2. TUN device.
        let mut tun_opts = quictun_tun::TunOptions::new(
            config.tunnel_ip,
            config.tunnel_prefix,
            config.tunnel_mtu,
        );
        tun_opts.name = config.tunnel_name.clone();
        #[cfg(target_os = "linux")]
        {
            tun_opts.offload = config.offload;
        }
        let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
        set_nonblocking(tun.as_raw_fd())?;

        // Get TUN interface info for route management.
        let tun_ifname = tun
            .name()
            .map(|n| n.to_string())
            .unwrap_or_else(|_| "tunnel".to_string());
        #[cfg(target_os = "linux")]
        let tun_ifindex = Self::get_ifindex(&tun_ifname)?;

        // 3. Signal pipe.
        let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;
        install_signal_handler(sig_write_fd)?;

        // 4. mio poll + register.
        let poll = Poll::new().context("failed to create mio::Poll")?;
        let events = Events::with_capacity(config.poll_events);

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

        // Ensure UDP socket is non-blocking via fcntl (required for recv_from in event loop).
        // socket2 uses FIONBIO which may not persist after conversion to std UdpSocket.
        set_nonblocking(udp_socket.as_raw_fd())?;

        // Enable UDP GRO on the receive side to match GSO on the send side.
        // Without GRO, each packet is delivered individually — at high rates the
        // recv side can't keep up with GSO-accelerated sends, causing socket
        // buffer overflow and retransmits.
        #[cfg(target_os = "linux")]
        let udp_gro_enabled = match quictun_core::batch_io::enable_udp_gro(&udp_socket) {
            Ok(true) => {
                info!("UDP GRO enabled on recv socket");
                true
            }
            Ok(false) => {
                info!("UDP GRO not supported by kernel, using recvmmsg fallback");
                false
            }
            Err(e) => {
                info!(error = %e, "failed to enable UDP GRO, using recvmmsg fallback");
                false
            }
        };

        Ok(Self {
            poll,
            events,
            udp_socket,
            tun,
            sig_read_fd,
            _sig_write_fd: sig_write_fd,
            signal_received: false,
            #[cfg(target_os = "linux")]
            tun_ifindex,
            tun_ifname,
            #[cfg(target_os = "linux")]
            recv_work: quictun_core::batch_io::RecvMmsgWork::new(config.batch_size),
            #[cfg(target_os = "linux")]
            offload_enabled: config.offload,
            #[cfg(target_os = "linux")]
            udp_gro_enabled,
            #[cfg(target_os = "linux")]
            gro_recv_buf: vec![0u8; quictun_core::batch_io::GRO_RECV_BUF_SIZE],
            #[cfg(target_os = "linux")]
            gro_remainder_offset: 0,
            #[cfg(target_os = "linux")]
            gro_remainder_total: 0,
            #[cfg(target_os = "linux")]
            gro_remainder_seg_size: 0,
            #[cfg(target_os = "linux")]
            gro_remainder_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            outer_ready: false,
            inner_ready: false,
        })
    }

    #[cfg(target_os = "linux")]
    fn get_ifindex(name: &str) -> Result<u32> {
        let c_name = std::ffi::CString::new(name)
            .map_err(|_| anyhow::anyhow!("invalid TUN name"))?;
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            Err(io::Error::last_os_error()).context("if_nametoindex")
        } else {
            Ok(idx)
        }
    }

    /// Access the raw UDP socket (for direct use by engine hot loop).
    pub fn udp_socket(&self) -> &std::net::UdpSocket {
        &self.udp_socket
    }

    /// Returns true if there are leftover GRO segments from a previous recv.
    /// The engine must call recv_outer_batch again to drain them, even if
    /// EPOLLET hasn't re-fired.
    #[cfg(target_os = "linux")]
    pub fn has_gro_remainder(&self) -> bool {
        self.gro_remainder_offset < self.gro_remainder_total
    }

    /// Access the raw TUN device (for use by event_loop helpers).
    pub fn tun(&self) -> &tun_rs::SyncDevice {
        &self.tun
    }

    /// GRO-aware batch recv: each recvmsg returns a coalesced buffer that we
    /// split into individual QUIC packets for the engine.
    ///
    /// Preserves remainder state: if a coalesced datagram has more segments
    /// than fit in one batch, leftover segments are saved and drained on the
    /// next call. This is critical for EPOLLET correctness — without it, the
    /// kernel considers the data delivered and won't re-notify.
    #[cfg(target_os = "linux")]
    fn recv_outer_batch_gro(
        &mut self,
        batch: &mut OuterRecvBatch,
    ) -> io::Result<usize> {
        let max_count = batch.bufs.len();
        let mut batch_idx = 0;

        // 1. Drain leftover segments from previous call.
        if self.gro_remainder_offset < self.gro_remainder_total {
            let seg_size = self.gro_remainder_seg_size;
            let addr = self.gro_remainder_addr;
            while self.gro_remainder_offset < self.gro_remainder_total && batch_idx < max_count {
                let end = (self.gro_remainder_offset + seg_size).min(self.gro_remainder_total);
                let seg_len = end - self.gro_remainder_offset;
                batch.bufs[batch_idx][..seg_len]
                    .copy_from_slice(&self.gro_recv_buf[self.gro_remainder_offset..end]);
                batch.lens[batch_idx] = seg_len;
                batch.addrs[batch_idx] = addr;
                batch_idx += 1;
                self.gro_remainder_offset = end;
            }
            // If we drained everything, clear the remainder state.
            if self.gro_remainder_offset >= self.gro_remainder_total {
                self.gro_remainder_total = 0;
            }
        }

        // 2. Read new coalesced datagrams from the socket.
        loop {
            if batch_idx >= max_count {
                break;
            }
            let (total, seg_size, addr) = match quictun_core::batch_io::recv_gro_from(
                &self.udp_socket,
                &mut self.gro_recv_buf,
            ) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            if total == 0 || seg_size == 0 {
                break;
            }

            // Split coalesced buffer into individual segments.
            let mut offset = 0;
            while offset < total && batch_idx < max_count {
                let end = (offset + seg_size).min(total);
                let seg_len = end - offset;
                batch.bufs[batch_idx][..seg_len]
                    .copy_from_slice(&self.gro_recv_buf[offset..end]);
                batch.lens[batch_idx] = seg_len;
                batch.addrs[batch_idx] = addr;
                batch_idx += 1;
                offset = end;
            }

            // Save remainder if we couldn't fit all segments.
            if offset < total {
                self.gro_remainder_offset = offset;
                self.gro_remainder_total = total;
                self.gro_remainder_seg_size = seg_size;
                self.gro_remainder_addr = addr;
                break;
            }
        }

        Ok(batch_idx)
    }
}

// ── DataPlaneIo implementation ──────────────────────────────────────────

impl DataPlaneIo for KernelAdapter {
    fn poll(&mut self, timeout: Duration) -> io::Result<Readiness> {
        self.outer_ready = false;
        self.inner_ready = false;
        self.signal_received = false;

        self.poll
            .poll(&mut self.events, Some(timeout))
            .or_else(|e| {
                if e.kind() == io::ErrorKind::Interrupted {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;

        for event in self.events.iter() {
            match event.token() {
                TOKEN_UDP => self.outer_ready = true,
                TOKEN_TUN => self.inner_ready = true,
                TOKEN_SIGNAL => {
                    drain_signal_pipe(self.sig_read_fd);
                    self.signal_received = true;
                }
                _ => {}
            }
        }

        Ok(Readiness {
            outer: self.outer_ready,
            inner: self.inner_ready,
            signal: self.signal_received,
        })
    }

    fn recv_outer(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.udp_socket.recv_from(buf)
    }

    fn send_outer(&mut self, pkt: &[u8], remote: SocketAddr) -> io::Result<()> {
        self.udp_socket.send_to(pkt, remote)?;
        Ok(())
    }

    fn recv_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf)
    }

    fn send_inner(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.tun.send(pkt)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_os_route(&mut self, dst: Ipv4Net) -> io::Result<()> {
        crate::route::add_route(dst, self.tun_ifindex)
    }

    #[cfg(target_os = "linux")]
    fn remove_os_route(&mut self, dst: Ipv4Net) -> io::Result<()> {
        crate::route::remove_route(dst, self.tun_ifindex)
    }

    #[cfg(target_os = "macos")]
    fn add_os_route(&mut self, dst: Ipv4Net) -> io::Result<()> {
        crate::route::add_route(dst, &self.tun_ifname)
    }

    #[cfg(target_os = "macos")]
    fn remove_os_route(&mut self, dst: Ipv4Net) -> io::Result<()> {
        crate::route::remove_route(dst, &self.tun_ifname)
    }
}

// ── DataPlaneIoBatch implementation ─────────────────────────────────────

impl DataPlaneIoBatch for KernelAdapter {
    #[cfg(target_os = "linux")]
    fn recv_outer_batch(&mut self, batch: &mut OuterRecvBatch) -> io::Result<usize> {
        if self.udp_gro_enabled {
            self.recv_outer_batch_gro(batch)
        } else {
            let max_count = batch.bufs.len();
            quictun_core::batch_io::recvmmsg_batch(
                &self.udp_socket,
                &mut batch.bufs,
                &mut batch.lens,
                &mut batch.addrs,
                max_count,
                &mut self.recv_work,
            )
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_outer_batch(&mut self, batch: &mut OuterRecvBatch) -> io::Result<usize> {
        // Fallback: single recv.
        match self.udp_socket.recv_from(&mut batch.bufs[0]) {
            Ok((len, addr)) => {
                batch.lens[0] = len;
                batch.addrs[0] = addr;
                Ok(1)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

}

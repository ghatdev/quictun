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
    DataPlaneIo, DataPlaneIoBatch, InnerRecvBatch, OuterRecvBatch, Readiness,
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

    // Linux GRO TX coalescing for TUN writes.
    #[cfg(target_os = "linux")]
    gro_table: Option<quictun_tun::GROTable>,
    #[cfg(target_os = "linux")]
    gro_tx_pool: crate::engine::GroTxPool,

    // GSO TX batching: accumulate send_outer packets, flush on poll().
    #[cfg(target_os = "linux")]
    gso_buf: Vec<u8>,
    #[cfg(target_os = "linux")]
    gso_pos: usize,
    #[cfg(target_os = "linux")]
    gso_segment_size: usize,
    #[cfg(target_os = "linux")]
    gso_remote: std::net::SocketAddr,
    #[cfg(target_os = "linux")]
    gso_count: usize,

    // TUN write backpressure buffer.
    tun_write_buf: std::collections::VecDeque<Vec<u8>>,

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
            gro_table: if config.offload {
                Some(quictun_tun::GROTable::default())
            } else {
                None
            },
            #[cfg(target_os = "linux")]
            gro_tx_pool: crate::engine::GroTxPool::new(),
            #[cfg(target_os = "linux")]
            gso_buf: vec![0u8; 44 * 2048],
            #[cfg(target_os = "linux")]
            gso_pos: 0,
            #[cfg(target_os = "linux")]
            gso_segment_size: 0,
            #[cfg(target_os = "linux")]
            gso_remote: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            #[cfg(target_os = "linux")]
            gso_count: 0,
            tun_write_buf: std::collections::VecDeque::with_capacity(256),
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

    /// Flush pending GSO batch via send_gso syscall.
    #[cfg(target_os = "linux")]
    fn flush_gso_batch(&mut self) {
        if self.gso_count == 0 {
            return;
        }
        let result = if self.gso_count == 1 {
            self.udp_socket.send_to(&self.gso_buf[..self.gso_pos], self.gso_remote)
                .map(|_| ())
        } else {
            quictun_core::batch_io::send_gso(
                &self.udp_socket,
                &self.gso_buf[..self.gso_pos],
                self.gso_segment_size as u16,
                self.gso_remote,
            ).map(|_| ())
        };
        if let Err(e) = result {
            if e.kind() == io::ErrorKind::WouldBlock {
                // Retry once after brief wait.
                crate::engine::wait_writable(self.udp_socket.as_raw_fd());
                let _ = if self.gso_count == 1 {
                    self.udp_socket.send_to(&self.gso_buf[..self.gso_pos], self.gso_remote)
                } else {
                    quictun_core::batch_io::send_gso(
                        &self.udp_socket,
                        &self.gso_buf[..self.gso_pos],
                        self.gso_segment_size as u16,
                        self.gso_remote,
                    )
                };
            }
        }
        self.gso_pos = 0;
        self.gso_count = 0;
        self.gso_segment_size = 0;
    }

    /// Access the raw UDP socket (for use by event_loop helpers).
    pub fn udp_socket(&self) -> &std::net::UdpSocket {
        &self.udp_socket
    }

    /// Access the raw TUN device (for use by event_loop helpers).
    pub fn tun(&self) -> &tun_rs::SyncDevice {
        &self.tun
    }
}

// ── DataPlaneIo implementation ──────────────────────────────────────────

impl DataPlaneIo for KernelAdapter {
    fn poll(&mut self, timeout: Duration) -> io::Result<Readiness> {
        // Flush pending GSO batch before polling (accumulated by send_outer).
        #[cfg(target_os = "linux")]
        self.flush_gso_batch();

        // Drain buffered TUN writes (backpressure from previous iteration).
        while let Some(pkt) = self.tun_write_buf.front() {
            match self.tun.send(pkt) {
                Ok(_) => { self.tun_write_buf.pop_front(); }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => { self.tun_write_buf.pop_front(); }
            }
        }

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

    #[cfg(target_os = "linux")]
    fn send_outer(&mut self, pkt: &[u8], remote: SocketAddr) -> io::Result<()> {
        const MAX_GSO_SEGMENTS: usize = 44;

        // Flush if remote changed, segment size changed, or batch full.
        if self.gso_count > 0
            && (remote != self.gso_remote
                || pkt.len() != self.gso_segment_size
                || self.gso_count >= MAX_GSO_SEGMENTS
                || self.gso_pos + pkt.len() > self.gso_buf.len())
        {
            self.flush_gso_batch();
        }

        // Accumulate into GSO buffer.
        self.gso_buf[self.gso_pos..self.gso_pos + pkt.len()]
            .copy_from_slice(pkt);
        if self.gso_count == 0 {
            self.gso_segment_size = pkt.len();
            self.gso_remote = remote;
        }
        self.gso_pos += pkt.len();
        self.gso_count += 1;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn send_outer(&mut self, pkt: &[u8], remote: SocketAddr) -> io::Result<()> {
        self.udp_socket.send_to(pkt, remote)?;
        Ok(())
    }

    fn recv_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf)
    }

    fn send_inner(&mut self, pkt: &[u8]) -> io::Result<()> {
        // Buffer if there's a backlog (preserve ordering).
        if !self.tun_write_buf.is_empty() {
            if self.tun_write_buf.len() < 256 {
                self.tun_write_buf.push_back(pkt.to_vec());
            }
            return Ok(());
        }
        match self.tun.send(pkt) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if self.tun_write_buf.len() < 256 {
                    self.tun_write_buf.push_back(pkt.to_vec());
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
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

    fn recv_inner_batch(&mut self, batch: &mut InnerRecvBatch) -> io::Result<usize> {
        // Simple fallback: one packet at a time.
        // GRO splitting is handled in the event_loop when offload is enabled.
        match self.tun.recv(&mut batch.bufs[0]) {
            Ok(len) => {
                batch.lens[0] = len;
                Ok(1)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    #[cfg(target_os = "linux")]
    fn send_outer_gso(
        &mut self,
        segments: &[u8],
        segment_size: usize,
        remote: SocketAddr,
    ) -> io::Result<()> {
        quictun_core::batch_io::send_gso(
            &self.udp_socket,
            segments,
            segment_size as u16,
            remote,
        )?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn send_outer_gso(
        &mut self,
        segments: &[u8],
        segment_size: usize,
        remote: SocketAddr,
    ) -> io::Result<()> {
        // Fallback: send each segment individually.
        for chunk in segments.chunks(segment_size) {
            self.udp_socket.send_to(chunk, remote)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn send_inner_gro(&mut self, pkt: &[u8]) -> io::Result<()> {
        if self.offload_enabled {
            self.gro_tx_pool.push_datagram(pkt);
            Ok(())
        } else {
            self.tun.send(pkt)?;
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn send_inner_gro(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.tun.send(pkt)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn flush_inner_gro(&mut self) -> io::Result<()> {
        if !self.offload_enabled || self.gro_tx_pool.is_empty() {
            return Ok(());
        }
        if let Some(ref mut gro) = self.gro_table {
            match self.tun.send_multiple(
                gro,
                self.gro_tx_pool.as_mut_slice(),
                quictun_tun::VIRTIO_NET_HDR_LEN,
            ) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Fallback: send individually on backpressure.
                    for buf in self.gro_tx_pool.iter() {
                        let _ = self.tun.send(buf);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.gro_tx_pool.reset();
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn flush_inner_gro(&mut self) -> io::Result<()> {
        Ok(())
    }
}

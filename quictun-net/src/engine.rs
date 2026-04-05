//! Kernel-mode engine: single-thread + multi-core.
//!
//! `run()` is the entry point. It creates the I/O adapter, runs the QUIC
//! handshake, then dispatches to single-thread (inline) or multi-core
//! (multicore.rs) based on `config.threads`.
//!
//! Architecture:
//!   quictun-core/manager.rs  — shared state (ConnectionManager)
//!   quictun-net/engine.rs    — single-thread hot loop + shared utilities
//!   quictun-net/multicore.rs — per-connection multi-core
//!   quictun-net/adapter.rs   — I/O setup, poll, route management

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use mio::Token;
#[allow(unused_imports)]
use tracing::{debug, info, warn};

use quictun_core::config::Config;
use quictun_core::data_plane::{DataPlaneIo, DataPlaneIoBatch, OuterRecvBatch};
pub use quictun_core::engine::{EndpointSetup, Engine, RunResult};
use quictun_core::manager::{ConnEntry, ConnectionManager, ManagerAction, PromoteResult};
use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::MultiQuicState;
use quictun_core::routing::RouteAction;
use quictun_core::session;
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;

use crate::adapter::{AdapterConfig, KernelAdapter};

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
    /// Data-plane rate control config. `None` = no CC.
    pub rate_control_config: Option<quictun_proto::rate_control::RateControlConfig>,
}


/// Kernel-mode engine backend.
pub struct NetEngine;

impl Engine for NetEngine {
    fn run(
        &self,
        local_addr: SocketAddr,
        setup: EndpointSetup,
        config: &Config,
        peers: Vec<PeerConfig>,
    ) -> Result<RunResult> {
        let net_config = NetConfig {
            tunnel_ip: config.parse_address()?.addr(),
            tunnel_prefix: config.parse_address()?.prefix_len(),
            tunnel_mtu: config.mtu(),
            tunnel_name: None, // set by CLI caller if needed
            idle_timeout: session::idle_timeout(config),
            cid_len: config.interface.cid_length as usize,
            peers,
            reconnect: session::reconnect_enabled(config),
            recv_buf: config.engine.recv_buf,
            send_buf: config.engine.send_buf,
            threads: config.engine.threads,
            offload: config.engine.offload,
            batch_size: config.engine.batch_size,
            gso_max_segments: config.engine.gso_max_segments,
            ack_interval: config.engine.ack_interval,
            ack_timer_ms: config.engine.ack_timer_ms,
            tun_write_buf_capacity: config.engine.tun_write_buf,
            channel_capacity: config.engine.channel_capacity,
            poll_events: config.engine.poll_events,
            max_peers: config.engine.max_peers,
            server_name: config.interface.server_name.clone()
                .unwrap_or_else(|| "quictun".to_owned()),
            rate_control_config: config.engine.rate_control_config(),
        };
        run_engine(local_addr, setup, net_config)
    }
}

/// Direct entry point (for backwards compatibility or testing).
pub fn run(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    run_engine(local_addr, setup, config)
}

/// Internal engine entry point.
fn run_engine(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });

    // 1. Create the kernel I/O adapter (setup + poll + routes).
    let adapter_config = AdapterConfig {
        local_addr,
        tunnel_ip: config.tunnel_ip,
        tunnel_prefix: config.tunnel_prefix,
        tunnel_mtu: config.tunnel_mtu,
        tunnel_name: config.tunnel_name.clone(),
        recv_buf: config.recv_buf,
        send_buf: config.send_buf,
        offload: config.offload,
        batch_size: config.batch_size,
        poll_events: config.poll_events,
    };
    let mut adapter = KernelAdapter::new(&adapter_config)?;

    // Buffer size validation: warn if sizes don't match GRO/GSO expectations.
    validate_buffer_config(&config);

    // 2. Connection manager (shared state).
    let mut manager = ConnectionManager::<LocalConnectionState>::new(
        config.tunnel_ip,
        false,
        config.max_peers,
        config.idle_timeout,
    );

    // 3. MultiQuicState for handshakes.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => MultiQuicState::new(server_config.clone()),
        EndpointSetup::Connector { .. } => MultiQuicState::new_connector(),
    };
    multi_state.ack_interval = config.ack_interval;
    multi_state.rate_control_config = config.rate_control_config;

    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        multi_state
            .connect(client_config, remote_addr, &config.server_name)
            .context("failed to initiate QUIC connection")?;
        drain_transmits(&adapter, &mut multi_state)?;
    }

    // 4. Multi-core or single-thread.
    if config.threads > 1 {
        info!(threads = config.threads, "multi-core engine starting");
        return crate::multicore::run_multicore(
            &mut adapter,
            &mut multi_state,
            &config,
        );
    }

    info!("engine starting");

    // ── Pre-allocated buffers ───────────────────────────────────────────
    let mut recv_batch = OuterRecvBatch::new(config.batch_size);
    let mut scratch = BytesMut::with_capacity(MAX_PACKET);
    let mut response_buf = vec![0u8; MAX_PACKET];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; config.gso_max_segments * MAX_PACKET];

    let mut tun_write_buf: std::collections::VecDeque<Vec<u8>> =
        std::collections::VecDeque::with_capacity(config.tun_write_buf_capacity);

    #[cfg(target_os = "linux")]
    let offload_enabled = config.offload;
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = GroTxPool::new();
    #[cfg(target_os = "linux")]
    let mut gro_table = if offload_enabled {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let mut tun_original_buf = if offload_enabled {
        vec![0u8; quictun_tun::VIRTIO_NET_HDR_LEN + 65535]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_bufs = if offload_enabled {
        vec![vec![0u8; MAX_PACKET]; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_sizes = if offload_enabled {
        vec![0usize; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };

    let ack_interval = Duration::from_millis(config.ack_timer_ms as u64);
    let mut next_ack = Instant::now() + ack_interval;
    let stats_interval = Duration::from_secs(30);
    let mut next_stats = Instant::now() + stats_interval;

    let cid_len = config.cid_len;
    let peers = &config.peers;

    // ── Main poll loop ──────────────────────────────────────────────────
    loop {
        while let Some(pkt) = tun_write_buf.front() {
            match adapter.tun().send(pkt) {
                Ok(_) => { tun_write_buf.pop_front(); }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => { tun_write_buf.pop_front(); }
            }
        }

        let timeout = manager.compute_poll_timeout(next_ack);
        let readiness = adapter.poll(timeout).context("poll failed")?;

        if readiness.signal {
            info!("received signal, shutting down");
            for entry in manager.values_mut() {
                if let Ok(r) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                    let _ = adapter.udp_socket().send_to(
                        &encrypt_buf[..r.len], entry.remote_addr,
                    );
                }
            }
            return Ok(RunResult::Shutdown);
        }

        // ── UDP RX → decrypt → TUN write ────────────────────────────
        if readiness.outer {
            loop {
                let count = match adapter.recv_outer_batch(&mut recv_batch) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e).context("recv_outer_batch failed"),
                };

                for i in 0..count {
                    let n = recv_batch.lens[i];
                    if n == 0 { continue; }
                    let from = recv_batch.addrs[i];
                    let first_byte = recv_batch.bufs[i][0];

                    if first_byte & 0x80 != 0 {
                        let mut data = BytesMut::with_capacity(n);
                        data.extend_from_slice(&recv_batch.bufs[i][..n]);
                        let responses = multi_state.handle_incoming(
                            Instant::now(), from, None, data, &mut response_buf,
                        );
                        for resp in &responses {
                            let _ = adapter.udp_socket().send_to(resp, from);
                        }
                        continue;
                    }

                    if cid_len == 0 || n < 1 + cid_len { continue; }
                    let cid_key = cid_to_u64(&recv_batch.bufs[i][1..1 + cid_len]);

                    let close_received =
                        if let Some(entry) = manager.get_mut(&cid_key) {
                            match entry.conn.decrypt_packet_with_buf(
                                &mut recv_batch.bufs[i][..n], &mut scratch,
                            ) {
                                Ok(decrypted) => {
                                    entry.last_rx = Instant::now();
                                    if let Some(ref ack) = decrypted.ack {
                                        entry.conn.process_ack(ack);
                                        entry.on_ack(ack);
                                    }
                                    if !decrypted.close_received {
                                        for datagram in &decrypted.datagrams {
                                            if datagram.len() < 20 { continue; }
                                            let src_ip = Ipv4Addr::new(
                                                datagram[12], datagram[13],
                                                datagram[14], datagram[15],
                                            );
                                            if !peer::is_allowed_source(&entry.allowed_ips, src_ip) {
                                                continue;
                                            }
                                            #[cfg(target_os = "linux")]
                                            if offload_enabled {
                                                gro_tx_pool.push_datagram(datagram);
                                            } else {
                                                tun_write_with_buf(adapter.tun(), datagram, &mut tun_write_buf);
                                            }
                                            #[cfg(not(target_os = "linux"))]
                                            tun_write_with_buf(adapter.tun(), datagram, &mut tun_write_buf);
                                        }
                                    }
                                    decrypted.close_received
                                }
                                Err(_) => false,
                            }
                        } else { false };

                    if close_received
                        && let Some(entry) = manager.remove_connection(cid_key)
                    {
                        info!(tunnel_ip = %entry.tunnel_ip, "peer sent CONNECTION_CLOSE");
                        for net in &entry.allowed_ips {
                            let _ = adapter.remove_os_route(*net);
                        }
                    }
                }
            }
        }

        // Flush GRO TX pool.
        #[cfg(target_os = "linux")]
        if offload_enabled && !gro_tx_pool.is_empty() {
            if let Some(ref mut gro) = gro_table {
                match adapter.tun().send_multiple(
                    gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN,
                ) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        for buf in gro_tx_pool.iter() {
                            tun_write_buf.push_back(buf.to_vec());
                        }
                    }
                    Err(e) => { debug!(error = %e, "TUN send_multiple failed"); }
                }
                gro_tx_pool.reset();
            }
        }

        // ── TUN RX → encrypt → UDP send ────────────────────────────
        if readiness.inner {
            #[cfg(target_os = "linux")]
            if offload_enabled {
                handle_tun_rx_offload(
                    &mut manager, adapter.tun(), adapter.udp_socket(),
                    &mut gso_buf, &mut tun_original_buf,
                    &mut tun_split_bufs, &mut tun_split_sizes,
                );
            } else {
                handle_tun_rx_gso(
                    &mut manager, adapter.tun(), adapter.udp_socket(), &mut gso_buf,
                );
            }

            #[cfg(not(target_os = "linux"))]
            handle_tun_rx_simple(
                &mut manager, adapter.tun(), adapter.udp_socket(), &mut encrypt_buf,
            );
        }

        // ── Timeouts ────────────────────────────────────────────────
        let actions = manager.sweep_timeouts();
        for action in actions {
            match action {
                ManagerAction::SendKeepalive { cid_key } => {
                    if let Some(entry) = manager.get_mut(&cid_key)
                        && let Ok(r) = entry.conn.encrypt_datagram(&[], &mut encrypt_buf, None)
                    {
                        let _ = adapter.udp_socket().send_to(
                            &encrypt_buf[..r.len], entry.remote_addr,
                        );
                        entry.last_tx = Instant::now();
                    }
                }
                ManagerAction::ConnectionRemoved { allowed_ips, .. } => {
                    for net in &allowed_ips {
                        let _ = adapter.remove_os_route(*net);
                    }
                }
            }
        }

        // ── ACK timer ───────────────────────────────────────────────
        let now = Instant::now();
        if now >= next_ack {
            for cid_key in manager.connections_needing_ack() {
                if let Some(entry) = manager.get_mut(&cid_key) {
                    let ack_delay = entry.queuing_delay_us();
                    if let Ok(r) = entry.conn.encrypt_ack(ack_delay, &mut encrypt_buf) {
                        let _ = adapter.udp_socket().send_to(
                            &encrypt_buf[..r.len], entry.remote_addr,
                        );
                    }
                }
            }
            next_ack = now + ack_interval;
        }

        // ── Stats ───────────────────────────────────────────────────
        if now >= next_stats {
            let stats = manager.stats();
            info!(
                connections = stats.connections,
                routes = stats.routes,
                handshakes = multi_state.handshakes.len(),
                "periodic stats"
            );
            next_stats = now + stats_interval;
        }

        // ── Drive handshakes ────────────────────────────────────────
        if !multi_state.handshakes.is_empty() {
            drain_transmits(&adapter, &mut multi_state)?;
            let result = multi_state.poll_handshakes();
            drain_transmits(&adapter, &mut multi_state)?;

            let hs_now = Instant::now();
            for hs in multi_state.handshakes.values_mut() {
                if let Some(t) = hs.connection.poll_timeout()
                    && hs_now >= t
                {
                    hs.connection.handle_timeout(hs_now);
                }
            }

            for ch in result.completed {
                let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
                    continue;
                };
                match manager.promote_handshake(&hs, conn_state, peers) {
                    PromoteResult::Accepted {
                        cid_key, cid_bytes, tunnel_ip, allowed_ips,
                        remote_addr, keepalive_interval, conn_state, ..
                    } => {
                        let now_inst = Instant::now();
                        info!(
                            remote = %remote_addr, tunnel_ip = %tunnel_ip,
                            cid = %hex::encode(&cid_bytes),
                            active = manager.len() + 1,
                            "connection established"
                        );
                        for net in &allowed_ips {
                            if let Err(e) = adapter.add_os_route(*net) {
                                warn!(error = %e, dst = %net, "failed to add OS route");
                            }
                        }
                        manager.insert_connection(cid_key, ConnEntry {
                            conn: conn_state, tunnel_ip, allowed_ips,
                            remote_addr, keepalive_interval,
                            last_tx: now_inst, last_rx: now_inst,
                            owd_tracker: quictun_proto::rate_control::OwdTracker::new(),
                            rate_controller: config.rate_control_config.map(
                                quictun_proto::rate_control::RateController::new,
                            ),
                        });
                    }
                    PromoteResult::Rejected { mut conn_state, remote_addr, reason } => {
                        warn!(remote = %remote_addr, reason = ?reason, "handshake rejected");
                        let mut close_buf = vec![0u8; 128];
                        if let Ok(r) = conn_state.encrypt_connection_close(&mut close_buf) {
                            let _ = adapter.udp_socket().send_to(&close_buf[..r.len], remote_addr);
                        }
                    }
                }
            }
        }

        // ── Connector: detect connection lost ───────────────────────
        if is_connector
            && config.reconnect
            && manager.had_connection()
            && manager.is_empty()
            && multi_state.handshakes.is_empty()
        {
            info!("connection lost, will reconnect");
            return Ok(RunResult::ConnectionLost);
        }
    }
}

// ── TUN RX helpers ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn handle_tun_rx_gso(
    manager: &mut ConnectionManager<LocalConnectionState>,
    tun: &tun_rs::SyncDevice,
    udp: &std::net::UdpSocket,
    gso_buf: &mut [u8],
) {
    let max_segs = gso_buf.len() / MAX_PACKET;
    let mut gso_pos: usize = 0;
    let mut gso_segment_size: usize = 0;
    let mut gso_count: usize = 0;
    let mut current_cid: Option<u64> = None;
    let mut current_remote: Option<SocketAddr> = None;
    let mut packet = [0u8; MAX_PACKET];

    loop {
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 || packet[0] >> 4 != 4 { continue; }
                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = match manager.lookup_route(dest_ip) {
                    RouteAction::ForwardToPeer(cid) => cid,
                    _ if manager.len() == 1 => {
                        match manager.keys().next() {
                            Some(&cid) => cid,
                            None => continue,
                        }
                    }
                    _ => continue,
                };

                if let Some(cur_cid) = current_cid {
                    if cur_cid != cid || gso_count >= max_segs || gso_pos + MAX_PACKET > gso_buf.len() {
                        if gso_count > 0 {
                            flush_gso(udp, gso_buf, gso_pos, gso_segment_size, current_remote.expect("remote set"));
                            if let Some(entry) = manager.get_mut(&cur_cid) { entry.last_tx = Instant::now(); }
                        }
                        gso_pos = 0; gso_segment_size = 0; gso_count = 0;
                    }
                }

                // Rate control: check before mutable borrow.
                if !manager.get(&cid).map_or(true, |e| e.can_send()) {
                    if gso_count > 0 {
                        flush_gso(udp, gso_buf, gso_pos, gso_segment_size, current_remote.expect("remote set"));
                        if let Some(cur_cid) = current_cid {
                            if let Some(e) = manager.get_mut(&cur_cid) { e.last_tx = Instant::now(); }
                        }
                    }
                    break;
                }

                let entry = match manager.get_mut(&cid) { Some(e) => e, None => continue };
                current_cid = Some(cid);
                current_remote = Some(entry.remote_addr);

                match entry.conn.encrypt_datagram(&packet[..n], &mut gso_buf[gso_pos..], None) {
                    Ok(result) => {
                        entry.on_bytes_sent(result.len);
                        if gso_count == 0 {
                            gso_segment_size = result.len; gso_pos += result.len; gso_count += 1;
                        } else if result.len == gso_segment_size {
                            gso_pos += result.len; gso_count += 1;
                        } else {
                            if gso_count > 0 {
                                flush_gso(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr);
                            }
                            gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                            gso_segment_size = result.len; gso_pos = result.len; gso_count = 1;
                        }
                    }
                    Err(e) => { warn!(error = %e, "encrypt failed"); }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => { debug!(error = %e, "TUN recv error"); break; }
        }
    }

    if gso_count > 0 {
        flush_gso(udp, gso_buf, gso_pos, gso_segment_size, current_remote.expect("remote set"));
        if let Some(cur_cid) = current_cid {
            if let Some(entry) = manager.get_mut(&cur_cid) { entry.last_tx = Instant::now(); }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn flush_gso(
    udp: &std::net::UdpSocket,
    gso_buf: &[u8],
    gso_pos: usize,
    segment_size: usize,
    remote: SocketAddr,
) {
    loop {
        let result = quictun_core::batch_io::send_gso(
            udp, &gso_buf[..gso_pos], segment_size as u16, remote,
        );
        match result {
            Ok(_) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => { wait_writable(udp.as_raw_fd()); }
            Err(e) => { debug!(error = %e, "GSO send failed"); return; }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn handle_tun_rx_simple(
    manager: &mut ConnectionManager<LocalConnectionState>,
    tun: &tun_rs::SyncDevice,
    udp: &std::net::UdpSocket,
    encrypt_buf: &mut [u8],
) {
    let mut packet = [0u8; MAX_PACKET];
    loop {
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 || packet[0] >> 4 != 4 { continue; }
                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                let cid = match manager.lookup_route(dest_ip) {
                    RouteAction::ForwardToPeer(cid) => cid,
                    _ if manager.len() == 1 => {
                        match manager.keys().next() { Some(&cid) => cid, None => continue }
                    }
                    _ => continue,
                };
                let entry = match manager.get_mut(&cid) { Some(e) => e, None => continue };
                if !entry.can_send() { break; }
                match entry.conn.encrypt_datagram(&packet[..n], encrypt_buf, None) {
                    Ok(result) => {
                        let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                        entry.on_bytes_sent(result.len);
                        entry.last_tx = Instant::now();
                    }
                    Err(e) => { warn!(error = %e, "encrypt failed"); }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn tun_write_with_buf(
    tun: &tun_rs::SyncDevice,
    data: &[u8],
    buf: &mut std::collections::VecDeque<Vec<u8>>,
) {
    if !buf.is_empty() {
        if buf.len() < buf.capacity().max(256) { buf.push_back(data.to_vec()); }
        return;
    }
    match tun.send(data) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => { buf.push_back(data.to_vec()); }
        Err(_) => {}
    }
}

#[cfg(target_os = "linux")]
fn handle_tun_rx_offload(
    manager: &mut ConnectionManager<LocalConnectionState>,
    tun: &tun_rs::SyncDevice,
    udp: &std::net::UdpSocket,
    gso_buf: &mut [u8],
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
) {
    use smallvec::SmallVec;
    let max_segs = gso_buf.len() / MAX_PACKET;

    loop {
        let n_pkts = match tun.recv_multiple(original_buf, split_bufs, split_sizes, 0) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => { debug!(error = %e, "TUN recv_multiple failed"); break; }
        };

        let mut batch_indices: SmallVec<[usize; 64]> = SmallVec::new();
        let mut batch_cid: Option<u64> = None;

        for i in 0..n_pkts {
            let pkt_len = split_sizes[i];
            if pkt_len < 20 || split_bufs[i][0] >> 4 != 4 { continue; }
            let packet = &split_bufs[i][..pkt_len];
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            let cid = match manager.lookup_route(dest_ip) {
                RouteAction::ForwardToPeer(cid) => cid,
                _ if manager.len() == 1 => *manager.keys().next().expect("single connection"),
                _ => continue,
            };

            // Rate control check.
            if !manager.get(&cid).map_or(true, |e| e.can_send()) {
                if let Some(prev_cid) = batch_cid {
                    if !batch_indices.is_empty() {
                        flush_offload_batch(udp, manager, gso_buf, split_bufs, split_sizes, &batch_indices, prev_cid, max_segs);
                    }
                }
                break;
            }

            if let Some(prev_cid) = batch_cid {
                if prev_cid != cid && !batch_indices.is_empty() {
                    flush_offload_batch(udp, manager, gso_buf, split_bufs, split_sizes, &batch_indices, prev_cid, max_segs);
                    batch_indices.clear();
                }
            }
            batch_cid = Some(cid);
            batch_indices.push(i);

            if batch_indices.len() >= max_segs {
                flush_offload_batch(udp, manager, gso_buf, split_bufs, split_sizes, &batch_indices, cid, max_segs);
                batch_indices.clear();
            }
        }

        if let Some(cid) = batch_cid {
            if !batch_indices.is_empty() {
                flush_offload_batch(udp, manager, gso_buf, split_bufs, split_sizes, &batch_indices, cid, max_segs);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn flush_offload_batch(
    udp: &std::net::UdpSocket,
    manager: &mut ConnectionManager<LocalConnectionState>,
    gso_buf: &mut [u8],
    split_bufs: &[Vec<u8>],
    split_sizes: &[usize],
    indices: &[usize],
    cid: u64,
    _max_segs: usize,
) {
    let entry = match manager.get_mut(&cid) { Some(e) => e, None => return };
    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;

    for &idx in indices {
        let pkt = &split_bufs[idx][..split_sizes[idx]];
        match entry.conn.encrypt_datagram(pkt, &mut gso_buf[gso_pos..], None) {
            Ok(result) => {
                entry.on_bytes_sent(result.len);
                if gso_count == 0 {
                    gso_segment_size = result.len; gso_pos += result.len; gso_count += 1;
                } else if result.len == gso_segment_size {
                    gso_pos += result.len; gso_count += 1;
                } else {
                    if gso_count > 0 { flush_gso(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr); }
                    gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                    gso_segment_size = result.len; gso_pos = result.len; gso_count = 1;
                }
            }
            Err(e) => { warn!(error = %e, "encrypt failed"); }
        }
    }

    if gso_count > 0 {
        flush_gso(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr);
        entry.last_tx = Instant::now();
    }
}

fn drain_transmits(adapter: &KernelAdapter, state: &mut MultiQuicState) -> Result<()> {
    let now = Instant::now();
    let mut buf = Vec::with_capacity(4096);
    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut buf) else { break };
            adapter.udp_socket()
                .send_to(&buf[..transmit.size], hs.remote_addr)
                .context("failed to send handshake transmit")?;
        }
    }
    Ok(())
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

    if let Ok(actual_recv) = sock.recv_buffer_size()
        && actual_recv < recv_buf / 2
    {
        warn!(
            requested = recv_buf,
            actual = actual_recv,
            "UDP recv buffer clamped by kernel — set net.core.rmem_max >= {} to avoid packet drops",
            recv_buf,
        );
    }
    if let Ok(actual_send) = sock.send_buffer_size()
        && actual_send < send_buf / 2
    {
        warn!(
            requested = send_buf,
            actual = actual_send,
            "UDP send buffer clamped by kernel — set net.core.wmem_max >= {}",
            send_buf,
        );
    }

    sock.bind(&addr.into())
        .with_context(|| format!("failed to bind UDP to {addr}"))?;

    Ok(sock.into())
}

/// Validate buffer configuration and warn about mismatches that can cause
/// retransmits or silent data loss.
fn validate_buffer_config(config: &NetConfig) {
    // GSO send buffer must fit gso_max_segments × MAX_PACKET.
    let gso_buf_needed = config.gso_max_segments * MAX_PACKET;
    if config.send_buf < gso_buf_needed {
        warn!(
            send_buf = config.send_buf,
            gso_buf_needed,
            gso_max_segments = config.gso_max_segments,
            "send_buf < gso_max_segments × {} — GSO batches may be dropped by kernel",
            MAX_PACKET,
        );
    }

    // Recv buffer should hold at least GRO_MAX_SEGMENTS × MAX_PACKET worth of
    // queued data to avoid drops during GRO coalescing.
    #[cfg(target_os = "linux")]
    {
        let gro_burst = quictun_core::batch_io::GRO_MAX_SEGMENTS * MAX_PACKET;
        // The recv_buf should hold many GRO bursts — at high rates, the
        // kernel can queue multiple GRO-coalesced datagrams.
        if config.recv_buf < gro_burst * 4 {
            warn!(
                recv_buf = config.recv_buf,
                min_recommended = gro_burst * 4,
                "recv_buf may be too small for UDP GRO — risk of packet drops at high rates. \
                 Set recv_buf >= {} or increase net.core.rmem_max",
                gro_burst * 4,
            );
        }
    }

    // TUN write buffer should be large enough to absorb bursts when TUN
    // blocks (WouldBlock). At 10 Gbps with ~1400-byte packets, that's
    // ~890K pps → ~89 packets per 100μs poll cycle.
    if config.tun_write_buf_capacity < 64 {
        warn!(
            tun_write_buf = config.tun_write_buf_capacity,
            "tun_write_buf < 64 — may cause packet drops when TUN blocks",
        );
    }

    info!(
        recv_buf = config.recv_buf,
        send_buf = config.send_buf,
        batch_size = config.batch_size,
        gso_max_segments = config.gso_max_segments,
        tun_write_buf = config.tun_write_buf_capacity,
        offload = config.offload,
        "buffer config validated",
    );
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

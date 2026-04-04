//! v2 engine: platform-specific hot loop + shared ConnectionManager.
//!
//! The event loop lives HERE (Layer 2, quictun-net) — not in quictun-core.
//! This gives direct access to UDP socket, TUN device, GSO buffers for
//! zero-copy performance. ConnectionManager (quictun-core) provides all
//! shared connection lifecycle logic (promote, timeout, routing, ACKs).
//!
//! Architecture:
//!   quictun-core/manager.rs  — shared state (ConnectionManager)
//!   quictun-net/engine_v2.rs — platform-specific hot loop (THIS FILE)
//!   quictun-net/adapter.rs   — I/O setup, poll, route management

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use quictun_core::data_plane::{DataPlaneIo, DataPlaneIoBatch, OuterRecvBatch};
use quictun_core::manager::{
    ConnEntry, ConnectionManager, ManagerAction, PromoteResult,
};
use quictun_core::peer;
use quictun_core::quic_state::MultiQuicState;
use quictun_core::routing::RouteAction;
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;
#[allow(unused_imports)]
use tracing::{debug, info, warn};

use crate::adapter::{AdapterConfig, KernelAdapter};
use crate::engine::{EndpointSetup, NetConfig, RunResult};

/// Maximum QUIC packet buffer size.
const MAX_PACKET: usize = 2048;

/// Run the v2 engine (single-thread).
pub fn run_v2(
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
        info!(threads = config.threads, "v2 multi-core engine starting");
        return crate::multicore::run_multicore(
            &mut adapter,
            &mut multi_state,
            &config,
        );
    }

    info!("v2 engine starting");

    // ── Pre-allocated buffers ───────────────────────────────────────────
    let mut recv_batch = OuterRecvBatch::new(config.batch_size);
    let mut scratch = BytesMut::with_capacity(MAX_PACKET);
    let mut response_buf = vec![0u8; MAX_PACKET];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    // GSO buffer: encrypt TUN→UDP packets directly here (zero copy).
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; config.gso_max_segments * MAX_PACKET];

    // TUN write backpressure buffer (non-offload path).
    let mut tun_write_buf: std::collections::VecDeque<Vec<u8>> =
        std::collections::VecDeque::with_capacity(config.tun_write_buf_capacity);

    // GRO TX pool: batch TUN writes when offload is enabled (Linux).
    #[cfg(target_os = "linux")]
    let offload_enabled = config.offload;
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = crate::engine::GroTxPool::new();
    #[cfg(target_os = "linux")]
    let mut gro_table = if offload_enabled {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };

    // TUN offload buffers for recv_multiple (Linux, offload=true).
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

    // Timer state.
    let ack_interval = Duration::from_millis(config.ack_timer_ms as u64);
    let mut next_ack = Instant::now() + ack_interval;
    let stats_interval = Duration::from_secs(30);
    let mut next_stats = Instant::now() + stats_interval;

    let cid_len = config.cid_len;
    let peers = &config.peers;

    // ── Main poll loop ──────────────────────────────────────────────────
    loop {
        // Drain buffered TUN writes.
        while let Some(pkt) = tun_write_buf.front() {
            match adapter.tun().send(pkt) {
                Ok(_) => { tun_write_buf.pop_front(); }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => { tun_write_buf.pop_front(); }
            }
        }

        let timeout = manager.compute_poll_timeout(next_ack);
        let readiness = adapter.poll(timeout).context("poll failed")?;

        // ── Signal ──────────────────────────────────────────────────
        if readiness.signal {
            info!("received signal, shutting down");
            for entry in manager.values_mut() {
                if let Ok(r) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                    let _ = adapter.udp_socket().send_to(
                        &encrypt_buf[..r.len],
                        entry.remote_addr,
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
                    if n == 0 {
                        continue;
                    }
                    let from = recv_batch.addrs[i];
                    let first_byte = recv_batch.bufs[i][0];

                    if first_byte & 0x80 != 0 {
                        // Long header → handshake.
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

                    // Short header → CID routing.
                    if cid_len == 0 || n < 1 + cid_len {
                        continue;
                    }
                    let cid_key = cid_to_u64(&recv_batch.bufs[i][1..1 + cid_len]);

                    let close_received =
                        if let Some(entry) = manager.get_mut(&cid_key) {
                            match entry.conn.decrypt_packet_with_buf(
                                &mut recv_batch.bufs[i][..n],
                                &mut scratch,
                            ) {
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
                                                datagram[12], datagram[13],
                                                datagram[14], datagram[15],
                                            );
                                            if !peer::is_allowed_source(
                                                &entry.allowed_ips, src_ip,
                                            ) {
                                                continue;
                                            }
                                            // TUN write: GRO batching (Linux offload) or per-packet.
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
                        } else {
                            false
                        };

                    if close_received {
                        if let Some(entry) = manager.remove_connection(cid_key) {
                            info!(
                                tunnel_ip = %entry.tunnel_ip,
                                cid = %hex::encode(cid_key.to_ne_bytes()),
                                "peer sent CONNECTION_CLOSE, removed"
                            );
                            for net in &entry.allowed_ips {
                                let _ = adapter.remove_os_route(*net);
                            }
                        }
                    }
                }
            }
        }

        // Flush GRO TX pool (batched TUN writes from UDP RX path).
        #[cfg(target_os = "linux")]
        if offload_enabled && !gro_tx_pool.is_empty() {
            if let Some(ref mut gro) = gro_table {
                match adapter.tun().send_multiple(
                    gro,
                    gro_tx_pool.as_mut_slice(),
                    quictun_tun::VIRTIO_NET_HDR_LEN,
                ) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Fallback: buffer for next iteration.
                        for buf in gro_tx_pool.iter() {
                            tun_write_buf.push_back(buf.to_vec());
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "TUN send_multiple failed");
                    }
                }
                gro_tx_pool.reset();
            }
        }

        // ── TUN RX → encrypt → UDP send (GSO) ──────────────────────
        if readiness.inner {
            #[cfg(target_os = "linux")]
            if offload_enabled {
                handle_tun_rx_offload(
                    &mut manager,
                    adapter.tun(),
                    adapter.udp_socket(),
                    &mut gso_buf,
                    &mut tun_original_buf,
                    &mut tun_split_bufs,
                    &mut tun_split_sizes,
                );
            } else {
                handle_tun_rx_gso(
                    &mut manager,
                    adapter.tun(),
                    adapter.udp_socket(),
                    &mut gso_buf,
                );
            }

            #[cfg(not(target_os = "linux"))]
            handle_tun_rx_simple(
                &mut manager,
                adapter.tun(),
                adapter.udp_socket(),
                &mut encrypt_buf,
            );
        }

        // ── Timeouts ────────────────────────────────────────────────
        let actions = manager.sweep_timeouts();
        for action in actions {
            match action {
                ManagerAction::SendKeepalive { cid_key } => {
                    if let Some(entry) = manager.get_mut(&cid_key) {
                        if let Ok(r) = entry.conn.encrypt_datagram(&[], &mut encrypt_buf) {
                            let _ = adapter.udp_socket().send_to(
                                &encrypt_buf[..r.len], entry.remote_addr,
                            );
                            entry.last_tx = Instant::now();
                        }
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
                    if let Ok(r) = entry.conn.encrypt_ack(&mut encrypt_buf) {
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

            // Handshake timeouts.
            let hs_now = Instant::now();
            for hs in multi_state.handshakes.values_mut() {
                if let Some(t) = hs.connection.poll_timeout() {
                    if hs_now >= t {
                        hs.connection.handle_timeout(hs_now);
                    }
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
                            remote = %remote_addr,
                            tunnel_ip = %tunnel_ip,
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
                            conn: conn_state,
                            tunnel_ip,
                            allowed_ips,
                            remote_addr,
                            keepalive_interval,
                            last_tx: now_inst,
                            last_rx: now_inst,
                        });
                    }
                    PromoteResult::Rejected { mut conn_state, remote_addr, reason } => {
                        warn!(remote = %remote_addr, reason = ?reason, "handshake rejected");
                        let mut close_buf = vec![0u8; 128];
                        if let Ok(r) = conn_state.encrypt_connection_close(&mut close_buf) {
                            let _ = adapter.udp_socket().send_to(
                                &close_buf[..r.len], remote_addr,
                            );
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

// ── TUN RX → encrypt → UDP GSO (Linux, zero-copy) ──────────────────────

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
    let mut packet = [0u8; 1500];

    loop {
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 || packet[0] >> 4 != 4 {
                    continue;
                }

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

                // Flush if CID changed or batch full.
                if let Some(cur_cid) = current_cid {
                    if cur_cid != cid
                        || gso_count >= max_segs
                        || gso_pos + MAX_PACKET > gso_buf.len()
                    {
                        if gso_count > 0 {
                            flush_gso(udp, gso_buf, gso_pos, gso_segment_size,
                                      current_remote.expect("remote set"));
                            if let Some(entry) = manager.get_mut(&cur_cid) {
                                entry.last_tx = Instant::now();
                            }
                        }
                        gso_pos = 0;
                        gso_segment_size = 0;
                        gso_count = 0;
                    }
                }

                let entry = match manager.get_mut(&cid) {
                    Some(e) => e,
                    None => continue,
                };

                current_cid = Some(cid);
                current_remote = Some(entry.remote_addr);

                // Encrypt DIRECTLY into gso_buf — zero copy.
                match entry.conn.encrypt_datagram(&packet[..n], &mut gso_buf[gso_pos..]) {
                    Ok(result) => {
                        if gso_count == 0 {
                            gso_segment_size = result.len;
                            gso_pos += result.len;
                            gso_count += 1;
                        } else if result.len == gso_segment_size {
                            gso_pos += result.len;
                            gso_count += 1;
                        } else {
                            // Odd-sized: flush then start new batch.
                            if gso_count > 0 {
                                flush_gso(udp, gso_buf, gso_pos, gso_segment_size,
                                          entry.remote_addr);
                            }
                            gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                            gso_segment_size = result.len;
                            gso_pos = result.len;
                            gso_count = 1;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed");
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                debug!(error = %e, "TUN recv error");
                break;
            }
        }
    }

    // Flush remaining.
    if gso_count > 0 {
        flush_gso(udp, gso_buf, gso_pos, gso_segment_size,
                  current_remote.expect("remote set"));
        if let Some(cur_cid) = current_cid {
            if let Some(entry) = manager.get_mut(&cur_cid) {
                entry.last_tx = Instant::now();
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn flush_gso(
    udp: &std::net::UdpSocket,
    gso_buf: &[u8],
    gso_pos: usize,
    segment_size: usize,
    remote: SocketAddr,
) {
    // Same as old engine's flush_gso_sync — retry on WouldBlock.
    loop {
        let result = quictun_core::batch_io::send_gso(
            udp, &gso_buf[..gso_pos], segment_size as u16, remote,
        );
        match result {
            Ok(_) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::engine::wait_writable(udp.as_raw_fd());
            }
            Err(e) => {
                debug!(error = %e, "GSO send failed");
                return;
            }
        }
    }
}

// ── TUN RX → encrypt → UDP send (non-Linux, per-packet) ────────────────

#[cfg(not(target_os = "linux"))]
fn handle_tun_rx_simple(
    manager: &mut ConnectionManager<LocalConnectionState>,
    tun: &tun_rs::SyncDevice,
    udp: &std::net::UdpSocket,
    encrypt_buf: &mut [u8],
) {
    let mut packet = [0u8; 1500];

    loop {
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 || packet[0] >> 4 != 4 {
                    continue;
                }

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

                let entry = match manager.get_mut(&cid) {
                    Some(e) => e,
                    None => continue,
                };

                match entry.conn.encrypt_datagram(&packet[..n], encrypt_buf) {
                    Ok(result) => {
                        let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                        entry.last_tx = Instant::now();
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed");
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

// ── TUN write with backpressure buffer ───────────────────────────────────

fn tun_write_with_buf(
    tun: &tun_rs::SyncDevice,
    data: &[u8],
    buf: &mut std::collections::VecDeque<Vec<u8>>,
) {
    if !buf.is_empty() {
        if buf.len() < buf.capacity().max(256) {
            buf.push_back(data.to_vec());
        }
        return;
    }
    match tun.send(data) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            buf.push_back(data.to_vec());
        }
        Err(_) => {}
    }
}

// ── TUN RX with offload (recv_multiple → encrypt → GSO) ────────────────

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
            Err(e) => {
                debug!(error = %e, "TUN recv_multiple failed");
                break;
            }
        };

        // Collect valid payloads and group by CID (common case: all same).
        let mut batch_indices: SmallVec<[usize; 64]> = SmallVec::new();
        let mut batch_cid: Option<u64> = None;

        for i in 0..n_pkts {
            let pkt_len = split_sizes[i];
            if pkt_len < 20 || split_bufs[i][0] >> 4 != 4 {
                continue;
            }
            let packet = &split_bufs[i][..pkt_len];
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            let cid = match manager.lookup_route(dest_ip) {
                RouteAction::ForwardToPeer(cid) => cid,
                _ if manager.len() == 1 => {
                    *manager.keys().next().expect("single connection")
                }
                _ => continue,
            };

            // Flush if CID changed.
            if let Some(prev_cid) = batch_cid {
                if prev_cid != cid && !batch_indices.is_empty() {
                    flush_offload_batch(
                        udp, manager, gso_buf, split_bufs, split_sizes,
                        &batch_indices, prev_cid, max_segs,
                    );
                    batch_indices.clear();
                }
            }
            batch_cid = Some(cid);
            batch_indices.push(i);

            if batch_indices.len() >= max_segs {
                flush_offload_batch(
                    udp, manager, gso_buf, split_bufs, split_sizes,
                    &batch_indices, cid, max_segs,
                );
                batch_indices.clear();
            }
        }

        // Flush remaining.
        if let Some(cid) = batch_cid {
            if !batch_indices.is_empty() {
                flush_offload_batch(
                    udp, manager, gso_buf, split_bufs, split_sizes,
                    &batch_indices, cid, max_segs,
                );
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
    max_segs: usize,
) {
    let entry = match manager.get_mut(&cid) {
        Some(e) => e,
        None => return,
    };

    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;

    for &idx in indices {
        let pkt = &split_bufs[idx][..split_sizes[idx]];
        match entry.conn.encrypt_datagram(pkt, &mut gso_buf[gso_pos..]) {
            Ok(result) => {
                if gso_count == 0 {
                    gso_segment_size = result.len;
                    gso_pos += result.len;
                    gso_count += 1;
                } else if result.len == gso_segment_size {
                    gso_pos += result.len;
                    gso_count += 1;
                } else {
                    // Odd-sized: flush then start new batch.
                    if gso_count > 0 {
                        flush_gso(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr);
                    }
                    gso_buf.copy_within(gso_pos..gso_pos + result.len, 0);
                    gso_segment_size = result.len;
                    gso_pos = result.len;
                    gso_count = 1;
                }
            }
            Err(e) => {
                warn!(error = %e, "encrypt failed");
            }
        }
    }

    if gso_count > 0 {
        flush_gso(udp, gso_buf, gso_pos, gso_segment_size, entry.remote_addr);
        entry.last_tx = Instant::now();
    }
}

// ── Drain handshake transmits ───────────────────────────────────────────

fn drain_transmits(adapter: &KernelAdapter, state: &mut MultiQuicState) -> Result<()> {
    let now = Instant::now();
    let mut buf = Vec::with_capacity(4096);

    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut buf) else {
                break;
            };
            adapter.udp_socket()
                .send_to(&buf[..transmit.size], hs.remote_addr)
                .context("failed to send handshake transmit")?;
        }
    }
    Ok(())
}

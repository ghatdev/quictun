//! Shared engine event loop (Layer 3 + Layer 2 integration).
//!
//! Generic over `I: DataPlaneIo` — the same loop works with kernel TUN+UDP,
//! future DPDK, or io_uring adapters. Uses [`ConnectionManager`] for all
//! connection lifecycle decisions and [`LocalConnectionState`] for crypto.
//!
//! See docs/v2-design-seed.md §5 for the design rationale.

use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;
use smallvec::SmallVec;
use tracing::{debug, info, warn};

use crate::data_plane::{DataPlaneIo, DataPlaneIoBatch, OuterRecvBatch};
use crate::manager::{
    ConnEntry, ConnectionManager, ManagerAction, PromoteResult,
};
use crate::peer::{self, PeerConfig};
use crate::quic_state::MultiQuicState;
use crate::routing::RouteAction;

// ── Engine config ───────────────────────────────────────────────────────

/// Configuration for the engine event loop.
pub struct EngineLoopConfig {
    pub cid_len: usize,
    pub ack_timer_ms: u64,
    pub batch_size: usize,
    pub reconnect: bool,
    pub is_connector: bool,
}

/// Result of the engine run — tells the CLI whether to reconnect.
pub enum RunResult {
    Shutdown,
    ConnectionLost,
}

/// Maximum QUIC packet buffer size.
const MAX_PACKET: usize = 2048;
/// Handshake response buffer size.
const HANDSHAKE_BUF_SIZE: usize = 4096;

// ── Main engine loop ────────────────────────────────────────────────────

/// Run the v2 engine event loop.
///
/// Generic over `I: DataPlaneIo + DataPlaneIoBatch`. The adapter provides
/// all platform-specific I/O; the loop handles connection management,
/// crypto, and packet routing using [`ConnectionManager`].
pub fn run_engine<I: DataPlaneIo + DataPlaneIoBatch>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    multi_state: &mut MultiQuicState,
    peers: &[PeerConfig],
    config: &EngineLoopConfig,
) -> Result<RunResult> {
    // Pre-allocated buffers.
    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut scratch = BytesMut::with_capacity(MAX_PACKET);
    let mut recv_batch = OuterRecvBatch::new(config.batch_size);

    // Timer state.
    let ack_interval = Duration::from_millis(config.ack_timer_ms);
    let mut next_ack = Instant::now() + ack_interval;
    let stats_interval = Duration::from_secs(30);
    let mut next_stats = Instant::now() + stats_interval;

    // Main poll loop.
    loop {
        let timeout = manager.compute_poll_timeout(next_ack);
        let readiness = io.poll(timeout).context("poll failed")?;

        // ── Signal ──────────────────────────────────────────────────
        if readiness.signal {
            info!("received signal, shutting down");
            graceful_shutdown(io, manager, &mut encrypt_buf);
            return Ok(RunResult::Shutdown);
        }

        // ── Outer (UDP) RX ──────────────────────────────────────────
        if readiness.outer {
            handle_outer_rx(
                io,
                manager,
                multi_state,
                &mut recv_batch,
                &mut scratch,
                &mut response_buf,
                config.cid_len,
            )?;
        }

        // ── Inner (TUN) RX ──────────────────────────────────────────
        if readiness.inner {
            handle_inner_rx(io, manager, &mut encrypt_buf)?;
        }

        // ── Timeouts ────────────────────────────────────────────────
        handle_timeouts(io, manager, &mut encrypt_buf)?;

        // ── ACK timer ───────────────────────────────────────────────
        let now = Instant::now();
        if now >= next_ack {
            handle_acks(io, manager, &mut encrypt_buf);
            next_ack = now + ack_interval;
        }

        // ── Periodic stats ──────────────────────────────────────────
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
        drive_handshakes(
            io,
            manager,
            multi_state,
            peers,
            &mut response_buf,
        )?;

        // ── Connector: detect connection lost ───────────────────────
        if config.is_connector
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

// ── Outer (UDP) RX ──────────────────────────────────────────────────────

fn handle_outer_rx<I: DataPlaneIo + DataPlaneIoBatch>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    multi_state: &mut MultiQuicState,
    batch: &mut OuterRecvBatch,
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
    cid_len: usize,
) -> Result<()> {
    // Loop until no more packets (edge-triggered).
    loop {
        let count = match io.recv_outer_batch(batch) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("recv_outer_batch failed"),
        };

        for i in 0..count {
            let n = batch.lens[i];
            if n == 0 {
                continue;
            }
            let first_byte = batch.bufs[i][0];
            let from = batch.addrs[i];

            if first_byte & 0x80 != 0 {
                // Long header → handshake packet.
                let mut data = BytesMut::with_capacity(n);
                data.extend_from_slice(&batch.bufs[i][..n]);
                let now = Instant::now();
                let responses =
                    multi_state.handle_incoming(now, from, None, data, response_buf);
                for resp in &responses {
                    if let Err(e) = io.send_outer(resp, from) {
                        warn!(error = %e, "failed to send handshake response");
                    }
                }
                continue;
            }

            // Short header → CID routing.
            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&batch.bufs[i][1..1 + cid_len]);

            let close_received =
                if let Some(entry) = manager.get_mut(&cid_key) {
                    match entry
                        .conn
                        .decrypt_packet_with_buf(&mut batch.bufs[i][..n], scratch)
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
                                    if !peer::is_allowed_source(
                                        &entry.allowed_ips,
                                        src_ip,
                                    ) {
                                        debug!(
                                            src = %src_ip,
                                            "dropping: source IP not in allowed_ips"
                                        );
                                        continue;
                                    }
                                    if let Err(e) = io.send_inner(datagram) {
                                        if e.kind() != io::ErrorKind::WouldBlock {
                                            debug!(error = %e, "TUN write failed");
                                        }
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

            if close_received {
                if let Some(entry) = manager.remove_connection(cid_key) {
                    info!(
                        tunnel_ip = %entry.tunnel_ip,
                        cid = %hex::encode(cid_key.to_ne_bytes()),
                        "peer sent CONNECTION_CLOSE, removed"
                    );
                    // Remove OS routes for closed connection.
                    for net in &entry.allowed_ips {
                        let _ = io.remove_os_route(*net);
                    }
                }
            }
        }
    }
}

// ── Inner (TUN) RX ──────────────────────────────────────────────────────

fn handle_inner_rx<I: DataPlaneIo>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    let mut packet = [0u8; 1500];

    loop {
        match io.recv_inner(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }

                let dest_ip =
                    Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                // Route lookup with single-peer fallback.
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
                        if let Err(e) = io.send_outer(
                            &encrypt_buf[..result.len],
                            entry.remote_addr,
                        ) {
                            debug!(error = %e, "UDP send failed");
                        }
                        entry.last_tx = Instant::now();
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed, dropping");
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }
    Ok(())
}

// ── Timeouts ────────────────────────────────────────────────────────────

fn handle_timeouts<I: DataPlaneIo>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    let actions = manager.sweep_timeouts();
    if actions.is_empty() {
        return Ok(());
    }

    for action in actions {
        match action {
            ManagerAction::SendKeepalive { cid_key } => {
                if let Some(entry) = manager.get_mut(&cid_key) {
                    match entry.conn.encrypt_datagram(&[], encrypt_buf) {
                        Ok(result) => {
                            let _ = io.send_outer(
                                &encrypt_buf[..result.len],
                                entry.remote_addr,
                            );
                            entry.last_tx = Instant::now();
                            debug!(
                                pn = result.pn,
                                remote = %entry.remote_addr,
                                "sent keepalive"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "keepalive encrypt failed");
                        }
                    }
                }
            }
            ManagerAction::ConnectionRemoved {
                cid_key: _,
                tunnel_ip: _,
                ref allowed_ips,
                reason: _,
            } => {
                // Remove OS routes for removed connections.
                for net in allowed_ips {
                    let _ = io.remove_os_route(*net);
                }
            }
        }
    }
    Ok(())
}

// ── ACK timer ───────────────────────────────────────────────────────────

fn handle_acks<I: DataPlaneIo>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    encrypt_buf: &mut [u8],
) {
    let needing_ack: SmallVec<[u64; 8]> = manager.connections_needing_ack();

    for cid_key in needing_ack {
        if let Some(entry) = manager.get_mut(&cid_key) {
            match entry.conn.encrypt_ack(encrypt_buf) {
                Ok(result) => {
                    let _ = io.send_outer(
                        &encrypt_buf[..result.len],
                        entry.remote_addr,
                    );
                }
                Err(e) => {
                    warn!(error = %e, "ACK encrypt failed");
                }
            }
        }
    }
}

// ── Handshake driving ───────────────────────────────────────────────────

fn drive_handshakes<I: DataPlaneIo>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    multi_state: &mut MultiQuicState,
    peers: &[PeerConfig],
    response_buf: &mut Vec<u8>,
) -> Result<()> {
    if multi_state.handshakes.is_empty() {
        return Ok(());
    }

    // Drain transmits.
    drain_transmits(io, multi_state, response_buf)?;

    // Poll for completed/failed handshakes.
    let result = multi_state.poll_handshakes();

    // Drain transmits again after polling.
    drain_transmits(io, multi_state, response_buf)?;

    // Handle handshake timeouts.
    let now = Instant::now();
    for hs in multi_state.handshakes.values_mut() {
        if let Some(timeout) = hs.connection.poll_timeout() {
            if now >= timeout {
                hs.connection.handle_timeout(now);
            }
        }
    }

    // Promote completed handshakes.
    for ch in result.completed {
        let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        match manager.promote_handshake(&hs, conn_state, peers) {
            PromoteResult::Accepted {
                cid_key,
                cid_bytes,
                tunnel_ip,
                allowed_ips,
                remote_addr,
                keepalive_interval,
                conn_state,
                evicted,
            } => {
                let now_inst = Instant::now();

                info!(
                    remote = %remote_addr,
                    tunnel_ip = %tunnel_ip,
                    cid = %hex::encode(&cid_bytes),
                    active = manager.len() + 1,
                    "connection established"
                );

                // Add OS routes for new connection.
                for net in &allowed_ips {
                    if let Err(e) = io.add_os_route(*net) {
                        warn!(error = %e, dst = %net, "failed to add OS route");
                    }
                }

                // If an old connection was evicted, remove its OS routes.
                if let Some(ref evicted_info) = evicted {
                    for net in &evicted_info.allowed_ips {
                        let _ = io.remove_os_route(*net);
                    }
                }

                manager.insert_connection(
                    cid_key,
                    ConnEntry {
                        conn: conn_state,
                        tunnel_ip,
                        allowed_ips,
                        remote_addr,
                        keepalive_interval,
                        last_tx: now_inst,
                        last_rx: now_inst,
                    },
                );
            }
            PromoteResult::Rejected {
                mut conn_state,
                remote_addr,
                reason,
            } => {
                warn!(
                    remote = %remote_addr,
                    reason = ?reason,
                    "handshake rejected"
                );
                let mut close_buf = vec![0u8; 128];
                if let Ok(result) = conn_state.encrypt_connection_close(&mut close_buf)
                {
                    let _ = io.send_outer(&close_buf[..result.len], remote_addr);
                }
            }
        }
    }

    Ok(())
}

// ── Drain transmits from MultiQuicState ─────────────────────────────────

fn drain_transmits<I: DataPlaneIo>(
    io: &mut I,
    state: &mut MultiQuicState,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let now = Instant::now();

    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, buf) else {
                break;
            };
            io.send_outer(&buf[..transmit.size], hs.remote_addr)
                .context("failed to send handshake transmit")?;
        }
    }
    Ok(())
}

// ── Graceful shutdown ───────────────────────────────────────────────────

fn graceful_shutdown<I: DataPlaneIo>(
    io: &mut I,
    manager: &mut ConnectionManager<LocalConnectionState>,
    encrypt_buf: &mut [u8],
) {
    for entry in manager.values_mut() {
        if let Ok(result) = entry.conn.encrypt_connection_close(encrypt_buf) {
            let _ = io.send_outer(&encrypt_buf[..result.len], entry.remote_addr);
        }
    }
}

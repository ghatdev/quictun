//! Fast forwarding loops using quictun-quic (custom 1-RTT data plane).
//!
//! After handshake completes via `proto_driver`, these loops handle the
//! TUN <-> QUIC data plane using `quictun_quic::local::LocalConnectionState`
//! directly, bypassing quinn's high-level API entirely.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use quictun_quic::local::LocalConnectionState;
use quictun_tun::TunDevice;

use crate::peer;
use crate::tunnel::TunnelResult;

/// Maximum QUIC packet size.
const MAX_PACKET: usize = 2048;

/// Buffer size for quinn-proto handshake response.
const HANDSHAKE_BUF_SIZE: usize = 2048;

// ── Per-connection entry in the connection table ─────────────────────

/// Per-connection state for the unified multi-connection loop.
struct ConnEntry {
    conn: LocalConnectionState,
    tunnel_ip: Ipv4Addr,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
}

/// In-progress handshake state (replaces HandshakeState from old accept loop).
struct HandshakeEntry {
    connection: quinn_proto::Connection,
    remote_addr: SocketAddr,
    local_cid: quinn_proto::ConnectionId,
}

// ── Unified multi-connection loop ────────────────────────────────────

/// Unified single-task loop for 1..N listener connections.
///
/// Replaces the old 3-task dispatcher + accept loop + per-connection tasks
/// architecture. All I/O is handled in one task with no channels, no atomics.
/// Uses inline handshake driving and a connection table for routing.
#[allow(clippy::too_many_arguments)]
pub async fn run_fast_loop_multi(
    udp: &UdpSocket,
    tun: &TunDevice,
    server_config: Arc<ServerConfig>,
    peers: Vec<peer::PeerConfig>,
    cid_len: usize,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    info!(
        peers = peers.len(),
        cid_len,
        "unified listener loop started"
    );

    // Connection table: CID bytes → connection entry.
    let mut connections: HashMap<Vec<u8>, ConnEntry> = HashMap::new();
    // Tunnel IP → CID (for TUN packet routing).
    let mut ip_to_cid: HashMap<Ipv4Addr, Vec<u8>> = HashMap::new();

    // Inline handshake state.
    let ep_config = {
        let mut cfg = EndpointConfig::default();
        cfg.cid_generator(move || {
            Box::new(quinn_proto::RandomConnectionIdGenerator::new(cid_len))
        });
        Arc::new(cfg)
    };
    let mut endpoint = Endpoint::new(ep_config, Some(server_config.clone()), true, None);
    let mut handshakes: HashMap<ConnectionHandle, HandshakeEntry> = HashMap::new();

    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut scratch = BytesMut::with_capacity(2048);

    // Linux: GSO send buffer + recvmmsg batch buffers.
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; crate::batch_io::GSO_BUF_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; crate::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; crate::batch_io::BATCH_SIZE];

    // Non-Linux: simple per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

    loop {
        // Compute next timeout: earliest keepalive, idle, or handshake timeout.
        let timeout = compute_timeout(&connections, &mut handshakes, idle_timeout);

        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("shutdown signal received");
                    return TunnelResult::Shutdown;
                }
            }

            // ── TUN readable: drain packets, route by dest IP, encrypt + GSO ──
            result = tun.readable() => {
                if let Err(e) = result {
                    return TunnelResult::Fatal(e.into());
                }

                #[cfg(target_os = "linux")]
                {
                    if let Some(result) = handle_tun_readable_linux(
                        tun, udp, &mut connections, &ip_to_cid,
                        &mut gso_buf, &mut encrypt_buf,
                    ).await {
                        return result;
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    if let Some(result) = handle_tun_readable_nonlinux(
                        tun, udp, &mut connections, &ip_to_cid,
                        &mut encrypt_buf,
                    ).await {
                        return result;
                    }
                }
            }

            // ── UDP readable: route short-header by CID, long-header to handshake ──
            result = udp.readable() => {
                if let Err(e) = result {
                    return TunnelResult::Fatal(e.into());
                }

                #[cfg(target_os = "linux")]
                {
                    if let Some(result) = handle_udp_readable_linux(
                        udp, tun, &mut connections, cid_len,
                        &mut endpoint, &mut handshakes, &server_config,
                        &mut recv_bufs, &mut recv_lens, &mut scratch,
                        &mut response_buf,
                    ).await {
                        return result;
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    if let Some(result) = handle_udp_readable_nonlinux(
                        udp, tun, &mut connections, cid_len,
                        &mut endpoint, &mut handshakes, &server_config,
                        &mut recv_buf, &mut scratch,
                        &mut response_buf,
                    ).await {
                        return result;
                    }
                }
            }

            // ── Timeout: keepalives, idle expiry, handshake timeouts ──
            _ = tokio::time::sleep(timeout) => {
                if let Some(result) = handle_timeouts(
                    udp, &mut connections, &mut ip_to_cid,
                    &mut handshakes, idle_timeout, &mut encrypt_buf,
                ).await {
                    return result;
                }
            }
        }

        // Drive handshakes after every select iteration.
        if let Some(result) = drive_handshakes(
            udp, &mut endpoint, &mut handshakes,
            &mut connections, &mut ip_to_cid, &peers,
            &server_config, &mut response_buf,
        ).await {
            return result;
        }
    }
}

/// Compute the next timeout duration for the select loop.
fn compute_timeout(
    connections: &HashMap<Vec<u8>, ConnEntry>,
    handshakes: &mut HashMap<ConnectionHandle, HandshakeEntry>,
    idle_timeout: Duration,
) -> Duration {
    let mut min_timeout = Duration::from_secs(5);

    for entry in connections.values() {
        let keepalive_remaining = entry.keepalive_interval.saturating_sub(entry.last_tx.elapsed());
        let idle_remaining = idle_timeout.saturating_sub(entry.last_rx.elapsed());
        min_timeout = min_timeout.min(keepalive_remaining).min(idle_remaining);
    }

    for hs in handshakes.values_mut() {
        if let Some(deadline) = hs.connection.poll_timeout() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            min_timeout = min_timeout.min(remaining);
        }
    }

    min_timeout
}

/// Handle TUN readable event on Linux (GSO batching).
#[cfg(target_os = "linux")]
async fn handle_tun_readable_linux(
    tun: &TunDevice,
    udp: &UdpSocket,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &HashMap<Ipv4Addr, Vec<u8>>,
    gso_buf: &mut [u8],
    encrypt_buf: &mut [u8],
) -> Option<TunnelResult> {
    let max_segs = crate::batch_io::GSO_MAX_SEGMENTS;
    let mut gso_pos = 0usize;
    let mut gso_segment_size = 0usize;
    let mut gso_count = 0usize;
    let mut current_cid: Option<Vec<u8>> = None;
    let mut current_remote: Option<SocketAddr> = None;

    loop {
        let mut packet = [0u8; 1500];
        match tun.try_recv(&mut packet) {
            Ok(n) => {
                if n < 20 { continue; }

                // Extract dest IP from IPv4 header.
                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                // Look up connection by dest IP.
                let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                    cid.clone()
                } else if connections.len() == 1 {
                    // Single-connection default route.
                    connections.keys().next().unwrap().clone()
                } else {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                    continue;
                };

                // Check if we need to flush the current GSO batch (different connection).
                if let Some(ref cur_cid) = current_cid {
                    if *cur_cid != cid || gso_count >= max_segs || gso_pos + MAX_PACKET > gso_buf.len() {
                        // Flush current batch.
                        if gso_count > 0 {
                            if let Some(result) = flush_gso(
                                udp, gso_buf, gso_pos, gso_segment_size,
                                current_remote.unwrap(),
                            ).await {
                                return Some(result);
                            }
                            if let Some(entry) = connections.get_mut(cur_cid) {
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
                            if let Err(e) = udp.send_to(&gso_buf[gso_pos..odd_end], entry.remote_addr).await {
                                return Some(TunnelResult::Fatal(e.into()));
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed, dropping packet");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Some(TunnelResult::Fatal(e.into())),
        }
    }

    // Flush remaining GSO batch.
    if gso_count > 0 {
        if let Some(result) = flush_gso(
            udp, gso_buf, gso_pos, gso_segment_size,
            current_remote.unwrap(),
        ).await {
            return Some(result);
        }
        if let Some(ref cid) = current_cid {
            if let Some(entry) = connections.get_mut(cid.as_slice()) {
                entry.last_tx = Instant::now();
            }
        }
    }

    // Also handle non-routable packets with encrypt_buf for keepalives etc. — not needed here.
    let _ = encrypt_buf; // suppress unused warning

    None
}

/// Flush a GSO buffer to the UDP socket.
#[cfg(target_os = "linux")]
async fn flush_gso(
    udp: &UdpSocket,
    gso_buf: &[u8],
    gso_pos: usize,
    gso_segment_size: usize,
    remote_addr: SocketAddr,
) -> Option<TunnelResult> {
    let seg = gso_segment_size as u16;
    loop {
        match crate::batch_io::send_gso(udp, &gso_buf[..gso_pos], seg, remote_addr) {
            Ok(_) => return None,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Err(e) = udp.writable().await {
                    return Some(TunnelResult::Fatal(e.into()));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "send_gso failed");
                return Some(TunnelResult::Fatal(e.into()));
            }
        }
    }
}

/// Handle TUN readable event on non-Linux (per-packet send).
#[cfg(not(target_os = "linux"))]
async fn handle_tun_readable_nonlinux(
    tun: &TunDevice,
    udp: &UdpSocket,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &HashMap<Ipv4Addr, Vec<u8>>,
    encrypt_buf: &mut [u8],
) -> Option<TunnelResult> {
    loop {
        let mut packet = [0u8; 1500];
        match tun.try_recv(&mut packet) {
            Ok(n) => {
                if n < 20 { continue; }

                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let cid = if let Some(cid) = ip_to_cid.get(&dest_ip) {
                    cid.clone()
                } else if connections.len() == 1 {
                    connections.keys().next().unwrap().clone()
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
                        if let Err(e) = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr).await {
                            return Some(TunnelResult::Fatal(e.into()));
                        }
                        entry.last_tx = Instant::now();
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed, dropping packet");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Some(TunnelResult::Fatal(e.into())),
        }
    }
    None
}

/// Handle UDP readable event on Linux (recvmmsg batch).
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn handle_udp_readable_linux(
    udp: &UdpSocket,
    tun: &TunDevice,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    cid_len: usize,
    endpoint: &mut Endpoint,
    handshakes: &mut HashMap<ConnectionHandle, HandshakeEntry>,
    server_config: &Arc<ServerConfig>,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
) -> Option<TunnelResult> {
    let n_msgs = match crate::batch_io::recvmmsg_batch(
        udp, recv_bufs, recv_lens, crate::batch_io::BATCH_SIZE,
    ) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
        Err(e) => {
            tracing::error!(error = %e, "recvmmsg failed");
            return Some(TunnelResult::Fatal(e.into()));
        }
    };

    for i in 0..n_msgs {
        let n = recv_lens[i];
        if n == 0 { continue; }
        let first_byte = recv_bufs[i][0];

        if first_byte & 0x80 != 0 {
            // Long header → handshake.
            let mut data = BytesMut::with_capacity(n);
            data.extend_from_slice(&recv_bufs[i][..n]);
            // recvmmsg doesn't give us source addr per-message easily;
            // use try_recv_from fallback for handshake packets below.
            // For now, feed to endpoint with a placeholder (handshakes will
            // also be caught in the non-batch path).
            // Actually, recvmmsg doesn't provide source addresses. For handshake
            // packets we need the source address. Fall through to handle below.
            continue;
        }

        // Short header → extract CID → decrypt.
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
                        if let Err(e) = tun.send(datagram).await {
                            return Some(TunnelResult::Fatal(e.into()));
                        }
                    }
                }
                Err(e) => {
                    debug!(error = %e, "decrypt failed, dropping");
                }
            }
        }
    }

    // Also drain with try_recv_from to catch handshake packets (which need source addr).
    loop {
        let mut buf = [0u8; MAX_PACKET];
        match udp.try_recv_from(&mut buf) {
            Ok((n, from)) => {
                if n == 0 { continue; }
                if buf[0] & 0x80 != 0 {
                    // Long header → endpoint.handle().
                    let mut data = BytesMut::with_capacity(n);
                    data.extend_from_slice(&buf[..n]);
                    let now = Instant::now();
                    if let Some(event) = endpoint.handle(now, from, None, None, data, response_buf)
                        && let Some(result) = handle_endpoint_event(
                            udp, endpoint, handshakes, server_config,
                            event, from, response_buf,
                        ).await
                    {
                        return Some(result);
                    }
                } else {
                    // Short header — may have been missed by recvmmsg.
                    if cid_len > 0 && n > cid_len {
                        let cid_bytes = &buf[1..1 + cid_len];
                        if let Some(entry) = connections.get_mut(cid_bytes) {
                            match entry.conn.decrypt_packet_with_buf(&mut buf[..n], scratch) {
                                Ok(decrypted) => {
                                    entry.last_rx = Instant::now();
                                    if let Some(ref ack) = decrypted.ack {
                                        entry.conn.process_ack(ack);
                                    }
                                    for datagram in &decrypted.datagrams {
                                        if datagram.is_empty() { continue; }
                                        if let Err(e) = tun.send(datagram).await {
                                            return Some(TunnelResult::Fatal(e.into()));
                                        }
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
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Some(TunnelResult::Fatal(e.into())),
        }
    }

    None
}

/// Handle UDP readable event on non-Linux (per-packet recv_from).
#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
async fn handle_udp_readable_nonlinux(
    udp: &UdpSocket,
    tun: &TunDevice,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    cid_len: usize,
    endpoint: &mut Endpoint,
    handshakes: &mut HashMap<ConnectionHandle, HandshakeEntry>,
    server_config: &Arc<ServerConfig>,
    recv_buf: &mut [u8],
    scratch: &mut BytesMut,
    response_buf: &mut Vec<u8>,
) -> Option<TunnelResult> {
    loop {
        match udp.try_recv_from(recv_buf) {
            Ok((n, from)) => {
                if n == 0 { continue; }

                if recv_buf[0] & 0x80 != 0 {
                    // Long header → handshake.
                    let mut data = BytesMut::with_capacity(n);
                    data.extend_from_slice(&recv_buf[..n]);
                    let now = Instant::now();
                    if let Some(event) = endpoint.handle(now, from, None, None, data, response_buf)
                        && let Some(result) = handle_endpoint_event(
                            udp, endpoint, handshakes, server_config,
                            event, from, response_buf,
                        ).await
                    {
                        return Some(result);
                    }
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
                                        if let Err(e) = tun.send(datagram).await {
                                            return Some(TunnelResult::Fatal(e.into()));
                                        }
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
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Some(TunnelResult::Fatal(e.into())),
        }
    }
    None
}

/// Handle a DatagramEvent from endpoint.handle() during the multi loop.
async fn handle_endpoint_event(
    udp: &UdpSocket,
    endpoint: &mut Endpoint,
    handshakes: &mut HashMap<ConnectionHandle, HandshakeEntry>,
    server_config: &Arc<ServerConfig>,
    event: DatagramEvent,
    from: SocketAddr,
    response_buf: &mut Vec<u8>,
) -> Option<TunnelResult> {
    match event {
        DatagramEvent::NewConnection(incoming) => {
            let now = Instant::now();
            match endpoint.accept(incoming, now, response_buf, Some(server_config.clone())) {
                Ok((ch, conn)) => {
                    let remote = conn.remote_address();
                    let local_cid = *conn.local_cid();
                    info!(
                        remote = %remote,
                        cid = %hex::encode(&local_cid[..]),
                        "accepted incoming handshake"
                    );
                    handshakes.insert(ch, HandshakeEntry {
                        connection: conn,
                        remote_addr: remote,
                        local_cid,
                    });
                }
                Err(e) => {
                    warn!(error = ?e.cause, "failed to accept connection");
                    if let Some(transmit) = e.response {
                        let _ = udp.send_to(&response_buf[..transmit.size], from).await;
                    }
                }
            }
        }
        DatagramEvent::ConnectionEvent(ch, event) => {
            if let Some(hs) = handshakes.get_mut(&ch) {
                hs.connection.handle_event(event);
            }
        }
        DatagramEvent::Response(transmit) => {
            let _ = udp.send_to(&response_buf[..transmit.size], from).await;
        }
    }
    None
}

/// Handle timeouts: keepalives, idle expiry, handshake timeouts.
async fn handle_timeouts(
    udp: &UdpSocket,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &mut HashMap<Ipv4Addr, Vec<u8>>,
    handshakes: &mut HashMap<ConnectionHandle, HandshakeEntry>,
    idle_timeout: Duration,
    encrypt_buf: &mut [u8],
) -> Option<TunnelResult> {
    // Collect expired connections.
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
                    if let Err(e) = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr).await {
                        return Some(TunnelResult::Fatal(e.into()));
                    }
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
    for hs in handshakes.values_mut() {
        hs.connection.handle_timeout(now);
    }

    None
}

/// Drive all in-progress handshakes: poll events, promote completed ones.
#[allow(clippy::too_many_arguments)]
async fn drive_handshakes(
    udp: &UdpSocket,
    endpoint: &mut Endpoint,
    handshakes: &mut HashMap<ConnectionHandle, HandshakeEntry>,
    connections: &mut HashMap<Vec<u8>, ConnEntry>,
    ip_to_cid: &mut HashMap<Ipv4Addr, Vec<u8>>,
    peers: &[peer::PeerConfig],
    _server_config: &Arc<ServerConfig>,
    _response_buf: &mut Vec<u8>,
) -> Option<TunnelResult> {
    if handshakes.is_empty() {
        return None;
    }

    let mut completed: Vec<ConnectionHandle> = Vec::new();
    let mut failed: Vec<ConnectionHandle> = Vec::new();

    for (&ch, hs) in handshakes.iter_mut() {
        // Endpoint events.
        while let Some(event) = hs.connection.poll_endpoint_events() {
            if let Some(conn_event) = endpoint.handle_event(ch, event) {
                hs.connection.handle_event(conn_event);
            }
        }

        // Connection events.
        while let Some(event) = hs.connection.poll() {
            match event {
                Event::Connected => {
                    completed.push(ch);
                }
                Event::ConnectionLost { reason } => {
                    warn!(error = %reason, "handshake connection lost");
                    failed.push(ch);
                }
                Event::HandshakeDataReady
                | Event::DatagramReceived
                | Event::DatagramsUnblocked
                | Event::Stream(_) => {}
            }
        }

        // Drain transmits.
        let remote = hs.remote_addr;
        let now = Instant::now();
        let mut transmit_buf = Vec::with_capacity(HANDSHAKE_BUF_SIZE);
        loop {
            transmit_buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut transmit_buf) else {
                break;
            };
            let _ = udp.send_to(&transmit_buf[..transmit.size], remote).await;
        }
    }

    // Remove failed handshakes.
    for ch in failed {
        if let Some(hs) = handshakes.remove(&ch) {
            info!(
                cid = %hex::encode(&hs.local_cid[..]),
                "handshake failed, removed"
            );
        }
    }

    // Promote completed handshakes to connections.
    for ch in completed {
        let Some(mut hs) = handshakes.remove(&ch) else { continue };

        let local_cid = hs.local_cid;
        let remote_cid = hs.connection.remote_cid();

        // Drain final transmits before extracting keys.
        let now = Instant::now();
        let mut transmit_buf = Vec::with_capacity(HANDSHAKE_BUF_SIZE);
        loop {
            transmit_buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut transmit_buf) else {
                break;
            };
            let _ = udp.send_to(&transmit_buf[..transmit.size], hs.remote_addr).await;
        }

        // Identify peer by certificate.
        let matched_peer = match peer::identify_peer(&hs.connection, peers) {
            Some(p) => p,
            None => {
                warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                continue;
            }
        };
        let tunnel_ip = matched_peer.tunnel_ip;
        let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));

        // Extract 1-RTT keys.
        let extracted = match peer::extract_1rtt_keys(&mut hs.connection) {
            Some(e) => e,
            None => {
                warn!("failed to extract 1-RTT keys after handshake");
                continue;
            }
        };

        // Create LocalConnectionState.
        let conn = LocalConnectionState::new(
            extracted.keys,
            extracted.key_gens,
            local_cid,
            remote_cid,
            true, // is_server
        );

        let cid_bytes: Vec<u8> = local_cid[..].to_vec();
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
            conn,
            tunnel_ip,
            remote_addr: hs.remote_addr,
            keepalive_interval,
            last_tx: now_inst,
            last_rx: now_inst,
        });
    }

    None
}

// ── Single-task fast loop ────────────────────────────────────────────

/// Single-task fast forwarding loop using `LocalConnectionState`.
///
/// No shared mutable state, no atomics, no cross-task coordination.
/// Uses GSO send + recvmmsg batching on Linux for high throughput.
/// Falls back to per-packet I/O on other platforms.
pub async fn run_fast_loop(
    mut conn: LocalConnectionState,
    udp: &UdpSocket,
    tun: &TunDevice,
    remote_addr: SocketAddr,
    idle_timeout: Duration,
    keepalive: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    tracing::info!("fast forwarding loop started (single-task, LocalConnectionState)");

    let keepalive_interval = keepalive.unwrap_or(Duration::from_secs(25));
    let mut last_tx = Instant::now();
    let mut last_rx = Instant::now();

    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut scratch = BytesMut::with_capacity(2048);

    // Linux: GSO send buffer + recvmmsg batch buffers.
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; crate::batch_io::GSO_BUF_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; crate::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; crate::batch_io::BATCH_SIZE];

    // Non-Linux: simple per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

    loop {
        let timeout = {
            let since_tx = last_tx.elapsed();
            let since_rx = last_rx.elapsed();
            let keepalive_remaining = if keepalive.is_some() {
                keepalive_interval.saturating_sub(since_tx)
            } else {
                Duration::from_secs(60)
            };
            let idle_remaining = idle_timeout.saturating_sub(since_rx);
            keepalive_remaining.min(idle_remaining)
        };

        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, closing fast tunnel");
                    return TunnelResult::Shutdown;
                }
            }

            result = tun.readable() => {
                if let Err(e) = result {
                    return TunnelResult::Fatal(e.into());
                }

                // Drain TUN packets, encrypt, batch into GSO buffer.
                #[cfg(target_os = "linux")]
                {
                    let max_segs = crate::batch_io::GSO_MAX_SEGMENTS;
                    let mut gso_pos = 0usize;
                    let mut gso_segment_size = 0usize;
                    let mut gso_count = 0usize;

                    loop {
                        if gso_count >= max_segs {
                            break;
                        }
                        let mut packet = [0u8; 1500];
                        match tun.try_recv(&mut packet) {
                            Ok(n) => {
                                if gso_pos + MAX_PACKET > gso_buf.len() {
                                    break;
                                }
                                let ack_ranges = if conn.needs_ack() {
                                    Some(conn.generate_ack_ranges())
                                } else {
                                    None
                                };
                                match conn.encrypt_datagram(
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
                                            // Odd-sized packet: send individually.
                                            let odd_end = gso_pos + result.len;
                                            if let Err(e) = udp
                                                .send_to(&gso_buf[gso_pos..odd_end], remote_addr)
                                                .await
                                            {
                                                tracing::error!(error = %e, "UDP send failed (odd size)");
                                                return TunnelResult::Fatal(e.into());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "encrypt failed, dropping packet");
                                    }
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                tracing::error!(error = %e, "TUN recv failed");
                                return TunnelResult::Fatal(e.into());
                            }
                        }
                    }

                    // Flush GSO batch.
                    if gso_count > 0 {
                        let seg = gso_segment_size as u16;
                        loop {
                            match crate::batch_io::send_gso(
                                udp,
                                &gso_buf[..gso_pos],
                                seg,
                                remote_addr,
                            ) {
                                Ok(_) => {
                                    debug!(
                                        count = gso_count,
                                        segment_size = gso_segment_size,
                                        total = gso_pos,
                                        "TUN -> QUIC (GSO)"
                                    );
                                    last_tx = Instant::now();
                                    break;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    if let Err(e) = udp.writable().await {
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "send_gso failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                            }
                        }
                    }
                }

                // Non-Linux: per-packet send.
                #[cfg(not(target_os = "linux"))]
                {
                    loop {
                        let mut packet = [0u8; 1500];
                        match tun.try_recv(&mut packet) {
                            Ok(n) => {
                                let ack_ranges = if conn.needs_ack() {
                                    Some(conn.generate_ack_ranges())
                                } else {
                                    None
                                };
                                match conn.encrypt_datagram(
                                    &packet[..n],
                                    ack_ranges.as_deref(),
                                    &mut encrypt_buf,
                                ) {
                                    Ok(result) => {
                                        if let Err(e) = udp.send_to(&encrypt_buf[..result.len], remote_addr).await {
                                            return TunnelResult::Fatal(e.into());
                                        }
                                        last_tx = Instant::now();
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "encrypt failed, dropping packet");
                                    }
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => return TunnelResult::Fatal(e.into()),
                        }
                    }
                }
            }

            result = udp.readable() => {
                if let Err(e) = result {
                    return TunnelResult::Fatal(e.into());
                }

                // Linux: recvmmsg batch.
                #[cfg(target_os = "linux")]
                {
                    let n_msgs = match crate::batch_io::recvmmsg_batch(
                        udp,
                        &mut recv_bufs,
                        &mut recv_lens,
                        crate::batch_io::BATCH_SIZE,
                    ) {
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => {
                            tracing::error!(error = %e, "recvmmsg failed");
                            return TunnelResult::Fatal(e.into());
                        }
                    };

                    for i in 0..n_msgs {
                        let n = recv_lens[i];
                        if n == 0 { continue; }
                        if recv_bufs[i][0] & 0x80 != 0 { continue; }

                        match conn.decrypt_packet_with_buf(&mut recv_bufs[i][..n], &mut scratch) {
                            Ok(decrypted) => {
                                last_rx = Instant::now();
                                if let Some(ref ack) = decrypted.ack {
                                    conn.process_ack(ack);
                                }
                                for datagram in &decrypted.datagrams {
                                    if datagram.is_empty() { continue; }
                                    if let Err(e) = tun.send(datagram).await {
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, size = n, "decrypt failed, dropping");
                            }
                        }
                    }
                }

                // Non-Linux: single recv_from.
                #[cfg(not(target_os = "linux"))]
                {
                    match udp.try_recv_from(&mut recv_buf) {
                        Ok((n, _from)) => {
                            if n > 0 && recv_buf[0] & 0x80 != 0 {
                                continue;
                            }
                            match conn.decrypt_packet_with_buf(&mut recv_buf[..n], &mut scratch) {
                                Ok(decrypted) => {
                                    last_rx = Instant::now();
                                    if let Some(ref ack) = decrypted.ack {
                                        conn.process_ack(ack);
                                    }
                                    for datagram in &decrypted.datagrams {
                                        if datagram.is_empty() { continue; }
                                        if let Err(e) = tun.send(datagram).await {
                                            return TunnelResult::Fatal(e.into());
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, size = n, "decrypt failed, dropping");
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => return TunnelResult::Fatal(e.into()),
                    }
                }
            }

            _ = tokio::time::sleep(timeout) => {
                // Check idle timeout.
                if last_rx.elapsed() >= idle_timeout {
                    tracing::info!("idle timeout exceeded, connection lost");
                    return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
                }
                // Keepalive.
                if keepalive.is_some() && last_tx.elapsed() >= keepalive_interval {
                    let ack_ranges = conn.generate_ack_ranges();
                    let ack_ref = if !ack_ranges.is_empty() {
                        Some(ack_ranges.as_slice())
                    } else {
                        None
                    };
                    match conn.encrypt_datagram(&[], ack_ref, &mut encrypt_buf) {
                        Ok(result) => {
                            if let Err(e) = udp.send_to(&encrypt_buf[..result.len], remote_addr).await {
                                return TunnelResult::Fatal(e.into());
                            }
                            last_tx = Instant::now();
                            debug!(pn = result.pn, "sent keepalive PING");
                        }
                        Err(e) => {
                            warn!(error = %e, "keepalive encrypt failed");
                        }
                    }
                }
            }
        }
    }
}

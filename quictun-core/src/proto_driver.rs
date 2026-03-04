//! Async quinn-proto handshake driver for tokio.
//!
//! Drives quinn-proto's `Endpoint` + `Connection` state machine over a tokio
//! `UdpSocket` until `Event::Connected` fires, then extracts 1-RTT keys and
//! returns a `quictun_quic::ConnectionState` for the fast data plane.
//!
//! This is the async equivalent of `quictun-dpdk/src/shared.rs`, which does
//! the same thing in a synchronous polling loop.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig, crypto};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{info, warn};

/// Maximum QUIC packet buffer size.
const BUF_SIZE: usize = 2048;

/// Setup for the handshake: connector or listener.
pub enum HandshakeSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: quinn_proto::ClientConfig,
    },
    Listener {
        server_config: Arc<ServerConfig>,
    },
}

/// Result of a successful handshake (thread-safe ConnectionState).
pub struct HandshakeResult {
    /// quictun-quic connection state with extracted 1-RTT keys.
    pub connection_state: Arc<quictun_quic::ConnectionState>,
    /// Remote peer address.
    pub remote_addr: SocketAddr,
}

/// Result of a successful handshake (single-owner LocalConnectionState).
pub struct LocalHandshakeResult {
    /// quictun-quic local connection state (non-atomic, for single-task loop).
    pub connection_state: quictun_quic::local::LocalConnectionState,
    /// Remote peer address.
    pub remote_addr: SocketAddr,
}

/// What happened in one iteration of the handshake loop.
enum LoopAction {
    /// Received a UDP packet.
    RecvPacket { n: usize, from: SocketAddr },
    /// Timer fired.
    Timeout,
    /// Shutdown requested.
    Shutdown,
}

/// Run the quinn-proto handshake, returning a thread-safe `ConnectionState`.
pub async fn run_handshake(
    udp: &UdpSocket,
    setup: &HandshakeSetup,
    shutdown: &watch::Receiver<bool>,
) -> Result<HandshakeResult> {
    let raw = run_handshake_raw(udp, setup, shutdown).await?;
    let connection_state = quictun_quic::ConnectionState::new(
        raw.keys,
        raw.key_gens,
        raw.local_cid,
        raw.remote_cid,
        raw.is_server,
    );
    Ok(HandshakeResult {
        connection_state,
        remote_addr: raw.remote_addr,
    })
}

/// Core handshake loop — returns raw keys for the caller to wrap.
async fn run_handshake_raw(
    udp: &UdpSocket,
    setup: &HandshakeSetup,
    shutdown: &watch::Receiver<bool>,
) -> Result<RawHandshakeKeys> {
    let local_addr = udp.local_addr().context("failed to get local address")?;

    let server_config = match setup {
        HandshakeSetup::Listener { server_config } => Some(server_config.clone()),
        HandshakeSetup::Connector { .. } => None,
    };

    let ep_config = Arc::new(EndpointConfig::default());
    let mut endpoint = Endpoint::new(ep_config, server_config.clone(), true, None);
    let mut connection: Option<quinn_proto::Connection> = None;
    let mut ch: Option<ConnectionHandle> = None;
    let mut remote_addr: SocketAddr = match setup {
        HandshakeSetup::Connector { remote_addr, .. } => *remote_addr,
        HandshakeSetup::Listener { .. } => "0.0.0.0:0".parse().unwrap(),
    };

    if let HandshakeSetup::Connector {
        remote_addr: addr,
        client_config,
    } = setup
    {
        let now = Instant::now();
        let (new_ch, new_conn) = endpoint
            .connect(now, client_config.clone(), *addr, "quictun")
            .context("failed to initiate QUIC connection")?;
        ch = Some(new_ch);
        connection = Some(new_conn);
        remote_addr = *addr;
        info!(remote = %addr, "QUIC connection initiated (handshake)");
        drain_transmits(udp, connection.as_mut().unwrap(), remote_addr).await?;
    } else {
        info!(address = %local_addr, "listening for incoming connection (handshake)");
    }

    let mut recv_buf = vec![0u8; BUF_SIZE];
    let mut response_buf = vec![0u8; BUF_SIZE];
    let mut deadline = Instant::now() + Duration::from_secs(1);
    let mut shutdown_rx = shutdown.clone();

    loop {
        if *shutdown.borrow() {
            anyhow::bail!("shutdown during handshake");
        }

        let timeout_dur = deadline.saturating_duration_since(Instant::now());

        let action = tokio::select! {
            result = udp.recv_from(&mut recv_buf) => {
                let (n, from) = result.context("UDP recv failed during handshake")?;
                LoopAction::RecvPacket { n, from }
            }
            _ = tokio::time::sleep(timeout_dur) => {
                LoopAction::Timeout
            }
            _ = shutdown_rx.changed() => {
                LoopAction::Shutdown
            }
        };

        match action {
            LoopAction::RecvPacket { n, from } => {
                let now = Instant::now();
                let mut data = BytesMut::new();
                data.extend_from_slice(&recv_buf[..n]);

                if let Some(event) =
                    endpoint.handle(now, from, None, None, data, &mut response_buf)
                {
                    handle_datagram_event(
                        &mut endpoint,
                        &mut connection,
                        &mut ch,
                        &mut remote_addr,
                        event,
                        &mut response_buf,
                        udp,
                        server_config.as_ref(),
                    )
                    .await?;
                }
            }
            LoopAction::Timeout => {
                if let Some(conn) = connection.as_mut() {
                    conn.handle_timeout(Instant::now());
                }
            }
            LoopAction::Shutdown => {
                if *shutdown.borrow() {
                    anyhow::bail!("shutdown during handshake");
                }
            }
        }

        if let Some(conn) = connection.as_mut() {
            let conn_ch = ch.expect("connection exists but no ConnectionHandle");

            while let Some(event) = conn.poll_endpoint_events() {
                if let Some(conn_event) = endpoint.handle_event(conn_ch, event) {
                    conn.handle_event(conn_event);
                }
            }

            while let Some(event) = conn.poll() {
                match event {
                    Event::Connected => {
                        info!("quic: handshake complete");
                        let is_server = server_config.is_some();
                        let raw = extract_keys(conn, is_server, remote_addr)?;
                        drain_transmits(udp, conn, remote_addr).await?;
                        return Ok(raw);
                    }
                    Event::ConnectionLost { reason } => {
                        anyhow::bail!("connection lost during handshake: {reason}");
                    }
                    Event::HandshakeDataReady
                    | Event::DatagramReceived
                    | Event::DatagramsUnblocked
                    | Event::Stream(_) => {}
                }
            }

            drain_transmits(udp, conn, remote_addr).await?;
            deadline = conn
                .poll_timeout()
                .unwrap_or(Instant::now() + Duration::from_secs(1));
        }
    }
}

/// Handle a DatagramEvent from endpoint.handle().
#[allow(clippy::too_many_arguments)]
async fn handle_datagram_event(
    endpoint: &mut Endpoint,
    connection: &mut Option<quinn_proto::Connection>,
    ch: &mut Option<ConnectionHandle>,
    remote_addr: &mut SocketAddr,
    event: DatagramEvent,
    response_buf: &mut Vec<u8>,
    udp: &UdpSocket,
    server_config: Option<&Arc<ServerConfig>>,
) -> Result<()> {
    match event {
        DatagramEvent::ConnectionEvent(event_ch, event) => {
            if let Some(conn) = connection.as_mut()
                && *ch == Some(event_ch)
            {
                conn.handle_event(event);
            }
        }
        DatagramEvent::NewConnection(incoming) => {
            if connection.is_none() {
                let now = Instant::now();
                match endpoint.accept(incoming, now, response_buf, server_config.cloned()) {
                    Ok((new_ch, new_conn)) => {
                        *remote_addr = new_conn.remote_address();
                        info!(remote = %remote_addr, "quic: accepted incoming connection");
                        *ch = Some(new_ch);
                        *connection = Some(new_conn);
                    }
                    Err(e) => {
                        warn!(error = ?e.cause, "quic: failed to accept connection");
                        if let Some(transmit) = e.response {
                            let len = transmit.size;
                            udp.send_to(&response_buf[..len], *remote_addr).await?;
                        }
                    }
                }
            } else {
                endpoint.ignore(incoming);
            }
        }
        DatagramEvent::Response(transmit) => {
            let len = transmit.size;
            udp.send_to(&response_buf[..len], *remote_addr).await?;
        }
    }
    Ok(())
}

/// Raw keys extracted from a quinn-proto handshake.
struct RawHandshakeKeys {
    keys: crypto::Keys,
    key_gens: VecDeque<crypto::KeyPair<Box<dyn quinn_proto::crypto::PacketKey>>>,
    local_cid: quinn_proto::ConnectionId,
    remote_cid: quinn_proto::ConnectionId,
    is_server: bool,
    remote_addr: SocketAddr,
}

/// Extract 1-RTT keys and pre-compute key generations from a connected quinn-proto Connection.
fn extract_keys(
    conn: &mut quinn_proto::Connection,
    is_server: bool,
    remote_addr: SocketAddr,
) -> Result<RawHandshakeKeys> {
    let keys = conn
        .take_1rtt_keys()
        .context("Connected but no 1-RTT keys available")?;

    let local_cid = *conn.local_cid();
    let remote_cid = conn.remote_cid();

    let mut key_gens = VecDeque::new();
    if let Some(first) = conn.take_next_1rtt_keys() {
        key_gens.push_back(first);
    }
    for _ in 0..999 {
        if let Some(kp) = conn.produce_next_1rtt_keys() {
            key_gens.push_back(kp);
        } else {
            break;
        }
    }
    info!(
        key_generations = key_gens.len(),
        "pre-computed key update generations"
    );

    Ok(RawHandshakeKeys {
        keys,
        key_gens,
        local_cid,
        remote_cid,
        is_server,
        remote_addr,
    })
}

/// Run the quinn-proto handshake, returning a `LocalConnectionState`.
///
/// Same handshake as `run_handshake`, but returns a single-owner state
/// for the single-task forwarding loop.
pub async fn run_handshake_local(
    udp: &UdpSocket,
    setup: &HandshakeSetup,
    shutdown: &watch::Receiver<bool>,
) -> Result<LocalHandshakeResult> {
    let raw = run_handshake_raw(udp, setup, shutdown).await?;
    let connection_state = quictun_quic::local::LocalConnectionState::new(
        raw.keys,
        raw.key_gens,
        raw.local_cid,
        raw.remote_cid,
        raw.is_server,
    );
    Ok(LocalHandshakeResult {
        connection_state,
        remote_addr: raw.remote_addr,
    })
}

/// Resolved peer info for multi-client accept loop.
pub struct ResolvedPeer {
    /// Peer's public key SPKI DER (for identity matching after handshake).
    pub spki_der: Vec<u8>,
    /// Peer's tunnel IP (first IP from `allowed_ips`).
    pub tunnel_ip: std::net::Ipv4Addr,
    /// Keepalive interval.
    pub keepalive: Option<std::time::Duration>,
}

/// Multi-client accept loop for the listener `--fast` data plane.
///
/// Drives a quinn-proto `Endpoint` that accepts N concurrent handshakes.
/// Each completed handshake spawns a per-connection task with its own
/// `LocalConnectionState`. The shared `DispatchTable` routes packets.
#[allow(clippy::too_many_arguments)]
pub async fn run_accept_loop(
    udp: std::sync::Arc<tokio::net::UdpSocket>,
    server_config: std::sync::Arc<ServerConfig>,
    table: std::sync::Arc<std::sync::RwLock<crate::dispatcher::DispatchTable>>,
    tun: std::sync::Arc<quictun_tun::TunDevice>,
    peers: Vec<ResolvedPeer>,
    cid_len: usize,
    idle_timeout: std::time::Duration,
    mut handshake_rx: tokio::sync::mpsc::Receiver<(BytesMut, std::net::SocketAddr)>,
    mut cleanup_rx: tokio::sync::mpsc::Receiver<(quinn_proto::ConnectionId, std::net::Ipv4Addr)>,
    cleanup_tx: tokio::sync::mpsc::Sender<(quinn_proto::ConnectionId, std::net::Ipv4Addr)>,
    mut shutdown: watch::Receiver<bool>,
) -> crate::tunnel::TunnelResult {
    use std::collections::HashMap;

    let ep_config = {
        let mut cfg = EndpointConfig::default();
        cfg.cid_generator(move || Box::new(quinn_proto::RandomConnectionIdGenerator::new(cid_len)));
        std::sync::Arc::new(cfg)
    };
    let mut endpoint = Endpoint::new(ep_config, Some(server_config.clone()), true, None);

    // In-progress handshakes: quinn ConnectionHandle → state.
    struct HandshakeState {
        connection: quinn_proto::Connection,
        remote_addr: std::net::SocketAddr,
    }
    let mut handshakes: HashMap<ConnectionHandle, HandshakeState> = HashMap::new();

    let mut response_buf = vec![0u8; BUF_SIZE];

    info!("accept loop started (multi-client)");

    loop {
        // Next timeout: earliest handshake timeout.
        let next_timeout = handshakes
            .values_mut()
            .filter_map(|hs| hs.connection.poll_timeout())
            .min()
            .unwrap_or(Instant::now() + Duration::from_secs(5));
        let timeout_dur = next_timeout.saturating_duration_since(Instant::now());

        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("accept loop: shutdown");
                    return crate::tunnel::TunnelResult::Shutdown;
                }
            }

            // Handshake packet from UDP dispatcher.
            pkt = handshake_rx.recv() => {
                let Some((data, from)) = pkt else {
                    info!("handshake channel closed");
                    return crate::tunnel::TunnelResult::Shutdown;
                };

                let now = Instant::now();
                if let Some(event) = endpoint.handle(now, from, None, None, data, &mut response_buf) {
                    match event {
                        DatagramEvent::NewConnection(incoming) => {
                            match endpoint.accept(incoming, now, &mut response_buf, Some(server_config.clone())) {
                                Ok((ch, conn)) => {
                                    let remote = conn.remote_address();
                                    info!(remote = %remote, "accepted incoming handshake");
                                    handshakes.insert(ch, HandshakeState {
                                        connection: conn,
                                        remote_addr: remote,
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
                }
            }

            // Cleanup from finished connection tasks.
            cleanup = cleanup_rx.recv() => {
                if let Some((cid, tunnel_ip)) = cleanup {
                    let mut t = table.write().expect("dispatch table poisoned");
                    t.unregister(&cid, tunnel_ip);
                    info!(
                        active = t.len(),
                        "connection cleaned up"
                    );
                }
            }

            // Handshake timeouts.
            _ = tokio::time::sleep(timeout_dur) => {
                let now = Instant::now();
                for hs in handshakes.values_mut() {
                    hs.connection.handle_timeout(now);
                }
            }
        }

        // Drive all handshakes: poll endpoint events, poll connection events, drain transmits.
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
            let mut transmit_buf = Vec::with_capacity(BUF_SIZE);
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
            handshakes.remove(&ch);
        }

        // Promote completed handshakes to connection tasks.
        for ch in completed {
            let Some(mut hs) = handshakes.remove(&ch) else { continue };

            // Extract keys.
            let is_server = true;
            let raw = match extract_keys(&mut hs.connection, is_server, hs.remote_addr) {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "failed to extract keys after handshake");
                    continue;
                }
            };

            // Drain final transmits.
            let now = Instant::now();
            let mut transmit_buf = Vec::with_capacity(BUF_SIZE);
            loop {
                transmit_buf.clear();
                let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut transmit_buf) else {
                    break;
                };
                let _ = udp.send_to(&transmit_buf[..transmit.size], hs.remote_addr).await;
            }

            // Match peer by certificate identity.
            let tunnel_ip = match identify_peer(&hs.connection, &peers) {
                Some(peer) => peer.tunnel_ip,
                None => {
                    warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                    continue;
                }
            };
            let peer_keepalive = peers
                .iter()
                .find(|p| p.tunnel_ip == tunnel_ip)
                .and_then(|p| p.keepalive);

            // Create LocalConnectionState.
            let conn = quictun_quic::local::LocalConnectionState::new(
                raw.keys,
                raw.key_gens,
                raw.local_cid,
                raw.remote_cid,
                raw.is_server,
            );

            // Create channels and register in dispatch table.
            let (handle, udp_chan_rx, tun_chan_rx) =
                crate::dispatcher::new_connection_channels(hs.remote_addr, tunnel_ip);
            {
                let mut t = table.write().expect("dispatch table poisoned");
                t.register(raw.local_cid, handle);
            }

            // Spawn the per-connection task.
            let udp_clone = udp.clone();
            let tun_clone = tun.clone();
            let shutdown_clone = shutdown.clone();
            let cleanup_tx_clone = cleanup_tx.clone();
            let local_cid = raw.local_cid;

            info!(
                remote = %hs.remote_addr,
                tunnel_ip = %tunnel_ip,
                cid = %hex::encode(&local_cid[..]),
                "spawning connection task"
            );

            tokio::spawn(async move {
                let result = crate::fast_tunnel::run_connection_task(
                    conn,
                    udp_chan_rx,
                    tun_chan_rx,
                    udp_clone,
                    tun_clone,
                    hs.remote_addr,
                    idle_timeout,
                    peer_keepalive,
                    shutdown_clone,
                )
                .await;

                info!(
                    tunnel_ip = %tunnel_ip,
                    cid = %hex::encode(&local_cid[..]),
                    result = ?result,
                    "connection task ended"
                );

                // Signal cleanup.
                let _ = cleanup_tx_clone.send((local_cid, tunnel_ip)).await;
            });
        }
    }
}

/// Identify which peer connected by matching peer certificate against known peers.
fn identify_peer<'a>(
    conn: &quinn_proto::Connection,
    peers: &'a [ResolvedPeer],
) -> Option<&'a ResolvedPeer> {
    let identity = conn.crypto_session().peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer<'static>> = identity.downcast_ref()?;
    let peer_cert = certs.first()?;
    let peer_der: &[u8] = peer_cert.as_ref();

    // Match against known peer SPKI DERs.
    peers.iter().find(|p| p.spki_der == peer_der)
}

/// Drain all pending transmits from a quinn-proto connection.
async fn drain_transmits(
    udp: &UdpSocket,
    conn: &mut quinn_proto::Connection,
    remote_addr: SocketAddr,
) -> Result<()> {
    let now = Instant::now();
    let mut transmit_buf = Vec::with_capacity(BUF_SIZE);

    loop {
        transmit_buf.clear();
        let Some(transmit) = conn.poll_transmit(now, 1, &mut transmit_buf) else {
            break;
        };
        udp.send_to(&transmit_buf[..transmit.size], remote_addr)
            .await
            .context("failed to send handshake transmit")?;
    }

    Ok(())
}

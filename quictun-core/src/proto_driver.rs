//! Async quinn-proto handshake driver for tokio.
//!
//! Drives quinn-proto's `Endpoint` + `Connection` state machine over a tokio
//! `UdpSocket` until `Event::Connected` fires, then extracts 1-RTT keys and
//! returns a `quictun_quic::local::LocalConnectionState` for the fast data plane.
//!
//! This is the async equivalent of `quictun-dpdk/src/shared.rs`, which does
//! the same thing in a synchronous polling loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::peer;

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

/// Core handshake loop — returns raw keys for the caller to wrap.
async fn run_handshake_raw(
    udp: &UdpSocket,
    setup: &HandshakeSetup,
    shutdown: &watch::Receiver<bool>,
) -> Result<RawHandshakeResult> {
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
                        let extracted = peer::extract_1rtt_keys(conn)
                            .context("Connected but no 1-RTT keys available")?;
                        let is_server = server_config.is_some();
                        drain_transmits(udp, conn, remote_addr).await?;
                        return Ok(RawHandshakeResult {
                            extracted,
                            is_server,
                            remote_addr,
                        });
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

/// Result of `run_handshake_raw`: extracted keys + metadata.
struct RawHandshakeResult {
    extracted: peer::ExtractedKeys,
    is_server: bool,
    remote_addr: SocketAddr,
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
    let e = raw.extracted;
    let connection_state = quictun_quic::local::LocalConnectionState::new(
        e.keys,
        e.key_gens,
        e.local_cid,
        e.remote_cid,
        raw.is_server,
    );
    Ok(LocalHandshakeResult {
        connection_state,
        remote_addr: raw.remote_addr,
    })
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

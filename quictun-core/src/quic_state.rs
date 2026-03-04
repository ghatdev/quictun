//! Multi-client QUIC handshake state machine.
//!
//! Manages concurrent handshakes via quinn-proto endpoint. Used by
//! quictun-net (synchronous engine) and quictun-dpdk (DPDK engine).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig};
use quictun_quic::local::LocalConnectionState;
use tracing::{info, warn};

use crate::peer;

/// Maximum QUIC packet buffer size.
pub const BUF_SIZE: usize = 2048;

/// Per-handshake state for a connection in progress.
pub struct HandshakeState {
    pub connection: quinn_proto::Connection,
    pub ch: ConnectionHandle,
    pub local_cid: quinn_proto::ConnectionId,
    pub remote_addr: SocketAddr,
}

/// Result of processing multi-client QUIC events.
pub struct MultiDriveResult {
    /// Connections that completed handshake (ready for key extraction).
    pub completed: Vec<ConnectionHandle>,
    /// Connections that failed.
    pub failed: Vec<ConnectionHandle>,
}

/// Multi-client QUIC handshake state for the dispatcher.
///
/// Manages multiple concurrent handshakes via quinn-proto endpoint.
/// Analogous to tokio's `run_accept_loop` but synchronous (DPDK polling).
/// Supports both listener (accepts N connections) and connector (initiates 1).
pub struct MultiQuicState {
    pub endpoint: Endpoint,
    pub server_config: Option<Arc<ServerConfig>>,
    pub handshakes: HashMap<ConnectionHandle, HandshakeState>,
}

impl MultiQuicState {
    /// Create for listener mode (accepts incoming connections).
    pub fn new(server_config: Arc<ServerConfig>) -> Self {
        let ep_config = Arc::new(EndpointConfig::default());
        let endpoint = Endpoint::new(ep_config, Some(server_config.clone()), true, None);
        Self {
            endpoint,
            server_config: Some(server_config),
            handshakes: HashMap::new(),
        }
    }

    /// Create for connector mode (no server config, initiates outgoing connection).
    pub fn new_connector() -> Self {
        let ep_config = Arc::new(EndpointConfig::default());
        let endpoint = Endpoint::new(ep_config, None, true, None);
        Self {
            endpoint,
            server_config: None,
            handshakes: HashMap::new(),
        }
    }

    /// Initiate an outgoing connection (connector).
    pub fn connect(
        &mut self,
        client_config: quinn_proto::ClientConfig,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let (ch, conn) = self
            .endpoint
            .connect(Instant::now(), client_config, remote_addr, "quictun")
            .map_err(|e| anyhow::anyhow!("connect failed: {e}"))?;
        let local_cid = *conn.local_cid();
        info!(remote = %remote_addr, cid = %hex_cid(&local_cid), "QUIC connection initiated");
        self.handshakes.insert(ch, HandshakeState {
            connection: conn,
            ch,
            local_cid,
            remote_addr,
        });
        Ok(())
    }

    /// Handle an incoming datagram on the outer port.
    ///
    /// Returns response transmits (handshake packets to send back).
    pub fn handle_incoming(
        &mut self,
        now: Instant,
        remote_addr: SocketAddr,
        ecn: Option<quinn_proto::EcnCodepoint>,
        data: bytes::BytesMut,
        response_buf: &mut Vec<u8>,
    ) -> Vec<(usize, [u8; BUF_SIZE])> {
        let mut response_transmits = Vec::new();

        let Some(event) = self.endpoint.handle(now, remote_addr, None, ecn, data, response_buf)
        else {
            return response_transmits;
        };

        match event {
            DatagramEvent::ConnectionEvent(ch, event) => {
                if let Some(hs) = self.handshakes.get_mut(&ch) {
                    hs.connection.handle_event(event);
                }
            }
            DatagramEvent::NewConnection(incoming) => {
                match self.endpoint.accept(
                    incoming,
                    now,
                    response_buf,
                    self.server_config.clone(),
                ) {
                    Ok((ch, conn)) => {
                        let local_cid = *conn.local_cid();
                        info!(remote = %remote_addr, cid = %hex_cid(&local_cid), "accepted new connection");
                        self.handshakes.insert(ch, HandshakeState {
                            connection: conn,
                            ch,
                            local_cid,
                            remote_addr,
                        });
                    }
                    Err(e) => {
                        warn!(error = ?e.cause, "failed to accept connection");
                        if let Some(transmit) = e.response {
                            let len = transmit.size;
                            let mut buf = [0u8; BUF_SIZE];
                            buf[..len].copy_from_slice(&response_buf[..len]);
                            response_transmits.push((len, buf));
                        }
                    }
                }
            }
            DatagramEvent::Response(transmit) => {
                let len = transmit.size;
                let mut buf = [0u8; BUF_SIZE];
                buf[..len].copy_from_slice(&response_buf[..len]);
                response_transmits.push((len, buf));
            }
        }

        response_transmits
    }

    /// Poll all in-progress handshakes: drain endpoint events, check for completion.
    ///
    /// Returns lists of completed and failed connection handles.
    pub fn poll_handshakes(&mut self) -> MultiDriveResult {
        let mut completed = Vec::new();
        let mut failed = Vec::new();

        for (ch, hs) in self.handshakes.iter_mut() {
            // Drain endpoint events.
            while let Some(ep_event) = hs.connection.poll_endpoint_events() {
                if let Some(conn_event) = self.endpoint.handle_event(*ch, ep_event) {
                    hs.connection.handle_event(conn_event);
                }
            }

            // Drain application events.
            while let Some(event) = hs.connection.poll() {
                match event {
                    Event::Connected => {
                        completed.push(*ch);
                    }
                    Event::ConnectionLost { reason } => {
                        warn!(remote = %hs.remote_addr, %reason, "handshake failed");
                        failed.push(*ch);
                    }
                    _ => {}
                }
            }
        }

        // Remove failed handshakes.
        for ch in &failed {
            self.handshakes.remove(ch);
        }

        MultiDriveResult { completed, failed }
    }

    /// Extract keys from a completed handshake and remove it from the map.
    ///
    /// Returns `(HandshakeState, LocalConnectionState)` on success.
    pub fn extract_connection(
        &mut self,
        ch: ConnectionHandle,
    ) -> Option<(HandshakeState, LocalConnectionState)> {
        let mut hs = self.handshakes.remove(&ch)?;

        let extracted = peer::extract_1rtt_keys(&mut hs.connection)?;
        let is_server = self.server_config.is_some();
        let conn_state = LocalConnectionState::new(
            extracted.keys,
            extracted.key_gens,
            extracted.local_cid,
            extracted.remote_cid,
            is_server,
        );

        Some((hs, conn_state))
    }
}

/// Format a ConnectionId as a hex string.
pub fn hex_cid(cid: &quinn_proto::ConnectionId) -> String {
    hex::encode(&cid[..])
}

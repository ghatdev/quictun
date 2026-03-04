use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig};
use quictun_core::peer;
use quictun_quic::local::LocalConnectionState;
use tracing::{info, warn};

// Re-export multi-client types from quictun-core (shared with quictun-net).
pub use quictun_core::quic_state::{
    BUF_SIZE, HandshakeState, MultiDriveResult, MultiQuicState, hex_cid,
};

/// QUIC state owned exclusively by the engine thread.
///
/// The engine thread drives the quinn-proto state machine. All I/O is
/// performed after `process_events()` returns, using the returned `DriveResult`.
pub struct QuicState {
    pub endpoint: Endpoint,
    pub connection: Option<quinn_proto::Connection>,
    pub ch: Option<ConnectionHandle>,
    pub remote_addr: SocketAddr,
    pub server_config: Option<Arc<ServerConfig>>,
}

impl QuicState {
    pub fn new(
        remote_addr: SocketAddr,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Self {
        let ep_config = Arc::new(EndpointConfig::default());
        let endpoint = Endpoint::new(ep_config, server_config.clone(), true, None);
        Self {
            endpoint,
            connection: None,
            ch: None,
            remote_addr,
            server_config,
        }
    }
}

/// Result of processing QUIC connection events.
///
/// Pre-allocated once and reused across loop iterations via `process_events()`.
/// Contains application-level output (datagrams, connection state).
pub struct DriveResult {
    /// Decrypted TUN packets received from the peer.
    pub datagrams: Vec<Bytes>,
    /// Whether the QUIC connection just became established.
    pub connected: bool,
    /// Whether the connection was lost.
    pub connection_lost: bool,
    /// quictun-quic connection state, set once on Event::Connected.
    pub connection_state: Option<LocalConnectionState>,
}

impl DriveResult {
    pub fn new() -> Self {
        Self {
            datagrams: Vec::new(),
            connected: false,
            connection_lost: false,
            connection_state: None,
        }
    }

    fn clear(&mut self) {
        self.datagrams.clear();
        self.connected = false;
        self.connection_lost = false;
        // NOTE: connection_state is NOT cleared — it persists across loop iterations.
    }
}

/// Process QUIC connection events: poll endpoint events and application events.
///
/// Fills `result` with datagrams and connection state changes.
/// Does NOT drain transmits — the engine handles those directly.
pub fn process_events(state: &mut QuicState, result: &mut DriveResult) {
    result.clear();

    let (Some(conn), Some(conn_ch)) = (state.connection.as_mut(), state.ch) else {
        return;
    };

    // 1. Process endpoint events.
    while let Some(event) = conn.poll_endpoint_events() {
        if let Some(conn_event) = state.endpoint.handle_event(conn_ch, event) {
            conn.handle_event(conn_event);
        }
    }

    // 2. Process application events.
    while let Some(event) = conn.poll() {
        match event {
            Event::Connected => {
                info!("quic: connection established");
                result.connected = true;

                // Extract 1-RTT keys for quictun-quic data plane
                if let Some(keys) = conn.take_1rtt_keys() {
                    let local_cid = conn.local_cid().clone();
                    let remote_cid = conn.remote_cid();
                    let is_server = state.server_config.is_some();

                    // Pre-compute key update generations (~2ms, ~128KB)
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
                    info!(key_generations = key_gens.len(), "pre-computed key update generations");

                    let conn_state = LocalConnectionState::new(
                        keys, key_gens, local_cid, remote_cid, is_server,
                    );
                    result.connection_state = Some(conn_state);
                } else {
                    warn!("quic: Connected but no 1-RTT keys available");
                }
            }
            Event::DatagramReceived => {
                // Only process datagrams via quinn-proto if quictun-quic hasn't taken over.
                // After key extraction, quinn-proto can't decrypt 1-RTT data anyway.
                while let Some(datagram) = conn.datagrams().recv() {
                    result.datagrams.push(datagram);
                }
            }
            Event::DatagramsUnblocked => {}
            Event::ConnectionLost { reason } => {
                info!(reason = %reason, "quic: connection lost");
                result.connection_lost = true;
            }
            Event::HandshakeDataReady | Event::Stream(_) => {}
        }
    }
}

/// Handle a DatagramEvent from endpoint.handle().
///
/// Mutates endpoint/connection state and collects any response transmits.
/// Caller should follow with `process_events()` to complete state machine processing.
pub fn handle_datagram_event(
    state: &mut QuicState,
    event: DatagramEvent,
    response_buf: &mut Vec<u8>,
) -> Vec<(usize, [u8; BUF_SIZE])> {
    let mut response_transmits = Vec::new();

    match event {
        DatagramEvent::ConnectionEvent(event_ch, event) => {
            if let Some(conn) = state.connection.as_mut() {
                if state.ch == Some(event_ch) {
                    conn.handle_event(event);
                }
            }
        }
        DatagramEvent::NewConnection(incoming) => {
            if state.connection.is_none() {
                let now = Instant::now();
                match state.endpoint.accept(
                    incoming,
                    now,
                    response_buf,
                    state.server_config.clone(),
                ) {
                    Ok((new_ch, new_conn)) => {
                        info!(remote = %state.remote_addr, "quic: accepted incoming connection");
                        state.ch = Some(new_ch);
                        state.connection = Some(new_conn);
                    }
                    Err(e) => {
                        warn!(error = ?e.cause, "quic: failed to accept connection");
                        if let Some(transmit) = e.response {
                            let len = transmit.size;
                            let mut buf = [0u8; BUF_SIZE];
                            buf[..len].copy_from_slice(&response_buf[..len]);
                            response_transmits.push((len, buf));
                        }
                    }
                }
            } else {
                state.endpoint.ignore(incoming);
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig};
use tracing::{info, warn};

use crate::bufpool::BUF_SIZE;

/// QUIC state owned exclusively by the engine thread.
///
/// The engine thread drives the quinn-proto state machine. All I/O is
/// performed after `drive()` returns, using the returned `DriveResult`.
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

/// Result of driving the QUIC connection state machine.
///
/// Collected by the engine thread, consumed immediately after.
/// Defers all I/O to the caller.
pub struct DriveResult {
    /// UDP packets to send: (length, data buffer).
    pub transmits: Vec<(usize, [u8; BUF_SIZE])>,
    /// Decrypted TUN packets received from the peer.
    pub datagrams: Vec<Bytes>,
    /// Next timeout deadline for the timer.
    pub timer_deadline: Option<Instant>,
    /// Whether the QUIC connection just became established.
    pub connected: bool,
    /// Whether the connection was lost.
    pub connection_lost: bool,
}

/// Drive the QUIC connection: poll endpoint events, app events, drain transmits.
///
/// Returns a DriveResult containing all data needed for I/O operations.
pub fn drive(state: &mut QuicState) -> DriveResult {
    let mut result = DriveResult {
        transmits: Vec::new(),
        datagrams: Vec::new(),
        timer_deadline: None,
        connected: false,
        connection_lost: false,
    };

    let (Some(conn), Some(conn_ch)) = (state.connection.as_mut(), state.ch) else {
        return result;
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
            }
            Event::DatagramReceived => {
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

    // 3. Drain transmit queue.
    let now = Instant::now();
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    loop {
        transmit_buf.clear();
        match conn.poll_transmit(now, 1, &mut transmit_buf) {
            Some(transmit) => {
                let len = transmit.size;
                let mut buf = [0u8; BUF_SIZE];
                buf[..len].copy_from_slice(&transmit_buf[..len]);
                result.transmits.push((len, buf));
            }
            None => break,
        }
    }

    // 4. Update timer deadline.
    result.timer_deadline = conn.poll_timeout();

    result
}

/// Handle a DatagramEvent from endpoint.handle().
///
/// Mutates endpoint/connection state and collects any response transmits.
/// Caller should follow with `drive()` to complete state machine processing.
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

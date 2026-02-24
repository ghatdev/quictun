use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig};
use tracing::{info, warn};

/// Shared QUIC state wrapped in `Rc<RefCell<>>` for the single-threaded compio runtime.
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
pub struct DriveResult {
    /// UDP packets to send.
    pub transmits: Vec<Vec<u8>>,
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
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(1500);
    loop {
        transmit_buf.clear();
        match conn.poll_transmit(now, 1, &mut transmit_buf) {
            Some(transmit) => {
                result.transmits.push(transmit_buf[..transmit.size].to_vec());
            }
            None => break,
        }
    }

    // 4. Update timer deadline.
    result.timer_deadline = conn.poll_timeout();

    result
}

/// Handle a DatagramEvent from endpoint.handle().
pub fn handle_datagram_event(
    state: &mut QuicState,
    event: DatagramEvent,
    response_buf: &mut Vec<u8>,
) -> Vec<Vec<u8>> {
    let mut response_transmits = Vec::new();

    match event {
        DatagramEvent::ConnectionEvent(event_ch, event) => {
            if let Some(conn) = state.connection.as_mut()
                && state.ch == Some(event_ch)
            {
                conn.handle_event(event);
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
                            response_transmits
                                .push(response_buf[..transmit.size].to_vec());
                        }
                    }
                }
            } else {
                state.endpoint.ignore(incoming);
            }
        }
        DatagramEvent::Response(transmit) => {
            response_transmits.push(response_buf[..transmit.size].to_vec());
        }
    }

    response_transmits
}

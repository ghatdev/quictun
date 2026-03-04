//! Multi-client packet dispatcher.
//!
//! Routes incoming UDP packets to per-connection tasks by Connection ID,
//! and routes TUN packets to per-connection tasks by destination IP.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use bytes::BytesMut;
use quinn_proto::ConnectionId;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use quictun_tun::TunDevice;

/// Channel capacity for per-connection packet queues.
const CHANNEL_CAPACITY: usize = 1024;

/// Handle to a per-connection task's inbound channels.
#[derive(Clone)]
pub struct ConnectionHandle {
    /// Inbound UDP packets (already dispatched by CID).
    pub udp_tx: mpsc::Sender<BytesMut>,
    /// Inbound TUN packets (already routed by dest IP).
    pub tun_tx: mpsc::Sender<BytesMut>,
    /// Peer's remote UDP address.
    pub remote_addr: SocketAddr,
    /// Peer's tunnel IP (from config `allowed_ips`).
    pub tunnel_ip: Ipv4Addr,
}

/// Shared routing state for the dispatcher.
///
/// Read-locked on the hot path (every packet). Write-locked only on
/// connection setup / teardown (rare).
#[derive(Default)]
pub struct DispatchTable {
    /// Local CID → connection handle (for UDP RX routing).
    connections: HashMap<ConnectionId, ConnectionHandle>,
    /// Peer tunnel IP → connection handle (for TUN TX routing).
    routes: HashMap<Ipv4Addr, ConnectionHandle>,
}

impl DispatchTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register CID routing only (phase 1).
    ///
    /// Called right after `endpoint.accept()`, before the handshake completes.
    /// Packets arriving for this CID get buffered in the channel while the
    /// handshake + key extraction proceed. The IP route is added later via
    /// `add_route()` once the peer is identified.
    pub fn register_cid(&mut self, cid: ConnectionId, handle: ConnectionHandle) {
        tracing::info!(
            cid = %hex::encode(&cid[..]),
            remote = %handle.remote_addr,
            "dispatcher: registered CID (pre-handshake)"
        );
        self.connections.insert(cid, handle);
    }

    /// Add IP route for an already-registered connection (phase 2).
    ///
    /// Called after handshake completes and the peer is identified.
    pub fn add_route(&mut self, cid: &ConnectionId, tunnel_ip: Ipv4Addr) {
        if let Some(handle) = self.connections.get(cid) {
            let mut routed = handle.clone();
            routed.tunnel_ip = tunnel_ip;
            tracing::info!(
                cid = %hex::encode(&cid[..]),
                tunnel_ip = %tunnel_ip,
                "dispatcher: added IP route"
            );
            self.routes.insert(tunnel_ip, routed);
        }
    }

    /// Remove a connection from both lookup tables.
    pub fn unregister(&mut self, cid: &ConnectionId, tunnel_ip: Ipv4Addr) {
        self.connections.remove(cid);
        self.routes.remove(&tunnel_ip);
        tracing::info!(
            cid = %hex::encode(&cid[..]),
            tunnel_ip = %tunnel_ip,
            "dispatcher: unregistered connection"
        );
    }

    /// Remove a CID-only registration (handshake failed before peer identified).
    pub fn unregister_cid(&mut self, cid: &ConnectionId) {
        self.connections.remove(cid);
        tracing::info!(
            cid = %hex::encode(&cid[..]),
            "dispatcher: unregistered CID (handshake failed)"
        );
    }

    /// Number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether no connections are registered.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

/// Create channels for a new per-connection task.
///
/// Returns the `ConnectionHandle` (for the dispatcher) and the receive
/// halves (for the connection task).
pub fn new_connection_channels(
    remote_addr: SocketAddr,
    tunnel_ip: Ipv4Addr,
) -> (ConnectionHandle, mpsc::Receiver<BytesMut>, mpsc::Receiver<BytesMut>) {
    let (udp_tx, udp_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (tun_tx, tun_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let handle = ConnectionHandle {
        udp_tx,
        tun_tx,
        remote_addr,
        tunnel_ip,
    };
    (handle, udp_rx, tun_rx)
}

/// UDP dispatcher task: receive from the shared UDP socket and route packets
/// to per-connection tasks (short header) or the handshake channel (long header).
///
/// Uses `readable()` + `try_recv_from()` drain loop to capture source addresses
/// (needed for handshake packets). Per-connection data packets are routed by CID.
pub async fn run_udp_dispatcher(
    udp: Arc<UdpSocket>,
    table: Arc<RwLock<DispatchTable>>,
    handshake_tx: mpsc::Sender<(BytesMut, SocketAddr)>,
    cid_len: usize,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::info!(cid_len, "UDP dispatcher started");

    let mut recv_buf = vec![0u8; 2048];

    loop {
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            }

            result = udp.readable() => {
                if result.is_err() { return; }

                // Drain all available packets.
                loop {
                    match udp.try_recv_from(&mut recv_buf) {
                        Ok((n, from)) => {
                            if n == 0 { continue; }
                            dispatch_packet(
                                &recv_buf[..n], from,
                                &table, &handshake_tx, cid_len,
                            );
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            tracing::error!(error = %e, "UDP dispatcher: recv_from failed");
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Route a single UDP packet to the right destination.
fn dispatch_packet(
    packet: &[u8],
    from: SocketAddr,
    table: &RwLock<DispatchTable>,
    handshake_tx: &mpsc::Sender<(BytesMut, SocketAddr)>,
    cid_len: usize,
) {
    let first_byte = packet[0];

    // Long header → handshake channel.
    if first_byte & 0x80 != 0 {
        let mut data = BytesMut::with_capacity(packet.len());
        data.extend_from_slice(packet);
        if handshake_tx.try_send((data, from)).is_err() {
            warn!("handshake channel full, dropping long-header packet");
        }
        return;
    }

    // Short header → extract CID and route to connection.
    if cid_len == 0 || packet.len() < 1 + cid_len {
        debug!(size = packet.len(), "dropping packet: too short for CID");
        return;
    }

    let cid = ConnectionId::new(&packet[1..1 + cid_len]);

    let sender = {
        let state = table.read().expect("dispatch table poisoned");
        state.connections.get(&cid).map(|h| h.udp_tx.clone())
    };

    if let Some(tx) = sender {
        let mut data = BytesMut::with_capacity(packet.len());
        data.extend_from_slice(packet);
        if tx.try_send(data).is_err() {
            debug!(cid = %hex::encode(&cid[..]), "connection channel full, dropping packet");
        }
    } else {
        debug!(cid = %hex::encode(&cid[..]), "no connection for CID, dropping packet");
    }
}

/// TUN router task: read from the shared TUN device and route packets
/// to per-connection tasks by destination IP.
pub async fn run_tun_router(
    tun: Arc<TunDevice>,
    table: Arc<RwLock<DispatchTable>>,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::info!("TUN router started");

    loop {
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            }

            result = tun.readable() => {
                if result.is_err() { return; }

                // Drain all available TUN packets.
                loop {
                    let mut packet = [0u8; 1500];
                    match tun.try_recv(&mut packet) {
                        Ok(n) => {
                            if n < 20 { continue; } // too short for IPv4

                            // IPv4 destination address: bytes 16..20.
                            let dest_ip = Ipv4Addr::new(
                                packet[16], packet[17], packet[18], packet[19],
                            );

                            let sender = {
                                let state = table.read().expect("dispatch table poisoned");
                                state.routes.get(&dest_ip).map(|h| h.tun_tx.clone())
                            };

                            if let Some(tx) = sender {
                                let mut data = BytesMut::with_capacity(n);
                                data.extend_from_slice(&packet[..n]);
                                if tx.try_send(data).is_err() {
                                    debug!(dest = %dest_ip, "connection TUN channel full, dropping");
                                }
                            } else {
                                debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            tracing::error!(error = %e, "TUN router: recv failed");
                            return;
                        }
                    }
                }
            }
        }
    }
}

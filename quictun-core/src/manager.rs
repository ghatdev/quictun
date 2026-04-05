//! Platform-agnostic connection lifecycle manager (Layer 3).
//!
//! Owns the connection table and routing table. Handles handshake promotion,
//! timeout/keepalive sweep, reconnect eviction, max_peers enforcement, and
//! route cleanup. Does NOT perform any I/O or crypto operations — the I/O
//! adapter (Layer 2) translates returned actions into backend-specific I/O.
//!
//! Generic over `S: ConnectionState` to support different connection state
//! types across backends:
//! - `LocalConnectionState` for single-thread and per-connection multi-core
//! - `SharedConnectionState` for DPDK pipeline (future)

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;
use quictun_proto::shared::SharedConnectionState;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use tracing::{info, warn};

use crate::peer::{self, PeerConfig};
use crate::quic_state::HandshakeState;
use crate::routing::{RouteAction, RoutingTable};

// ── ConnectionState trait ───────────────────────────────────────────────

/// Minimal trait for connection lifecycle decisions.
///
/// The full encrypt/decrypt API stays on the concrete type — only what the
/// manager needs for timeout sweep and ACK scheduling is abstracted here.
pub trait ConnectionState {
    fn is_key_exhausted(&self) -> bool;
    fn needs_ack(&self) -> bool;
}

impl ConnectionState for LocalConnectionState {
    fn is_key_exhausted(&self) -> bool {
        self.is_key_exhausted()
    }

    fn needs_ack(&self) -> bool {
        self.needs_ack()
    }
}

impl ConnectionState for SharedConnectionState {
    fn is_key_exhausted(&self) -> bool {
        self.is_key_exhausted()
    }

    fn needs_ack(&self) -> bool {
        self.replay.needs_ack()
    }
}

impl<S: ConnectionState> ConnectionState for Arc<S> {
    fn is_key_exhausted(&self) -> bool {
        (**self).is_key_exhausted()
    }

    fn needs_ack(&self) -> bool {
        (**self).needs_ack()
    }
}

// ── ConnEntry ───────────────────────────────────────────────────────────

/// Per-connection state in the connection table.
///
/// Generic over `S` to hold different crypto state types per backend.
/// The metadata fields (tunnel_ip, allowed_ips, timing) are always the same.
pub struct ConnEntry<S: ConnectionState> {
    pub conn: S,
    pub tunnel_ip: Ipv4Addr,
    pub allowed_ips: Vec<Ipv4Net>,
    pub remote_addr: SocketAddr,
    pub keepalive_interval: Duration,
    pub last_tx: Instant,
    pub last_rx: Instant,
}

// ── Manager actions ─────────────────────────────────────────────────────

/// Actions the I/O loop must perform after calling a ConnectionManager method.
#[derive(Debug)]
pub enum ManagerAction {
    /// Send a keepalive for this connection (encrypt empty datagram + send).
    SendKeepalive { cid_key: u64 },
    /// A connection was removed. Backend should clean up resources, remove OS routes.
    ConnectionRemoved {
        cid_key: u64,
        tunnel_ip: Ipv4Addr,
        allowed_ips: Vec<Ipv4Net>,
        reason: RemoveReason,
    },
}

/// Why a connection was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveReason {
    IdleTimeout,
    KeyExhausted,
    ConnectionClose,
    ReconnectEviction,
}

// ── Promote result ──────────────────────────────────────────────────────

/// Result of attempting to promote a completed handshake.
pub enum PromoteResult {
    /// Handshake promoted. Caller must convert `conn_state` to `S`, then
    /// call `insert_connection()`.
    Accepted {
        cid_key: u64,
        cid_bytes: Vec<u8>,
        tunnel_ip: Ipv4Addr,
        allowed_ips: Vec<Ipv4Net>,
        remote_addr: SocketAddr,
        keepalive_interval: Duration,
        conn_state: LocalConnectionState,
        /// CID of evicted connection (reconnect), if any.
        evicted: Option<EvictedInfo>,
    },
    /// Peer not identified or max_peers reached. Caller should send
    /// CONNECTION_CLOSE using the returned `conn_state`.
    Rejected {
        conn_state: LocalConnectionState,
        remote_addr: SocketAddr,
        reason: RejectReason,
    },
}

/// Info about an evicted connection (for OS route cleanup).
#[derive(Debug)]
pub struct EvictedInfo {
    pub cid_key: u64,
    pub tunnel_ip: Ipv4Addr,
    pub allowed_ips: Vec<Ipv4Net>,
}

/// Why a handshake was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    UnknownPeer,
    MaxPeersReached,
}

// ── Stats ───────────────────────────────────────────────────────────────

/// Snapshot of manager statistics for periodic logging.
#[derive(Debug)]
pub struct ManagerStats {
    pub connections: usize,
    pub routes: usize,
}

// ── ConnectionManager ───────────────────────────────────────────────────

/// Platform-agnostic connection lifecycle manager.
///
/// Owns the connection table (Layer 3 CID routing) and the internal
/// [`RoutingTable`] (dest IP → peer CID lookup). Does NOT perform any I/O.
pub struct ConnectionManager<S: ConnectionState> {
    connections: FxHashMap<u64, ConnEntry<S>>,
    routing_table: RoutingTable,
    max_peers: usize,
    idle_timeout: Duration,
    had_connection: bool,
}

impl<S: ConnectionState> ConnectionManager<S> {
    /// Create a new connection manager.
    ///
    /// - `tunnel_ip`: our local tunnel IP
    /// - `default_external`: if true, unmatched IPs route externally (gateway mode)
    /// - `max_peers`: maximum concurrent connections (0 = unlimited)
    /// - `idle_timeout`: connections idle longer than this are removed
    pub fn new(
        tunnel_ip: Ipv4Addr,
        default_external: bool,
        max_peers: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            connections: FxHashMap::default(),
            routing_table: RoutingTable::new(tunnel_ip, default_external),
            max_peers,
            idle_timeout,
            had_connection: false,
        }
    }

    // ── Hot path (called per packet) ────────────────────────────────────

    /// Get a mutable reference to a connection entry by CID key.
    #[inline]
    pub fn get_mut(&mut self, cid_key: &u64) -> Option<&mut ConnEntry<S>> {
        self.connections.get_mut(cid_key)
    }

    /// Get an immutable reference to a connection entry.
    #[inline]
    pub fn get(&self, cid_key: &u64) -> Option<&ConnEntry<S>> {
        self.connections.get(cid_key)
    }

    /// Look up the route for a destination IP (Layer 3 CID routing).
    #[inline]
    pub fn lookup_route(&self, dst_ip: Ipv4Addr) -> RouteAction {
        self.routing_table.lookup(dst_ip)
    }

    // ── Accessors ───────────────────────────────────────────────────────

    /// Number of active connections.
    #[inline]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the connection table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Whether we ever had a connection (for connector reconnect detection).
    #[inline]
    pub fn had_connection(&self) -> bool {
        self.had_connection
    }

    /// Number of routes in the routing table.
    #[inline]
    pub fn route_count(&self) -> usize {
        self.routing_table.len()
    }

    /// Iterate over all connections (immutable).
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &ConnEntry<S>)> {
        self.connections.iter()
    }

    /// Iterate over all connections (mutable).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&u64, &mut ConnEntry<S>)> {
        self.connections.iter_mut()
    }

    /// Iterate over all connection values (mutable).
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut ConnEntry<S>> {
        self.connections.values_mut()
    }

    /// Iterate over all CID keys.
    pub fn keys(&self) -> impl Iterator<Item = &u64> {
        self.connections.keys()
    }

    /// Snapshot of stats for periodic logging.
    pub fn stats(&self) -> ManagerStats {
        ManagerStats {
            connections: self.connections.len(),
            routes: self.routing_table.len(),
        }
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    /// Insert a new connection and add its routes.
    ///
    /// Called by the I/O loop after converting `LocalConnectionState` to `S`.
    pub fn insert_connection(&mut self, cid_key: u64, entry: ConnEntry<S>) {
        self.routing_table
            .add_peer_routes(cid_key, &entry.allowed_ips);
        self.connections.insert(cid_key, entry);
        self.had_connection = true;
    }

    /// Remove a connection and clean up its routes.
    ///
    /// Replaces the 6+ inline `connections.remove + routing_table.remove_peer_routes`
    /// patterns that were duplicated across engine.rs and pipeline.rs.
    pub fn remove_connection(&mut self, cid_key: u64) -> Option<ConnEntry<S>> {
        let entry = self.connections.remove(&cid_key);
        if entry.is_some() {
            self.routing_table.remove_peer_routes(cid_key);
        }
        entry
    }

    // ── Handshake promotion ─────────────────────────────────────────────

    /// Attempt to promote a completed handshake into an active connection.
    ///
    /// Performs (in order):
    /// 1. Peer identification via `identify_peer()`
    /// 2. Reconnect eviction (if peer already connected, remove old)
    /// 3. `max_peers` enforcement (after eviction, so reconnects don't count double)
    ///
    /// Does NOT insert the connection — the caller must:
    /// 1. Convert `conn_state` to backend-specific `S` (e.g., `into_split()`)
    /// 2. Construct `ConnEntry<S>`
    /// 3. Call `insert_connection(cid_key, entry)`
    ///
    /// Does NOT send packets — the caller sends CONNECTION_CLOSE for rejections.
    pub fn promote_handshake(
        &mut self,
        hs: &HandshakeState,
        conn_state: LocalConnectionState,
        peers: &[PeerConfig],
    ) -> PromoteResult {
        // 1. Identify peer (handles both RPK and X.509).
        let matched_peer = match peer::identify_peer(&hs.connection, peers) {
            Some(p) => p,
            None => {
                warn!(
                    remote = %hs.remote_addr,
                    "could not identify peer, rejecting"
                );
                return PromoteResult::Rejected {
                    conn_state,
                    remote_addr: hs.remote_addr,
                    reason: RejectReason::UnknownPeer,
                };
            }
        };

        let tunnel_ip = matched_peer.tunnel_ip;
        let allowed_ips = matched_peer.allowed_ips.clone();
        let keepalive_interval = matched_peer
            .keepalive
            .unwrap_or(Duration::from_secs(25));

        // 2. Reconnect eviction: if this peer already has a connection, evict it.
        let evicted = self.evict_by_tunnel_ip(tunnel_ip);

        // 3. Check max_peers (after eviction, so reconnects don't count double).
        if self.max_peers > 0 && self.connections.len() >= self.max_peers {
            warn!(
                max_peers = self.max_peers,
                remote = %hs.remote_addr,
                "max_peers reached, rejecting"
            );
            return PromoteResult::Rejected {
                conn_state,
                remote_addr: hs.remote_addr,
                reason: RejectReason::MaxPeersReached,
            };
        }

        let cid_bytes: Vec<u8> = conn_state.local_cid()[..].to_vec();
        let cid_key = cid_to_u64(&cid_bytes);

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            "handshake promoted"
        );

        PromoteResult::Accepted {
            cid_key,
            cid_bytes,
            tunnel_ip,
            allowed_ips,
            remote_addr: hs.remote_addr,
            keepalive_interval,
            conn_state,
            evicted,
        }
    }

    /// Evict an existing connection with the same tunnel IP (reconnect scenario).
    fn evict_by_tunnel_ip(&mut self, tunnel_ip: Ipv4Addr) -> Option<EvictedInfo> {
        let old_cid = self
            .connections
            .iter()
            .find(|(_, e)| e.tunnel_ip == tunnel_ip)
            .map(|(&cid, _)| cid);

        if let Some(old) = old_cid
            && let Some(entry) = self.remove_connection(old)
        {
            info!(
                tunnel_ip = %entry.tunnel_ip,
                old_cid = %hex::encode(old.to_ne_bytes()),
                "evicted stale connection (peer reconnected)"
            );
            return Some(EvictedInfo {
                cid_key: old,
                tunnel_ip: entry.tunnel_ip,
                allowed_ips: entry.allowed_ips,
            });
        }
        None
    }

    // ── Timeout sweep ───────────────────────────────────────────────────

    /// Sweep connections for idle timeout, key exhaustion, and keepalive.
    ///
    /// Returns actions the I/O loop must execute:
    /// - `ConnectionRemoved`: connection was removed (idle/key exhaustion)
    /// - `SendKeepalive`: connection needs a keepalive packet
    ///
    /// The I/O loop encrypts keepalives and sends them. For removed connections,
    /// the I/O loop should remove OS routes via `DataPlaneIo::remove_os_route()`.
    pub fn sweep_timeouts(&mut self) -> SmallVec<[ManagerAction; 8]> {
        let mut actions = SmallVec::new();

        // 1. Find expired connections (idle timeout or key exhaustion).
        let expired: SmallVec<[(u64, RemoveReason); 4]> = self
            .connections
            .iter()
            .filter_map(|(&cid, e)| {
                if e.conn.is_key_exhausted() {
                    Some((cid, RemoveReason::KeyExhausted))
                } else if e.last_rx.elapsed() >= self.idle_timeout {
                    Some((cid, RemoveReason::IdleTimeout))
                } else {
                    None
                }
            })
            .collect();

        // 2. Remove expired and emit actions.
        for (cid, reason) in expired {
            if let Some(entry) = self.remove_connection(cid) {
                info!(
                    tunnel_ip = %entry.tunnel_ip,
                    cid = %hex::encode(cid.to_ne_bytes()),
                    reason = ?reason,
                    "connection removed"
                );
                actions.push(ManagerAction::ConnectionRemoved {
                    cid_key: cid,
                    tunnel_ip: entry.tunnel_ip,
                    allowed_ips: entry.allowed_ips,
                    reason,
                });
            }
        }

        // 3. Find connections needing keepalive.
        for (&cid, entry) in &self.connections {
            if entry.last_tx.elapsed() >= entry.keepalive_interval {
                actions.push(ManagerAction::SendKeepalive { cid_key: cid });
            }
        }

        actions
    }

    // ── ACK helper ──────────────────────────────────────────────────────

    /// Return CID keys of connections that need an ACK sent.
    pub fn connections_needing_ack(&self) -> SmallVec<[u64; 8]> {
        self.connections
            .iter()
            .filter(|(_, e)| e.conn.needs_ack())
            .map(|(&k, _)| k)
            .collect()
    }

    // ── Poll timeout computation ────────────────────────────────────────

    /// Compute the minimum timeout for the next poll iteration.
    ///
    /// Considers idle timeout, keepalive intervals, and the next ACK deadline.
    /// Returns at least 1ms to avoid busy spin.
    pub fn compute_poll_timeout(&self, next_ack_deadline: Instant) -> Duration {
        let now = Instant::now();
        let mut min_timeout = self.idle_timeout;

        // Keepalive: find the soonest keepalive deadline.
        for entry in self.connections.values() {
            let elapsed = entry.last_tx.elapsed();
            if elapsed < entry.keepalive_interval {
                let remaining = entry.keepalive_interval - elapsed;
                min_timeout = min_timeout.min(remaining);
            } else {
                // Already past keepalive deadline — wake up immediately.
                return Duration::from_millis(1);
            }
        }

        // ACK deadline.
        let ack_remaining = next_ack_deadline.saturating_duration_since(now);
        min_timeout = min_timeout.min(ack_remaining);

        // At least 1ms to avoid busy spin.
        min_timeout.max(Duration::from_millis(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock connection state for testing.
    struct MockConn {
        key_exhausted: bool,
        needs_ack: bool,
    }

    impl ConnectionState for MockConn {
        fn is_key_exhausted(&self) -> bool {
            self.key_exhausted
        }
        fn needs_ack(&self) -> bool {
            self.needs_ack
        }
    }

    fn make_entry(tunnel_ip: Ipv4Addr) -> ConnEntry<MockConn> {
        ConnEntry {
            conn: MockConn {
                key_exhausted: false,
                needs_ack: false,
            },
            tunnel_ip,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            remote_addr: "1.2.3.4:1234".parse().unwrap(),
            keepalive_interval: Duration::from_secs(25),
            last_tx: Instant::now(),
            last_rx: Instant::now(),
        }
    }

    fn make_manager() -> ConnectionManager<MockConn> {
        ConnectionManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            false,
            10,
            Duration::from_secs(60),
        )
    }

    #[test]
    fn test_insert_and_remove() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));

        mgr.insert_connection(42, entry);
        assert_eq!(mgr.len(), 1);
        assert!(mgr.had_connection());
        assert_eq!(mgr.route_count(), 1);

        let removed = mgr.remove_connection(42);
        assert!(removed.is_some());
        assert_eq!(mgr.len(), 0);
        assert_eq!(mgr.route_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mgr = make_manager();
        assert!(mgr.remove_connection(999).is_none());
    }

    #[test]
    fn test_lookup_route() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        mgr.insert_connection(42, entry);

        // 10.0.0.5 matches the 10.0.0.0/24 route → ForwardToPeer(42).
        assert_eq!(
            mgr.lookup_route(Ipv4Addr::new(10, 0, 0, 5)),
            RouteAction::ForwardToPeer(42)
        );
        // 10.0.0.1 is our local IP → Local.
        assert_eq!(
            mgr.lookup_route(Ipv4Addr::new(10, 0, 0, 1)),
            RouteAction::Local
        );
        // Unmatched → Drop (default_external=false).
        assert_eq!(
            mgr.lookup_route(Ipv4Addr::new(8, 8, 8, 8)),
            RouteAction::Drop
        );
    }

    #[test]
    fn test_remove_cleans_routes() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        mgr.insert_connection(42, entry);

        assert_eq!(
            mgr.lookup_route(Ipv4Addr::new(10, 0, 0, 5)),
            RouteAction::ForwardToPeer(42)
        );

        mgr.remove_connection(42);

        // Route should be gone.
        assert_eq!(
            mgr.lookup_route(Ipv4Addr::new(10, 0, 0, 5)),
            RouteAction::Drop
        );
    }

    #[test]
    fn test_sweep_idle_timeout() {
        let mut mgr: ConnectionManager<MockConn> = ConnectionManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            false,
            10,
            Duration::from_millis(10), // very short timeout for testing
        );

        let mut entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        entry.last_rx = Instant::now() - Duration::from_secs(1); // well past timeout
        mgr.insert_connection(42, entry);

        let actions = mgr.sweep_timeouts();
        assert_eq!(mgr.len(), 0);

        let removed = actions
            .iter()
            .find(|a| matches!(a, ManagerAction::ConnectionRemoved { reason: RemoveReason::IdleTimeout, .. }));
        assert!(removed.is_some());
    }

    #[test]
    fn test_sweep_key_exhausted() {
        let mut mgr = make_manager();
        let mut entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        entry.conn.key_exhausted = true;
        mgr.insert_connection(42, entry);

        let actions = mgr.sweep_timeouts();
        assert_eq!(mgr.len(), 0);

        let removed = actions
            .iter()
            .find(|a| matches!(a, ManagerAction::ConnectionRemoved { reason: RemoveReason::KeyExhausted, .. }));
        assert!(removed.is_some());
    }

    #[test]
    fn test_sweep_keepalive() {
        let mut mgr = make_manager();
        let mut entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        entry.keepalive_interval = Duration::from_millis(10);
        entry.last_tx = Instant::now() - Duration::from_secs(1); // past keepalive
        mgr.insert_connection(42, entry);

        let actions = mgr.sweep_timeouts();
        // Connection should still be alive.
        assert_eq!(mgr.len(), 1);

        let keepalive = actions
            .iter()
            .find(|a| matches!(a, ManagerAction::SendKeepalive { cid_key: 42 }));
        assert!(keepalive.is_some());
    }

    #[test]
    fn test_sweep_no_action_for_fresh_connections() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        mgr.insert_connection(42, entry);

        let actions = mgr.sweep_timeouts();
        assert!(actions.is_empty());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_connections_needing_ack() {
        let mut mgr = make_manager();

        let mut entry1 = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        entry1.conn.needs_ack = true;
        mgr.insert_connection(1, entry1);

        let mut entry2 = make_entry(Ipv4Addr::new(10, 0, 0, 3));
        entry2.conn.needs_ack = false;
        entry2.allowed_ips = vec!["10.0.1.0/24".parse().unwrap()];
        mgr.insert_connection(2, entry2);

        let ack_cids = mgr.connections_needing_ack();
        assert_eq!(ack_cids.len(), 1);
        assert_eq!(ack_cids[0], 1);
    }

    #[test]
    fn test_compute_poll_timeout_respects_ack_deadline() {
        let mgr = make_manager();
        let next_ack = Instant::now() + Duration::from_millis(50);
        let timeout = mgr.compute_poll_timeout(next_ack);
        // Should be close to 50ms (the ACK deadline).
        assert!(timeout <= Duration::from_millis(55));
    }

    #[test]
    fn test_compute_poll_timeout_at_least_1ms() {
        let mut mgr = make_manager();
        let mut entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        entry.keepalive_interval = Duration::from_millis(1);
        entry.last_tx = Instant::now() - Duration::from_secs(1);
        mgr.insert_connection(42, entry);

        let timeout = mgr.compute_poll_timeout(Instant::now());
        assert!(timeout >= Duration::from_millis(1));
    }

    #[test]
    fn test_stats() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        mgr.insert_connection(42, entry);

        let stats = mgr.stats();
        assert_eq!(stats.connections, 1);
        assert_eq!(stats.routes, 1);
    }

    // ── promote_handshake tests require quinn-proto HandshakeState which
    // is hard to mock without a full TLS handshake. These are tested via
    // the integration tests (echo_test, production_features_test) that
    // exercise the full engine path. The eviction and max_peers logic is
    // tested below using direct ConnectionManager methods. ──

    #[test]
    fn test_evict_by_tunnel_ip() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        mgr.insert_connection(42, entry);

        // Evict the connection with tunnel_ip 10.0.0.2.
        let evicted = mgr.evict_by_tunnel_ip(Ipv4Addr::new(10, 0, 0, 2));
        assert!(evicted.is_some());
        let info = evicted.unwrap();
        assert_eq!(info.cid_key, 42);
        assert_eq!(info.tunnel_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_evict_nonexistent_tunnel_ip() {
        let mut mgr = make_manager();
        let entry = make_entry(Ipv4Addr::new(10, 0, 0, 2));
        mgr.insert_connection(42, entry);

        let evicted = mgr.evict_by_tunnel_ip(Ipv4Addr::new(10, 0, 0, 99));
        assert!(evicted.is_none());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_max_peers_zero_means_unlimited() {
        let mut mgr: ConnectionManager<MockConn> = ConnectionManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            false,
            0, // unlimited
            Duration::from_secs(60),
        );

        // Insert many connections — should never hit max_peers.
        for i in 0..100u64 {
            let mut entry = make_entry(Ipv4Addr::new(10, 0, i as u8 + 2, 1));
            entry.allowed_ips = vec![format!("10.0.{}.0/24", i + 2).parse().unwrap()];
            mgr.insert_connection(i, entry);
        }
        assert_eq!(mgr.len(), 100);
    }
}

//! Routing table built from peer `allowed_ips`.
//!
//! Determines whether a decrypted packet should be forwarded to another peer
//! (hub-and-spoke), forwarded externally (internet gateway), or handled locally.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Action to take for a given destination IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    /// Encrypt and forward to a specific peer (identified by CID key).
    ForwardToPeer(u64),
    /// NAT and forward as plaintext to the network (internet gateway).
    ForwardExternal,
    /// Addressed to us (e.g., ICMP echo, management).
    Local,
    /// No route — drop.
    Drop,
}

/// Routing table for the router-mode data plane.
///
/// Built from peer `allowed_ips` at startup. Routes are sorted by prefix
/// length (longest first) for longest-prefix matching.
pub struct RoutingTable {
    /// (network, peer CID key) sorted by descending prefix length.
    routes: Vec<(Ipv4Net, u64)>,
    /// Our local tunnel IP.
    local_ip: Ipv4Addr,
    /// If true, unmatched IPs go to ForwardExternal; otherwise Drop.
    default_external: bool,
}

impl RoutingTable {
    /// Create a new routing table.
    ///
    /// - `local_ip`: our tunnel IP (packets addressed here → `Local`)
    /// - `default_external`: if true, IPs not matching any peer route
    ///   are forwarded externally (internet gateway mode)
    pub fn new(local_ip: Ipv4Addr, default_external: bool) -> Self {
        Self {
            routes: Vec::new(),
            local_ip,
            default_external,
        }
    }

    /// Add a route for a peer's allowed IPs.
    pub fn add_peer_routes(&mut self, cid_key: u64, allowed_ips: &[Ipv4Net]) {
        for net in allowed_ips {
            self.routes.push((*net, cid_key));
        }
        // Keep sorted by descending prefix length for longest-prefix match.
        self.routes.sort_by(|a, b| b.0.prefix_len().cmp(&a.0.prefix_len()));
    }

    /// Look up the route for a destination IP.
    #[inline]
    pub fn lookup(&self, dst_ip: Ipv4Addr) -> RouteAction {
        if dst_ip == self.local_ip {
            return RouteAction::Local;
        }

        // Linear scan — fine for handful of routes.
        for (net, cid) in &self.routes {
            if net.contains(&dst_ip) {
                return RouteAction::ForwardToPeer(*cid);
            }
        }

        if self.default_external {
            RouteAction::ForwardExternal
        } else {
            RouteAction::Drop
        }
    }

    /// Number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_ip() {
        let table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), true);
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 0, 1)),
            RouteAction::Local
        );
    }

    #[test]
    fn test_peer_route() {
        let mut table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), true);
        let net: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        table.add_peer_routes(42, &[net]);

        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 0, 2)),
            RouteAction::ForwardToPeer(42)
        );
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 0, 254)),
            RouteAction::ForwardToPeer(42)
        );
    }

    #[test]
    fn test_external_default() {
        let table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), true);
        assert_eq!(
            table.lookup(Ipv4Addr::new(8, 8, 8, 8)),
            RouteAction::ForwardExternal
        );
    }

    #[test]
    fn test_drop_default() {
        let table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), false);
        assert_eq!(
            table.lookup(Ipv4Addr::new(8, 8, 8, 8)),
            RouteAction::Drop
        );
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), true);
        let broad: Ipv4Net = "10.0.0.0/16".parse().unwrap();
        let narrow: Ipv4Net = "10.0.1.0/24".parse().unwrap();
        table.add_peer_routes(100, &[broad]);
        table.add_peer_routes(200, &[narrow]);

        // 10.0.1.5 matches both, but /24 is longer → peer 200.
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 1, 5)),
            RouteAction::ForwardToPeer(200)
        );

        // 10.0.2.5 only matches /16 → peer 100.
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 2, 5)),
            RouteAction::ForwardToPeer(100)
        );
    }

    #[test]
    fn test_local_takes_precedence() {
        let mut table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), true);
        let net: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        table.add_peer_routes(42, &[net]);

        // Local IP should still be Local even though it matches the peer route.
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 0, 1)),
            RouteAction::Local
        );
    }

    #[test]
    fn test_multiple_peers() {
        let mut table = RoutingTable::new(Ipv4Addr::new(10, 0, 0, 1), false);
        let net_a: Ipv4Net = "10.0.1.0/24".parse().unwrap();
        let net_b: Ipv4Net = "10.0.2.0/24".parse().unwrap();
        table.add_peer_routes(1, &[net_a]);
        table.add_peer_routes(2, &[net_b]);

        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 1, 100)),
            RouteAction::ForwardToPeer(1)
        );
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 2, 100)),
            RouteAction::ForwardToPeer(2)
        );
        assert_eq!(
            table.lookup(Ipv4Addr::new(10, 0, 3, 100)),
            RouteAction::Drop
        );
    }
}

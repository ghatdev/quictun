//! Shared peer identification and key extraction.
//!
//! Used by both the tokio and DPDK backends to avoid duplicating:
//! - Peer identity matching (certificate → config lookup)
//! - 1-RTT key extraction + key generation pre-computation

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;

use ipnet::Ipv4Net;
use quinn_proto::crypto;
use tracing::info;

/// Peer configuration for identity matching after handshake.
///
/// Replaces the backend-specific `ResolvedPeer` (tokio) and `PeerInfo` (DPDK).
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// SPKI DER of the peer's public key.
    ///
    /// With RPK (raw public keys), the certificate DER IS the SPKI DER,
    /// so direct comparison works. For X.509, you would need to extract
    /// the SPKI from the certificate first.
    pub spki_der: Vec<u8>,
    /// Tunnel IP assigned to this peer (first IP from `allowed_ips`).
    pub tunnel_ip: Ipv4Addr,
    /// Networks this peer is allowed to send from.
    pub allowed_ips: Vec<Ipv4Net>,
    /// Keepalive interval (used by tokio backend; DPDK can set to `None`).
    pub keepalive: Option<Duration>,
}

/// Check if an IP is within any of the allowed_ips networks.
///
/// Fail-closed: returns `false` if `allowed_ips` is empty.
/// Callers must validate that `allowed_ips` is non-empty at config time
/// (see [`crate::session::resolve_peers`]).
pub fn is_allowed_source(allowed_ips: &[Ipv4Net], src_ip: Ipv4Addr) -> bool {
    allowed_ips.iter().any(|net| net.contains(&src_ip))
}

/// Identify which peer connected by matching their certificate against known peers.
///
/// Works with RPK where the certificate DER equals the SPKI DER.
pub fn identify_peer<'a>(
    conn: &quinn_proto::Connection,
    peers: &'a [PeerConfig],
) -> Option<&'a PeerConfig> {
    let identity = conn.crypto_session().peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer<'static>> = identity.downcast_ref()?;
    let peer_cert = certs.first()?;
    let peer_der: &[u8] = peer_cert.as_ref();

    peers.iter().find(|p| p.spki_der == peer_der)
}

/// Identify a peer from their X.509 certificate by extracting SAN IP addresses.
///
/// For X.509/CA mode: the certificate SAN IPs define the peer's tunnel IP
/// and allowed networks. No per-peer config section is needed — the CA is
/// the trust anchor and the cert is the identity.
pub fn identify_peer_x509(conn: &quinn_proto::Connection) -> Option<PeerConfig> {
    let identity = conn.crypto_session().peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer<'static>> = identity.downcast_ref()?;
    let peer_cert = certs.first()?;

    let (_, x509) =
        x509_parser::parse_x509_certificate(peer_cert.as_ref()).ok()?;

    let mut san_ips: Vec<Ipv4Addr> = Vec::new();
    for ext in x509.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::IPAddress(bytes) = name {
                    if bytes.len() == 4 {
                        san_ips.push(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
                    }
                }
            }
        }
    }

    if san_ips.is_empty() {
        tracing::warn!("X.509 peer cert has no SAN IPv4 addresses, rejecting");
        return None;
    }

    let tunnel_ip = san_ips[0];
    let allowed_ips: Vec<Ipv4Net> = san_ips
        .iter()
        .map(|ip| Ipv4Net::new(*ip, 32).expect("valid /32"))
        .collect();

    info!(
        tunnel_ip = %tunnel_ip,
        san_count = san_ips.len(),
        "identified X.509 peer by SAN IPs"
    );

    Some(PeerConfig {
        spki_der: peer_cert.as_ref().to_vec(),
        tunnel_ip,
        allowed_ips,
        keepalive: None,
    })
}

/// Keys extracted from a completed quinn-proto handshake.
pub struct ExtractedKeys {
    pub keys: crypto::Keys,
    pub key_gens: VecDeque<crypto::KeyPair<Box<dyn quinn_proto::crypto::PacketKey>>>,
    pub local_cid: quinn_proto::ConnectionId,
    pub remote_cid: quinn_proto::ConnectionId,
}

/// Extract 1-RTT keys and pre-compute ~1000 key generations from a connected
/// quinn-proto `Connection`.
///
/// This is the shared implementation used by both `proto_driver` (tokio) and
/// `MultiQuicState::extract_connection` (DPDK).
pub fn extract_1rtt_keys(conn: &mut quinn_proto::Connection) -> Option<ExtractedKeys> {
    let keys = conn.take_1rtt_keys()?;
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

    Some(ExtractedKeys {
        keys,
        key_gens,
        local_cid,
        remote_cid,
    })
}

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
    /// so direct comparison works. Empty for X.509 mode.
    pub spki_der: Vec<u8>,
    /// Certificate CN or SAN DNS name (X.509 mode). Used to match peers
    /// during handshake. Empty for RPK mode.
    pub cn: String,
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
/// Dispatches to RPK (SPKI DER match) or X.509 (CN/SAN DNS match) based on
/// whether peers have `cn` or `spki_der` populated. The engine doesn't need
/// to know which auth mode is in use — this function handles both.
pub fn identify_peer<'a>(
    conn: &quinn_proto::Connection,
    peers: &'a [PeerConfig],
) -> Option<&'a PeerConfig> {
    let identity = conn.crypto_session().peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer<'static>> = identity.downcast_ref()?;
    let peer_cert = certs.first()?;

    // Try RPK match first (SPKI DER comparison).
    let rpk_match = peers.iter().find(|p| {
        !p.spki_der.is_empty() && p.spki_der == peer_cert.as_ref()
    });
    if rpk_match.is_some() {
        return rpk_match;
    }

    // Try X.509 CN/SAN DNS match.
    identify_peer_x509_inner(peer_cert.as_ref(), peers)
}

/// X.509 peer matching: cert CN or SAN DNS name against `peer.cn` field.
fn identify_peer_x509_inner<'a>(
    cert_der: &[u8],
    peers: &'a [PeerConfig],
) -> Option<&'a PeerConfig> {
    let (_, x509) = x509_parser::parse_x509_certificate(cert_der).ok()?;

    let cert_cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok());

    let mut san_dns: Vec<&str> = Vec::new();
    for ext in x509.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    san_dns.push(dns);
                }
            }
        }
    }

    // Match peer.cn against both Subject CN and SAN DNS names (case-insensitive).
    // Note: RFC 6125 SAN-over-CN applies to TLS hostname verification (handled
    // by rustls). This is application-level config lookup — the admin sets
    // peer.cn to whatever name they want to match, regardless of where it
    // appears in the cert.
    //
    // Limitation: wildcard certs (e.g., *.example.com) require peer.cn to use
    // the same wildcard pattern. Literal expansion is not supported — use
    // cn = "*.example.com" in config to match a wildcard cert.
    let matched = peers.iter().find(|p| {
        if p.cn.is_empty() {
            return false;
        }
        let cn_lower = p.cn.to_ascii_lowercase();
        cert_cn.is_some_and(|c| c.eq_ignore_ascii_case(&cn_lower))
            || san_dns
                .iter()
                .any(|&name| name.eq_ignore_ascii_case(&cn_lower))
    });

    if let Some(p) = matched {
        info!(
            cn = %p.cn,
            tunnel_ip = %p.tunnel_ip,
            "identified X.509 peer by CN/SAN DNS"
        );
    }

    matched
}

/// Legacy X.509 identify — delegates to unified identify_peer.
/// Kept for API compatibility; callers should prefer `identify_peer`.
#[deprecated(note = "use identify_peer() which handles both RPK and X.509")]
pub fn identify_peer_x509<'a>(
    conn: &quinn_proto::Connection,
    peers: &'a [PeerConfig],
) -> Option<&'a PeerConfig> {
    let identity = conn.crypto_session().peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer<'static>> = identity.downcast_ref()?;
    let peer_cert = certs.first()?;

    let (_, x509) = x509_parser::parse_x509_certificate(peer_cert.as_ref()).ok()?;

    // Extract Subject CN.
    let cert_cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok());

    // Extract SAN DNS names.
    let mut san_dns: Vec<&str> = Vec::new();
    for ext in x509.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    san_dns.push(dns);
                }
            }
        }
    }

    // Match: cert CN or any SAN DNS name against peer.cn
    let matched = peers.iter().find(|p| {
        if p.cn.is_empty() {
            return false;
        }
        cert_cn == Some(p.cn.as_str()) || san_dns.iter().any(|&name| name == p.cn)
    });

    if let Some(p) = matched {
        info!(
            cn = %p.cn,
            tunnel_ip = %p.tunnel_ip,
            "identified X.509 peer by CN/SAN DNS"
        );
    }

    matched
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

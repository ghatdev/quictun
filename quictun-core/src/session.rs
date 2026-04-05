//! Session assembly: validated config → ready-to-use engine inputs.
//!
//! Replaces the ad-hoc peer resolution and config assembly that previously
//! lived in `quictun-cli/src/up.rs`, enabling reuse across backends (kernel,
//! DPDK) and embedding quictun-net as a library.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;

use crate::config::{Config, CipherSuite, Mode};
use crate::connection::{CongestionControl, TransportTuning};
use crate::engine::EndpointSetup;
use crate::peer;
use crate::proto_config;

/// Resolved peer ready for engine use.
///
/// Produced by [`resolve_peers`] with strict validation (no silent drops).
pub use peer::PeerConfig as ResolvedPeer;

/// Parse and validate all peer configs from a loaded [`Config`].
///
/// Unlike the previous CLI-level code, this function:
/// - Returns an error on any invalid CIDR in `allowed_ips` (no silent `filter_map`)
/// - Rejects peers with empty `allowed_ips` (fail-closed)
/// - Derives `tunnel_ip` from the first `allowed_ips` entry
pub fn resolve_peers(
    config: &Config,
    peer_spki_ders: &[Vec<u8>],
) -> Result<Vec<peer::PeerConfig>> {
    let raw_peers = config.all_peers();
    if raw_peers.len() != peer_spki_ders.len() {
        bail!(
            "peer count mismatch: config has {} peers but {} SPKI DERs provided",
            raw_peers.len(),
            peer_spki_ders.len()
        );
    }

    raw_peers
        .iter()
        .zip(peer_spki_ders.iter())
        .enumerate()
        .map(|(i, (raw, spki_der))| {
            if raw.allowed_ips.is_empty() {
                bail!("peer[{i}]: allowed_ips must not be empty");
            }

            let allowed_ips: Vec<Ipv4Net> = raw
                .allowed_ips
                .iter()
                .enumerate()
                .map(|(j, s)| {
                    s.parse::<Ipv4Net>().with_context(|| {
                        format!("peer[{i}].allowed_ips[{j}]: invalid CIDR \"{s}\"")
                    })
                })
                .collect::<Result<_>>()?;

            let tunnel_ip: Ipv4Addr = allowed_ips[0].addr();

            Ok(peer::PeerConfig {
                spki_der: spki_der.clone(),
                cn: String::new(),
                tunnel_ip,
                allowed_ips,
                keepalive: raw.keepalive.map(Duration::from_secs),
            })
        })
        .collect()
}

/// Parse and validate peer configs for X.509 mode.
///
/// Populates the `cn` field from config for peer identification at handshake.
/// For connector mode, `cn` defaults to `server_name` if not explicitly set.
/// SPKI DER is left empty — X.509 uses CN/SAN DNS matching instead.
pub fn resolve_peers_x509(config: &Config) -> Result<Vec<peer::PeerConfig>> {
    let raw_peers = config.all_peers();
    // For connector, default cn from server_name so identify_peer works.
    let default_cn = config.interface.server_name.clone().unwrap_or_default();

    raw_peers
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            if raw.allowed_ips.is_empty() {
                bail!("peer[{i}]: allowed_ips must not be empty");
            }

            let allowed_ips: Vec<Ipv4Net> = raw
                .allowed_ips
                .iter()
                .enumerate()
                .map(|(j, s)| {
                    s.parse::<Ipv4Net>().with_context(|| {
                        format!("peer[{i}].allowed_ips[{j}]: invalid CIDR \"{s}\"")
                    })
                })
                .collect::<Result<_>>()?;

            let tunnel_ip: Ipv4Addr = allowed_ips[0].addr();

            Ok(peer::PeerConfig {
                spki_der: Vec::new(),
                cn: if raw.cn.is_empty() { default_cn.clone() } else { raw.cn.clone() },
                tunnel_ip,
                allowed_ips,
                keepalive: raw.keepalive.map(Duration::from_secs),
            })
        })
        .collect()
}

/// Build [`TransportTuning`] from a loaded [`Config`], with validation.
pub fn build_transport_tuning(config: &Config) -> Result<TransportTuning> {
    let cc: CongestionControl = config
        .engine
        .cc
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Validate idle timeout range at config time (prevents runtime panic in
    // quinn::IdleTimeout::try_from).
    if config.interface.max_idle_timeout_ms > 0 {
        quinn::IdleTimeout::try_from(Duration::from_millis(
            config.interface.max_idle_timeout_ms,
        ))
        .map_err(|_| {
            anyhow::anyhow!(
                "max_idle_timeout_ms {} exceeds maximum allowed value",
                config.interface.max_idle_timeout_ms
            )
        })?;
    }

    Ok(TransportTuning {
        datagram_recv_buffer: config.engine.recv_buf,
        datagram_send_buffer: config.engine.send_buf,
        send_window: config.engine.send_window,
        cc,
        max_idle_timeout_ms: config.interface.max_idle_timeout_ms,
        initial_rtt_ms: config.engine.initial_rtt_ms,
        pin_mtu: config.engine.pin_mtu,
        ..Default::default()
    })
}

/// Resolve cipher suites from config.
pub fn resolve_cipher_suites(config: &Config) -> Result<(Vec<CipherSuite>, Vec<CipherSuite>)> {
    let server = config.server_cipher_suites()?;
    let client = config.client_cipher_suites()?;
    Ok((server, client))
}

/// Compute the idle timeout [`Duration`] from config.
pub fn idle_timeout(config: &Config) -> Duration {
    if config.interface.max_idle_timeout_ms > 0 {
        Duration::from_millis(config.interface.max_idle_timeout_ms)
    } else {
        Duration::from_secs(30)
    }
}

/// Whether this config uses X.509/CA authentication.
pub fn is_x509(config: &Config) -> bool {
    config.interface.auth_mode == "x509"
}

/// Whether reconnection is enabled for this config.
pub fn reconnect_enabled(config: &Config) -> bool {
    config
        .all_peers()
        .first()
        .and_then(|p| p.reconnect_interval)
        .is_some()
}

/// Get the reconnect interval in seconds (minimum 1s).
pub fn reconnect_interval_secs(config: &Config) -> u64 {
    config
        .all_peers()
        .first()
        .and_then(|p| p.reconnect_interval)
        .unwrap_or(1)
        .max(1) // Clamp to prevent busy-loop on reconnect_interval = 0
}

/// Resolve all peers from config (handles both RPK and X.509).
pub fn resolve_all_peers(config: &Config) -> Result<Vec<peer::PeerConfig>> {
    if is_x509(config) {
        resolve_peers_x509(config)
    } else {
        let raw_peers = config.all_peers();
        let peer_pubkeys: Vec<quictun_crypto::PublicKey> = raw_peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                quictun_crypto::PublicKey::from_base64(&p.public_key)
                    .with_context(|| format!("invalid public_key for peer[{i}]"))
            })
            .collect::<Result<_>>()?;
        let spki_ders: Vec<Vec<u8>> =
            peer_pubkeys.iter().map(|pk| pk.spki_der().to_vec()).collect();
        resolve_peers(config, &spki_ders)
    }
}

/// Build the QUIC endpoint setup from config (handles both RPK and X.509).
///
/// Resolves crypto keys, builds quinn-proto ClientConfig/ServerConfig,
/// and returns a ready-to-use `EndpointSetup`.
pub fn build_endpoint_setup(config: &Config) -> Result<EndpointSetup> {
    let mode = config.mode();
    let peers = config.all_peers();
    let tuning = build_transport_tuning(config)?;
    let (server_ciphers, client_ciphers) = resolve_cipher_suites(config)?;
    let first_keepalive = peers.first().and_then(|p| p.keepalive.map(Duration::from_secs));
    let pq = config.interface.post_quantum;

    if is_x509(config) {
        let cert_file = Path::new(
            config.interface.cert_file.as_ref().context("x509 mode requires cert_file")?,
        );
        let key_file = Path::new(
            config.interface.key_file.as_ref().context("x509 mode requires key_file")?,
        );
        let ca_file = Path::new(
            config.interface.ca_file.as_ref().context("x509 mode requires ca_file")?,
        );

        match mode {
            Mode::Listener => {
                let server_config = proto_config::build_proto_server_config_x509(
                    cert_file, key_file, ca_file, first_keepalive,
                    &tuning, &server_ciphers, pq,
                )?;
                Ok(EndpointSetup::Listener { server_config })
            }
            Mode::Connector => {
                let peer = &peers[0];
                let keepalive = peer.keepalive.map(Duration::from_secs);
                let client_config = proto_config::build_proto_client_config_x509(
                    cert_file, key_file, ca_file, keepalive,
                    &tuning, &client_ciphers, config.interface.zero_rtt, pq,
                )?;
                let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
                Ok(EndpointSetup::Connector { remote_addr, client_config })
            }
        }
    } else {
        let private_key = quictun_crypto::PrivateKey::from_base64(&config.interface.private_key)
            .context("invalid interface private_key")?;
        let peer_pubkeys: Vec<quictun_crypto::PublicKey> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                quictun_crypto::PublicKey::from_base64(&p.public_key)
                    .with_context(|| format!("invalid public_key for peer[{i}]"))
            })
            .collect::<Result<_>>()?;

        match mode {
            Mode::Listener => {
                let server_config = proto_config::build_proto_server_config(
                    &private_key, &peer_pubkeys, first_keepalive,
                    &tuning, &server_ciphers, pq,
                )?;
                Ok(EndpointSetup::Listener { server_config })
            }
            Mode::Connector => {
                let peer = &peers[0];
                let peer_pubkey = &peer_pubkeys[0];
                let keepalive = peer.keepalive.map(Duration::from_secs);
                let client_config = proto_config::build_proto_client_config(
                    &private_key, peer_pubkey, keepalive,
                    &tuning, &client_ciphers, config.interface.zero_rtt, pq,
                )?;
                let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
                Ok(EndpointSetup::Connector { remote_addr, client_config })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn make_config(allowed_ips: Vec<&str>) -> Config {
        let toml = format!(
            r#"
[interface]
mode = "connector"
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.0.0.1/24"

[peer]
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
endpoint = "1.2.3.4:51820"
allowed_ips = [{ips}]
"#,
            ips = allowed_ips
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn reject_empty_allowed_ips() {
        let config = make_config(vec![]);
        let spki = vec![vec![0u8; 32]];
        let result = resolve_peers(&config, &spki);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
    }

    #[test]
    fn reject_invalid_cidr() {
        let config = make_config(vec!["not-a-cidr"]);
        let spki = vec![vec![0u8; 32]];
        let result = resolve_peers(&config, &spki);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid CIDR"));
    }

    #[test]
    fn valid_peer_resolution() {
        let config = make_config(vec!["10.0.0.2/32", "10.0.1.0/24"]);
        let spki = vec![vec![0u8; 32]];
        let result = resolve_peers(&config, &spki).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tunnel_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(result[0].allowed_ips.len(), 2);
    }
}

//! Session assembly: validated config → ready-to-use engine inputs.
//!
//! Replaces the ad-hoc peer resolution and config assembly that previously
//! lived in `quictun-cli/src/up.rs`, enabling reuse across backends (kernel,
//! DPDK) and embedding quictun-net as a library.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;

use crate::config::{Config, CipherSuite};
use crate::connection::{CongestionControl, TransportTuning};
use crate::peer;

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

/// Whether reconnection is enabled for this config.
pub fn reconnect_enabled(config: &Config) -> bool {
    config
        .all_peers()
        .first()
        .and_then(|p| p.reconnect_interval)
        .is_some()
}

/// Get the reconnect interval in seconds (or default 1s).
pub fn reconnect_interval_secs(config: &Config) -> u64 {
    config
        .all_peers()
        .first()
        .and_then(|p| p.reconnect_interval)
        .unwrap_or(1)
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

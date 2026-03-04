use std::net::SocketAddr;
use std::path::Path;

use ipnet::Ipv4Net;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Top-level tunnel configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub peer: Vec<PeerConfig>,
}

/// Local interface configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub address: String,
    pub listen_port: Option<u16>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Optional explicit interface name (e.g. "connector"). If omitted,
    /// `Config::interface_name()` derives it from the config filename.
    pub name: Option<String>,
    /// Max QUIC idle timeout in milliseconds. 0 = quinn default.
    #[serde(default)]
    pub max_idle_timeout_ms: u64,
    /// Enable FIPS-only ciphersuites (AES-GCM + P-256/P-384, no ChaCha20/x25519).
    /// Requires the `fips` cargo feature.
    #[serde(default)]
    pub fips_mode: bool,
    /// QUIC Connection ID length in bytes. Valid values: 0, 4, 8. Default 8.
    #[serde(default = "default_cid_length")]
    pub cid_length: u8,
    /// Enable 0-RTT session resumption on reconnect (connector only).
    #[serde(default)]
    pub zero_rtt: bool,
    /// Authentication mode: "rpk" (default) or "x509".
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    /// PEM certificate chain file (x509 mode).
    pub cert_file: Option<String>,
    /// PEM private key file (x509 mode, alternative to base64 private_key).
    pub key_file: Option<String>,
    /// PEM CA bundle for peer verification (x509 mode).
    pub ca_file: Option<String>,
}

fn default_mtu() -> u16 {
    1380
}

fn default_cid_length() -> u8 {
    8
}

fn default_auth_mode() -> String {
    "rpk".to_owned()
}

/// Remote peer configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u64>,
    /// Auto-reconnect interval in seconds. None = no auto-reconnect (process exits on drop).
    #[serde(default)]
    pub reconnect_interval: Option<u64>,
}

/// Whether this node acts as a listener (server) or connector (client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Listener,
    Connector,
}

impl Config {
    /// Load and validate configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.peer.is_empty() {
            return Err(ConfigError::Invalid("at least one peer is required".into()));
        }
        // Connector mode requires exactly one peer (with endpoint).
        // Listener mode supports multiple peers (multi-client).
        if self.peer.len() > 1 && self.role() == Role::Connector {
            return Err(ConfigError::Invalid(
                "connector mode supports exactly one peer".into(),
            ));
        }
        // Validate address parses as IPv4 network
        self.parse_address()?;

        // Validate CID length
        match self.interface.cid_length {
            0 | 4 | 8 => {}
            other => {
                return Err(ConfigError::Invalid(format!(
                    "cid_length must be 0, 4, or 8 (got {other})"
                )));
            }
        }

        // Validate auth_mode
        match self.interface.auth_mode.as_str() {
            "rpk" => {}
            "x509" => {
                if self.interface.cert_file.is_none() {
                    return Err(ConfigError::Invalid(
                        "auth_mode = \"x509\" requires cert_file".into(),
                    ));
                }
                if self.interface.key_file.is_none() {
                    return Err(ConfigError::Invalid(
                        "auth_mode = \"x509\" requires key_file".into(),
                    ));
                }
                if self.interface.ca_file.is_none() {
                    return Err(ConfigError::Invalid(
                        "auth_mode = \"x509\" requires ca_file".into(),
                    ));
                }
            }
            other => {
                return Err(ConfigError::Invalid(format!(
                    "auth_mode must be \"rpk\" or \"x509\" (got \"{other}\")"
                )));
            }
        }

        Ok(())
    }

    /// Determine the role based on the first peer's endpoint.
    pub fn role(&self) -> Role {
        if self.peer[0].endpoint.is_some() {
            Role::Connector
        } else {
            Role::Listener
        }
    }

    /// Parse the interface address as an IPv4 network (e.g. "10.0.0.1/24").
    pub fn parse_address(&self) -> Result<Ipv4Net, ConfigError> {
        self.interface.address.parse::<Ipv4Net>().map_err(|e| {
            ConfigError::Invalid(format!("invalid address '{}': {e}", self.interface.address))
        })
    }

    /// Return the configured MTU.
    pub fn mtu(&self) -> u16 {
        self.interface.mtu
    }

    /// Return the interface name: explicit `name` if set, otherwise derived
    /// from the config filename (e.g. `connector.toml` → `connector`).
    pub fn interface_name(&self, config_path: &Path) -> String {
        if let Some(ref name) = self.interface.name {
            return name.clone();
        }
        config_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("quictun")
            .to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listener_config() {
        let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.role(), Role::Listener);
    }

    #[test]
    fn parse_connector_config() {
        let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
keepalive = 25
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.role(), Role::Connector);
        assert_eq!(config.mtu(), 1380);
    }

    #[test]
    fn default_mtu_is_1380() {
        let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.mtu(), 1380);
    }

    #[test]
    fn rejects_no_peers() {
        let config = Config {
            interface: InterfaceConfig {
                private_key: "dGVzdA==".into(),
                address: "10.0.0.1/24".into(),
                listen_port: None,
                mtu: 1380,
                name: None,
                max_idle_timeout_ms: 0,
                fips_mode: false,
                cid_length: 8,
                zero_rtt: false,
                auth_mode: "rpk".into(),
                cert_file: None,
                key_file: None,
                ca_file: None,
            },
            peer: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn multi_peer_listener_allowed() {
        let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]

[[peer]]
public_key = "dGVzdB=="
allowed_ips = ["10.0.0.3/32"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.role(), Role::Listener);
        assert_eq!(config.peer.len(), 2);
    }

    #[test]
    fn multi_peer_connector_rejected() {
        let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"

[[peer]]
public_key = "dGVzdB=="
allowed_ips = ["10.0.0.3/32"]
endpoint = "1.2.3.5:443"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"
bogus_field = true

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }
}

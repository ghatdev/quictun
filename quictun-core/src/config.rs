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
}

fn default_mtu() -> u16 {
    1380
}

/// Remote peer configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u64>,
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
        if self.peer.len() > 1 {
            return Err(ConfigError::Invalid(
                "phase 1 supports exactly one peer".into(),
            ));
        }
        // Validate address parses as IPv4 network
        self.parse_address()?;
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
            },
            peer: vec![],
        };
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

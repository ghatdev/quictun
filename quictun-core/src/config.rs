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

// ── Cipher suite ─────────────────────────────────────────────────────────────

/// TLS 1.3 cipher suite for QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20,
}

impl CipherSuite {
    /// Parse a cipher suite name from the config file.
    pub fn from_name(name: &str) -> Result<Self, ConfigError> {
        match name {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20" => Ok(Self::ChaCha20),
            other => Err(ConfigError::Invalid(format!(
                "unknown cipher: \"{other}\" (expected \"aes-128-gcm\", \"aes-256-gcm\", or \"chacha20\")"
            ))),
        }
    }

    /// All supported cipher suites in default preference order.
    pub fn all() -> Vec<Self> {
        vec![Self::Aes128Gcm, Self::Aes256Gcm, Self::ChaCha20]
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "aes-128-gcm"),
            Self::Aes256Gcm => write!(f, "aes-256-gcm"),
            Self::ChaCha20 => write!(f, "chacha20"),
        }
    }
}

// ── Mode ─────────────────────────────────────────────────────────────────────

/// Tunnel operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Listener,
    Connector,
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "listener" => Ok(Mode::Listener),
            "connector" => Ok(Mode::Connector),
            other => Err(serde::de::Error::custom(format!(
                "unknown mode: \"{other}\" (expected \"listener\" or \"connector\")"
            ))),
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listener => write!(f, "listener"),
            Self::Connector => write!(f, "connector"),
        }
    }
}

// ── Engine backend ───────────────────────────────────────────────────────────

/// Data plane backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Kernel,
    DpdkVirtio,
    DpdkRouter,
}

impl<'de> Deserialize<'de> for Backend {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "kernel" => Ok(Backend::Kernel),
            "dpdk-virtio" => Ok(Backend::DpdkVirtio),
            "dpdk-router" => Ok(Backend::DpdkRouter),
            other => Err(serde::de::Error::custom(format!(
                "unknown backend: \"{other}\" (expected \"kernel\", \"dpdk-virtio\", or \"dpdk-router\")"
            ))),
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kernel => write!(f, "kernel"),
            Self::DpdkVirtio => write!(f, "dpdk-virtio"),
            Self::DpdkRouter => write!(f, "dpdk-router"),
        }
    }
}

fn default_backend() -> Backend {
    Backend::Kernel
}

// ── Top-level config ─────────────────────────────────────────────────────────

/// Top-level tunnel configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    pub routing: Option<RoutingConfig>,
    /// Single peer (connector mode). Use `[peer]` in TOML.
    pub peer: Option<PeerConfig>,
    /// Multiple peers (listener mode). Use `[[peers]]` in TOML.
    pub peers: Option<Vec<PeerConfig>>,
}

/// Local interface configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub mode: Mode,
    /// Base64-encoded private key (RPK mode). Optional for X.509 mode.
    #[serde(default)]
    pub private_key: String,
    pub address: String,
    pub listen_port: Option<u16>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub name: Option<String>,
    #[serde(default)]
    pub max_idle_timeout_ms: u64,
    #[serde(default = "default_cid_length")]
    pub cid_length: u8,
    /// Preferred cipher suite for outbound connections (connector, or listener initiating).
    /// Single value: "aes-128-gcm", "aes-256-gcm", or "chacha20".
    pub cipher: Option<String>,
    /// Accepted cipher suites for inbound connections (listener).
    /// Array of: "aes-128-gcm", "aes-256-gcm", "chacha20".
    pub ciphers: Option<Vec<String>>,
    #[serde(default)]
    pub zero_rtt: bool,
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
}

/// Engine / data plane configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    #[serde(default = "default_backend")]
    pub backend: Backend,
    #[serde(default = "default_threads")]
    pub threads: usize,
    #[serde(default = "default_cc")]
    pub cc: String,
    #[serde(default = "default_buf_size")]
    pub recv_buf: usize,
    #[serde(default = "default_buf_size")]
    pub send_buf: usize,
    #[serde(default)]
    pub send_window: u64,
    #[serde(default)]
    pub initial_rtt_ms: u64,
    #[serde(default)]
    pub pin_mtu: bool,
    #[serde(default)]
    pub offload: bool,
    #[serde(default = "default_dpdk_cores")]
    pub dpdk_cores: usize,
    pub dpdk_local_ip: Option<String>,
    pub dpdk_local_port: Option<u16>,
    #[serde(default = "default_dpdk_eal_args")]
    pub dpdk_eal_args: String,
    #[serde(default)]
    pub dpdk_port: u16,
    #[serde(default)]
    pub no_udp_checksum: bool,
    #[serde(default = "default_adaptive_poll")]
    pub adaptive_poll: bool,
    /// recvmmsg/sendmmsg batch count.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// UDP GSO segments per sendmsg.
    #[serde(default = "default_gso_max_segments")]
    pub gso_max_segments: usize,
    /// Packets between ACK generation.
    #[serde(default = "default_ack_interval")]
    pub ack_interval: u32,
    /// Standalone ACK timer interval in milliseconds.
    #[serde(default = "default_ack_timer_ms")]
    pub ack_timer_ms: u32,
    /// TUN write backpressure buffer (packets).
    #[serde(default = "default_tun_write_buf")]
    pub tun_write_buf: usize,
    /// Dispatcher↔worker channel size (multi-thread).
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    /// mio Events capacity.
    #[serde(default = "default_poll_events")]
    pub poll_events: usize,
    /// Maximum number of concurrent peer connections (listener mode).
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Kernel,
            threads: 1,
            cc: "bbr".to_owned(),
            recv_buf: 8 * 1024 * 1024,
            send_buf: 8 * 1024 * 1024,
            send_window: 0,
            initial_rtt_ms: 0,
            pin_mtu: false,
            offload: false,
            dpdk_cores: 1,
            dpdk_local_ip: None,
            dpdk_local_port: None,
            dpdk_eal_args: "-l;0;-n;4".to_owned(),
            dpdk_port: 0,
            no_udp_checksum: false,
            adaptive_poll: true,
            batch_size: 64,
            gso_max_segments: 44,
            ack_interval: 64,
            ack_timer_ms: 20,
            tun_write_buf: 256,
            channel_capacity: 4096,
            poll_events: 64,
            max_peers: 256,
        }
    }
}

/// Router-mode configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub nat: bool,
    #[serde(default)]
    pub mss_clamp: u16,
}

/// Remote peer configuration.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Base64-encoded public key (RPK mode). Optional for X.509 mode.
    #[serde(default)]
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u64>,
    #[serde(default)]
    pub reconnect_interval: Option<u64>,
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

fn default_threads() -> usize {
    1
}

fn default_cc() -> String {
    "bbr".to_owned()
}

fn default_buf_size() -> usize {
    8 * 1024 * 1024
}

fn default_dpdk_cores() -> usize {
    1
}

fn default_dpdk_eal_args() -> String {
    "-l;0;-n;4".to_owned()
}

fn default_adaptive_poll() -> bool {
    true
}

fn default_batch_size() -> usize {
    64
}

fn default_gso_max_segments() -> usize {
    44
}

fn default_ack_interval() -> u32 {
    64
}

fn default_ack_timer_ms() -> u32 {
    20
}

fn default_tun_write_buf() -> usize {
    256
}

fn default_channel_capacity() -> usize {
    4096
}

fn default_poll_events() -> usize {
    64
}

fn default_max_peers() -> usize {
    256
}

fn default_true() -> bool {
    true
}

// ── Config methods ───────────────────────────────────────────────────────────

impl Config {
    /// Load and validate configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Parse from a TOML string and validate.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(s).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mode = self.interface.mode;
        let is_x509 = self.interface.auth_mode == "x509";

        // ── Peer validation ──
        match mode {
            Mode::Connector => {
                if self.peers.is_some() {
                    return Err(ConfigError::Invalid(
                        "connector mode uses [peer], not [[peers]]".into(),
                    ));
                }
                let peer = self.peer.as_ref().ok_or_else(|| {
                    ConfigError::Invalid("connector mode requires [peer] section".into())
                })?;
                if peer.endpoint.is_none() {
                    return Err(ConfigError::Invalid(
                        "connector peer requires endpoint".into(),
                    ));
                }
                if !is_x509 && peer.public_key.is_empty() {
                    return Err(ConfigError::Invalid(
                        "RPK mode requires peer public_key".into(),
                    ));
                }
            }
            Mode::Listener => {
                if self.peer.is_some() {
                    return Err(ConfigError::Invalid(
                        "listener mode uses [[peers]], not [peer]".into(),
                    ));
                }
                if is_x509 {
                    // X.509 listener: [[peers]] is optional — peers discovered by cert SAN.
                } else {
                    let peers = self.peers.as_ref().ok_or_else(|| {
                        ConfigError::Invalid("listener mode requires [[peers]] section".into())
                    })?;
                    if peers.is_empty() {
                        return Err(ConfigError::Invalid(
                            "listener requires at least one peer".into(),
                        ));
                    }
                }
            }
        }

        // ── listen_port ──
        match mode {
            Mode::Connector => {
                if self.interface.listen_port.is_some() {
                    return Err(ConfigError::Invalid(
                        "connector mode must not set listen_port".into(),
                    ));
                }
            }
            Mode::Listener => {
                if self.interface.listen_port.is_none() {
                    return Err(ConfigError::Invalid(
                        "listener mode requires listen_port".into(),
                    ));
                }
            }
        }

        // ── Cipher validation ──
        if let Some(ref cipher) = self.interface.cipher {
            CipherSuite::from_name(cipher)?;
        }
        if let Some(ref ciphers) = self.interface.ciphers {
            if ciphers.is_empty() {
                return Err(ConfigError::Invalid("ciphers must not be empty".into()));
            }
            for c in ciphers {
                CipherSuite::from_name(c)?;
            }
        }

        // ── zero_rtt only for connector ──
        if mode == Mode::Listener && self.interface.zero_rtt {
            return Err(ConfigError::Invalid(
                "zero_rtt is only valid for connector mode".into(),
            ));
        }

        // ── Address validation ──
        self.parse_address()?;

        // ── CID length ──
        match self.interface.cid_length {
            0 | 4 | 8 => {}
            other => {
                return Err(ConfigError::Invalid(format!(
                    "cid_length must be 0, 4, or 8 (got {other})"
                )));
            }
        }

        // ── Auth mode ──
        match self.interface.auth_mode.as_str() {
            "rpk" => {
                if self.interface.private_key.is_empty() {
                    return Err(ConfigError::Invalid(
                        "RPK mode requires private_key".into(),
                    ));
                }
            }
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

        // ── Backend validation ──
        let backend = self.engine.backend;
        if mode == Mode::Connector && backend == Backend::DpdkRouter {
            return Err(ConfigError::Invalid(
                "connector mode cannot use dpdk-router backend".into(),
            ));
        }

        // ── Routing section validation ──
        if self.routing.is_some() && backend != Backend::DpdkRouter {
            return Err(ConfigError::Invalid(
                "[routing] section requires backend = \"dpdk-router\"".into(),
            ));
        }

        // ── DPDK field validation ──
        if backend != Backend::Kernel {
            if self.engine.dpdk_local_ip.is_none() {
                return Err(ConfigError::Invalid(
                    "DPDK backends require dpdk_local_ip in [engine]".into(),
                ));
            }
        }

        Ok(())
    }

    /// Operating mode.
    pub fn mode(&self) -> Mode {
        self.interface.mode
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

    /// Get all peer configs as a slice, regardless of mode.
    pub fn all_peers(&self) -> &[PeerConfig] {
        if let Some(ref peers) = self.peers {
            peers
        } else if let Some(ref peer) = self.peer {
            std::slice::from_ref(peer)
        } else {
            &[]
        }
    }

    /// Resolve cipher suites for server (inbound) TLS config.
    /// Uses `ciphers` if set, otherwise all.
    pub fn server_cipher_suites(&self) -> Result<Vec<CipherSuite>, ConfigError> {
        match &self.interface.ciphers {
            Some(names) => names.iter().map(|n| CipherSuite::from_name(n)).collect(),
            None => Ok(CipherSuite::all()),
        }
    }

    /// Resolve cipher suites for client (outbound) TLS config.
    /// Uses `cipher` if set, otherwise all.
    pub fn client_cipher_suites(&self) -> Result<Vec<CipherSuite>, ConfigError> {
        match &self.interface.cipher {
            Some(name) => Ok(vec![CipherSuite::from_name(name)?]),
            None => Ok(CipherSuite::all()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listener_config() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .unwrap();
        assert_eq!(config.mode(), Mode::Listener);
    }

    #[test]
    fn parse_connector_config() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
keepalive = 25
"#,
        )
        .unwrap();
        assert_eq!(config.mode(), Mode::Connector);
        assert_eq!(config.mtu(), 1380);
    }

    #[test]
    fn default_mtu_is_1380() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .unwrap();
        assert_eq!(config.mtu(), 1380);
    }

    #[test]
    fn connector_rejects_no_peer() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn connector_rejects_peers_array() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn connector_rejects_no_endpoint() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn listener_rejects_single_peer() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn listener_requires_listen_port() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn connector_rejects_listen_port() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"
listen_port = 443

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn multi_peer_listener() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]

[[peers]]
public_key = "dGVzdB=="
allowed_ips = ["10.0.0.3/32"]
"#,
        )
        .unwrap();
        assert_eq!(config.mode(), Mode::Listener);
        assert_eq!(config.all_peers().len(), 2);
    }

    #[test]
    fn cipher_selection() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"
cipher = "chacha20"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        )
        .unwrap();
        let suites = config.client_cipher_suites().unwrap();
        assert_eq!(suites, vec![CipherSuite::ChaCha20]);
    }

    #[test]
    fn ciphers_selection() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443
ciphers = ["aes-256-gcm", "chacha20"]

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .unwrap();
        let suites = config.server_cipher_suites().unwrap();
        assert_eq!(suites, vec![CipherSuite::Aes256Gcm, CipherSuite::ChaCha20]);
    }

    #[test]
    fn invalid_cipher_rejected() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"
cipher = "rc4"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443
bogus_field = true

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn connector_rejects_dpdk_router() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[engine]
backend = "dpdk-virtio"
dpdk_local_ip = "10.23.30.100"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        );
        // dpdk-virtio is fine for connector
        assert!(result.is_ok());

        let result = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[engine]
backend = "dpdk-router"
dpdk_local_ip = "10.23.30.100"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn routing_requires_dpdk_router() {
        let result = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[routing]
nat = true

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn engine_defaults() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .unwrap();
        assert_eq!(config.engine.backend, Backend::Kernel);
        assert_eq!(config.engine.threads, 1);
        assert_eq!(config.engine.cc, "bbr");
        assert_eq!(config.engine.recv_buf, 8 * 1024 * 1024);
    }

    #[test]
    fn all_peers_connector() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
"#,
        )
        .unwrap();
        assert_eq!(config.all_peers().len(), 1);
    }

    #[test]
    fn default_cipher_suites() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .unwrap();
        let server_suites = config.server_cipher_suites().unwrap();
        assert_eq!(server_suites, CipherSuite::all());
        let client_suites = config.client_cipher_suites().unwrap();
        assert_eq!(client_suites, CipherSuite::all());
    }

    #[test]
    fn listener_with_cipher_for_outbound() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443
cipher = "aes-256-gcm"
ciphers = ["aes-256-gcm", "chacha20"]

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
endpoint = "2.3.4.5:443"
keepalive = 25
"#,
        )
        .unwrap();
        let server = config.server_cipher_suites().unwrap();
        assert_eq!(server, vec![CipherSuite::Aes256Gcm, CipherSuite::ChaCha20]);
        let client = config.client_cipher_suites().unwrap();
        assert_eq!(client, vec![CipherSuite::Aes256Gcm]);
    }

    #[test]
    fn reconnect_interval_parses() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "connector"
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[peer]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
reconnect_interval = 5
"#,
        )
        .unwrap();
        assert_eq!(config.all_peers()[0].reconnect_interval, Some(5));
    }

    #[test]
    fn dpdk_router_with_routing() {
        let config = Config::from_toml(
            r#"
[interface]
mode = "listener"
private_key = "dGVzdA=="
address = "10.0.0.1/24"
listen_port = 443

[engine]
backend = "dpdk-router"
dpdk_cores = 4
dpdk_local_ip = "10.23.30.100"

[routing]
nat = true
mss_clamp = 1360

[[peers]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .unwrap();
        assert_eq!(config.engine.backend, Backend::DpdkRouter);
        assert_eq!(config.engine.dpdk_cores, 4);
        let routing = config.routing.as_ref().unwrap();
        assert!(routing.nat);
        assert_eq!(routing.mss_clamp, 1360);
    }
}

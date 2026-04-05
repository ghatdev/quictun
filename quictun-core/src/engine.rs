//! Engine trait: unified backend interface.
//!
//! Called once at startup to run the data plane. Zero hot-path overhead —
//! the packet forwarding loop uses concrete types, not trait objects.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use quinn_proto::ServerConfig;

use crate::config::Config;
use crate::peer::PeerConfig;

/// Result of an engine run — tells the CLI whether to reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunResult {
    Shutdown,
    ConnectionLost,
}

/// QUIC endpoint setup: connector (client) or listener (server).
///
/// Built once by `session::build_endpoint_setup()` from the parsed config.
/// Passed to `Engine::run()` — each backend uses the quinn-proto configs
/// to drive the QUIC handshake.
#[derive(Clone)]
pub enum EndpointSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: quinn_proto::ClientConfig,
    },
    Listener {
        server_config: Arc<ServerConfig>,
    },
}

/// Backend engine interface.
///
/// Implementors: `quictun_net::NetEngine`, `quictun_dpdk::DpdkEngine`.
/// Static dispatch — the compiler monomorphizes at the call site.
pub trait Engine {
    fn run(
        &self,
        local_addr: SocketAddr,
        setup: EndpointSetup,
        config: &Config,
        peers: Vec<PeerConfig>,
    ) -> Result<RunResult>;
}

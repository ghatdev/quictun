use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quictun_core::connection::{self, TransportTuning};
use quictun_crypto::{PrivateKey, PublicKey};

/// Build a `quinn_proto::ClientConfig` for the io_uring data plane.
pub fn build_proto_client_config(
    private_key: &PrivateKey,
    server_pubkey: &PublicKey,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<quinn_proto::ClientConfig> {
    let tls = connection::build_rustls_client_tls_config(private_key, server_pubkey)?;
    let quic_crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("failed to create QUIC client crypto config")?;
    let mut config = quinn_proto::ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(Arc::new(connection::make_transport_config(keepalive, tuning)));
    Ok(config)
}

/// Build a `quinn_proto::ServerConfig` for the io_uring data plane.
pub fn build_proto_server_config(
    private_key: &PrivateKey,
    allowed_peers: &[PublicKey],
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<Arc<quinn_proto::ServerConfig>> {
    let tls = connection::build_rustls_server_tls_config(private_key, allowed_peers)?;
    let quic_crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("failed to create QUIC server crypto config")?;
    let mut config = quinn_proto::ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport = Arc::new(connection::make_transport_config(keepalive, tuning));
    Ok(Arc::new(config))
}

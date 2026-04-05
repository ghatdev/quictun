use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::config::CipherSuite;
use crate::connection::{self, TransportTuning};
use quictun_crypto::{PrivateKey, PublicKey};

/// Build a `quinn_proto::ClientConfig` for direct quinn-proto data planes.
///
/// Used by DPDK, io_uring, and tokio `--fast` paths that drive quinn-proto
/// manually instead of through the quinn high-level API.
pub fn build_proto_client_config(
    private_key: &PrivateKey,
    server_pubkey: &PublicKey,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    cipher_suites: &[CipherSuite],
    enable_session_resumption: bool,
    post_quantum: bool,
) -> Result<quinn_proto::ClientConfig> {
    let tls = connection::build_rustls_client_tls_config(
        private_key,
        server_pubkey,
        cipher_suites,
        enable_session_resumption,
        post_quantum,
    )?;
    let quic_crypto = connection::make_quic_client_config(tls, cipher_suites)?;
    let mut config = quinn_proto::ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(Arc::new(connection::make_transport_config(
        keepalive, tuning,
    )));
    Ok(config)
}

/// Build a `quinn_proto::ServerConfig` for direct quinn-proto data planes.
///
/// Used by DPDK, io_uring, and tokio `--fast` paths that drive quinn-proto
/// manually instead of through the quinn high-level API.
pub fn build_proto_server_config(
    private_key: &PrivateKey,
    allowed_peers: &[PublicKey],
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    cipher_suites: &[CipherSuite],
    post_quantum: bool,
) -> Result<Arc<quinn_proto::ServerConfig>> {
    let tls = connection::build_rustls_server_tls_config(private_key, allowed_peers, cipher_suites, post_quantum)?;
    let quic_crypto = connection::make_quic_server_config(tls, cipher_suites)?;
    let mut config = quinn_proto::ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport = Arc::new(connection::make_transport_config(keepalive, tuning));
    Ok(Arc::new(config))
}

// ── X.509 proto config builders ─────────────────────────────────────────────

/// Build a `quinn_proto::ServerConfig` with X.509/CA authentication.
pub fn build_proto_server_config_x509(
    cert_file: &Path,
    key_file: &Path,
    ca_file: &Path,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    cipher_suites: &[CipherSuite],
    post_quantum: bool,
) -> Result<Arc<quinn_proto::ServerConfig>> {
    let tls =
        connection::build_rustls_server_tls_config_x509(cert_file, key_file, ca_file, cipher_suites, post_quantum)?;
    let quic_crypto = connection::make_quic_server_config(tls, cipher_suites)?;
    let mut config = quinn_proto::ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport = Arc::new(connection::make_transport_config(keepalive, tuning));
    Ok(Arc::new(config))
}

/// Build a `quinn_proto::ClientConfig` with X.509/CA authentication.
#[allow(clippy::too_many_arguments)]
pub fn build_proto_client_config_x509(
    cert_file: &Path,
    key_file: &Path,
    ca_file: &Path,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    cipher_suites: &[CipherSuite],
    enable_session_resumption: bool,
    post_quantum: bool,
) -> Result<quinn_proto::ClientConfig> {
    let tls = connection::build_rustls_client_tls_config_x509(
        cert_file,
        key_file,
        ca_file,
        cipher_suites,
        enable_session_resumption,
        post_quantum,
    )?;
    let quic_crypto = connection::make_quic_client_config(tls, cipher_suites)?;
    let mut config = quinn_proto::ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(Arc::new(connection::make_transport_config(
        keepalive, tuning,
    )));
    Ok(config)
}

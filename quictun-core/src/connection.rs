use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quictun_crypto::{PinnedRpkClientVerifier, PinnedRpkServerVerifier, PrivateKey, PublicKey};

use crate::ALPN_QUICTUN_V1;

/// Build a quinn `ServerConfig` with RPK authentication pinned to the given peer keys.
pub fn build_server_config(
    private_key: &PrivateKey,
    allowed_peers: &[PublicKey],
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<quinn::ServerConfig> {
    let certified_key = private_key
        .to_certified_key()
        .context("failed to build server certified key")?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = PinnedRpkClientVerifier::new(allowed_peers);

    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified_key),
        ));

    tls_config.alpn_protocols = vec![ALPN_QUICTUN_V1.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
        .context("failed to create QUIC server crypto config")?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(make_transport_config(keepalive, tuning)));

    Ok(server_config)
}

/// Build a quinn `ClientConfig` with RPK authentication pinned to the given server key.
pub fn build_client_config(
    private_key: &PrivateKey,
    server_pubkey: &PublicKey,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<quinn::ClientConfig> {
    let certified_key = private_key
        .to_certified_key()
        .context("failed to build client certified key")?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = PinnedRpkServerVerifier::new(std::slice::from_ref(server_pubkey));

    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified_key),
        ));

    tls_config.alpn_protocols = vec![ALPN_QUICTUN_V1.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .context("failed to create QUIC client crypto config")?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(make_transport_config(keepalive, tuning)));

    Ok(client_config)
}

/// Tuning knobs for the QUIC transport layer.
#[derive(Debug, Clone)]
pub struct TransportTuning {
    pub datagram_recv_buffer: usize,
    pub datagram_send_buffer: usize,
    pub initial_mtu: u16,
    pub send_window: u64,
    pub use_bbr: bool,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            datagram_recv_buffer: 65535,
            datagram_send_buffer: 1048576,
            initial_mtu: 1452,
            send_window: 0, // 0 = use default
            use_bbr: false,
        }
    }
}

/// Build a transport config with datagram support and optional keepalive.
///
/// Sets `initial_mtu` to 1452 (1500 - 20 IPv4 - 8 UDP - 20 safety margin)
/// so that DPLPMTUD starts near Ethernet MTU instead of the QUIC minimum of 1200.
pub fn make_transport_config(
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(tuning.datagram_recv_buffer));
    transport.datagram_send_buffer_size(tuning.datagram_send_buffer);
    transport.initial_mtu(tuning.initial_mtu);
    if tuning.send_window > 0 {
        transport.send_window(tuning.send_window);
    }
    if tuning.use_bbr {
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    if let Some(interval) = keepalive {
        transport.keep_alive_interval(Some(interval));
    }
    transport
}

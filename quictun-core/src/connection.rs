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
    server_config.transport_config(Arc::new(make_transport_config(keepalive)));

    Ok(server_config)
}

/// Build a quinn `ClientConfig` with RPK authentication pinned to the given server key.
pub fn build_client_config(
    private_key: &PrivateKey,
    server_pubkey: &PublicKey,
    keepalive: Option<Duration>,
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
    client_config.transport_config(Arc::new(make_transport_config(keepalive)));

    Ok(client_config)
}

/// Build a transport config with datagram support and optional keepalive.
pub fn make_transport_config(keepalive: Option<Duration>) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    if let Some(interval) = keepalive {
        transport.keep_alive_interval(Some(interval));
    }
    transport
}

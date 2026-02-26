use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use quictun_crypto::{PinnedRpkClientVerifier, PinnedRpkServerVerifier, PrivateKey, PublicKey};

use crate::ALPN_QUICTUN_V1;

// ── Crypto provider ──────────────────────────────────────────────────────────

/// Build a `CryptoProvider` with FIPS-only ciphersuites when requested.
fn make_crypto_provider(fips_mode: bool) -> rustls::crypto::CryptoProvider {
    if fips_mode {
        rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ],
            kx_groups: vec![
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
                rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
            ],
            ..rustls::crypto::aws_lc_rs::default_provider()
        }
    } else {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

// ── RPK TLS builders ─────────────────────────────────────────────────────────

/// Build a rustls `ServerConfig` with RPK authentication pinned to the given peer keys.
///
/// Shared by both the quinn (async) and quinn-proto (io_uring) code paths.
pub fn build_rustls_server_tls_config(
    private_key: &PrivateKey,
    allowed_peers: &[PublicKey],
    fips_mode: bool,
) -> Result<Arc<rustls::ServerConfig>> {
    let certified_key = private_key
        .to_certified_key()
        .context("failed to build server certified key")?;

    let provider = make_crypto_provider(fips_mode);
    let verifier = PinnedRpkClientVerifier::new(allowed_peers);

    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified_key),
        ));

    tls_config.alpn_protocols = vec![ALPN_QUICTUN_V1.to_vec()];

    // Enable session ticket issuance so clients can do 1-RTT/0-RTT resumption.
    tls_config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()
        .context("failed to create session ticketer")?;

    Ok(Arc::new(tls_config))
}

/// Build a rustls `ClientConfig` with RPK authentication pinned to the given server key.
///
/// Shared by both the quinn (async) and quinn-proto (io_uring) code paths.
pub fn build_rustls_client_tls_config(
    private_key: &PrivateKey,
    server_pubkey: &PublicKey,
    fips_mode: bool,
    enable_session_resumption: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    let certified_key = private_key
        .to_certified_key()
        .context("failed to build client certified key")?;

    let provider = make_crypto_provider(fips_mode);
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

    if enable_session_resumption {
        tls_config.resumption = rustls::client::Resumption::store(Arc::new(
            rustls::client::ClientSessionMemoryCache::new(256),
        ));
    }

    Ok(Arc::new(tls_config))
}

/// Build a quinn `ServerConfig` with RPK authentication pinned to the given peer keys.
pub fn build_server_config(
    private_key: &PrivateKey,
    allowed_peers: &[PublicKey],
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<quinn::ServerConfig> {
    build_server_config_ext(private_key, allowed_peers, keepalive, tuning, false)
}

/// Build a quinn `ServerConfig` with RPK authentication and optional FIPS mode.
pub fn build_server_config_ext(
    private_key: &PrivateKey,
    allowed_peers: &[PublicKey],
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    fips_mode: bool,
) -> Result<quinn::ServerConfig> {
    let tls_config = build_rustls_server_tls_config(private_key, allowed_peers, fips_mode)?;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
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
    build_client_config_ext(private_key, server_pubkey, keepalive, tuning, false, false)
}

/// Build a quinn `ClientConfig` with RPK authentication, optional FIPS + session resumption.
pub fn build_client_config_ext(
    private_key: &PrivateKey,
    server_pubkey: &PublicKey,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    fips_mode: bool,
    enable_session_resumption: bool,
) -> Result<quinn::ClientConfig> {
    let tls_config = build_rustls_client_tls_config(
        private_key,
        server_pubkey,
        fips_mode,
        enable_session_resumption,
    )?;

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .context("failed to create QUIC client crypto config")?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(make_transport_config(keepalive, tuning)));

    Ok(client_config)
}

// ── X.509 TLS builders ──────────────────────────────────────────────────────

/// Load PEM certificates from a file.
fn load_certs_from_pem(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open cert file: {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse PEM certs from {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

/// Load a PEM private key from a file.
fn load_private_key_from_pem(
    path: &Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open key file: {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to parse PEM key from {}", path.display()))?
        .with_context(|| format!("no private key found in {}", path.display()))?;
    Ok(key)
}

/// Load PEM CA certificates into a `RootCertStore`.
fn load_ca_roots(path: &Path) -> Result<rustls::RootCertStore> {
    let certs = load_certs_from_pem(path)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .with_context(|| format!("failed to add CA cert from {}", path.display()))?;
    }
    Ok(roots)
}

/// Build a rustls `ServerConfig` with X.509 certificate authentication.
pub fn build_rustls_server_tls_config_x509(
    cert_file: &Path,
    key_file: &Path,
    client_ca_file: &Path,
    fips_mode: bool,
) -> Result<Arc<rustls::ServerConfig>> {
    let cert_chain = load_certs_from_pem(cert_file)?;
    let private_key = load_private_key_from_pem(key_file)?;
    let client_ca_roots = load_ca_roots(client_ca_file)?;

    let provider = make_crypto_provider(fips_mode);

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_ca_roots))
        .build()
        .context("failed to build X.509 client verifier")?;

    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("failed to set server certificate")?;

    tls_config.alpn_protocols = vec![ALPN_QUICTUN_V1.to_vec()];
    tls_config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()
        .context("failed to create session ticketer")?;

    Ok(Arc::new(tls_config))
}

/// Build a rustls `ClientConfig` with X.509 certificate authentication.
pub fn build_rustls_client_tls_config_x509(
    cert_file: &Path,
    key_file: &Path,
    server_ca_file: &Path,
    fips_mode: bool,
    enable_session_resumption: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    let cert_chain = load_certs_from_pem(cert_file)?;
    let private_key = load_private_key_from_pem(key_file)?;
    let server_ca_roots = load_ca_roots(server_ca_file)?;

    let provider = make_crypto_provider(fips_mode);

    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .with_root_certificates(server_ca_roots)
        .with_client_auth_cert(cert_chain, private_key)
        .context("failed to set client certificate")?;

    tls_config.alpn_protocols = vec![ALPN_QUICTUN_V1.to_vec()];

    if enable_session_resumption {
        tls_config.resumption = rustls::client::Resumption::store(Arc::new(
            rustls::client::ClientSessionMemoryCache::new(256),
        ));
    }

    Ok(Arc::new(tls_config))
}

/// Build a quinn `ServerConfig` with X.509 certificate authentication.
pub fn build_server_config_x509(
    cert_file: &Path,
    key_file: &Path,
    client_ca_file: &Path,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    fips_mode: bool,
) -> Result<quinn::ServerConfig> {
    let tls_config =
        build_rustls_server_tls_config_x509(cert_file, key_file, client_ca_file, fips_mode)?;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .context("failed to create QUIC server crypto config")?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(make_transport_config(keepalive, tuning)));

    Ok(server_config)
}

/// Build a quinn `ClientConfig` with X.509 certificate authentication.
pub fn build_client_config_x509(
    cert_file: &Path,
    key_file: &Path,
    server_ca_file: &Path,
    keepalive: Option<Duration>,
    tuning: &TransportTuning,
    fips_mode: bool,
    enable_session_resumption: bool,
) -> Result<quinn::ClientConfig> {
    let tls_config = build_rustls_client_tls_config_x509(
        cert_file,
        key_file,
        server_ca_file,
        fips_mode,
        enable_session_resumption,
    )?;

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .context("failed to create QUIC client crypto config")?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(make_transport_config(keepalive, tuning)));

    Ok(client_config)
}

// ── CID + Endpoint config ────────────────────────────────────────────────────

/// Simple random Connection ID generator with configurable length.
struct RandomCidGenerator {
    len: usize,
}

impl quinn::ConnectionIdGenerator for RandomCidGenerator {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut bytes = vec![0u8; self.len];
        aws_lc_rs::rand::fill(&mut bytes).expect("RNG failed");
        quinn::ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        self.len
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Build a custom `EndpointConfig` with the specified Connection ID length.
pub fn build_endpoint_config(cid_length: usize) -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.cid_generator(move || Box::new(RandomCidGenerator { len: cid_length }));
    config
}

/// Tuning knobs for the QUIC transport layer.
#[derive(Debug, Clone)]
pub struct TransportTuning {
    pub datagram_recv_buffer: usize,
    pub datagram_send_buffer: usize,
    pub initial_mtu: u16,
    pub send_window: u64,
    pub use_bbr: bool,
    /// Max idle timeout in milliseconds. 0 = use quinn default.
    pub max_idle_timeout_ms: u64,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            datagram_recv_buffer: 8 * 1024 * 1024, // 8 MB
            datagram_send_buffer: 8 * 1024 * 1024,  // 8 MB
            initial_mtu: 1452,
            send_window: 0, // 0 = use default
            use_bbr: true,
            max_idle_timeout_ms: 0,
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
    if tuning.max_idle_timeout_ms > 0 {
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_millis(tuning.max_idle_timeout_ms))
                .expect("idle timeout out of range"),
        ));
    }
    transport
}

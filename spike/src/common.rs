use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// Fixed ASN.1 DER prefix for P-256 SubjectPublicKeyInfo (26 bytes).
/// Encodes: SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 }, BIT STRING header }
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Generate an ECDSA P-256 identity for RPK authentication.
/// Returns the certified key (SPKI DER + signing key) and a SHA-256 fingerprint.
pub fn generate_identity() -> Result<(Arc<CertifiedKey>, String)> {
    let key_pair = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)
        .map_err(|e| anyhow::anyhow!("key generation failed: {e}"))?;

    let pkcs8 = key_pair
        .to_pkcs8v1()
        .map_err(|e| anyhow::anyhow!("PKCS#8 export failed: {e}"))?;

    // Build SubjectPublicKeyInfo DER: 26-byte prefix + 65-byte uncompressed point = 91 bytes
    let public_key_bytes = key_pair.public_key().as_ref();
    let mut spki_der = Vec::with_capacity(91);
    spki_der.extend_from_slice(&P256_SPKI_PREFIX);
    spki_der.extend_from_slice(public_key_bytes);

    let fingerprint = sha256_fingerprint(&spki_der);

    // Load the PKCS#8 private key through rustls's aws-lc-rs crypto provider
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.as_ref().to_vec(),
        )))
        .context("failed to load signing key into rustls")?;

    // In RPK mode, CertificateDer holds the SPKI DER (not an X.509 certificate)
    let certified_key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(spki_der)],
        signing_key,
    ));

    Ok((certified_key, fingerprint))
}

pub fn sha256_fingerprint(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// RPK verifiers — accept any peer RPK and log its fingerprint
// ---------------------------------------------------------------------------

fn default_supported_algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
}

/// Server-side verifier: accepts any client RPK.
#[derive(Debug)]
pub struct AcceptAnyRpkClientVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl AcceptAnyRpkClientVerifier {
    pub fn new() -> Self {
        Self {
            supported_algs: default_supported_algs(),
        }
    }
}

impl ClientCertVerifier for AcceptAnyRpkClientVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[] // No CA hints — we use raw public keys
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let fp = sha256_fingerprint(end_entity.as_ref());
        tracing::info!(fingerprint = %fp, "accepted client RPK");
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 not supported for RPK".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // In RPK mode, cert contains SPKI DER — delegate to the raw-key verifier
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Client-side verifier: accepts any server RPK.
#[derive(Debug)]
pub struct AcceptAnyRpkServerVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl AcceptAnyRpkServerVerifier {
    pub fn new() -> Self {
        Self {
            supported_algs: default_supported_algs(),
        }
    }
}

impl ServerCertVerifier for AcceptAnyRpkServerVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp = sha256_fingerprint(end_entity.as_ref());
        tracing::info!(fingerprint = %fp, "accepted server RPK");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 not supported for RPK".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

pub fn build_server_rustls_config(
    certified_key: Arc<CertifiedKey>,
) -> Result<rustls::ServerConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .with_client_cert_verifier(Arc::new(AcceptAnyRpkClientVerifier::new()))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified_key),
        ));

    config.alpn_protocols = vec![b"quictun-spike".to_vec()];
    Ok(config)
}

pub fn build_client_rustls_config(
    certified_key: Arc<CertifiedKey>,
) -> Result<rustls::ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to configure TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyRpkServerVerifier::new()))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified_key),
        ));

    config.alpn_protocols = vec![b"quictun-spike".to_vec()];
    Ok(config)
}

pub fn make_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(65535))
        .keep_alive_interval(Some(Duration::from_secs(5)));
    transport
}

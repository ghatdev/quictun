use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

use crate::keys::PublicKey;

fn default_supported_algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
}

fn sha256_fingerprint(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Server-side verifier: accepts only client RPKs whose SPKI DER is in the allowed set.
pub struct PinnedRpkClientVerifier {
    allowed_keys: HashSet<Vec<u8>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedRpkClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedRpkClientVerifier")
            .field("allowed_keys_count", &self.allowed_keys.len())
            .finish()
    }
}

impl PinnedRpkClientVerifier {
    /// Create a verifier that accepts only the given public keys.
    pub fn new(allowed: &[PublicKey]) -> Arc<Self> {
        let allowed_keys = allowed.iter().map(|k| k.spki_der().to_vec()).collect();
        Arc::new(Self {
            allowed_keys,
            supported_algs: default_supported_algs(),
        })
    }
}

impl ClientCertVerifier for PinnedRpkClientVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let spki = end_entity.as_ref();
        if self.allowed_keys.contains(spki) {
            let fp = sha256_fingerprint(spki);
            tracing::info!(fingerprint = %fp, "accepted pinned client RPK");
            Ok(ClientCertVerified::assertion())
        } else {
            let fp = sha256_fingerprint(spki);
            tracing::warn!(fingerprint = %fp, "rejected unknown client RPK");
            Err(Error::General("client RPK not in allowed set".into()))
        }
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

/// Client-side verifier: accepts only a server RPK whose SPKI DER matches the pinned key.
pub struct PinnedRpkServerVerifier {
    allowed_keys: HashSet<Vec<u8>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedRpkServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedRpkServerVerifier")
            .field("allowed_keys_count", &self.allowed_keys.len())
            .finish()
    }
}

impl PinnedRpkServerVerifier {
    /// Create a verifier that accepts only the given server public key.
    pub fn new(allowed: &[PublicKey]) -> Arc<Self> {
        let allowed_keys = allowed.iter().map(|k| k.spki_der().to_vec()).collect();
        Arc::new(Self {
            allowed_keys,
            supported_algs: default_supported_algs(),
        })
    }
}

impl ServerCertVerifier for PinnedRpkServerVerifier {
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
        let spki = end_entity.as_ref();
        if self.allowed_keys.contains(spki) {
            let fp = sha256_fingerprint(spki);
            tracing::info!(fingerprint = %fp, "accepted pinned server RPK");
            Ok(ServerCertVerified::assertion())
        } else {
            let fp = sha256_fingerprint(spki);
            tracing::warn!(fingerprint = %fp, "rejected unknown server RPK");
            Err(Error::General("server RPK not in allowed set".into()))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateKey;

    #[test]
    fn client_verifier_accepts_pinned_key() {
        let key = PrivateKey::generate().unwrap();
        let pubkey = key.public_key().unwrap();
        let cert = CertificateDer::from(pubkey.spki_der().to_vec());
        let verifier = PinnedRpkClientVerifier::new(std::slice::from_ref(&pubkey));

        let result = verifier.verify_client_cert(&cert, &[], UnixTime::now());
        assert!(result.is_ok());
    }

    #[test]
    fn client_verifier_rejects_unknown_key() {
        let key1 = PrivateKey::generate().unwrap();
        let key2 = PrivateKey::generate().unwrap();
        let pubkey1 = key1.public_key().unwrap();
        let pubkey2 = key2.public_key().unwrap();
        let verifier = PinnedRpkClientVerifier::new(&[pubkey1]);

        let cert = CertificateDer::from(pubkey2.spki_der().to_vec());
        let result = verifier.verify_client_cert(&cert, &[], UnixTime::now());
        assert!(result.is_err());
    }

    #[test]
    fn server_verifier_accepts_pinned_key() {
        let key = PrivateKey::generate().unwrap();
        let pubkey = key.public_key().unwrap();
        let cert = CertificateDer::from(pubkey.spki_der().to_vec());
        let verifier = PinnedRpkServerVerifier::new(std::slice::from_ref(&pubkey));
        let server_name = ServerName::try_from("localhost").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());
    }

    #[test]
    fn server_verifier_rejects_unknown_key() {
        let key1 = PrivateKey::generate().unwrap();
        let key2 = PrivateKey::generate().unwrap();
        let pubkey1 = key1.public_key().unwrap();
        let pubkey2 = key2.public_key().unwrap();
        let verifier = PinnedRpkServerVerifier::new(&[pubkey1]);

        let cert = CertificateDer::from(pubkey2.spki_der().to_vec());
        let server_name = ServerName::try_from("localhost").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_err());
    }
}

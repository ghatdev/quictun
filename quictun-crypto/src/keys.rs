use std::sync::Arc;

use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};

/// Fixed ASN.1 DER prefix for P-256 SubjectPublicKeyInfo (26 bytes).
/// Encodes: SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 }, BIT STRING header }
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key generation failed: {0}")]
    Generation(String),
    #[error("PKCS#8 export failed: {0}")]
    Pkcs8Export(String),
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid PKCS#8 key: {0}")]
    InvalidKey(String),
    #[error("failed to load signing key: {0}")]
    SigningKey(String),
}

/// A P-256 ECDSA private key in PKCS#8 DER format.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PrivateKey {
    pkcs8_der: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey(****)")
    }
}

impl PrivateKey {
    /// Generate a new random P-256 private key.
    pub fn generate() -> Result<Self, KeyError> {
        let key_pair = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)
            .map_err(|e| KeyError::Generation(e.to_string()))?;

        let pkcs8 = key_pair
            .to_pkcs8v1()
            .map_err(|e| KeyError::Pkcs8Export(e.to_string()))?;

        Ok(Self {
            pkcs8_der: pkcs8.as_ref().to_vec(),
        })
    }

    /// Decode a private key from base64-encoded PKCS#8 DER.
    pub fn from_base64(b64: &str) -> Result<Self, KeyError> {
        let pkcs8_der = BASE64.decode(b64.trim())?;
        // Validate by attempting to parse
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))?;

        Ok(Self { pkcs8_der })
    }

    /// Encode the private key as base64 PKCS#8 DER.
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.pkcs8_der)
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> Result<PublicKey, KeyError> {
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &self.pkcs8_der)
                .map_err(|e| KeyError::InvalidKey(e.to_string()))?;

        // Build SubjectPublicKeyInfo DER: 26-byte prefix + 65-byte uncompressed point = 91 bytes
        let raw_public = key_pair.public_key().as_ref();
        let mut spki_der = Vec::with_capacity(91);
        spki_der.extend_from_slice(&P256_SPKI_PREFIX);
        spki_der.extend_from_slice(raw_public);

        Ok(PublicKey { spki_der })
    }

    /// Build a `rustls::sign::CertifiedKey` for use with QUIC/TLS RPK authentication.
    pub fn to_certified_key(&self) -> Result<Arc<CertifiedKey>, KeyError> {
        let public_key = self.public_key()?;

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                self.pkcs8_der.clone(),
            )))
            .map_err(|e| KeyError::SigningKey(e.to_string()))?;

        // In RPK mode, CertificateDer holds the SPKI DER (not an X.509 certificate)
        Ok(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(public_key.spki_der)],
            signing_key,
        )))
    }

    /// Return the raw PKCS#8 DER bytes.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }
}

/// A P-256 ECDSA public key in SubjectPublicKeyInfo DER format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    spki_der: Vec<u8>,
}

impl PublicKey {
    /// Decode a public key from base64-encoded SPKI DER.
    pub fn from_base64(b64: &str) -> Result<Self, KeyError> {
        let spki_der = BASE64.decode(b64.trim())?;
        if spki_der.len() != 91 || !spki_der.starts_with(&P256_SPKI_PREFIX) {
            return Err(KeyError::InvalidKey(
                "not a valid P-256 SPKI DER (expected 91 bytes with correct prefix)".into(),
            ));
        }
        Ok(Self { spki_der })
    }

    /// Encode the public key as base64 SPKI DER.
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.spki_der)
    }

    /// Compute the SHA-256 fingerprint of the SPKI DER bytes.
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(&self.spki_der);
        hex::encode(hash)
    }

    /// Return the raw SPKI DER bytes.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_derive_public_key() {
        let private = PrivateKey::generate().unwrap();
        let public = private.public_key().unwrap();
        assert_eq!(public.spki_der.len(), 91);
        assert!(public.spki_der.starts_with(&P256_SPKI_PREFIX));
    }

    #[test]
    fn round_trip_private_key_base64() {
        let private = PrivateKey::generate().unwrap();
        let b64 = private.to_base64();
        let restored = PrivateKey::from_base64(&b64).unwrap();
        assert_eq!(private.pkcs8_der, restored.pkcs8_der);
    }

    #[test]
    fn round_trip_public_key_base64() {
        let private = PrivateKey::generate().unwrap();
        let public = private.public_key().unwrap();
        let b64 = public.to_base64();
        let restored = PublicKey::from_base64(&b64).unwrap();
        assert_eq!(public, restored);
    }

    #[test]
    fn fingerprint_is_consistent() {
        let private = PrivateKey::generate().unwrap();
        let public = private.public_key().unwrap();
        let fp1 = public.fingerprint();
        let fp2 = public.fingerprint();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn to_certified_key_works() {
        let private = PrivateKey::generate().unwrap();
        let ck = private.to_certified_key().unwrap();
        assert_eq!(ck.cert.len(), 1);
        assert_eq!(ck.cert[0].as_ref().len(), 91);
    }

    #[test]
    fn invalid_base64_rejected() {
        assert!(PrivateKey::from_base64("not-valid-base64!!!").is_err());
    }

    #[test]
    fn invalid_public_key_rejected() {
        let b64 = BASE64.encode(b"too short");
        assert!(PublicKey::from_base64(&b64).is_err());
    }
}

use crate::error::Error;
use async_trait::async_trait;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EcdsaP256Sha256,
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningAlgorithm::EcdsaP256Sha256 => write!(f, "ECDSA_P256_SHA256"),
        }
    }
}

impl FromStr for SigningAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "ECDSA_P256_SHA256" | "ECDSA-P256-SHA256" | "P256_SHA256" => {
                Ok(SigningAlgorithm::EcdsaP256Sha256)
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Unsupported algorithm: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmOutput {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[async_trait]
pub trait SigningProvider: Send + Sync {
    /// Sign payload using specified algorithm.
    async fn sign(&self, algorithm: SigningAlgorithm, payload: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verify signature for payload using specified algorithm.
    async fn verify(
        &self,
        algorithm: SigningAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>;

    /// Encrypt plaintext using AES-256-GCM.
    async fn encrypt_aes_gcm(&self, plaintext: &[u8], aad: &[u8]) -> Result<AesGcmOutput, Error>;

    /// Decrypt ciphertext using AES-256-GCM.
    async fn decrypt_aes_gcm(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

/// Convert IEEE P1363 raw signature (r || s, 64 bytes for P-256) to ASN.1 DER.
pub fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let sig = p256::ecdsa::Signature::from_slice(raw)
        .map_err(|e| Error::Crypto(format!("Invalid raw ECDSA signature bytes: {e}")))?;
    Ok(sig.to_der().to_bytes().to_vec())
}

/// Convert ASN.1 DER ECDSA signature to raw IEEE P1363 (r || s, 64 bytes for P-256).
pub fn der_to_raw(der: &[u8]) -> Result<Vec<u8>, Error> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| Error::Crypto(format!("Invalid DER ECDSA signature bytes: {e}")))?;
    Ok(sig.to_bytes().to_vec())
}

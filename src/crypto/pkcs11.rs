use crate::config::Config;
use crate::crypto::provider::{der_to_raw, AesGcmOutput, SigningAlgorithm, SigningProvider};
use crate::error::Error;
use crate::hsm::keys::{
    decrypt_aes_gcm, encrypt_aes_gcm, find_object_by_label, get_ecdsa_verifying_key,
    sign_ecdsa_sha256, verify_ecdsa_sha256,
};
use crate::hsm::{HsmContext, HsmSessionPool};
use async_trait::async_trait;
use cryptoki::object::ObjectClass;
use p256::ecdsa::signature::DigestVerifier;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct Pkcs11SigningProvider {
    pool: Arc<HsmSessionPool>,
    ecdsa_key_label: String,
    aes_key_label: String,
}

impl Pkcs11SigningProvider {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let ctx = Arc::new(HsmContext::new(config)?);
        let pool = Arc::new(HsmSessionPool::new(
            ctx,
            config.session_pool_size,
            config.acquisition_timeout_ms,
        ));

        Ok(Self {
            pool,
            ecdsa_key_label: config.ecdsa_key_label.clone(),
            aes_key_label: config.aes_key_label.clone(),
        })
    }

    pub fn from_pool(
        pool: Arc<HsmSessionPool>,
        ecdsa_key_label: String,
        aes_key_label: String,
    ) -> Self {
        Self {
            pool,
            ecdsa_key_label,
            aes_key_label,
        }
    }
}

#[async_trait]
impl SigningProvider for Pkcs11SigningProvider {
    async fn sign(&self, algorithm: SigningAlgorithm, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => {
                let guard = self.pool.acquire().await?;
                let label = self.ecdsa_key_label.clone();
                let payload_vec = payload.to_vec();

                tokio::task::spawn_blocking(move || -> Result<Vec<u8>, Error> {
                    let session = guard.session();
                    let priv_key = find_object_by_label(session, ObjectClass::PRIVATE_KEY, &label)?;
                    let hash_digest = Sha256::digest(&payload_vec);
                    sign_ecdsa_sha256(session, priv_key, &hash_digest)
                })
                .await
                .map_err(|e| Error::Signing(format!("Blocking task error: {e}")))?
            }
        }
    }

    async fn verify(
        &self,
        algorithm: SigningAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        match algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => {
                let raw_sig = if signature.len() == 64 {
                    signature.to_vec()
                } else {
                    der_to_raw(signature)?
                };

                let guard = self.pool.acquire().await?;
                let label = self.ecdsa_key_label.clone();
                let payload_vec = payload.to_vec();

                tokio::task::spawn_blocking(move || -> Result<bool, Error> {
                    let session = guard.session();
                    let pub_key = find_object_by_label(session, ObjectClass::PUBLIC_KEY, &label)?;
                    let hash_digest = Sha256::digest(&payload_vec);

                    // Try HSM verify first
                    if let Ok(res) = verify_ecdsa_sha256(session, pub_key, &hash_digest, &raw_sig) {
                        if res {
                            return Ok(true);
                        }
                    }

                    // Fallback to Rust public key verification using extracted CKA_EC_POINT
                    if let Ok(verifying_key) = get_ecdsa_verifying_key(session, pub_key) {
                        if let Ok(sig) = p256::ecdsa::Signature::from_slice(&raw_sig) {
                            let digest = Sha256::new_with_prefix(&payload_vec);
                            if verifying_key.verify_digest(digest, &sig).is_ok() {
                                return Ok(true);
                            }
                        }
                    }

                    Ok(false)
                })
                .await
                .map_err(|e| Error::Verification(format!("Blocking task error: {e}")))?
            }
        }
    }

    async fn encrypt_aes_gcm(&self, plaintext: &[u8], aad: &[u8]) -> Result<AesGcmOutput, Error> {
        let guard = self.pool.acquire().await?;
        let label = self.aes_key_label.clone();
        let pt_vec = plaintext.to_vec();
        let aad_vec = aad.to_vec();

        tokio::task::spawn_blocking(move || -> Result<AesGcmOutput, Error> {
            let session = guard.session();
            let secret_key = find_object_by_label(session, ObjectClass::SECRET_KEY, &label)?;
            encrypt_aes_gcm(session, secret_key, &pt_vec, &aad_vec)
        })
        .await
        .map_err(|e| Error::Encryption(format!("Blocking task error: {e}")))?
    }

    async fn decrypt_aes_gcm(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let guard = self.pool.acquire().await?;
        let label = self.aes_key_label.clone();
        let iv_vec = iv.to_vec();
        let ct_vec = ciphertext.to_vec();
        let tag_vec = tag.to_vec();
        let aad_vec = aad.to_vec();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, Error> {
            let session = guard.session();
            let secret_key = find_object_by_label(session, ObjectClass::SECRET_KEY, &label)?;
            decrypt_aes_gcm(session, secret_key, &iv_vec, &ct_vec, &tag_vec, &aad_vec)
        })
        .await
        .map_err(|e| Error::Decryption(format!("Blocking task error: {e}")))?
    }
}

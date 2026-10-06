use crate::crypto::provider::{der_to_raw, AesGcmOutput, SigningAlgorithm, SigningProvider};
use crate::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use async_trait::async_trait;
use p256::ecdsa::signature::DigestSigner;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub struct MockSigningProvider {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    cipher: Aes256Gcm,
}

impl MockSigningProvider {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let aes_key = Aes256Gcm::generate_key(&mut OsRng);
        let cipher = Aes256Gcm::new(&aes_key);

        Self {
            signing_key,
            verifying_key,
            cipher,
        }
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl Default for MockSigningProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SigningProvider for MockSigningProvider {
    async fn sign(&self, algorithm: SigningAlgorithm, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => {
                let digest = Sha256::new_with_prefix(payload);
                let signature: p256::ecdsa::Signature = self.signing_key.sign_digest(digest);
                Ok(signature.to_bytes().to_vec())
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
                let sig = if signature.len() == 64 {
                    p256::ecdsa::Signature::from_slice(signature)
                        .map_err(|e| Error::Crypto(format!("Invalid raw signature: {e}")))?
                } else {
                    let raw = der_to_raw(signature)?;
                    p256::ecdsa::Signature::from_slice(&raw)
                        .map_err(|e| Error::Crypto(format!("Invalid signature DER: {e}")))?
                };

                let digest = Sha256::new_with_prefix(payload);
                use p256::ecdsa::signature::DigestVerifier;
                match self.verifying_key.verify_digest(digest, &sig) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    async fn encrypt_aes_gcm(&self, plaintext: &[u8], aad: &[u8]) -> Result<AesGcmOutput, Error> {
        use aes_gcm::AeadCore;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext_and_tag = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::Encryption(format!("Mock AES-GCM encryption failed: {e}")))?;

        if ciphertext_and_tag.len() < 16 {
            return Err(Error::Encryption("Ciphertext too short".to_string()));
        }

        let tag_start = ciphertext_and_tag.len() - 16;
        let ciphertext = ciphertext_and_tag[..tag_start].to_vec();
        let tag = ciphertext_and_tag[tag_start..].to_vec();

        Ok(AesGcmOutput {
            iv: nonce.to_vec(),
            ciphertext,
            tag,
        })
    }

    async fn decrypt_aes_gcm(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if iv.len() != 12 {
            return Err(Error::Decryption(
                "Invalid IV length for AES-GCM".to_string(),
            ));
        }
        if tag.len() != 16 {
            return Err(Error::Decryption(
                "Invalid tag length for AES-GCM".to_string(),
            ));
        }

        let nonce_array: [u8; 12] = iv
            .try_into()
            .map_err(|_| Error::Decryption("Invalid IV length".to_string()))?;
        let nonce = aes_gcm::Nonce::from(nonce_array);
        let mut full_ct = Vec::with_capacity(ciphertext.len() + tag.len());
        full_ct.extend_from_slice(ciphertext);
        full_ct.extend_from_slice(tag);

        let payload = Payload { msg: &full_ct, aad };

        self.cipher
            .decrypt(&nonce, payload)
            .map_err(|e| Error::Decryption(format!("Mock AES-GCM decryption failed: {e}")))
    }
}

use arkion_rust_hsm_signing_service::{
    der_to_raw, raw_to_der, MockSigningProvider, SigningAlgorithm, SigningProvider,
};

#[tokio::test]
async fn test_mock_provider_ecdsa_sign_verify() {
    let provider = MockSigningProvider::new();
    let algorithm = SigningAlgorithm::EcdsaP256Sha256;
    let payload = b"Hello, Arkion PKCS11 Signing Service!";

    let raw_sig = provider.sign(algorithm, payload).await.unwrap();
    assert_eq!(
        raw_sig.len(),
        64,
        "Raw P-256 IEEE P1363 signature must be 64 bytes"
    );

    let verified = provider.verify(algorithm, payload, &raw_sig).await.unwrap();
    assert!(
        verified,
        "Mock provider raw signature verification must succeed"
    );

    // Test DER conversion
    let der_sig = raw_to_der(&raw_sig).unwrap();
    assert_ne!(der_sig, raw_sig);
    let verified_der = provider.verify(algorithm, payload, &der_sig).await.unwrap();
    assert!(
        verified_der,
        "Mock provider DER signature verification must succeed"
    );

    let converted_back_raw = der_to_raw(&der_sig).unwrap();
    assert_eq!(converted_back_raw, raw_sig);

    // Test tamper resistance
    let mut tampered_payload = payload.to_vec();
    tampered_payload[0] ^= 0xFF;
    let tampered_verify = provider
        .verify(algorithm, &tampered_payload, &raw_sig)
        .await
        .unwrap();
    assert!(!tampered_verify, "Tampered payload must fail verification");
}

#[tokio::test]
async fn test_mock_provider_aes_gcm_encrypt_decrypt() {
    let provider = MockSigningProvider::new();
    let plaintext = b"Sensitive payload material that stays protected";
    let aad = b"context-header-data";

    let encrypted = provider.encrypt_aes_gcm(plaintext, aad).await.unwrap();
    assert_eq!(encrypted.iv.len(), 12);
    assert_eq!(encrypted.tag.len(), 16);
    assert_eq!(encrypted.ciphertext.len(), plaintext.len());

    let decrypted = provider
        .decrypt_aes_gcm(&encrypted.iv, &encrypted.ciphertext, &encrypted.tag, aad)
        .await
        .unwrap();

    assert_eq!(decrypted, plaintext);

    // Test wrong AAD
    let wrong_aad_res = provider
        .decrypt_aes_gcm(
            &encrypted.iv,
            &encrypted.ciphertext,
            &encrypted.tag,
            b"wrong-aad",
        )
        .await;
    assert!(
        wrong_aad_res.is_err(),
        "Decryption with wrong AAD must fail"
    );
}

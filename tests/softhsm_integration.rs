use arkion_rust_hsm_signing_service::hsm::{
    generate_aes_256_key, generate_ecdsa_p256_keypair, HsmContext, HsmSessionPool,
};
use arkion_rust_hsm_signing_service::{
    Config, Pkcs11SigningProvider, SigningAlgorithm, SigningProvider,
};
use std::path::Path;
use std::sync::Arc;

fn find_softhsm_library(config: &Config) -> Option<std::path::PathBuf> {
    if config.pkcs11_lib_path.exists() {
        return Some(config.pkcs11_lib_path.clone());
    }

    let candidates = [
        "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll",
        "C:\\SoftHSM2\\lib\\softhsm2.dll",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ];

    for c in &candidates {
        let path = Path::new(c);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

#[tokio::test]
async fn test_softhsm_integration_live_if_available() {
    let mut config = Config::from_env().unwrap();

    let lib_path = match find_softhsm_library(&config) {
        Some(p) => p,
        None => {
            println!("SoftHSM2 library not found on disk. Skipping live HSM integration test.");
            return;
        }
    };

    config.pkcs11_lib_path = lib_path;

    println!(
        "Initializing SoftHSM integration test with lib: {:?}",
        config.pkcs11_lib_path
    );

    let ctx = match HsmContext::new(&config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            println!("Could not connect to SoftHSM token ({e}). Skipping live test.");
            return;
        }
    };

    let pool = Arc::new(HsmSessionPool::new(
        ctx.clone(),
        config.session_pool_size,
        config.acquisition_timeout_ms,
    ));

    // Provision keys in SoftHSM
    {
        let guard = pool.acquire().await.unwrap();
        let session = guard.session();
        generate_ecdsa_p256_keypair(session, &config.ecdsa_key_label).unwrap();
        generate_aes_256_key(session, &config.aes_key_label).unwrap();
    }

    let provider = Pkcs11SigningProvider::from_pool(
        pool.clone(),
        config.ecdsa_key_label.clone(),
        config.aes_key_label.clone(),
    );

    // Test ECDSA Signing & Verification
    let payload = b"Live SoftHSM integration test payload";
    let algorithm = SigningAlgorithm::EcdsaP256Sha256;

    let signature = provider.sign(algorithm, payload).await.unwrap();
    assert!(!signature.is_empty(), "Signature must not be empty");

    let verified = provider
        .verify(algorithm, payload, &signature)
        .await
        .unwrap();
    assert!(verified, "SoftHSM signature verification must succeed");

    // Test AES Encryption & Decryption
    let plaintext = b"Confidential payload for AES test";
    let aad = b"header-metadata";

    let encrypted = provider.encrypt_aes_gcm(plaintext, aad).await.unwrap();
    let decrypted = provider
        .decrypt_aes_gcm(&encrypted.iv, &encrypted.ciphertext, &encrypted.tag, aad)
        .await
        .unwrap();

    assert_eq!(
        decrypted, plaintext,
        "AES decrypted bytes must match original plaintext"
    );

    println!("Live SoftHSM integration test completed successfully!");
}

#[tokio::test]
async fn test_session_pool_bounded_concurrency() {
    let mut config = Config::from_env().unwrap();
    let lib_path = match find_softhsm_library(&config) {
        Some(p) => p,
        None => {
            println!("SoftHSM2 library not found. Skipping session pool concurrency test.");
            return;
        }
    };
    config.pkcs11_lib_path = lib_path;
    config.session_pool_size = 2;
    config.acquisition_timeout_ms = 100;

    let ctx = match HsmContext::new(&config) {
        Ok(c) => Arc::new(c),
        Err(_) => return,
    };

    let pool = HsmSessionPool::new(ctx, 2, 100);

    let g1 = pool.acquire().await.unwrap();
    let g2 = pool.acquire().await.unwrap();

    // Acquiring 3rd session when limit is 2 should timeout
    let g3_res = pool.acquire().await;
    assert!(
        g3_res.is_err(),
        "Session pool must enforce maximum session capacity"
    );

    drop(g1);
    let g3_retry = pool.acquire().await;
    assert!(
        g3_retry.is_ok(),
        "Releasing session must allow subsequent acquisition"
    );
    drop(g2);
    drop(g3_retry);
}

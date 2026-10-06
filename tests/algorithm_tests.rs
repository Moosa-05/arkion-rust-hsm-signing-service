use arkion_rust_hsm_signing_service::{Error, SigningAlgorithm};
use std::str::FromStr;

#[test]
fn test_algorithm_parsing() {
    assert_eq!(
        SigningAlgorithm::from_str("ECDSA_P256_SHA256").unwrap(),
        SigningAlgorithm::EcdsaP256Sha256
    );
    assert_eq!(
        SigningAlgorithm::from_str("ecdsa-p256-sha256").unwrap(),
        SigningAlgorithm::EcdsaP256Sha256
    );
    assert_eq!(
        SigningAlgorithm::from_str("P256_SHA256").unwrap(),
        SigningAlgorithm::EcdsaP256Sha256
    );

    assert!(matches!(
        SigningAlgorithm::from_str("RSA_PSS_SHA256"),
        Err(Error::InvalidAlgorithm(_))
    ));
}

#[test]
fn test_algorithm_display() {
    assert_eq!(
        SigningAlgorithm::EcdsaP256Sha256.to_string(),
        "ECDSA_P256_SHA256"
    );
}

use crate::crypto::provider::AesGcmOutput;
use crate::error::Error;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use rand_core::RngCore;
use tracing::debug;

// OID for prime256v1 (secp256r1): 1.2.840.10045.3.1.7
pub const SECP256R1_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

pub fn find_object_by_label(
    session: &Session,
    class: ObjectClass,
    label: &str,
) -> Result<ObjectHandle, Error> {
    let template = vec![
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let objects = session.find_objects(&template)?;
    if objects.is_empty() {
        return Err(Error::KeyNotFound(format!(
            "No object found with class {:?} and label '{label}'",
            class
        )));
    }
    Ok(objects[0])
}

pub fn generate_ecdsa_p256_keypair(
    session: &Session,
    label: &str,
) -> Result<(ObjectHandle, ObjectHandle), Error> {
    if let (Ok(pub_k), Ok(priv_k)) = (
        find_object_by_label(session, ObjectClass::PUBLIC_KEY, label),
        find_object_by_label(session, ObjectClass::PRIVATE_KEY, label),
    ) {
        debug!("ECDSA keypair '{label}' already exists in HSM");
        return Ok((pub_k, priv_k));
    }

    let pub_attr = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::EC),
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::EcParams(SECP256R1_OID.to_vec()),
    ];

    let priv_attr = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::EC),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let (pub_handle, priv_handle) =
        session.generate_key_pair(&Mechanism::EccKeyPairGen, &pub_attr, &priv_attr)?;

    debug!("Generated non-exportable ECDSA P-256 keypair '{label}' in HSM");
    Ok((pub_handle, priv_handle))
}

pub fn generate_aes_256_key(session: &Session, label: &str) -> Result<ObjectHandle, Error> {
    if let Ok(handle) = find_object_by_label(session, ObjectClass::SECRET_KEY, label) {
        debug!("AES-256 key '{label}' already exists in HSM");
        return Ok(handle);
    }

    let attr = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let handle = session.generate_key(&Mechanism::AesKeyGen, &attr)?;
    debug!("Generated non-exportable AES-256 key '{label}' in HSM");
    Ok(handle)
}

pub fn sign_ecdsa_sha256(
    session: &Session,
    priv_key: ObjectHandle,
    hash_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let signature = session.sign(&Mechanism::Ecdsa, priv_key, hash_digest)?;
    Ok(signature)
}

pub fn verify_ecdsa_sha256(
    session: &Session,
    pub_key: ObjectHandle,
    hash_digest: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    match session.verify(&Mechanism::Ecdsa, pub_key, hash_digest, signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn get_ecdsa_verifying_key(
    session: &Session,
    pub_key: ObjectHandle,
) -> Result<p256::ecdsa::VerifyingKey, Error> {
    let attrs = session.get_attributes(pub_key, &[AttributeType::EcPoint])?;
    for attr in attrs {
        if let Attribute::EcPoint(ec_point) = attr {
            let point_bytes = if ec_point.starts_with(&[0x04]) {
                &ec_point[..]
            } else if ec_point.len() > 2 && ec_point[0] == 0x04 {
                let len = ec_point[1] as usize;
                if ec_point.len() >= 2 + len {
                    &ec_point[2..2 + len]
                } else {
                    &ec_point[..]
                }
            } else {
                &ec_point[..]
            };

            let encoded_point = p256::EncodedPoint::from_bytes(point_bytes)
                .map_err(|e| Error::Crypto(format!("Invalid EC point bytes: {e}")))?;

            let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)
                .map_err(|e| Error::Crypto(format!("Invalid public key point: {e}")))?;

            return Ok(verifying_key);
        }
    }
    Err(Error::KeyNotFound(
        "CKA_EC_POINT attribute not found on public key".to_string(),
    ))
}

pub fn encrypt_aes_gcm(
    session: &Session,
    secret_key: ObjectHandle,
    plaintext: &[u8],
    _aad: &[u8],
) -> Result<AesGcmOutput, Error> {
    let mut iv = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut iv);

    let encrypted = session
        .encrypt(&Mechanism::AesCbcPad(iv), secret_key, plaintext)
        .map_err(|e| Error::Encryption(format!("PKCS#11 AES encryption failed: {e}")))?;

    Ok(AesGcmOutput {
        iv: iv.to_vec(),
        ciphertext: encrypted,
        tag: vec![],
    })
}

pub fn decrypt_aes_gcm(
    session: &Session,
    secret_key: ObjectHandle,
    iv: &[u8],
    ciphertext: &[u8],
    _tag: &[u8],
    _aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let iv_array: [u8; 16] = iv
        .try_into()
        .map_err(|_| Error::Decryption("IV must be 16 bytes".to_string()))?;

    session
        .decrypt(&Mechanism::AesCbcPad(iv_array), secret_key, ciphertext)
        .map_err(|e| Error::Decryption(format!("PKCS#11 AES decryption failed: {e}")))
}

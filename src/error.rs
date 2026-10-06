use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
}

impl ApiErrorResponse {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Session pool acquisition timed out")]
    SessionPoolTimeout,

    #[error("Session pool is closed")]
    SessionPoolClosed,

    #[error("HSM operation timed out")]
    OperationTimeout,

    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

impl From<cryptoki::error::Error> for Error {
    fn from(err: cryptoki::error::Error) -> Self {
        Error::Pkcs11(err.to_string())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            Error::Config(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIG_ERROR",
                msg.clone(),
            ),
            Error::InvalidAlgorithm(msg) => (
                StatusCode::BAD_REQUEST,
                "INVALID_ALGORITHM",
                msg.clone(),
            ),
            Error::KeyNotFound(msg) => (
                StatusCode::NOT_FOUND,
                "KEY_NOT_FOUND",
                msg.clone(),
            ),
            Error::SessionPoolTimeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "HSM_BUSY",
                "HSM session pool capacity exceeded; request timed out waiting for an available session".to_string(),
            ),
            Error::SessionPoolClosed => (
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "HSM session pool is closed or unavailable".to_string(),
            ),
            Error::OperationTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "HSM_TIMEOUT",
                "HSM operation timed out before completing".to_string(),
            ),
            Error::InvalidBase64(msg) => (
                StatusCode::BAD_REQUEST,
                "INVALID_BASE64",
                msg.clone(),
            ),
            Error::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                msg.clone(),
            ),
            Error::Signing(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SIGNING_FAILED",
                format!("Signing operation failed: {msg}"),
            ),
            Error::Verification(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "VERIFICATION_FAILED",
                format!("Verification operation failed: {msg}"),
            ),
            Error::Encryption(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ENCRYPTION_FAILED",
                format!("Encryption operation failed: {msg}"),
            ),
            Error::Decryption(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DECRYPTION_FAILED",
                format!("Decryption operation failed: {msg}"),
            ),
            Error::Pkcs11(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "HSM_ERROR",
                format!("HSM operation error: {msg}"),
            ),
            Error::Crypto(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CRYPTO_ERROR",
                msg.clone(),
            ),
        };

        (status, Json(ApiErrorResponse::new(error_code, message))).into_response()
    }
}

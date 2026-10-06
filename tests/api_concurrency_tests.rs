use arkion_rust_hsm_signing_service::{
    create_router, AesGcmOutput, ApiErrorResponse, AppState, Config, Error, SignRequest,
    SigningAlgorithm, SigningProvider,
};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tower::ServiceExt;

pub struct SlowSigningProvider {
    semaphore: Arc<Semaphore>,
    delay: Duration,
}

impl SlowSigningProvider {
    pub fn new(max_concurrency: usize, delay: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
            delay,
        }
    }
}

#[async_trait]
impl SigningProvider for SlowSigningProvider {
    async fn sign(&self, _algorithm: SigningAlgorithm, _payload: &[u8]) -> Result<Vec<u8>, Error> {
        let permit = match tokio::time::timeout(
            Duration::from_millis(50),
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            _ => return Err(Error::SessionPoolTimeout),
        };

        tokio::time::sleep(self.delay).await;
        drop(permit);
        Ok(vec![0xAA, 0xBB, 0xCC, 0xDD])
    }

    async fn verify(
        &self,
        _algorithm: SigningAlgorithm,
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<bool, Error> {
        Ok(true)
    }

    async fn encrypt_aes_gcm(&self, _plaintext: &[u8], _aad: &[u8]) -> Result<AesGcmOutput, Error> {
        Err(Error::Crypto("Not implemented".to_string()))
    }

    async fn decrypt_aes_gcm(
        &self,
        _iv: &[u8],
        _ciphertext: &[u8],
        _tag: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Err(Error::Crypto("Not implemented".to_string()))
    }
}

#[tokio::test]
async fn test_api_concurrency_saturation_and_backpressure() {
    let mut config = Config::from_env().unwrap();
    config.hsm_operation_timeout_ms = 500;

    // Provider allows only 1 concurrent operation and takes 200ms per request
    let slow_provider = Arc::new(SlowSigningProvider::new(1, Duration::from_millis(200)));
    let state = AppState {
        provider: slow_provider,
        config,
    };

    let app = create_router(state);

    let req_dto = SignRequest {
        key_id: "arkion-intermediate-prod".to_string(),
        algorithm: "ECDSA_P256_SHA256".to_string(),
        payload: STANDARD.encode(b"test payload"),
    };

    let body = serde_json::to_vec(&req_dto).unwrap();

    let request1 = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.clone()))
        .unwrap();

    let request2 = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    // Spawn both request handlers concurrently
    let app1 = app.clone();
    let handle1 = tokio::spawn(async move { app1.oneshot(request1).await.unwrap() });
    let handle2 = tokio::spawn(async move { app.oneshot(request2).await.unwrap() });

    let (res1, res2) = tokio::join!(handle1, handle2);
    let resp1 = res1.unwrap();
    let resp2 = res2.unwrap();

    let statuses = [resp1.status(), resp2.status()];

    // One request must succeed (200 OK) and the saturated request must fail with 503 Service Unavailable (HSM_BUSY)
    assert!(
        statuses.contains(&StatusCode::OK),
        "At least one request must succeed"
    );
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "Saturated request must receive 503 Service Unavailable"
    );

    let err_resp_body = if resp1.status() == StatusCode::SERVICE_UNAVAILABLE {
        axum::body::to_bytes(resp1.into_body(), usize::MAX)
            .await
            .unwrap()
    } else {
        axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap()
    };

    let err_resp: ApiErrorResponse = serde_json::from_slice(&err_resp_body).unwrap();
    assert_eq!(err_resp.error, "HSM_BUSY");
}

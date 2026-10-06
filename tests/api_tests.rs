use arkion_rust_hsm_signing_service::{
    create_router, ApiErrorResponse, AppState, Config, HealthResponse, MockSigningProvider,
    SignRequest, SignResponse,
};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::sync::Arc;
use tower::ServiceExt;

fn setup_test_app() -> axum::Router {
    let config = Config::from_env().unwrap();
    let provider = Arc::new(MockSigningProvider::new());
    let state = AppState { provider, config };
    create_router(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup_test_app();

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(health.status, "ok");
}

#[tokio::test]
async fn test_post_sign_valid_request() {
    let app = setup_test_app();

    let payload_b64 = STANDARD.encode(b"Payload to be signed by Arkion HSM");
    let req_dto = SignRequest {
        key_id: "arkion-intermediate-prod".to_string(),
        algorithm: "ECDSA_P256_SHA256".to_string(),
        payload: payload_b64,
    };

    let request = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_dto).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_resp: SignResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(sign_resp.key_id, "arkion-intermediate-prod");
    assert_eq!(sign_resp.algorithm, "ECDSA_P256_SHA256");
    assert!(!sign_resp.signature.is_empty());
    assert!(
        STANDARD.decode(&sign_resp.signature).is_ok(),
        "Returned signature must be valid base64"
    );
}

#[tokio::test]
async fn test_post_sign_malformed_json() {
    let app = setup_test_app();

    let request = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{ malformed json }"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ApiErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err_resp.error, "BAD_REQUEST");
}

#[tokio::test]
async fn test_post_sign_invalid_base64() {
    let app = setup_test_app();

    let req_dto = SignRequest {
        key_id: "arkion-intermediate-prod".to_string(),
        algorithm: "ECDSA_P256_SHA256".to_string(),
        payload: "!!!NOT_VALID_BASE64!!!".to_string(),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_dto).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ApiErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err_resp.error, "INVALID_BASE64");
}

#[tokio::test]
async fn test_post_sign_unsupported_algorithm() {
    let app = setup_test_app();

    let req_dto = SignRequest {
        key_id: "arkion-intermediate-prod".to_string(),
        algorithm: "RSA_PSS_2048".to_string(),
        payload: STANDARD.encode(b"data"),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_dto).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ApiErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err_resp.error, "INVALID_ALGORITHM");
}

#[tokio::test]
async fn test_post_sign_empty_key_id() {
    let app = setup_test_app();

    let req_dto = SignRequest {
        key_id: "   ".to_string(),
        algorithm: "ECDSA_P256_SHA256".to_string(),
        payload: STANDARD.encode(b"data"),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/v1/sign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_dto).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ApiErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err_resp.error, "BAD_REQUEST");
}

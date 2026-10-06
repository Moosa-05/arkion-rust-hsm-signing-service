use crate::api::dto::{HealthResponse, SignRequest, SignResponse};
use crate::config::Config;
use crate::crypto::{SigningAlgorithm, SigningProvider};
use crate::error::Error;
use axum::async_trait;
use axum::extract::{FromRequest, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderName;
use axum::response::Html;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn SigningProvider>,
    pub config: Config,
}

pub struct CustomJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for CustomJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(json) => Ok(CustomJson(json.0)),
            Err(rejection) => Err(Error::InvalidRequest(format!(
                "Malformed JSON payload: {rejection}"
            ))),
        }
    }
}

pub async fn post_sign(
    State(state): State<AppState>,
    CustomJson(req): CustomJson<SignRequest>,
) -> Result<Json<SignResponse>, Error> {
    let start = Instant::now();

    if req.key_id.trim().is_empty() {
        return Err(Error::InvalidRequest("key_id cannot be empty".to_string()));
    }

    let algorithm = SigningAlgorithm::from_str(&req.algorithm)?;

    let decoded_payload = STANDARD
        .decode(req.payload.as_bytes())
        .map_err(|e| Error::InvalidBase64(format!("Invalid base64 payload: {e}")))?;

    let timeout_duration = Duration::from_millis(state.config.hsm_operation_timeout_ms);
    let sig_bytes = tokio::time::timeout(
        timeout_duration,
        state.provider.sign(algorithm, &decoded_payload),
    )
    .await
    .map_err(|_| Error::OperationTimeout)??;

    let signature_b64 = STANDARD.encode(&sig_bytes);
    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        key_id = %req.key_id,
        algorithm = %algorithm,
        duration_ms = duration_ms,
        "Successfully produced HSM signature"
    );

    Ok(Json(SignResponse {
        key_id: req.key_id,
        algorithm: algorithm.to_string(),
        signature: signature_b64,
        duration_ms,
    }))
}

pub async fn get_health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

pub async fn get_ui_index() -> Html<&'static str> {
    Html(include_str!("../../ui/index.html"))
}

pub async fn get_ui_styles() -> ([(HeaderName, &'static str); 1], &'static str) {
    (
        [(CONTENT_TYPE, "text/css")],
        include_str!("../../ui/styles.css"),
    )
}

pub async fn get_ui_js() -> ([(HeaderName, &'static str); 1], &'static str) {
    (
        [(CONTENT_TYPE, "application/javascript")],
        include_str!("../../ui/app.js"),
    )
}

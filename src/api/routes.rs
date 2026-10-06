use crate::api::handlers::{
    get_health, get_ui_index, get_ui_js, get_ui_styles, post_sign, AppState,
};
use axum::routing::{get, post};
use axum::Router;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(get_ui_index))
        .route("/styles.css", get(get_ui_styles))
        .route("/app.js", get(get_ui_js))
        .route("/v1/sign", post(post_sign))
        .route("/health", get(get_health))
        .with_state(state)
}

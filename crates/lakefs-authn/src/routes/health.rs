//! Liveness, readiness, and the health check the lakeFS client calls.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use lakefs_auth_core::error::ApiError;

use crate::state::AppState;

/// `GET /healthz`: the process is up.
pub async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// `GET /readyz`: discovery succeeded at least once, so logins can work.
pub async fn readyz(State(state): State<AppState>) -> Result<Response, ApiError> {
    state.oidc.ready()?;
    Ok((StatusCode::OK, "ready").into_response())
}

/// `GET {base}/healthcheck`: 204, the only code the lakeFS client accepts.
pub async fn healthcheck() -> StatusCode {
    StatusCode::NO_CONTENT
}

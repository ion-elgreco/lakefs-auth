//! Health, readiness, and version.
//!
//! lakeFS calls `/healthcheck` and `/config/version` at startup and treats a
//! failure of either as fatal, so neither touches the database. `/readyz` is
//! for the orchestrator: it pings the store, so a replica whose database is
//! unreachable leaves the Service until the database is back.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::VersionConfig;

use crate::app::AppState;

/// `GET {base}/healthcheck`: the process is up. Unauthenticated.
pub async fn healthcheck() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// `GET /readyz`: 200 when the store answers, 503 otherwise. Unauthenticated.
pub async fn readyz(State(state): State<AppState>) -> Result<(StatusCode, &'static str), ApiError> {
    state.store.ping().await.map_err(|error| {
        tracing::warn!(error = %error, "readiness check failed: the store does not answer");
        ApiError::unavailable("the store does not answer")
    })?;
    Ok((StatusCode::OK, "ready"))
}

pub async fn version() -> Json<VersionConfig> {
    Json(VersionConfig {
        version: crate::VERSION.to_owned(),
    })
}

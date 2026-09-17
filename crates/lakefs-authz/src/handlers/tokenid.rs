//! `POST /auth/tokenid/claim`: make a lakeFS token single use.

use axum::extract::State;
use axum::http::StatusCode;
use lakefs_auth_core::error::{ApiError, ApiJson};
use lakefs_auth_core::model::ClaimTokenId;

use crate::app::AppState;
use crate::service;

pub async fn claim_token_id(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<ClaimTokenId>,
) -> Result<StatusCode, ApiError> {
    service::claim_token_id(&state, body).await?;
    Ok(StatusCode::CREATED)
}

//! `/auth/policies`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::{ApiError, ApiJson};
use lakefs_auth_core::model::{ListResponse, Policy};
use lakefs_auth_core::pagination::PaginationParams;

use crate::app::AppState;
use crate::service;

pub async fn list_policies(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<Policy>>, ApiError> {
    let policies = state.store.list_policies(&params.normalize()).await?;
    Ok(Json(policies.map(service::policy_to_wire).into_response()))
}

pub async fn create_policy(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Policy>,
) -> Result<(StatusCode, Json<Policy>), ApiError> {
    let policy = service::create_policy(&state, body).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

pub async fn get_policy(State(state): State<AppState>, Path(name): Path<String>) -> Result<Json<Policy>, ApiError> {
    let policy = state.store.get_policy(&name).await?;
    Ok(Json(service::policy_to_wire(policy)))
}

/// The only update in the API, and the only one that answers 200 instead of 201.
pub async fn update_policy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    ApiJson(body): ApiJson<Policy>,
) -> Result<Json<Policy>, ApiError> {
    let policy = service::update_policy(&state, &name, body).await?;
    Ok(Json(policy))
}

pub async fn delete_policy(State(state): State<AppState>, Path(name): Path<String>) -> Result<StatusCode, ApiError> {
    state.store.delete_policy(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

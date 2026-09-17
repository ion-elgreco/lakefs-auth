//! `/auth/groups`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::{ApiError, ApiJson};
use lakefs_auth_core::model::{Group, GroupCreation, ListResponse};
use lakefs_auth_core::pagination::PaginationParams;

use crate::app::AppState;
use crate::service;

pub async fn list_groups(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<Group>>, ApiError> {
    let groups = state.store.list_groups(&params.normalize()).await?;
    Ok(Json(groups.map(service::group_to_wire).into_response()))
}

pub async fn create_group(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<GroupCreation>,
) -> Result<(StatusCode, Json<Group>), ApiError> {
    let group = service::create_group(&state, body).await?;
    Ok((StatusCode::CREATED, Json(group)))
}

pub async fn get_group(State(state): State<AppState>, Path(group_id): Path<String>) -> Result<Json<Group>, ApiError> {
    let group = state.store.get_group(&group_id).await?;
    Ok(Json(service::group_to_wire(group)))
}

pub async fn delete_group(State(state): State<AppState>, Path(group_id): Path<String>) -> Result<StatusCode, ApiError> {
    state.store.delete_group(&group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

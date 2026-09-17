//! Group membership: `/auth/groups/{groupId}/members` and `/auth/users/{userId}/groups`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::{Group, ListResponse, User};
use lakefs_auth_core::pagination::PaginationParams;

use crate::app::AppState;
use crate::service;

pub async fn list_group_members(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<User>>, ApiError> {
    let members = state.store.list_group_members(&group_id, &params.normalize()).await?;
    Ok(Json(members.map(service::user_to_wire).into_response()))
}

pub async fn list_user_groups(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<Group>>, ApiError> {
    let groups = state.store.list_user_groups(&username, &params.normalize()).await?;
    Ok(Json(groups.map(service::group_to_wire).into_response()))
}

/// `PUT` is idempotent: adding an existing membership again is still 201.
pub async fn add_membership(
    State(state): State<AppState>,
    Path((group_id, username)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.add_membership(&group_id, &username).await?;
    Ok(StatusCode::CREATED)
}

pub async fn delete_membership(
    State(state): State<AppState>,
    Path((group_id, username)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.remove_membership(&group_id, &username).await?;
    Ok(StatusCode::NO_CONTENT)
}

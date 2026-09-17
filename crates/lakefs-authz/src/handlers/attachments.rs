//! Policy attachments for users and groups.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::{ListResponse, Policy};
use lakefs_auth_core::pagination::{PaginationParams, deserialize_lenient_bool};
use serde::Deserialize;

use crate::app::AppState;
use crate::service;

#[derive(Debug, Default, Deserialize)]
pub struct ListUserPoliciesQuery {
    #[serde(flatten)]
    pub page: PaginationParams,
    /// lakeFS asks for the effective set on every authorization decision.
    #[serde(default, deserialize_with = "deserialize_lenient_bool")]
    pub effective: bool,
}

pub async fn list_user_policies(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<ListUserPoliciesQuery>,
) -> Result<Json<ListResponse<Policy>>, ApiError> {
    let page = query.page.normalize();
    let policies = if query.effective {
        state.store.list_effective_user_policies(&username, &page).await?
    } else {
        state.store.list_user_policies(&username, &page).await?
    };
    Ok(Json(policies.map(service::policy_to_wire).into_response()))
}

pub async fn attach_policy_to_user(
    State(state): State<AppState>,
    Path((username, policy)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.attach_policy_to_user(&username, &policy).await?;
    Ok(StatusCode::CREATED)
}

pub async fn detach_policy_from_user(
    State(state): State<AppState>,
    Path((username, policy)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.detach_policy_from_user(&username, &policy).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_group_policies(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<Policy>>, ApiError> {
    let policies = state.store.list_group_policies(&group_id, &params.normalize()).await?;
    Ok(Json(policies.map(service::policy_to_wire).into_response()))
}

pub async fn attach_policy_to_group(
    State(state): State<AppState>,
    Path((group_id, policy)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.attach_policy_to_group(&group_id, &policy).await?;
    Ok(StatusCode::CREATED)
}

pub async fn detach_policy_from_group(
    State(state): State<AppState>,
    Path((group_id, policy)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.detach_policy_from_group(&group_id, &policy).await?;
    Ok(StatusCode::NO_CONTENT)
}

//! `/auth/users` and the per-user sub-resources that do not have their own module.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::{ApiError, ApiJson};
use lakefs_auth_core::model::{FriendlyNameUpdate, ListResponse, User, UserCreation};
use lakefs_auth_core::pagination::{PageOf, PaginationParams};
use lakefs_auth_core::text::non_blank;
use serde::Deserialize;

use crate::app::AppState;
use crate::service;

/// `GET /auth/users` takes the page parameters plus three mutually exclusive
/// lookups. A lookup that matches nothing answers with an empty list, which is
/// how lakeFS detects "no such user".
#[derive(Debug, Default, Deserialize)]
pub struct ListUsersQuery {
    #[serde(flatten)]
    pub page: PaginationParams,
    pub id: Option<String>,
    pub email: Option<String>,
    pub external_id: Option<String>,
}

fn single(user: Option<crate::store::types::UserRecord>) -> Json<ListResponse<User>> {
    let items = user.map(service::user_to_wire).into_iter().collect();
    Json(PageOf::last(items).into_response())
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<ListResponse<User>>, ApiError> {
    if let Some(id) = query.id.as_deref().and_then(non_blank) {
        let Ok(id) = id.parse::<i64>() else {
            return Ok(single(None));
        };
        return Ok(single(state.store.find_user_by_id(id).await?));
    }
    if let Some(email) = query.email.as_deref().and_then(non_blank) {
        return Ok(single(state.store.find_user_by_email(email).await?));
    }
    if let Some(external_id) = query.external_id.as_deref().and_then(non_blank) {
        return Ok(single(state.store.find_user_by_external_id(external_id).await?));
    }

    let page = query.page.normalize();
    let users = state.store.list_users(&page).await?;
    Ok(Json(users.map(service::user_to_wire).into_response()))
}

pub async fn create_user(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<UserCreation>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    let user = service::create_user(&state, body).await?;
    Ok((StatusCode::CREATED, Json(user)))
}

pub async fn get_user(State(state): State<AppState>, Path(username): Path<String>) -> Result<Json<User>, ApiError> {
    let user = state.store.get_user(&username).await?;
    Ok(Json(service::user_to_wire(user)))
}

pub async fn delete_user(State(state): State<AppState>, Path(username): Path<String>) -> Result<StatusCode, ApiError> {
    state.store.delete_user(&username).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// lakeFS never calls this route; password login is not part of version one.
/// Nothing is extracted, so even a malformed request gets 501 rather than 400.
pub async fn update_password() -> ApiError {
    ApiError::not_implemented("password authentication is not supported by this server")
}

pub async fn update_friendly_name(
    State(state): State<AppState>,
    Path(username): Path<String>,
    ApiJson(body): ApiJson<FriendlyNameUpdate>,
) -> Result<StatusCode, ApiError> {
    state.store.set_friendly_name(&username, &body.friendly_name).await?;
    Ok(StatusCode::NO_CONTENT)
}

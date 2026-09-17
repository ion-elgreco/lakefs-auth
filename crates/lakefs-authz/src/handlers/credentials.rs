//! Credentials. `GET /auth/credentials/{accessKeyId}` is the hot path lakeFS
//! uses to verify S3 signatures, and the only route that returns a secret.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::{Credentials, CredentialsWithSecret, ListResponse};
use lakefs_auth_core::pagination::PaginationParams;
use serde::Deserialize;

use crate::app::AppState;
use crate::service;

/// Both values are optional. When either is missing or empty the server
/// generates a fresh pair, which is what lakeFS setup relies on.
#[derive(Debug, Default, Deserialize)]
pub struct CreateCredentialsQuery {
    #[serde(default)]
    pub access_key: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
}

pub async fn list_user_credentials(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<Credentials>>, ApiError> {
    let credentials = state
        .store
        .list_user_credentials(&username, &params.normalize())
        .await?;
    let page = credentials.map(|record| service::credentials_to_wire(&record));
    Ok(Json(page.into_response()))
}

pub async fn create_credentials(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<CreateCredentialsQuery>,
) -> Result<(StatusCode, Json<CredentialsWithSecret>), ApiError> {
    let credentials = service::create_credentials(
        &state,
        &username,
        query.access_key.as_deref(),
        query.secret_key.as_deref(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(credentials)))
}

pub async fn get_credentials_for_user(
    State(state): State<AppState>,
    Path((username, access_key_id)): Path<(String, String)>,
) -> Result<Json<Credentials>, ApiError> {
    let record = state.store.get_user_credential(&username, &access_key_id).await?;
    Ok(Json(service::credentials_to_wire(&record)))
}

pub async fn delete_credentials(
    State(state): State<AppState>,
    Path((username, access_key_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.store.delete_credential(&username, &access_key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_credentials(
    State(state): State<AppState>,
    Path(access_key_id): Path<String>,
) -> Result<Json<CredentialsWithSecret>, ApiError> {
    let credentials = service::credentials_with_secret(&state, &access_key_id).await?;
    Ok(Json(credentials))
}

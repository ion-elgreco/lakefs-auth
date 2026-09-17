//! External principals: an identity such as an AWS IAM role ARN attached to a
//! user. lakeFS gates the login through them behind
//! `auth.authentication_api.external_principals_enabled`, which lakefs-authn does
//! not serve yet, but the store side is complete and served here.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::{ExternalPrincipal, ListResponse};
use lakefs_auth_core::pagination::PaginationParams;
use lakefs_auth_core::text::non_blank;
use serde::Deserialize;

use crate::app::AppState;
use crate::service;

/// `principalId` as the specification spells it.
#[derive(Debug, Default, Deserialize)]
pub struct PrincipalQuery {
    #[serde(rename = "principalId", default)]
    pub principal_id: Option<String>,
}

impl PrincipalQuery {
    fn principal_id(&self) -> Result<&str, ApiError> {
        let id = self
            .principal_id
            .as_deref()
            .and_then(non_blank)
            .ok_or_else(|| ApiError::invalid("principalId is required"))?;
        if id.chars().any(char::is_control) {
            return Err(ApiError::invalid("principalId must not contain control characters"));
        }
        Ok(id)
    }
}

pub async fn list_user_external_principals(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListResponse<ExternalPrincipal>>, ApiError> {
    let principals = state
        .store
        .list_user_external_principals(&username, &params.normalize())
        .await?;
    Ok(Json(principals.map(service::principal_to_wire).into_response()))
}

pub async fn create_user_external_principal(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<PrincipalQuery>,
) -> Result<StatusCode, ApiError> {
    state
        .store
        .create_external_principal(&username, query.principal_id()?)
        .await?;
    Ok(StatusCode::CREATED)
}

pub async fn delete_user_external_principal(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<PrincipalQuery>,
) -> Result<StatusCode, ApiError> {
    state
        .store
        .delete_external_principal(&username, query.principal_id()?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_external_principal(
    State(state): State<AppState>,
    Query(query): Query<PrincipalQuery>,
) -> Result<Json<ExternalPrincipal>, ApiError> {
    let record = state.store.get_external_principal(query.principal_id()?).await?;
    Ok(Json(service::principal_to_wire(record)))
}

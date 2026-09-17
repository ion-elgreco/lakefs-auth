//! Operations of `authentication.yml` that version one does not implement.

use lakefs_auth_core::error::ApiError;

const MESSAGE: &str = "not implemented";

/// `POST {base}/ldap/login`.
pub async fn ldap_login() -> ApiError {
    ApiError::not_implemented(MESSAGE)
}

/// `POST {base}/auth/external/principal/login`.
pub async fn external_principal_login() -> ApiError {
    ApiError::not_implemented(MESSAGE)
}

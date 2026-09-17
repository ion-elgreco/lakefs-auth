//! Error type shared by the handlers and services of both servers.
//!
//! Every variant renders as `{"message": "..."}`, the error body both lakeFS
//! clients understand, with one of the statuses lakeFS knows: 404, 400, 409,
//! 401, 403, 501, 503, and 500. `WithStatus` carries any other status, such as
//! the one lakeFS itself answered. Internal details stay in the logs.

use crate::model::ErrorBody;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    AlreadyExists(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotImplemented(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("internal error: {0:#}")]
    Internal(anyhow::Error),
    /// A public message under a status the other variants do not name.
    #[error("{message}")]
    WithStatus { status: u16, message: String },
}

impl ApiError {
    pub fn not_found(entity: &str, id: &str) -> Self {
        Self::NotFound(format!("{entity} not found: {id}"))
    }

    pub fn already_exists(entity: &str, id: &str) -> Self {
        Self::AlreadyExists(format!("{entity} already exists: {id}"))
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::NotImplemented(message.into())
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    pub fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::Internal(error.into())
    }

    pub fn with_status(status: u16, message: impl Into<String>) -> Self {
        Self::WithStatus {
            status,
            message: message.into(),
        }
    }

    /// HTTP status for the variant.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::NotFound(_) => 404,
            Self::Invalid(_) => 400,
            Self::AlreadyExists(_) => 409,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::NotImplemented(_) => 501,
            Self::Unavailable(_) => 503,
            Self::Internal(_) => 500,
            Self::WithStatus { status, .. } => *status,
        }
    }

    /// The same status as a typed value.
    #[cfg(feature = "server")]
    pub fn status(&self) -> axum::http::StatusCode {
        axum::http::StatusCode::from_u16(self.status_code()).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Message that is safe to send to the caller. Internal details stay in the logs.
    pub fn public_message(&self) -> String {
        match self {
            Self::Internal(_) => "internal server error".to_owned(),
            other => other.to_string(),
        }
    }

    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            message: self.public_message(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        if let Self::Internal(error) = &self {
            tracing::error!(error = format!("{error:#}"), "request failed");
        }
        (self.status(), axum::Json(self.body())).into_response()
    }
}

/// `axum::Json` as an extractor, with the contract's error shape on a
/// rejection: a body the server cannot read is a 400 with `{"message": ...}`,
/// never axum's plain-text 415 or 422. A body that could not be buffered
/// keeps its own status, so a body limit layer still answers 413.
#[cfg(feature = "server")]
pub struct ApiJson<T>(pub T);

#[cfg(feature = "server")]
impl<T, S> axum::extract::FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        use axum::extract::rejection::JsonRejection;

        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection @ JsonRejection::BytesRejection(_)) => Err(ApiError::with_status(
                rejection.status().as_u16(),
                rejection.body_text(),
            )),
            Err(rejection) => Err(ApiError::invalid(rejection.body_text())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_the_contract() {
        assert_eq!(ApiError::not_found("user", "x").status_code(), 404);
        assert_eq!(ApiError::invalid("x").status_code(), 400);
        assert_eq!(ApiError::already_exists("user", "x").status_code(), 409);
        assert_eq!(ApiError::unauthorized("x").status_code(), 401);
        assert_eq!(ApiError::forbidden("x").status_code(), 403);
        assert_eq!(ApiError::not_implemented("x").status_code(), 501);
        assert_eq!(ApiError::unavailable("x").status_code(), 503);
        assert_eq!(ApiError::with_status(502, "x").status_code(), 502);
    }

    #[test]
    fn internal_details_do_not_reach_the_caller() {
        let error = ApiError::internal(anyhow::anyhow!("database password is hunter2"));
        assert_eq!(error.public_message(), "internal server error");
        assert_eq!(error.status_code(), 500);
        assert_eq!(error.body().message, "internal server error");
    }
}

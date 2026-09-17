//! axum middleware that enforces the bearer token.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::TokenVerifier;
use crate::error::ApiError;

/// Use with `axum::middleware::from_fn_with_state(verifier, require_auth)`.
pub async fn require_auth(State(verifier): State<Arc<TokenVerifier>>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    match token {
        None if verifier.is_disabled() => next.run(request).await,
        None => ApiError::unauthorized("missing bearer token").into_response(),
        Some(token) => match verifier.verify(token) {
            Ok(()) => next.run(request).await,
            Err(error) => error.into_response(),
        },
    }
}

fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn parses_bearer_scheme_case_insensitively() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer  abc "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("abc"), None);
    }
}

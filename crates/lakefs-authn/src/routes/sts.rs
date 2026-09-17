//! `POST {base}/sts/login`: the code exchange behind the SDK token login that lakeFS forwards here.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use lakefs_auth_core::error::{ApiError, ApiJson};
use openidconnect::{PkceCodeVerifier, RedirectUrl};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::oidc::AnyNonce;
use crate::oidc::claims::{flatten_claims, validate_claims};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct StsLoginRequest {
    pub code: String,
    /// The lakeFS sample client puts the PKCE verifier here.
    #[serde(default)]
    pub state: String,
    pub redirect_uri: String,
}

#[derive(Debug, Serialize)]
pub struct StsLoginResponse {
    /// Every value is a string; lakeFS reads `sub` and the configured claim checks.
    pub claims: BTreeMap<String, String>,
}

pub async fn login(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<StsLoginRequest>,
) -> Result<Json<StsLoginResponse>, ApiError> {
    let discovered = state.oidc.ready()?;

    // This is the one unauthenticated route that redeems authorization codes,
    // and nothing binds the code to the caller, so an empty allow list refuses
    // every request rather than accepting any redirect URI.
    if !redirect_uri_allowed(state.cfg.sts_allowed_redirect_uris.as_slice(), &request.redirect_uri) {
        tracing::warn!("rejecting an STS login with a redirect URI that is not on the allow list");
        return Err(ApiError::invalid("redirect_uri is not allowed"));
    }
    let redirect_uri = RedirectUrl::new(request.redirect_uri.clone())
        .map_err(|_| ApiError::invalid("redirect_uri is not a valid URL"))?;

    let pkce_verifier = if state.cfg.state_is_pkce_verifier && !request.state.is_empty() {
        Some(PkceCodeVerifier::new(request.state))
    } else {
        None
    };

    let tokens = state
        .oidc
        .exchange_code(&discovered, request.code, pkce_verifier, Some(redirect_uri))
        .await?;

    // lakeFS never issued a nonce, so any value in the token is acceptable.
    let (claims, _raw) = state.oidc.verify_id_token(&discovered, &tokens, AnyNonce).await?;

    validate_claims(&claims, state.cfg.oidc_validate_claims.as_map()).map_err(|reason| {
        tracing::warn!(reason = %reason, "rejecting an STS login that fails the configured claim checks");
        ApiError::unauthorized("the identity does not satisfy the configured claim requirements")
    })?;

    // lakeFS looks the user up by external_id right after this call returns.
    let provisioned = state.prov.ensure_user(&claims).await?;
    tracing::info!(username = %provisioned.user.username, created = provisioned.created, "STS login succeeded");

    Ok(Json(StsLoginResponse {
        claims: flatten_claims(&claims),
    }))
}

/// True when `candidate` is on the allow list. An entry matches exactly, except
/// that a loopback entry without a port matches the same scheme, host, path,
/// and query on any port, which is what RFC 8252 requires for native clients
/// that listen on an ephemeral port.
pub fn redirect_uri_allowed(allowed: &[String], candidate: &str) -> bool {
    allowed
        .iter()
        .any(|entry| entry == candidate || loopback_matches(entry, candidate))
}

fn loopback_matches(entry: &str, candidate: &str) -> bool {
    let (Ok(entry), Ok(candidate)) = (Url::parse(entry), Url::parse(candidate)) else {
        return false;
    };
    let loopback = matches!(entry.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    loopback
        && entry.port().is_none()
        && entry.scheme() == candidate.scheme()
        && entry.host_str() == candidate.host_str()
        && entry.path() == candidate.path()
        && entry.query() == candidate.query()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn an_empty_allow_list_refuses_everything() {
        assert!(!redirect_uri_allowed(&[], "http://127.0.0.1:1234/callback"));
    }

    #[test]
    fn loopback_entries_match_any_port_and_others_match_exactly() {
        let allowed = list(&[
            "http://127.0.0.1/cb",
            "http://localhost/cb",
            "https://app.example.com/cb",
        ]);
        assert!(redirect_uri_allowed(&allowed, "http://127.0.0.1:41234/cb"));
        assert!(redirect_uri_allowed(&allowed, "http://127.0.0.1/cb"));
        assert!(redirect_uri_allowed(&allowed, "http://localhost:5/cb"));
        assert!(redirect_uri_allowed(&allowed, "https://app.example.com/cb"));
        assert!(!redirect_uri_allowed(&allowed, "https://127.0.0.1:41234/cb"));
        assert!(!redirect_uri_allowed(&allowed, "http://127.0.0.1:41234/other"));
        assert!(!redirect_uri_allowed(&allowed, "http://127.0.0.1:41234/cb?x=1"));
        assert!(!redirect_uri_allowed(&allowed, "https://app.example.com:8443/cb"));
        assert!(!redirect_uri_allowed(&allowed, "http://app.example.com/cb"));
        // A loopback entry with a port is exact, like any other entry.
        let pinned = list(&["http://127.0.0.1:9000/cb"]);
        assert!(redirect_uri_allowed(&pinned, "http://127.0.0.1:9000/cb"));
        assert!(!redirect_uri_allowed(&pinned, "http://127.0.0.1:9001/cb"));
    }
}

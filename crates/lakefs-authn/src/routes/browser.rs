//! The browser login: `/oidc/login`, `/oidc/callback`, and `/oidc/logout`.
//!
//! Authorization codes, tokens, and cookie values never reach the logs.

use std::str::FromStr;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::PrivateCookieJar;
use cookie::Cookie;
use lakefs_auth_core::error::ApiError;
use openidconnect::{ClientId, LogoutRequest, Nonce, PkceCodeVerifier, PostLogoutRedirectUrl};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::lakefs::jwt::mint_login_token;
use crate::lakefs::session::{FLOW_COOKIE, FLOW_TTL, ID_TOKEN_COOKIE};
use crate::oidc::claims::validate_claims;
use crate::oidc::types::AuthnIdToken;
use crate::oidc::{Discovered, ExpectedNonce};
use crate::routes::redirect_found;
use crate::state::AppState;
use crate::util::{resolve_next, safe_next};

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// What the login handler stores in the private flow cookie.
#[derive(Debug, Serialize, Deserialize)]
struct FlowState {
    #[serde(rename = "s")]
    state: String,
    #[serde(rename = "n")]
    nonce: String,
    #[serde(rename = "p")]
    pkce_verifier: String,
    #[serde(rename = "x", default, skip_serializing_if = "Option::is_none")]
    next: Option<String>,
    #[serde(rename = "t")]
    issued_at: i64,
}

/// `GET /oidc/login?next=`
pub async fn login(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let discovered = state.oidc.ready()?;

    let next = match query.next.as_deref() {
        Some(value) if !value.is_empty() => Some(
            safe_next(value, state.cfg.allowed_redirect_hosts.as_slice())
                .map_err(|error| ApiError::invalid(error.to_string()))?,
        ),
        _ => None,
    };

    let request = state.oidc.authorize_url(&discovered);
    let flow = FlowState {
        state: request.state.secret().clone(),
        nonce: request.nonce.secret().clone(),
        pkce_verifier: request.pkce_verifier.secret().clone(),
        next,
        issued_at: jiff::Timestamp::now().as_second(),
    };
    let payload = serde_json::to_string(&flow).map_err(ApiError::internal)?;
    let jar = jar.add(state.session.flow(payload));
    Ok((jar, redirect_found(request.url.as_str())).into_response())
}

/// `GET /oidc/callback?code&state`, also mounted under the API base path.
///
/// The flow cookie holds the state, nonce, and PKCE verifier of one login and
/// is single use. It is cleared on success and on every failure that comes
/// after the state check, so a used code cannot be replayed with the same
/// state. Before the state check it stays: anyone can send a browser to this
/// URL with a bad or missing state, and clearing the cookie then would let a
/// third party cancel a login in progress.
pub async fn callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let stored = jar.get(FLOW_COOKIE).map(|cookie| cookie.value().to_owned());
    let outcome = callback_inner(&state, stored, query).await;
    crate::metrics::record_browser_login(outcome.is_ok());
    let removal = || state.session.removal(FLOW_COOKIE);
    match outcome {
        Ok(login) => {
            let jar = jar.remove(removal());
            let jar = if state.cfg.rp_initiated_logout
                && let Some(cookie) = state.session.id_token(login.raw_id_token)
            {
                jar.add(cookie)
            } else {
                jar
            };
            let response = with_session_cookie(redirect_found(&login.target), &login.session_cookie);
            (jar, response).into_response()
        }
        Err(CallbackFailure { error, consume_flow }) => {
            let response = error.into_response();
            if consume_flow {
                (jar.remove(removal()), response).into_response()
            } else {
                response
            }
        }
    }
}

/// What a successful callback hands to the browser.
struct LoginOutcome {
    raw_id_token: String,
    target: String,
    /// The lakeFS session cookie.
    session_cookie: Cookie<'static>,
}

/// A failed callback, and whether it proved to be the provider's answer to the
/// stored flow, in which case the flow cookie is consumed.
struct CallbackFailure {
    error: ApiError,
    consume_flow: bool,
}

/// The body of the callback, without the cookie jar. Split out so that one
/// counter call and one cookie decision cover every exit.
///
/// The flow cookie decision follows the structure: a failure of the state
/// check keeps the cookie, and every failure after it consumes the cookie,
/// because from then on the request is the provider's answer to this flow.
async fn callback_inner(
    state: &AppState,
    stored: Option<String>,
    query: CallbackQuery,
) -> Result<LoginOutcome, CallbackFailure> {
    let flow: Option<FlowState> = stored.as_deref().and_then(|value| serde_json::from_str(value).ok());
    let state_matches = match (&flow, query.state.as_deref()) {
        (Some(flow), Some(received)) => bool::from(received.as_bytes().ct_eq(flow.state.as_bytes())),
        _ => false,
    };

    if let Some(error) = query.error.as_deref() {
        let detail = query.error_description.as_deref().unwrap_or(error);
        tracing::warn!(error = %error, "the identity provider refused the login");
        return Err(CallbackFailure {
            error: ApiError::unauthorized(format!("login failed: {detail}")),
            consume_flow: state_matches,
        });
    }

    let (discovered, flow) = check_state(state, flow, state_matches).map_err(|error| CallbackFailure {
        error,
        consume_flow: false,
    })?;
    finish_login(state, &discovered, flow, query.code)
        .await
        .map_err(|error| CallbackFailure {
            error,
            consume_flow: true,
        })
}

/// The part of the callback that anyone can trigger: the server must be ready,
/// the browser must carry a flow, and the state must match it.
fn check_state(
    state: &AppState,
    flow: Option<FlowState>,
    state_matches: bool,
) -> Result<(std::sync::Arc<Discovered>, FlowState), ApiError> {
    let discovered = state.oidc.ready()?;
    let flow = flow.ok_or_else(|| ApiError::invalid("the login session is missing or expired, start again"))?;
    if !state_matches {
        tracing::warn!("the callback state does not match the login state");
        return Err(ApiError::invalid("the login state does not match, start again"));
    }
    Ok((discovered, flow))
}

/// The part of the callback that is the provider's answer to the flow: the
/// code exchange, the token checks, the provisioning, and the session cookie.
async fn finish_login(
    state: &AppState,
    discovered: &Discovered,
    flow: FlowState,
    code: Option<String>,
) -> Result<LoginOutcome, ApiError> {
    if jiff::Timestamp::now().as_second() - flow.issued_at > FLOW_TTL.as_secs() as i64 {
        return Err(ApiError::invalid("the login session expired, start again"));
    }
    let code = code
        .filter(|code| !code.is_empty())
        .ok_or_else(|| ApiError::invalid("the callback carries no authorization code"))?;

    let tokens = state
        .oidc
        .exchange_code(discovered, code, Some(PkceCodeVerifier::new(flow.pkce_verifier)), None)
        .await?;
    let (claims, raw_id_token) = state
        .oidc
        .verify_id_token(discovered, &tokens, ExpectedNonce(Nonce::new(flow.nonce)))
        .await?;
    validate_claims(&claims, state.cfg.oidc_validate_claims.as_map()).map_err(|reason| {
        tracing::warn!(reason = %reason, "rejecting a login that fails the configured claim checks");
        ApiError::forbidden("the identity does not satisfy the configured claim requirements")
    })?;

    let provisioned = state.prov.ensure_user(&claims).await?;
    let token = mint_login_token(
        &state.jwt_key,
        &provisioned.user.username,
        state.cfg.effective_session_ttl(),
    )
    .map_err(ApiError::internal)?;
    let session_cookie = state.session.login(&token).map_err(ApiError::internal)?;

    let target = resolve_next(&state.cfg.post_login_redirect_url, flow.next.as_deref());
    tracing::info!(username = %provisioned.user.username, created = provisioned.created, "browser login succeeded");
    Ok(LoginOutcome {
        raw_id_token,
        target,
        session_cookie,
    })
}

/// `GET /oidc/logout`
pub async fn logout(State(state): State<AppState>, jar: PrivateCookieJar) -> Result<Response, ApiError> {
    let id_token = jar.get(ID_TOKEN_COOKIE).map(|cookie| cookie.value().to_owned());
    let jar = jar
        .remove(state.session.removal(FLOW_COOKIE))
        .remove(state.session.removal(ID_TOKEN_COOKIE));

    let target = self::logout_target(&state, id_token.as_deref());
    let response = with_session_cookie(redirect_found(&target), &state.session.clear());
    Ok((jar, response).into_response())
}

/// Appends the lakeFS session `Set-Cookie` header with its value verbatim.
///
/// lakeFS opens the value with gorilla `securecookie`, whose base64 decoder
/// rejects a `%`. A cookie jar percent-encodes the value, so the base64 padding
/// would go out as `%3D` and lakeFS would silently treat the browser as
/// anonymous. Whether padding occurs depends on the length of the username.
fn with_session_cookie(mut response: Response, cookie: &Cookie<'_>) -> Response {
    match HeaderValue::from_str(&cookie.to_string()) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
            response
        }
        Err(error) => ApiError::internal(error).into_response(),
    }
}

fn logout_target(state: &AppState, id_token: Option<&str>) -> String {
    if state.cfg.rp_initiated_logout
        && let Some(discovered) = state.oidc.current()
        && let Some(end_session) = discovered.end_session_endpoint.clone()
    {
        let mut request =
            LogoutRequest::from(end_session).set_client_id(ClientId::new(state.cfg.oidc_client_id.clone()));
        if let Some(raw) = id_token
            && let Ok(parsed) = AuthnIdToken::from_str(raw)
        {
            request = request.set_id_token_hint(&parsed);
        }
        if let Some(redirect) = post_logout_redirect(state) {
            request = request.set_post_logout_redirect_uri(redirect);
        }
        return request.http_get_url().to_string();
    }
    state.cfg.post_logout_redirect_url.clone()
}

/// The provider needs an absolute URI, so a relative setting resolves against the public URL.
fn post_logout_redirect(state: &AppState) -> Option<PostLogoutRedirectUrl> {
    let configured = &state.cfg.post_logout_redirect_url;
    let absolute = match url::Url::parse(configured) {
        Ok(url) => url,
        Err(_) => state.cfg.public_url.join(configured).ok()?,
    };
    Some(PostLogoutRedirectUrl::from_url(absolute))
}

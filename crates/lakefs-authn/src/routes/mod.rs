//! HTTP surface: the browser OIDC routes, the lakeFS authentication API, and health.

pub mod browser;
pub mod health;
pub mod sts;
pub mod stubs;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use lakefs_auth_core::telemetry::with_http_layers;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::state::AppState;

/// `POST /sts/login` carries three short strings; anything larger is a mistake.
pub const MAX_STS_BODY: usize = 64 * 1024;

/// Builds the whole router. Exposed so that tests can run the server in process.
pub fn build_router(state: AppState) -> Router {
    let base = state.cfg.base_path();

    let mut api = Router::new()
        .route("/healthcheck", get(health::healthcheck))
        .route(
            "/sts/login",
            post(sts::login).layer(RequestBodyLimitLayer::new(MAX_STS_BODY)),
        )
        .route("/ldap/login", post(stubs::ldap_login))
        .route("/auth/external/principal/login", post(stubs::external_principal_login));

    let mut router = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/oidc/login", get(browser::login))
        .route("/oidc/callback", get(browser::callback))
        .route("/oidc/logout", get(browser::logout));

    if base.is_empty() {
        // Without a base path the alias would collide with the browser callback.
        router = router.merge(api);
    } else {
        // The spec mounts the browser callback under the API base path as well.
        api = api.route("/oidc/callback", get(browser::callback));
        router = router.nest(&base, api);
    }

    // A slow identity provider or authorization server must not pin a
    // connection forever, so every route has the same server-side ceiling.
    let timeout = TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, state.cfg.request_timeout);
    with_http_layers(router.with_state(state).layer(timeout))
}

/// A 302 with a `Location` header, which is what browsers expect after a login.
pub fn redirect_found(target: &str) -> Response {
    match HeaderValue::from_str(target) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => {
            tracing::error!("refusing to redirect to a target that cannot be a header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

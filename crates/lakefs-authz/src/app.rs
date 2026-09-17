//! Application state, router assembly, and the server loop.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use lakefs_auth_core::auth::TokenVerifier;
use lakefs_auth_core::auth::middleware::require_auth;
use lakefs_auth_core::crypto::SecretBox;
use lakefs_auth_core::shutdown::shutdown_signal;
use lakefs_auth_core::telemetry::with_http_layers;
use lakefs_auth_core::text::normalize_base_path;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;

use crate::routes;
use crate::store::Store;

/// Everything a handler needs. Cheap to clone: three `Arc`s.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub secrets: Arc<SecretBox>,
    pub verifier: Arc<TokenVerifier>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, secrets: SecretBox, verifier: TokenVerifier) -> Self {
        Self {
            store,
            secrets: Arc::new(secrets),
            verifier: Arc::new(verifier),
        }
    }
}

/// Everything about the HTTP surface that is not the state.
#[derive(Debug, Clone)]
pub struct RouterOptions {
    /// Prefix every route sits behind. lakeFS uses `auth.api.endpoint` verbatim,
    /// so this must match the `/api/v1` in that URL.
    pub base_path: String,
    /// lakeFS has no client timeout toward this server, so the server has one.
    pub request_timeout: Duration,
    /// Empty means no CORS layer. `*` allows any origin.
    pub cors_allow_origins: Vec<String>,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            base_path: crate::DEFAULT_BASE_PATH.to_owned(),
            request_timeout: Duration::from_secs(30),
            cors_allow_origins: Vec::new(),
        }
    }
}

impl RouterOptions {
    #[must_use]
    pub fn with_base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = base_path.into();
        self
    }
}

/// Builds the router with the layer order from the design: request id, trace,
/// request id propagation, timeout, optional CORS, bearer authentication. The
/// readiness probe sits at the root, outside the base path and the bearer check.
pub fn build_router(state: AppState, options: &RouterOptions) -> Router {
    let verifier = Arc::clone(&state.verifier);
    let root = routes::root_router().with_state(state.clone());
    let api = routes::protected_router()
        .layer(axum::middleware::from_fn_with_state(verifier, require_auth))
        .merge(routes::public_router())
        .with_state(state);

    let base = normalize_base_path(&options.base_path);
    let app = if base.is_empty() {
        api.merge(root)
    } else {
        Router::new().nest(&base, api).merge(root)
    };

    let app = match cors_layer(&options.cors_allow_origins) {
        Some(cors) => app.layer(cors),
        None => app,
    };
    let timeout = TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, options.request_timeout);
    with_http_layers(app.layer(timeout))
}

/// Serves until Ctrl+C or SIGTERM.
pub async fn serve(listener: tokio::net::TcpListener, router: Router) -> std::io::Result<()> {
    serve_with_shutdown(listener, router, shutdown_signal()).await
}

/// Serves until `shutdown` resolves. Tests use this to stop the server.
pub async fn serve_with_shutdown(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router).with_graceful_shutdown(shutdown).await
}

fn cors_layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    // The headers are mirrored from the preflight rather than answered with
    // `*`: the Fetch specification never lets the wildcard cover
    // `Authorization`, which every call to this API carries.
    let layer = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(AllowHeaders::mirror_request());
    if origins.iter().any(|origin| origin == "*") {
        return Some(layer.allow_origin(Any));
    }
    let list: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();
    Some(layer.allow_origin(list))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_is_off_unless_origins_are_configured() {
        assert!(cors_layer(&[]).is_none());
        assert!(cors_layer(&["*".to_owned()]).is_some());
        assert!(cors_layer(&["http://localhost:8000".to_owned()]).is_some());
    }

    /// The Fetch specification never lets a `*` in `Access-Control-Allow-Headers`
    /// cover `Authorization`, so a preflight must name the headers the browser
    /// asks for, or no browser can send the bearer token.
    #[tokio::test]
    async fn cors_preflights_allow_the_authorization_header() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let cors = cors_layer(&["http://ui.test".to_owned()]).expect("a layer");
        let router = Router::new()
            .route("/x", axum::routing::get(|| async { "ok" }))
            .layer(cors);
        let request = Request::builder()
            .method("OPTIONS")
            .uri("/x")
            .header("origin", "http://ui.test")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "authorization, content-type")
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("serve");
        let allowed = response
            .headers()
            .get("access-control-allow-headers")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(allowed.contains("authorization"), "{allowed:?}");
        assert!(allowed.contains("content-type"), "{allowed:?}");
    }
}

//! The policy builder page and the read-only data it needs.
//!
//! It runs on its own listener, like the metrics endpoint, and never on the
//! listener that carries the API. The API listener keeps every route behind its
//! bearer token, and that token never reaches a browser.
//!
//! Every data route acts as the person using the page. The browser already
//! holds the `internal_auth_session` cookie from signing in to lakeFS, and
//! cookies ignore the port, so the builder receives it and forwards it to
//! lakeFS. lakeFS then applies that user's own policies. Nobody sees a
//! repository, branch, user, group, or policy they could not already see, and
//! the server stores no lakeFS credential of its own.
//!
//! One route writes: `POST /api/policies` creates the policy in lakeFS. It
//! carries the caller's session, so lakeFS enforces `auth:CreatePolicy` and the
//! page can do nothing the person could not already do in the lakeFS user
//! interface. Because that session is a cookie, the write also refuses any
//! request whose `Origin` is not the builder's own or whose browser marks it
//! cross-site, so a page elsewhere cannot drive it with the visitor's cookie.
//! The router carries the same request id, tracing, and metrics layers as the
//! API, so every write leaves a trace.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use lakefs_auth_core::error::{ApiError, ApiJson};
use lakefs_auth_core::listener::serve_aux;
use lakefs_auth_core::model::Statement;
use lakefs_auth_core::telemetry::with_http_layers;
use lakefs_auth_core::validate::validate_policy;
use serde::{Deserialize, Serialize};

use crate::lakefs::{LakeFsClient, LakeFsError, Session};

/// The page, compiled in so the server needs no files on disk.
const PAGE: &str = include_str!("../assets/policy-builder.html");

/// The lakeFS client behind the builder routes, when an endpoint is configured.
#[derive(Clone)]
pub struct BuilderState {
    pub lakefs: Option<LakeFsClient>,
}

/// What the page can offer, decided per request.
#[derive(Serialize)]
struct Context {
    /// True when a lakeFS endpoint is configured.
    lakefs: bool,
    /// The lakeFS user the caller's session resolves to, if it resolves at all.
    user: Option<String>,
}

#[derive(Serialize)]
struct Names {
    users: Vec<String>,
    groups: Vec<String>,
    policies: Vec<String>,
}

#[derive(Serialize)]
struct Repositories {
    repositories: Vec<String>,
}

#[derive(Serialize)]
struct Branches {
    branches: Vec<String>,
}

/// What the page sends to create a policy.
#[derive(Deserialize)]
struct PolicyRequest {
    name: String,
    statement: Vec<Statement>,
}

#[derive(Serialize)]
struct Created {
    name: String,
}

/// The builder router. Mount it on a dedicated listener.
pub fn builder_router(state: BuilderState) -> Router {
    with_http_layers(
        Router::new()
            .route("/", get(page))
            .route("/api/context", get(context))
            .route("/api/names", get(names))
            .route("/api/policies", post(create_policy))
            .route("/api/repositories", get(repositories))
            .route("/api/repositories/{repository}/branches", get(branches))
            .with_state(state),
    )
}

async fn page() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE)
}

/// Reports whether lakeFS is reachable for this caller, and as whom.
///
/// This never fails: the page uses it to choose between live fields and free
/// text, so an anonymous visitor gets `user: null` rather than an error.
async fn context(State(state): State<BuilderState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(client) = state.lakefs.as_ref() else {
        return axum::Json(Context {
            lakefs: false,
            user: None,
        });
    };
    let user = match session(&headers) {
        Some(session) => client.current_user(&session).await.ok(),
        None => None,
    };
    axum::Json(Context { lakefs: true, user })
}

/// User, group, and policy names, read from lakeFS as the caller.
///
/// lakeFS enforces `auth:ListUsers`, `auth:ListGroups`, and `auth:ListPolicies`,
/// so a caller without one of those permissions gets an empty list for it.
async fn names(State(state): State<BuilderState>, headers: HeaderMap) -> Result<impl IntoResponse, BuilderError> {
    let (client, session) = live(&state, &headers)?;
    let (users, groups, policies) = client.names(&session).await?;
    Ok(axum::Json(Names {
        users,
        groups,
        policies,
    }))
}

/// Creates the policy in lakeFS, as the caller.
///
/// The same rules that guard the API run here first, so an invalid policy never
/// leaves this server. Whatever lakeFS then says, including "already exists",
/// is passed back with its own status so the page can show the real reason.
async fn create_policy(
    State(state): State<BuilderState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<PolicyRequest>,
) -> Result<impl IntoResponse, BuilderError> {
    same_origin(&headers)?;
    let (client, session) = live(&state, &headers)?;
    validate_policy(&request.name, &request.statement)?;

    let name = client
        .create_policy(&request.name, &request.statement, &session)
        .await?;
    tracing::info!(policy = %name, "the policy builder created a policy in lakeFS");
    Ok((StatusCode::CREATED, axum::Json(Created { name })))
}

async fn repositories(
    State(state): State<BuilderState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BuilderError> {
    let (client, session) = live(&state, &headers)?;
    Ok(axum::Json(Repositories {
        repositories: client.repositories(&session).await?,
    }))
}

async fn branches(
    State(state): State<BuilderState>,
    headers: HeaderMap,
    Path(repository): Path<String>,
) -> Result<impl IntoResponse, BuilderError> {
    let (client, session) = live(&state, &headers)?;
    Ok(axum::Json(Branches {
        branches: client.branches(&repository, &session).await?,
    }))
}

/// A configured lakeFS client together with the caller's session, or an error
/// that tells the page which of the two is missing.
fn live<'a>(state: &'a BuilderState, headers: &HeaderMap) -> Result<(&'a LakeFsClient, Session), BuilderError> {
    let client = state.lakefs.as_ref().ok_or(BuilderError::NoLakeFs)?;
    let session = session(headers).ok_or(BuilderError::NoSession)?;
    Ok((client, session))
}

fn session(headers: &HeaderMap) -> Option<Session> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(Session::from_cookie_header)
}

/// The cross-site request forgery guard of the write route.
///
/// A browser that sends `Sec-Fetch-Site` has already compared the page's origin
/// with this request, and only `same-origin` (or `none`, a navigation the user
/// started) passes. That verdict wins over the `Host` header, which a reverse
/// proxy may rewrite to the upstream address. Without it, `Origin` must name
/// this server. A request without either header, such as one from a script,
/// passes: it holds no cookie it did not obtain itself.
fn same_origin(headers: &HeaderMap) -> Result<(), BuilderError> {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    if let Some(site) = text("sec-fetch-site") {
        let own = site.eq_ignore_ascii_case("same-origin") || site.eq_ignore_ascii_case("none");
        return if own { Ok(()) } else { Err(BuilderError::CrossOrigin) };
    }
    if let Some(origin) = text("origin") {
        let authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
        let host = text("host").unwrap_or_default();
        if !authority.eq_ignore_ascii_case(host) {
            return Err(BuilderError::CrossOrigin);
        }
    }
    Ok(())
}

/// Binds `address` and serves the builder until `shutdown` resolves.
///
/// A bind failure is logged and the future returns. The builder is an operator
/// convenience, so it must never stop the authorization server from starting.
pub async fn serve_builder(address: String, state: BuilderState, shutdown: impl Future<Output = ()> + Send + 'static) {
    tracing::info!(
        lakefs = state.lakefs.is_some(),
        "the policy builder acts with the caller's own lakeFS session"
    );
    serve_aux("policy builder", address, builder_router(state), shutdown).await;
}

#[derive(Debug, thiserror::Error)]
enum BuilderError {
    #[error("no lakeFS endpoint is configured")]
    NoLakeFs,
    #[error("sign in to lakeFS first: no {cookie} cookie was sent", cookie = crate::lakefs::SESSION_COOKIE)]
    NoSession,
    #[error("the request comes from another origin")]
    CrossOrigin,
    #[error(transparent)]
    LakeFs(#[from] LakeFsError),
    #[error(transparent)]
    Invalid(#[from] ApiError),
}

impl From<BuilderError> for ApiError {
    fn from(error: BuilderError) -> Self {
        let message = error.to_string();
        match error {
            // A wrapped API error keeps its own status and its public message,
            // so an internal error stays a 500 and never shows its chain.
            BuilderError::Invalid(error) => error,
            BuilderError::NoLakeFs => Self::NotFound(message),
            BuilderError::NoSession => Self::Unauthorized(message),
            BuilderError::CrossOrigin => Self::Forbidden(message),
            BuilderError::LakeFs(LakeFsError::Forbidden { .. }) => Self::Unauthorized(message),
            // lakeFS already decided: keep its status so 409 stays a conflict.
            BuilderError::LakeFs(LakeFsError::Rejected { status, .. }) => Self::with_status(status.as_u16(), message),
            BuilderError::LakeFs(_) => {
                tracing::warn!(error = %message, "a policy builder request failed");
                Self::with_status(StatusCode::BAD_GATEWAY.as_u16(), message)
            }
        }
    }
}

impl IntoResponse for BuilderError {
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::Request;
    use lakefs_auth_core::SESSION_COOKIE;
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::*;

    /// Extracts the `CATALOG = {...};` literal the page carries.
    fn embedded_catalog() -> Value {
        let start = PAGE.find("const CATALOG = ").expect("the page declares CATALOG");
        let body = &PAGE[start + "const CATALOG = ".len()..];
        let end = body.find(";\n").expect("the CATALOG literal ends with a semicolon");
        serde_json::from_str(&body[..end]).expect("the CATALOG literal is JSON")
    }

    /// The page must offer the same actions the crate knows about. Without this
    /// test the page could drift and suggest an action lakeFS no longer has.
    #[test]
    fn the_page_carries_the_same_catalog_as_the_crate() {
        assert_eq!(
            embedded_catalog(),
            lakefs_auth_core::catalog::as_json(),
            "the page is stale; run `just sync-catalog`"
        );
    }

    /// The documentation reaches the page through a symlink, so it can never go
    /// stale. This guards the symlink itself: a plain copy, or a link pointing
    /// somewhere else, would let the two drift apart again.
    #[test]
    fn the_documentation_links_to_this_exact_page() {
        let link = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/tools/builder.html"));
        let target = std::fs::read_link(link).expect("docs/tools/builder.html is a symlink");
        assert_eq!(
            target,
            std::path::Path::new("../../crates/lakefs-authz/assets/policy-builder.html"),
            "the documentation symlink points somewhere unexpected"
        );
        let through_link = std::fs::read_to_string(link).expect("the symlink resolves");
        assert_eq!(through_link, PAGE, "the symlink does not resolve to the served page");
    }

    /// Calls the builder in process and buffers the answer.
    async fn call(router: Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let response = router.oneshot(request).await.expect("serve");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, headers, String::from_utf8(body.to_vec()).expect("utf-8"))
    }

    /// A builder whose lakeFS endpoint is a closed port, so any request that
    /// reaches lakeFS fails loudly with 502.
    fn unreachable_lakefs_router() -> Router {
        let client = LakeFsClient::new("http://127.0.0.1:1/api/v1", Duration::from_secs(1)).expect("client");
        builder_router(BuilderState { lakefs: Some(client) })
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).expect("request")
    }

    /// A policy write with the session cookie and the given extra headers.
    fn post_policy(body: &Value, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/policies")
            .header("host", "builder.test:8080")
            .header("content-type", "application/json")
            .header("cookie", format!("{SESSION_COOKIE}=pretend"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::from(body.to_string())).expect("request")
    }

    /// Calls every route without a session, which is what an unauthenticated
    /// visitor gets.
    #[tokio::test]
    async fn a_caller_without_a_session_gets_the_page_but_no_data() {
        let router = unreachable_lakefs_router();

        let (status, headers, body) = call(router.clone(), get("/")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers["content-type"], "text/html; charset=utf-8",
            "a browser must render the page, not download it"
        );
        assert_eq!(body, PAGE, "the page is truncated");

        // The context never fails; it reports that nobody is signed in.
        let (status, _, body) = call(router.clone(), get("/api/context")).await;
        assert_eq!(status, StatusCode::OK);
        let context: Value = serde_json::from_str(&body).expect("context is JSON");
        assert_eq!(context, serde_json::json!({ "lakefs": true, "user": null }));

        // Every data route refuses without a session, and none of them reaches
        // lakeFS, so the unreachable endpoint above is never contacted.
        for path in ["/api/names", "/api/repositories", "/api/repositories/demo/branches"] {
            let (status, _, _) = call(router.clone(), get(path)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    /// A policy that the API would reject must never reach lakeFS. The client
    /// here points at a closed port, so any request that escapes fails loudly
    /// with 502 instead of the 400 these cases expect.
    #[tokio::test]
    async fn an_invalid_policy_is_refused_before_lakefs_is_called() {
        let router = unreachable_lakefs_router();
        let fine = serde_json::json!({ "name": "Fine", "statement": [
            { "effect": "allow", "action": ["fs:ReadObject"], "resource": "*" }
        ]});

        // A session is needed at all: without one the route stops first.
        let mut request = post_policy(&fine, &[]);
        request.headers_mut().remove("cookie");
        let (status, _, _) = call(router.clone(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no session");

        let cases = [
            (
                "a slash in the name",
                serde_json::json!({ "name": "bad/name", "statement": [
                    { "effect": "allow", "action": ["fs:ReadObject"], "resource": "*" }
                ]}),
            ),
            (
                "an unknown service",
                serde_json::json!({ "name": "Fine", "statement": [
                    { "effect": "allow", "action": ["nosuch:Read"], "resource": "*" }
                ]}),
            ),
            (
                "a resource that is not an ARN",
                serde_json::json!({ "name": "Fine", "statement": [
                    { "effect": "allow", "action": ["fs:ReadObject"], "resource": "repository/x" }
                ]}),
            ),
            (
                "no statement at all",
                serde_json::json!({ "name": "Fine", "statement": [] }),
            ),
            ("a body that is not a policy", serde_json::json!({ "name": 7 })),
        ];
        for (what, body) in cases {
            let (status, _, text) = call(router.clone(), post_policy(&body, &[])).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what}");
            let error: Value = serde_json::from_str(&text).expect("the error body is JSON");
            assert!(error["message"].is_string(), "{what}: {text}");
        }
    }

    /// A wrapped internal error must not leak its chain to the caller, and its
    /// status must be the one the error carries, not a flat 400.
    #[tokio::test]
    async fn a_wrapped_api_error_keeps_its_status_and_hides_internal_details() {
        let error = BuilderError::Invalid(lakefs_auth_core::error::ApiError::internal(anyhow::anyhow!(
            "database password is hunter2"
        )));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf-8");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("internal server error"), "{text}");

        let invalid = BuilderError::Invalid(lakefs_auth_core::error::ApiError::invalid("bad name"));
        assert_eq!(invalid.into_response().status(), StatusCode::BAD_REQUEST);
    }

    /// The write route is protected by the lakeFS session cookie, so a page on
    /// another origin must not be able to drive it with the visitor's cookie.
    #[tokio::test]
    async fn a_cross_origin_policy_write_is_refused() {
        let router = unreachable_lakefs_router();
        let body = serde_json::json!({ "name": "Fine", "statement": [
            { "effect": "allow", "action": ["fs:ReadObject"], "resource": "*" }
        ]});

        for headers in [
            &[("origin", "http://evil.test")][..],
            &[("origin", "http://builder.test:9999")][..],
            &[("sec-fetch-site", "cross-site")][..],
            // A sibling site shares the cookie and is not the page's own origin.
            &[("sec-fetch-site", "same-site")][..],
            &[("sec-fetch-site", "same-site"), ("origin", "http://builder.test:8080")][..],
        ] {
            let (status, _, _) = call(router.clone(), post_policy(&body, headers)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{headers:?}");
        }
        // The page's own origin passes the guard and reaches lakeFS, which is unreachable here.
        // A browser's `Sec-Fetch-Site` verdict wins over the `Host` header, which a
        // reverse proxy may rewrite to the upstream address.
        for headers in [
            &[("origin", "http://builder.test:8080")][..],
            &[("sec-fetch-site", "same-origin")][..],
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://builder.example.com"),
            ][..],
            &[("sec-fetch-site", "none")][..],
            &[][..],
        ] {
            let (status, _, _) = call(router.clone(), post_policy(&body, headers)).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{headers:?}");
        }
    }

    /// The builder carries the same request id and tracing layers as the API,
    /// so a policy write leaves a trace.
    #[tokio::test]
    async fn builder_responses_carry_a_request_id() {
        let (_, headers, _) = call(builder_router(BuilderState { lakefs: None }), get("/")).await;
        assert!(headers.get("x-request-id").is_some());
    }

    /// With no lakeFS endpoint the page still works, in standalone mode.
    #[tokio::test]
    async fn without_a_lakefs_endpoint_the_data_routes_report_they_are_off() {
        let router = builder_router(BuilderState { lakefs: None });
        let (status, _, _) = call(router.clone(), get("/api/context")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(router, get("/api/repositories")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

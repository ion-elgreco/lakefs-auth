//! The bearer token rules: every route but the health check needs one, and the
//! token is either the static `auth.api.token` or the HS256 token lakeFS mints
//! from `auth.encrypt.secret_key`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{BASE, SECRET, TestServer, call, internal_token, router_with};
use lakefs_auth_core::auth::TokenVerifier;
use lakefs_authz::app::RouterOptions;
use lakefs_authz::routes::ROUTE_TABLE;

fn request(path: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(value) = authorization {
        builder = builder.header("authorization", value);
    }
    builder.body(Body::empty()).expect("build request")
}

fn secret_verifier() -> TokenVerifier {
    TokenVerifier::new(Some(SECRET), None, false).expect("verifier")
}

#[tokio::test]
async fn the_health_check_is_the_only_unauthenticated_route() {
    let router = router_with(secret_verifier(), BASE);

    let health = call(&router, request(&format!("{BASE}/healthcheck"), None)).await;
    assert_eq!(health.status, StatusCode::NO_CONTENT);

    for path in ["/config/version", "/auth/users", "/auth/groups", "/auth/policies"] {
        let response = call(&router, request(&format!("{BASE}{path}"), None)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
        assert!(!response.message().is_empty(), "{path}");
    }
}

#[tokio::test]
async fn a_token_minted_from_the_shared_secret_is_accepted() {
    let router = router_with(secret_verifier(), BASE);
    let header = format!("Bearer {}", internal_token(SECRET));
    let response = call(&router, request(&format!("{BASE}/config/version"), Some(&header))).await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn wrong_secrets_and_malformed_headers_are_rejected() {
    let router = router_with(secret_verifier(), BASE);
    let path = format!("{BASE}/auth/users");

    let cases = [
        format!("Bearer {}", internal_token("a different secret")),
        "Bearer not-a-jwt".to_owned(),
        "Bearer ".to_owned(),
        "Basic dXNlcjpwYXNz".to_owned(),
        internal_token(SECRET),
    ];
    for header in cases {
        let response = call(&router, request(&path, Some(&header))).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{header}");
    }
}

#[tokio::test]
async fn a_static_token_is_compared_exactly() {
    let verifier = TokenVerifier::new(None, Some("static-api-token"), false).expect("verifier");
    let router = router_with(verifier, BASE);
    let path = format!("{BASE}/config/version");

    let ok = call(&router, request(&path, Some("Bearer static-api-token"))).await;
    assert_eq!(ok.status, StatusCode::OK);

    for header in ["Bearer static-api-toke", "Bearer static-api-token2", "Bearer other"] {
        let response = call(&router, request(&path, Some(header))).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{header}");
    }
}

#[tokio::test]
async fn disabled_authentication_accepts_everything() {
    let router = router_with(TokenVerifier::disabled(), BASE);
    let path = format!("{BASE}/config/version");

    assert_eq!(call(&router, request(&path, None)).await.status, StatusCode::OK);
    assert_eq!(
        call(&router, request(&path, Some("Bearer nonsense"))).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn routes_live_under_the_configured_base_path() {
    let router = router_with(secret_verifier(), "/custom/base");
    let header = format!("Bearer {}", internal_token(SECRET));

    let found = call(&router, request("/custom/base/config/version", Some(&header))).await;
    assert_eq!(found.status, StatusCode::OK);

    let missing = call(&router, request("/api/v1/config/version", Some(&header))).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let health = call(&router, request("/custom/base/healthcheck", None)).await;
    assert_eq!(health.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_empty_base_path_mounts_at_the_root() {
    let router = router_with(secret_verifier(), "/");
    let header = format!("Bearer {}", internal_token(SECRET));
    assert_eq!(
        call(&router, request("/config/version", Some(&header))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&router, request("/healthcheck", None)).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn the_request_id_lakefs_sends_is_echoed_back() {
    let router = router_with(secret_verifier(), BASE);
    let request = Request::builder()
        .method("GET")
        .uri(format!("{BASE}/healthcheck"))
        .header("x-request-id", "lakefs-123")
        .body(Body::empty())
        .expect("build request");
    let response = call(&router, request).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(response.header("x-request-id"), Some("lakefs-123"));
}

/// The route table is what the specification test checks, so every entry must
/// also be served: without a token it is refused, with one it is not a 404 or 405.
#[tokio::test]
async fn every_route_in_the_table_is_served() {
    let server = TestServer::new();
    for (method, pattern) in ROUTE_TABLE {
        let path = pattern
            .replace("{userId}", "someone")
            .replace("{groupId}", "somegroup")
            .replace("{policyId}", "somepolicy")
            .replace("{accessKeyId}", "AKIAJSOMEKEYXXXXXQ");
        let anonymous = Request::builder()
            .method(*method)
            .uri(format!("{BASE}{path}"))
            .body(Body::empty())
            .expect("build request");
        let response = server.send(anonymous).await;
        if path == "/healthcheck" {
            assert_eq!(response.status, StatusCode::NO_CONTENT);
        } else {
            assert_eq!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} without a token"
            );
        }

        let authenticated = Request::builder()
            .method(*method)
            .uri(format!("{BASE}{path}"))
            .header("authorization", format!("Bearer {}", server.token))
            .body(Body::empty())
            .expect("build request");
        let response = server.send(authenticated).await;
        assert!(
            response.status != StatusCode::NOT_FOUND || !response.message().is_empty(),
            "{method} {path} is not routed"
        );
        assert_ne!(
            response.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} is routed under another method"
        );
        // An unrouted path answers 404 with an empty body; a routed one that
        // misses its entity answers 404 with a JSON message.
        if response.status == StatusCode::NOT_FOUND {
            assert!(!response.message().is_empty(), "{method} {path} is not routed");
        }
    }
}

/// CORS is off by default and reachable from the configuration when a browser
/// origin has to call the API.
#[tokio::test]
async fn cors_headers_appear_only_for_configured_origins() {
    let request = || {
        Request::builder()
            .method("GET")
            .uri(format!("{BASE}/healthcheck"))
            .header("origin", "http://lakefs.test")
            .body(Body::empty())
            .expect("build request")
    };

    let plain = TestServer::new();
    let response = plain.send(request()).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(
        response.header("access-control-allow-origin").is_none(),
        "no CORS header without configuration"
    );

    let options = RouterOptions {
        cors_allow_origins: vec!["http://lakefs.test".to_owned()],
        ..RouterOptions::default().with_base_path(BASE)
    };
    let with_cors = TestServer::with_options(options);
    let response = with_cors.send(request()).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some("http://lakefs.test")
    );
}

//! The metrics endpoint of a real server, end to end.
//!
//! The router under test is the one the binary builds, so this proves the
//! middleware is wired and that the labels stay bounded on the real routes.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{BASE, TestServer, call};
use lakefs_auth_core::metrics::{metrics_router, scrape};

/// Scrapes `/metrics` through the router the binary serves on its own listener.
async fn scrape_endpoint() -> (u16, String, String) {
    let request = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .expect("build request");
    let response = call(&metrics_router(), request).await;
    let content_type = response.header("content-type").unwrap_or_default().to_owned();
    let body = String::from_utf8(response.body).expect("utf-8");
    (response.status.as_u16(), content_type, body)
}

#[tokio::test]
async fn the_endpoint_serves_the_prometheus_text_format() {
    let server = TestServer::new();
    server.get("/healthcheck").await;

    let (status, content_type, body) = scrape_endpoint().await;
    assert_eq!(status, 200);
    assert!(
        content_type.starts_with("text/plain"),
        "wrong content type: {content_type}"
    );
    assert!(
        body.contains("# HELP lakefs_auth_http_requests_total"),
        "the exposition format is missing its HELP lines:\n{body}"
    );
}

#[tokio::test]
async fn a_real_request_is_counted_under_its_route_pattern() {
    let server = TestServer::new();
    // The user does not exist, so this answers 404. The route still matches, and
    // the name is exactly the kind of path parameter that must not become a label.
    server.get("/auth/users/metrics-subject").await;

    let rendered = scrape();
    assert!(
        rendered.contains(r#"route="/api/v1/auth/users/{userId}""#),
        "the matched pattern including the base path is missing:\n{rendered}"
    );
    assert!(
        !rendered.contains("metrics-subject"),
        "a user name leaked into a metric label:\n{rendered}"
    );
}

#[tokio::test]
async fn a_failed_request_is_counted_with_its_status() {
    let server = TestServer::new();
    let request = Request::builder()
        .uri(format!("{BASE}/auth/users/definitely-absent"))
        .body(Body::empty())
        .expect("build request");
    // No bearer token, so the middleware rejects it before the handler runs.
    let response = server.send(request).await;
    assert_eq!(response.status.as_u16(), 401);

    let rendered = scrape();
    assert!(
        rendered.contains(r#"status="401""#),
        "the rejected request was not counted:\n{rendered}"
    );
}

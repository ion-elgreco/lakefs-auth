//! End-to-end tests against a wiremock identity provider and a wiremock authorization API.
//!
//! This suite is the only place PKCE, group mapping, and key rotation are exercised,
//! because ferriskey supports none of them.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use axum::http::StatusCode;
use common::app::{TestApp, TestResponse, config, query_pairs, session_username, urlencode};
use common::authz::{MockAuthz, existing_user};
use common::idp::{MockIdp, TokenBehaviour};
use lakefs_authn::lakefs::{FLOW_COOKIE, ID_TOKEN_COOKIE, SESSION_COOKIE};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

const BASE: &str = "/api/v1";

struct Harness {
    idp: MockIdp,
    authz: MockAuthz,
    app: TestApp,
}

impl Harness {
    /// Builds a running server whose discovery already succeeded.
    async fn start(extra: &[&str]) -> Self {
        let idp = MockIdp::start().await;
        let authz = MockAuthz::start().await;
        let app = TestApp::discovered(config(&idp.issuer(), &authz.uri(), extra)).await;
        Self { idp, authz, app }
    }
}

/// The allow list the STS tests register, because an empty list refuses every SDK login.
const STS_ALLOW: &[&str] = &[
    "--sts-allowed-redirect-uris",
    "http://localhost:8000/oidc/callback,http://localhost:8000/cb",
];

/// Whether a response clears the flow cookie (`Max-Age=0`).
fn clears_flow_cookie(response: &TestResponse) -> bool {
    response
        .cookie_header(FLOW_COOKIE)
        .is_some_and(|header| header.contains("Max-Age=0"))
}

/// What `/oidc/login` handed to the browser.
struct Login {
    params: BTreeMap<String, String>,
    cookie: String,
}

impl Login {
    fn state(&self) -> &str {
        &self.params["state"]
    }

    fn nonce(&self) -> &str {
        &self.params["nonce"]
    }
}

async fn start_login(app: &TestApp, uri: &str) -> Login {
    let response = app.get(uri).await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    Login {
        params: query_pairs(&response.location()),
        cookie: response.cookie(FLOW_COOKIE).expect("the flow cookie is set"),
    }
}

async fn callback(app: &TestApp, login: &Login, code: &str) -> TestResponse {
    let uri = format!("/oidc/callback?code={code}&state={}", login.state());
    app.get_with_cookies(&uri, std::slice::from_ref(&login.cookie)).await
}

/// The claims of a token the provider issues for `username` in this login.
fn claims_for(login: &Login, username: &str) -> Value {
    json!({"sub": "s", "nonce": login.nonce(), "preferred_username": username})
}

/// An STS login with a code and a state the mock provider accepts.
async fn sts_login(app: &TestApp, redirect_uri: &str) -> TestResponse {
    app.post_json(
        &format!("{BASE}/sts/login"),
        &json!({"code": "c", "state": "v", "redirect_uri": redirect_uri}),
    )
    .await
}

// ---------------------------------------------------------------- health

#[tokio::test]
async fn health_endpoints_answer_with_the_documented_codes() {
    let harness = Harness::start(&[]).await;
    let live = harness.app.get("/healthz").await;
    assert_eq!(live.status, StatusCode::OK);
    assert_eq!(live.text(), "ok");

    let ready = harness.app.get("/readyz").await;
    assert_eq!(ready.status, StatusCode::OK);

    let check = harness.app.get(&format!("{BASE}/healthcheck")).await;
    assert_eq!(check.status, StatusCode::NO_CONTENT);
    assert!(check.body.is_empty());
}

#[tokio::test]
async fn health_requests_carry_a_request_id() {
    let harness = Harness::start(&[]).await;
    let response = harness.app.get("/healthz").await;
    assert!(response.header("x-request-id").is_some());
}

// ---------------------------------------------------------------- discovery

#[tokio::test]
async fn discovery_retries_until_the_provider_answers() {
    let idp = MockIdp::start().await;
    let authz = MockAuthz::start().await;
    idp.set_discovery_broken(true);

    let app = TestApp::new(config(&idp.issuer(), &authz.uri(), &[])).await;
    app.state.spawn_discovery();
    wait_until(|| idp.discovery_hits() >= 1).await;

    assert_eq!(app.get("/readyz").await.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        app.get("/oidc/login").await.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "logins are refused before discovery succeeds"
    );

    idp.set_discovery_broken(false);
    wait_for_ready(&app).await;
    assert_eq!(app.get("/readyz").await.status, StatusCode::OK);
    assert!(idp.discovery_hits() >= 2, "discovery was retried");
}

#[tokio::test]
async fn discovery_rejects_an_issuer_that_does_not_match() {
    let idp = MockIdp::start().await;
    let authz = MockAuthz::start().await;
    // A different host than the one the document advertises.
    let wrong = idp.issuer().replace("127.0.0.1", "localhost");
    let app = TestApp::new(config(&wrong, &authz.uri(), &[])).await;
    assert!(app.state.oidc.discover().await.is_err());
    assert!(!app.state.oidc.is_ready());
}

/// One discovery round is one metadata fetch and one JWKS fetch, also when
/// the logout endpoint is wanted: the logout data comes from the same document.
#[tokio::test]
async fn discovery_with_logout_metadata_fetches_the_provider_once() {
    let harness = Harness::start(&["--rp-initiated-logout", "true"]).await;
    assert_eq!(harness.idp.discovery_hits(), 1);
    assert_eq!(harness.idp.jwks_hits(), 1);
    let discovered = harness.app.state.oidc.current().expect("discovered");
    assert_eq!(
        discovered.end_session_endpoint.as_ref().map(|url| url.to_string()),
        Some(harness.idp.end_session_endpoint())
    );
}

async fn wait_for_ready(app: &TestApp) {
    wait_until(|| app.state.oidc.is_ready()).await;
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the condition never became true");
}

// ---------------------------------------------------------------- browser login

#[tokio::test]
async fn browser_login_builds_the_authorization_request() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;

    assert_eq!(login.params["response_type"], "code");
    assert_eq!(login.params["client_id"], "lakefs");
    assert_eq!(login.params["redirect_uri"], "http://authn.test/oidc/callback");
    assert_eq!(login.params["code_challenge_method"], "S256");
    assert!(!login.params["code_challenge"].is_empty());
    assert!(!login.state().is_empty());
    assert!(!login.nonce().is_empty());
    let scopes: Vec<&str> = login.params["scope"].split(' ').collect();
    assert!(scopes.contains(&"openid"));
    assert!(scopes.contains(&"profile"));
    assert!(scopes.contains(&"email"));

    let header = harness
        .app
        .get("/oidc/login")
        .await
        .cookie_header(FLOW_COOKIE)
        .expect("flow cookie");
    assert!(header.contains("HttpOnly"), "{header}");
    assert!(header.contains("SameSite=Lax"), "{header}");
    assert!(header.contains("Max-Age=600"), "{header}");
    assert!(header.contains("Path=/"), "{header}");
}

#[tokio::test]
async fn browser_login_creates_the_user_and_sets_the_lakefs_cookie() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login?next=/repositories").await;
    harness.idp.set_claims(json!({
        "sub": "subject-1",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "email": "alice@example.com",
        "name": "Alice Example",
    }));

    let response = callback(&harness.app, &login, "the-code").await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert_eq!(response.location(), "/repositories");

    // The authorization code went out with the PKCE verifier of this flow.
    let token_request = harness.idp.last_token_request();
    assert_eq!(token_request["grant_type"], "authorization_code");
    assert_eq!(token_request["code"], "the-code");
    assert!(token_request.contains_key("code_verifier"));

    // A user exists with the external id and the initial group.
    let user = harness.authz.user("alice").expect("alice was provisioned");
    assert_eq!(user.external_id.as_deref(), Some("subject-1"));
    assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    assert_eq!(user.friendly_name.as_deref(), Some("Alice Example"));
    assert_eq!(user.source.as_deref(), Some("oidc"));
    assert_eq!(harness.authz.memberships(), [("Developers".into(), "alice".into())]);
    // One lookup decides that the identity is new; the create must not repeat it.
    let requests = harness.authz.requests();
    let lookups = requests
        .iter()
        .filter(|(method, path)| method == "GET" && path == "/api/v1/auth/users")
        .count();
    assert_eq!(lookups, 1, "{requests:?}");

    // The session cookie holds a login JWT for that user.
    let cookie = response.raw_cookie_value(SESSION_COOKIE).expect("session cookie");
    assert_eq!(session_username(&cookie), "alice");
    let header = response.cookie_header(SESSION_COOKIE).unwrap();
    assert!(header.contains("HttpOnly"), "{header}");
    assert!(header.contains("Max-Age=604800"), "{header}");
    assert!(!header.contains("Secure"), "an http public URL means no Secure flag");

    // The flow cookie is cleared.
    let flow = response.cookie_header(FLOW_COOKIE).expect("flow cookie cleared");
    assert!(flow.contains("Max-Age=0"), "{flow}");
    // No ID token cookie without RP-initiated logout.
    assert!(response.cookie(ID_TOKEN_COOKIE).is_none());
}

/// lakeFS opens the session cookie with gorilla `securecookie`, whose base64
/// decoder rejects a percent-encoded padding. Whether the value ends in `=`
/// depends on the length of the username, so several lengths are tried, and
/// the raw header value must open without any decoding.
#[tokio::test]
async fn the_session_cookie_goes_out_without_percent_encoding() {
    let harness = Harness::start(&[]).await;
    let mut padded = 0;
    for username in ["a", "ab", "abc", "abcd", "abcde", "abcdef"] {
        let login = start_login(&harness.app, "/oidc/login").await;
        harness.idp.set_claims(json!({
            "sub": username,
            "nonce": login.nonce(),
            "preferred_username": username,
        }));
        let response = callback(&harness.app, &login, "the-code").await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        let raw = response.raw_cookie_value(SESSION_COOKIE).expect("session cookie");
        assert!(!raw.contains('%'), "{username}: {raw}");
        padded += usize::from(raw.ends_with('='));
        assert_eq!(session_username(&raw), username);
    }
    assert!(
        padded > 0,
        "no username produced base64 padding, so the test proves nothing"
    );
}

#[tokio::test]
async fn browser_login_without_next_uses_the_configured_redirect() {
    let harness = Harness::start(&["--post-login-redirect-url", "/repositories/main"]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "bob"));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.location(), "/repositories/main");
}

#[tokio::test]
async fn browser_login_refuses_open_redirects() {
    let harness = Harness::start(&[]).await;
    for next in ["//evil.test/", "https://evil.test/", "/%5Cevil", "/\\evil.test"] {
        let encoded = urlencode(next);
        let response = harness.app.get(&format!("/oidc/login?next={encoded}")).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "next={next}");
    }
    // An allowed host passes.
    let harness = Harness::start(&["--allowed-redirect-hosts", "lakefs.example.com"]).await;
    let response = harness
        .app
        .get(&format!(
            "/oidc/login?next={}",
            urlencode("https://lakefs.example.com/x")
        ))
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
}

#[tokio::test]
async fn browser_callback_needs_the_flow_cookie() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = harness
        .app
        .get(&format!("/oidc/callback?code=c&state={}", login.state()))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.message().contains("login session"), "{}", response.message());
    assert!(harness.idp.token_requests().is_empty(), "no code was exchanged");
}

#[tokio::test]
async fn browser_callback_refuses_a_state_that_does_not_match() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = harness
        .app
        .get_with_cookies(
            "/oidc/callback?code=c&state=not-the-state",
            std::slice::from_ref(&login.cookie),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(harness.idp.token_requests().is_empty(), "no code was exchanged");
    assert!(
        response.cookie_header(FLOW_COOKIE).is_none(),
        "a callback that fails the state check must not clear the flow of the real login"
    );

    // A missing state is refused as well.
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = harness
        .app
        .get_with_cookies("/oidc/callback?code=c", std::slice::from_ref(&login.cookie))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn browser_callback_reports_a_provider_error() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = harness
        .app
        .get_with_cookies(
            &format!(
                "/oidc/callback?error=access_denied&error_description=user%20said%20no&state={}",
                login.state()
            ),
            std::slice::from_ref(&login.cookie),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.message().contains("user said no"), "{}", response.message());
    assert!(
        clears_flow_cookie(&response),
        "the provider ended this flow, so its cookie goes"
    );
}

/// A forced top-level `GET /oidc/callback?error=` from another site carries no
/// valid state, so it must not wipe the victim's login in progress.
#[tokio::test]
async fn a_provider_error_without_the_right_state_does_not_clear_the_flow() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = harness
        .app
        .get_with_cookies(
            "/oidc/callback?error=access_denied&state=forged",
            std::slice::from_ref(&login.cookie),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.cookie_header(FLOW_COOKIE).is_none(), "the flow survives");

    let without_state = harness
        .app
        .get_with_cookies(
            "/oidc/callback?error=access_denied",
            std::slice::from_ref(&login.cookie),
        )
        .await;
    assert_eq!(without_state.status, StatusCode::UNAUTHORIZED);
    assert!(without_state.cookie_header(FLOW_COOKIE).is_none(), "the flow survives");
}

#[tokio::test]
async fn browser_callback_refuses_a_missing_code() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = harness
        .app
        .get_with_cookies(
            &format!("/oidc/callback?state={}", login.state()),
            std::slice::from_ref(&login.cookie),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.message().contains("authorization code"));
    assert!(
        clears_flow_cookie(&response),
        "the state matched, so the flow is consumed"
    );
}

#[tokio::test]
async fn browser_callback_refuses_a_bad_nonce() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "nonce": "a different nonce", "preferred_username": "alice"}));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(harness.authz.users().is_empty(), "nothing was provisioned");
    assert!(clears_flow_cookie(&response), "the nonce and verifier are single use");
}

#[tokio::test]
async fn browser_callback_refuses_a_missing_nonce() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "alice"}));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_callback_refuses_an_unsigned_token() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_unsigned(true);
    harness.idp.set_claims(claims_for(&login, "alice"));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(harness.authz.users().is_empty());
}

#[tokio::test]
async fn browser_callback_refuses_an_expired_token() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    let past = jiff::Timestamp::now().as_second() - 7200;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "iat": past,
        "exp": past + 60,
    }));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_callback_refuses_a_foreign_issuer() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "iss": "https://evil.test",
    }));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_callback_refuses_a_foreign_audience() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "aud": "another-client",
    }));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_callback_refuses_a_failed_token_exchange() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_token_behaviour(TokenBehaviour::Fail(
        400,
        json!({"error": "invalid_grant", "error_description": "code already used"}),
    ));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(harness.authz.users().is_empty());
    assert!(
        clears_flow_cookie(&response),
        "a used code cannot be replayed with the same state"
    );
}

/// A token endpoint that cannot be reached is a provider outage, which the
/// browser and the alerting must see as a 503, not as bad credentials.
#[tokio::test]
async fn browser_callback_reports_an_unreachable_provider_as_unavailable() {
    let harness = Harness::start(&[]).await;
    harness.idp.set_token_endpoint_unreachable();
    harness.app.state.oidc.discover().await.expect("rediscovered");
    let login = start_login(&harness.app, "/oidc/login").await;
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE, "{}", response.text());
    assert!(clears_flow_cookie(&response), "the code was spent on this flow");
}

/// A groups claim in a shape the provisioner does not read must not make the
/// whole token unreadable. Only the configured groups claim is interpreted.
#[tokio::test]
async fn browser_login_tolerates_a_groups_claim_of_another_shape() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "subject-9",
        "nonce": login.nonce(),
        "preferred_username": "carol",
        "groups": [{"id": "7"}, 8],
    }));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert!(harness.authz.user("carol").is_some());
}

/// A cookie above 4096 bytes is dropped by the browser without a word, so a
/// large ID token is not stored at all; the login itself still succeeds.
#[tokio::test]
async fn a_large_id_token_is_not_kept_in_a_cookie() {
    let harness = Harness::start(&["--rp-initiated-logout", "true"]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "groups": vec!["12345678-1234-1234-1234-123456789012"; 80],
    }));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert!(response.cookie(SESSION_COOKIE).is_some());
    assert!(
        response.cookie(ID_TOKEN_COOKIE).is_none(),
        "{:?}",
        response.set_cookie_headers()
    );
}

/// The browser going away, or the request timeout, must not leave a user that
/// was created without its groups: a returning user is never re-synced, so the
/// provisioning has to finish once it started.
#[tokio::test]
async fn provisioning_finishes_after_the_request_timed_out() {
    let harness = Harness::start(&["--request-timeout", "200ms"]).await;
    harness.authz.set_create_delay(Duration::from_millis(600));
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::REQUEST_TIMEOUT, "{}", response.text());
    wait_until(|| harness.authz.memberships() == [("Developers".to_owned(), "alice".to_owned())]).await;
}

#[tokio::test]
async fn browser_callback_refuses_a_response_without_an_id_token() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_token_behaviour(TokenBehaviour::NoIdToken);
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_callback_refreshes_the_keys_once_on_an_unknown_key_id() {
    let harness = Harness::start(&[]).await;
    let before = harness.idp.discovery_hits();
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_key_id("rotated-key");
    harness.idp.set_claims(claims_for(&login, "alice"));

    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness.idp.discovery_hits(),
        before + 1,
        "exactly one extra discovery round"
    );

    // A second attempt stays inside the rate limit window and does not refetch.
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(harness.idp.discovery_hits(), before + 1);
}

#[tokio::test]
async fn browser_callback_recovers_after_a_key_rotation() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    // The provider rotated: both the token header and the JWKS carry the new id.
    harness.idp.set_key_id("rotated-key");
    harness.idp.rotate_jwks_key_id("rotated-key");
    harness.idp.set_claims(claims_for(&login, "alice"));

    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert!(harness.authz.user("alice").is_some());
}

#[tokio::test]
async fn browser_login_reuses_a_returning_user_without_creating_one() {
    let harness = Harness::start(&[]).await;
    harness.authz.add_user(existing_user("existing", "subject-1"));
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "subject-1",
        "nonce": login.nonce(),
        "preferred_username": "someone-else",
        "name": "Existing User",
    }));

    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FOUND);
    let cookie = response.raw_cookie_value(SESSION_COOKIE).unwrap();
    assert_eq!(session_username(&cookie), "existing", "the stored username wins");
    assert!(
        !harness
            .authz
            .requests()
            .iter()
            .any(|(method, path)| method == "POST" && path.ends_with("/auth/users")),
        "no user was created"
    );
    // The friendly name is refreshed on the way through.
    assert_eq!(
        harness.authz.friendly_names(),
        [("existing".to_owned(), "Existing User".to_owned())]
    );
    assert!(harness.authz.memberships().is_empty(), "groups are not re-synced");
}

#[tokio::test]
async fn browser_login_refuses_a_username_collision() {
    let harness = Harness::start(&[]).await;
    // Every create answers 409 while no user carries the external id.
    harness.authz.set_always_conflict(true);
    let login = start_login(&harness.app, "/oidc/login").await;
    harness
        .idp
        .set_claims(json!({"sub": "subject-1", "nonce": login.nonce(), "preferred_username": "alice"}));

    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.cookie(SESSION_COOKIE).is_none(), "no session is handed out");
}

#[tokio::test]
async fn browser_login_refuses_an_unusable_username() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "bad/name"));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn browser_login_reports_an_authorization_api_failure_as_internal() {
    let harness = Harness::start(&[]).await;
    harness.authz.set_broken(true);
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.message(), "internal server error");
}

#[tokio::test]
async fn browser_login_enforces_the_configured_claim_checks() {
    let harness = Harness::start(&["--oidc-validate-claims", "hd=example.com"]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "hd": "other.example",
    }));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(harness.authz.users().is_empty(), "the check runs before provisioning");

    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "hd": "example.com",
    }));
    assert_eq!(callback(&harness.app, &login, "c").await.status, StatusCode::FOUND);
}

#[tokio::test]
async fn browser_login_maps_groups_from_a_claim() {
    let harness = Harness::start(&[
        "--groups-claim",
        "groups",
        "--group-map",
        "idp-admins=Admins,idp-devs=Developers",
    ])
    .await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "s",
        "nonce": login.nonce(),
        "preferred_username": "alice",
        "groups": ["idp-admins", "idp-devs", "idp-unknown"],
    }));

    assert_eq!(callback(&harness.app, &login, "c").await.status, StatusCode::FOUND);
    let mut memberships = harness.authz.memberships();
    memberships.sort();
    assert_eq!(
        memberships,
        [
            ("Admins".to_owned(), "alice".to_owned()),
            ("Developers".to_owned(), "alice".to_owned())
        ],
        "the unmapped group is dropped in strict mode"
    );
}

#[tokio::test]
async fn browser_callback_is_also_mounted_under_the_api_base_path() {
    let harness = Harness::start(&[]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    let uri = format!("{BASE}/oidc/callback?code=c&state={}", login.state());
    let response = harness
        .app
        .get_with_cookies(&uri, std::slice::from_ref(&login.cookie))
        .await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert!(response.cookie(SESSION_COOKIE).is_some());
}

// ---------------------------------------------------------------- STS

#[tokio::test]
async fn sts_login_exchanges_the_code_with_state_as_the_pkce_verifier() {
    let harness = Harness::start(STS_ALLOW).await;
    harness.idp.set_claims(json!({
        "sub": "subject-7",
        "preferred_username": "carol",
        "email": "carol@example.com",
        "email_verified": true,
        "groups": ["a", "b"],
        "exp": jiff::Timestamp::now().as_second() + 600,
    }));

    let response = harness
        .app
        .post_json(
            &format!("{BASE}/sts/login"),
            &json!({
                "code": "the-code",
                "state": "the-pkce-verifier-value-that-is-long-enough",
                "redirect_uri": "http://localhost:8000/oidc/callback",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    let request = harness.idp.last_token_request();
    assert_eq!(request["code"], "the-code");
    assert_eq!(request["code_verifier"], "the-pkce-verifier-value-that-is-long-enough");
    assert_eq!(request["redirect_uri"], "http://localhost:8000/oidc/callback");

    let claims = &response.json()["claims"];
    assert_eq!(claims["sub"], "subject-7");
    assert_eq!(claims["email"], "carol@example.com");
    assert_eq!(claims["email_verified"], "true", "booleans become strings");
    assert_eq!(claims["groups"], "a,b", "string arrays join with commas");
    assert!(claims["exp"].is_string(), "numbers become strings");

    let user = harness.authz.user("carol").expect("carol was provisioned");
    assert_eq!(user.external_id.as_deref(), Some("subject-7"));
}

#[tokio::test]
async fn sts_login_without_pkce_sends_no_verifier() {
    let harness = Harness::start(&[
        "--state-is-pkce-verifier",
        "false",
        "--sts-allowed-redirect-uris",
        "http://localhost:8000/cb",
    ])
    .await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "dave"}));
    let response = harness
        .app
        .post_json(
            &format!("{BASE}/sts/login"),
            &json!({"code": "c", "state": "some-state", "redirect_uri": "http://localhost:8000/cb"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert!(!harness.idp.last_token_request().contains_key("code_verifier"));
}

#[tokio::test]
async fn sts_login_with_an_empty_state_sends_no_verifier() {
    let harness = Harness::start(STS_ALLOW).await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "dave"}));
    let response = harness
        .app
        .post_json(
            &format!("{BASE}/sts/login"),
            &json!({"code": "c", "state": "", "redirect_uri": "http://localhost:8000/cb"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert!(!harness.idp.last_token_request().contains_key("code_verifier"));
}

#[tokio::test]
async fn sts_login_accepts_a_token_without_a_nonce() {
    let harness = Harness::start(STS_ALLOW).await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "erin"}));
    let response = sts_login(&harness.app, "http://localhost:8000/cb").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.json()["claims"]["nonce"].is_null());
}

#[tokio::test]
async fn sts_login_enforces_the_redirect_uri_allow_list() {
    let harness = Harness::start(&["--sts-allowed-redirect-uris", "http://localhost:8000/cb"]).await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "erin"}));

    let refused = sts_login(&harness.app, "http://evil.test/cb").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(harness.idp.token_requests().is_empty());

    let accepted = sts_login(&harness.app, "http://localhost:8000/cb").await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text());
}

#[tokio::test]
async fn sts_login_refuses_a_failed_exchange() {
    let harness = Harness::start(STS_ALLOW).await;
    harness
        .idp
        .set_token_behaviour(TokenBehaviour::Fail(401, json!({"error": "invalid_client"})));
    let response = sts_login(&harness.app, "http://localhost:8000/cb").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(!response.message().is_empty());
    assert!(harness.authz.users().is_empty());
}

#[tokio::test]
async fn sts_login_refuses_a_token_that_fails_the_claim_checks() {
    let harness = Harness::start(&[
        "--oidc-validate-claims",
        "hd=example.com",
        "--sts-allowed-redirect-uris",
        "http://localhost:8000/cb",
    ])
    .await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "erin", "hd": "other.test"}));
    let response = sts_login(&harness.app, "http://localhost:8000/cb").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(harness.authz.users().is_empty());
}

#[tokio::test]
async fn sts_login_refuses_a_bad_body_and_a_bad_redirect_uri() {
    let harness = Harness::start(STS_ALLOW).await;
    let missing = harness.app.post_json(&format!("{BASE}/sts/login"), &json!({})).await;
    assert_eq!(
        missing.status,
        StatusCode::BAD_REQUEST,
        "the contract's error shape, not axum's 422"
    );

    let bad_uri = sts_login(&harness.app, "not a url").await;
    assert_eq!(bad_uri.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sts_login_rejects_an_oversized_body() {
    let harness = Harness::start(STS_ALLOW).await;
    let response = harness
        .app
        .post_json(
            &format!("{BASE}/sts/login"),
            &json!({"code": "x".repeat(70 * 1024), "state": "v", "redirect_uri": "http://localhost:8000/cb"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
}

// ---------------------------------------------------------------- logout

#[tokio::test]
async fn logout_clears_the_session_and_redirects() {
    let harness = Harness::start(&[]).await;
    let response = harness.app.get("/oidc/logout").await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), "/auth/login");
    let header = response.cookie_header(SESSION_COOKIE).expect("clearing cookie");
    assert!(header.contains("Max-Age=0"), "{header}");
    assert!(header.contains("Path=/"), "{header}");
}

#[tokio::test]
async fn logout_honours_the_configured_target() {
    let harness = Harness::start(&["--post-logout-redirect-url", "/goodbye"]).await;
    assert_eq!(harness.app.get("/oidc/logout").await.location(), "/goodbye");
}

#[tokio::test]
async fn logout_uses_rp_initiated_logout_when_enabled() {
    let harness = Harness::start(&["--rp-initiated-logout", "true"]).await;
    // Log in first so that the ID token cookie exists.
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    let logged_in = callback(&harness.app, &login, "c").await;
    let id_token_cookie = logged_in.cookie(ID_TOKEN_COOKIE).expect("the ID token is kept");

    let response = harness.app.get_with_cookies("/oidc/logout", &[id_token_cookie]).await;
    assert_eq!(response.status, StatusCode::FOUND);
    let target = response.location();
    assert!(target.starts_with(&harness.idp.end_session_endpoint()), "{target}");
    let params = query_pairs(&target);
    assert_eq!(params["client_id"], "lakefs");
    assert_eq!(params["post_logout_redirect_uri"], "http://authn.test/auth/login");
    assert!(params.contains_key("id_token_hint"), "the ID token hint is forwarded");

    assert!(
        response
            .cookie_header(SESSION_COOKIE)
            .is_some_and(|header| header.contains("Max-Age=0"))
    );
    assert!(
        response
            .cookie_header(ID_TOKEN_COOKIE)
            .is_some_and(|header| header.contains("Max-Age=0"))
    );
}

#[tokio::test]
async fn logout_without_an_id_token_still_reaches_the_provider() {
    let harness = Harness::start(&["--rp-initiated-logout", "true"]).await;
    let response = harness.app.get("/oidc/logout").await;
    let params = query_pairs(&response.location());
    assert_eq!(params["client_id"], "lakefs");
    assert!(!params.contains_key("id_token_hint"));
}

// ---------------------------------------------------------------- stubs

#[tokio::test]
async fn stubs_answer_with_501() {
    let harness = Harness::start(&[]).await;
    for path in ["/ldap/login", "/auth/external/principal/login"] {
        let response = harness.app.post_empty(&format!("{BASE}{path}")).await;
        assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED, "{path}");
        assert_eq!(response.message(), "not implemented", "{path}");
    }
}

// ---------------------------------------------------------------- request timeout

/// A hung identity provider must not pin a connection forever: the server has
/// its own ceiling and answers 408.
#[tokio::test]
async fn a_slow_dependency_hits_the_request_timeout() {
    let harness = Harness::start(&["--request-timeout", "300ms"]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_token_delay(Duration::from_secs(2));
    harness.idp.set_claims(claims_for(&login, "alice"));
    let started = std::time::Instant::now();
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::REQUEST_TIMEOUT, "{}", response.text());
    assert!(started.elapsed() < Duration::from_secs(2), "the server gave up first");
}

// ---------------------------------------------------------------- STS allow list

/// The one unauthenticated endpoint that redeems authorization codes refuses
/// every `redirect_uri` until the operator lists the allowed ones.
#[tokio::test]
async fn sts_login_is_refused_until_redirect_uris_are_allowed() {
    let harness = Harness::start(&[]).await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "erin"}));
    let response = sts_login(&harness.app, "http://127.0.0.1:41234/callback").await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text());
    assert!(harness.idp.token_requests().is_empty(), "no code was exchanged");
    assert!(harness.authz.users().is_empty());
}

/// A loopback entry without a port matches any port, as RFC 8252 requires for
/// native clients; every other entry matches exactly.
#[tokio::test]
async fn sts_login_matches_loopback_entries_on_any_port_and_others_exactly() {
    let harness = Harness::start(&[
        "--sts-allowed-redirect-uris",
        "http://127.0.0.1/callback,http://localhost/cb,https://app.example.com/cb",
    ])
    .await;
    harness
        .idp
        .set_claims(json!({"sub": "s", "preferred_username": "erin"}));
    for accepted in [
        "http://127.0.0.1:41234/callback",
        "http://127.0.0.1/callback",
        "http://localhost:9999/cb",
        "https://app.example.com/cb",
    ] {
        let response = sts_login(&harness.app, accepted).await;
        assert_eq!(response.status, StatusCode::OK, "{accepted}: {}", response.text());
    }
    for refused in [
        "http://127.0.0.1:41234/other",
        "https://127.0.0.1:41234/callback",
        "http://localhost:9999/callback",
        "https://app.example.com:8443/cb",
        "https://app.example.com/cb/extra",
        "http://app.example.com/cb",
    ] {
        let response = sts_login(&harness.app, refused).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{refused}");
    }
}

// ---------------------------------------------------------------- auto-provisioning

/// With auto-provisioning off, only identities the operator created can sign
/// in, so no identity provider account can claim an unused principal name.
#[tokio::test]
async fn login_refuses_an_unknown_identity_when_auto_provisioning_is_off() {
    let harness = Harness::start(&["--auto-provision", "false"]).await;
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "unknown-sub",
        "nonce": login.nonce(),
        "preferred_username": "data-admin",
    }));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{}", response.text());
    assert!(harness.authz.users().is_empty(), "nothing was created");
    assert!(
        !harness.authz.requests().iter().any(|(method, _)| method == "POST"),
        "no create was even attempted"
    );

    harness.authz.add_user(existing_user("data-admin", "known-sub"));
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(json!({
        "sub": "known-sub",
        "nonce": login.nonce(),
        "preferred_username": "someone-else",
    }));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert_eq!(
        session_username(&response.raw_cookie_value(SESSION_COOKIE).unwrap()),
        "data-admin"
    );
}

// ---------------------------------------------------------------- key refresh

/// A refresh that fails during a provider blip must not lock logins out for
/// the whole rate-limit window: the stamp is only taken on success.
#[tokio::test]
async fn a_failed_key_refresh_does_not_block_logins_for_the_whole_window() {
    let harness = Harness::start(&[
        "--discovery-min-refresh-interval",
        "600s",
        "--discovery-failed-refresh-cooldown",
        "200ms",
    ])
    .await;
    let before = harness.idp.discovery_hits();

    // The provider rotated, and its metadata endpoint is down for a moment.
    harness.idp.set_key_id("rotated-key");
    harness.idp.set_discovery_broken(true);
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(harness.idp.discovery_hits(), before + 1, "one refresh was attempted");

    // Inside the failure cooldown nothing is fetched again.
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    assert_eq!(
        callback(&harness.app, &login, "c").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(harness.idp.discovery_hits(), before + 1);

    // The provider is back with the new key; the next login after the cooldown succeeds.
    tokio::time::sleep(Duration::from_millis(300)).await;
    harness.idp.set_discovery_broken(false);
    harness.idp.rotate_jwks_key_id("rotated-key");
    let login = start_login(&harness.app, "/oidc/login").await;
    harness.idp.set_claims(claims_for(&login, "alice"));
    let response = callback(&harness.app, &login, "c").await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert_eq!(harness.idp.discovery_hits(), before + 2);
}

/// Callbacks that arrive while a refresh runs wait for it and use the new keys,
/// instead of being refused because the window was already stamped.
#[tokio::test]
async fn concurrent_callbacks_share_one_key_refresh() {
    let harness = Harness::start(&[]).await;
    let before = harness.idp.discovery_hits();
    harness.idp.set_key_id("rotated-key");
    harness.idp.rotate_jwks_key_id("rotated-key");
    harness.idp.set_discovery_delay(Duration::from_millis(300));

    let mut logins = Vec::new();
    for _ in 0..5 {
        logins.push(start_login(&harness.app, "/oidc/login").await);
    }
    // Every callback must carry a nonce from its own login; the mock signs one
    // set of claims, so use the same nonce for all five flows.
    let nonce = logins[0].nonce().to_owned();
    harness
        .idp
        .set_claims(json!({"sub": "s", "nonce": nonce, "preferred_username": "alice"}));
    let first = &logins[0];
    let responses = futures::future::join_all((0..5).map(|_| callback(&harness.app, first, "c"))).await;
    for response in &responses {
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    }
    assert_eq!(harness.idp.discovery_hits(), before + 1, "one refresh served all five");
}

// ---------------------------------------------------------------- helpers

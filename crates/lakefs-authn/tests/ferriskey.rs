//! Integration tests against a real ferriskey identity provider in Docker.
//!
//! Run with:
//!
//! ```text
//! cargo test -p lakefs-authn --features docker-tests --test ferriskey -- --test-threads=1
//! ```
//!
//! ferriskey has no PKCE and no groups claim, so those paths live in `oidc_mock.rs`.
#![cfg(feature = "docker-tests")]

mod common;

use axum::http::StatusCode;
use common::app::{TestApp, TestResponse, config, query_pairs, session_username, urlencode};
use common::authz::MockAuthz;
use common::ferriskey::{Ferriskey, TestUser};
use lakefs_authn::lakefs::{FLOW_COOKIE, ID_TOKEN_COOKIE, SESSION_COOKIE};
use pretty_assertions::assert_eq;

const BASE: &str = "/api/v1";
const REALM: &str = "lakefs";
const CLIENT_ID: &str = "lakefs";
/// The public URL of the authentication server, registered with ferriskey.
const AUTHN_PUBLIC_URL: &str = "http://127.0.0.1:8001";
/// Where the lakeFS STS client would receive the code.
const STS_REDIRECT_URI: &str = "http://localhost:8000/oidc/callback";

struct Stack {
    idp: Ferriskey,
    authz: MockAuthz,
    user: TestUser,
}

impl Stack {
    async fn start() -> anyhow::Result<Self> {
        let idp = Ferriskey::start(
            REALM,
            CLIENT_ID,
            &[format!("{AUTHN_PUBLIC_URL}/oidc/callback"), STS_REDIRECT_URI.to_owned()],
        )
        .await?;
        let user = idp
            .create_user("alice", "alice@example.com", "alice-password-1")
            .await?;
        Ok(Self {
            idp,
            authz: MockAuthz::start().await,
            user,
        })
    }

    /// Builds the authentication server against this identity provider.
    async fn app(&self, extra: &[&str]) -> TestApp {
        let issuer = self.idp.issuer();
        let secret = self.idp.client_secret.clone();
        let mut args: Vec<&str> = vec![
            "--public-url",
            AUTHN_PUBLIC_URL,
            "--oidc-client-secret",
            &secret,
            // ferriskey sends given_name and family_name, never a single name claim.
            "--friendly-name-claim",
            "given_name",
        ];
        args.extend_from_slice(extra);
        let mut config = config(&issuer, &self.authz.uri(), &args);
        config.oidc_client_id = CLIENT_ID.to_owned();
        TestApp::discovered(config).await
    }

    /// Walks the whole browser login and returns the callback response.
    async fn browser_login(&self, app: &TestApp, next: &str) -> anyhow::Result<TestResponse> {
        let login = app.get(&format!("/oidc/login?next={next}")).await;
        assert_eq!(login.status, StatusCode::FOUND, "{}", login.text());
        let authorize_url = login.location();
        assert!(authorize_url.starts_with(&self.idp.issuer()), "{authorize_url}");
        let flow_cookie = login.cookie(FLOW_COOKIE).expect("the flow cookie is set");

        let redirected = self.idp.authenticate(&authorize_url, &self.user).await?;
        let returned = query_pairs(&redirected);
        let sent = query_pairs(&authorize_url);
        assert_eq!(returned["state"], sent["state"], "ferriskey returns the state we sent");

        Ok(app
            .get_with_cookies(
                &format!("/oidc/callback?code={}&state={}", returned["code"], returned["state"]),
                &[flow_cookie],
            )
            .await)
    }
}

#[tokio::test]
async fn ferriskey_browser_login_provisions_and_sets_the_lakefs_cookie() -> anyhow::Result<()> {
    let stack = Stack::start().await?;
    let app = stack.app(&[]).await;

    let response = stack.browser_login(&app, "/repositories").await?;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    assert_eq!(response.location(), "/repositories");

    // The user exists in the authorization API, keyed by the ferriskey subject.
    let user = stack.authz.user("alice").expect("alice was provisioned");
    assert_eq!(user.external_id.as_deref(), Some(stack.user.id.as_str()));
    assert_eq!(user.email.as_deref(), Some(stack.user.email.as_str()));
    assert_eq!(user.source.as_deref(), Some("oidc"));
    assert_eq!(user.friendly_name.as_deref(), Some("Test"));
    assert_eq!(stack.authz.memberships(), [("Developers".into(), "alice".into())]);

    // The cookie is a gorilla session holding the lakeFS login JWT.
    let cookie = response.raw_cookie_value(SESSION_COOKIE).expect("the session cookie");
    assert_eq!(session_username(&cookie), "alice");

    // A second login reuses the same user.
    let again = stack.browser_login(&app, "/").await?;
    assert_eq!(again.status, StatusCode::FOUND);
    assert_eq!(stack.authz.users().len(), 1, "no second user was created");
    Ok(())
}

#[tokio::test]
async fn ferriskey_sts_login_matches_the_lakefs_sample_client() -> anyhow::Result<()> {
    let stack = Stack::start().await?;
    let app = stack.app(&["--sts-allowed-redirect-uris", STS_REDIRECT_URI]).await;

    // The lakeFS sample client sends its PKCE verifier as `state`.
    let verifier = "lakefs-sample-client-pkce-verifier-0123456789";
    let authorize_url = format!(
        "{}/protocol/openid-connect/auth?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri={}&scope=openid%20profile%20email&state={verifier}",
        stack.idp.issuer(),
        urlencode(STS_REDIRECT_URI),
    );
    let redirected = stack.idp.authenticate(&authorize_url, &stack.user).await?;
    let returned = query_pairs(&redirected);
    assert_eq!(returned["state"], verifier);

    let response = app
        .post_json(
            &format!("{BASE}/sts/login"),
            &serde_json::json!({
                "code": returned["code"],
                "state": verifier,
                "redirect_uri": STS_REDIRECT_URI,
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    let claims = &response.json()["claims"];
    assert_eq!(claims["sub"], stack.user.id, "lakeFS looks the user up by sub");
    assert_eq!(claims["preferred_username"], "alice");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["email_verified"], "true", "every value is a string");
    assert!(
        claims.as_object().unwrap().values().all(serde_json::Value::is_string),
        "the STS contract allows string values only: {claims}"
    );

    // lakeFS looks the user up by external_id straight after this call.
    let user = stack.authz.user("alice").expect("alice was provisioned");
    assert_eq!(user.external_id.as_deref(), Some(stack.user.id.as_str()));

    // A redirect URI outside the allow list never reaches the provider.
    let refused = app
        .post_json(
            &format!("{BASE}/sts/login"),
            &serde_json::json!({"code": "x", "state": verifier, "redirect_uri": "http://evil.test/cb"}),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    // A code that was already used is refused.
    let replayed = app
        .post_json(
            &format!("{BASE}/sts/login"),
            &serde_json::json!({
                "code": returned["code"],
                "state": verifier,
                "redirect_uri": STS_REDIRECT_URI,
            }),
        )
        .await;
    assert_eq!(replayed.status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn ferriskey_logout_works_with_and_without_rp_initiated_logout() -> anyhow::Result<()> {
    let stack = Stack::start().await?;

    // Without RP-initiated logout the browser stays on the lakeFS side.
    let plain = stack.app(&[]).await;
    let response = plain.get("/oidc/logout").await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), "/auth/login");
    let header = response.cookie_header(SESSION_COOKIE).expect("clearing cookie");
    assert!(header.contains("Max-Age=0"), "{header}");

    // With RP-initiated logout the browser goes to the ferriskey end session endpoint.
    let app = stack.app(&["--rp-initiated-logout", "true"]).await;
    let discovered = app.state.oidc.current().expect("discovery ran");
    assert!(
        discovered.end_session_endpoint.is_some(),
        "ferriskey advertises an end session endpoint"
    );

    let logged_in = stack.browser_login(&app, "/").await?;
    assert_eq!(logged_in.status, StatusCode::FOUND, "{}", logged_in.text());
    let id_token_cookie = logged_in.cookie(ID_TOKEN_COOKIE).expect("the ID token is kept");

    let response = app.get_with_cookies("/oidc/logout", &[id_token_cookie]).await;
    assert_eq!(response.status, StatusCode::FOUND);
    let target = response.location();
    assert!(
        target.starts_with(&stack.idp.end_session_endpoint()),
        "expected the ferriskey logout endpoint, got {target}"
    );
    let params = query_pairs(&target);
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(
        params["post_logout_redirect_uri"],
        format!("{AUTHN_PUBLIC_URL}/auth/login")
    );
    assert!(params.contains_key("id_token_hint"));
    assert!(
        response
            .cookie_header(SESSION_COOKIE)
            .is_some_and(|header| header.contains("Max-Age=0"))
    );
    Ok(())
}

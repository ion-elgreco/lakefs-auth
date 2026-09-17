//! Full stack: lakeFS, lakefs-authz, lakefs-authn, and ferriskey together.
//!
//! PostgreSQL, ferriskey, and `treeverse/lakefs:1.86.0` run in containers. Both
//! Rust servers run in process on the host, and lakeFS reaches them through
//! `host.docker.internal`. The test proves the two hand-offs that no other suite
//! can: lakeFS accepts the browser session cookie this server writes, and the
//! STS login through lakeFS ends in a lakeFS token for the provisioned user.
//!
//! ```text
//! cargo test -p lakefs-authn --features docker-tests --test lakefs_e2e -- --ignored --nocapture
//! ```
#![cfg(feature = "docker-tests")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use common::app::{config, location, query_pairs, set_cookie_pair, urlencode};
use common::ferriskey::{Ferriskey, TestUser};
use lakefs_auth_core::auth::TokenVerifier;
use lakefs_auth_core::crypto::SecretBox;
use lakefs_authn::lakefs::{FLOW_COOKIE, SESSION_COOKIE};
use lakefs_authn::{AppState, build_router};
use lakefs_authz::app::{
    AppState as AuthzState, RouterOptions, build_router as build_authz_router, serve_with_shutdown,
};
use lakefs_authz::store::{PgStore, Store};
use reqwest::header::{COOKIE, SET_COOKIE};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use testcontainers::core::{Host, IntoContainerPort as _};
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};
use testcontainers_modules::postgres::Postgres;

const REALM: &str = "lakefs";
const CLIENT_ID: &str = "lakefs";
/// Where a lakeFS STS client would receive the code. Registered with ferriskey.
const STS_REDIRECT_URI: &str = "http://localhost:8000/oidc/callback";
const LAKEFS_IMAGE: &str = "treeverse/lakefs";
const LAKEFS_TAG: &str = "1.86.0";
const READY_ATTEMPTS: u32 = 120;

/// Shared with lakeFS as `auth.encrypt.secret_key`. Random per run, so nobody
/// who reads this repository can mint a token for a running test.
static SECRET: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| format!("e2e-{}", uuid::Uuid::new_v4()));

/// Where the in-process servers listen: every interface, so the lakeFS
/// container reaches them, unless `LAKEFS_E2E_LISTEN` narrows it to the address
/// of the Docker bridge.
fn listen_address() -> String {
    let host = std::env::var("LAKEFS_E2E_LISTEN").unwrap_or_else(|_| "0.0.0.0".to_owned());
    format!("{host}:0")
}

/// One in-process axum server bound to every interface, stoppable from the test.
struct Served {
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Served {
    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.task.await;
    }
}

async fn serve(listener: tokio::net::TcpListener, router: axum::Router) -> Served {
    let port = listener.local_addr().expect("local address").port();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        serve_with_shutdown(listener, router, async {
            let _ = stopped.await;
        })
        .await
    });
    Served {
        port,
        stop: Some(stop),
        task,
    }
}

struct Http {
    client: reqwest::Client,
}

impl Http {
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .expect("HTTP client"),
        }
    }

    async fn call(
        &self,
        method: Method,
        url: &str,
        cookie: Option<&str>,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, reqwest::header::HeaderMap, Value)> {
        let mut request = self.client.request(method.clone(), url);
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.with_context(|| format!("{method} {url}"))?;
        let status = response.status();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        Ok((status, headers, value))
    }
}

async fn wait_for_lakefs(http: &Http, base: &str) -> anyhow::Result<()> {
    for attempt in 0..READY_ATTEMPTS {
        if let Ok((StatusCode::NO_CONTENT, _, _)) = http
            .call(Method::GET, &format!("{base}/healthcheck"), None, None, None)
            .await
        {
            println!("lakeFS is ready after {attempt} attempts");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("lakeFS did not become ready in {READY_ATTEMPTS} seconds")
}

async fn dump_logs(container: &ContainerAsync<GenericImage>) {
    for (name, bytes) in [
        ("stdout", container.stdout_to_vec().await),
        ("stderr", container.stderr_to_vec().await),
    ] {
        match bytes {
            Ok(bytes) => eprintln!("----- lakeFS {name} -----\n{}", String::from_utf8_lossy(&bytes)),
            Err(error) => eprintln!("could not read lakeFS {name}: {error}"),
        }
    }
}

#[tokio::test]
#[ignore = "needs Docker: postgres, ferriskey, and treeverse/lakefs:1.86.0"]
async fn lakefs_accepts_the_sso_cookie_and_the_sts_login() -> anyhow::Result<()> {
    // 1. The authorization server over PostgreSQL.
    let postgres = Postgres::default().with_tag("17-alpine").start().await?;
    let postgres_port = postgres.get_host_port_ipv4(5432).await?;
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}/postgres");
    let store = PgStore::connect(&database_url, 10).await?;
    store.run_migrations().await?;
    let store: Arc<dyn Store> = Arc::new(store);
    let authz_state = AuthzState::new(
        store,
        SecretBox::derive(SECRET.as_bytes()),
        TokenVerifier::new(Some(SECRET.as_str()), None, false)?,
    );
    let authz_listener = tokio::net::TcpListener::bind(listen_address()).await?;
    let authz = serve(
        authz_listener,
        build_authz_router(authz_state, &RouterOptions::default()),
    )
    .await;
    println!("lakefs-authz listens on port {}", authz.port);

    // 2. The authentication server needs its public URL before ferriskey learns the redirect URI.
    let authn_listener = tokio::net::TcpListener::bind(listen_address()).await?;
    let authn_port = authn_listener.local_addr()?.port();
    let authn_public_url = format!("http://127.0.0.1:{authn_port}");

    // 3. ferriskey with the realm, the confidential client, and the demo user.
    let idp = Ferriskey::start(
        REALM,
        CLIENT_ID,
        &[format!("{authn_public_url}/oidc/callback"), STS_REDIRECT_URI.to_owned()],
    )
    .await?;
    let user: TestUser = idp
        .create_user("alice", "alice@example.com", "alice-password-1")
        .await?;

    let secret = idp.client_secret.clone();
    let mut authn_config = config(
        &idp.issuer(),
        &format!("http://127.0.0.1:{}", authz.port),
        &[
            "--secret-key",
            SECRET.as_str(),
            "--public-url",
            &authn_public_url,
            "--oidc-client-secret",
            &secret,
            "--friendly-name-claim",
            "given_name",
            "--sts-allowed-redirect-uris",
            STS_REDIRECT_URI,
        ],
    );
    authn_config.oidc_client_id = CLIENT_ID.to_owned();
    let authn_state = AppState::from_config(authn_config).await?;
    authn_state.oidc.discover().await?;
    let authn = serve(authn_listener, build_router(authn_state)).await;
    println!("lakefs-authn listens on port {}", authn.port);

    // 4. lakeFS with both endpoints pointing at the host.
    let lakefs = GenericImage::new(LAKEFS_IMAGE, LAKEFS_TAG)
        .with_exposed_port(8000.tcp())
        .with_cmd(["run"])
        .with_host("host.docker.internal", Host::HostGateway)
        .with_env_var("LAKEFS_LISTEN_ADDRESS", "0.0.0.0:8000")
        .with_env_var("LAKEFS_DATABASE_TYPE", "local")
        .with_env_var("LAKEFS_BLOCKSTORE_TYPE", "local")
        .with_env_var("LAKEFS_AUTH_ENCRYPT_SECRET_KEY", SECRET.as_str())
        .with_env_var(
            "LAKEFS_AUTH_API_ENDPOINT",
            format!("http://host.docker.internal:{}/api/v1", authz.port),
        )
        .with_env_var(
            "LAKEFS_AUTH_AUTHENTICATION_API_ENDPOINT",
            format!("http://host.docker.internal:{}/api/v1", authn.port),
        )
        .with_env_var("LAKEFS_AUTH_UI_CONFIG_RBAC", "internal")
        .with_env_var("LAKEFS_AUTH_UI_CONFIG_LOGIN_COOKIE_NAMES", SESSION_COOKIE)
        .with_env_var("LAKEFS_AUTH_CACHE_ENABLED", "false")
        .with_env_var("LAKEFS_STATS_ENABLED", "false")
        .with_env_var("LAKEFS_USAGE_REPORT_ENABLED", "false")
        .with_env_var("LAKEFS_LOGGING_LEVEL", "INFO")
        .start()
        .await?;
    let lakefs_port = lakefs.get_host_port_ipv4(8000).await?;
    println!("lakeFS listens on host port {lakefs_port}");

    let result = run_assertions(&idp, &user, &authn_public_url, lakefs_port).await;
    if let Err(error) = &result {
        dump_logs(&lakefs).await;
        eprintln!("full stack assertions failed: {error:#}");
    }
    authn.shutdown().await;
    authz.shutdown().await;
    result
}

async fn run_assertions(
    idp: &Ferriskey,
    user: &TestUser,
    authn_public_url: &str,
    lakefs_port: u16,
) -> anyhow::Result<()> {
    let http = Http::new();
    let lakefs = format!("http://127.0.0.1:{lakefs_port}/api/v1");
    wait_for_lakefs(&http, &lakefs).await?;

    // lakeFS setup creates the default groups, so Developers exists for provisioning.
    let (status, _, setup) = http
        .call(
            Method::POST,
            &format!("{lakefs}/setup_lakefs"),
            None,
            None,
            Some(json!({ "username": "admin" })),
        )
        .await?;
    ensure!(status == StatusCode::OK, "setup_lakefs returned {status}: {setup}");
    let admin_key = setup["access_key_id"].as_str().context("admin access key")?.to_owned();
    let admin_secret = setup["secret_access_key"]
        .as_str()
        .context("admin secret key")?
        .to_owned();
    let (status, _, login) = http
        .call(
            Method::POST,
            &format!("{lakefs}/auth/login"),
            None,
            None,
            Some(json!({ "access_key_id": admin_key, "secret_access_key": admin_secret })),
        )
        .await?;
    ensure!(status == StatusCode::OK, "admin login returned {status}: {login}");
    let admin_token = login["token"].as_str().context("admin token")?.to_owned();

    // Browser login through lakefs-authn over real HTTP.
    let (status, headers, body) = http
        .call(
            Method::GET,
            &format!("{authn_public_url}/oidc/login?next=/repositories"),
            None,
            None,
            None,
        )
        .await?;
    ensure!(status == StatusCode::FOUND, "/oidc/login returned {status}: {body}");
    let authorize_url = location(&headers).context("no Location header")?;
    let flow_cookie = set_cookie_pair(&headers, FLOW_COOKIE).context("flow cookie")?;

    let callback_url = idp.authenticate(&authorize_url, user).await?;
    ensure!(
        callback_url.starts_with(&format!("{authn_public_url}/oidc/callback")),
        "ferriskey sent the browser to {callback_url}"
    );
    let (status, headers, body) = http
        .call(Method::GET, &callback_url, Some(&flow_cookie), None, None)
        .await?;
    ensure!(status == StatusCode::FOUND, "/oidc/callback returned {status}: {body}");
    ensure!(
        location(&headers).as_deref() == Some("/repositories"),
        "unexpected post-login redirect"
    );
    let session_cookie = set_cookie_pair(&headers, SESSION_COOKIE).context("session cookie")?;
    println!("lakefs-authn set a session cookie of {} bytes", session_cookie.len());

    // lakeFS accepts the cookie: gob + securecookie + login JWT + provisioning all agree.
    let (status, _, me) = http
        .call(
            Method::GET,
            &format!("{lakefs}/user"),
            Some(&session_cookie),
            None,
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "GET /user with the SSO cookie returned {status}: {me}"
    );
    ensure!(me["user"]["id"] == "alice", "lakeFS sees {me}");
    println!("lakeFS accepted the SSO session for {}", me["user"]["id"]);

    // The provisioned user landed in Developers and carries the ferriskey subject.
    let (status, _, groups) = http
        .call(
            Method::GET,
            &format!("{lakefs}/auth/users/alice/groups"),
            None,
            Some(&admin_token),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "listing alice's groups returned {status}: {groups}"
    );
    let group_ids: Vec<&str> = groups["results"]
        .as_array()
        .context("groups results")?
        .iter()
        .filter_map(|group| group["id"].as_str().or_else(|| group["name"].as_str()))
        .collect();
    ensure!(group_ids.contains(&"Developers"), "alice is in {group_ids:?}");

    // STS through lakeFS: the client sends its PKCE verifier as `state`, like the lakeFS sample client.
    let verifier = "lakefs-sample-client-pkce-verifier-0123456789";
    let sts_authorize_url = format!(
        "{}/protocol/openid-connect/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&scope=openid%20profile%20email&state={verifier}",
        idp.issuer(),
        urlencode(STS_REDIRECT_URI),
    );
    let redirected = idp.authenticate(&sts_authorize_url, user).await?;
    let returned = query_pairs(&redirected);
    let (status, _, sts) = http
        .call(
            Method::POST,
            &format!("{lakefs}/sts/login"),
            None,
            None,
            Some(json!({
                "code": returned["code"],
                "state": verifier,
                "redirect_uri": STS_REDIRECT_URI,
                "ttl_seconds": 3600
            })),
        )
        .await?;
    ensure!(status == StatusCode::OK, "lakeFS sts/login returned {status}: {sts}");
    let sts_token = sts["token"].as_str().context("sts token")?;
    let (status, _, me) = http
        .call(Method::GET, &format!("{lakefs}/user"), None, Some(sts_token), None)
        .await?;
    ensure!(
        status == StatusCode::OK,
        "GET /user with the STS token returned {status}: {me}"
    );
    ensure!(me["user"]["id"] == "alice", "lakeFS sees {me} for the STS token");
    println!("lakeFS issued a working STS token for {}", me["user"]["id"]);

    // Logout clears the cookie on the lakeFS host.
    let (status, headers, _) = http
        .call(
            Method::GET,
            &format!("{authn_public_url}/oidc/logout"),
            None,
            None,
            None,
        )
        .await?;
    ensure!(status == StatusCode::FOUND, "/oidc/logout returned {status}");
    let cleared = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&format!("{SESSION_COOKIE}=")) && value.contains("Max-Age=0"));
    ensure!(cleared, "logout did not clear the session cookie");

    println!("all full stack assertions passed");
    Ok(())
}

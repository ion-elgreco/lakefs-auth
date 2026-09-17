//! End to end with a real lakeFS.
//!
//! PostgreSQL and `treeverse/lakefs:1.86.0` run in containers; this server runs
//! in process on the host and lakeFS reaches it through `host.docker.internal`.
//! Behind the `pg-tests` feature and marked `#[ignore]`, because it needs a
//! Docker daemon and pulls two images:
//!
//! ```text
//! cargo test -p lakefs-authz --features pg-tests --test e2e_lakefs -- --ignored --nocapture
//! ```
//!
//! The in-process server must be reachable from the lakeFS container, so it
//! binds every interface for the duration of the run. Set `LAKEFS_E2E_LISTEN`
//! to the address of the Docker bridge to narrow that, for example
//! `172.17.0.1`. The shared secret is random per run, so nobody who reads this
//! repository can mint a bearer token for a running test.
//!
//! Two scenarios: lakeFS in `rbac: internal` mode running its own setup, and
//! lakeFS in `rbac: external` mode where a bootstrap file is the only source of
//! policies, groups, users, and credentials.
#![cfg(feature = "pg-tests")]

use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context as _, bail};
use lakefs_auth_core::auth::TokenVerifier;
use lakefs_auth_core::crypto::SecretBox;
use lakefs_authz::app::{AppState, RouterOptions, build_router, serve_with_shutdown};
use lakefs_authz::bootstrap;
use lakefs_authz::store::{PgStore, Store};
use reqwest::StatusCode;
use serde_json::{Value, json};
use testcontainers::core::{Host, IntoContainerPort as _};
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};
use testcontainers_modules::postgres::Postgres;

/// Shared with lakeFS as `auth.encrypt.secret_key`. Random per run.
static SHARED_SECRET: LazyLock<String> = LazyLock::new(|| format!("e2e-{}", uuid::Uuid::new_v4()));

/// Where the in-process server listens; every interface unless narrowed.
fn listen_address() -> String {
    let host = std::env::var("LAKEFS_E2E_LISTEN").unwrap_or_else(|_| "0.0.0.0".to_owned());
    format!("{host}:0")
}
const LAKEFS_IMAGE: &str = "treeverse/lakefs";
const LAKEFS_TAG: &str = "1.86.0";
const READY_ATTEMPTS: u32 = 120;

/// A minimal client for the lakeFS API.
struct LakeFs {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl LakeFs {
    fn new(base: String) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            http,
            base,
            token: None,
        })
    }

    fn with_token(&self, token: Option<String>) -> Self {
        Self {
            http: self.http.clone(),
            base: self.base.clone(),
            token,
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        let mut request = self.http.request(method.clone(), format!("{}{path}", self.base));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.with_context(|| format!("{method} {path}"))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        Ok((status, value))
    }

    async fn get(&self, path: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.call(reqwest::Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
        self.call(reqwest::Method::POST, path, Some(body)).await
    }

    async fn put(&self, path: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.call(reqwest::Method::PUT, path, None).await
    }

    async fn wait_until_ready(&self) -> anyhow::Result<()> {
        for attempt in 0..READY_ATTEMPTS {
            match self.get("/healthcheck").await {
                Ok((StatusCode::NO_CONTENT, _)) => {
                    println!("lakeFS is ready after {attempt} attempts");
                    return Ok(());
                }
                Ok((status, body)) => {
                    if attempt % 10 == 0 {
                        println!("lakeFS health check: {status} {body}");
                    }
                }
                Err(error) => {
                    if attempt % 10 == 0 {
                        println!("lakeFS is not up yet: {error}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("lakeFS did not become ready in {READY_ATTEMPTS} seconds")
    }

    async fn login(&self, access_key_id: &str, secret_access_key: &str) -> anyhow::Result<String> {
        let (status, body) = self
            .post(
                "/auth/login",
                json!({ "access_key_id": access_key_id, "secret_access_key": secret_access_key }),
            )
            .await?;
        if status != StatusCode::OK {
            bail!("login failed: {status} {body}");
        }
        body["token"]
            .as_str()
            .map(str::to_owned)
            .context("login response has no token")
    }
}

fn expect_status(actual: StatusCode, expected: StatusCode, what: &str, body: &Value) -> anyhow::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        bail!("{what}: expected {expected}, got {actual}, body {body}")
    }
}

/// lakeFS answers an authorization failure with 401 and the message
/// "insufficient permissions"; older releases used 403. Accept both and check
/// the message, because what matters is that the effective policies denied it.
fn expect_denied(actual: StatusCode, what: &str, body: &Value) -> anyhow::Result<()> {
    let denied = actual == StatusCode::UNAUTHORIZED || actual == StatusCode::FORBIDDEN;
    let message = body["message"].as_str().unwrap_or_default();
    if denied && message.contains("insufficient permissions") {
        println!("{what} was denied with {actual}: {message}");
        Ok(())
    } else {
        bail!("{what}: expected a permission denial, got {actual}, body {body}")
    }
}

#[tokio::test]
#[ignore = "needs Docker: pulls postgres:17-alpine and treeverse/lakefs:1.86.0"]
async fn lakefs_runs_its_whole_rbac_setup_against_this_server() {
    let postgres = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres:17-alpine");
    let postgres_port = postgres.get_host_port_ipv4(5432).await.expect("postgres port");
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}/postgres");

    let store = PgStore::connect(&database_url, 10).await.expect("connect");
    store.run_migrations().await.expect("migrate");
    let store: Arc<dyn Store> = Arc::new(store);

    // The authorization server runs in process, bound to every interface so that
    // the lakeFS container can reach it through the host gateway.
    let listener = tokio::net::TcpListener::bind(listen_address()).await.expect("bind");
    let authz_port = listener.local_addr().expect("local address").port();
    let state = AppState::new(
        Arc::clone(&store),
        SecretBox::derive(SHARED_SECRET.as_bytes()),
        TokenVerifier::new(Some(SHARED_SECRET.as_str()), None, false).expect("verifier"),
    );
    let router = build_router(state, &RouterOptions::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve_with_shutdown(listener, router, async {
            let _ = stopped.await;
        })
        .await
    });
    println!("lakefs-authz listens on port {authz_port}");

    let endpoint = format!("http://host.docker.internal:{authz_port}/api/v1");
    let lakefs = GenericImage::new(LAKEFS_IMAGE, LAKEFS_TAG)
        .with_exposed_port(8000.tcp())
        .with_cmd(["run"])
        .with_host("host.docker.internal", Host::HostGateway)
        .with_env_var("LAKEFS_LISTEN_ADDRESS", "0.0.0.0:8000")
        .with_env_var("LAKEFS_DATABASE_TYPE", "local")
        .with_env_var("LAKEFS_BLOCKSTORE_TYPE", "local")
        .with_env_var("LAKEFS_AUTH_ENCRYPT_SECRET_KEY", SHARED_SECRET.as_str())
        .with_env_var("LAKEFS_AUTH_API_ENDPOINT", &endpoint)
        .with_env_var("LAKEFS_AUTH_UI_CONFIG_RBAC", "internal")
        .with_env_var("LAKEFS_AUTH_CACHE_ENABLED", "false")
        .with_env_var("LAKEFS_STATS_ENABLED", "false")
        .with_env_var("LAKEFS_USAGE_REPORT_ENABLED", "false")
        .with_env_var("LAKEFS_LOGGING_LEVEL", "INFO")
        .start()
        .await
        .expect("start lakeFS");
    let lakefs_port = lakefs.get_host_port_ipv4(8000).await.expect("lakeFS port");
    println!("lakeFS listens on host port {lakefs_port}");

    let result = run_assertions(lakefs_port).await;
    if let Err(error) = &result {
        dump_logs(&lakefs).await;
        eprintln!("end to end assertions failed: {error:#}");
    }

    let _ = stop.send(());
    let _ = server.await;
    result.expect("end to end assertions");
}

async fn run_assertions(lakefs_port: u16) -> anyhow::Result<()> {
    let client = LakeFs::new(format!("http://127.0.0.1:{lakefs_port}/api/v1"))?;
    client.wait_until_ready().await?;

    // lakeFS drives the whole RBAC setup sequence against this server.
    let (status, setup) = client.post("/setup_lakefs", json!({ "username": "admin" })).await?;
    expect_status(status, StatusCode::OK, "setup_lakefs", &setup)?;
    let admin_key = setup["access_key_id"].as_str().context("setup access key")?.to_owned();
    let admin_secret = setup["secret_access_key"]
        .as_str()
        .context("setup secret key")?
        .to_owned();
    println!("setup created admin credentials {admin_key}");

    let token = client.login(&admin_key, &admin_secret).await?;
    let admin = client.with_token(Some(token));

    let (status, user) = admin.get("/user").await?;
    expect_status(status, StatusCode::OK, "GET /user", &user)?;
    anyhow::ensure!(user["user"]["id"] == "admin", "unexpected current user: {user}");

    // What lakeFS lists is what this server stored.
    let (status, users) = admin.get("/auth/users").await?;
    expect_status(status, StatusCode::OK, "GET /auth/users", &users)?;
    let usernames: Vec<&str> = users["results"]
        .as_array()
        .context("users results")?
        .iter()
        .filter_map(|user| user["id"].as_str())
        .collect();
    anyhow::ensure!(usernames.contains(&"admin"), "admin is missing from {usernames:?}");

    let (status, groups) = admin.get("/auth/groups").await?;
    expect_status(status, StatusCode::OK, "GET /auth/groups", &groups)?;
    let group_names: Vec<&str> = groups["results"]
        .as_array()
        .context("groups results")?
        .iter()
        .filter_map(|group| group["name"].as_str().or_else(|| group["id"].as_str()))
        .collect();
    for expected in ["Admins", "SuperUsers", "Developers", "Viewers"] {
        anyhow::ensure!(
            group_names.contains(&expected),
            "group {expected} is missing from {group_names:?}"
        );
    }

    let (status, policies) = admin.get("/auth/policies").await?;
    expect_status(status, StatusCode::OK, "GET /auth/policies", &policies)?;
    let policy_names: Vec<&str> = policies["results"]
        .as_array()
        .context("policies results")?
        .iter()
        .filter_map(|policy| policy["id"].as_str().or_else(|| policy["name"].as_str()))
        .collect();
    anyhow::ensure!(
        policy_names.len() >= 10,
        "expected the 10 base policies, got {policy_names:?}"
    );
    for expected in ["FSFullAccess", "AuthFullAccess", "FSReadAll"] {
        anyhow::ensure!(policy_names.contains(&expected), "policy {expected} is missing");
    }

    // A repeated create of a default object succeeds through lakeFS; a changed one conflicts.
    let (status, again) = admin.post("/auth/groups", json!({ "id": "Admins" })).await?;
    expect_status(status, StatusCode::CREATED, "repeated POST /auth/groups Admins", &again)?;
    let (status, changed) = admin
        .post(
            "/auth/policies",
            json!({
                "id": "FSFullAccess",
                "statement": [{ "effect": "deny", "action": ["fs:*"], "resource": "*" }]
            }),
        )
        .await?;
    expect_status(
        status,
        StatusCode::CONFLICT,
        "changed POST /auth/policies FSFullAccess",
        &changed,
    )?;

    // The admin can write.
    let (status, repository) = admin
        .post(
            "/repositories",
            json!({
                "name": "e2e-repo",
                "storage_namespace": "local://e2e-repo",
                "default_branch": "main"
            }),
        )
        .await?;
    expect_status(status, StatusCode::CREATED, "POST /repositories", &repository)?;

    // A Viewers member can read but not write.
    let (status, created) = admin.post("/auth/users", json!({ "id": "viewer" })).await?;
    expect_status(status, StatusCode::CREATED, "POST /auth/users", &created)?;
    let (status, joined) = admin.put("/auth/groups/Viewers/members/viewer").await?;
    expect_status(status, StatusCode::CREATED, "PUT group membership", &joined)?;
    let (status, credentials) = admin.post("/auth/users/viewer/credentials", Value::Null).await?;
    expect_status(status, StatusCode::CREATED, "POST viewer credentials", &credentials)?;
    let viewer_key = credentials["access_key_id"].as_str().context("viewer key")?;
    let viewer_secret = credentials["secret_access_key"].as_str().context("viewer secret")?;

    let viewer_token = client.login(viewer_key, viewer_secret).await?;
    let viewer = client.with_token(Some(viewer_token));

    let (status, whoami) = viewer.get("/user").await?;
    expect_status(status, StatusCode::OK, "viewer GET /user", &whoami)?;
    anyhow::ensure!(whoami["user"]["id"] == "viewer", "unexpected viewer: {whoami}");

    let (status, listed) = viewer.get("/repositories").await?;
    expect_status(status, StatusCode::OK, "viewer lists repositories", &listed)?;

    let (status, denied) = viewer
        .post(
            "/repositories",
            json!({
                "name": "viewer-repo",
                "storage_namespace": "local://viewer-repo",
                "default_branch": "main"
            }),
        )
        .await?;
    expect_denied(status, "viewer creates a repository", &denied)?;

    let (status, denied_branch) = viewer
        .post(
            "/repositories/e2e-repo/branches",
            json!({ "name": "viewer-branch", "source": "main" }),
        )
        .await?;
    expect_denied(status, "viewer creates a branch", &denied_branch)?;

    println!("all end to end assertions passed");
    Ok(())
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

/// Roles that do not overlap with the lakeFS defaults, plus the admin and a
/// read-only user with fixed credentials.
const EXTERNAL_BOOTSTRAP: &str = r#"
version: 1
policies:
  - name: PlatformAdmin
    statement:
      - effect: allow
        action: ["fs:*", "auth:*", "ci:*", "retention:*", "branches:*", "pr:*"]
        resource: "*"
  - name: ReadEverything
    statement:
      - effect: allow
        action: ["fs:List*", "fs:Read*"]
        resource: "*"
groups:
  - id: platform-admins
    description: full control
    policies: [PlatformAdmin]
  - id: readers
    description: read only
    policies: [ReadEverything]
users:
  - username: admin
    source: internal
    groups: [platform-admins]
    credentials:
      - access_key_id: AKIAJEXTERNALADMINQ
        secret_access_key: external-admin-secret-0000000000000000
  - username: reader
    source: internal
    groups: [readers]
    credentials:
      - access_key_id: AKIAJEXTERNALREADRQ
        secret_access_key: external-reader-secret-000000000000000
"#;

#[tokio::test]
#[ignore = "needs Docker: pulls postgres:17-alpine and treeverse/lakefs:1.86.0"]
async fn lakefs_external_rbac_uses_only_the_bootstrapped_roles() {
    let postgres = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres:17-alpine");
    let postgres_port = postgres.get_host_port_ipv4(5432).await.expect("postgres port");
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{postgres_port}/postgres");

    let store = PgStore::connect(&database_url, 10).await.expect("connect");
    store.run_migrations().await.expect("migrate");
    let store: Arc<dyn Store> = Arc::new(store);

    // The bootstrap file seeds everything before the server accepts requests,
    // exactly like `--bootstrap-file` does at startup.
    let secrets = SecretBox::derive(SHARED_SECRET.as_bytes());
    let plan = bootstrap::parse_plan(EXTERNAL_BOOTSTRAP, &secrets).expect("parse bootstrap");
    let report = bootstrap::apply(store.as_ref(), &plan).await.expect("apply bootstrap");
    println!("bootstrap applied: {report}");

    let listener = tokio::net::TcpListener::bind(listen_address()).await.expect("bind");
    let authz_port = listener.local_addr().expect("local address").port();
    let state = AppState::new(
        Arc::clone(&store),
        secrets,
        TokenVerifier::new(Some(SHARED_SECRET.as_str()), None, false).expect("verifier"),
    );
    let router = build_router(state, &RouterOptions::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve_with_shutdown(listener, router, async {
            let _ = stopped.await;
        })
        .await
    });
    println!("lakefs-authz listens on port {authz_port}");

    let endpoint = format!("http://host.docker.internal:{authz_port}/api/v1");
    let lakefs = GenericImage::new(LAKEFS_IMAGE, LAKEFS_TAG)
        .with_exposed_port(8000.tcp())
        .with_cmd(["run"])
        .with_host("host.docker.internal", Host::HostGateway)
        .with_env_var("LAKEFS_LISTEN_ADDRESS", "0.0.0.0:8000")
        .with_env_var("LAKEFS_DATABASE_TYPE", "local")
        .with_env_var("LAKEFS_BLOCKSTORE_TYPE", "local")
        .with_env_var("LAKEFS_AUTH_ENCRYPT_SECRET_KEY", SHARED_SECRET.as_str())
        .with_env_var("LAKEFS_AUTH_API_ENDPOINT", &endpoint)
        .with_env_var("LAKEFS_AUTH_UI_CONFIG_RBAC", "external")
        .with_env_var("LAKEFS_AUTH_CACHE_ENABLED", "false")
        .with_env_var("LAKEFS_STATS_ENABLED", "false")
        .with_env_var("LAKEFS_USAGE_REPORT_ENABLED", "false")
        .with_env_var("LAKEFS_LOGGING_LEVEL", "INFO")
        .start()
        .await
        .expect("start lakeFS");
    let lakefs_port = lakefs.get_host_port_ipv4(8000).await.expect("lakeFS port");
    println!("lakeFS listens on host port {lakefs_port}");

    let result = run_external_assertions(lakefs_port).await;
    if let Err(error) = &result {
        dump_logs(&lakefs).await;
        eprintln!("external mode assertions failed: {error:#}");
    }

    let _ = stop.send(());
    let _ = server.await;
    result.expect("external mode assertions");
}

async fn run_external_assertions(lakefs_port: u16) -> anyhow::Result<()> {
    let client = LakeFs::new(format!("http://127.0.0.1:{lakefs_port}/api/v1"))?;
    client.wait_until_ready().await?;

    // lakeFS reports itself as set up and never runs its own setup.
    let (status, setup_state) = client.get("/setup_lakefs").await?;
    expect_status(status, StatusCode::OK, "GET /setup_lakefs", &setup_state)?;
    anyhow::ensure!(
        setup_state["state"] == "initialized",
        "external mode should report an initialized setup: {setup_state}"
    );

    // The bootstrapped admin credentials work without any lakeFS setup call.
    let token = client
        .login("AKIAJEXTERNALADMINQ", "external-admin-secret-0000000000000000")
        .await?;
    let admin = client.with_token(Some(token));
    let (status, user) = admin.get("/user").await?;
    expect_status(status, StatusCode::OK, "GET /user", &user)?;
    anyhow::ensure!(user["user"]["id"] == "admin", "unexpected current user: {user}");

    // Only the bootstrapped roles exist: none of the lakeFS defaults.
    let (status, groups) = admin.get("/auth/groups").await?;
    expect_status(status, StatusCode::OK, "GET /auth/groups", &groups)?;
    let mut group_names: Vec<&str> = groups["results"]
        .as_array()
        .context("groups results")?
        .iter()
        .filter_map(|group| group["name"].as_str().or_else(|| group["id"].as_str()))
        .collect();
    group_names.sort_unstable();
    anyhow::ensure!(
        group_names == ["platform-admins", "readers"],
        "expected only the bootstrapped groups, got {group_names:?}"
    );
    let (status, policies) = admin.get("/auth/policies").await?;
    expect_status(status, StatusCode::OK, "GET /auth/policies", &policies)?;
    let mut policy_names: Vec<&str> = policies["results"]
        .as_array()
        .context("policies results")?
        .iter()
        .filter_map(|policy| policy["id"].as_str().or_else(|| policy["name"].as_str()))
        .collect();
    policy_names.sort_unstable();
    anyhow::ensure!(
        policy_names == ["PlatformAdmin", "ReadEverything"],
        "expected only the bootstrapped policies, got {policy_names:?}"
    );
    let (status, users) = admin.get("/auth/users").await?;
    expect_status(status, StatusCode::OK, "GET /auth/users", &users)?;
    let mut usernames: Vec<&str> = users["results"]
        .as_array()
        .context("users results")?
        .iter()
        .filter_map(|user| user["id"].as_str())
        .collect();
    usernames.sort_unstable();
    anyhow::ensure!(usernames == ["admin", "reader"], "unexpected users: {usernames:?}");

    // The custom admin role can write.
    let (status, repository) = admin
        .post(
            "/repositories",
            json!({
                "name": "external-repo",
                "storage_namespace": "local://external-repo",
                "default_branch": "main"
            }),
        )
        .await?;
    expect_status(status, StatusCode::CREATED, "POST /repositories", &repository)?;

    // The custom read-only role can list but not write.
    let reader_token = client
        .login("AKIAJEXTERNALREADRQ", "external-reader-secret-000000000000000")
        .await?;
    let reader = client.with_token(Some(reader_token));
    let (status, whoami) = reader.get("/user").await?;
    expect_status(status, StatusCode::OK, "reader GET /user", &whoami)?;
    anyhow::ensure!(whoami["user"]["id"] == "reader", "unexpected reader: {whoami}");
    let (status, listed) = reader.get("/repositories").await?;
    expect_status(status, StatusCode::OK, "reader lists repositories", &listed)?;
    let (status, denied) = reader
        .post(
            "/repositories",
            json!({
                "name": "reader-repo",
                "storage_namespace": "local://reader-repo",
                "default_branch": "main"
            }),
        )
        .await?;
    expect_denied(status, "reader creates a repository", &denied)?;

    println!("all external mode assertions passed");
    Ok(())
}

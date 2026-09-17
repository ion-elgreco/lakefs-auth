//! A ferriskey 0.7.2 identity provider in Docker, driven without a browser.
//!
//! Three containers on one throwaway network: PostgreSQL, a one-shot migration
//! run of the ferriskey image, and the API itself. ferriskey has no
//! `SERVER_PUBLIC_URL`, so it derives the issuer from the `Host` header; every
//! call therefore goes through the same `http://127.0.0.1:<port>` base.

use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::{Value, json};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::postgres;

const FERRISKEY_IMAGE: &str = "ghcr.io/ferriskey/ferriskey-api";
const FERRISKEY_TAG: &str = "0.7.2";
const POSTGRES_TAG: &str = "18.2";
const API_PORT: u16 = 3333;
const DB_USER: &str = "ferriskey";
const DB_PASSWORD: &str = "ferriskey";
const DB_NAME: &str = "ferriskey";
const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "admin";
/// ferriskey seeds this client in the `master` realm for the admin password grant.
const ADMIN_CLIENT: &str = "admin-cli";
const MIGRATIONS: &str = "/usr/local/src/ferriskey/migrations";

pub struct Ferriskey {
    _postgres: ContainerAsync<postgres::Postgres>,
    _api: ContainerAsync<GenericImage>,
    http: reqwest::Client,
    pub base: String,
    pub realm: String,
    pub client_id: String,
    pub client_secret: String,
}

/// A user ferriskey holds, with the password the headless login uses.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub username: String,
    pub password: String,
    pub email: String,
}

impl Ferriskey {
    /// Starts the stack and registers a realm and one confidential client.
    pub async fn start(realm: &str, client_id: &str, redirect_uris: &[String]) -> anyhow::Result<Self> {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let unique = &unique[..8];
        let network = format!("lakefs-authn-{unique}");
        let db_host = format!("lakefs-authn-pg-{unique}");

        let postgres = postgres::Postgres::default()
            .with_user(DB_USER)
            .with_password(DB_PASSWORD)
            .with_db_name(DB_NAME)
            .with_tag(POSTGRES_TAG)
            .with_network(network.clone())
            .with_container_name(db_host.clone())
            .with_startup_timeout(Duration::from_secs(120))
            .start()
            .await
            .context("postgres did not start")?;

        run_migrations(&network, &db_host).await?;

        let api = GenericImage::new(FERRISKEY_IMAGE, FERRISKEY_TAG)
            .with_exposed_port(API_PORT.tcp())
            // No log wait: the readiness poll below is the contract ferriskey documents.
            .with_network(network.clone())
            .with_env_var("DATABASE_HOST", &db_host)
            .with_env_var("DATABASE_PORT", "5432")
            .with_env_var("DATABASE_USER", DB_USER)
            .with_env_var("DATABASE_PASSWORD", DB_PASSWORD)
            .with_env_var("DATABASE_NAME", DB_NAME)
            .with_env_var("ADMIN_USERNAME", ADMIN_USERNAME)
            .with_env_var("ADMIN_PASSWORD", ADMIN_PASSWORD)
            .with_env_var("ADMIN_EMAIL", "admin@local")
            .with_env_var("SERVER_PORT", API_PORT.to_string())
            .with_env_var("ENV", "development")
            .with_env_var("LOG_FILTER", "warn")
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .await
            .context("the ferriskey API did not start")?;

        let port = api.get_host_port_ipv4(API_PORT).await?;
        // One canonical base: ferriskey builds the issuer from the Host header.
        let base = format!("http://127.0.0.1:{port}");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;

        let provider = Self {
            _postgres: postgres,
            _api: api,
            http,
            base,
            realm: realm.to_owned(),
            client_id: client_id.to_owned(),
            client_secret: String::new(),
        };
        provider.wait_until_ready().await?;

        let secret = provider.bootstrap(redirect_uris).await?;
        Ok(Self {
            client_secret: secret,
            ..provider
        })
    }

    pub fn issuer(&self) -> String {
        format!("{}/realms/{}", self.base, self.realm)
    }

    pub fn end_session_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/logout", self.issuer())
    }

    async fn wait_until_ready(&self) -> anyhow::Result<()> {
        let mut last = String::new();
        for _ in 0..120 {
            match self.http.get(format!("{}/health/ready", self.base)).send().await {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => last = format!("status {}", response.status()),
                Err(error) => last = error.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        bail!(
            "ferriskey never became ready at {} (last attempt: {last})\nstdout: {}\nstderr: {}",
            self.base,
            self.api_logs(false).await,
            self.api_logs(true).await
        )
    }

    /// Container output, used when a startup problem needs explaining.
    async fn api_logs(&self, stderr: bool) -> String {
        let bytes = if stderr {
            self._api.stderr_to_vec().await
        } else {
            self._api.stdout_to_vec().await
        };
        String::from_utf8_lossy(&bytes.unwrap_or_default()).into_owned()
    }

    /// Admin access token from the password grant on `admin-cli` in `master`.
    async fn admin_token(&self) -> anyhow::Result<String> {
        let response = self
            .http
            .post(format!("{}/realms/master/protocol/openid-connect/token", self.base))
            .form(&[
                ("grant_type", "password"),
                ("client_id", ADMIN_CLIENT),
                ("username", ADMIN_USERNAME),
                ("password", ADMIN_PASSWORD),
            ])
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await.context("the admin token response is not JSON")?;
        if !status.is_success() {
            bail!("the admin password grant failed with {status}: {body}");
        }
        body["access_token"]
            .as_str()
            .map(str::to_owned)
            .context("the admin token response has no access_token")
    }

    /// Creates the realm, the confidential client, and its redirect URIs.
    async fn bootstrap(&self, redirect_uris: &[String]) -> anyhow::Result<String> {
        let token = self.admin_token().await?;
        self.admin_post(&token, "/realms", &json!({"name": self.realm})).await?;

        let client = self
            .admin_post(
                &token,
                &format!("/realms/{}/clients", self.realm),
                &json!({
                    "client_id": self.client_id,
                    "name": self.client_id,
                    "client_type": "confidential",
                    "enabled": true,
                    "protocol": "openid-connect",
                    "public_client": false,
                    "service_account_enabled": false,
                    "direct_access_grants_enabled": true,
                    "oauth_device_code_grant_enabled": false,
                }),
            )
            .await?;
        let client_uuid = client["id"].as_str().context("the client has no id")?.to_owned();
        let secret = client["secret"]
            .as_str()
            .context("the confidential client has no secret")?
            .to_owned();

        for uri in redirect_uris {
            self.admin_post(
                &token,
                &format!("/realms/{}/clients/{client_uuid}/redirects", self.realm),
                &json!({"value": uri, "enabled": true}),
            )
            .await?;
        }
        Ok(secret)
    }

    /// Creates a user with a verified email and a password that is not temporary.
    pub async fn create_user(&self, username: &str, email: &str, password: &str) -> anyhow::Result<TestUser> {
        let token = self.admin_token().await?;
        let created = self
            .admin_post(
                &token,
                &format!("/realms/{}/users", self.realm),
                &json!({
                    "username": username,
                    "email": email,
                    "email_verified": true,
                    "firstname": "Test",
                    "lastname": "User",
                }),
            )
            .await?;
        let id = created["data"]["id"]
            .as_str()
            .context("the created user has no id")?
            .to_owned();
        let response = self
            .http
            .put(format!("{}/realms/{}/users/{id}/reset-password", self.base, self.realm))
            .bearer_auth(&token)
            .json(&json!({"value": password, "temporary": false, "credential_type": "password"}))
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("setting the password failed: {}", response.text().await?);
        }
        Ok(TestUser {
            id,
            username: username.to_owned(),
            password: password.to_owned(),
            email: email.to_owned(),
        })
    }

    /// Walks the authorization endpoint and the login form without a browser.
    ///
    /// Returns the URL ferriskey would send the browser to, carrying `code` and `state`.
    pub async fn authenticate(&self, authorize_url: &str, user: &TestUser) -> anyhow::Result<String> {
        let response = self.http.get(authorize_url).send().await?;
        if response.status() != reqwest::StatusCode::FOUND {
            bail!(
                "the authorization endpoint answered {} instead of a redirect: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }
        let session = super::app::set_cookie_pair(response.headers(), "FERRISKEY_SESSION")
            .context("the authorization endpoint set no FERRISKEY_SESSION cookie")?;
        let login_page =
            super::app::location(response.headers()).context("the authorization endpoint sent no Location")?;

        // The web app forwards the query of the login page to the authenticate call.
        let query = url::Url::parse(&login_page)
            .context("the login page is not an absolute URL")?
            .query()
            .unwrap_or_default()
            .to_owned();
        let authenticate = format!("{}/realms/{}/login-actions/authenticate?{query}", self.base, self.realm);
        let response = self
            .http
            .post(authenticate)
            .header(reqwest::header::COOKIE, session)
            .json(&json!({"username": user.username, "password": user.password}))
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await.context("the login response is not JSON")?;
        if !status.is_success() || body["status"] != "Success" {
            bail!("the headless login failed with {status}: {body}");
        }
        body["url"]
            .as_str()
            .map(str::to_owned)
            .context("the login response carries no redirect URL")
    }

    async fn admin_post(&self, token: &str, path: &str, body: &Value) -> anyhow::Result<Value> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(token)
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("POST {path} failed with {status}: {text}");
        }
        serde_json::from_str(&text).with_context(|| format!("POST {path} returned {text}"))
    }
}

/// Runs the bundled sqlx migrations once and waits for the container to exit.
///
/// The API refuses to boot against a half migrated database, so this has to block
/// until the one-shot container is really gone, not merely until its output ends.
async fn run_migrations(network: &str, db_host: &str) -> anyhow::Result<()> {
    let url = format!("postgres://{DB_USER}:{DB_PASSWORD}@{db_host}:5432/{DB_NAME}");
    let container = GenericImage::new(FERRISKEY_IMAGE, FERRISKEY_TAG)
        .with_entrypoint("sqlx")
        .with_network(network.to_owned())
        .with_env_var("DATABASE_URL", url)
        .with_cmd(["migrate", "run", "--source", MIGRATIONS])
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await
        .context("the migration container did not start")?;

    // Reading stdout to the end drains the output; the exit code is the real signal.
    let stdout = container.stdout_to_vec().await.unwrap_or_default();
    for _ in 0..480 {
        match container.exit_code().await? {
            Some(0) => return Ok(()),
            Some(code) => {
                let stderr = container.stderr_to_vec().await.unwrap_or_default();
                bail!(
                    "the ferriskey migrations failed with exit code {code}\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
            }
            None => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
    bail!("the ferriskey migrations did not finish in time")
}

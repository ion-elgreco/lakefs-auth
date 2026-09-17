//! Command line and environment configuration.
//!
//! Boolean flags use `ArgAction::Set` with one argument so that
//! `LAKEFS_AUTHZ_RUN_MIGRATIONS=false` works the same as `--run-migrations false`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgAction, Parser};
use http::HeaderValue;
use lakefs_auth_core::auth::TokenVerifier;
use lakefs_auth_core::config::{CommaList, Secret, parse_duration};
use lakefs_auth_core::crypto::SecretBox;
use lakefs_auth_core::telemetry::LogFormat;
use lakefs_auth_core::text::non_blank;

use crate::app::RouterOptions;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configure --secret-key or --encryption-key so that credential secrets can be encrypted")]
    NoEncryptionSecret,
    #[error(transparent)]
    Verifier(#[from] lakefs_auth_core::auth::VerifierConfigError),
}

/// Every secret is a [`Secret`], so the startup log can print the configuration.
#[derive(Debug, Parser)]
#[command(
    name = "lakefs-authz",
    version,
    about = "lakeFS authorization server backed by PostgreSQL"
)]
pub struct Config {
    /// Address to listen on.
    #[arg(long, env = "LAKEFS_AUTHZ_LISTEN", default_value = crate::DEFAULT_LISTEN)]
    pub listen: String,

    /// Path prefix for every route. Must match the suffix of lakeFS `auth.api.endpoint`.
    #[arg(long, env = "LAKEFS_AUTHZ_BASE_PATH", default_value = crate::DEFAULT_BASE_PATH)]
    pub base_path: String,

    /// Shared secret, the same value as lakeFS `auth.encrypt.secret_key`.
    #[arg(long, env = "LAKEFS_AUTHZ_SECRET_KEY")]
    pub secret_key: Option<Secret<String>>,

    /// Static bearer token, the same value as lakeFS `auth.api.token`.
    #[arg(long, env = "LAKEFS_AUTHZ_API_TOKEN")]
    pub api_token: Option<Secret<String>>,

    /// Key for credential encryption. Defaults to the shared secret.
    #[arg(long, env = "LAKEFS_AUTHZ_ENCRYPTION_KEY")]
    pub encryption_key: Option<Secret<String>>,

    /// Accept every request without a bearer token. Development only.
    #[arg(long, env = "LAKEFS_AUTHZ_DISABLE_AUTH", action = ArgAction::Set, num_args = 1, default_value_t = false)]
    pub disable_auth: bool,

    /// PostgreSQL connection string. It carries the database password.
    #[arg(long, env = "LAKEFS_AUTHZ_DATABASE_URL")]
    pub database_url: Secret<String>,

    #[arg(long, env = "LAKEFS_AUTHZ_DATABASE_MAX_CONNECTIONS", default_value_t = 10)]
    pub database_max_connections: u32,

    /// Run the embedded migrations at startup.
    #[arg(long, env = "LAKEFS_AUTHZ_RUN_MIGRATIONS", action = ArgAction::Set, num_args = 1, default_value_t = true)]
    pub run_migrations: bool,

    /// YAML file with policies, groups, and users to create if they are missing.
    #[arg(long, env = "LAKEFS_AUTHZ_BOOTSTRAP_FILE")]
    pub bootstrap_file: Option<PathBuf>,

    /// Server-side request timeout. lakeFS has no client timeout toward this server.
    #[arg(long, env = "LAKEFS_AUTHZ_REQUEST_TIMEOUT", default_value = "30s", value_parser = parse_duration)]
    pub request_timeout: Duration,

    /// Browser origins that may call the API, comma separated, for example
    /// `https://lakefs.example.com`. Empty sends no CORS headers; `*` allows any origin.
    #[arg(
        long,
        env = "LAKEFS_AUTHZ_CORS_ALLOW_ORIGINS",
        default_value = "",
        value_parser = parse_origins
    )]
    pub cors_allow_origins: CommaList,

    /// How often expired claimed token ids are removed.
    #[arg(long, env = "LAKEFS_AUTHZ_TOKEN_CLEANUP_INTERVAL", default_value = "5m", value_parser = parse_duration)]
    pub token_cleanup_interval: Duration,

    /// Address for the Prometheus `/metrics` endpoint, for example `0.0.0.0:9090`.
    /// Unset keeps the endpoint off. Never put it on the API address: metrics
    /// belong on a port that only your monitoring reaches.
    #[arg(long, env = "LAKEFS_AUTHZ_METRICS_LISTEN")]
    pub metrics_listen: Option<String>,

    /// Address for the policy builder page, for example `127.0.0.1:8080`.
    /// Unset keeps it off. The page holds no credential: every call, including
    /// the policy create, forwards the caller's own lakeFS session cookie and
    /// lakeFS applies that person's permissions. Bind it to a private address.
    #[arg(long, env = "LAKEFS_AUTHZ_BUILDER_LISTEN")]
    pub builder_listen: Option<String>,

    /// lakeFS API endpoint including the version prefix, for example
    /// `http://lakefs:8000/api/v1`. The policy builder calls it to offer real
    /// repository, branch, user, group, and policy names. Unset keeps those
    /// fields free text.
    ///
    /// No credential belongs here. The builder forwards the caller's own lakeFS
    /// session cookie, so lakeFS applies that person's policies.
    #[arg(long, env = "LAKEFS_AUTHZ_LAKEFS_ENDPOINT")]
    pub lakefs_endpoint: Option<String>,

    #[arg(long, env = "LAKEFS_AUTHZ_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    #[arg(long, env = "LAKEFS_AUTHZ_LOG_FORMAT", default_value = "text")]
    pub log_format: LogFormat,
}

/// A configured secret, unless it is blank.
fn given(secret: Option<&Secret<String>>) -> Option<&str> {
    secret.and_then(Secret::non_blank)
}

/// Each origin must be usable as a header value, or the CORS layer would drop
/// it in silence and the browser would see no CORS header at all.
fn parse_origins(value: &str) -> Result<CommaList, String> {
    let Ok(list) = value.parse::<CommaList>();
    for origin in list.as_slice() {
        if origin != "*" {
            HeaderValue::from_str(origin)
                .map_err(|error| format!("origin {origin:?} is not a valid header value: {error}"))?;
        }
    }
    Ok(list)
}

impl Config {
    /// The bearer token check, or a verifier that accepts everything when
    /// authentication is switched off.
    pub fn verifier(&self) -> Result<TokenVerifier, ConfigError> {
        Ok(TokenVerifier::new(
            given(self.secret_key.as_ref()),
            given(self.api_token.as_ref()),
            self.disable_auth,
        )?)
    }

    /// The read-only lakeFS client for the policy builder.
    ///
    /// It carries no credential: each call uses the session cookie of whoever
    /// is using the page, so lakeFS decides what they may see.
    pub fn lakefs_client(&self) -> Option<crate::lakefs::LakeFsClient> {
        let endpoint = self.lakefs_endpoint.as_deref().and_then(non_blank)?;
        match crate::lakefs::LakeFsClient::new(endpoint, self.request_timeout) {
            Ok(client) => Some(client),
            Err(error) => {
                tracing::warn!(error = %error, "building the lakeFS client failed; the builder stays free text");
                None
            }
        }
    }

    /// Credential encryption uses `--encryption-key` when set, otherwise the shared secret.
    pub fn secret_box(&self) -> Result<SecretBox, ConfigError> {
        let secret = given(self.encryption_key.as_ref())
            .or(given(self.secret_key.as_ref()))
            .ok_or(ConfigError::NoEncryptionSecret)?;
        Ok(SecretBox::derive(secret.as_bytes()))
    }

    pub fn router_options(&self) -> RouterOptions {
        RouterOptions {
            base_path: self.base_path.clone(),
            request_timeout: self.request_timeout,
            cors_allow_origins: self.cors_allow_origins.as_slice().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    fn parse(args: &[&str]) -> Config {
        Config::try_parse_from(args).expect("parse arguments")
    }

    #[test]
    fn the_command_is_valid() {
        Config::command().debug_assert();
    }

    #[test]
    fn defaults_match_the_design() {
        let config = parse(&["lakefs-authz", "--database-url", "postgres://x"]);
        assert_eq!(config.listen, "0.0.0.0:8002");
        assert_eq!(config.base_path, "/api/v1");
        assert_eq!(config.database_max_connections, 10);
        assert!(config.run_migrations);
        assert!(!config.disable_auth);
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.token_cleanup_interval, Duration::from_secs(300));
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, LogFormat::Text);
    }

    #[test]
    fn cors_origins_reach_the_router_options() {
        let config = parse(&["lakefs-authz", "--database-url", "postgres://x"]);
        assert!(config.router_options().cors_allow_origins.is_empty());
        let config = parse(&[
            "lakefs-authz",
            "--database-url",
            "postgres://x",
            "--cors-allow-origins",
            "http://lakefs.test, https://lakefs.example.com",
        ]);
        assert_eq!(
            config.router_options().cors_allow_origins,
            ["http://lakefs.test", "https://lakefs.example.com"]
        );
    }

    #[test]
    fn an_origin_that_is_not_a_header_value_is_refused() {
        let error = Config::try_parse_from([
            "lakefs-authz",
            "--database-url",
            "postgres://x",
            "--cors-allow-origins",
            "http://ok.test,bad\u{1}origin",
        ])
        .expect_err("a control character cannot be a header value");
        assert!(error.to_string().contains("not a valid header value"), "{error}");
    }

    #[test]
    fn booleans_accept_an_explicit_value() {
        let config = parse(&[
            "lakefs-authz",
            "--database-url",
            "postgres://x",
            "--run-migrations",
            "false",
            "--disable-auth",
            "true",
        ]);
        assert!(!config.run_migrations);
        assert!(config.disable_auth);
    }

    #[test]
    fn the_debug_output_holds_no_secret() {
        let config = parse(&[
            "lakefs-authz",
            "--database-url",
            "postgres://user:hunter2@db/authz",
            "--secret-key",
            "super-secret",
            "--api-token",
            "token-value",
        ]);
        let printed = format!("{config:?}");
        assert!(!printed.contains("super-secret"), "{printed}");
        assert!(!printed.contains("token-value"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    #[test]
    fn encryption_falls_back_to_the_shared_secret() {
        let config = parse(&[
            "lakefs-authz",
            "--database-url",
            "postgres://x",
            "--secret-key",
            "shared",
        ]);
        let blob = config.secret_box().expect("secret box").seal_str("value").unwrap();
        assert_eq!(
            SecretBox::derive(b"shared").open_str(&blob).unwrap(),
            "value",
            "the shared secret must derive the same key"
        );

        let without = parse(&[
            "lakefs-authz",
            "--database-url",
            "postgres://x",
            "--disable-auth",
            "true",
        ]);
        assert!(matches!(without.secret_box(), Err(ConfigError::NoEncryptionSecret)));
    }

    #[test]
    fn a_verifier_needs_a_secret_a_token_or_disabled_auth() {
        let config = parse(&["lakefs-authz", "--database-url", "postgres://x"]);
        assert!(config.verifier().is_err());
        let disabled = parse(&[
            "lakefs-authz",
            "--database-url",
            "postgres://x",
            "--disable-auth",
            "true",
        ]);
        assert!(disabled.verifier().expect("disabled verifier").is_disabled());
    }
}

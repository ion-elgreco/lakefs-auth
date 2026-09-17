//! Command line and environment configuration.
//!
//! Every flag has an `LAKEFS_AUTHN_*` environment variable. Boolean flags take an
//! explicit value (`--flag false`, `VAR=false`) so that turning a default on flag
//! off through the environment works.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use clap::builder::BoolishValueParser;
use clap::{ArgAction, Parser};
use lakefs_auth_core::config::{CommaList, Secret, parse_duration};
use lakefs_auth_core::telemetry::LogFormat;
use lakefs_auth_core::text::non_blank;
use url::Url;

/// The cookie format carries a timestamp that gorilla rejects after 30 days.
pub const MAX_SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// Path of the browser callback, relative to `--public-url`.
pub const CALLBACK_PATH: &str = "/oidc/callback";

/// A comma separated `key=value` list, for example `--group-map "idp-admins=Admins,idp-devs=Developers"`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyValues(pub BTreeMap<String, String>);

impl KeyValues {
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for KeyValues {
    type Err = String;

    /// `key=value,key=value`. An item without `=` continues the value before
    /// it, so `aud=lakefs,other` is one pair whose value is `lakefs,other`:
    /// that is how an array claim is matched, by its flattened `a,b` form.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut map = BTreeMap::new();
        let mut current: Option<(String, String)> = None;
        let Ok(CommaList(items)) = value.parse();
        for item in &items {
            match item.split_once('=') {
                Some((key, val)) => {
                    if let Some((key, val)) = current.take() {
                        insert_once(&mut map, key, val)?;
                    }
                    let key = key.trim();
                    let val = val.trim();
                    if key.is_empty() {
                        return Err(format!("empty key in {item:?}"));
                    }
                    if val.is_empty() {
                        return Err(format!("empty value in {item:?}"));
                    }
                    current = Some((key.to_owned(), val.to_owned()));
                }
                None => match &mut current {
                    Some((_, val)) => {
                        val.push(',');
                        val.push_str(item);
                    }
                    None => return Err(format!("expected key=value, got {item:?}")),
                },
            }
        }
        if let Some((key, val)) = current {
            insert_once(&mut map, key, val)?;
        }
        Ok(Self(map))
    }
}

fn insert_once(map: &mut BTreeMap<String, String>, key: String, value: String) -> Result<(), String> {
    if map.contains_key(&key) {
        return Err(format!("key {key:?} is given more than once"));
    }
    map.insert(key, value);
    Ok(())
}

/// The shared secret has no empty form: every cookie and token is signed with it.
fn parse_required_secret(value: &str) -> Result<Secret<String>, String> {
    non_blank(value)
        .map(|value| Secret::new(value.to_owned()))
        .ok_or_else(|| "the secret key must not be empty".to_owned())
}

/// For intervals and timeouts where zero has no meaning: a zero refresh
/// interval would run discovery back to back, a zero timeout fails every request.
fn parse_positive_duration(value: &str) -> Result<Duration, String> {
    let duration = parse_duration(value)?;
    if duration.is_zero() {
        return Err(format!("{value:?} must be greater than zero"));
    }
    Ok(duration)
}

/// Keeps the issuer exactly as the operator wrote it.
///
/// OpenID Connect discovery compares the issuer byte for byte, and `Url` would add
/// a trailing slash to an authority-only issuer, which no provider advertises.
fn parse_issuer(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    Url::parse(trimmed).map_err(|err| format!("invalid issuer URL {value:?}: {err}"))?;
    Ok(trimmed.to_owned())
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "lakefs-authn",
    version,
    about = "lakeFS authentication server: OIDC browser login and STS code exchange"
)]
pub struct Config {
    /// Address the HTTP server binds to.
    #[arg(long, env = "LAKEFS_AUTHN_LISTEN", default_value = "0.0.0.0:8001")]
    pub listen: String,

    /// Same value as the lakeFS `auth.encrypt.secret_key`.
    #[arg(long, env = "LAKEFS_AUTHN_SECRET_KEY", value_parser = parse_required_secret)]
    pub secret_key: Secret<String>,

    /// External base URL of this server; the OIDC redirect URI derives from it.
    #[arg(long, env = "LAKEFS_AUTHN_PUBLIC_URL")]
    pub public_url: Url,

    /// Base path of the lakeFS authentication API.
    #[arg(long, env = "LAKEFS_AUTHN_API_BASE_PATH", default_value = "/api/v1")]
    pub api_base_path: String,

    /// Server-side ceiling per request. A hung identity provider or
    /// authorization server must not pin a connection forever.
    #[arg(long, env = "LAKEFS_AUTHN_REQUEST_TIMEOUT", default_value = "30s", value_parser = parse_positive_duration)]
    pub request_timeout: Duration,

    /// OIDC issuer URL; discovery appends `/.well-known/openid-configuration`.
    ///
    /// Stored verbatim because the provider must advertise the very same string.
    #[arg(long, env = "LAKEFS_AUTHN_OIDC_ISSUER", value_parser = parse_issuer)]
    pub oidc_issuer: String,

    #[arg(long, env = "LAKEFS_AUTHN_OIDC_CLIENT_ID")]
    pub oidc_client_id: String,

    #[arg(long, env = "LAKEFS_AUTHN_OIDC_CLIENT_SECRET")]
    pub oidc_client_secret: Option<Secret<String>>,

    /// File holding the client secret, read at startup when `--oidc-client-secret` is unset.
    /// Lets a bootstrap job or a secret manager hand the value over through a mounted file.
    #[arg(long, env = "LAKEFS_AUTHN_OIDC_CLIENT_SECRET_FILE")]
    pub oidc_client_secret_file: Option<std::path::PathBuf>,

    #[arg(long, env = "LAKEFS_AUTHN_OIDC_SCOPES", default_value = "openid,profile,email")]
    pub oidc_scopes: CommaList,

    /// Claims that must match before a login is accepted, for example
    /// `hd=example.com`. An array claim matches its flattened form, and an
    /// item without `=` continues the value before it: `aud=lakefs,other`
    /// expects the array `["lakefs", "other"]`.
    #[arg(long, env = "LAKEFS_AUTHN_OIDC_VALIDATE_CLAIMS", default_value = "")]
    pub oidc_validate_claims: KeyValues,

    /// Claims tried in order when deriving the lakeFS username.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_USERNAME_CLAIM",
        default_value = "preferred_username,email,sub"
    )]
    pub username_claim: CommaList,

    #[arg(long, env = "LAKEFS_AUTHN_FRIENDLY_NAME_CLAIM", default_value = "name")]
    pub friendly_name_claim: String,

    #[arg(
        long,
        env = "LAKEFS_AUTHN_PERSIST_FRIENDLY_NAME",
        action = ArgAction::Set,
        num_args = 1,
        value_parser = BoolishValueParser::new(),
        default_value = "true"
    )]
    pub persist_friendly_name: bool,

    /// Create a lakeFS user at the first login of an unknown identity. With
    /// `false` only users that already exist can sign in, for example the ones a
    /// lakefs-authz bootstrap file creates with their `external_id`, so no
    /// identity provider account can claim an unused principal name.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_AUTO_PROVISION",
        action = ArgAction::Set,
        num_args = 1,
        value_parser = BoolishValueParser::new(),
        default_value = "true"
    )]
    pub auto_provision: bool,

    /// Groups a newly provisioned user joins when no groups claim resolves.
    #[arg(long, env = "LAKEFS_AUTHN_INITIAL_GROUPS", default_value = "Developers")]
    pub initial_groups: CommaList,

    #[arg(long, env = "LAKEFS_AUTHN_GROUPS_CLAIM")]
    pub groups_claim: Option<String>,

    /// Maps identity provider group names onto lakeFS group names.
    #[arg(long, env = "LAKEFS_AUTHN_GROUP_MAP", default_value = "")]
    pub group_map: KeyValues,

    /// Drop groups that the group map does not mention.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_GROUP_MAP_STRICT",
        action = ArgAction::Set,
        num_args = 1,
        value_parser = BoolishValueParser::new(),
        default_value = "true"
    )]
    pub group_map_strict: bool,

    /// Authorization API base URL, including `/api/v1`.
    #[arg(long, env = "LAKEFS_AUTHN_AUTHZ_URL")]
    pub authz_url: Url,

    /// Static bearer token. Without it the server mints the lakeFS internal JWT.
    #[arg(long, env = "LAKEFS_AUTHN_AUTHZ_TOKEN")]
    pub authz_token: Option<Secret<String>>,

    /// Value stored in `User.source`.
    #[arg(long, env = "LAKEFS_AUTHN_AUTH_SOURCE", default_value = "oidc")]
    pub auth_source: String,

    #[arg(long, env = "LAKEFS_AUTHN_POST_LOGIN_REDIRECT_URL", default_value = "/")]
    pub post_login_redirect_url: String,

    #[arg(long, env = "LAKEFS_AUTHN_POST_LOGOUT_REDIRECT_URL", default_value = "/auth/login")]
    pub post_logout_redirect_url: String,

    /// Lifetime of the lakeFS session cookie, capped at 30 days by the cookie format.
    #[arg(long, env = "LAKEFS_AUTHN_SESSION_TTL", default_value = "168h", value_parser = parse_duration)]
    pub session_ttl: Duration,

    /// Defaults to true when `--public-url` uses https.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_COOKIE_SECURE",
        action = ArgAction::Set,
        num_args = 1,
        value_parser = BoolishValueParser::new()
    )]
    pub cookie_secure: Option<bool>,

    #[arg(long, env = "LAKEFS_AUTHN_COOKIE_DOMAIN")]
    pub cookie_domain: Option<String>,

    /// The lakeFS STS client sends the PKCE verifier in `state`.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_STATE_IS_PKCE_VERIFIER",
        action = ArgAction::Set,
        num_args = 1,
        value_parser = BoolishValueParser::new(),
        default_value = "true"
    )]
    pub state_is_pkce_verifier: bool,

    /// Allow list for the `redirect_uri` of `POST {base}/sts/login`. Empty
    /// refuses every SDK login. A loopback entry without a port, such as
    /// `http://127.0.0.1/callback`, matches any port; other entries match exactly.
    #[arg(long, env = "LAKEFS_AUTHN_STS_ALLOWED_REDIRECT_URIS", default_value = "")]
    pub sts_allowed_redirect_uris: CommaList,

    /// Origins that `?next=` may point at with an absolute URL, as `host`,
    /// `host:port`, or `scheme://host[:port]`. A bare host matches only the
    /// default port of either scheme.
    #[arg(long, env = "LAKEFS_AUTHN_ALLOWED_REDIRECT_HOSTS", default_value = "")]
    pub allowed_redirect_hosts: CommaList,

    /// Send the browser to the identity provider `end_session_endpoint` on logout.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_RP_INITIATED_LOGOUT",
        action = ArgAction::Set,
        num_args = 1,
        value_parser = BoolishValueParser::new(),
        default_value = "false"
    )]
    pub rp_initiated_logout: bool,

    /// How often the provider metadata and signing keys are refreshed.
    #[arg(long, env = "LAKEFS_AUTHN_DISCOVERY_REFRESH_INTERVAL", default_value = "1h", value_parser = parse_positive_duration)]
    pub discovery_refresh_interval: Duration,

    /// Shortest gap between two refreshes triggered by an unknown signing key.
    #[arg(long, env = "LAKEFS_AUTHN_DISCOVERY_MIN_REFRESH_INTERVAL", default_value = "60s", value_parser = parse_duration)]
    pub discovery_min_refresh_interval: Duration,

    /// Timeout of one request to the identity provider: discovery, the JWKS,
    /// and the authorization code exchange all use it.
    #[arg(long, env = "LAKEFS_AUTHN_DISCOVERY_TIMEOUT", default_value = "10s", value_parser = parse_positive_duration)]
    pub discovery_timeout: Duration,

    /// Gap after a refresh for an unknown signing key that failed, before the
    /// next login may try again. Shorter than the regular interval, so a blip
    /// at the provider does not lock logins out for the whole window.
    #[arg(
        long,
        env = "LAKEFS_AUTHN_DISCOVERY_FAILED_REFRESH_COOLDOWN",
        default_value = "5s",
        value_parser = parse_duration,
        hide = true
    )]
    pub discovery_failed_refresh_cooldown: Duration,

    /// Address for the Prometheus `/metrics` endpoint, for example `0.0.0.0:9090`.
    /// Unset keeps the endpoint off. Never put it on the API address: metrics
    /// belong on a port that only your monitoring reaches.
    #[arg(long, env = "LAKEFS_AUTHN_METRICS_LISTEN")]
    pub metrics_listen: Option<String>,

    #[arg(long, env = "LAKEFS_AUTHN_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    #[arg(long, env = "LAKEFS_AUTHN_LOG_FORMAT", default_value = "text")]
    pub log_format: LogFormat,
}

impl Config {
    /// Parses an argument vector. Lets integration tests build a config without depending on clap.
    pub fn try_from_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(args)
    }

    /// `--api-base-path` with a leading slash and without a trailing one. The root path is `""`.
    pub fn base_path(&self) -> String {
        lakefs_auth_core::text::normalize_base_path(&self.api_base_path)
    }

    /// Absolute redirect URI registered with the identity provider.
    pub fn redirect_uri(&self) -> Result<Url, url::ParseError> {
        let mut base = self.public_url.clone();
        let path = base.path().trim_end_matches('/').to_owned();
        base.set_path(&format!("{path}{CALLBACK_PATH}"));
        base.set_query(None);
        base.set_fragment(None);
        Ok(base)
    }

    /// The client secret from `--oidc-client-secret`, else from `--oidc-client-secret-file`.
    ///
    /// The file is read once, trimmed, and must not be empty. `None` means a public client.
    pub fn oidc_client_secret(&self) -> anyhow::Result<Option<Secret<String>>> {
        if let Some(secret) = self.oidc_client_secret.as_ref().and_then(Secret::non_blank) {
            return Ok(Some(Secret::new(secret.to_owned())));
        }
        let Some(path) = &self.oidc_client_secret_file else {
            return Ok(None);
        };
        let value = std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("cannot read --oidc-client-secret-file {}: {error}", path.display()))?;
        let value = value.trim();
        anyhow::ensure!(
            !value.is_empty(),
            "--oidc-client-secret-file {} is empty",
            path.display()
        );
        Ok(Some(Secret::new(value.to_owned())))
    }

    /// `--cookie-secure` when set, otherwise derived from the public URL scheme.
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure.unwrap_or(self.public_url.scheme() == "https")
    }

    /// Session lifetime, never above the 30 days the cookie format allows.
    pub fn effective_session_ttl(&self) -> Duration {
        self.session_ttl.min(MAX_SESSION_TTL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// The mandatory flags plus `extra`. A flag that `extra` carries replaces
    /// the default, because clap refuses a flag given twice.
    fn minimal_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        let defaults = [
            ("--secret-key", "shhh"),
            ("--public-url", "http://localhost:8001"),
            ("--oidc-issuer", "http://idp.test/realms/x"),
            ("--oidc-client-id", "lakefs"),
            ("--authz-url", "http://localhost:8002/api/v1"),
        ];
        let mut args = vec!["lakefs-authn"];
        for (flag, value) in defaults {
            if !extra.contains(&flag) {
                args.extend([flag, value]);
            }
        }
        args.extend_from_slice(extra);
        args
    }

    fn minimal(extra: &[&str]) -> Config {
        Config::try_from_args(minimal_args(extra)).expect("config parses")
    }

    /// A refresh interval of zero would run discovery back to back against the
    /// provider, and a zero timeout would fail every request; both are refused
    /// at startup with a message that names the flag.
    #[test]
    fn zero_intervals_and_timeouts_are_refused() {
        for flag in [
            "--discovery-refresh-interval",
            "--discovery-timeout",
            "--request-timeout",
        ] {
            let error = Config::try_from_args(minimal_args(&[flag, "0s"])).expect_err(flag);
            let text = error.to_string();
            assert!(
                text.contains(flag) && text.contains("greater than zero"),
                "{flag}: {text}"
            );
        }
        assert_eq!(
            minimal(&["--discovery-refresh-interval", "30m"]).discovery_refresh_interval,
            Duration::from_secs(1800)
        );
    }

    #[test]
    fn an_empty_secret_key_is_refused_at_parse_time() {
        let mut args = minimal_args(&[]);
        args[2] = "  ";
        let error = Config::try_from_args(args).expect_err("blank secret");
        assert!(error.to_string().contains("must not be empty"), "{error}");
    }

    #[test]
    fn defaults_match_the_documented_table() {
        let config = minimal(&[]);
        assert_eq!(config.listen, "0.0.0.0:8001");
        assert_eq!(config.api_base_path, "/api/v1");
        assert_eq!(config.oidc_scopes.as_slice(), ["openid", "profile", "email"]);
        assert!(config.oidc_validate_claims.is_empty());
        assert_eq!(config.username_claim.as_slice(), ["preferred_username", "email", "sub"]);
        assert_eq!(config.friendly_name_claim, "name");
        assert!(config.persist_friendly_name);
        assert_eq!(config.initial_groups.as_slice(), ["Developers"]);
        assert_eq!(config.groups_claim, None);
        assert!(config.group_map.is_empty());
        assert!(config.group_map_strict);
        assert_eq!(config.auth_source, "oidc");
        assert_eq!(config.post_login_redirect_url, "/");
        assert_eq!(config.post_logout_redirect_url, "/auth/login");
        assert_eq!(config.session_ttl, Duration::from_secs(168 * 3600));
        assert_eq!(config.cookie_secure, None);
        assert!(config.state_is_pkce_verifier);
        assert!(config.sts_allowed_redirect_uris.is_empty());
        assert!(config.allowed_redirect_hosts.is_empty());
        assert!(!config.rp_initiated_logout);
        assert_eq!(config.discovery_refresh_interval, Duration::from_secs(3600));
        assert_eq!(config.discovery_min_refresh_interval, Duration::from_secs(60));
        assert_eq!(config.discovery_timeout, Duration::from_secs(10));
        assert_eq!(config.discovery_failed_refresh_cooldown, Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert!(config.auto_provision);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, LogFormat::Text);
        assert_eq!(config.oidc_issuer, "http://idp.test/realms/x");
    }

    #[test]
    fn the_request_timeout_and_auto_provisioning_are_configurable() {
        let config = minimal(&["--request-timeout", "5s", "--auto-provision", "false"]);
        assert_eq!(config.request_timeout, Duration::from_secs(5));
        assert!(!config.auto_provision);
    }

    #[test]
    fn boolean_flags_accept_an_explicit_false() {
        let config = minimal(&[
            "--persist-friendly-name",
            "false",
            "--group-map-strict",
            "false",
            "--state-is-pkce-verifier",
            "false",
            "--rp-initiated-logout",
            "true",
            "--cookie-secure",
            "false",
        ]);
        assert!(!config.persist_friendly_name);
        assert!(!config.group_map_strict);
        assert!(!config.state_is_pkce_verifier);
        assert!(config.rp_initiated_logout);
        assert_eq!(config.cookie_secure, Some(false));
        assert!(!config.cookie_secure());
    }

    #[test]
    fn key_value_lists_parse_and_reject_garbage() {
        let config = minimal(&["--group-map", "idp-admins=Admins, idp-devs = Developers"]);
        assert_eq!(config.group_map.as_map()["idp-admins"], "Admins");
        assert_eq!(config.group_map.as_map()["idp-devs"], "Developers");
        assert!("no-equals-sign".parse::<KeyValues>().is_err());
        assert!("=value".parse::<KeyValues>().is_err());
        // A trailing-equals typo would map a group onto the empty name.
        assert!("idp-admins=Admins,idp-devs=".parse::<KeyValues>().is_err());
        assert!("key= ".parse::<KeyValues>().is_err());
        // A repeated key would silently drop a configured check.
        assert!("hd=a,hd=b".parse::<KeyValues>().is_err());
        assert!("hd=a,hd=a".parse::<KeyValues>().is_err());
    }

    /// A value may hold commas: an array claim matches its flattened `a,b`
    /// form, so `aud=lakefs,other` must be one pair. An item without `=`
    /// continues the value before it; only the first item needs a key.
    #[test]
    fn key_value_lists_keep_commas_inside_a_value() {
        let parsed: KeyValues = "aud=lakefs,other,hd=example.com".parse().unwrap();
        assert_eq!(parsed.as_map()["aud"], "lakefs,other");
        assert_eq!(parsed.as_map()["hd"], "example.com");
        let config = minimal(&["--oidc-validate-claims", "groups=a, b ,c"]);
        assert_eq!(config.oidc_validate_claims.as_map()["groups"], "a,b,c");
        assert!(
            "other,aud=x".parse::<KeyValues>().is_err(),
            "the first item needs a key"
        );
        assert!("aud=x,,hd=y".parse::<KeyValues>().is_ok(), "an empty item is skipped");
    }

    #[test]
    fn redirect_uri_follows_the_public_url() {
        assert_eq!(
            minimal(&[]).redirect_uri().unwrap().as_str(),
            "http://localhost:8001/oidc/callback"
        );
        let mut nested = minimal(&[]);
        nested.public_url = Url::parse("https://lakefs.example.com/authn/").unwrap();
        assert_eq!(
            nested.redirect_uri().unwrap().as_str(),
            "https://lakefs.example.com/authn/oidc/callback"
        );
        assert!(nested.cookie_secure());
    }

    /// An authority-only issuer must not gain a trailing slash.
    #[test]
    fn the_issuer_keeps_the_exact_spelling() {
        let bare = minimal(&["--oidc-issuer", "https://idp.example.com"]);
        assert_eq!(bare.oidc_issuer, "https://idp.example.com");
    }

    #[test]
    fn base_path_is_normalized() {
        assert_eq!(minimal(&[]).base_path(), "/api/v1");
        assert_eq!(minimal(&["--api-base-path", "api/v1/"]).base_path(), "/api/v1");
        assert_eq!(minimal(&["--api-base-path", "/"]).base_path(), "");
    }

    #[test]
    fn session_ttl_is_capped_at_thirty_days() {
        let config = minimal(&["--session-ttl", "90d"]);
        assert_eq!(config.effective_session_ttl(), MAX_SESSION_TTL);
    }

    #[test]
    fn debug_output_carries_no_secret() {
        let config = minimal(&[
            "--oidc-client-secret",
            "client-secret-value",
            "--authz-token",
            "tok-value",
        ]);
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("shhh"), "{rendered}");
        assert!(!rendered.contains("client-secret-value"), "{rendered}");
        assert!(!rendered.contains("tok-value"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn command_line_definition_is_valid() {
        use clap::CommandFactory;
        Config::command().debug_assert();
    }

    #[test]
    fn client_secret_file_is_read_when_the_flag_is_unset() {
        let dir = std::env::temp_dir().join(format!("lakefs-authn-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client_secret");
        std::fs::write(&path, "from-file\n").unwrap();
        let file = ["--oidc-client-secret-file", path.to_str().unwrap()];

        let config = minimal(&file);
        assert_eq!(config.oidc_client_secret().unwrap().unwrap().expose(), "from-file");

        let config = minimal(&[&["--oidc-client-secret", "inline"][..], &file[..]].concat());
        assert_eq!(config.oidc_client_secret().unwrap().unwrap().expose(), "inline");

        assert!(minimal(&[]).oidc_client_secret().unwrap().is_none());

        std::fs::write(&path, "   \n").unwrap();
        assert!(minimal(&file).oidc_client_secret().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

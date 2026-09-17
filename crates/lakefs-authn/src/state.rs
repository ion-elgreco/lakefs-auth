//! Shared state every handler receives.

use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use jsonwebtoken::EncodingKey;
use lakefs_auth_core::config::Secret;
use lakefs_auth_core::tasks::supervise;
use lakefs_authz_client::{AuthzClient, AuthzClientConfig, ClientAuth};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl, Scope};

use crate::config::Config;
use crate::lakefs::session::{SessionCookies, SessionOptions};
use crate::oidc::{OidcProvider, OidcSettings};
use crate::provision::{ProvisionSettings, Provisioner};
use crate::util::derive_cookie_key;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub oidc: Arc<OidcProvider>,
    pub prov: Arc<Provisioner>,
    pub session: Arc<SessionCookies>,
    pub jwt_key: Arc<EncodingKey>,
    /// Key of the private cookies that carry our own flow state.
    pub key: Key,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("oidc", &self.oidc)
            .field("prov", &self.prov)
            .finish_non_exhaustive()
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

impl AppState {
    /// Builds every long lived component. Discovery runs separately, see [`AppState::spawn_discovery`].
    pub async fn from_config(config: Config) -> anyhow::Result<Self> {
        let secret = config.secret_key.as_str().as_bytes();

        let auth = match config.authz_token.as_ref().and_then(Secret::non_blank) {
            Some(token) => ClientAuth::Static(token.to_owned()),
            None => ClientAuth::internal_jwt(secret),
        };
        let client = AuthzClient::new(AuthzClientConfig::new(config.authz_url.clone(), auth))?;

        let provisioner = Provisioner::new(
            client,
            ProvisionSettings {
                username_claims: config.username_claim.0.clone(),
                friendly_name_claim: config.friendly_name_claim.clone(),
                persist_friendly_name: config.persist_friendly_name,
                initial_groups: config.initial_groups.0.clone(),
                groups_claim: config.groups_claim.clone(),
                group_map: config.group_map.0.clone(),
                group_map_strict: config.group_map_strict,
                source: config.auth_source.clone(),
                auto_provision: config.auto_provision,
            },
        );
        if config.sts_allowed_redirect_uris.is_empty() {
            tracing::warn!("--sts-allowed-redirect-uris is empty: every SDK (STS) login is refused");
        }

        let oidc = OidcProvider::new(OidcSettings {
            issuer: IssuerUrl::new(config.oidc_issuer.clone())
                .map_err(|err| anyhow::anyhow!("--oidc-issuer is not a valid URL: {err}"))?,
            client_id: ClientId::new(config.oidc_client_id.clone()),
            client_secret: config
                .oidc_client_secret()?
                .map(|secret| ClientSecret::new(secret.expose().clone())),
            redirect_uri: RedirectUrl::from_url(config.redirect_uri()?),
            scopes: config
                .oidc_scopes
                .0
                .iter()
                .filter(|scope| scope.as_str() != "openid")
                .map(|scope| Scope::new(scope.clone()))
                .collect(),
            rp_initiated_logout: config.rp_initiated_logout,
            refresh_interval: config.discovery_refresh_interval,
            min_refresh_interval: config.discovery_min_refresh_interval,
            failed_refresh_cooldown: config.discovery_failed_refresh_cooldown,
            timeout: config.discovery_timeout,
        })?;

        let session = SessionCookies::new(
            secret,
            SessionOptions {
                secure: config.cookie_secure(),
                domain: config.cookie_domain.clone(),
                ttl: config.effective_session_ttl(),
            },
        );

        Ok(Self {
            key: derive_cookie_key(secret),
            jwt_key: Arc::new(EncodingKey::from_secret(secret)),
            session: Arc::new(session),
            prov: Arc::new(provisioner),
            oidc: Arc::new(oidc),
            cfg: Arc::new(config),
        })
    }

    /// Starts the discovery retry and refresh loop under a supervisor, which
    /// logs the loop's exit or panic and starts it again: it is the only thing
    /// that picks up a provider key rotation, so it must never die in silence.
    pub fn spawn_discovery(&self) -> tokio::task::JoinHandle<()> {
        let oidc = Arc::clone(&self.oidc);
        supervise("OpenID Connect discovery", move || Arc::clone(&oidc).run())
    }
}

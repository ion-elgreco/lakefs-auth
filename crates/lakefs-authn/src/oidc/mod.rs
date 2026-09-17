//! The OpenID Connect side of the server: discovery state, authorize URLs,
//! code exchange, and ID token verification.

pub mod claims;
pub mod discovery;
pub mod types;

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::reqwest::ClientBuilder;
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, NonceVerifier,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, SignatureVerificationError,
    TokenResponse as _,
};
use url::Url;

pub use claims::{Claims, ClaimsError};
pub use discovery::{Discovered, DiscoveryFailure};
pub use types::{AuthnClient, AuthnIdToken, AuthnTokenResponse, GroupsClaim};

use discovery::DiscoveryRequest;

/// Backoff bounds while the provider is not reachable at startup.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("the identity provider is not available yet")]
    NotReady,
    #[error("the identity provider advertises no token endpoint")]
    NoTokenEndpoint,
    #[error("the identity provider rejected the authorization code")]
    CodeRejected,
    #[error("the identity provider could not be reached")]
    ProviderUnreachable,
    #[error("the identity provider returned an unreadable token response")]
    BadTokenResponse,
    #[error("the identity provider returned no ID token")]
    MissingIdToken,
    #[error("the ID token is not valid: {0}")]
    InvalidIdToken(String),
    #[error("the ID token claims cannot be read")]
    UnreadableClaims(#[from] ClaimsError),
}

/// A provider that is not there is an outage, which callers and alerting see
/// as a 503; a rejected code or a bad token is a 401. The message is the
/// error's own text, which names no code, token, or body.
impl From<OidcError> for lakefs_auth_core::error::ApiError {
    fn from(error: OidcError) -> Self {
        match error {
            OidcError::NotReady | OidcError::NoTokenEndpoint | OidcError::ProviderUnreachable => {
                Self::unavailable(error.to_string())
            }
            other => Self::unauthorized(other.to_string()),
        }
    }
}

/// Settings the provider needs; a subset of the process configuration.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub issuer: IssuerUrl,
    pub client_id: ClientId,
    pub client_secret: Option<ClientSecret>,
    pub redirect_uri: RedirectUrl,
    pub scopes: Vec<Scope>,
    pub rp_initiated_logout: bool,
    pub refresh_interval: Duration,
    /// Shortest gap between two successful refreshes triggered by an unknown key id.
    pub min_refresh_interval: Duration,
    /// Gap after a refresh triggered by an unknown key id that failed.
    pub failed_refresh_cooldown: Duration,
    pub timeout: Duration,
}

/// One refresh triggered by an unknown key id, and how it went.
#[derive(Debug, Clone, Copy)]
struct KeyRefresh {
    at: Instant,
    succeeded: bool,
}

/// Holds the discovered client and keeps it fresh.
pub struct OidcProvider {
    http: reqwest::Client,
    settings: OidcSettings,
    current: RwLock<Option<Arc<Discovered>>>,
    /// The last refresh for an unknown key id, behind an async lock so that
    /// callers that arrive during a refresh wait for it instead of failing.
    last_key_refresh: tokio::sync::Mutex<Option<KeyRefresh>>,
}

impl std::fmt::Debug for OidcProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProvider")
            .field("issuer", &self.settings.issuer.as_str())
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

impl OidcProvider {
    pub fn new(settings: OidcSettings) -> anyhow::Result<Self> {
        let http = ClientBuilder::new()
            // The provider must never bounce us to another host.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(settings.timeout)
            .build()?;
        Ok(Self {
            http,
            settings,
            current: RwLock::new(None),
            last_key_refresh: tokio::sync::Mutex::new(None),
        })
    }

    /// The discovered client, or `None` while discovery has not succeeded.
    ///
    /// A poisoned lock is recovered rather than propagated: the value is
    /// replaced as a whole, so a panic elsewhere cannot leave it half written.
    pub fn current(&self) -> Option<Arc<Discovered>> {
        self.current.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub fn is_ready(&self) -> bool {
        self.current().is_some()
    }

    /// The discovered client, or [`OidcError::NotReady`], which every login
    /// route turns into the same 503.
    pub fn ready(&self) -> Result<Arc<Discovered>, OidcError> {
        self.current().ok_or(OidcError::NotReady)
    }

    /// Fetches the metadata once and publishes it.
    pub async fn discover(&self) -> Result<Arc<Discovered>, DiscoveryFailure> {
        let discovered = discovery::discover(DiscoveryRequest {
            http: &self.http,
            issuer: &self.settings.issuer,
            client_id: &self.settings.client_id,
            client_secret: self.settings.client_secret.as_ref(),
            redirect_uri: &self.settings.redirect_uri,
            want_logout_metadata: self.settings.rp_initiated_logout,
        })
        .await
        .inspect_err(|_| crate::metrics::record_discovery(false))?;
        crate::metrics::record_discovery(true);
        let discovered = Arc::new(discovered);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Some(discovered.clone());
        tracing::info!(
            issuer = %self.settings.issuer.as_str(),
            rp_initiated_logout = discovered.end_session_endpoint.is_some(),
            "OpenID Connect discovery succeeded"
        );
        Ok(discovered)
    }

    /// Retries discovery until it works, then refreshes on a fixed interval.
    ///
    /// The JWKS is not refetched on an unknown key id during verification, so this
    /// loop is what picks up a provider key rotation.
    pub async fn run(self: Arc<Self>) {
        let mut backoff = INITIAL_BACKOFF;
        while let Err(error) = self.discover().await {
            tracing::warn!(
                error = %error,
                issuer = %self.settings.issuer.as_str(),
                retry_in = ?backoff,
                "OpenID Connect discovery failed, retrying"
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        loop {
            tokio::time::sleep(self.settings.refresh_interval).await;
            if let Err(error) = self.discover().await {
                tracing::warn!(error = %error, "scheduled discovery refresh failed, keeping the previous keys");
            }
        }
    }

    /// One rate-limited refresh after a signature failed on an unknown key id.
    ///
    /// Refreshes are serialised: a caller that arrives while one runs waits for
    /// it and receives the metadata it produced, so ten callbacks after a key
    /// rotation cost one fetch and nine waits, not one fetch and nine refusals.
    /// A refresh that succeeded holds the next one off for the regular
    /// interval; one that failed is logged and holds it off only for the short
    /// failure cooldown, so a blip at the provider does not lock logins out for
    /// the whole window. Returns `None` when nothing new can be tried.
    pub async fn refresh_for_key_error(&self) -> Option<Arc<Discovered>> {
        let mut last = self.last_key_refresh.lock().await;
        if let Some(previous) = *last {
            let hold = if previous.succeeded {
                self.settings.min_refresh_interval
            } else {
                self.settings
                    .failed_refresh_cooldown
                    .min(self.settings.min_refresh_interval)
            };
            if previous.at.elapsed() < hold {
                return if previous.succeeded { self.current() } else { None };
            }
        }
        tracing::info!("refreshing OpenID Connect metadata after an unknown signing key");
        match self.discover().await {
            Ok(discovered) => {
                *last = Some(KeyRefresh {
                    at: Instant::now(),
                    succeeded: true,
                });
                Some(discovered)
            }
            Err(error) => {
                tracing::warn!(error = %error, "refreshing the metadata after an unknown signing key failed");
                *last = Some(KeyRefresh {
                    at: Instant::now(),
                    succeeded: false,
                });
                None
            }
        }
    }

    /// Builds the authorization URL and the values the callback has to match.
    pub fn authorize_url(&self, discovered: &Discovered) -> AuthorizeRequest {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = discovered
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(self.settings.scopes.iter().cloned())
            .set_pkce_challenge(challenge)
            .url();
        AuthorizeRequest {
            url,
            state,
            nonce,
            pkce_verifier: verifier,
        }
    }

    /// Exchanges an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        discovered: &Discovered,
        code: String,
        pkce_verifier: Option<PkceCodeVerifier>,
        redirect_uri: Option<RedirectUrl>,
    ) -> Result<AuthnTokenResponse, OidcError> {
        let mut request = discovered
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| OidcError::NoTokenEndpoint)?;
        if let Some(verifier) = pkce_verifier {
            request = request.set_pkce_verifier(verifier);
        }
        if let Some(redirect_uri) = &redirect_uri {
            request = request.set_redirect_uri(std::borrow::Cow::Borrowed(redirect_uri));
        }
        request.request_async(&self.http).await.map_err(|error| {
            // Never render the raw error: a parse failure carries the response body.
            match &error {
                RequestTokenError::ServerResponse(response) => {
                    tracing::warn!(error = %response, "token endpoint returned an error");
                    OidcError::CodeRejected
                }
                RequestTokenError::Request(_) => {
                    tracing::warn!("token endpoint could not be reached");
                    OidcError::ProviderUnreachable
                }
                RequestTokenError::Parse(parse_error, _body) => {
                    tracing::warn!(error = %parse_error, "token endpoint returned an unreadable body");
                    OidcError::BadTokenResponse
                }
                RequestTokenError::Other(message) => {
                    tracing::warn!(error = %message, "token exchange failed");
                    OidcError::BadTokenResponse
                }
            }
        })
    }

    /// Verifies an ID token and returns the claims as they were signed.
    ///
    /// On an unknown key id the metadata refreshes once, rate limited, and the
    /// verification runs again against the new key set.
    pub async fn verify_id_token<N>(
        &self,
        discovered: &Discovered,
        response: &AuthnTokenResponse,
        nonce_verifier: N,
    ) -> Result<(Claims, String), OidcError>
    where
        N: NonceVerifier + Clone,
    {
        let id_token = response.id_token().ok_or(OidcError::MissingIdToken)?;
        let raw = id_token.to_string();
        let first = id_token.claims(&discovered.client.id_token_verifier(), nonce_verifier.clone());
        match first {
            Ok(_) => {}
            Err(error) if is_unknown_key(&error) => {
                let refreshed = self
                    .refresh_for_key_error()
                    .await
                    .ok_or_else(|| OidcError::InvalidIdToken(error.to_string()))?;
                id_token
                    .claims(&refreshed.client.id_token_verifier(), nonce_verifier)
                    .map_err(|error| OidcError::InvalidIdToken(error.to_string()))?;
            }
            Err(error) => return Err(OidcError::InvalidIdToken(error.to_string())),
        }
        Ok((claims::raw_payload(&raw)?, raw))
    }
}

/// Everything `/oidc/login` has to remember until the callback arrives.
pub struct AuthorizeRequest {
    pub url: Url,
    pub state: CsrfToken,
    pub nonce: Nonce,
    pub pkce_verifier: PkceCodeVerifier,
}

/// True when the signature failed because no key in the set matched the key id.
fn is_unknown_key(error: &ClaimsVerificationError) -> bool {
    matches!(
        error,
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey | SignatureVerificationError::AmbiguousKeyId(_)
        )
    )
}

/// Nonce verifier for the STS flow: lakeFS never issued a nonce, so any value passes.
#[derive(Debug, Clone, Copy)]
pub struct AnyNonce;

impl NonceVerifier for AnyNonce {
    fn verify(self, _nonce: Option<&Nonce>) -> Result<(), String> {
        Ok(())
    }
}

/// Nonce verifier for the browser flow: the nonce must equal the one we stored.
#[derive(Debug, Clone)]
pub struct ExpectedNonce(pub Nonce);

impl NonceVerifier for ExpectedNonce {
    fn verify(self, nonce: Option<&Nonce>) -> Result<(), String> {
        NonceVerifier::verify(&self.0, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> OidcSettings {
        OidcSettings {
            issuer: IssuerUrl::new("https://idp.test/realms/x".to_owned()).unwrap(),
            client_id: ClientId::new("lakefs".to_owned()),
            client_secret: None,
            redirect_uri: RedirectUrl::new("http://localhost:8001/oidc/callback".to_owned()).unwrap(),
            scopes: vec![Scope::new("email".to_owned())],
            rp_initiated_logout: false,
            refresh_interval: Duration::from_secs(3600),
            min_refresh_interval: Duration::from_secs(60),
            failed_refresh_cooldown: Duration::from_secs(5),
            timeout: Duration::from_secs(10),
        }
    }

    /// A provider that cannot be reached is an outage, not bad credentials:
    /// the caller and the alerting must see a 503, while a rejected code or a
    /// bad token stays a 401.
    #[test]
    fn provider_failures_are_unavailable_and_token_failures_unauthorized() {
        use axum::http::StatusCode;

        use lakefs_auth_core::error::ApiError;

        for error in [
            OidcError::ProviderUnreachable,
            OidcError::NoTokenEndpoint,
            OidcError::NotReady,
        ] {
            assert_eq!(ApiError::from(error).status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        for error in [
            OidcError::CodeRejected,
            OidcError::BadTokenResponse,
            OidcError::MissingIdToken,
            OidcError::InvalidIdToken("x".to_owned()),
            OidcError::UnreadableClaims(ClaimsError::Malformed),
        ] {
            let converted = ApiError::from(error);
            assert_eq!(converted.status(), StatusCode::UNAUTHORIZED, "{converted}");
        }
    }

    #[test]
    fn a_fresh_provider_is_not_ready() {
        let provider = OidcProvider::new(settings()).unwrap();
        assert!(!provider.is_ready());
        assert!(provider.current().is_none());
        assert!(matches!(provider.ready(), Err(OidcError::NotReady)));
        assert!(format!("{provider:?}").contains("ready: false"));
    }

    #[test]
    fn any_nonce_passes_and_an_expected_nonce_has_to_match() {
        assert!(AnyNonce.verify(None).is_ok());
        assert!(AnyNonce.verify(Some(&Nonce::new("x".to_owned()))).is_ok());
        let expected = ExpectedNonce(Nonce::new("abc".to_owned()));
        assert!(expected.clone().verify(Some(&Nonce::new("abc".to_owned()))).is_ok());
        assert!(expected.clone().verify(Some(&Nonce::new("other".to_owned()))).is_err());
        assert!(expected.verify(None).is_err());
    }

    #[tokio::test]
    async fn a_failed_key_error_refresh_is_held_off_for_the_cooldown() {
        let mut settings = settings();
        settings.min_refresh_interval = Duration::from_secs(600);
        settings.failed_refresh_cooldown = Duration::from_secs(5);
        let provider = OidcProvider::new(settings).unwrap();
        // The first call attempts a refresh, which fails because the issuer is unreachable.
        assert!(provider.refresh_for_key_error().await.is_none());
        // The second call is inside the failure cooldown and does not even try.
        let started = Instant::now();
        assert!(provider.refresh_for_key_error().await.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

//! `Set-Cookie` builders for the lakeFS browser session and for our own flow state.

use std::time::Duration;

use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, SameSite};

use crate::lakefs::gob::{self, GobError};
use crate::lakefs::securecookie::{CookieCodec, CookieError};

pub use lakefs_auth_core::SESSION_COOKIE;
/// Private cookie holding the state, nonce, and PKCE verifier of a browser login.
pub const FLOW_COOKIE: &str = "lakefs_authn_flow";
/// Private cookie holding the raw ID token, only with RP-initiated logout.
pub const ID_TOKEN_COOKIE: &str = "lakefs_authn_idt";
/// Path every cookie uses, so that clearing always matches.
pub const COOKIE_PATH: &str = "/";
/// How long a browser has to come back from the identity provider.
pub const FLOW_TTL: Duration = Duration::from_secs(600);

/// Largest raw ID token the ID token cookie stores.
///
/// The private cookie jar encrypts the value (a 12-byte nonce and a 16-byte
/// tag), base64 encodes it, and percent-encodes the `+`, `/`, and `=` of
/// base64, so the cookie value is about 1.4 times the token. Browsers drop a
/// cookie whose name and value exceed 4096 bytes without a word.
pub const MAX_ID_TOKEN_BYTES: usize = 2_800;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Cookie(#[from] CookieError),
    #[error(transparent)]
    Gob(#[from] GobError),
}

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub secure: bool,
    pub domain: Option<String>,
    pub ttl: Duration,
}

/// Builds every cookie the server sets: the `internal_auth_session` cookie
/// lakeFS reads, and the private flow cookies of a browser login. The
/// `Secure` flag and the lifetimes come from the options, so no route decides
/// them per cookie.
#[derive(Debug, Clone)]
pub struct SessionCookies {
    codec: CookieCodec,
    options: SessionOptions,
}

impl SessionCookies {
    pub fn new(secret: &[u8], options: SessionOptions) -> Self {
        Self {
            codec: CookieCodec::new(secret),
            options,
        }
    }

    /// The `Set-Cookie` that logs a browser into lakeFS.
    pub fn login(&self, token: &str) -> Result<Cookie<'static>, SessionError> {
        let payload = gob::encode_token_map(token);
        let value = self.codec.encode(SESSION_COOKIE, &payload)?;
        let mut cookie = base_cookie(SESSION_COOKIE, value, self.options.secure);
        cookie.set_max_age(to_cookie_duration(self.options.ttl));
        if let Some(domain) = &self.options.domain {
            cookie.set_domain(domain.clone());
        }
        Ok(cookie)
    }

    /// The `Set-Cookie` that logs a browser out. Path and domain must match `login`.
    pub fn clear(&self) -> Cookie<'static> {
        let mut cookie = base_cookie(SESSION_COOKIE, String::new(), self.options.secure);
        cookie.set_max_age(CookieDuration::ZERO);
        if let Some(domain) = &self.options.domain {
            cookie.set_domain(domain.clone());
        }
        cookie
    }

    /// Reads a cookie value back into the login token.
    #[cfg(test)]
    fn read(&self, value: &str) -> Result<String, SessionError> {
        let payload = self.codec.decode(SESSION_COOKIE, value)?;
        Ok(gob::decode_token_map(&payload)?)
    }

    /// The short lived private cookie that carries the state of one browser login.
    pub fn flow(&self, payload: String) -> Cookie<'static> {
        self.private(FLOW_COOKIE, payload, FLOW_TTL)
    }

    /// The private cookie that keeps the raw ID token for RP-initiated logout,
    /// for as long as the session itself.
    ///
    /// A token the browser would drop is not stored at all: logout then behaves
    /// as if no ID token existed, and the log says why instead of a silent gap.
    pub fn id_token(&self, raw_id_token: String) -> Option<Cookie<'static>> {
        if raw_id_token.len() > MAX_ID_TOKEN_BYTES {
            tracing::warn!(
                bytes = raw_id_token.len(),
                limit = MAX_ID_TOKEN_BYTES,
                "the ID token is too large for a browser cookie; logout runs without id_token_hint"
            );
            return None;
        }
        Some(self.private(ID_TOKEN_COOKIE, raw_id_token, self.options.ttl))
    }

    /// Removal cookie with the same path and flags as the private cookie it clears.
    pub fn removal(&self, name: &'static str) -> Cookie<'static> {
        let mut cookie = base_cookie(name, String::new(), self.options.secure);
        cookie.set_max_age(CookieDuration::ZERO);
        cookie
    }

    fn private(&self, name: &'static str, value: String, ttl: Duration) -> Cookie<'static> {
        let mut cookie = base_cookie(name, value, self.options.secure);
        cookie.set_max_age(to_cookie_duration(ttl));
        cookie
    }
}

fn base_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path(COOKIE_PATH);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie
}

fn to_cookie_duration(ttl: Duration) -> CookieDuration {
    CookieDuration::try_from(ttl).unwrap_or(CookieDuration::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn options() -> SessionOptions {
        SessionOptions {
            secure: false,
            domain: None,
            ttl: Duration::from_secs(3600),
        }
    }

    #[test]
    fn login_cookie_round_trips_and_carries_the_expected_attributes() {
        let cookies = SessionCookies::new(b"secret", options());
        let cookie = cookies.login("the.jwt.token").unwrap();
        assert_eq!(cookie.name(), SESSION_COOKIE);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(3600)));
        assert_eq!(cookies.read(cookie.value()).unwrap(), "the.jwt.token");
    }

    #[test]
    fn secure_and_domain_reach_the_header() {
        let cookies = SessionCookies::new(
            b"secret",
            SessionOptions {
                secure: true,
                domain: Some("lakefs.example.com".to_owned()),
                ttl: Duration::from_secs(60),
            },
        );
        let header = cookies.login("t").unwrap().to_string();
        assert!(header.contains("Secure"), "{header}");
        assert!(header.contains("Domain=lakefs.example.com"), "{header}");
        assert!(header.contains("HttpOnly"), "{header}");
        assert!(header.contains("SameSite=Lax"), "{header}");
        let clear = cookies.clear().to_string();
        assert!(clear.contains("Domain=lakefs.example.com"), "{clear}");
        assert!(clear.contains("Max-Age=0"), "{clear}");
    }

    #[test]
    fn a_cookie_from_another_secret_does_not_open() {
        let cookie = SessionCookies::new(b"secret", options()).login("t").unwrap();
        let other = SessionCookies::new(b"another", options());
        assert!(matches!(
            other.read(cookie.value()),
            Err(SessionError::Cookie(CookieError::BadSignature))
        ));
    }

    /// Encryption and encoding grow the value by about two fifths, and browsers
    /// drop a cookie above 4096 bytes without a word. A token that would end up
    /// there is not stored, so that logout at least behaves as if no ID token
    /// existed, and the operator gets a log line instead of a silent gap.
    #[test]
    fn an_oversized_id_token_is_not_put_in_a_cookie() {
        let mut options = options();
        options.ttl = Duration::from_secs(60);
        let cookies = SessionCookies::new(b"secret", options);
        let fits = cookies.id_token("x".repeat(2_000)).expect("stored");
        assert_eq!(fits.name(), ID_TOKEN_COOKIE);
        assert_eq!(fits.max_age(), Some(CookieDuration::seconds(60)));
        assert!(cookies.id_token("x".repeat(3_000)).is_none());
    }

    /// The flow cookies take the `Secure` flag from the options, like the
    /// session cookie, so a route cannot ship one without it on https.
    #[test]
    fn private_cookies_follow_the_secure_option() {
        let mut options = options();
        options.secure = true;
        let cookies = SessionCookies::new(b"secret", options);
        let flow = cookies.flow("payload".to_owned());
        assert_eq!(flow.name(), FLOW_COOKIE);
        assert_eq!(flow.secure(), Some(true));
        assert_eq!(flow.http_only(), Some(true));
        assert_eq!(flow.max_age(), Some(CookieDuration::seconds(600)));
        let removal = cookies.removal(FLOW_COOKIE);
        assert_eq!(removal.max_age(), Some(CookieDuration::ZERO));
        assert_eq!(removal.path(), Some("/"));
        assert_eq!(removal.secure(), Some(true));
    }
}

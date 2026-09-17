//! The login JWT lakeFS reads out of the browser session cookie.
//!
//! HS256 over the raw bytes of `auth.encrypt.secret_key`. `aud` must be the plain
//! string `login`; lakeFS fails to parse an array. `exp` is required.

use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lakefs_auth_core::auth::expires_at;
use serde::{Deserialize, Serialize};

/// Value lakeFS expects in `iss`.
pub const LOGIN_ISSUER: &str = "auth";
/// Value lakeFS expects in `aud`.
pub const LOGIN_AUDIENCE: &str = "login";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginClaims {
    pub jti: String,
    pub iss: String,
    pub sub: String,
    /// A plain string, never an array.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

impl LoginClaims {
    pub fn new(username: &str, issued_at: i64, ttl: Duration) -> Self {
        Self {
            jti: uuid::Uuid::new_v4().to_string(),
            iss: LOGIN_ISSUER.to_owned(),
            sub: username.to_owned(),
            aud: LOGIN_AUDIENCE.to_owned(),
            iat: issued_at,
            exp: expires_at(issued_at, ttl),
        }
    }
}

/// Mints the token that goes into `internal_auth_session`.
pub fn mint_login_token(
    key: &EncodingKey,
    username: &str,
    ttl: Duration,
) -> Result<String, jsonwebtoken::errors::Error> {
    mint_login_token_at(key, username, ttl, jiff::Timestamp::now().as_second())
}

pub fn mint_login_token_at(
    key: &EncodingKey,
    username: &str,
    ttl: Duration,
    issued_at: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::new(Algorithm::HS256),
        &LoginClaims::new(username, issued_at, ttl),
        key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use pretty_assertions::assert_eq;

    const SECRET: &[u8] = b"lakefs shared secret";

    #[test]
    fn header_and_claims_match_what_lakefs_parses() {
        let key = EncodingKey::from_secret(SECRET);
        let token = mint_login_token_at(&key, "alice", Duration::from_secs(3600), 1_767_225_600).unwrap();
        let mut parts = token.split('.');
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap()).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap()).unwrap();
        assert_eq!(header, serde_json::json!({"alg": "HS256", "typ": "JWT"}));
        assert_eq!(claims["iss"], "auth");
        assert_eq!(claims["sub"], "alice");
        // A plain string, not an array.
        assert_eq!(claims["aud"], serde_json::Value::String("login".to_owned()));
        assert_eq!(claims["iat"], 1_767_225_600i64);
        assert_eq!(claims["exp"], 1_767_229_200i64);
        assert!(claims["jti"].as_str().is_some_and(|jti| jti.len() == 36));
        assert_eq!(parts.next().unwrap().len(), 43, "HS256 signature is 32 bytes");
        assert!(parts.next().is_none());
    }

    #[test]
    fn verifies_under_the_lakefs_validation_rules() {
        let token = mint_login_token(&EncodingKey::from_secret(SECRET), "alice", Duration::from_secs(3600)).unwrap();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[LOGIN_AUDIENCE]);
        validation.set_issuer(&[LOGIN_ISSUER]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let decoded =
            decode::<LoginClaims>(&token, &DecodingKey::from_secret(SECRET), &validation).expect("token verifies");
        assert_eq!(decoded.claims.sub, "alice");
        assert_eq!(decoded.claims.aud, "login");
    }

    #[test]
    fn another_secret_does_not_verify() {
        let token = mint_login_token(&EncodingKey::from_secret(SECRET), "alice", Duration::from_secs(3600)).unwrap();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[LOGIN_AUDIENCE]);
        assert!(decode::<LoginClaims>(&token, &DecodingKey::from_secret(b"other"), &validation).is_err());
    }

    #[test]
    fn an_expired_token_does_not_verify() {
        let key = EncodingKey::from_secret(SECRET);
        let issued = jiff::Timestamp::now().as_second() - 7200;
        let token = mint_login_token_at(&key, "alice", Duration::from_secs(60), issued).unwrap();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[LOGIN_AUDIENCE]);
        assert!(decode::<LoginClaims>(&token, &DecodingKey::from_secret(SECRET), &validation).is_err());
    }

    #[test]
    fn each_token_gets_its_own_jti() {
        let key = EncodingKey::from_secret(SECRET);
        let first = LoginClaims::new("alice", 1, Duration::from_secs(1));
        let second = LoginClaims::new("alice", 1, Duration::from_secs(1));
        assert_ne!(first.jti, second.jti);
        assert_ne!(
            mint_login_token_at(&key, "a", Duration::from_secs(1), 1).unwrap(),
            mint_login_token_at(&key, "a", Duration::from_secs(1), 1).unwrap()
        );
    }
}

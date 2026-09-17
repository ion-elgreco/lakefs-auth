use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::text::non_blank;

/// Audience lakeFS puts in the token it mints when `auth.api.token` is empty.
pub const INTERNAL_AUDIENCE: &str = "auth-client";
/// Subject of that token.
pub const INTERNAL_SUBJECT: &str = "_lakefs-internal";

const LEEWAY_SECONDS: u64 = 60;

/// The verifier reads no claim itself: `jsonwebtoken` checks `exp` and `aud`
/// in its own pass, so nothing is deserialized and then thrown away.
#[derive(Deserialize)]
struct NoClaims {}

#[derive(Debug, Serialize)]
struct InternalClaims {
    jti: String,
    aud: Vec<String>,
    sub: String,
    iat: i64,
    exp: i64,
}

/// The `exp` claim of a token issued at `issued_at` that lives for `ttl`. A
/// ttl too large for the claim clamps to a value no clock reaches.
pub fn expires_at(issued_at: i64, ttl: Duration) -> i64 {
    issued_at.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX / 2))
}

/// Mints the same HS256 token lakeFS mints from `auth.encrypt.secret_key`.
/// `key` is `EncodingKey::from_secret(secret)`, built once by the caller.
pub fn mint_internal_token(key: &EncodingKey, ttl: Duration) -> Result<String, jsonwebtoken::errors::Error> {
    let now = jiff::Timestamp::now().as_second();
    let claims = InternalClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        aud: vec![INTERNAL_AUDIENCE.to_owned()],
        sub: INTERNAL_SUBJECT.to_owned(),
        iat: now,
        exp: expires_at(now, ttl),
    };
    encode(&Header::new(Algorithm::HS256), &claims, key)
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierConfigError {
    #[error("configure a shared secret key or a static API token, or disable authentication")]
    NothingConfigured,
}

/// Verifies the bearer token on incoming requests.
///
/// Accepts a configured static token (constant-time compare). Without a static
/// token it accepts an HS256 JWT signed with the shared secret and addressed to
/// `auth-client`, which is what lakeFS mints when `auth.api.token` is empty.
/// With a static token configured lakeFS sends only that token, so the JWT path
/// stays closed and the shared secret serves credential encryption alone.
pub struct TokenVerifier {
    static_token: Option<Vec<u8>>,
    decoding_key: Option<DecodingKey>,
    validation: Validation,
    disabled: bool,
}

impl std::fmt::Debug for TokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenVerifier")
            .field("static_token", &self.static_token.is_some())
            .field("jwt", &self.decoding_key.is_some())
            .field("disabled", &self.disabled)
            .finish()
    }
}

impl TokenVerifier {
    pub fn new(secret_key: Option<&str>, api_token: Option<&str>, disabled: bool) -> Result<Self, VerifierConfigError> {
        let static_token = api_token.and_then(non_blank).map(|t| t.as_bytes().to_vec());
        let decoding_key = if static_token.is_some() {
            None
        } else {
            secret_key
                .and_then(non_blank)
                .map(|s| DecodingKey::from_secret(s.as_bytes()))
        };
        if !disabled && static_token.is_none() && decoding_key.is_none() {
            return Err(VerifierConfigError::NothingConfigured);
        }
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[INTERNAL_AUDIENCE]);
        // `set_audience` only pins the value when the claim is present. Without
        // this line a token that omits `aud` passes, so any HS256 token minted
        // from the shared secret anywhere in the trust domain would be accepted.
        validation.set_required_spec_claims(&["exp", "aud"]);
        validation.leeway = LEEWAY_SECONDS;
        Ok(Self {
            static_token,
            decoding_key,
            validation,
            disabled,
        })
    }

    /// A verifier that accepts everything. Only for local development.
    pub fn disabled() -> Self {
        Self::new(None, None, true).expect("disabled verifier needs no configuration")
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// One phrase for the startup log, decided by the same precedence `verify` applies.
    pub fn mode(&self) -> &'static str {
        if self.disabled {
            "disabled"
        } else if self.static_token.is_some() {
            "static token"
        } else {
            "shared secret (HS256)"
        }
    }

    pub fn verify(&self, bearer: &str) -> Result<(), ApiError> {
        if self.disabled {
            return Ok(());
        }
        if let Some(expected) = &self.static_token
            && bool::from(expected.as_slice().ct_eq(bearer.as_bytes()))
        {
            return Ok(());
        }
        if let Some(key) = &self.decoding_key {
            match decode::<NoClaims>(bearer, key, &self.validation) {
                Ok(_) => return Ok(()),
                Err(error) => tracing::debug!(error = %error, "bearer token rejected"),
            }
        }
        Err(ApiError::unauthorized("invalid bearer token"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "some random secret string";

    #[test]
    fn accepts_token_minted_with_shared_secret() {
        let verifier = TokenVerifier::new(Some(SECRET), None, false).unwrap();
        let token =
            mint_internal_token(&EncodingKey::from_secret(SECRET.as_bytes()), Duration::from_secs(3600)).unwrap();
        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn rejects_wrong_secret_and_garbage() {
        let verifier = TokenVerifier::new(Some(SECRET), None, false).unwrap();
        let token = mint_internal_token(&EncodingKey::from_secret(b"other secret"), Duration::from_secs(3600)).unwrap();
        assert!(verifier.verify(&token).is_err());
        assert!(verifier.verify("not.a.jwt").is_err());
        assert!(verifier.verify("").is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        #[derive(Serialize)]
        struct Claims<'a> {
            aud: &'a str,
            sub: &'a str,
            exp: i64,
        }
        let verifier = TokenVerifier::new(Some(SECRET), None, false).unwrap();
        let claims = Claims {
            aud: "login",
            sub: "alice",
            exp: jiff::Timestamp::now().as_second() + 600,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        assert!(verifier.verify(&token).is_err());
    }

    #[test]
    fn rejects_a_token_without_an_audience() {
        #[derive(Serialize)]
        struct ExpOnly {
            exp: i64,
        }
        #[derive(Serialize)]
        struct NoAudience<'a> {
            sub: &'a str,
            exp: i64,
        }
        let verifier = TokenVerifier::new(Some(SECRET), None, false).unwrap();
        let key = EncodingKey::from_secret(SECRET.as_bytes());
        let exp = jiff::Timestamp::now().as_second() + 600;
        let bare = encode(&Header::new(Algorithm::HS256), &ExpOnly { exp }, &key).unwrap();
        assert!(verifier.verify(&bare).is_err(), "a token with only exp must be refused");
        let no_aud = encode(
            &Header::new(Algorithm::HS256),
            &NoAudience {
                sub: INTERNAL_SUBJECT,
                exp,
            },
            &key,
        )
        .unwrap();
        assert!(verifier.verify(&no_aud).is_err(), "a token without aud must be refused");
    }

    /// With a static token configured, lakeFS sends that token and never mints
    /// the shared-secret JWT, so the JWT path must be closed.
    #[test]
    fn a_static_token_switches_the_shared_secret_off() {
        let verifier = TokenVerifier::new(Some(SECRET), Some("static-token"), false).unwrap();
        assert!(verifier.verify("static-token").is_ok());
        let jwt = mint_internal_token(&EncodingKey::from_secret(SECRET.as_bytes()), Duration::from_secs(600)).unwrap();
        assert!(
            verifier.verify(&jwt).is_err(),
            "the JWT must not be accepted next to a static token"
        );
        assert!(format!("{verifier:?}").contains("jwt: false"), "{verifier:?}");
        assert_eq!(verifier.mode(), "static token");
    }

    #[test]
    fn static_token_is_compared_exactly() {
        let verifier = TokenVerifier::new(None, Some("static-token"), false).unwrap();
        assert!(verifier.verify("static-token").is_ok());
        assert!(verifier.verify("static-token2").is_err());
        assert!(verifier.verify("static-toke").is_err());
    }

    #[test]
    fn needs_some_configuration_unless_disabled() {
        assert!(TokenVerifier::new(None, None, false).is_err());
        assert!(TokenVerifier::new(Some(""), Some(""), false).is_err());
        assert!(TokenVerifier::disabled().verify("anything").is_ok());
        assert_eq!(TokenVerifier::disabled().mode(), "disabled");
        assert_eq!(
            TokenVerifier::new(Some(SECRET), None, false).unwrap().mode(),
            "shared secret (HS256)"
        );
    }
}

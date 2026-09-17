//! The bearer token lakeFS sends to the authorization API.

#[cfg(feature = "server")]
pub mod middleware;
mod token;

pub use jsonwebtoken::EncodingKey;
pub use token::{
    INTERNAL_AUDIENCE, INTERNAL_SUBJECT, TokenVerifier, VerifierConfigError, expires_at, mint_internal_token,
};

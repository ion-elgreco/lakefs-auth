//! Shared building blocks for the lakeFS authentication and authorization servers.
//!
//! The crate has no server dependencies by default. Enable `server` for the axum
//! middleware and telemetry helpers, `jwt` for the lakeFS internal token handling,
//! and `crypto` for secret encryption and access key generation.

/// The cookie lakeFS reads the login token from. The authentication server
/// sets it, and the policy builder of the authorization server reads it back.
/// lakeFS lists it in `auth.ui_config.login_cookie_names`.
pub const SESSION_COOKIE: &str = "internal_auth_session";

pub mod catalog;
pub mod config;
pub mod error;
pub mod model;
pub mod pagination;
pub mod text;
pub mod validate;

#[cfg(feature = "jwt")]
pub mod auth;

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "server")]
pub mod listener;
#[cfg(feature = "server")]
pub mod metrics;
#[cfg(feature = "server")]
pub mod shutdown;
#[cfg(feature = "server")]
pub mod tasks;
#[cfg(feature = "server")]
pub mod telemetry;

#[cfg(test)]
mod tests {
    /// The workspace manifest and the LICENSE file must agree; the image labels
    /// and the release tarballs both read the manifest.
    #[test]
    fn the_package_license_matches_the_license_file() {
        assert_eq!(env!("CARGO_PKG_LICENSE"), "MIT");
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../LICENSE")).expect("LICENSE");
        assert!(text.starts_with("MIT License"), "{text}");
    }
}

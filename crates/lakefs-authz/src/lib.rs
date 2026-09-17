//! lakeFS authorization server.
//!
//! Implements `api/authorization.yml` on top of PostgreSQL. lakeFS evaluates
//! policies itself and uses this server as the store for users, groups,
//! policies, credentials, and claimed token ids.
//!
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use std::sync::Arc;
//! use lakefs_auth_core::auth::TokenVerifier;
//! use lakefs_auth_core::crypto::SecretBox;
//! use lakefs_authz::app::{AppState, RouterOptions, build_router, serve};
//! use lakefs_authz::store::PgStore;
//!
//! let store = PgStore::connect("postgres://localhost/authz", 10).await?;
//! store.run_migrations().await?;
//! let state = AppState::new(
//!     Arc::new(store),
//!     SecretBox::derive(b"shared secret"),
//!     TokenVerifier::new(Some("shared secret"), None, false)?,
//! );
//! let router = build_router(state, &RouterOptions::default());
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8002").await?;
//! serve(listener, router).await?;
//! # Ok(()) }
//! ```

pub mod app;
pub mod bootstrap;
pub mod policy_builder;
pub mod cleanup;
pub mod config;
pub mod handlers;
pub mod lakefs;
pub mod metrics;
pub mod routes;
pub mod service;
pub mod store;

/// Reported by `GET /config/version`, which lakeFS logs at startup.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// lakeFS uses `auth.api.endpoint` verbatim, and that URL carries `/api/v1`.
pub const DEFAULT_BASE_PATH: &str = "/api/v1";

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8002";

//! lakeFS authentication server.
//!
//! Serves the operations of the lakeFS `api/authentication.yml` contract plus the
//! browser OIDC routes, and writes the lakeFS browser session cookie itself.
//!
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use lakefs_authn::{AppState, Config, build_router};
//!
//! let config = Config::try_from_args(std::env::args_os())?;
//! let state = AppState::from_config(config).await?;
//! state.spawn_discovery();
//! let app = build_router(state);
//! # let _ = app;
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod lakefs;
pub mod metrics;
pub mod oidc;
pub mod provision;
pub mod routes;
pub mod state;
pub mod util;

pub use config::Config;
pub use routes::build_router;
pub use state::AppState;

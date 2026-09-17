//! Entry point of the lakeFS authentication server.

use std::sync::Arc;

use clap::Parser;
use lakefs_auth_core::metrics::serve_metrics;
use lakefs_auth_core::shutdown::shutdown_signal;
use lakefs_auth_core::telemetry::init_tracing;
use lakefs_authn::{AppState, Config, build_router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    init_tracing(&config.log_level, config.log_format);
    lakefs_authn::metrics::init();

    let state = AppState::from_config(config).await?;
    state.spawn_discovery();
    let cfg = Arc::clone(&state.cfg);
    let app = build_router(state);

    let metrics = cfg
        .metrics_listen
        .clone()
        .map(|address| tokio::spawn(serve_metrics(address, shutdown_signal())));

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(
        address = %listener.local_addr()?,
        base_path = %cfg.base_path(),
        issuer = %cfg.oidc_issuer,
        redirect_uri = %cfg.redirect_uri()?,
        "lakefs-authn is listening"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    if let Some(metrics) = metrics {
        metrics.abort();
    }
    Ok(())
}

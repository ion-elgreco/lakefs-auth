//! Server entry point.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser as _;
use lakefs_auth_core::metrics::serve_metrics;
use lakefs_auth_core::shutdown::shutdown_signal;
use lakefs_auth_core::tasks::supervise;
use lakefs_auth_core::telemetry::init_tracing;
use lakefs_authz::app::{AppState, build_router, serve};
use lakefs_authz::bootstrap;
use lakefs_authz::cleanup::cleanup_token_ids;
use lakefs_authz::config::Config;
use lakefs_authz::policy_builder::{BuilderState, serve_builder};
use lakefs_authz::store::{AdminStore as _, PgStore, Store};

/// How often the database pool gauges are refreshed. Fast enough to catch a
/// pool that saturates, slow enough to cost nothing.
const POOL_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    init_tracing(&config.log_level, config.log_format);
    lakefs_authz::metrics::init();

    let verifier = config.verifier().context("bearer token configuration")?;
    if verifier.is_disabled() {
        tracing::warn!("authentication is disabled: every caller is trusted, do not run this in production");
    }
    let secrets = config.secret_box().context("credential encryption key")?;

    let store = PgStore::connect(config.database_url.expose(), config.database_max_connections).await?;
    if config.run_migrations {
        store.run_migrations().await?;
        tracing::info!("migrations are up to date");
    }
    store.ping().await.context("database health check")?;

    let pool = store.pool().clone();
    let store: Arc<dyn Store> = Arc::new(store);

    if let Some(path) = &config.bootstrap_file {
        let plan = bootstrap::load_plan(path, &secrets)?;
        bootstrap::apply(store.as_ref(), &plan).await?;
    }

    // Both loops run for the whole process lifetime. A supervisor logs a panic
    // and restarts the loop instead of losing it in silence.
    let cleanup = {
        let store = Arc::clone(&store);
        let interval = config.token_cleanup_interval;
        supervise("token id cleanup", move || {
            cleanup_token_ids(Arc::clone(&store), interval)
        })
    };
    let metrics = config.metrics_listen.clone().map(|address| {
        let sampler = supervise("database pool sampler", move || {
            lakefs_authz::metrics::sample_pool(pool.clone(), POOL_SAMPLE_INTERVAL)
        });
        (tokio::spawn(serve_metrics(address, shutdown_signal())), sampler)
    });

    let builder = config.builder_listen.clone().map(|address| {
        let state = BuilderState {
            lakefs: config.lakefs_client(),
        };
        tokio::spawn(serve_builder(address, state, shutdown_signal()))
    });

    let options = config.router_options();
    let auth_mode = verifier.mode();
    let state = AppState::new(Arc::clone(&store), secrets, verifier);
    let router = build_router(state, &options);

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    tracing::info!(
        listen = %listener.local_addr()?,
        base_path = %config.base_path,
        auth = auth_mode,
        version = lakefs_authz::VERSION,
        "lakefs-authz is ready"
    );

    let result = serve(listener, router).await;
    cleanup.abort();
    if let Some((server, sampler)) = metrics {
        server.abort();
        sampler.abort();
    }
    if let Some(server) = builder {
        server.abort();
    }
    result.context("serve")
}

//! The auxiliary listeners: metrics and the policy builder each get one.

use axum::Router;

/// Binds `address` and serves `router` until `shutdown` resolves.
///
/// A bind failure is logged and the future returns, because losing an
/// auxiliary listener must never take the API down. `name` is what the log
/// lines call the listener.
pub async fn serve_aux(
    name: &'static str,
    address: String,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    let listener = match tokio::net::TcpListener::bind(&address).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(listener = name, address = %address, error = %error, "binding the listener failed");
            return;
        }
    };
    match listener.local_addr() {
        Ok(bound) => tracing::info!(listener = name, address = %bound, "listening"),
        Err(error) => tracing::warn!(listener = name, error = %error, "the listener has no local address"),
    }
    if let Err(error) = axum::serve(listener, router).with_graceful_shutdown(shutdown).await {
        tracing::error!(listener = name, error = %error, "the listener stopped");
    }
}

//! Tracing setup and HTTP layers shared by both servers.

use std::str::FromStr;

use axum::Router;
use http::Request;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{MakeSpan, TraceLayer};
use tracing::{Span, info_span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!("unknown log format {other:?}, expected text or json")),
        }
    }
}

/// Installs the global subscriber. `RUST_LOG` overrides `level`. Safe to call more than once.
pub fn init_tracing(level: &str, format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let result = match format {
        LogFormat::Text => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .try_init(),
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().flatten_event(true))
            .try_init(),
    };
    if result.is_err() {
        tracing::debug!("tracing subscriber was already installed");
    }
}

/// Span per request with the method, path, and the request id lakeFS forwards.
#[derive(Debug, Clone, Copy, Default)]
pub struct MakeHttpSpan;

impl<B> MakeSpan<B> for MakeHttpSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let request_id = request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-");
        info_span!(
            "http",
            method = %request.method(),
            path = %request.uri().path(),
            request_id = %request_id,
        )
    }
}

/// Adds request-id generation, tracing, metrics, and request-id propagation,
/// outermost first. Every route of both servers is counted and timed because
/// both routers pass through here.
pub fn with_http_layers<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(TraceLayer::new_for_http().make_span_with(MakeHttpSpan))
            .layer(axum::middleware::from_fn(crate::metrics::track_http))
            .layer(PropagateRequestIdLayer::x_request_id()),
    )
}

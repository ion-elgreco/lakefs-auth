//! Prometheus metrics shared by both servers.
//!
//! Every metric registers itself against [`REGISTRY`] on first use. [`scrape`]
//! renders the current snapshot in the text exposition format. The HTTP metrics
//! come from [`track_http`], which [`crate::telemetry::with_http_layers`] adds to
//! both routers, so a server gets them without wiring anything.
//!
//! Recording always runs. Nothing is exposed until the binary serves
//! [`metrics_router`] on its own listener, which both servers do only when the
//! operator sets a metrics address.

use std::sync::LazyLock;
use std::time::Instant;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use prometheus::{Encoder as _, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

/// Label used when a request matched no route, so the label stays bounded.
const UNMATCHED: &str = "<unmatched>";

/// Label used for any HTTP method outside the nine standard ones. hyper accepts
/// any token as a method, so the raw value would be an unbounded label.
const OTHER_METHOD: &str = "<other>";

/// Status label of a request whose future was dropped before a response existed,
/// which is what a client disconnect or an upstream reset looks like.
const CANCELLED: &str = "cancelled";

/// Buckets in seconds. The lower end matters because lakeFS calls lakefs-authz
/// on every authorization decision, so most requests should land under 25 ms.
const DURATION_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// Registers a collector against [`REGISTRY`], or panics with the metric name
/// when it clashes. Each server crate uses this for its own metrics, so one
/// scrape returns everything.
pub fn register<C: prometheus::core::Collector + Clone + 'static>(collector: C, name: &str) -> C {
    REGISTRY
        .register(Box::new(collector.clone()))
        .unwrap_or_else(|error| panic!("metric {name} registers: {error}"));
    collector
}

static HTTP_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "lakefs_auth_http_requests_total",
            "HTTP requests handled, by method, matched route, and response status.",
        ),
        &["method", "route", "status"],
    )
    .expect("valid metric options");
    register(counter, "lakefs_auth_http_requests_total")
});

static HTTP_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "lakefs_auth_http_request_duration_seconds",
            "Wall time to handle an HTTP request, by method and matched route.",
        )
        .buckets(DURATION_BUCKETS.to_vec()),
        &["method", "route"],
    )
    .expect("valid metric options");
    register(histogram, "lakefs_auth_http_request_duration_seconds")
});

static HTTP_IN_FLIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    let gauge = IntGauge::new(
        "lakefs_auth_http_requests_in_flight",
        "HTTP requests currently being handled.",
    )
    .expect("valid metric options");
    register(gauge, "lakefs_auth_http_requests_in_flight")
});

/// Registers every HTTP metric family now, so that the first scrape after a
/// restart already lists the gauge. The counter and histogram families appear
/// with their first request, because their label values are only known then.
pub fn init() {
    LazyLock::force(&HTTP_REQUESTS);
    LazyLock::force(&HTTP_DURATION);
    LazyLock::force(&HTTP_IN_FLIGHT);
}

/// Middleware that counts and times every request.
///
/// The route label is the matched path pattern, never the raw URI, so a path
/// parameter such as a user name cannot blow up the label cardinality. The
/// method label is one of the nine standard verbs or [`OTHER_METHOD`].
pub async fn track_http(request: Request, next: Next) -> Response {
    let route = request.extensions().get::<MatchedPath>().cloned();
    let in_flight = InFlight::start(method_label(request.method()), route);
    let response = next.run(request).await;
    in_flight.finish(response.status().as_str());
    response
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        _ => OTHER_METHOD,
    }
}

/// One request in progress. Created before the handler runs and finished with
/// the response status. When the request future is dropped instead, `Drop`
/// still lowers the gauge and counts the request as cancelled, so a client
/// that disconnects cannot leave the gauge one too high forever.
struct InFlight {
    method: &'static str,
    /// The matched pattern; `None` when no route matched. `MatchedPath` is a
    /// shared string, so holding it costs no copy per request.
    route: Option<MatchedPath>,
    started: Instant,
    finished: bool,
}

impl InFlight {
    fn start(method: &'static str, route: Option<MatchedPath>) -> Self {
        HTTP_IN_FLIGHT.inc();
        Self {
            method,
            route,
            started: Instant::now(),
            finished: false,
        }
    }

    fn finish(mut self, status: &str) {
        self.finished = true;
        self.record(status);
    }

    fn record(&self, status: &str) {
        let route = self.route.as_ref().map_or(UNMATCHED, MatchedPath::as_str);
        HTTP_REQUESTS.with_label_values(&[self.method, route, status]).inc();
        HTTP_DURATION
            .with_label_values(&[self.method, route])
            .observe(self.started.elapsed().as_secs_f64());
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        HTTP_IN_FLIGHT.dec();
        if !self.finished {
            self.record(CANCELLED);
        }
    }
}

/// Renders the registry in the Prometheus text exposition format.
pub fn scrape() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(error) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        tracing::warn!(error = %error, "encoding metrics failed");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|error| {
        tracing::warn!(error = %error, "metrics output is not valid UTF-8");
        String::new()
    })
}

/// A router with `/metrics` only. Serve it on its own listener, never on the
/// listener that carries the API.
pub fn metrics_router() -> Router {
    Router::new().route("/metrics", get(handler))
}

async fn handler() -> ([(axum::http::HeaderName, &'static str); 1], String) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        scrape(),
    )
}

/// Binds `address` and serves `/metrics` until `shutdown` resolves. A bind
/// failure is logged and the future returns, because losing metrics must
/// never take the server down.
pub async fn serve_metrics(address: String, shutdown: impl Future<Output = ()> + Send + 'static) {
    init();
    crate::listener::serve_aux("metrics", address, metrics_router(), shutdown).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrape_renders_the_registered_metrics() {
        HTTP_REQUESTS.with_label_values(&["GET", "/healthz", "200"]).inc();
        HTTP_DURATION.with_label_values(&["GET", "/healthz"]).observe(0.004);
        let rendered = scrape();
        assert!(
            rendered.contains("lakefs_auth_http_requests_total"),
            "counter is missing from:\n{rendered}"
        );
        assert!(
            rendered.contains("lakefs_auth_http_request_duration_seconds_bucket"),
            "histogram buckets are missing from:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"route="/healthz""#),
            "route label is missing from:\n{rendered}"
        );
    }

    /// The label must be the route pattern. If it were the raw URI, one metric
    /// series would appear per user name and the registry would grow without end.
    #[tokio::test]
    async fn the_route_label_is_the_pattern_not_the_raw_path() {
        use axum::routing::get;
        use tower::ServiceExt as _;

        let router =
            crate::telemetry::with_http_layers(Router::new().route("/auth/users/{username}", get(|| async { "ok" })));
        let request = Request::builder()
            .uri("/auth/users/some-very-specific-person")
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = router.oneshot(request).await.expect("call router");
        assert_eq!(response.status(), 200);

        let rendered = scrape();
        assert!(
            rendered.contains(r#"route="/auth/users/{username}""#),
            "the matched pattern is missing from:\n{rendered}"
        );
        assert!(
            !rendered.contains("some-very-specific-person"),
            "the raw path leaked into a label:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn an_unmatched_request_uses_a_single_bounded_label() {
        use tower::ServiceExt as _;

        let router = crate::telemetry::with_http_layers(Router::new());
        let request = Request::builder()
            .uri("/no/such/route")
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = router.oneshot(request).await.expect("call router");
        assert_eq!(response.status(), 404);

        let rendered = scrape();
        assert!(
            rendered.contains(r#"route="<unmatched>""#),
            "the unmatched label is missing from:\n{rendered}"
        );
        assert!(
            !rendered.contains("/no/such/route"),
            "the raw path leaked into a label:\n{rendered}"
        );
    }

    /// HTTP methods are an open token set: hyper accepts any token. Every unknown
    /// verb must fold into one label, or junk requests grow the registry forever.
    #[tokio::test]
    async fn an_unknown_http_method_is_folded_into_one_label() {
        use axum::http::Method;
        use axum::routing::get;
        use tower::ServiceExt as _;

        let router = crate::telemetry::with_http_layers(Router::new().route("/verbs", get(|| async { "ok" })));
        let request = Request::builder()
            .method(Method::from_bytes(b"AAAA1").expect("hyper accepts any token"))
            .uri("/verbs")
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = router.oneshot(request).await.expect("call router");
        assert_eq!(response.status(), 405);

        let rendered = scrape();
        assert!(
            !rendered.contains("AAAA1"),
            "the raw verb leaked into a label:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"method="<other>",route="/verbs""#),
            "the folded label is missing from:\n{rendered}"
        );
    }

    /// A client that disconnects drops the request future before the handler
    /// answers. The gauge must still go back down, and the request is counted.
    #[tokio::test]
    async fn a_cancelled_request_does_not_leak_the_in_flight_gauge() {
        use axum::routing::get;
        use std::time::Duration;
        use tower::ServiceExt as _;

        let router = crate::telemetry::with_http_layers(Router::new().route(
            "/slow",
            get(|| async {
                std::future::pending::<()>().await;
                "never"
            }),
        ));
        let before = HTTP_IN_FLIGHT.get();
        let request = Request::builder()
            .uri("/slow")
            .body(axum::body::Body::empty())
            .expect("build request");
        let outcome = tokio::time::timeout(Duration::from_millis(50), router.oneshot(request)).await;
        assert!(outcome.is_err(), "the request must have been cancelled");

        // Other tests in this binary run at the same time, so wait for the
        // gauge to settle instead of reading it once.
        for _ in 0..200 {
            if HTTP_IN_FLIGHT.get() <= before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            HTTP_IN_FLIGHT.get() <= before,
            "the gauge leaked: {} > {before}",
            HTTP_IN_FLIGHT.get()
        );
        let rendered = scrape();
        assert!(
            rendered.contains(r#"method="GET",route="/slow",status="cancelled""#),
            "the cancelled request was not counted:\n{rendered}"
        );
    }

    /// The gauge must be visible on the first scrape after a restart, before
    /// any request arrived.
    #[test]
    fn init_registers_the_http_families_before_the_first_request() {
        init();
        let rendered = scrape();
        assert!(
            rendered.contains("# HELP lakefs_auth_http_requests_in_flight"),
            "the gauge is missing from:\n{rendered}"
        );
    }

    #[test]
    fn every_metric_carries_a_help_string() {
        LazyLock::force(&HTTP_REQUESTS);
        LazyLock::force(&HTTP_DURATION);
        LazyLock::force(&HTTP_IN_FLIGHT);
        for family in REGISTRY.gather() {
            assert!(!family.help().is_empty(), "{} has no help text", family.name());
        }
    }
}

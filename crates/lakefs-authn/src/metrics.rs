//! Metrics specific to lakefs-authn.
//!
//! They register against the shared registry in [`lakefs_auth_core::metrics`], so
//! the `/metrics` endpoint of this server returns these together with the HTTP
//! metrics that every route already reports.

use std::sync::LazyLock;

use lakefs_auth_core::metrics::register;
use prometheus::{IntCounterVec, Opts};

static BROWSER_LOGINS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "lakefs_authn_browser_logins_total",
            "Completed browser logins at the OpenID Connect callback, by outcome.",
        ),
        &["outcome"],
    )
    .expect("valid metric options");
    register(counter, "lakefs_authn_browser_logins_total")
});

static OIDC_DISCOVERY: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "lakefs_authn_oidc_discovery_total",
            "Attempts to fetch the identity provider metadata, by outcome.",
        ),
        &["outcome"],
    )
    .expect("valid metric options");
    register(counter, "lakefs_authn_oidc_discovery_total")
});

fn outcome(succeeded: bool) -> &'static str {
    if succeeded { "success" } else { "failure" }
}

/// Registers this server's metrics and the shared HTTP metrics now, with both
/// outcomes of each counter present at zero, so the first scrape after a
/// restart lists them all instead of only what has happened so far.
pub fn init() {
    lakefs_auth_core::metrics::init();
    for outcome in ["success", "failure"] {
        // Creates the child at zero when it does not exist yet.
        let _ = BROWSER_LOGINS.with_label_values(&[outcome]);
        let _ = OIDC_DISCOVERY.with_label_values(&[outcome]);
    }
}

/// One call per finished callback, whichever branch returned.
pub fn record_browser_login(succeeded: bool) {
    BROWSER_LOGINS.with_label_values(&[outcome(succeeded)]).inc();
}

/// One call per discovery attempt. A rising failure count means the identity
/// provider is unreachable, and logins stop working before anyone reports it.
pub fn record_discovery(succeeded: bool) {
    OIDC_DISCOVERY.with_label_values(&[outcome(succeeded)]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_lists_every_series_before_the_first_event() {
        init();
        let rendered = lakefs_auth_core::metrics::scrape();
        for series in [
            r#"lakefs_authn_browser_logins_total{outcome="success"}"#,
            r#"lakefs_authn_browser_logins_total{outcome="failure"}"#,
            r#"lakefs_authn_oidc_discovery_total{outcome="success"}"#,
            r#"lakefs_authn_oidc_discovery_total{outcome="failure"}"#,
            "# HELP lakefs_auth_http_requests_in_flight",
        ] {
            assert!(rendered.contains(series), "{series} is missing from:\n{rendered}");
        }
    }

    #[test]
    fn both_outcomes_are_counted_separately() {
        record_browser_login(true);
        record_browser_login(false);
        record_discovery(false);
        let rendered = lakefs_auth_core::metrics::scrape();
        assert!(
            rendered.contains(r#"lakefs_authn_browser_logins_total{outcome="success"}"#),
            "success series is missing from:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"lakefs_authn_browser_logins_total{outcome="failure"}"#),
            "failure series is missing from:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"lakefs_authn_oidc_discovery_total{outcome="failure"}"#),
            "discovery series is missing from:\n{rendered}"
        );
    }
}

//! Metrics specific to lakefs-authz.
//!
//! They register against the shared registry in [`lakefs_auth_core::metrics`], so
//! the `/metrics` endpoint of this server returns these together with the HTTP
//! metrics that every route already reports.

use std::time::Duration;

use std::sync::LazyLock;

use lakefs_auth_core::metrics::register;
use prometheus::{IntGaugeVec, Opts};
use sqlx::PgPool;

static DB_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let gauge = IntGaugeVec::new(
        Opts::new(
            "lakefs_authz_db_connections",
            "PostgreSQL pool connections, split into the ones handed out and the ones idle.",
        ),
        &["state"],
    )
    .expect("valid metric options");
    register(gauge, "lakefs_authz_db_connections")
});

/// Registers this server's metrics and the shared HTTP metrics now, with both
/// pool states present at zero, so the first scrape after a restart lists them
/// all. A state that already has a value keeps it.
pub fn init() {
    lakefs_auth_core::metrics::init();
    for state in ["in_use", "idle"] {
        // Creates the child at zero when it does not exist yet.
        let _ = DB_CONNECTIONS.with_label_values(&[state]);
    }
}

/// Publishes one pool sample. `size` counts every connection the pool holds and
/// `idle` counts the ones free right now, so the difference is what is in use.
pub fn record_pool(size: u32, idle: usize) {
    let in_use = i64::from(size) - i64::try_from(idle).unwrap_or(i64::MAX);
    DB_CONNECTIONS.with_label_values(&["in_use"]).set(in_use.max(0));
    DB_CONNECTIONS
        .with_label_values(&["idle"])
        .set(i64::try_from(idle).unwrap_or(i64::MAX));
}

/// Samples the pool forever. A pool pinned at its maximum with nothing idle is
/// the shape of a database that has become the bottleneck.
pub async fn sample_pool(pool: PgPool, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        record_pool(pool.size(), pool.num_idle());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_lists_every_family_before_the_first_sample() {
        init();
        let rendered = lakefs_auth_core::metrics::scrape();
        assert!(rendered.contains("# HELP lakefs_authz_db_connections"), "{rendered}");
        assert!(
            rendered.contains("# HELP lakefs_auth_http_requests_in_flight"),
            "{rendered}"
        );
    }

    #[test]
    fn in_use_is_the_difference_and_never_negative() {
        record_pool(10, 4);
        let rendered = lakefs_auth_core::metrics::scrape();
        assert!(
            rendered.contains(r#"lakefs_authz_db_connections{state="in_use"} 6"#),
            "in_use is wrong in:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"lakefs_authz_db_connections{state="idle"} 4"#),
            "idle is wrong in:\n{rendered}"
        );

        // A sample taken while the pool grows can report more idle than size.
        record_pool(0, 3);
        let rendered = lakefs_auth_core::metrics::scrape();
        assert!(
            rendered.contains(r#"lakefs_authz_db_connections{state="in_use"} 0"#),
            "in_use went negative in:\n{rendered}"
        );
    }
}

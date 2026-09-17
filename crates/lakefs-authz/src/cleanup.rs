//! Removal of expired claimed token ids.

use std::sync::Arc;
use std::time::Duration;

use crate::store::Store;

/// Removes claimed token ids whose expiry has passed, once per `interval`.
/// Without this the table only grows.
///
/// A zero interval switches the cleanup off. The task then stays pending
/// instead of returning, because it runs under a supervisor that restarts,
/// and logs an error for, every task that returns.
pub async fn cleanup_token_ids(store: Arc<dyn Store>, interval: Duration) {
    if interval.is_zero() {
        tracing::info!("token id cleanup is switched off");
        return std::future::pending().await;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // The first tick fires immediately.
    loop {
        ticker.tick().await;
        match store.delete_expired_token_ids(jiff::Timestamp::now()).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "expired token ids removed"),
            Err(error) => tracing::warn!(error = %error, "token id cleanup failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    /// A zero interval means off. The task must stay pending rather than
    /// return, because it runs under a supervisor that restarts a task that
    /// returns, and that would log an error every thirty seconds forever.
    #[tokio::test(start_paused = true)]
    async fn a_zero_interval_keeps_the_task_pending() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let outcome = tokio::time::timeout(Duration::from_secs(3600), cleanup_token_ids(store, Duration::ZERO)).await;
        assert!(outcome.is_err(), "the task returned although the cleanup is off");
    }

    #[tokio::test(start_paused = true)]
    async fn expired_token_ids_are_removed_on_each_tick() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let now = jiff::Timestamp::now();
        let later = now + jiff::SignedDuration::from_hours(1);
        store
            .claim_token_id("expired", now - jiff::SignedDuration::from_secs(1))
            .await
            .expect("claim");
        store.claim_token_id("live", later).await.expect("claim");

        let task = tokio::spawn(cleanup_token_ids(Arc::clone(&store), Duration::from_secs(60)));
        tokio::time::sleep(Duration::from_secs(61)).await;
        task.abort();

        assert!(
            store.claim_token_id("expired", later).await.is_ok(),
            "the expired id was removed and is free again"
        );
        assert!(
            store.claim_token_id("live", later).await.is_err(),
            "the live id stays claimed"
        );
    }
}

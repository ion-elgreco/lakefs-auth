//! Claimed token ids. lakeFS calls `POST /auth/tokenid/claim` to make a token
//! single use; a repeat claim must fail with 400.

use async_trait::async_trait;
use jiff::Timestamp;
use jiff_sqlx::ToSqlx as _;

use super::convert::map_unique;
use super::{PgStore, sql};
use crate::store::error::{StoreError, StoreResult};
use crate::store::traits::TokenIdStore;

#[async_trait]
impl TokenIdStore for PgStore {
    async fn claim_token_id(&self, token_id: &str, expires_at: Timestamp) -> StoreResult<()> {
        sqlx::query(sql::INSERT_TOKEN_ID)
            .bind(token_id)
            .bind(expires_at.to_sqlx())
            .execute(self.pool())
            .await
            .map_err(|error| map_unique(error, |_| StoreError::already_exists("token id", token_id)))?;
        Ok(())
    }

    async fn delete_expired_token_ids(&self, now: Timestamp) -> StoreResult<u64> {
        let done = sqlx::query(sql::DELETE_EXPIRED_TOKEN_IDS)
            .bind(now.to_sqlx())
            .execute(self.pool())
            .await
            .map_err(StoreError::backend)?;
        Ok(done.rows_affected())
    }
}

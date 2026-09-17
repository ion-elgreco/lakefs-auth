//! External principals. The routes return 501 in version one, but the store is
//! complete so that enabling them later needs no schema change.

use async_trait::async_trait;
use lakefs_auth_core::pagination::{PageOf, PageQuery};

use super::convert::{map_error, missing_from_constraint};
use super::{PgStore, execute_one, fetch_one, fetch_owned_page, sql};
use crate::store::error::{StoreError, StoreResult};
use crate::store::traits::ExternalPrincipalStore;
use crate::store::types::ExternalPrincipalRecord;

#[async_trait]
impl ExternalPrincipalStore for PgStore {
    async fn create_external_principal(&self, username: &str, principal_id: &str) -> StoreResult<()> {
        sqlx::query(sql::INSERT_EXTERNAL_PRINCIPAL)
            .bind(principal_id)
            .bind(username)
            .execute(self.pool())
            .await
            .map_err(|error| {
                map_error(
                    error,
                    |_| StoreError::already_exists("external principal", principal_id),
                    |constraint| missing_from_constraint(constraint, &[("user", username)]),
                )
            })?;
        Ok(())
    }

    async fn delete_external_principal(&self, username: &str, principal_id: &str) -> StoreResult<()> {
        let statement = sqlx::query(sql::DELETE_EXTERNAL_PRINCIPAL)
            .bind(principal_id)
            .bind(username);
        execute_one(statement, self.pool(), "external principal", principal_id).await
    }

    async fn get_external_principal(&self, principal_id: &str) -> StoreResult<ExternalPrincipalRecord> {
        let statement = sqlx::query_as(sql::SELECT_EXTERNAL_PRINCIPAL).bind(principal_id);
        fetch_one(statement, self.pool(), "external principal", principal_id).await
    }

    async fn list_user_external_principals(
        &self,
        username: &str,
        query: &PageQuery,
    ) -> StoreResult<PageOf<ExternalPrincipalRecord>> {
        let statement = sqlx::query_as(sql::LIST_USER_EXTERNAL_PRINCIPALS).bind(username);
        let key = |principal: &ExternalPrincipalRecord| principal.id.clone();
        fetch_owned_page(statement, self.pool(), query, key, self.user_exists(username)).await
    }
}

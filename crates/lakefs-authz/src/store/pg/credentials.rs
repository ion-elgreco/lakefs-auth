//! Credentials. The secret is stored encrypted and never leaves the store in clear text.

use async_trait::async_trait;
use jiff_sqlx::ToSqlx as _;
use lakefs_auth_core::pagination::{PageOf, PageQuery};

use super::convert::credential_error;
use super::{PgStore, execute_one, fetch_one, fetch_owned_page, sql};
use crate::store::error::StoreResult;
use crate::store::traits::CredentialStore;
use crate::store::types::{CredentialRecord, NewCredential};

#[async_trait]
impl CredentialStore for PgStore {
    async fn create_credential(&self, credential: NewCredential) -> StoreResult<CredentialRecord> {
        let row: CredentialRecord = sqlx::query_as(sql::INSERT_CREDENTIAL)
            .bind(&credential.access_key_id)
            .bind(&credential.username)
            .bind(&credential.secret_ciphertext)
            .bind(credential.creation_date.to_sqlx())
            .fetch_one(self.pool())
            .await
            .map_err(|error| credential_error(error, &credential))?;
        Ok(row)
    }

    async fn get_credential(&self, access_key_id: &str) -> StoreResult<CredentialRecord> {
        let statement = sqlx::query_as(sql::SELECT_CREDENTIAL).bind(access_key_id);
        fetch_one(statement, self.pool(), "credentials", access_key_id).await
    }

    async fn get_user_credential(&self, username: &str, access_key_id: &str) -> StoreResult<CredentialRecord> {
        let statement = sqlx::query_as(sql::SELECT_USER_CREDENTIAL)
            .bind(access_key_id)
            .bind(username);
        fetch_one(statement, self.pool(), "credentials", access_key_id).await
    }

    async fn delete_credential(&self, username: &str, access_key_id: &str) -> StoreResult<()> {
        let statement = sqlx::query(sql::DELETE_CREDENTIAL).bind(access_key_id).bind(username);
        execute_one(statement, self.pool(), "credentials", access_key_id).await
    }

    async fn list_user_credentials(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<CredentialRecord>> {
        let statement = sqlx::query_as(sql::LIST_USER_CREDENTIALS).bind(username);
        let key = |credential: &CredentialRecord| credential.access_key_id.clone();
        fetch_owned_page(statement, self.pool(), query, key, self.user_exists(username)).await
    }
}

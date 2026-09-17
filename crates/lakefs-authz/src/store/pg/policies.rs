//! Policies and their attachments to users and groups.

use async_trait::async_trait;
use jiff_sqlx::ToSqlx as _;
use lakefs_auth_core::pagination::{PageOf, PageQuery};
use sqlx::PgExecutor;
use sqlx::postgres::PgQueryResult;
use sqlx::types::Json;

use super::convert::{map_error, map_unique, missing_from_constraint};
use super::{PgStore, execute_one, fetch_one, fetch_owned_page, fetch_page, sql};
use crate::store::error::{StoreError, StoreResult};
use crate::store::traits::{AttachmentStore, PolicyStore};
use crate::store::types::{NewPolicy, PolicyRecord};

fn policy_key(policy: &PolicyRecord) -> String {
    policy.name.clone()
}

/// One user attachment row. The statement says `ON CONFLICT DO NOTHING`, so
/// the result tells whether a row was added. Shared by the API and the
/// bootstrap transaction.
pub(super) async fn insert_user_policy(
    executor: impl PgExecutor<'_>,
    username: &str,
    policy: &str,
) -> StoreResult<PgQueryResult> {
    sqlx::query(sql::INSERT_USER_POLICY)
        .bind(username)
        .bind(policy)
        .execute(executor)
        .await
        .map_err(|error| {
            map_error(
                error,
                |_| StoreError::already_exists("policy attachment", policy),
                |constraint| missing_from_constraint(constraint, &[("user", username), ("policy", policy)]),
            )
        })
}

/// One group attachment row, see [`insert_user_policy`].
pub(super) async fn insert_group_policy(
    executor: impl PgExecutor<'_>,
    group_id: &str,
    policy: &str,
) -> StoreResult<PgQueryResult> {
    sqlx::query(sql::INSERT_GROUP_POLICY)
        .bind(group_id)
        .bind(policy)
        .execute(executor)
        .await
        .map_err(|error| {
            map_error(
                error,
                |_| StoreError::already_exists("policy attachment", policy),
                |constraint| missing_from_constraint(constraint, &[("group", group_id), ("policy", policy)]),
            )
        })
}

#[async_trait]
impl PolicyStore for PgStore {
    async fn create_policy(&self, policy: NewPolicy) -> StoreResult<PolicyRecord> {
        let row: PolicyRecord = sqlx::query_as(sql::INSERT_POLICY)
            .bind(&policy.name)
            .bind(policy.creation_date.to_sqlx())
            .bind(Json(&policy.statement))
            .bind(policy.acl.as_deref())
            .fetch_one(self.pool())
            .await
            .map_err(|error| map_unique(error, |_| StoreError::already_exists("policy", &policy.name)))?;
        Ok(row)
    }

    async fn get_policy(&self, name: &str) -> StoreResult<PolicyRecord> {
        fetch_one(
            sqlx::query_as(sql::SELECT_POLICY).bind(name),
            self.pool(),
            "policy",
            name,
        )
        .await
    }

    async fn update_policy(&self, policy: NewPolicy) -> StoreResult<PolicyRecord> {
        let statement = sqlx::query_as(sql::UPDATE_POLICY)
            .bind(&policy.name)
            .bind(policy.creation_date.to_sqlx())
            .bind(Json(&policy.statement))
            .bind(policy.acl.as_deref());
        fetch_one(statement, self.pool(), "policy", &policy.name).await
    }

    async fn delete_policy(&self, name: &str) -> StoreResult<()> {
        execute_one(sqlx::query(sql::DELETE_POLICY).bind(name), self.pool(), "policy", name).await
    }

    async fn list_policies(&self, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>> {
        fetch_page(sqlx::query_as(sql::LIST_POLICIES), self.pool(), query, policy_key).await
    }
}

#[async_trait]
impl AttachmentStore for PgStore {
    async fn attach_policy_to_user(&self, username: &str, policy: &str) -> StoreResult<()> {
        insert_user_policy(self.pool(), username, policy).await.map(|_| ())
    }

    async fn detach_policy_from_user(&self, username: &str, policy: &str) -> StoreResult<()> {
        let statement = sqlx::query(sql::DELETE_USER_POLICY).bind(username).bind(policy);
        execute_one(statement, self.pool(), "policy attachment", policy).await
    }

    async fn list_user_policies(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>> {
        let statement = sqlx::query_as(sql::LIST_USER_POLICIES).bind(username);
        fetch_owned_page(statement, self.pool(), query, policy_key, self.user_exists(username)).await
    }

    /// The lakeFS authorization hot path: one statement, and the owner check
    /// only for an empty page.
    async fn list_effective_user_policies(
        &self,
        username: &str,
        query: &PageQuery,
    ) -> StoreResult<PageOf<PolicyRecord>> {
        let statement = sqlx::query_as(sql::LIST_EFFECTIVE_USER_POLICIES).bind(username);
        fetch_owned_page(statement, self.pool(), query, policy_key, self.user_exists(username)).await
    }

    async fn attach_policy_to_group(&self, group_id: &str, policy: &str) -> StoreResult<()> {
        insert_group_policy(self.pool(), group_id, policy).await.map(|_| ())
    }

    async fn detach_policy_from_group(&self, group_id: &str, policy: &str) -> StoreResult<()> {
        let statement = sqlx::query(sql::DELETE_GROUP_POLICY).bind(group_id).bind(policy);
        execute_one(statement, self.pool(), "policy attachment", policy).await
    }

    async fn list_group_policies(&self, group_id: &str, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>> {
        let statement = sqlx::query_as(sql::LIST_GROUP_POLICIES).bind(group_id);
        fetch_owned_page(statement, self.pool(), query, policy_key, self.group_exists(group_id)).await
    }
}

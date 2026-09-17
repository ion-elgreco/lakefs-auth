//! Users and group memberships.

use async_trait::async_trait;
use jiff_sqlx::ToSqlx as _;
use lakefs_auth_core::pagination::{PageOf, PageQuery};
use sqlx::PgExecutor;
use sqlx::postgres::PgQueryResult;

use super::convert::{map_error, map_unique, missing_from_constraint, user_conflict};
use super::groups::group_key;
use super::{PgStore, execute_one, fetch_one, fetch_optional, fetch_owned_page, fetch_page, sql};
use crate::store::error::{StoreError, StoreResult};
use crate::store::traits::{MembershipStore, UserStore};
use crate::store::types::{GroupRecord, NewUser, UserRecord};

pub(super) fn user_key(user: &UserRecord) -> String {
    user.username.clone()
}

/// One membership row. The statement says `ON CONFLICT DO NOTHING`, so the
/// result tells whether a row was added. Shared by the API and the bootstrap
/// transaction, so both name the missing row the same way.
pub(super) async fn insert_membership(
    executor: impl PgExecutor<'_>,
    group_id: &str,
    username: &str,
) -> StoreResult<PgQueryResult> {
    sqlx::query(sql::INSERT_MEMBERSHIP)
        .bind(group_id)
        .bind(username)
        .execute(executor)
        .await
        .map_err(|error| {
            map_error(
                error,
                |_| StoreError::already_exists("group membership", username),
                |constraint| missing_from_constraint(constraint, &[("user", username), ("group", group_id)]),
            )
        })
}

#[async_trait]
impl UserStore for PgStore {
    async fn create_user(&self, user: NewUser) -> StoreResult<UserRecord> {
        let row: UserRecord = sqlx::query_as(sql::INSERT_USER)
            .bind(&user.username)
            .bind(user.creation_date.to_sqlx())
            .bind(user.friendly_name.as_deref())
            .bind(user.email.as_deref())
            .bind(user.source.as_deref())
            .bind(user.external_id.as_deref())
            .bind(user.encrypted_password.as_deref())
            .fetch_one(self.pool())
            .await
            .map_err(|error| map_unique(error, |constraint| user_conflict(constraint, &user)))?;
        Ok(row)
    }

    async fn get_user(&self, username: &str) -> StoreResult<UserRecord> {
        fetch_one(
            sqlx::query_as(sql::SELECT_USER).bind(username),
            self.pool(),
            "user",
            username,
        )
        .await
    }

    async fn find_user_by_id(&self, user_id: i64) -> StoreResult<Option<UserRecord>> {
        fetch_optional(sqlx::query_as(sql::SELECT_USER_BY_ID).bind(user_id), self.pool()).await
    }

    async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<UserRecord>> {
        fetch_optional(sqlx::query_as(sql::SELECT_USER_BY_EMAIL).bind(email), self.pool()).await
    }

    async fn find_user_by_external_id(&self, external_id: &str) -> StoreResult<Option<UserRecord>> {
        fetch_optional(
            sqlx::query_as(sql::SELECT_USER_BY_EXTERNAL_ID).bind(external_id),
            self.pool(),
        )
        .await
    }

    async fn delete_user(&self, username: &str) -> StoreResult<()> {
        execute_one(
            sqlx::query(sql::DELETE_USER).bind(username),
            self.pool(),
            "user",
            username,
        )
        .await
    }

    async fn list_users(&self, query: &PageQuery) -> StoreResult<PageOf<UserRecord>> {
        fetch_page(sqlx::query_as(sql::LIST_USERS), self.pool(), query, user_key).await
    }

    async fn set_friendly_name(&self, username: &str, friendly_name: &str) -> StoreResult<()> {
        let statement = sqlx::query(sql::UPDATE_USER_FRIENDLY_NAME)
            .bind(username)
            .bind(friendly_name);
        execute_one(statement, self.pool(), "user", username).await
    }
}

#[async_trait]
impl MembershipStore for PgStore {
    async fn add_membership(&self, group_id: &str, username: &str) -> StoreResult<()> {
        insert_membership(self.pool(), group_id, username).await.map(|_| ())
    }

    async fn remove_membership(&self, group_id: &str, username: &str) -> StoreResult<()> {
        let statement = sqlx::query(sql::DELETE_MEMBERSHIP).bind(group_id).bind(username);
        execute_one(statement, self.pool(), "group membership", username).await
    }

    async fn list_group_members(&self, group_id: &str, query: &PageQuery) -> StoreResult<PageOf<UserRecord>> {
        let statement = sqlx::query_as(sql::LIST_GROUP_MEMBERS).bind(group_id);
        fetch_owned_page(statement, self.pool(), query, user_key, self.group_exists(group_id)).await
    }

    async fn list_user_groups(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<GroupRecord>> {
        let statement = sqlx::query_as(sql::LIST_USER_GROUPS).bind(username);
        fetch_owned_page(statement, self.pool(), query, group_key, self.user_exists(username)).await
    }
}

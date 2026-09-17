//! PostgreSQL store.

mod convert;
mod credentials;
mod external;
mod groups;
mod policies;
mod sql;
mod tokens;
mod users;

use anyhow::Context as _;
use async_trait::async_trait;
use jiff_sqlx::ToSqlx as _;
use lakefs_auth_core::pagination::{PageOf, PageQuery, escape_like_prefix};
use sqlx::postgres::{PgArguments, PgPool, PgPoolOptions, PgRow};
use sqlx::query::{Query, QueryAs};
use sqlx::types::Json;
use sqlx::{Executor as _, PgExecutor, Postgres};

use super::bootstrap::{BootstrapWriter, apply_plan};
use super::error::{StoreError, StoreResult};
use super::traits::AdminStore;
use super::types::{
    BootstrapPlan, BootstrapReport, CredentialRecord, NewCredential, NewGroup, NewPolicy, NewUser, UserRecord,
};

/// Migrations embedded at build time. No database is needed to compile.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(database_url: &str, max_connections: u32) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await
            .context("connect to PostgreSQL")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR.run(&self.pool).await.context("run migrations")?;
        Ok(())
    }

    /// The owner check of a per-user or per-group list: a missing user or
    /// group is a 404, not an empty page.
    async fn exists(&self, statement: &'static str, entity: &'static str, id: &str) -> StoreResult<()> {
        let found = sqlx::query(statement)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::backend)?;
        found.map(|_| ()).ok_or_else(|| StoreError::not_found(entity, id))
    }

    pub(crate) async fn user_exists(&self, username: &str) -> StoreResult<()> {
        self.exists(sql::SELECT_USER_EXISTS, "user", username).await
    }

    pub(crate) async fn group_exists(&self, group_id: &str) -> StoreResult<()> {
        self.exists(sql::SELECT_GROUP_EXISTS, "group", group_id).await
    }
}

/// `prefix%` with `\`, `%`, and `_` escaped for `LIKE ... ESCAPE '\'`.
fn like_pattern(query: &PageQuery) -> String {
    format!("{}%", escape_like_prefix(&query.prefix))
}

/// Runs a point lookup. A missing row is `NotFound` for `entity`, never a
/// backend error, so every get answers 404 the same way.
pub(crate) async fn fetch_one<'q, T>(
    statement: QueryAs<'q, Postgres, T, PgArguments>,
    executor: impl PgExecutor<'_>,
    entity: &'static str,
    id: &str,
) -> StoreResult<T>
where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
{
    statement
        .fetch_optional(executor)
        .await
        .map_err(StoreError::backend)?
        .ok_or_else(|| StoreError::not_found(entity, id))
}

/// Runs a lookup that may match nothing. A missing row is `None`, so the
/// list endpoints can answer an empty page for a lookup that found nothing.
pub(crate) async fn fetch_optional<'q, T>(
    statement: QueryAs<'q, Postgres, T, PgArguments>,
    executor: impl PgExecutor<'_>,
) -> StoreResult<Option<T>>
where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
{
    statement.fetch_optional(executor).await.map_err(StoreError::backend)
}

/// Runs a delete or update that addresses one row. No row affected is
/// `NotFound` for `entity`, so a delete of a row that never existed is a 404
/// and not a 204.
pub(crate) async fn execute_one(
    statement: Query<'_, Postgres, PgArguments>,
    executor: impl PgExecutor<'_>,
    entity: &'static str,
    id: &str,
) -> StoreResult<()> {
    let done = statement.execute(executor).await.map_err(StoreError::backend)?;
    if done.rows_affected() == 0 {
        return Err(StoreError::not_found(entity, id));
    }
    Ok(())
}

/// Runs a list statement whose last three placeholders are the page: the
/// `LIKE` pattern, the exclusive `after` key, and `fetch_limit()`. The caller
/// binds the placeholders before those, such as the owner. The extra row of
/// the overfetch becomes the `next_offset` cursor.
pub(crate) async fn fetch_page<'q, T>(
    statement: QueryAs<'q, Postgres, T, PgArguments>,
    pool: &PgPool,
    query: &'q PageQuery,
    key: impl Fn(&T) -> String,
) -> StoreResult<PageOf<T>>
where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
{
    let rows = statement
        .bind(like_pattern(query))
        .bind(query.after.as_str())
        .bind(query.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(StoreError::backend)?;
    Ok(PageOf::from_overfetch(rows, query.limit, key))
}

/// [`fetch_page`] for a list that belongs to a user or a group. A page with
/// rows proves the owner exists, so `owner` only runs for an empty page: a
/// missing owner is a 404, and the common case costs one round trip.
pub(crate) async fn fetch_owned_page<'q, T>(
    statement: QueryAs<'q, Postgres, T, PgArguments>,
    pool: &PgPool,
    query: &'q PageQuery,
    key: impl Fn(&T) -> String,
    owner: impl Future<Output = StoreResult<()>>,
) -> StoreResult<PageOf<T>>
where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
{
    let page = fetch_page(statement, pool, query, key).await?;
    if page.items.is_empty() {
        owner.await?;
    }
    Ok(page)
}

#[async_trait]
impl AdminStore for PgStore {
    async fn ping(&self) -> StoreResult<()> {
        self.pool
            .execute(sql::PING)
            .await
            .map(|_| ())
            .map_err(StoreError::backend)
    }

    async fn apply_bootstrap(&self, plan: &BootstrapPlan) -> StoreResult<BootstrapReport> {
        let mut tx = self.pool.begin().await.map_err(StoreError::backend)?;
        let report = apply_plan(&mut tx, plan).await?;
        tx.commit().await.map_err(StoreError::backend)?;
        Ok(report)
    }
}

/// Every insert runs `ON CONFLICT DO NOTHING`, so no row affected means the
/// row was already there.
#[async_trait]
impl BootstrapWriter for sqlx::Transaction<'static, Postgres> {
    async fn insert_policy_if_missing(&mut self, policy: &NewPolicy) -> StoreResult<bool> {
        let done = sqlx::query(sql::BOOTSTRAP_INSERT_POLICY)
            .bind(&policy.name)
            .bind(policy.creation_date.to_sqlx())
            .bind(Json(&policy.statement))
            .bind(policy.acl.as_deref())
            .execute(&mut **self)
            .await
            .map_err(StoreError::backend)?;
        Ok(done.rows_affected() > 0)
    }

    async fn insert_group_if_missing(&mut self, group: &NewGroup) -> StoreResult<bool> {
        let done = sqlx::query(sql::BOOTSTRAP_INSERT_GROUP)
            .bind(&group.id)
            .bind(group.description.as_deref())
            .bind(group.creation_date.to_sqlx())
            .execute(&mut **self)
            .await
            .map_err(StoreError::backend)?;
        Ok(done.rows_affected() > 0)
    }

    async fn insert_user_if_missing(&mut self, user: &NewUser) -> StoreResult<Option<UserRecord>> {
        let done = sqlx::query(sql::BOOTSTRAP_INSERT_USER)
            .bind(&user.username)
            .bind(user.creation_date.to_sqlx())
            .bind(user.friendly_name.as_deref())
            .bind(user.email.as_deref())
            .bind(user.source.as_deref())
            .bind(user.external_id.as_deref())
            .bind(user.encrypted_password.as_deref())
            .execute(&mut **self)
            .await
            .map_err(|error| convert::map_unique(error, |constraint| convert::user_conflict(constraint, user)))?;
        if done.rows_affected() > 0 {
            return Ok(None);
        }
        fetch_one(
            sqlx::query_as(sql::SELECT_USER).bind(&user.username),
            &mut **self,
            "user",
            &user.username,
        )
        .await
        .map(Some)
    }

    async fn insert_membership_if_missing(&mut self, group_id: &str, username: &str) -> StoreResult<bool> {
        let done = users::insert_membership(&mut **self, group_id, username).await?;
        Ok(done.rows_affected() > 0)
    }

    async fn insert_user_policy_if_missing(&mut self, username: &str, policy: &str) -> StoreResult<bool> {
        let done = policies::insert_user_policy(&mut **self, username, policy).await?;
        Ok(done.rows_affected() > 0)
    }

    async fn insert_group_policy_if_missing(&mut self, group_id: &str, policy: &str) -> StoreResult<bool> {
        let done = policies::insert_group_policy(&mut **self, group_id, policy).await?;
        Ok(done.rows_affected() > 0)
    }

    async fn insert_credential_if_missing(
        &mut self,
        credential: &NewCredential,
    ) -> StoreResult<Option<CredentialRecord>> {
        let done = sqlx::query(sql::BOOTSTRAP_INSERT_CREDENTIAL)
            .bind(&credential.access_key_id)
            .bind(&credential.username)
            .bind(&credential.secret_ciphertext)
            .bind(credential.creation_date.to_sqlx())
            .execute(&mut **self)
            .await
            .map_err(|error| convert::credential_error(error, credential))?;
        if done.rows_affected() > 0 {
            return Ok(None);
        }
        fetch_one(
            sqlx::query_as(sql::SELECT_CREDENTIAL).bind(&credential.access_key_id),
            &mut **self,
            "credentials",
            &credential.access_key_id,
        )
        .await
        .map(Some)
    }
}

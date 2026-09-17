//! Groups.

use async_trait::async_trait;
use jiff_sqlx::ToSqlx as _;
use lakefs_auth_core::pagination::{PageOf, PageQuery};

use super::convert::map_unique;
use super::{PgStore, execute_one, fetch_one, fetch_page, sql};
use crate::store::error::{StoreError, StoreResult};
use crate::store::traits::GroupStore;
use crate::store::types::{GroupRecord, NewGroup};

pub(super) fn group_key(group: &GroupRecord) -> String {
    group.id.clone()
}

#[async_trait]
impl GroupStore for PgStore {
    async fn create_group(&self, group: NewGroup) -> StoreResult<GroupRecord> {
        let row: GroupRecord = sqlx::query_as(sql::INSERT_GROUP)
            .bind(&group.id)
            .bind(group.description.as_deref())
            .bind(group.creation_date.to_sqlx())
            .fetch_one(self.pool())
            .await
            .map_err(|error| map_unique(error, |_| StoreError::already_exists("group", &group.id)))?;
        Ok(row)
    }

    async fn get_group(&self, group_id: &str) -> StoreResult<GroupRecord> {
        fetch_one(
            sqlx::query_as(sql::SELECT_GROUP).bind(group_id),
            self.pool(),
            "group",
            group_id,
        )
        .await
    }

    async fn delete_group(&self, group_id: &str) -> StoreResult<()> {
        execute_one(
            sqlx::query(sql::DELETE_GROUP).bind(group_id),
            self.pool(),
            "group",
            group_id,
        )
        .await
    }

    async fn list_groups(&self, query: &PageQuery) -> StoreResult<PageOf<GroupRecord>> {
        fetch_page(sqlx::query_as(sql::LIST_GROUPS), self.pool(), query, group_key).await
    }
}

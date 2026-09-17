//! The store conformance suite. It always runs against `MemStore`; with the
//! `pg-tests` feature it also runs against PostgreSQL.

use std::sync::Arc;

use lakefs_authz::store::{MemStore, Store, testsuite};

fn mem() -> Arc<dyn Store> {
    Arc::new(MemStore::new())
}

macro_rules! mem_case {
    ($name:ident, $case:path) => {
        #[tokio::test]
        async fn $name() {
            let store = mem();
            $case(store.as_ref()).await;
        }
    };
}

mem_case!(mem_user_round_trip, testsuite::user_round_trip);
mem_case!(mem_group_and_policy_round_trip, testsuite::group_and_policy_round_trip);
mem_case!(mem_duplicates_are_rejected, testsuite::duplicates_are_rejected);
mem_case!(mem_deleting_a_user_cascades, testsuite::deleting_a_user_cascades);
mem_case!(mem_deleting_a_group_cascades, testsuite::deleting_a_group_cascades);
mem_case!(mem_deleting_a_policy_cascades, testsuite::deleting_a_policy_cascades);
mem_case!(mem_keys_sort_bytewise, testsuite::keys_sort_bytewise);
mem_case!(
    mem_prefixes_escape_like_wildcards,
    testsuite::prefixes_escape_like_wildcards
);
mem_case!(
    mem_pagination_is_keyset_and_exclusive,
    testsuite::pagination_is_keyset_and_exclusive
);
mem_case!(
    mem_effective_policies_are_a_union_without_duplicates,
    testsuite::effective_policies_are_a_union_without_duplicates
);
mem_case!(mem_memberships_and_attachments, testsuite::memberships_and_attachments);
mem_case!(
    mem_sub_resources_require_the_parent,
    testsuite::sub_resources_require_the_parent
);
mem_case!(mem_credentials_round_trip, testsuite::credentials_round_trip);
mem_case!(
    mem_external_principals_round_trip,
    testsuite::external_principals_round_trip
);
mem_case!(mem_token_ids_are_claimed_once, testsuite::token_ids_are_claimed_once);
mem_case!(mem_bootstrap_is_idempotent, testsuite::bootstrap_is_idempotent);
mem_case!(
    mem_bootstrap_refuses_a_user_that_belongs_to_another_identity,
    testsuite::bootstrap_refuses_a_user_that_belongs_to_another_identity
);
mem_case!(
    mem_bootstrap_refuses_a_credential_that_belongs_to_another_user,
    testsuite::bootstrap_refuses_a_credential_that_belongs_to_another_user
);
mem_case!(
    mem_bootstrap_reports_a_collision_on_another_unique_column,
    testsuite::bootstrap_reports_a_collision_on_another_unique_column
);
mem_case!(
    mem_groups_and_policies_page_like_users,
    testsuite::groups_and_policies_page_like_users
);
mem_case!(
    mem_missing_entities_are_not_found,
    testsuite::missing_entities_are_not_found
);

#[tokio::test]
async fn mem_full_suite() {
    let store = mem();
    testsuite::run_all(store.as_ref()).await;
}

#[cfg(feature = "pg-tests")]
mod postgres {
    use lakefs_authz::store::{PgStore, testsuite};
    use testcontainers::ImageExt as _;
    use testcontainers::runners::AsyncRunner as _;
    use testcontainers_modules::postgres::Postgres;

    /// Runs the whole suite in one database. Cases use disjoint key prefixes, so
    /// one container is enough.
    #[tokio::test]
    async fn postgres_conformance() {
        let _container;
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.is_empty() => url,
            _ => {
                let container = Postgres::default()
                    .with_tag("17-alpine")
                    .start()
                    .await
                    .expect("start postgres:17-alpine");
                let port = container.get_host_port_ipv4(5432).await.expect("mapped postgres port");
                let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
                _container = container;
                url
            }
        };

        let store = PgStore::connect(&url, 5).await.expect("connect");
        store.run_migrations().await.expect("migrate");
        // The suite creates rows under fixed keys, so a database that ran it
        // before must be emptied first, or every create would answer 409.
        sqlx::query("TRUNCATE users, groups, policies, claimed_token_ids CASCADE")
            .execute(store.pool())
            .await
            .expect("empty the tables");
        testsuite::run_all(&store).await;
        // Running it twice in one process is the "second run" an operator sees.
        sqlx::query("TRUNCATE users, groups, policies, claimed_token_ids CASCADE")
            .execute(store.pool())
            .await
            .expect("empty the tables again");
        testsuite::run_all(&store).await;
    }
}

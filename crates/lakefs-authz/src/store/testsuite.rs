//! Conformance suite shared by every store implementation.
//!
//! Each case works under its own key prefix, so the whole suite can run against
//! one database without the cases interfering. That also exercises prefix
//! filtering on every list.

use jiff::{SignedDuration, Timestamp};
use lakefs_auth_core::model::{Effect, Statement};
use lakefs_auth_core::pagination::{PageOf, PageQuery};

use super::error::StoreError;
use super::traits::Store;
use super::types::{
    BootstrapPlan, CredentialRecord, GroupRecord, NewCredential, NewGroup, NewPolicy, NewUser, PolicyRecord, UserRecord,
};

fn statement() -> Statement {
    Statement {
        effect: Effect::Allow,
        resource: "*".to_owned(),
        action: vec!["fs:*".to_owned()],
        condition: None,
    }
}

fn new_policy(name: &str) -> NewPolicy {
    NewPolicy {
        name: name.to_owned(),
        creation_date: Timestamp::now(),
        statement: vec![statement()],
        acl: None,
    }
}

fn new_credential(access_key_id: &str, username: &str) -> NewCredential {
    NewCredential {
        access_key_id: access_key_id.to_owned(),
        username: username.to_owned(),
        secret_ciphertext: b"ciphertext".to_vec(),
        creation_date: Timestamp::now(),
    }
}

fn page(prefix: &str, after: &str, limit: i64) -> PageQuery {
    PageQuery {
        prefix: prefix.to_owned(),
        after: after.to_owned(),
        limit,
    }
}

/// The sort keys of a page, for assertions on order and content.
fn keys<T>(page: &PageOf<T>, key: impl Fn(&T) -> &str) -> Vec<&str> {
    page.items.iter().map(key).collect()
}

fn usernames(page: &PageOf<UserRecord>) -> Vec<&str> {
    keys(page, |user| &user.username)
}

fn group_ids(page: &PageOf<GroupRecord>) -> Vec<&str> {
    keys(page, |group| &group.id)
}

fn policy_names(page: &PageOf<PolicyRecord>) -> Vec<&str> {
    keys(page, |policy| &policy.name)
}

fn access_key_ids(page: &PageOf<CredentialRecord>) -> Vec<&str> {
    keys(page, |credential| &credential.access_key_id)
}

/// Create, read, update, delete, plus the three lookups `GET /auth/users` needs.
pub async fn user_round_trip(store: &dyn Store) {
    let mut user = NewUser::named("rt-alice");
    user.email = Some("rt-alice@example.com".to_owned());
    user.external_id = Some("rt-sub-1".to_owned());
    user.friendly_name = Some("Alice".to_owned());
    user.source = Some("internal".to_owned());
    user.encrypted_password = Some(b"pw".to_vec());

    let created = store.create_user(user).await.expect("create user");
    assert!(created.user_id > 0, "user_id must be assigned");
    assert_eq!(created.username, "rt-alice");
    assert_eq!(created.encrypted_password.as_deref(), Some(b"pw".as_slice()));

    let loaded = store.get_user("rt-alice").await.expect("get user");
    assert_eq!(loaded, created);

    let by_id = store.find_user_by_id(created.user_id).await.expect("find by id");
    assert_eq!(by_id.as_ref(), Some(&created));
    let by_email = store
        .find_user_by_email("rt-alice@example.com")
        .await
        .expect("find by email");
    assert_eq!(by_email.as_ref(), Some(&created));
    let by_external = store
        .find_user_by_external_id("rt-sub-1")
        .await
        .expect("find by external id");
    assert_eq!(by_external.as_ref(), Some(&created));

    assert_eq!(store.find_user_by_id(-1).await.expect("miss by id"), None);
    assert_eq!(store.find_user_by_email("nobody").await.expect("miss email"), None);
    assert_eq!(
        store.find_user_by_external_id("nobody").await.expect("miss external"),
        None
    );

    store
        .set_friendly_name("rt-alice", "Alice Renamed")
        .await
        .expect("set friendly name");
    let renamed = store.get_user("rt-alice").await.expect("get renamed");
    assert_eq!(renamed.friendly_name.as_deref(), Some("Alice Renamed"));

    store.delete_user("rt-alice").await.expect("delete user");
    let error = store.get_user("rt-alice").await.expect_err("user is gone");
    assert!(error.is_not_found(), "{error}");
    assert!(store.delete_user("rt-alice").await.is_err(), "second delete is 404");
}

/// Groups and policies round trip, including the policy update path.
pub async fn group_and_policy_round_trip(store: &dyn Store) {
    let mut group = NewGroup::named("gp-Data");
    group.description = Some("data team".to_owned());
    let created = store.create_group(group).await.expect("create group");
    assert_eq!(created.id, "gp-Data");
    assert_eq!(store.get_group("gp-Data").await.expect("get group"), created);

    let policy = store.create_policy(new_policy("gp-Policy")).await.expect("create");
    assert_eq!(policy.statement, vec![statement()]);

    let mut updated = new_policy("gp-Policy");
    updated.statement = vec![Statement {
        effect: Effect::Deny,
        resource: "*".to_owned(),
        action: vec!["auth:*".to_owned()],
        condition: None,
    }];
    updated.acl = Some("read".to_owned());
    let stored = store.update_policy(updated).await.expect("update policy");
    assert_eq!(stored.statement[0].effect, Effect::Deny);
    assert_eq!(stored.acl.as_deref(), Some("read"));
    assert_eq!(store.get_policy("gp-Policy").await.expect("re-read"), stored);

    let missing = store
        .update_policy(new_policy("gp-Unknown"))
        .await
        .expect_err("update of a missing policy is 404");
    assert!(missing.is_not_found(), "{missing}");

    store.delete_group("gp-Data").await.expect("delete group");
    store.delete_policy("gp-Policy").await.expect("delete policy");
    assert!(store.get_group("gp-Data").await.is_err());
    assert!(store.get_policy("gp-Policy").await.is_err());
}

/// Every unique key rejects a second insert.
pub async fn duplicates_are_rejected(store: &dyn Store) {
    let mut user = NewUser::named("dup-user");
    user.email = Some("dup@example.com".to_owned());
    user.external_id = Some("dup-sub".to_owned());
    store.create_user(user.clone()).await.expect("first user");

    let same_name = store.create_user(user.clone()).await.expect_err("same username");
    assert!(same_name.is_already_exists(), "{same_name}");

    let mut same_email = NewUser::named("dup-user-2");
    same_email.email = Some("dup@example.com".to_owned());
    let error = store.create_user(same_email).await.expect_err("same email");
    assert!(error.is_already_exists(), "{error}");
    assert!(
        error.to_string().contains("email") && error.to_string().contains("dup@example.com"),
        "the error must name the colliding email: {error}"
    );

    let mut same_external = NewUser::named("dup-user-3");
    same_external.external_id = Some("dup-sub".to_owned());
    let error = store.create_user(same_external).await.expect_err("same external id");
    assert!(error.is_already_exists(), "{error}");
    assert!(
        error.to_string().contains("external id") && error.to_string().contains("dup-sub"),
        "the error must name the colliding external id: {error}"
    );

    store
        .create_group(NewGroup::named("dup-group"))
        .await
        .expect("first group");
    let error = store
        .create_group(NewGroup::named("dup-group"))
        .await
        .expect_err("same group");
    assert!(error.is_already_exists(), "{error}");

    store
        .create_policy(new_policy("dup-policy"))
        .await
        .expect("first policy");
    let error = store
        .create_policy(new_policy("dup-policy"))
        .await
        .expect_err("same policy");
    assert!(error.is_already_exists(), "{error}");
}

/// Deleting a user removes memberships, attachments, credentials, and principals.
pub async fn deleting_a_user_cascades(store: &dyn Store) {
    store.create_user(NewUser::named("cu-user")).await.expect("user");
    store.create_group(NewGroup::named("cu-group")).await.expect("group");
    store.create_policy(new_policy("cu-policy")).await.expect("policy");
    store.add_membership("cu-group", "cu-user").await.expect("membership");
    store
        .attach_policy_to_user("cu-user", "cu-policy")
        .await
        .expect("attachment");
    store
        .create_credential(new_credential("cu-key", "cu-user"))
        .await
        .expect("credential");
    store
        .create_external_principal("cu-user", "cu-principal")
        .await
        .expect("principal");

    store.delete_user("cu-user").await.expect("delete user");

    let members = store
        .list_group_members("cu-group", &page("cu-", "", 10))
        .await
        .expect("members");
    assert!(members.items.is_empty(), "membership must be gone");
    assert!(store.get_credential("cu-key").await.is_err(), "credential must be gone");
    assert!(
        store.get_external_principal("cu-principal").await.is_err(),
        "principal must be gone"
    );
    // The group and the policy themselves survive.
    store.get_group("cu-group").await.expect("group survives");
    store.get_policy("cu-policy").await.expect("policy survives");
}

/// Deleting a group removes its memberships and attachments but keeps the users.
pub async fn deleting_a_group_cascades(store: &dyn Store) {
    store.create_user(NewUser::named("cg-user")).await.expect("user");
    store.create_group(NewGroup::named("cg-group")).await.expect("group");
    store.create_policy(new_policy("cg-policy")).await.expect("policy");
    store.add_membership("cg-group", "cg-user").await.expect("membership");
    store
        .attach_policy_to_group("cg-group", "cg-policy")
        .await
        .expect("attachment");

    store.delete_group("cg-group").await.expect("delete group");

    store.get_user("cg-user").await.expect("user survives");
    let groups = store
        .list_user_groups("cg-user", &page("cg-", "", 10))
        .await
        .expect("groups");
    assert!(groups.items.is_empty(), "membership must be gone");
    let effective = store
        .list_effective_user_policies("cg-user", &page("cg-", "", 10))
        .await
        .expect("effective");
    assert!(effective.items.is_empty(), "group attachment must be gone");
}

/// Deleting a policy removes both attachment kinds.
pub async fn deleting_a_policy_cascades(store: &dyn Store) {
    store.create_user(NewUser::named("cp-user")).await.expect("user");
    store.create_group(NewGroup::named("cp-group")).await.expect("group");
    store.create_policy(new_policy("cp-policy")).await.expect("policy");
    store.add_membership("cp-group", "cp-user").await.expect("membership");
    store
        .attach_policy_to_user("cp-user", "cp-policy")
        .await
        .expect("user attachment");
    store
        .attach_policy_to_group("cp-group", "cp-policy")
        .await
        .expect("group attachment");

    store.delete_policy("cp-policy").await.expect("delete policy");

    let direct = store
        .list_user_policies("cp-user", &page("cp-", "", 10))
        .await
        .expect("direct");
    assert!(direct.items.is_empty());
    let group_policies = store
        .list_group_policies("cp-group", &page("cp-", "", 10))
        .await
        .expect("group policies");
    assert!(group_policies.items.is_empty());
}

/// `COLLATE "C"` means uppercase, underscore, and lowercase sort by byte value.
pub async fn keys_sort_bytewise(store: &dyn Store) {
    for name in ["bo-a", "bo-Z", "bo-_", "bo-A"] {
        store.create_user(NewUser::named(name)).await.expect("user");
        store.create_group(NewGroup::named(name)).await.expect("group");
        store.create_policy(new_policy(name)).await.expect("policy");
    }
    let listed = store.list_users(&page("bo-", "", 10)).await.expect("list users");
    assert_eq!(usernames(&listed), vec!["bo-A", "bo-Z", "bo-_", "bo-a"]);
    let listed = store.list_groups(&page("bo-", "", 10)).await.expect("list groups");
    assert_eq!(group_ids(&listed), vec!["bo-A", "bo-Z", "bo-_", "bo-a"]);
    let listed = store.list_policies(&page("bo-", "", 10)).await.expect("list policies");
    assert_eq!(policy_names(&listed), vec!["bo-A", "bo-Z", "bo-_", "bo-a"]);
}

/// `_` and `%` in a prefix are literal, not LIKE wildcards, on every list.
pub async fn prefixes_escape_like_wildcards(store: &dyn Store) {
    for name in ["pe_a", "pe_b", "peXa", "pe%c", "peYc"] {
        store.create_user(NewUser::named(name)).await.expect("user");
        store.create_group(NewGroup::named(name)).await.expect("group");
        store.create_policy(new_policy(name)).await.expect("policy");
    }
    let underscore = store.list_users(&page("pe_", "", 10)).await.expect("underscore");
    assert_eq!(usernames(&underscore), vec!["pe_a", "pe_b"]);
    let percent = store.list_users(&page("pe%", "", 10)).await.expect("percent");
    assert_eq!(usernames(&percent), vec!["pe%c"]);

    let underscore = store.list_groups(&page("pe_", "", 10)).await.expect("group underscore");
    assert_eq!(group_ids(&underscore), vec!["pe_a", "pe_b"]);
    let percent = store.list_groups(&page("pe%", "", 10)).await.expect("group percent");
    assert_eq!(group_ids(&percent), vec!["pe%c"]);

    let underscore = store
        .list_policies(&page("pe_", "", 10))
        .await
        .expect("policy underscore");
    assert_eq!(policy_names(&underscore), vec!["pe_a", "pe_b"]);
    let percent = store.list_policies(&page("pe%", "", 10)).await.expect("policy percent");
    assert_eq!(policy_names(&percent), vec!["pe%c"]);
}

/// Groups and policies page with the same keyset rules as users.
pub async fn groups_and_policies_page_like_users(store: &dyn Store) {
    for name in ["pq-1", "pq-2", "pq-3"] {
        store.create_group(NewGroup::named(name)).await.expect("group");
        store.create_policy(new_policy(name)).await.expect("policy");
    }
    let first = store.list_groups(&page("pq-", "", 2)).await.expect("first groups");
    assert_eq!(group_ids(&first), vec!["pq-1", "pq-2"]);
    assert_eq!(first.next_offset.as_deref(), Some("pq-2"));
    let second = store.list_groups(&page("pq-", "pq-2", 2)).await.expect("second groups");
    assert_eq!(group_ids(&second), vec!["pq-3"]);
    assert_eq!(second.next_offset, None);

    let first = store.list_policies(&page("pq-", "", 2)).await.expect("first policies");
    assert_eq!(policy_names(&first), vec!["pq-1", "pq-2"]);
    assert_eq!(first.next_offset.as_deref(), Some("pq-2"));
    let second = store
        .list_policies(&page("pq-", "pq-2", 2))
        .await
        .expect("second policies");
    assert_eq!(policy_names(&second), vec!["pq-3"]);
    assert_eq!(second.next_offset, None);
}

/// `after` skips the row with that exact key, and the page size boundary is exact.
pub async fn pagination_is_keyset_and_exclusive(store: &dyn Store) {
    for name in ["pg-1", "pg-2", "pg-3", "pg-4"] {
        store.create_user(NewUser::named(name)).await.expect("user");
    }

    let exact = store.list_users(&page("pg-", "", 4)).await.expect("exact limit");
    assert_eq!(usernames(&exact), vec!["pg-1", "pg-2", "pg-3", "pg-4"]);
    assert_eq!(exact.next_offset, None, "a full page is still the last page");
    assert_eq!(exact.into_response().pagination.next_offset, "");

    let first = store.list_users(&page("pg-", "", 2)).await.expect("first page");
    assert_eq!(usernames(&first), vec!["pg-1", "pg-2"]);
    assert_eq!(first.next_offset.as_deref(), Some("pg-2"));

    let second = store.list_users(&page("pg-", "pg-2", 2)).await.expect("second page");
    assert_eq!(usernames(&second), vec!["pg-3", "pg-4"]);
    assert_eq!(second.next_offset, None);

    let past_end = store.list_users(&page("pg-", "pg-4", 2)).await.expect("past the end");
    assert!(past_end.items.is_empty());
    assert_eq!(past_end.next_offset, None);
}

/// The effective set is the union of direct and group policies, each once.
pub async fn effective_policies_are_a_union_without_duplicates(store: &dyn Store) {
    store.create_user(NewUser::named("ef-user")).await.expect("user");
    for name in ["ef-p1", "ef-p2", "ef-p3", "ef-p4"] {
        store.create_policy(new_policy(name)).await.expect("policy");
    }
    for id in ["ef-g1", "ef-g2"] {
        store.create_group(NewGroup::named(id)).await.expect("group");
        store.add_membership(id, "ef-user").await.expect("membership");
    }
    store.attach_policy_to_user("ef-user", "ef-p1").await.expect("direct");
    store.attach_policy_to_group("ef-g1", "ef-p1").await.expect("g1 p1");
    store.attach_policy_to_group("ef-g1", "ef-p2").await.expect("g1 p2");
    store.attach_policy_to_group("ef-g2", "ef-p2").await.expect("g2 p2");
    store.attach_policy_to_group("ef-g2", "ef-p3").await.expect("g2 p3");

    let direct = store
        .list_user_policies("ef-user", &page("ef-", "", 100))
        .await
        .expect("direct");
    assert_eq!(policy_names(&direct), vec!["ef-p1"]);

    let effective = store
        .list_effective_user_policies("ef-user", &page("ef-", "", 100))
        .await
        .expect("effective");
    assert_eq!(policy_names(&effective), vec!["ef-p1", "ef-p2", "ef-p3"]);
    assert_eq!(effective.next_offset, None);

    // The same walk lakeFS performs: keep paging while next_offset is not empty.
    let mut seen = Vec::new();
    let mut after = String::new();
    loop {
        let chunk = store
            .list_effective_user_policies("ef-user", &page("ef-", &after, 2))
            .await
            .expect("page");
        seen.extend(policy_names(&chunk).into_iter().map(str::to_owned));
        let response = chunk.into_response();
        if response.pagination.next_offset.is_empty() {
            break;
        }
        after = response.pagination.next_offset;
    }
    assert_eq!(seen, vec!["ef-p1", "ef-p2", "ef-p3"]);
}

/// Memberships and attachments are idempotent and reject missing references.
pub async fn memberships_and_attachments(store: &dyn Store) {
    store.create_user(NewUser::named("ma-user")).await.expect("user");
    store.create_group(NewGroup::named("ma-group")).await.expect("group");
    store.create_policy(new_policy("ma-policy")).await.expect("policy");

    store.add_membership("ma-group", "ma-user").await.expect("first add");
    store.add_membership("ma-group", "ma-user").await.expect("repeat add");
    let members = store
        .list_group_members("ma-group", &page("ma-", "", 10))
        .await
        .expect("members");
    assert_eq!(usernames(&members), vec!["ma-user"]);
    let groups = store
        .list_user_groups("ma-user", &page("ma-", "", 10))
        .await
        .expect("groups");
    assert_eq!(group_ids(&groups), vec!["ma-group"]);

    store
        .attach_policy_to_user("ma-user", "ma-policy")
        .await
        .expect("first attach");
    store
        .attach_policy_to_user("ma-user", "ma-policy")
        .await
        .expect("repeat attach");
    let attached = store
        .list_user_policies("ma-user", &page("ma-", "", 10))
        .await
        .expect("attached");
    assert_eq!(policy_names(&attached), vec!["ma-policy"]);

    let missing_user = store
        .add_membership("ma-group", "ma-nobody")
        .await
        .expect_err("missing user");
    assert!(missing_user.is_not_found(), "{missing_user}");
    let missing_group = store
        .add_membership("ma-nogroup", "ma-user")
        .await
        .expect_err("missing group");
    assert!(missing_group.is_not_found(), "{missing_group}");
    let missing_policy = store
        .attach_policy_to_user("ma-user", "ma-nopolicy")
        .await
        .expect_err("missing policy");
    assert!(missing_policy.is_not_found(), "{missing_policy}");

    store
        .remove_membership("ma-group", "ma-user")
        .await
        .expect("remove membership");
    let error = store
        .remove_membership("ma-group", "ma-user")
        .await
        .expect_err("second remove");
    assert!(error.is_not_found(), "{error}");
    store
        .detach_policy_from_user("ma-user", "ma-policy")
        .await
        .expect("detach");
    let error = store
        .detach_policy_from_user("ma-user", "ma-policy")
        .await
        .expect_err("second detach");
    assert!(error.is_not_found(), "{error}");

    store
        .attach_policy_to_group("ma-group", "ma-policy")
        .await
        .expect("group attach");
    store
        .attach_policy_to_group("ma-group", "ma-policy")
        .await
        .expect("repeat group attach");
    let attached = store
        .list_group_policies("ma-group", &page("ma-", "", 10))
        .await
        .expect("group policies");
    assert_eq!(policy_names(&attached), vec!["ma-policy"]);
    store
        .detach_policy_from_group("ma-group", "ma-policy")
        .await
        .expect("group detach");
    let error = store
        .detach_policy_from_group("ma-group", "ma-policy")
        .await
        .expect_err("second group detach");
    assert!(error.is_not_found(), "{error}");
    let attached = store
        .list_group_policies("ma-group", &page("ma-", "", 10))
        .await
        .expect("group policies after detach");
    assert!(attached.items.is_empty());
}

/// Sub-resource listings for a user or group that does not exist are 404, not an empty page.
pub async fn sub_resources_require_the_parent(store: &dyn Store) {
    for error in [
        store.list_user_groups("sr-nobody", &page("", "", 10)).await.err(),
        store.list_user_policies("sr-nobody", &page("", "", 10)).await.err(),
        store
            .list_effective_user_policies("sr-nobody", &page("", "", 10))
            .await
            .err(),
        store.list_user_credentials("sr-nobody", &page("", "", 10)).await.err(),
        store.list_group_members("sr-nogroup", &page("", "", 10)).await.err(),
        store.list_group_policies("sr-nogroup", &page("", "", 10)).await.err(),
    ] {
        let error = error.expect("listing a missing parent must fail");
        assert!(error.is_not_found(), "{error}");
    }
}

/// Credentials are stored encrypted, listed per user, and scoped to their owner.
pub async fn credentials_round_trip(store: &dyn Store) {
    let user = store.create_user(NewUser::named("cr-user")).await.expect("user");
    store.create_user(NewUser::named("cr-other")).await.expect("other user");

    let created = store
        .create_credential(new_credential("cr-key-1", "cr-user"))
        .await
        .expect("create");
    assert_eq!(created.user_id, user.user_id);
    assert_eq!(created.secret_ciphertext, b"ciphertext".to_vec());

    store
        .create_credential(new_credential("cr-key-2", "cr-user"))
        .await
        .expect("second key");

    let by_key = store.get_credential("cr-key-1").await.expect("by access key");
    assert_eq!(by_key, created);
    let by_user = store
        .get_user_credential("cr-user", "cr-key-1")
        .await
        .expect("by user and key");
    assert_eq!(by_user, created);
    let wrong_owner = store
        .get_user_credential("cr-other", "cr-key-1")
        .await
        .expect_err("other user must not see it");
    assert!(wrong_owner.is_not_found(), "{wrong_owner}");

    let listed = store
        .list_user_credentials("cr-user", &page("cr-", "", 10))
        .await
        .expect("list");
    assert_eq!(access_key_ids(&listed), vec!["cr-key-1", "cr-key-2"]);

    let duplicate = store
        .create_credential(new_credential("cr-key-1", "cr-user"))
        .await
        .expect_err("duplicate access key");
    assert!(duplicate.is_already_exists(), "{duplicate}");

    let missing_user = store
        .create_credential(new_credential("cr-key-3", "cr-nobody"))
        .await
        .expect_err("missing user");
    assert!(missing_user.is_not_found(), "{missing_user}");

    store
        .delete_credential("cr-user", "cr-key-1")
        .await
        .expect("delete credential");
    assert!(store.get_credential("cr-key-1").await.is_err());
    let error = store
        .delete_credential("cr-user", "cr-key-1")
        .await
        .expect_err("second delete");
    assert!(error.is_not_found(), "{error}");
}

/// External principals belong to one user and are unique by id.
pub async fn external_principals_round_trip(store: &dyn Store) {
    store.create_user(NewUser::named("ep-user")).await.expect("user");
    store.create_user(NewUser::named("ep-other")).await.expect("other");
    store
        .create_external_principal("ep-user", "ep-arn-1")
        .await
        .expect("create");
    store
        .create_external_principal("ep-user", "ep-arn-2")
        .await
        .expect("second");

    let found = store.get_external_principal("ep-arn-1").await.expect("get");
    assert_eq!(found.username, "ep-user");

    let listed = store
        .list_user_external_principals("ep-user", &page("ep-", "", 10))
        .await
        .expect("list");
    assert_eq!(listed.items.len(), 2);

    let duplicate = store
        .create_external_principal("ep-other", "ep-arn-1")
        .await
        .expect_err("duplicate id");
    assert!(duplicate.is_already_exists(), "{duplicate}");

    store
        .delete_external_principal("ep-user", "ep-arn-1")
        .await
        .expect("delete");
    assert!(store.get_external_principal("ep-arn-1").await.is_err());
}

/// A token id can be claimed once; the cleanup removes expired rows only.
pub async fn token_ids_are_claimed_once(store: &dyn Store) {
    let future = Timestamp::now() + SignedDuration::from_hours(1);
    let past = Timestamp::now() - SignedDuration::from_hours(1);

    store.claim_token_id("ti-live", future).await.expect("first claim");
    let repeat = store.claim_token_id("ti-live", future).await.expect_err("second claim");
    assert!(repeat.is_already_exists(), "{repeat}");

    store.claim_token_id("ti-expired", past).await.expect("expired claim");
    let removed = store
        .delete_expired_token_ids(Timestamp::now())
        .await
        .expect("cleanup expired");
    assert!(removed >= 1, "the expired token id must be removed");
    store
        .claim_token_id("ti-expired", future)
        .await
        .expect("the id is free again");
    let still_claimed = store
        .claim_token_id("ti-live", future)
        .await
        .expect_err("the live id stays claimed");
    assert!(still_claimed.is_already_exists(), "{still_claimed}");
}

/// Bootstrap creates what is missing and reports the rest as skipped.
pub async fn bootstrap_is_idempotent(store: &dyn Store) {
    let plan = BootstrapPlan {
        policies: vec![new_policy("bs-policy")],
        groups: vec![NewGroup::named("bs-group")],
        users: vec![NewUser::named("bs-user")],
        memberships: vec![("bs-group".to_owned(), "bs-user".to_owned())],
        user_policies: vec![("bs-user".to_owned(), "bs-policy".to_owned())],
        group_policies: vec![("bs-group".to_owned(), "bs-policy".to_owned())],
        credentials: vec![new_credential("bs-key", "bs-user")],
    };

    let first = store.apply_bootstrap(&plan).await.expect("first run");
    assert_eq!(first.created.policies, 1);
    assert_eq!(first.created.groups, 1);
    assert_eq!(first.created.users, 1);
    assert_eq!(first.created.memberships, 1);
    assert_eq!(first.created.attachments, 2);
    assert_eq!(first.created.credentials, 1);
    assert_eq!(first.skipped, Default::default());

    let second = store.apply_bootstrap(&plan).await.expect("second run");
    assert_eq!(second.created, Default::default(), "nothing new on a re-run");
    assert_eq!(second.skipped.policies, 1);
    assert_eq!(second.skipped.groups, 1);
    assert_eq!(second.skipped.users, 1);
    assert_eq!(second.skipped.memberships, 1);
    assert_eq!(second.skipped.attachments, 2);
    assert_eq!(second.skipped.credentials, 1);

    let effective = store
        .list_effective_user_policies("bs-user", &page("bs-", "", 10))
        .await
        .expect("effective");
    assert_eq!(policy_names(&effective), vec!["bs-policy"]);

    // A plan that points at a missing user leaves the store untouched.
    let broken = BootstrapPlan {
        groups: vec![NewGroup::named("bs-group-2")],
        memberships: vec![("bs-group-2".to_owned(), "bs-nobody".to_owned())],
        ..BootstrapPlan::default()
    };
    let error = store.apply_bootstrap(&broken).await.expect_err("broken plan");
    assert!(error.is_not_found(), "{error}");
    assert!(
        store.get_group("bs-group-2").await.is_err(),
        "a failed bootstrap must roll back"
    );
}

/// A bootstrap entry decorates an existing user only when that user is the
/// same identity. A row that another identity created first, for example an
/// OIDC login that claimed the name, gets neither the groups, nor the policies,
/// nor the credentials of the entry, and the whole plan is refused.
pub async fn bootstrap_refuses_a_user_that_belongs_to_another_identity(store: &dyn Store) {
    let mut claimed = NewUser::named("bi-admin");
    claimed.external_id = Some("bi-attacker-sub".to_owned());
    store.create_user(claimed).await.expect("the attacker's row");

    let plan = BootstrapPlan {
        policies: vec![new_policy("bi-policy")],
        groups: vec![NewGroup::named("bi-Admins")],
        users: vec![NewUser::named("bi-admin")],
        memberships: vec![("bi-Admins".to_owned(), "bi-admin".to_owned())],
        user_policies: vec![("bi-admin".to_owned(), "bi-policy".to_owned())],
        group_policies: vec![],
        credentials: vec![new_credential("bi-key", "bi-admin")],
    };
    let error = store.apply_bootstrap(&plan).await.expect_err("the plan is refused");
    assert!(
        error.to_string().contains("bi-admin") && error.to_string().contains("identity"),
        "{error}"
    );
    assert!(
        store.get_group("bi-Admins").await.is_err(),
        "nothing of the plan is applied"
    );
    assert!(store.get_credential("bi-key").await.is_err(), "no credential is bound");
    let groups = store
        .list_user_groups("bi-admin", &page("bi-", "", 10))
        .await
        .expect("groups");
    assert!(groups.items.is_empty(), "the attacker's row gained no group");

    // The same plan with the matching external id is the pre-provisioning case and applies.
    let mut matching = plan.clone();
    matching.users[0].external_id = Some("bi-attacker-sub".to_owned());
    let report = store.apply_bootstrap(&matching).await.expect("matching identity");
    assert_eq!(report.skipped.users, 1);
    assert_eq!(report.created.memberships, 1);
    assert_eq!(report.created.credentials, 1);
}

/// A bootstrap credential whose access key already belongs to a different user
/// is refused, the same way a user row of another identity is. A skip would
/// report the entry as satisfied while the key authenticates as someone else.
pub async fn bootstrap_refuses_a_credential_that_belongs_to_another_user(store: &dyn Store) {
    store.create_user(NewUser::named("bc-alice")).await.expect("alice");
    store.create_user(NewUser::named("bc-bob")).await.expect("bob");
    store
        .create_credential(new_credential("bc-key", "bc-alice"))
        .await
        .expect("alice's key");

    let plan = BootstrapPlan {
        credentials: vec![new_credential("bc-key", "bc-bob")],
        ..BootstrapPlan::default()
    };
    let error = store.apply_bootstrap(&plan).await.expect_err("the plan is refused");
    assert!(matches!(error, StoreError::WrongIdentity { .. }), "{error}");
    let credential = store.get_credential("bc-key").await.expect("the key still exists");
    assert_eq!(credential.username, "bc-alice", "the key keeps its owner");

    // The same key under its owner is the idempotent re-run and is skipped.
    let same = BootstrapPlan {
        credentials: vec![new_credential("bc-key", "bc-alice")],
        ..BootstrapPlan::default()
    };
    let report = store.apply_bootstrap(&same).await.expect("re-run");
    assert_eq!(report.skipped.credentials, 1);
    assert_eq!(report.created.credentials, 0);
}

/// A bootstrap user whose email or external id belongs to a different row is
/// an error that names the field, never a silent skip.
pub async fn bootstrap_reports_a_collision_on_another_unique_column(store: &dyn Store) {
    let mut existing = NewUser::named("bu-alice");
    existing.email = Some("bu-ops@example.com".to_owned());
    store.create_user(existing).await.expect("existing user");

    let mut clashing = NewUser::named("bu-svc-ci");
    clashing.email = Some("bu-ops@example.com".to_owned());
    let plan = BootstrapPlan {
        users: vec![clashing],
        ..BootstrapPlan::default()
    };
    let error = store
        .apply_bootstrap(&plan)
        .await
        .expect_err("the collision is reported");
    assert!(error.to_string().contains("email"), "{error}");
    assert!(store.get_user("bu-svc-ci").await.is_err(), "the user was not created");
}

/// Reading or deleting something that is not there is a 404, never a panic.
pub async fn missing_entities_are_not_found(store: &dyn Store) {
    for error in [
        store.get_user("nf-user").await.err(),
        store.get_group("nf-group").await.err(),
        store.get_policy("nf-policy").await.err(),
        store.get_credential("nf-key").await.err(),
        store.get_external_principal("nf-principal").await.err(),
        store.delete_user("nf-user").await.err(),
        store.delete_group("nf-group").await.err(),
        store.delete_policy("nf-policy").await.err(),
        store.set_friendly_name("nf-user", "x").await.err(),
    ] {
        let error = error.expect("missing entity must fail");
        assert!(error.is_not_found(), "{error}");
    }
}

/// Runs every case in order. Cases use disjoint key prefixes.
pub async fn run_all(store: &dyn Store) {
    store.ping().await.expect("ping");
    user_round_trip(store).await;
    group_and_policy_round_trip(store).await;
    duplicates_are_rejected(store).await;
    deleting_a_user_cascades(store).await;
    deleting_a_group_cascades(store).await;
    deleting_a_policy_cascades(store).await;
    keys_sort_bytewise(store).await;
    prefixes_escape_like_wildcards(store).await;
    groups_and_policies_page_like_users(store).await;
    pagination_is_keyset_and_exclusive(store).await;
    effective_policies_are_a_union_without_duplicates(store).await;
    memberships_and_attachments(store).await;
    sub_resources_require_the_parent(store).await;
    credentials_round_trip(store).await;
    external_principals_round_trip(store).await;
    token_ids_are_claimed_once(store).await;
    bootstrap_is_idempotent(store).await;
    bootstrap_refuses_a_user_that_belongs_to_another_identity(store).await;
    bootstrap_refuses_a_credential_that_belongs_to_another_user(store).await;
    bootstrap_reports_a_collision_on_another_unique_column(store).await;
    missing_entities_are_not_found(store).await;
}

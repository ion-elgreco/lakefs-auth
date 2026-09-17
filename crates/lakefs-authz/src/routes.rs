//! The route table and the router.
//!
//! With the `testkit` feature, `ROUTE_TABLE` lists every operation of
//! `api/authorization.yml` relative to the base path, in the OpenAPI path
//! syntax, which axum 0.8 shares. A test compares it with the vendored
//! specification.

use axum::Router;
use axum::routing::{get, post, put};

use crate::app::AppState;
use crate::handlers::{attachments, credentials, external, groups, memberships, meta, policies, tokenid, users};

/// Method and path of all 37 operations, relative to `--base-path`.
///
/// Only the tests read this, so it is behind `testkit` and stays out of the
/// public API of the release build.
#[cfg(feature = "testkit")]
pub const ROUTE_TABLE: &[(&str, &str)] = &[
    ("GET", "/auth/users"),
    ("POST", "/auth/users"),
    ("GET", "/auth/users/{userId}"),
    ("DELETE", "/auth/users/{userId}"),
    ("PUT", "/auth/users/{userId}/password"),
    ("PUT", "/auth/users/{userId}/friendly_name"),
    ("GET", "/auth/groups"),
    ("POST", "/auth/groups"),
    ("GET", "/auth/groups/{groupId}"),
    ("DELETE", "/auth/groups/{groupId}"),
    ("GET", "/auth/policies"),
    ("POST", "/auth/policies"),
    ("GET", "/auth/policies/{policyId}"),
    ("PUT", "/auth/policies/{policyId}"),
    ("DELETE", "/auth/policies/{policyId}"),
    ("GET", "/auth/groups/{groupId}/members"),
    ("PUT", "/auth/groups/{groupId}/members/{userId}"),
    ("DELETE", "/auth/groups/{groupId}/members/{userId}"),
    ("GET", "/auth/users/{userId}/credentials"),
    ("POST", "/auth/users/{userId}/credentials"),
    ("GET", "/auth/users/{userId}/credentials/{accessKeyId}"),
    ("DELETE", "/auth/users/{userId}/credentials/{accessKeyId}"),
    ("GET", "/auth/credentials/{accessKeyId}"),
    ("GET", "/auth/users/{userId}/groups"),
    ("GET", "/auth/users/{userId}/policies"),
    ("PUT", "/auth/users/{userId}/policies/{policyId}"),
    ("DELETE", "/auth/users/{userId}/policies/{policyId}"),
    ("GET", "/auth/groups/{groupId}/policies"),
    ("PUT", "/auth/groups/{groupId}/policies/{policyId}"),
    ("DELETE", "/auth/groups/{groupId}/policies/{policyId}"),
    ("POST", "/auth/tokenid/claim"),
    ("GET", "/auth/users/{userId}/external/principals/ls"),
    ("POST", "/auth/users/{userId}/external/principals"),
    ("DELETE", "/auth/users/{userId}/external/principals"),
    ("GET", "/auth/external/principals"),
    ("GET", "/healthcheck"),
    ("GET", "/config/version"),
];

/// Path of the only API route that needs no bearer token.
pub const HEALTHCHECK_PATH: &str = "/healthcheck";

/// Readiness probe, served at the root and not under the base path, like the
/// probes of lakefs-authn. It is not part of the lakeFS contract.
pub const READYZ_PATH: &str = "/readyz";

/// Everything the bearer token protects, which is every route but the health check.
pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/auth/users", get(users::list_users).post(users::create_user))
        .route("/auth/users/{userId}", get(users::get_user).delete(users::delete_user))
        .route("/auth/users/{userId}/password", put(users::update_password))
        .route("/auth/users/{userId}/friendly_name", put(users::update_friendly_name))
        .route("/auth/groups", get(groups::list_groups).post(groups::create_group))
        .route(
            "/auth/groups/{groupId}",
            get(groups::get_group).delete(groups::delete_group),
        )
        .route(
            "/auth/policies",
            get(policies::list_policies).post(policies::create_policy),
        )
        .route(
            "/auth/policies/{policyId}",
            get(policies::get_policy)
                .put(policies::update_policy)
                .delete(policies::delete_policy),
        )
        .route("/auth/groups/{groupId}/members", get(memberships::list_group_members))
        .route(
            "/auth/groups/{groupId}/members/{userId}",
            put(memberships::add_membership).delete(memberships::delete_membership),
        )
        .route(
            "/auth/users/{userId}/credentials",
            get(credentials::list_user_credentials).post(credentials::create_credentials),
        )
        .route(
            "/auth/users/{userId}/credentials/{accessKeyId}",
            get(credentials::get_credentials_for_user).delete(credentials::delete_credentials),
        )
        .route("/auth/credentials/{accessKeyId}", get(credentials::get_credentials))
        .route("/auth/users/{userId}/groups", get(memberships::list_user_groups))
        .route("/auth/users/{userId}/policies", get(attachments::list_user_policies))
        .route(
            "/auth/users/{userId}/policies/{policyId}",
            put(attachments::attach_policy_to_user).delete(attachments::detach_policy_from_user),
        )
        .route("/auth/groups/{groupId}/policies", get(attachments::list_group_policies))
        .route(
            "/auth/groups/{groupId}/policies/{policyId}",
            put(attachments::attach_policy_to_group).delete(attachments::detach_policy_from_group),
        )
        .route("/auth/tokenid/claim", post(tokenid::claim_token_id))
        .route(
            "/auth/users/{userId}/external/principals/ls",
            get(external::list_user_external_principals),
        )
        .route(
            "/auth/users/{userId}/external/principals",
            post(external::create_user_external_principal).delete(external::delete_user_external_principal),
        )
        .route("/auth/external/principals", get(external::get_external_principal))
        .route("/config/version", get(meta::version))
}

/// The health check. lakeFS polls it before anything else and expects 204.
pub fn public_router() -> Router<AppState> {
    Router::new().route(HEALTHCHECK_PATH, get(meta::healthcheck))
}

/// The routes that live at the root, outside the base path: the readiness probe.
pub fn root_router() -> Router<AppState> {
    Router::new().route(READYZ_PATH, get(meta::readyz))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[cfg(feature = "testkit")]
    #[test]
    fn the_route_table_has_all_37_operations_once() {
        let unique: BTreeSet<_> = ROUTE_TABLE.iter().collect();
        assert_eq!(unique.len(), ROUTE_TABLE.len(), "duplicate entry in ROUTE_TABLE");
        assert_eq!(ROUTE_TABLE.len(), 37);
    }

    #[test]
    fn the_router_builds() {
        // Route conflicts panic when the router is built, so this is the check.
        let _ = protected_router().merge(public_router()).merge(root_router());
    }
}

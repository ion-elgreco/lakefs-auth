//! The bootstrap loop, written once for every store.
//!
//! A store implements [`BootstrapWriter`] on its transaction, or on its staged
//! copy, with one insert per plan entry that answers whether it created the
//! row. [`apply_plan`] holds the loop, the counting, and the identity rules,
//! so the two stores cannot drift apart on what bootstrap tolerates.

use async_trait::async_trait;

use super::error::{StoreError, StoreResult};
use super::types::{
    BootstrapPlan, BootstrapReport, CredentialRecord, NewCredential, NewGroup, NewPolicy, NewUser, UserRecord,
};

/// The inserts of a bootstrap run. Each one creates the row when it is
/// missing and reports whether it did; none of them updates.
#[async_trait]
pub trait BootstrapWriter: Send {
    async fn insert_policy_if_missing(&mut self, policy: &NewPolicy) -> StoreResult<bool>;
    async fn insert_group_if_missing(&mut self, group: &NewGroup) -> StoreResult<bool>;
    /// The stored row when the username was already taken, `None` when the
    /// user was created.
    async fn insert_user_if_missing(&mut self, user: &NewUser) -> StoreResult<Option<UserRecord>>;
    async fn insert_membership_if_missing(&mut self, group_id: &str, username: &str) -> StoreResult<bool>;
    async fn insert_user_policy_if_missing(&mut self, username: &str, policy: &str) -> StoreResult<bool>;
    async fn insert_group_policy_if_missing(&mut self, group_id: &str, policy: &str) -> StoreResult<bool>;
    /// The stored row when the access key already existed, `None` when the
    /// credentials were created.
    async fn insert_credential_if_missing(
        &mut self,
        credential: &NewCredential,
    ) -> StoreResult<Option<CredentialRecord>>;
}

/// Applies a plan through `writer`, creating only missing rows.
///
/// An existing user must be the identity the entry describes, and existing
/// credentials must belong to the entry's user. Otherwise the entry's
/// memberships, policies, or credentials would be granted to someone else,
/// so the run stops with `WrongIdentity` and the caller rolls back.
pub async fn apply_plan<W: BootstrapWriter + ?Sized>(
    writer: &mut W,
    plan: &BootstrapPlan,
) -> StoreResult<BootstrapReport> {
    let mut report = BootstrapReport::default();
    let (created, skipped) = (&mut report.created, &mut report.skipped);

    for policy in &plan.policies {
        let done = writer.insert_policy_if_missing(policy).await?;
        tally(&mut created.policies, &mut skipped.policies, done);
    }
    for group in &plan.groups {
        let done = writer.insert_group_if_missing(group).await?;
        tally(&mut created.groups, &mut skipped.groups, done);
    }
    for user in &plan.users {
        let existing = writer.insert_user_if_missing(user).await?;
        if let Some(existing) = &existing
            && !user.same_identity_as(existing)
        {
            return Err(StoreError::wrong_identity("user", &user.username));
        }
        tally(&mut created.users, &mut skipped.users, existing.is_none());
    }
    for (group_id, username) in &plan.memberships {
        let done = writer.insert_membership_if_missing(group_id, username).await?;
        tally(&mut created.memberships, &mut skipped.memberships, done);
    }
    for (username, policy) in &plan.user_policies {
        let done = writer.insert_user_policy_if_missing(username, policy).await?;
        tally(&mut created.attachments, &mut skipped.attachments, done);
    }
    for (group_id, policy) in &plan.group_policies {
        let done = writer.insert_group_policy_if_missing(group_id, policy).await?;
        tally(&mut created.attachments, &mut skipped.attachments, done);
    }
    for credential in &plan.credentials {
        let existing = writer.insert_credential_if_missing(credential).await?;
        if let Some(existing) = &existing
            && existing.username != credential.username
        {
            return Err(StoreError::wrong_identity("credentials", &credential.access_key_id));
        }
        tally(&mut created.credentials, &mut skipped.credentials, existing.is_none());
    }
    Ok(report)
}

fn tally(created: &mut u32, skipped: &mut u32, was_created: bool) {
    if was_created {
        *created += 1;
    } else {
        *skipped += 1;
    }
}

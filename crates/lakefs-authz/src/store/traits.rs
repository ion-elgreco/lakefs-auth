//! The storage contract. `Store` is the umbrella every handler works against as
//! `Arc<dyn Store>`; the sub-traits keep each area readable.

use async_trait::async_trait;
use jiff::Timestamp;
use lakefs_auth_core::pagination::{PageOf, PageQuery};

use super::error::StoreResult;
use super::types::{
    BootstrapPlan, BootstrapReport, CredentialRecord, ExternalPrincipalRecord, GroupRecord, NewCredential, NewGroup,
    NewPolicy, NewUser, PolicyRecord, UserRecord,
};

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: NewUser) -> StoreResult<UserRecord>;
    async fn get_user(&self, username: &str) -> StoreResult<UserRecord>;
    /// `None` instead of an error: `GET /auth/users?id=` answers with an empty list.
    async fn find_user_by_id(&self, user_id: i64) -> StoreResult<Option<UserRecord>>;
    async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<UserRecord>>;
    async fn find_user_by_external_id(&self, external_id: &str) -> StoreResult<Option<UserRecord>>;
    async fn delete_user(&self, username: &str) -> StoreResult<()>;
    async fn list_users(&self, query: &PageQuery) -> StoreResult<PageOf<UserRecord>>;
    async fn set_friendly_name(&self, username: &str, friendly_name: &str) -> StoreResult<()>;
}

#[async_trait]
pub trait GroupStore: Send + Sync {
    async fn create_group(&self, group: NewGroup) -> StoreResult<GroupRecord>;
    async fn get_group(&self, group_id: &str) -> StoreResult<GroupRecord>;
    async fn delete_group(&self, group_id: &str) -> StoreResult<()>;
    async fn list_groups(&self, query: &PageQuery) -> StoreResult<PageOf<GroupRecord>>;
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn create_policy(&self, policy: NewPolicy) -> StoreResult<PolicyRecord>;
    async fn get_policy(&self, name: &str) -> StoreResult<PolicyRecord>;
    async fn update_policy(&self, policy: NewPolicy) -> StoreResult<PolicyRecord>;
    async fn delete_policy(&self, name: &str) -> StoreResult<()>;
    async fn list_policies(&self, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>>;
}

#[async_trait]
pub trait MembershipStore: Send + Sync {
    /// Idempotent, because `PUT` is: a repeated membership is not an error.
    async fn add_membership(&self, group_id: &str, username: &str) -> StoreResult<()>;
    async fn remove_membership(&self, group_id: &str, username: &str) -> StoreResult<()>;
    async fn list_group_members(&self, group_id: &str, query: &PageQuery) -> StoreResult<PageOf<UserRecord>>;
    async fn list_user_groups(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<GroupRecord>>;
}

#[async_trait]
pub trait AttachmentStore: Send + Sync {
    async fn attach_policy_to_user(&self, username: &str, policy: &str) -> StoreResult<()>;
    async fn detach_policy_from_user(&self, username: &str, policy: &str) -> StoreResult<()>;
    async fn list_user_policies(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>>;
    /// Direct attachments plus the ones from every group the user belongs to, without duplicates.
    async fn list_effective_user_policies(
        &self,
        username: &str,
        query: &PageQuery,
    ) -> StoreResult<PageOf<PolicyRecord>>;
    async fn attach_policy_to_group(&self, group_id: &str, policy: &str) -> StoreResult<()>;
    async fn detach_policy_from_group(&self, group_id: &str, policy: &str) -> StoreResult<()>;
    async fn list_group_policies(&self, group_id: &str, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>>;
}

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn create_credential(&self, credential: NewCredential) -> StoreResult<CredentialRecord>;
    /// The hot path: lakeFS resolves an access key id on every S3 request.
    async fn get_credential(&self, access_key_id: &str) -> StoreResult<CredentialRecord>;
    async fn get_user_credential(&self, username: &str, access_key_id: &str) -> StoreResult<CredentialRecord>;
    async fn delete_credential(&self, username: &str, access_key_id: &str) -> StoreResult<()>;
    async fn list_user_credentials(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<CredentialRecord>>;
}

#[async_trait]
pub trait ExternalPrincipalStore: Send + Sync {
    async fn create_external_principal(&self, username: &str, principal_id: &str) -> StoreResult<()>;
    async fn delete_external_principal(&self, username: &str, principal_id: &str) -> StoreResult<()>;
    async fn get_external_principal(&self, principal_id: &str) -> StoreResult<ExternalPrincipalRecord>;
    async fn list_user_external_principals(
        &self,
        username: &str,
        query: &PageQuery,
    ) -> StoreResult<PageOf<ExternalPrincipalRecord>>;
}

#[async_trait]
pub trait TokenIdStore: Send + Sync {
    /// `AlreadyExists` when the id was claimed before, which the handler turns into 400.
    async fn claim_token_id(&self, token_id: &str, expires_at: Timestamp) -> StoreResult<()>;
    async fn delete_expired_token_ids(&self, now: Timestamp) -> StoreResult<u64>;
}

#[async_trait]
pub trait AdminStore: Send + Sync {
    /// Checks that the backend answers. Called at startup and by `GET /readyz`.
    async fn ping(&self) -> StoreResult<()>;
    /// Applies a bootstrap plan in one transaction, creating only missing rows.
    async fn apply_bootstrap(&self, plan: &BootstrapPlan) -> StoreResult<BootstrapReport>;
}

/// Everything the server needs from storage.
pub trait Store:
    UserStore
    + GroupStore
    + PolicyStore
    + MembershipStore
    + AttachmentStore
    + CredentialStore
    + ExternalPrincipalStore
    + TokenIdStore
    + AdminStore
    + Send
    + Sync
    + 'static
{
}

impl<T> Store for T where
    T: UserStore
        + GroupStore
        + PolicyStore
        + MembershipStore
        + AttachmentStore
        + CredentialStore
        + ExternalPrincipalStore
        + TokenIdStore
        + AdminStore
        + Send
        + Sync
        + 'static
{
}

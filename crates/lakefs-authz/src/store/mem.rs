//! In-memory store. Keys mirror the PostgreSQL primary keys so that both stores
//! order and paginate identically, and the cascades are written out explicitly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use async_trait::async_trait;
use jiff::Timestamp;
use lakefs_auth_core::pagination::{PageOf, PageQuery, page_sorted};

use super::bootstrap::{BootstrapWriter, apply_plan};
use super::error::{StoreError, StoreResult};
use super::traits::{
    AdminStore, AttachmentStore, CredentialStore, ExternalPrincipalStore, GroupStore, MembershipStore, PolicyStore,
    TokenIdStore, UserStore,
};
use super::types::{
    BootstrapPlan, BootstrapReport, CredentialRecord, ExternalPrincipalRecord, GroupRecord, NewCredential, NewGroup,
    NewPolicy, NewUser, PolicyRecord, UserRecord,
};

#[derive(Debug, Clone, Default)]
struct Inner {
    users: BTreeMap<String, UserRecord>,
    /// The identity column starts at 1, like a PostgreSQL sequence.
    next_user_id: i64,
    groups: BTreeMap<String, GroupRecord>,
    policies: BTreeMap<String, PolicyRecord>,
    /// `(group_id, username)`, like the composite primary key.
    group_members: BTreeSet<(String, String)>,
    /// `(username, policy_name)`.
    user_policies: BTreeSet<(String, String)>,
    /// `(group_id, policy_name)`.
    group_policies: BTreeSet<(String, String)>,
    credentials: BTreeMap<String, CredentialRecord>,
    external_principals: BTreeMap<String, ExternalPrincipalRecord>,
    claimed_token_ids: BTreeMap<String, Timestamp>,
}

/// A store that keeps everything in memory. Used by the API tests and by the
/// full-stack test that needs a server without a database.
#[derive(Debug, Default)]
pub struct MemStore {
    inner: RwLock<Inner>,
    /// Test knob: makes `ping` fail, the way an unreachable database would.
    unavailable: std::sync::atomic::AtomicBool,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `ping` fail while `unavailable` is true, for readiness tests.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, std::sync::atomic::Ordering::SeqCst);
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().expect("in-memory store lock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().expect("in-memory store lock poisoned")
    }
}

/// The owner check of a reference: a missing row is a 404.
fn require(found: bool, entity: &'static str, id: &str) -> StoreResult<()> {
    if found {
        Ok(())
    } else {
        Err(StoreError::not_found(entity, id))
    }
}

impl Inner {
    fn require_user(&self, username: &str) -> StoreResult<()> {
        require(self.users.contains_key(username), "user", username)
    }

    fn require_group(&self, group_id: &str) -> StoreResult<()> {
        require(self.groups.contains_key(group_id), "group", group_id)
    }

    fn require_policy(&self, name: &str) -> StoreResult<()> {
        require(self.policies.contains_key(name), "policy", name)
    }

    fn insert_user(&mut self, user: NewUser) -> StoreResult<UserRecord> {
        if self.users.contains_key(&user.username) {
            return Err(StoreError::already_exists("user", &user.username));
        }
        if let Some(email) = &user.email
            && self.users.values().any(|u| u.email.as_deref() == Some(email.as_str()))
        {
            return Err(StoreError::already_exists("user with email", email));
        }
        if let Some(external_id) = &user.external_id
            && self
                .users
                .values()
                .any(|u| u.external_id.as_deref() == Some(external_id.as_str()))
        {
            return Err(StoreError::already_exists("user with external id", external_id));
        }
        self.next_user_id += 1;
        let record = UserRecord {
            username: user.username.clone(),
            user_id: self.next_user_id,
            creation_date: user.creation_date,
            friendly_name: user.friendly_name,
            email: user.email,
            source: user.source,
            external_id: user.external_id,
            encrypted_password: user.encrypted_password,
        };
        self.users.insert(user.username, record.clone());
        Ok(record)
    }

    fn insert_group(&mut self, group: NewGroup) -> StoreResult<GroupRecord> {
        if self.groups.contains_key(&group.id) {
            return Err(StoreError::already_exists("group", &group.id));
        }
        let record = GroupRecord {
            id: group.id.clone(),
            description: group.description,
            creation_date: group.creation_date,
        };
        self.groups.insert(group.id, record.clone());
        Ok(record)
    }

    fn insert_policy(&mut self, policy: NewPolicy) -> StoreResult<PolicyRecord> {
        if self.policies.contains_key(&policy.name) {
            return Err(StoreError::already_exists("policy", &policy.name));
        }
        let record = PolicyRecord {
            name: policy.name.clone(),
            creation_date: policy.creation_date,
            statement: policy.statement,
            acl: policy.acl,
        };
        self.policies.insert(policy.name, record.clone());
        Ok(record)
    }

    fn insert_credential(&mut self, credential: NewCredential) -> StoreResult<CredentialRecord> {
        let user_id = self
            .users
            .get(&credential.username)
            .ok_or_else(|| StoreError::not_found("user", &credential.username))?
            .user_id;
        if self.credentials.contains_key(&credential.access_key_id) {
            return Err(StoreError::already_exists("credentials", &credential.access_key_id));
        }
        let record = CredentialRecord {
            access_key_id: credential.access_key_id.clone(),
            username: credential.username,
            user_id,
            secret_ciphertext: credential.secret_ciphertext,
            creation_date: credential.creation_date,
        };
        self.credentials.insert(credential.access_key_id, record.clone());
        Ok(record)
    }

    /// The `ON DELETE CASCADE` rules of the schema, written out.
    fn cascade_delete_user(&mut self, username: &str) {
        self.group_members.retain(|(_, member)| member != username);
        self.user_policies.retain(|(user, _)| user != username);
        self.credentials.retain(|_, cred| cred.username != username);
        self.external_principals.retain(|_, p| p.username != username);
    }

    fn cascade_delete_group(&mut self, group_id: &str) {
        self.group_members.retain(|(group, _)| group != group_id);
        self.group_policies.retain(|(group, _)| group != group_id);
    }

    fn cascade_delete_policy(&mut self, name: &str) {
        self.user_policies.retain(|(_, policy)| policy != name);
        self.group_policies.retain(|(_, policy)| policy != name);
    }

    fn policies_named<'a>(
        &'a self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> impl Iterator<Item = (&'a str, &'a PolicyRecord)> {
        names
            .into_iter()
            .filter_map(|name| self.policies.get(name).map(|policy| (name, policy)))
    }
}

/// One page of a map whose keys are the sort keys.
fn page_map<T: Clone>(map: &BTreeMap<String, T>, query: &PageQuery) -> PageOf<T> {
    page_sorted(map.iter().map(|(key, item)| (key.as_str(), item)), query)
}

#[async_trait]
impl UserStore for MemStore {
    async fn create_user(&self, user: NewUser) -> StoreResult<UserRecord> {
        self.write().insert_user(user)
    }

    async fn get_user(&self, username: &str) -> StoreResult<UserRecord> {
        self.read()
            .users
            .get(username)
            .cloned()
            .ok_or_else(|| StoreError::not_found("user", username))
    }

    async fn find_user_by_id(&self, user_id: i64) -> StoreResult<Option<UserRecord>> {
        Ok(self.read().users.values().find(|u| u.user_id == user_id).cloned())
    }

    async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<UserRecord>> {
        Ok(self
            .read()
            .users
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn find_user_by_external_id(&self, external_id: &str) -> StoreResult<Option<UserRecord>> {
        Ok(self
            .read()
            .users
            .values()
            .find(|u| u.external_id.as_deref() == Some(external_id))
            .cloned())
    }

    async fn delete_user(&self, username: &str) -> StoreResult<()> {
        let mut inner = self.write();
        if inner.users.remove(username).is_none() {
            return Err(StoreError::not_found("user", username));
        }
        inner.cascade_delete_user(username);
        Ok(())
    }

    async fn list_users(&self, query: &PageQuery) -> StoreResult<PageOf<UserRecord>> {
        let inner = self.read();
        Ok(page_map(&inner.users, query))
    }

    async fn set_friendly_name(&self, username: &str, friendly_name: &str) -> StoreResult<()> {
        let mut inner = self.write();
        let user = inner
            .users
            .get_mut(username)
            .ok_or_else(|| StoreError::not_found("user", username))?;
        user.friendly_name = Some(friendly_name.to_owned());
        Ok(())
    }
}

#[async_trait]
impl GroupStore for MemStore {
    async fn create_group(&self, group: NewGroup) -> StoreResult<GroupRecord> {
        self.write().insert_group(group)
    }

    async fn get_group(&self, group_id: &str) -> StoreResult<GroupRecord> {
        self.read()
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| StoreError::not_found("group", group_id))
    }

    async fn delete_group(&self, group_id: &str) -> StoreResult<()> {
        let mut inner = self.write();
        if inner.groups.remove(group_id).is_none() {
            return Err(StoreError::not_found("group", group_id));
        }
        inner.cascade_delete_group(group_id);
        Ok(())
    }

    async fn list_groups(&self, query: &PageQuery) -> StoreResult<PageOf<GroupRecord>> {
        let inner = self.read();
        Ok(page_map(&inner.groups, query))
    }
}

#[async_trait]
impl PolicyStore for MemStore {
    async fn create_policy(&self, policy: NewPolicy) -> StoreResult<PolicyRecord> {
        self.write().insert_policy(policy)
    }

    async fn get_policy(&self, name: &str) -> StoreResult<PolicyRecord> {
        self.read()
            .policies
            .get(name)
            .cloned()
            .ok_or_else(|| StoreError::not_found("policy", name))
    }

    async fn update_policy(&self, policy: NewPolicy) -> StoreResult<PolicyRecord> {
        let mut inner = self.write();
        let slot = inner
            .policies
            .get_mut(&policy.name)
            .ok_or_else(|| StoreError::not_found("policy", &policy.name))?;
        slot.creation_date = policy.creation_date;
        slot.statement = policy.statement;
        slot.acl = policy.acl;
        Ok(slot.clone())
    }

    async fn delete_policy(&self, name: &str) -> StoreResult<()> {
        let mut inner = self.write();
        if inner.policies.remove(name).is_none() {
            return Err(StoreError::not_found("policy", name));
        }
        inner.cascade_delete_policy(name);
        Ok(())
    }

    async fn list_policies(&self, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>> {
        let inner = self.read();
        Ok(page_map(&inner.policies, query))
    }
}

#[async_trait]
impl MembershipStore for MemStore {
    async fn add_membership(&self, group_id: &str, username: &str) -> StoreResult<()> {
        let mut inner = self.write();
        inner.require_group(group_id)?;
        inner.require_user(username)?;
        inner.group_members.insert((group_id.to_owned(), username.to_owned()));
        Ok(())
    }

    async fn remove_membership(&self, group_id: &str, username: &str) -> StoreResult<()> {
        let mut inner = self.write();
        if !inner.group_members.remove(&(group_id.to_owned(), username.to_owned())) {
            return Err(StoreError::not_found("group membership", username));
        }
        Ok(())
    }

    async fn list_group_members(&self, group_id: &str, query: &PageQuery) -> StoreResult<PageOf<UserRecord>> {
        let inner = self.read();
        inner.require_group(group_id)?;
        let rows = inner
            .group_members
            .iter()
            .filter(|(group, _)| group == group_id)
            .filter_map(|(_, username)| inner.users.get(username).map(|user| (username.as_str(), user)));
        Ok(page_sorted(rows, query))
    }

    async fn list_user_groups(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<GroupRecord>> {
        let inner = self.read();
        inner.require_user(username)?;
        let rows = inner
            .group_members
            .iter()
            .filter(|(_, member)| member == username)
            .filter_map(|(group, _)| inner.groups.get(group).map(|record| (group.as_str(), record)));
        Ok(page_sorted(rows, query))
    }
}

#[async_trait]
impl AttachmentStore for MemStore {
    async fn attach_policy_to_user(&self, username: &str, policy: &str) -> StoreResult<()> {
        let mut inner = self.write();
        inner.require_user(username)?;
        inner.require_policy(policy)?;
        inner.user_policies.insert((username.to_owned(), policy.to_owned()));
        Ok(())
    }

    async fn detach_policy_from_user(&self, username: &str, policy: &str) -> StoreResult<()> {
        let mut inner = self.write();
        if !inner.user_policies.remove(&(username.to_owned(), policy.to_owned())) {
            return Err(StoreError::not_found("policy attachment", policy));
        }
        Ok(())
    }

    async fn list_user_policies(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>> {
        let inner = self.read();
        inner.require_user(username)?;
        let names = inner
            .user_policies
            .iter()
            .filter(|(user, _)| user == username)
            .map(|(_, policy)| policy.as_str());
        Ok(page_sorted(inner.policies_named(names), query))
    }

    async fn list_effective_user_policies(
        &self,
        username: &str,
        query: &PageQuery,
    ) -> StoreResult<PageOf<PolicyRecord>> {
        let inner = self.read();
        inner.require_user(username)?;
        let groups: BTreeSet<&String> = inner
            .group_members
            .iter()
            .filter(|(_, member)| member == username)
            .map(|(group, _)| group)
            .collect();
        // A BTreeSet removes the duplicates a user gets through several groups.
        let mut names: BTreeSet<&str> = inner
            .user_policies
            .iter()
            .filter(|(user, _)| user == username)
            .map(|(_, policy)| policy.as_str())
            .collect();
        names.extend(
            inner
                .group_policies
                .iter()
                .filter(|(group, _)| groups.contains(group))
                .map(|(_, policy)| policy.as_str()),
        );
        Ok(page_sorted(inner.policies_named(names), query))
    }

    async fn attach_policy_to_group(&self, group_id: &str, policy: &str) -> StoreResult<()> {
        let mut inner = self.write();
        inner.require_group(group_id)?;
        inner.require_policy(policy)?;
        inner.group_policies.insert((group_id.to_owned(), policy.to_owned()));
        Ok(())
    }

    async fn detach_policy_from_group(&self, group_id: &str, policy: &str) -> StoreResult<()> {
        let mut inner = self.write();
        if !inner.group_policies.remove(&(group_id.to_owned(), policy.to_owned())) {
            return Err(StoreError::not_found("policy attachment", policy));
        }
        Ok(())
    }

    async fn list_group_policies(&self, group_id: &str, query: &PageQuery) -> StoreResult<PageOf<PolicyRecord>> {
        let inner = self.read();
        inner.require_group(group_id)?;
        let names = inner
            .group_policies
            .iter()
            .filter(|(group, _)| group == group_id)
            .map(|(_, policy)| policy.as_str());
        Ok(page_sorted(inner.policies_named(names), query))
    }
}

#[async_trait]
impl CredentialStore for MemStore {
    async fn create_credential(&self, credential: NewCredential) -> StoreResult<CredentialRecord> {
        self.write().insert_credential(credential)
    }

    async fn get_credential(&self, access_key_id: &str) -> StoreResult<CredentialRecord> {
        self.read()
            .credentials
            .get(access_key_id)
            .cloned()
            .ok_or_else(|| StoreError::not_found("credentials", access_key_id))
    }

    async fn get_user_credential(&self, username: &str, access_key_id: &str) -> StoreResult<CredentialRecord> {
        self.read()
            .credentials
            .get(access_key_id)
            .filter(|cred| cred.username == username)
            .cloned()
            .ok_or_else(|| StoreError::not_found("credentials", access_key_id))
    }

    async fn delete_credential(&self, username: &str, access_key_id: &str) -> StoreResult<()> {
        let mut inner = self.write();
        let owned = inner
            .credentials
            .get(access_key_id)
            .is_some_and(|cred| cred.username == username);
        if !owned {
            return Err(StoreError::not_found("credentials", access_key_id));
        }
        inner.credentials.remove(access_key_id);
        Ok(())
    }

    async fn list_user_credentials(&self, username: &str, query: &PageQuery) -> StoreResult<PageOf<CredentialRecord>> {
        let inner = self.read();
        inner.require_user(username)?;
        let rows = inner
            .credentials
            .iter()
            .filter(|(_, credential)| credential.username == username)
            .map(|(key, credential)| (key.as_str(), credential));
        Ok(page_sorted(rows, query))
    }
}

#[async_trait]
impl ExternalPrincipalStore for MemStore {
    async fn create_external_principal(&self, username: &str, principal_id: &str) -> StoreResult<()> {
        let mut inner = self.write();
        inner.require_user(username)?;
        if inner.external_principals.contains_key(principal_id) {
            return Err(StoreError::already_exists("external principal", principal_id));
        }
        inner.external_principals.insert(
            principal_id.to_owned(),
            ExternalPrincipalRecord {
                id: principal_id.to_owned(),
                username: username.to_owned(),
            },
        );
        Ok(())
    }

    async fn delete_external_principal(&self, username: &str, principal_id: &str) -> StoreResult<()> {
        let mut inner = self.write();
        let owned = inner
            .external_principals
            .get(principal_id)
            .is_some_and(|p| p.username == username);
        if !owned {
            return Err(StoreError::not_found("external principal", principal_id));
        }
        inner.external_principals.remove(principal_id);
        Ok(())
    }

    async fn get_external_principal(&self, principal_id: &str) -> StoreResult<ExternalPrincipalRecord> {
        self.read()
            .external_principals
            .get(principal_id)
            .cloned()
            .ok_or_else(|| StoreError::not_found("external principal", principal_id))
    }

    async fn list_user_external_principals(
        &self,
        username: &str,
        query: &PageQuery,
    ) -> StoreResult<PageOf<ExternalPrincipalRecord>> {
        let inner = self.read();
        inner.require_user(username)?;
        let rows = inner
            .external_principals
            .iter()
            .filter(|(_, principal)| principal.username == username)
            .map(|(key, principal)| (key.as_str(), principal));
        Ok(page_sorted(rows, query))
    }
}

#[async_trait]
impl TokenIdStore for MemStore {
    async fn claim_token_id(&self, token_id: &str, expires_at: Timestamp) -> StoreResult<()> {
        let mut inner = self.write();
        if inner.claimed_token_ids.contains_key(token_id) {
            return Err(StoreError::already_exists("token id", token_id));
        }
        inner.claimed_token_ids.insert(token_id.to_owned(), expires_at);
        Ok(())
    }

    async fn delete_expired_token_ids(&self, now: Timestamp) -> StoreResult<u64> {
        let mut inner = self.write();
        let before = inner.claimed_token_ids.len();
        inner.claimed_token_ids.retain(|_, expires| *expires > now);
        Ok(u64::try_from(before - inner.claimed_token_ids.len()).unwrap_or(0))
    }
}

#[async_trait]
impl AdminStore for MemStore {
    async fn ping(&self) -> StoreResult<()> {
        if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::backend(anyhow::anyhow!(
                "the in-memory store is marked unavailable"
            )));
        }
        drop(self.read());
        Ok(())
    }

    async fn apply_bootstrap(&self, plan: &BootstrapPlan) -> StoreResult<BootstrapReport> {
        // Staging a copy and swapping it in is the in-memory equivalent of one
        // transaction: a failure half way leaves the store untouched. The lock
        // is not held while the plan runs, so a write that lands in between
        // is lost; bootstrap runs before the server takes requests.
        let mut inner = self.read().clone();
        let report = apply_plan(&mut inner, plan).await?;
        *self.write() = inner;
        Ok(report)
    }
}

#[async_trait]
impl BootstrapWriter for Inner {
    async fn insert_policy_if_missing(&mut self, policy: &NewPolicy) -> StoreResult<bool> {
        if self.policies.contains_key(&policy.name) {
            return Ok(false);
        }
        self.insert_policy(policy.clone())?;
        Ok(true)
    }

    async fn insert_group_if_missing(&mut self, group: &NewGroup) -> StoreResult<bool> {
        if self.groups.contains_key(&group.id) {
            return Ok(false);
        }
        self.insert_group(group.clone())?;
        Ok(true)
    }

    async fn insert_user_if_missing(&mut self, user: &NewUser) -> StoreResult<Option<UserRecord>> {
        if let Some(existing) = self.users.get(&user.username) {
            return Ok(Some(existing.clone()));
        }
        self.insert_user(user.clone())?;
        Ok(None)
    }

    async fn insert_membership_if_missing(&mut self, group_id: &str, username: &str) -> StoreResult<bool> {
        self.require_group(group_id)?;
        self.require_user(username)?;
        Ok(self.group_members.insert((group_id.to_owned(), username.to_owned())))
    }

    async fn insert_user_policy_if_missing(&mut self, username: &str, policy: &str) -> StoreResult<bool> {
        self.require_user(username)?;
        self.require_policy(policy)?;
        Ok(self.user_policies.insert((username.to_owned(), policy.to_owned())))
    }

    async fn insert_group_policy_if_missing(&mut self, group_id: &str, policy: &str) -> StoreResult<bool> {
        self.require_group(group_id)?;
        self.require_policy(policy)?;
        Ok(self.group_policies.insert((group_id.to_owned(), policy.to_owned())))
    }

    async fn insert_credential_if_missing(
        &mut self,
        credential: &NewCredential,
    ) -> StoreResult<Option<CredentialRecord>> {
        if let Some(existing) = self.credentials.get(&credential.access_key_id) {
            return Ok(Some(existing.clone()));
        }
        self.insert_credential(credential.clone())?;
        Ok(None)
    }
}

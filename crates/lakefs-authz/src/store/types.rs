//! Records the store reads and writes. The stored records map onto the
//! database rows column for column, so the PostgreSQL store reads them
//! directly; `service` converts them into the wire models.

use jiff::Timestamp;
use lakefs_auth_core::crypto::{CryptoError, SecretBox, is_well_formed_access_key_id};
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::Statement;
use lakefs_auth_core::text::non_blank;
use lakefs_auth_core::validate::{validate_entity_id, validate_policy};

/// An optional text field as stored: trimmed, and absent when blank. The
/// lookups trim and drop blank values, so the writes must agree, or `""` would
/// be a real value that collides on the unique email and external id indexes.
pub(crate) fn optional_text(value: Option<&str>) -> Option<String> {
    value.and_then(non_blank).map(str::to_owned)
}

/// A stored user. `user_id` is the database identity column, which
/// `CredentialsWithSecret.user_id` and `GET /auth/users?id=` need.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UserRecord {
    pub username: String,
    pub user_id: i64,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub creation_date: Timestamp,
    pub friendly_name: Option<String>,
    pub email: Option<String>,
    pub source: Option<String>,
    pub external_id: Option<String>,
    pub encrypted_password: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    pub username: String,
    pub creation_date: Timestamp,
    pub friendly_name: Option<String>,
    pub email: Option<String>,
    pub source: Option<String>,
    pub external_id: Option<String>,
    pub encrypted_password: Option<Vec<u8>>,
}

/// The optional fields of a user, as the API and the bootstrap file send them.
#[derive(Debug, Default)]
pub struct UserFields {
    pub friendly_name: Option<String>,
    pub email: Option<String>,
    pub source: Option<String>,
    pub external_id: Option<String>,
    pub encrypted_password: Option<Vec<u8>>,
}

impl NewUser {
    /// A user whose name passed the rules of the API and whose optional text
    /// went through [`optional_text`]. The bootstrap file goes through the
    /// same call.
    pub fn validated(username: String, fields: UserFields, creation_date: Timestamp) -> Result<Self, ApiError> {
        validate_entity_id("user", &username)?;
        Ok(Self {
            username,
            creation_date,
            friendly_name: optional_text(fields.friendly_name.as_deref()),
            email: optional_text(fields.email.as_deref()),
            source: optional_text(fields.source.as_deref()),
            external_id: optional_text(fields.external_id.as_deref()),
            encrypted_password: fields.encrypted_password,
        })
    }

    /// True when an existing row is the identity this entry describes: the
    /// external id, which binds a row to an identity provider subject, matches.
    /// Two rows without one are both local principals and count as the same.
    pub fn same_identity_as(&self, existing: &UserRecord) -> bool {
        self.external_id == existing.external_id
    }

    /// A user with only the required fields, created now.
    pub fn named(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            creation_date: Timestamp::now(),
            friendly_name: None,
            email: None,
            source: None,
            external_id: None,
            encrypted_password: None,
        }
    }
}

/// A stored group. lakeFS uses the same value as both `id` and `name`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct GroupRecord {
    pub id: String,
    pub description: Option<String>,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub creation_date: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGroup {
    pub id: String,
    pub description: Option<String>,
    pub creation_date: Timestamp,
}

impl NewGroup {
    /// A group whose id passed the rules of the API. The bootstrap file goes
    /// through the same call.
    pub fn validated(id: String, description: Option<String>, creation_date: Timestamp) -> Result<Self, ApiError> {
        validate_entity_id("group", &id)?;
        Ok(Self {
            id,
            description,
            creation_date,
        })
    }

    pub fn named(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: None,
            creation_date: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PolicyRecord {
    pub name: String,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub creation_date: Timestamp,
    /// Stored as `jsonb`.
    #[sqlx(json)]
    pub statement: Vec<Statement>,
    pub acl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPolicy {
    pub name: String,
    pub creation_date: Timestamp,
    pub statement: Vec<Statement>,
    pub acl: Option<String>,
}

impl NewPolicy {
    /// A policy that passed the rules of the API. The bootstrap file goes
    /// through the same call, so it cannot create what the API would reject.
    pub fn validated(
        name: &str,
        statement: Vec<Statement>,
        acl: Option<String>,
        creation_date: Timestamp,
    ) -> Result<Self, ApiError> {
        validate_policy(name, &statement)?;
        Ok(Self {
            name: name.to_owned(),
            creation_date,
            statement,
            acl,
        })
    }
}

/// Stored credentials. The secret is only ever held encrypted.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct CredentialRecord {
    pub access_key_id: String,
    pub username: String,
    pub user_id: i64,
    pub secret_ciphertext: Vec<u8>,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub creation_date: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    pub access_key_id: String,
    pub username: String,
    pub secret_ciphertext: Vec<u8>,
    pub creation_date: Timestamp,
}

impl NewCredential {
    /// Credentials with the secret sealed under the server's key. lakeFS
    /// imports keys of any shape, so a key without the lakeFS shape is only
    /// logged.
    pub fn sealed(
        username: &str,
        access_key_id: String,
        secret_access_key: &str,
        secrets: &SecretBox,
        creation_date: Timestamp,
    ) -> Result<Self, CryptoError> {
        if !is_well_formed_access_key_id(&access_key_id) {
            tracing::warn!(access_key_id = %access_key_id, "access key id does not have the lakeFS shape");
        }
        Ok(Self {
            access_key_id,
            username: username.to_owned(),
            secret_ciphertext: secrets.seal_str(secret_access_key)?,
            creation_date,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ExternalPrincipalRecord {
    pub id: String,
    pub username: String,
}

/// Everything a bootstrap file asks for, already validated and with secrets encrypted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapPlan {
    pub policies: Vec<NewPolicy>,
    pub groups: Vec<NewGroup>,
    pub users: Vec<NewUser>,
    /// `(group_id, username)`.
    pub memberships: Vec<(String, String)>,
    /// `(username, policy_name)`.
    pub user_policies: Vec<(String, String)>,
    /// `(group_id, policy_name)`.
    pub group_policies: Vec<(String, String)>,
    pub credentials: Vec<NewCredential>,
}

impl BootstrapPlan {
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
            && self.groups.is_empty()
            && self.users.is_empty()
            && self.memberships.is_empty()
            && self.user_policies.is_empty()
            && self.group_policies.is_empty()
            && self.credentials.is_empty()
    }
}

/// Rows created and rows that were already there. Bootstrap never updates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootstrapCounts {
    pub policies: u32,
    pub groups: u32,
    pub users: u32,
    pub memberships: u32,
    pub attachments: u32,
    pub credentials: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootstrapReport {
    pub created: BootstrapCounts,
    pub skipped: BootstrapCounts,
}

impl std::fmt::Display for BootstrapReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (c, s) = (&self.created, &self.skipped);
        write!(
            f,
            "policies {}/{} groups {}/{} users {}/{} memberships {}/{} attachments {}/{} credentials {}/{} (created/skipped)",
            c.policies,
            s.policies,
            c.groups,
            s.groups,
            c.users,
            s.users,
            c.memberships,
            s.memberships,
            c.attachments,
            s.attachments,
            c.credentials,
            s.credentials
        )
    }
}

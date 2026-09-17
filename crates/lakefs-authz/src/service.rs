//! Validation, key generation, encryption, and the conversion between store
//! records and the wire models. The handlers stay thin on top of this.

use jiff::Timestamp;
use lakefs_auth_core::crypto::{new_access_key_id, new_secret_access_key};
use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::model::{
    Base64Bytes, ClaimTokenId, Credentials, CredentialsWithSecret, ExternalPrincipal, Group, GroupCreation, Policy,
    Statement, User, UserCreation,
};
use lakefs_auth_core::text::non_blank;
use lakefs_auth_core::validate::validate_entity_id;

use crate::app::AppState;
use crate::store::error::{StoreError, StoreResult};
use crate::store::types::{
    CredentialRecord, ExternalPrincipalRecord, GroupRecord, NewCredential, NewGroup, NewPolicy, NewUser, PolicyRecord,
    UserFields, UserRecord,
};

/// First second of year 1. jiff itself reaches back to the year -9999, which
/// nothing here should accept; on the other side jiff's own end of the year
/// 9999 is the bound, and every client renders those years the same way.
const MIN_UNIX_SECONDS: i64 = -62_135_596_800;

/// Unix seconds on the wire, a [`Timestamp`] in the store. A value before
/// the year 1 or beyond the year 9999, such as milliseconds sent as seconds,
/// is a 400 that names the field, never a silent "now" and never a 500 from
/// the store.
pub fn from_unix(field: &str, seconds: i64) -> Result<Timestamp, ApiError> {
    let invalid = || ApiError::invalid(format!("{field} is not a valid unix timestamp: {seconds}"));
    if seconds < MIN_UNIX_SECONDS {
        return Err(invalid());
    }
    Timestamp::from_second(seconds).map_err(|_| invalid())
}

/// The outcome of a create. An insert that answered "already exists" is
/// decided from a re-read of the stored row: a row that `matches` is returned
/// as the created one, so that a repeated lakeFS setup succeeds; a different
/// row, or a row that vanished in between, is the original conflict; and a
/// failure of the re-read itself is that failure, never a 409.
async fn create_or_existing<T, Fut>(
    created: StoreResult<T>,
    reread: impl FnOnce() -> Fut,
    matches: impl FnOnce(&T) -> bool,
    entity: &str,
    id: &str,
) -> Result<T, ApiError>
where
    Fut: Future<Output = StoreResult<T>>,
{
    match created {
        Ok(created) => Ok(created),
        Err(conflict) if conflict.is_already_exists() => match reread().await {
            Ok(existing) if matches(&existing) => {
                tracing::info!(entity, id, "create matched the existing row; returned it");
                Ok(existing)
            }
            Ok(_) | Err(StoreError::NotFound { .. }) => Err(conflict.into()),
            Err(error) => Err(error.into()),
        },
        Err(error) => Err(error.into()),
    }
}

pub fn user_to_wire(record: UserRecord) -> User {
    User {
        username: record.username,
        creation_date: record.creation_date.as_second(),
        friendly_name: record.friendly_name,
        email: record.email,
        source: record.source,
        encrypted_password: record.encrypted_password.map(Base64Bytes),
        external_id: record.external_id,
    }
}

pub fn group_to_wire(record: GroupRecord) -> Group {
    Group {
        id: Some(record.id.clone()),
        name: record.id,
        description: record.description,
        creation_date: record.creation_date.as_second(),
    }
}

pub fn policy_to_wire(record: PolicyRecord) -> Policy {
    Policy {
        name: record.name,
        creation_date: Some(record.creation_date.as_second()),
        statement: record.statement,
        acl: record.acl,
    }
}

pub fn credentials_to_wire(record: &CredentialRecord) -> Credentials {
    Credentials {
        access_key_id: record.access_key_id.clone(),
        creation_date: record.creation_date.as_second(),
    }
}

/// The wire shape that carries the clear secret: a create answers with it, and
/// the credential lookup lakeFS makes per S3 request decrypts it.
fn with_secret(record: CredentialRecord, secret_access_key: String) -> CredentialsWithSecret {
    CredentialsWithSecret {
        access_key_id: record.access_key_id,
        secret_access_key,
        creation_date: record.creation_date.as_second(),
        user_id: record.user_id,
        user_name: Some(record.username),
    }
}

pub fn principal_to_wire(record: ExternalPrincipalRecord) -> ExternalPrincipal {
    ExternalPrincipal {
        user_id: record.username,
        id: record.id,
    }
}

/// `POST /auth/users`. `invite: true` is a 400: this server sends no email.
///
/// A create that repeats an existing user with the same content answers 201
/// with the stored row, so that a repeated lakeFS setup succeeds. A duplicate
/// with different content answers 409.
pub async fn create_user(state: &AppState, body: UserCreation) -> Result<User, ApiError> {
    if body.invite == Some(true) {
        return Err(ApiError::invalid(
            "invitations are not supported; create the user without invite",
        ));
    }
    let fields = UserFields {
        friendly_name: body.friendly_name,
        email: body.email,
        source: body.source,
        external_id: body.external_id,
        encrypted_password: body.encrypted_password.map(|bytes| bytes.0),
    };
    let requested = NewUser::validated(body.username, fields, Timestamp::now())?;
    let created = state.store.create_user(requested.clone()).await;
    let user = create_or_existing(
        created,
        || state.store.get_user(&requested.username),
        |existing| same_user(&requested, existing),
        "user",
        &requested.username,
    )
    .await?;
    Ok(user_to_wire(user))
}

/// True when every value the request specifies equals the stored one. Values
/// the request leaves out do not count, so the lakeFS setup, which sends the
/// username and the source only, matches an admin that gained an email later.
fn same_user(requested: &NewUser, existing: &UserRecord) -> bool {
    same_if_given(&requested.friendly_name, &existing.friendly_name)
        && same_if_given(&requested.email, &existing.email)
        && same_if_given(&requested.source, &existing.source)
        && same_if_given(&requested.external_id, &existing.external_id)
        && requested
            .encrypted_password
            .as_ref()
            .is_none_or(|password| existing.encrypted_password.as_deref() == Some(password.as_slice()))
}

fn same_if_given(requested: &Option<String>, existing: &Option<String>) -> bool {
    requested.is_none() || requested == existing
}

/// `POST /auth/groups`. lakeFS sends the group name in `id`. A repeated create
/// with the same description, or none, answers 201 with the stored row.
pub async fn create_group(state: &AppState, body: GroupCreation) -> Result<Group, ApiError> {
    let requested = NewGroup::validated(body.id, body.description, Timestamp::now())?;
    let created = state.store.create_group(requested.clone()).await;
    let group = create_or_existing(
        created,
        || state.store.get_group(&requested.id),
        |existing| same_if_given(&requested.description, &existing.description),
        "group",
        &requested.id,
    )
    .await?;
    Ok(group_to_wire(group))
}

/// `POST /auth/policies`. A repeated create with the same statements, in any
/// order, answers 201 with the stored row; different statements answer 409.
pub async fn create_policy(state: &AppState, body: Policy) -> Result<Policy, ApiError> {
    let name = body.name.clone();
    let requested = validated_policy(&name, body, Timestamp::now(), None)?;
    let created = state.store.create_policy(requested.clone()).await;
    let policy = create_or_existing(
        created,
        || state.store.get_policy(&name),
        |existing| same_policy(&requested, existing),
        "policy",
        &name,
    )
    .await?;
    Ok(policy_to_wire(policy))
}

/// True when the statements match as a set, ignoring the order of statements
/// and of actions, and the ACL matches when the request gives one.
fn same_policy(requested: &NewPolicy, existing: &PolicyRecord) -> bool {
    canonical_statements(&requested.statement) == canonical_statements(&existing.statement)
        && same_if_given(&requested.acl, &existing.acl)
}

fn canonical_statements(statements: &[Statement]) -> Vec<String> {
    let mut canonical: Vec<String> = statements
        .iter()
        .map(|statement| {
            let mut statement = statement.clone();
            statement.action.sort_unstable();
            serde_json::to_string(&statement).unwrap_or_default()
        })
        .collect();
    canonical.sort_unstable();
    canonical
}

/// `PUT /auth/policies/{policyId}`. The path parameter is the key; the body may repeat it.
///
/// The specification requires only `name` and `statement` in the body, so a
/// `creation_date` or `acl` the body leaves out keeps its stored value instead
/// of being reset to "now" or cleared.
pub async fn update_policy(state: &AppState, name: &str, body: Policy) -> Result<Policy, ApiError> {
    validate_entity_id("policy", name)?;
    let existing = state.store.get_policy(name).await?;
    let record = validated_policy(name, body, existing.creation_date, existing.acl)?;
    let updated = state.store.update_policy(record).await?;
    Ok(policy_to_wire(updated))
}

/// The record a body describes. `creation_date` and `acl` fall back to the
/// given values when the body leaves them out.
fn validated_policy(
    name: &str,
    body: Policy,
    fallback_creation_date: Timestamp,
    fallback_acl: Option<String>,
) -> Result<NewPolicy, ApiError> {
    let creation_date = match body.creation_date {
        Some(seconds) => from_unix("creation_date", seconds)?,
        None => fallback_creation_date,
    };
    NewPolicy::validated(name, body.statement, body.acl.or(fallback_acl), creation_date)
}

/// `POST /auth/users/{userId}/credentials`.
///
/// lakeFS sends no query parameters when it wants generated keys, and both when
/// it imports an existing pair. A value that is empty or whitespace counts as
/// missing on either side, and both values are stored trimmed.
pub async fn create_credentials(
    state: &AppState,
    username: &str,
    access_key: Option<&str>,
    secret_key: Option<&str>,
) -> Result<CredentialsWithSecret, ApiError> {
    let supplied = access_key.and_then(non_blank).zip(secret_key.and_then(non_blank));
    let (access_key_id, secret_access_key) = match supplied {
        Some((access, secret)) => (access.to_owned(), secret.to_owned()),
        None => (new_access_key_id(), new_secret_access_key()),
    };

    let record = NewCredential::sealed(
        username,
        access_key_id,
        &secret_access_key,
        &state.secrets,
        Timestamp::now(),
    )
    .map_err(|error| ApiError::internal(anyhow::anyhow!("encrypt credentials secret: {error}")))?;
    let created = state.store.create_credential(record).await?;
    Ok(with_secret(created, secret_access_key))
}

/// `GET /auth/credentials/{accessKeyId}`: the only place a secret is decrypted.
pub async fn credentials_with_secret(state: &AppState, access_key_id: &str) -> Result<CredentialsWithSecret, ApiError> {
    let record = state.store.get_credential(access_key_id).await?;
    let secret_access_key = state.secrets.open_str(&record.secret_ciphertext).map_err(|error| {
        ApiError::internal(anyhow::anyhow!(
            "decrypt credentials secret for {access_key_id}: {error}"
        ))
    })?;
    Ok(with_secret(record, secret_access_key))
}

/// `POST /auth/tokenid/claim`. A second claim of the same id is a 400.
pub async fn claim_token_id(state: &AppState, body: ClaimTokenId) -> Result<(), ApiError> {
    if body.token_id.is_empty() {
        return Err(ApiError::invalid("token_id must not be empty"));
    }
    let expires_at = from_unix("expires_at", body.expires_at)?;
    match state.store.claim_token_id(&body.token_id, expires_at).await {
        Ok(()) => Ok(()),
        Err(StoreError::AlreadyExists { .. }) => Err(ApiError::invalid("token id was already claimed")),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-read after a conflicting create must not hide its own failure
    /// behind the 409: a backend error is a 500, a mismatch and a vanished row
    /// stay 409.
    #[tokio::test]
    async fn a_failed_reread_after_a_conflict_is_not_reported_as_a_conflict() {
        let conflict = || Err(StoreError::already_exists("user", "alice"));
        let resolve = |reread: StoreResult<i32>| async {
            create_or_existing(conflict(), || async { reread }, |value| *value == 7, "user", "alice").await
        };

        let backend = Err(StoreError::backend(anyhow::anyhow!("pool exhausted")));
        let error = resolve(backend).await.expect_err("a backend error propagates");
        assert_eq!(error.status_code(), 500);

        assert_eq!(resolve(Ok(7)).await.expect("the row matches"), 7);

        let mismatch = resolve(Ok(8)).await.expect_err("mismatch");
        assert_eq!(mismatch.status_code(), 409);

        let gone = resolve(Err(StoreError::not_found("user", "alice")))
            .await
            .expect_err("vanished row");
        assert_eq!(gone.status_code(), 409);
    }

    #[test]
    fn out_of_range_unix_seconds_are_an_error() {
        assert!(from_unix("creation_date", 1_700_000_000).is_ok());
        let error = from_unix("expires_at", i64::MAX).expect_err("out of range");
        assert_eq!(error.status_code(), 400);
        assert!(error.to_string().contains("expires_at"), "{error}");
    }

    /// The store reaches back before the year 1 and jiff back to -9999, but
    /// every client renders only the years 1 through 9999 the same way, so
    /// the accepted range starts at year 1 and ends where jiff ends.
    #[test]
    fn unix_seconds_outside_the_storable_years_are_an_error() {
        assert!(from_unix("creation_date", -62_135_596_800).is_ok(), "0001-01-01");
        let last = Timestamp::MAX.as_second();
        assert!(from_unix("creation_date", last).is_ok(), "the last second jiff holds");
        for seconds in [
            -62_135_596_801,
            last + 1,
            253_402_300_800,
            -300_000_000_000,
            9_300_000_000_000,
        ] {
            let error = from_unix("expires_at", seconds).expect_err("out of range");
            assert_eq!(error.status_code(), 400, "{seconds}");
            assert!(error.to_string().contains("expires_at"), "{error}");
        }
    }
}

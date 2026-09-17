//! The SQLSTATE mapping of the PostgreSQL store.
//!
//! 23505 (unique violation) becomes `AlreadyExists` and therefore HTTP 409,
//! 23503 (foreign key violation) becomes `NotFound` for the reference and therefore 404.

use crate::store::error::StoreError;
use crate::store::types::{NewCredential, NewUser};

const UNIQUE_VIOLATION: &str = "23505";
const FOREIGN_KEY_VIOLATION: &str = "23503";

/// A constraint violation, with the name of the constraint, for example
/// `users_email_key` or `group_members_user_fk`.
enum Violation<'a> {
    Unique(&'a str),
    ForeignKey(&'a str),
}

fn violation(error: &sqlx::Error) -> Option<Violation<'_>> {
    let sqlx::Error::Database(db) = error else {
        return None;
    };
    let constraint = db.constraint().unwrap_or_default();
    match db.code().as_deref() {
        Some(UNIQUE_VIOLATION) => Some(Violation::Unique(constraint)),
        Some(FOREIGN_KEY_VIOLATION) => Some(Violation::ForeignKey(constraint)),
        _ => None,
    }
}

/// Turns a driver error into a store error. `unique` and `foreign_key` build
/// the message from the constraint name, because only the caller knows which
/// entity the statement was about.
pub fn map_error(
    error: sqlx::Error,
    unique: impl FnOnce(&str) -> StoreError,
    foreign_key: impl FnOnce(&str) -> StoreError,
) -> StoreError {
    match violation(&error) {
        Some(Violation::Unique(constraint)) => unique(constraint),
        Some(Violation::ForeignKey(constraint)) => foreign_key(constraint),
        None => StoreError::backend(error),
    }
}

/// [`map_error`] for a table without a foreign key: only a unique violation
/// has a meaning the caller can name.
pub fn map_unique(error: sqlx::Error, unique: impl FnOnce(&str) -> StoreError) -> StoreError {
    match violation(&error) {
        Some(Violation::Unique(constraint)) => unique(constraint),
        _ => StoreError::backend(error),
    }
}

/// Names the column of a unique violation on `users`: the email index, the
/// external id index, or the primary key.
pub fn user_conflict(constraint: &str, user: &NewUser) -> StoreError {
    if constraint.ends_with("_email_key") {
        StoreError::already_exists("user with email", user.email.as_deref().unwrap_or_default())
    } else if constraint.ends_with("_external_id_key") {
        StoreError::already_exists("user with external id", user.external_id.as_deref().unwrap_or_default())
    } else {
        StoreError::already_exists("user", &user.username)
    }
}

/// The mapping of a credentials insert, shared by the API and the bootstrap
/// transaction: the key is taken, or the user it names is gone.
pub fn credential_error(error: sqlx::Error, credential: &NewCredential) -> StoreError {
    map_error(
        error,
        |_| StoreError::already_exists("credentials", &credential.access_key_id),
        |constraint| missing_from_constraint(constraint, &[("user", &credential.username)]),
    )
}

/// Maps a violation of a constraint named `*_{entity}_fk` onto the reference
/// with that entity. `references` holds the rows the statement points at, as
/// `(entity, id)`; the first one is the answer for a constraint named otherwise.
pub fn missing_from_constraint(constraint: &str, references: &[(&'static str, &str)]) -> StoreError {
    let (entity, id) = references
        .iter()
        .find(|(entity, _)| constraint.ends_with(&format!("_{entity}_fk")))
        .or(references.first())
        .copied()
        .expect("a statement with a foreign key names at least one reference");
    StoreError::not_found(entity, id)
}

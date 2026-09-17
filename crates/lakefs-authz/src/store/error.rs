//! Errors every store implementation shares.

use lakefs_auth_core::error::ApiError;

/// What went wrong in the store.
///
/// A foreign key violation, where the row itself is fine but the user, group,
/// or policy it points at is gone, is `NotFound` for that reference. lakeFS
/// expects 404 for it, the same as for a missing row.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: String },
    #[error("{entity} already exists: {id}")]
    AlreadyExists { entity: &'static str, id: String },
    /// A bootstrap entry names a row that another identity created. Bootstrap
    /// never updates, so it must not grant that row the entry's memberships,
    /// policies, or credentials either.
    #[error("{entity} {id} exists with a different identity; bootstrap leaves it untouched")]
    WrongIdentity { entity: &'static str, id: String },
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

impl StoreError {
    pub fn not_found(entity: &'static str, id: impl Into<String>) -> Self {
        Self::NotFound { entity, id: id.into() }
    }

    pub fn already_exists(entity: &'static str, id: impl Into<String>) -> Self {
        Self::AlreadyExists { entity, id: id.into() }
    }

    pub fn wrong_identity(entity: &'static str, id: impl Into<String>) -> Self {
        Self::WrongIdentity { entity, id: id.into() }
    }

    pub fn backend(error: impl Into<anyhow::Error>) -> Self {
        Self::Backend(error.into())
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    pub fn is_already_exists(&self) -> bool {
        matches!(self, Self::AlreadyExists { .. })
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound { entity, id } => Self::not_found(entity, &id),
            StoreError::AlreadyExists { entity, id } => Self::already_exists(entity, &id),
            StoreError::WrongIdentity { .. } => Self::AlreadyExists(error.to_string()),
            StoreError::Backend(error) => Self::Internal(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_onto_the_http_statuses_lakefs_understands() {
        let cases = [
            (StoreError::not_found("user", "alice"), 404),
            (StoreError::already_exists("policy", "FSFullAccess"), 409),
            (StoreError::wrong_identity("user", "admin"), 409),
            (StoreError::backend(anyhow::anyhow!("boom")), 500),
        ];
        for (error, status) in cases {
            assert_eq!(ApiError::from(error).status_code(), status);
        }
    }
}

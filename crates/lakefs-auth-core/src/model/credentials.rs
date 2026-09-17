use serde::{Deserialize, Serialize};

/// Credentials without the secret, as listed per user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub access_key_id: String,
    /// Unix epoch seconds.
    pub creation_date: i64,
}

/// Credentials with the clear-text secret. lakeFS needs the secret to verify S3 signatures.
///
/// `user_id` is deprecated but required by the spec; `user_name` is what lakeFS uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsWithSecret {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Unix epoch seconds.
    pub creation_date: i64,
    pub user_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

use serde::{Deserialize, Serialize};

/// Body of `POST /auth/tokenid/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimTokenId {
    pub token_id: String,
    /// Unix epoch seconds.
    pub expires_at: i64,
}

use serde::{Deserialize, Serialize};

/// An external principal (for example an AWS IAM role ARN) attached to a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPrincipal {
    pub user_id: String,
    pub id: String,
}

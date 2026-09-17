use serde::{Deserialize, Serialize};

/// Body of `GET /config/version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionConfig {
    pub version: String,
}

/// Error body shared by both lakeFS APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub message: String,
}

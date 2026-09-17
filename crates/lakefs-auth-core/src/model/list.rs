use serde::{Deserialize, Serialize};

/// Largest page lakeFS asks for, and the value reported as `max_per_page`.
pub const MAX_PAGE: i64 = 1000;

/// Page size when a request carries no `amount`, the default the specification declares.
pub const DEFAULT_PAGE: i64 = 100;

/// Pagination block of every list response.
///
/// lakeFS reads only `next_offset` and `results`. It keeps paging while
/// `next_offset` is not empty, so the last page must carry an empty string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pagination {
    pub has_more: bool,
    pub next_offset: String,
    pub results: i64,
    pub max_per_page: i64,
}

/// Generic list response: `{"pagination": {...}, "results": [...]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub pagination: Pagination,
    pub results: Vec<T>,
}

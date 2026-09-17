//! Small text helpers both servers and the clients share.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// Everything but the unreserved characters of a URL path segment is encoded.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Trims `value` and drops it when nothing is left. Optional text is stored
/// and looked up through this one rule, so that a blank value is never a real
/// value that collides on a unique index or misses a trimmed lookup.
pub fn non_blank(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// `/api/v1`, `api/v1/`, and `/api/v1/` all become `/api/v1`; `/` and an empty
/// value mean "mount at the root". Both servers derive their mount point from
/// this rule, because lakeFS derives both endpoints the same way.
pub fn normalize_base_path(base_path: &str) -> String {
    let trimmed = base_path.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// One URL path segment, percent encoded, so that a name with a slash or a
/// space stays one segment.
pub fn path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_values_are_absent() {
        assert_eq!(non_blank(""), None);
        assert_eq!(non_blank("  "), None);
        assert_eq!(non_blank(" x "), Some("x"));
    }

    #[test]
    fn base_paths_are_normalized() {
        assert_eq!(normalize_base_path("/api/v1"), "/api/v1");
        assert_eq!(normalize_base_path("api/v1"), "/api/v1");
        assert_eq!(normalize_base_path("/api/v1/"), "/api/v1");
        assert_eq!(normalize_base_path("  /api/v1/  "), "/api/v1");
        assert_eq!(normalize_base_path("/"), "");
        assert_eq!(normalize_base_path(""), "");
    }

    #[test]
    fn path_segments_keep_only_unreserved_characters() {
        assert_eq!(path_segment("my repo/x"), "my%20repo%2Fx");
        assert_eq!(path_segment("plain-name_1.2~3"), "plain-name_1.2~3");
        assert_eq!(path_segment("alice@example.com"), "alice%40example.com");
    }
}

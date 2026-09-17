//! Pagination helpers for the `prefix` / `after` / `amount` contract.
//!
//! lakeFS keeps paging while `next_offset` is not empty and ignores `has_more`.
//! `PageOf::from_overfetch` derives both from a `limit + 1` fetch so that the
//! last page always carries an empty `next_offset`.

use serde::{Deserialize, Deserializer};

use crate::model::{DEFAULT_PAGE, ListResponse, MAX_PAGE, Pagination};
use crate::text::non_blank;

/// Query parameters as lakeFS sends them. An empty or unreadable `amount` is
/// treated as absent rather than rejected, because a 400 on a list would stop
/// the lakeFS setup sequence.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PaginationParams {
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default, deserialize_with = "deserialize_lenient_i64")]
    pub amount: Option<i64>,
}

/// Normalized page request. `limit` is always between 1 and [`MAX_PAGE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageQuery {
    pub prefix: String,
    pub after: String,
    pub limit: i64,
}

impl PageQuery {
    /// Number of rows to fetch so that `has_more` can be derived.
    pub fn fetch_limit(&self) -> i64 {
        self.limit + 1
    }
}

impl PaginationParams {
    /// Applies the specification: a missing amount means [`DEFAULT_PAGE`], and
    /// zero, a negative value, or a value above [`MAX_PAGE`] mean the maximum.
    pub fn normalize(self) -> PageQuery {
        let limit = match self.amount {
            None => DEFAULT_PAGE,
            Some(amount) if (1..=MAX_PAGE).contains(&amount) => amount,
            Some(_) => MAX_PAGE,
        };
        PageQuery {
            prefix: self.prefix.unwrap_or_default(),
            after: self.after.unwrap_or_default(),
            limit,
        }
    }
}

/// One page of results plus the cursor for the next page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageOf<T> {
    pub items: Vec<T>,
    pub next_offset: Option<String>,
}

impl<T> PageOf<T> {
    /// Builds a page from a `limit + 1` fetch. `key` returns the sort key of an item.
    pub fn from_overfetch(mut rows: Vec<T>, limit: i64, key: impl Fn(&T) -> String) -> Self {
        let limit = usize::try_from(limit.max(0)).unwrap_or(0);
        if rows.len() > limit {
            rows.truncate(limit);
            let next_offset = rows.last().map(key);
            Self {
                items: rows,
                next_offset,
            }
        } else {
            Self {
                items: rows,
                next_offset: None,
            }
        }
    }

    /// A page that is the whole result, so `next_offset` is empty.
    pub fn last(items: Vec<T>) -> Self {
        Self {
            items,
            next_offset: None,
        }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> PageOf<U> {
        PageOf {
            items: self.items.into_iter().map(f).collect(),
            next_offset: self.next_offset,
        }
    }

    /// Wire form. `has_more` follows `next_offset`, never the other way round.
    pub fn into_response(self) -> ListResponse<T> {
        let results = i64::try_from(self.items.len()).unwrap_or(i64::MAX);
        ListResponse {
            pagination: Pagination {
                has_more: self.next_offset.is_some(),
                next_offset: self.next_offset.unwrap_or_default(),
                results,
                max_per_page: MAX_PAGE,
            },
            results: self.items,
        }
    }
}

/// Why a cursor walk stopped early.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CursorError {
    #[error("the server repeated the cursor {0:?}")]
    Repeated(String),
    #[error("the listing spans more than {0} pages")]
    TooManyPages(u32),
}

/// Follows `next_offset` cursors on behalf of a client that collects every
/// page. A cursor that repeats and a walk beyond `max_pages` are errors, so a
/// server or proxy that misbehaves cannot spin the caller forever.
#[derive(Debug)]
pub struct CursorWalk {
    after: String,
    pages: u32,
    max_pages: u32,
}

impl CursorWalk {
    pub fn new(max_pages: u32) -> Self {
        Self {
            after: String::new(),
            pages: 0,
            max_pages,
        }
    }

    /// The `after` value of the next request.
    pub fn after(&self) -> &str {
        &self.after
    }

    /// Records the page just read. `Ok(true)` asks for another page with
    /// [`Self::after`]; `Ok(false)` means the listing is complete. lakeFS keeps
    /// paging while `next_offset` is not empty and ignores `has_more`, and so
    /// does this.
    pub fn advance(&mut self, next_offset: &str) -> Result<bool, CursorError> {
        self.pages += 1;
        if next_offset.is_empty() {
            return Ok(false);
        }
        if next_offset == self.after {
            return Err(CursorError::Repeated(next_offset.to_owned()));
        }
        if self.pages >= self.max_pages {
            return Err(CursorError::TooManyPages(self.max_pages));
        }
        self.after = next_offset.to_owned();
        Ok(true)
    }
}

/// Pages an iterator that is already sorted ascending by key. Only the rows
/// of the page are cloned, never the rows the prefix and cursor skip.
pub fn page_sorted<'a, T: Clone + 'a>(
    sorted: impl IntoIterator<Item = (&'a str, &'a T)>,
    query: &PageQuery,
) -> PageOf<T> {
    let fetch = usize::try_from(query.fetch_limit()).unwrap_or(usize::MAX);
    let rows: Vec<(&str, T)> = sorted
        .into_iter()
        .filter(|(key, _)| key.starts_with(&query.prefix) && *key > query.after.as_str())
        .take(fetch)
        .map(|(key, item)| (key, item.clone()))
        .collect();
    PageOf::from_overfetch(rows, query.limit, |(key, _)| (*key).to_owned()).map(|(_, item)| item)
}

/// Escapes `\`, `%`, and `_` so that a prefix can be used in `LIKE ... ESCAPE '\'`.
pub fn escape_like_prefix(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + 4);
    for ch in prefix.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `amount` as a number, or `None` when it is absent, empty, or not an integer.
fn parse_amount(raw: Option<&str>) -> Option<i64> {
    raw.and_then(non_blank).and_then(|value| value.parse().ok())
}

/// A query integer that is absent when empty or unreadable, never a 400.
pub fn deserialize_lenient_i64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    let raw: Option<String> = Option::deserialize(deserializer)?;
    Ok(parse_amount(raw.as_deref()))
}

/// A query flag such as `effective=true`. Only `true` and `1`, in any case
/// and with padding, are true; everything else, including an absent value,
/// is false.
pub fn deserialize_lenient_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let raw: Option<String> = Option::deserialize(deserializer)?;
    Ok(raw
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn params(query: &str) -> PaginationParams {
        serde_urlencoded::from_str(query).unwrap()
    }

    /// The specification gives `amount` a default of 100; `0`, `-1`, and an
    /// oversized value mean the maximum. An unreadable value counts as absent
    /// rather than as a 400, because a rejected list would stop lakeFS setup.
    #[test]
    fn normalize_follows_lakefs_rules() {
        assert_eq!(params("").normalize().limit, DEFAULT_PAGE);
        assert_eq!(params("amount=").normalize().limit, DEFAULT_PAGE);
        assert_eq!(params("amount=nonsense").normalize().limit, DEFAULT_PAGE);
        assert_eq!(params("amount=0").normalize().limit, MAX_PAGE);
        assert_eq!(params("amount=-1").normalize().limit, MAX_PAGE);
        assert_eq!(params("amount=50").normalize().limit, 50);
        assert_eq!(params("amount=%2025%20").normalize().limit, 25, "padding is trimmed");
        assert_eq!(params("amount=5000").normalize().limit, MAX_PAGE);
        let q = params("prefix=ab&after=abc&amount=2").normalize();
        assert_eq!(
            q,
            PageQuery {
                prefix: "ab".into(),
                after: "abc".into(),
                limit: 2
            }
        );
    }

    #[test]
    fn exact_limit_has_no_next_offset() {
        let page = PageOf::from_overfetch(vec!["a", "b"], 2, |s| s.to_string());
        assert_eq!(page.next_offset, None);
        let response = page.into_response();
        assert!(!response.pagination.has_more);
        assert_eq!(response.pagination.next_offset, "");
        assert_eq!(response.pagination.results, 2);
    }

    #[test]
    fn overfetch_sets_cursor_to_last_returned_key() {
        let page = PageOf::from_overfetch(vec!["a", "b", "c"], 2, |s| s.to_string());
        assert_eq!(page.items, vec!["a", "b"]);
        assert_eq!(page.next_offset.as_deref(), Some("b"));
        assert!(page.into_response().pagination.has_more);
    }

    #[test]
    fn page_sorted_applies_prefix_and_exclusive_after() {
        let items = ["_x", "A", "Z", "a", "ab", "abc", "z"];
        let sorted = items.iter().map(|key| (*key, key));
        let q = PageQuery {
            prefix: "a".into(),
            after: "a".into(),
            limit: 1,
        };
        let page = page_sorted(sorted, &q);
        assert_eq!(page.items, vec!["ab"]);
        assert_eq!(page.next_offset.as_deref(), Some("ab"));
    }

    #[test]
    fn like_prefix_is_escaped() {
        assert_eq!(escape_like_prefix(r"a%b_c\d"), r"a\%b\_c\\d");
    }

    #[test]
    fn a_cursor_walk_follows_cursors_until_the_last_page() {
        let mut walk = CursorWalk::new(20);
        assert_eq!(walk.after(), "");
        assert_eq!(walk.advance("b"), Ok(true));
        assert_eq!(walk.after(), "b");
        assert_eq!(walk.advance(""), Ok(false));
    }

    #[test]
    fn a_cursor_walk_refuses_a_repeated_cursor_and_too_many_pages() {
        let mut stuck = CursorWalk::new(20);
        assert_eq!(stuck.advance("x"), Ok(true));
        assert_eq!(stuck.advance("x"), Err(CursorError::Repeated("x".to_owned())));

        let mut endless = CursorWalk::new(3);
        assert_eq!(endless.advance("a"), Ok(true));
        assert_eq!(endless.advance("b"), Ok(true));
        assert_eq!(endless.advance("c"), Err(CursorError::TooManyPages(3)));
    }
}

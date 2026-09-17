//! A read-only lakeFS client that acts as the person using the policy builder.
//!
//! It holds no credentials. Each call carries the `internal_auth_session`
//! cookie that the caller's browser already has from signing in to lakeFS, so
//! lakeFS resolves the request to that user and applies their own policies.
//! The builder therefore never shows more than the person may already see.
//!
//! Cookies are not scoped by port, so a browser that signed in to lakeFS on
//! `example.com:8000` also sends the cookie to a builder on `example.com:8080`.
//! Across different hosts, set `--cookie-domain` on `lakefs-authn` to a shared
//! parent domain.

use std::time::Duration;

use lakefs_auth_core::model::{ErrorBody, ListResponse};
use lakefs_auth_core::pagination::{CursorError, CursorWalk};
use lakefs_auth_core::text::path_segment;
use reqwest::StatusCode;
use reqwest::header::{COOKIE, HeaderValue};
use serde::{Deserialize, Serialize};

/// The lakeFS session cookie. lakeFS accepts it as `cookie_auth` on every API route.
pub use lakefs_auth_core::SESSION_COOKIE;

/// Entries per request. lakeFS caps `amount` at 1000.
const PAGE_AMOUNT: u32 = 1000;

/// Pages to follow before stopping, so a huge installation cannot stall a
/// request. The names only feed autocompletion, so a cut list is fine.
const MAX_PAGES: u32 = 20;

#[derive(Debug, thiserror::Error)]
pub enum LakeFsError {
    #[error("build lakeFS client: {0}")]
    Build(#[source] reqwest::Error),
    #[error("call lakeFS: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("the lakeFS session may not read {path}")]
    Forbidden { path: String },
    #[error("lakeFS rejected the request: {message}")]
    Rejected { status: StatusCode, message: String },
    #[error("lakeFS returned {status} for {path}")]
    Status { status: StatusCode, path: String },
    #[error("lakeFS pagination of {path} did not advance: {error}")]
    Pagination { path: String, error: CursorError },
}

/// The caller's lakeFS session, taken from their request to the builder and
/// kept as the `Cookie` header value to send on, built once per request
/// rather than once per page fetched.
#[derive(Clone)]
pub struct Session(HeaderValue);

impl Session {
    /// Reads `internal_auth_session` out of a `Cookie` header. A value that
    /// cannot travel in a header is no session.
    pub fn from_cookie_header(header: &str) -> Option<Self> {
        let value = header.split(';').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name.trim() == SESSION_COOKIE).then(|| value.trim())
        })?;
        HeaderValue::from_str(&format!("{SESSION_COOKIE}={value}"))
            .ok()
            .map(Self)
    }

    /// The `Cookie` header to send to lakeFS.
    fn header(&self) -> HeaderValue {
        self.0.clone()
    }
}

/// Endpoint and HTTP client. The identity comes from the [`Session`] per call.
#[derive(Clone)]
pub struct LakeFsClient {
    http: reqwest::Client,
    /// Endpoint including the API prefix, such as `http://lakefs:8000/api/v1`.
    endpoint: String,
}

/// Repositories, branches, groups, and policies all carry their name in `id`.
#[derive(Deserialize)]
struct Named {
    id: String,
}

/// The caller lakeFS resolved the session to.
#[derive(Deserialize)]
struct CurrentUser {
    user: Named,
}

/// The body of `POST /auth/policies`. lakeFS names the policy `id` and sets
/// `creation_date` itself when it is left out.
#[derive(Serialize)]
struct NewPolicy<'a> {
    id: &'a str,
    statement: &'a [lakefs_auth_core::model::Statement],
}

impl LakeFsClient {
    /// Builds a client. `endpoint` may end with a slash; the trailing slash is dropped.
    pub fn new(endpoint: &str, timeout: Duration) -> Result<Self, LakeFsError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(LakeFsError::Build)?;
        Ok(Self {
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// The user name lakeFS resolves the session to. This is how the builder
    /// checks that a session is real before it serves anything.
    pub async fn current_user(&self, session: &Session) -> Result<String, LakeFsError> {
        let body: CurrentUser = self.get("/user", session).await?;
        Ok(body.user.id)
    }

    /// Every repository the caller may see. lakeFS filters the list by their policies.
    pub async fn repositories(&self, session: &Session) -> Result<Vec<String>, LakeFsError> {
        self.list_names("/repositories", session).await
    }

    /// Every branch of one repository the caller may see.
    pub async fn branches(&self, repository: &str, session: &Session) -> Result<Vec<String>, LakeFsError> {
        let path = format!("/repositories/{}/branches", path_segment(repository));
        self.list_names(&path, session).await
    }

    /// User, group, and policy names, as far as the caller may read them.
    ///
    /// lakeFS applies `auth:ListUsers`, `auth:ListGroups`, and `auth:ListPolicies`
    /// here, so a caller without those permissions gets empty lists rather than
    /// an error. The builder only uses these names for autocompletion.
    pub async fn names(&self, session: &Session) -> Result<(Vec<String>, Vec<String>, Vec<String>), LakeFsError> {
        // The three lists are independent, so the page waits for the slowest
        // walk rather than for the sum of the three.
        tokio::try_join!(
            self.list_names_or_empty("/auth/users", session),
            self.list_names_or_empty("/auth/groups", session),
            self.list_names_or_empty("/auth/policies", session),
        )
    }

    /// Creates a policy as the caller.
    ///
    /// lakeFS enforces `auth:CreatePolicy`, so this can only do what the person
    /// could already do in the lakeFS user interface. It returns the name lakeFS
    /// stored, which is the confirmation the page shows.
    pub async fn create_policy(
        &self,
        name: &str,
        statement: &[lakefs_auth_core::model::Statement],
        session: &Session,
    ) -> Result<String, LakeFsError> {
        let response = self
            .http
            .post(format!("{}/auth/policies", self.endpoint))
            .header(COOKIE, session.header())
            .json(&NewPolicy { id: name, statement })
            .send()
            .await
            .map_err(LakeFsError::Transport)?;

        let status = response.status();
        if status == StatusCode::CREATED {
            let created: Named = response.json().await.map_err(LakeFsError::Transport)?;
            return Ok(created.id);
        }
        // Pass the reason through: "policy already exists" and a validation
        // complaint are both worth showing verbatim.
        let message = response
            .json::<ErrorBody>()
            .await
            .map(|body| body.message)
            .unwrap_or_else(|_| format!("lakeFS answered {status}"));
        Err(LakeFsError::Rejected { status, message })
    }

    async fn list_names_or_empty(&self, path: &str, session: &Session) -> Result<Vec<String>, LakeFsError> {
        match self.list_names(path, session).await {
            Err(LakeFsError::Forbidden { .. }) => Ok(Vec::new()),
            other => other,
        }
    }

    /// Follows `next_offset` until lakeFS reports no more, or [`MAX_PAGES`] is
    /// reached. A cursor that repeats is an error: the list would never end.
    async fn list_names(&self, path: &str, session: &Session) -> Result<Vec<String>, LakeFsError> {
        let mut names = Vec::new();
        let mut walk = CursorWalk::new(MAX_PAGES);
        loop {
            let query = format!("?amount={PAGE_AMOUNT}&after={}", path_segment(walk.after()));
            let page: ListResponse<Named> = self.get(&format!("{path}{query}"), session).await?;
            names.extend(page.results.into_iter().map(|item| item.id));
            match walk.advance(&page.pagination.next_offset) {
                Ok(true) => {}
                Ok(false) | Err(CursorError::TooManyPages(_)) => return Ok(names),
                Err(error) => {
                    return Err(LakeFsError::Pagination {
                        path: path.to_owned(),
                        error,
                    });
                }
            }
        }
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str, session: &Session) -> Result<T, LakeFsError> {
        let response = self
            .http
            .get(format!("{}{path}", self.endpoint))
            .header(COOKIE, session.header())
            .send()
            .await
            .map_err(LakeFsError::Transport)?;

        // lakeFS answers 401 both for an expired session and for a missing
        // permission, so the two are told apart by whether the session resolves.
        let status = response.status();
        let route = path.split('?').next().unwrap_or(path).to_owned();
        match status {
            StatusCode::OK => response.json().await.map_err(LakeFsError::Transport),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(LakeFsError::Forbidden { path: route }),
            status => Err(LakeFsError::Status { status, path: route }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_slash_on_the_endpoint_is_dropped() {
        let client = LakeFsClient::new("http://lakefs:8000/api/v1/", Duration::from_secs(5)).expect("build client");
        assert_eq!(client.endpoint, "http://lakefs:8000/api/v1");
    }

    #[test]
    fn the_session_is_picked_out_of_a_cookie_header() {
        let header = "other=1; internal_auth_session=abc123; FERRISKEY_SESSION=zz";
        let session = Session::from_cookie_header(header).expect("the session cookie is there");
        assert_eq!(session.header(), "internal_auth_session=abc123");
    }

    #[test]
    fn a_header_without_the_session_yields_nothing() {
        assert!(Session::from_cookie_header("other=1; FERRISKEY_SESSION=zz").is_none());
        assert!(Session::from_cookie_header("").is_none());
        // A cookie whose name merely ends with the session name must not match.
        assert!(Session::from_cookie_header("not_internal_auth_session=abc").is_none());
    }
}

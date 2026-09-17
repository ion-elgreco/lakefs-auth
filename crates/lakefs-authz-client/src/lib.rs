//! Async client for the lakeFS authorization API (`api/authorization.yml`).
//!
//! The authentication server uses it to provision users after an OIDC login.
//! Requests carry the same bearer token lakeFS would send, either a static
//! token or the HS256 token lakeFS mints from the shared secret.

use std::borrow::Cow;
use std::time::Duration;

use lakefs_auth_core::auth::{EncodingKey, mint_internal_token};
use lakefs_auth_core::model::{
    CredentialsWithSecret, ErrorBody, FriendlyNameUpdate, Group, ListResponse, User, UserCreation, VersionConfig,
};
use lakefs_auth_core::pagination::CursorWalk;
use lakefs_auth_core::text::path_segment;
use lakefs_auth_core::validate::validate_entity_id;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use url::Url;

/// Lifetime of the internal token. One is minted per request, so a captured
/// token is worth minutes, not the whole process lifetime.
const INTERNAL_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);
const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);
/// Pages [`AuthzClient::list_user_groups`] follows before it gives up.
const MAX_PAGES: u32 = 20;

/// How the client authenticates toward the authorization server.
#[derive(Clone)]
pub enum ClientAuth {
    /// A static bearer token, the value of lakeFS `auth.api.token`.
    Static(String),
    /// Mint the token lakeFS mints from `auth.encrypt.secret_key`, with the
    /// signing key prepared once; see [`ClientAuth::internal_jwt`].
    InternalJwt(EncodingKey),
    /// No bearer token. Only for servers that run with authentication disabled.
    None,
}

impl ClientAuth {
    /// Mint the internal token from the shared secret on every request.
    pub fn internal_jwt(secret: &[u8]) -> Self {
        Self::InternalJwt(EncodingKey::from_secret(secret))
    }
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(_) => f.write_str("ClientAuth::Static(..)"),
            Self::InternalJwt(_) => f.write_str("ClientAuth::InternalJwt(..)"),
            Self::None => f.write_str("ClientAuth::None"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthzClientConfig {
    /// Base URL including the `/api/v1` prefix, for example `http://authz:8002/api/v1`.
    pub endpoint: Url,
    pub auth: ClientAuth,
    pub timeout: Duration,
    /// Retries on transport errors and 5xx responses.
    pub max_retries: u32,
}

impl AuthzClientConfig {
    pub fn new(endpoint: Url, auth: ClientAuth) -> Self {
        Self {
            endpoint,
            auth,
            timeout: Duration::from_secs(10),
            max_retries: 2,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid client configuration: {0}")]
    Config(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("authorization API rejected the request: {0}")]
    BadRequest(String),
    #[error("authorization API rejected the bearer token")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("more than one user matched the lookup")]
    NonUnique,
    #[error("invalid identifier: {0}")]
    InvalidId(String),
    #[error("pagination did not terminate: {0}")]
    Pagination(String),
    #[error("authorization API returned status {status}: {message}")]
    Status { status: u16, message: String },
    #[error("unexpected response body: {0}")]
    Decode(String),
}

/// What a user should look like after an identity provider login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureUserSpec {
    pub external_id: String,
    pub username: String,
    pub email: Option<String>,
    pub friendly_name: Option<String>,
    pub source: String,
    /// Groups a newly created user joins. Existing users are not re-synced.
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsuredUser {
    pub user: User,
    pub created: bool,
}

#[derive(Clone)]
pub struct AuthzClient {
    http: reqwest::Client,
    base: Url,
    auth: ClientAuth,
    max_retries: u32,
}

impl std::fmt::Debug for AuthzClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthzClient")
            .field("base", &self.base.as_str())
            .field("auth", &self.auth)
            .finish()
    }
}

impl AuthzClient {
    pub fn new(config: AuthzClientConfig) -> Result<Self, ClientError> {
        let mut base = config.endpoint;
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let http = reqwest::Client::builder().timeout(config.timeout).build()?;
        Ok(Self {
            http,
            base,
            auth: config.auth,
            max_retries: config.max_retries,
        })
    }

    /// The bearer token of one request: the static token, or a fresh internal token.
    fn bearer(&self) -> Result<Option<Cow<'_, str>>, ClientError> {
        match &self.auth {
            ClientAuth::Static(token) => Ok(Some(Cow::Borrowed(token))),
            ClientAuth::InternalJwt(key) => mint_internal_token(key, INTERNAL_TOKEN_TTL)
                .map(|token| Some(Cow::Owned(token)))
                .map_err(|err| ClientError::Config(format!("cannot mint internal token: {err}"))),
            ClientAuth::None => Ok(None),
        }
    }

    /// `GET /healthcheck`, expects 204.
    pub async fn healthcheck(&self) -> Result<(), ClientError> {
        let response = self.send(Method::GET, "healthcheck", None).await?;
        expect_status(response, StatusCode::NO_CONTENT).await.map(|_| ())
    }

    /// `GET /config/version`.
    pub async fn version(&self) -> Result<VersionConfig, ClientError> {
        let response = self.send(Method::GET, "config/version", None).await?;
        decode_json(expect_status(response, StatusCode::OK).await?).await
    }

    /// `GET /auth/users/{userId}`. Returns `None` on 404.
    pub async fn get_user(&self, username: &str) -> Result<Option<User>, ClientError> {
        let response = self
            .send(Method::GET, &format!("auth/users/{}", segment(username)?), None)
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        decode_json(expect_status(response, StatusCode::OK).await?)
            .await
            .map(Some)
    }

    /// `GET /auth/users?external_id=...`. Returns `None` when no user matches.
    pub async fn find_user_by_external_id(&self, external_id: &str) -> Result<Option<User>, ClientError> {
        self.find_user("external_id", external_id).await
    }

    /// `GET /auth/users?email=...`. Returns `None` when no user matches.
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, ClientError> {
        self.find_user("email", email).await
    }

    /// A blank value never reaches the server: the server reads it as "no
    /// filter" and would list everyone, which is not a lookup.
    async fn find_user(&self, filter: &str, value: &str) -> Result<Option<User>, ClientError> {
        if value.trim().is_empty() {
            return Ok(None);
        }
        let query = [(filter, value), ("amount", "2")];
        let response = self.send(Method::GET, "auth/users", Some(&query)).await?;
        let list: ListResponse<User> = decode_json(expect_status(response, StatusCode::OK).await?).await?;
        let mut results = list.results.into_iter();
        match (results.next(), results.next()) {
            (None, _) => Ok(None),
            (Some(user), None) => Ok(Some(user)),
            (Some(_), Some(_)) => Err(ClientError::NonUnique),
        }
    }

    /// `POST /auth/users`, expects 201.
    pub async fn create_user(&self, user: &UserCreation) -> Result<User, ClientError> {
        let response = self.send_json(Method::POST, "auth/users", user).await?;
        decode_json(expect_status(response, StatusCode::CREATED).await?).await
    }

    /// `DELETE /auth/users/{userId}`, expects 204.
    pub async fn delete_user(&self, username: &str) -> Result<(), ClientError> {
        let response = self
            .send(Method::DELETE, &format!("auth/users/{}", segment(username)?), None)
            .await?;
        expect_status(response, StatusCode::NO_CONTENT).await.map(|_| ())
    }

    /// `PUT /auth/users/{userId}/friendly_name`, expects 204.
    pub async fn update_friendly_name(&self, username: &str, friendly_name: &str) -> Result<(), ClientError> {
        let body = FriendlyNameUpdate {
            friendly_name: friendly_name.to_owned(),
        };
        let response = self
            .send_json(
                Method::PUT,
                &format!("auth/users/{}/friendly_name", segment(username)?),
                &body,
            )
            .await?;
        expect_status(response, StatusCode::NO_CONTENT).await.map(|_| ())
    }

    /// `PUT /auth/groups/{groupId}/members/{userId}`, expects 201. 409 maps to `AlreadyExists`.
    pub async fn add_group_membership(&self, group_id: &str, username: &str) -> Result<(), ClientError> {
        let path = format!("auth/groups/{}/members/{}", segment(group_id)?, segment(username)?);
        let response = self.send(Method::PUT, &path, None).await?;
        expect_status(response, StatusCode::CREATED).await.map(|_| ())
    }

    /// All groups of a user, following pagination.
    ///
    /// The walk stops with an error when a cursor repeats or after [`MAX_PAGES`]
    /// pages, so a server or proxy that misbehaves cannot spin this forever.
    pub async fn list_user_groups(&self, username: &str) -> Result<Vec<Group>, ClientError> {
        let path = format!("auth/users/{}/groups", segment(username)?);
        let mut walk = CursorWalk::new(MAX_PAGES);
        let mut groups = Vec::new();
        loop {
            let query = [("after", walk.after()), ("amount", "1000")];
            let response = self.send(Method::GET, &path, Some(&query)).await?;
            let page: ListResponse<Group> = decode_json(expect_status(response, StatusCode::OK).await?).await?;
            groups.extend(page.results);
            let more = walk
                .advance(&page.pagination.next_offset)
                .map_err(|error| ClientError::Pagination(format!("{error} for the groups of {username}")))?;
            if !more {
                return Ok(groups);
            }
        }
    }

    /// `POST /auth/users/{userId}/credentials` with server-generated keys, expects 201.
    pub async fn create_credentials(&self, username: &str) -> Result<CredentialsWithSecret, ClientError> {
        let path = format!("auth/users/{}/credentials", segment(username)?);
        let response = self.send(Method::POST, &path, None).await?;
        decode_json(expect_status(response, StatusCode::CREATED).await?).await
    }

    /// Finds the user by external id, creates it when missing, and adds a new user to its groups.
    pub async fn ensure_user(&self, spec: &EnsureUserSpec) -> Result<EnsuredUser, ClientError> {
        if let Some(user) = self.find_user_by_external_id(&spec.external_id).await? {
            return Ok(EnsuredUser { user, created: false });
        }
        self.create_user_with_groups(spec).await
    }

    /// Creates the user of `spec` and adds it to its groups, for a caller that
    /// already looked the identity up and found nothing.
    ///
    /// A 409 on create means a concurrent login won the race, and the user is
    /// read back; or another identity holds the email, and the user is created
    /// without it; or the username belongs to another identity, which is an
    /// error. A 409 on a membership means the user is already in the group. A
    /// missing group is logged and skipped, because with lenient group mapping
    /// an identity provider group that lakeFS does not know is expected. Any
    /// other membership failure deletes the user again, so that the next login
    /// retries the whole create instead of finding a user with no groups.
    pub async fn create_user_with_groups(&self, spec: &EnsureUserSpec) -> Result<EnsuredUser, ClientError> {
        let mut creation = UserCreation {
            username: spec.username.clone(),
            email: spec.email.clone(),
            friendly_name: spec.friendly_name.clone(),
            source: Some(spec.source.clone()),
            encrypted_password: None,
            external_id: Some(spec.external_id.clone()),
            invite: None,
        };
        let user = match self.create_user(&creation).await {
            Ok(user) => user,
            Err(ClientError::AlreadyExists) => {
                if let Some(user) = self.find_user_by_external_id(&spec.external_id).await? {
                    return Ok(EnsuredUser { user, created: false });
                }
                match self.email_holder(spec).await? {
                    Some(holder) => {
                        tracing::warn!(
                            username = %spec.username,
                            holder = %holder.username,
                            "another user holds this email; creating the user without it"
                        );
                        creation.email = None;
                        // A second 409 is a real username collision and propagates.
                        self.create_user(&creation).await?
                    }
                    // The username belongs to another identity.
                    None => return Err(ClientError::AlreadyExists),
                }
            }
            Err(other) => return Err(other),
        };
        for group in &spec.groups {
            match self.add_group_membership(group, &user.username).await {
                Ok(()) | Err(ClientError::AlreadyExists) => {}
                Err(ClientError::NotFound) => {
                    tracing::warn!(group = %group, username = %user.username, "initial group does not exist");
                }
                Err(other) => {
                    self.roll_back_create(&user.username).await;
                    return Err(other);
                }
            }
        }
        Ok(EnsuredUser { user, created: true })
    }

    /// The user that holds the email of `spec`, if it is another identity.
    async fn email_holder(&self, spec: &EnsureUserSpec) -> Result<Option<User>, ClientError> {
        let Some(email) = spec.email.as_deref() else {
            return Ok(None);
        };
        Ok(self
            .find_user_by_email(email)
            .await?
            .filter(|user| user.external_id.as_deref() != Some(spec.external_id.as_str())))
    }

    /// Deletes a user whose creation could not be completed. Best effort: a
    /// failure here is logged, and the user keeps existing without groups.
    async fn roll_back_create(&self, username: &str) {
        match self.delete_user(username).await {
            Ok(()) | Err(ClientError::NotFound) => {
                tracing::warn!(username = %username, "rolled back the user create after a group assignment failed");
            }
            Err(error) => {
                tracing::error!(
                    username = %username,
                    error = %error,
                    "could not roll back the user create; the user exists without its groups"
                );
            }
        }
    }

    async fn send(&self, method: Method, path: &str, query: Option<&[(&str, &str)]>) -> Result<Response, ClientError> {
        let url = self.url(path)?;
        self.send_with_retry(&method, || {
            let mut request = self.http.request(method.clone(), url.clone());
            if let Some(query) = query {
                request = request.query(query);
            }
            request
        })
        .await
    }

    async fn send_json<T: serde::Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: &T,
    ) -> Result<Response, ClientError> {
        let url = self.url(path)?;
        self.send_with_retry(&method, || self.http.request(method.clone(), url.clone()).json(body))
            .await
    }

    /// Sends with retries. An idempotent request is retried on a connection
    /// failure, a timeout, a transport error, and a 5xx. A `POST` is retried only
    /// when the connection could not be made, because after that the server may
    /// have committed: a replayed credential create would mint a second pair.
    async fn send_with_retry(
        &self,
        method: &Method,
        build: impl Fn() -> RequestBuilder,
    ) -> Result<Response, ClientError> {
        let idempotent = matches!(
            *method,
            Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS
        );
        let mut attempt = 0u32;
        loop {
            let mut request = build();
            if let Some(bearer) = self.bearer()? {
                request = request.bearer_auth(bearer);
            }
            let outcome = request.send().await;
            let retryable = match &outcome {
                Ok(response) => idempotent && response.status().is_server_error(),
                Err(error) => error.is_connect() || (idempotent && (error.is_timeout() || error.is_request())),
            };
            if retryable && attempt < self.max_retries {
                attempt += 1;
                let delay = RETRY_BASE_DELAY * 2u32.saturating_pow(attempt - 1);
                tracing::debug!(attempt, "retrying authorization API request");
                tokio::time::sleep(delay).await;
                continue;
            }
            return Ok(outcome?);
        }
    }

    fn url(&self, path: &str) -> Result<Url, ClientError> {
        self.base
            .join(path)
            .map_err(|err| ClientError::Config(format!("invalid path {path}: {err}")))
    }
}

/// One path segment, percent encoded, under the entity id rule of the server:
/// what the server would refuse with a 400 never leaves the client. The dot
/// segments would also collapse the path when joined onto the base URL, so
/// `auth/users/../groups` would list every group instead of one user.
fn segment(value: &str) -> Result<String, ClientError> {
    validate_entity_id("entity", value).map_err(|error| ClientError::InvalidId(error.to_string()))?;
    Ok(path_segment(value))
}

async fn expect_status(response: Response, expected: StatusCode) -> Result<Response, ClientError> {
    let status = response.status();
    if status == expected {
        return Ok(response);
    }
    let message = response
        .json::<ErrorBody>()
        .await
        .map(|body| body.message)
        .unwrap_or_default();
    Err(match status {
        StatusCode::BAD_REQUEST => ClientError::BadRequest(message),
        StatusCode::UNAUTHORIZED => ClientError::Unauthorized,
        StatusCode::NOT_FOUND => ClientError::NotFound,
        StatusCode::CONFLICT => ClientError::AlreadyExists,
        other => ClientError::Status {
            status: other.as_u16(),
            message,
        },
    })
}

async fn decode_json<T: DeserializeOwned>(response: Response) -> Result<T, ClientError> {
    let bytes = response.bytes().await?;
    serde_json::from_slice(&bytes).map_err(|err| ClientError::Decode(err.to_string()))
}

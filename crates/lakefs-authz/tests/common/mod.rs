//! Shared harness: an in-process server over `MemStore` plus the fixtures of
//! the lakeFS setup sequence.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt as _;
use lakefs_auth_core::auth::{EncodingKey, TokenVerifier, mint_internal_token};
use lakefs_auth_core::crypto::SecretBox;
use lakefs_authz::app::{AppState, RouterOptions, build_router};
use lakefs_authz::store::{MemStore, Store};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Stands in for lakeFS `auth.encrypt.secret_key`.
pub const SECRET: &str = "lakefs-authz integration secret";
pub const BASE: &str = "/api/v1";

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Response {
    /// One header as text, when it is present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "expected a JSON body, got {:?}: {error}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub fn message(&self) -> String {
        self.json()["message"].as_str().unwrap_or_default().to_owned()
    }
}

/// A server over `MemStore`, driven through `tower::ServiceExt::oneshot`.
pub struct TestServer {
    router: Router,
    pub store: Arc<dyn Store>,
    /// The same store, typed, for the test knobs `MemStore` offers.
    pub mem: Arc<MemStore>,
    pub token: String,
}

impl TestServer {
    pub fn new() -> Self {
        Self::with_options(RouterOptions::default().with_base_path(BASE))
    }

    pub fn with_options(options: RouterOptions) -> Self {
        let mem = Arc::new(MemStore::new());
        let store: Arc<dyn Store> = Arc::clone(&mem) as Arc<dyn Store>;
        let state = AppState::new(
            Arc::clone(&store),
            SecretBox::derive(SECRET.as_bytes()),
            TokenVerifier::new(Some(SECRET), None, false).expect("verifier"),
        );
        let router = build_router(state, &options);
        let token = internal_token(SECRET);
        Self {
            router,
            store,
            mem,
            token,
        }
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub async fn send(&self, request: Request<Body>) -> Response {
        call(&self.router, request).await
    }

    /// An authorized request under the base path. `body` is the content type
    /// and the bytes, when there is one.
    fn build(&self, method: &str, path: &str, body: Option<(&str, Vec<u8>)>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{BASE}{path}"))
            .header("authorization", format!("Bearer {}", self.token));
        let body = match body {
            Some((content_type, bytes)) => {
                builder = builder.header("content-type", content_type);
                Body::from(bytes)
            }
            None => Body::empty(),
        };
        builder.body(body).expect("build request")
    }

    fn build_json(&self, method: &str, path: &str, body: Value) -> Request<Body> {
        let bytes = serde_json::to_vec(&body).expect("serialize body");
        self.build(method, path, Some(("application/json", bytes)))
    }

    pub async fn get(&self, path: &str) -> Response {
        self.send(self.build("GET", path, None)).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Response {
        self.send(self.build_json("POST", path, body)).await
    }

    pub async fn post_empty(&self, path: &str) -> Response {
        self.send(self.build("POST", path, None)).await
    }

    pub async fn put(&self, path: &str) -> Response {
        self.send(self.build("PUT", path, None)).await
    }

    pub async fn put_json(&self, path: &str, body: Value) -> Response {
        self.send(self.build_json("PUT", path, body)).await
    }

    pub async fn delete(&self, path: &str) -> Response {
        self.send(self.build("DELETE", path, None)).await
    }

    /// A request with an arbitrary body and content type, for the malformed-body cases.
    pub async fn send_raw(&self, method: &str, path: &str, content_type: &str, body: &str) -> Response {
        self.send(self.build(method, path, Some((content_type, body.as_bytes().to_vec()))))
            .await
    }

    /// A request without the base path, for the root-level probes.
    pub async fn get_root(&self, path: &str) -> Response {
        let request = Request::builder().uri(path).body(Body::empty()).expect("build request");
        self.send(request).await
    }

    /// Replays what lakeFS does on `POST /api/v1/setup_lakefs` with `rbac: internal`.
    pub async fn run_lakefs_setup(&self) {
        for group in GROUPS {
            let response = self.post("/auth/groups", json!({ "id": group })).await;
            assert_eq!(response.status, StatusCode::CREATED, "create group {group}");
        }
        for policy in base_policies() {
            let name = policy["name"].clone();
            let response = self.post("/auth/policies", policy).await;
            assert_eq!(response.status, StatusCode::CREATED, "create policy {name}");
        }
        for (group, policy) in ATTACHMENTS {
            let response = self.put(&format!("/auth/groups/{group}/policies/{policy}")).await;
            assert_eq!(response.status, StatusCode::CREATED, "attach {policy} to {group}");
        }
        let response = self
            .post("/auth/users", json!({ "username": "admin", "source": "internal" }))
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "create admin");
        let response = self.put("/auth/groups/Admins/members/admin").await;
        assert_eq!(response.status, StatusCode::CREATED, "admin joins Admins");
    }
}

/// Builds a router over a fresh `MemStore` with a caller-supplied verifier.
/// Used by the authentication tests, which need other token configurations.
pub fn router_with(verifier: TokenVerifier, base_path: &str) -> Router {
    let state = AppState::new(
        Arc::new(MemStore::new()),
        SecretBox::derive(SECRET.as_bytes()),
        verifier,
    );
    build_router(state, &RouterOptions::default().with_base_path(base_path))
}

/// Sends one request through a router built by [`router_with`].
pub async fn call(router: &Router, request: Request<Body>) -> Response {
    let response = router.clone().oneshot(request).await.expect("router call");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    Response { status, headers, body }
}

/// One string field of every item in a list response.
pub fn names(list: &Value, field: &str) -> Vec<String> {
    list["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|item| item[field].as_str().expect("string field").to_owned())
        .collect()
}

/// A bearer token lakeFS would mint from the shared secret.
pub fn internal_token(secret: &str) -> String {
    mint_internal_token(&EncodingKey::from_secret(secret.as_bytes()), Duration::from_secs(3600)).expect("mint token")
}

/// The groups lakeFS creates, in order.
pub const GROUPS: &[&str] = &["Admins", "SuperUsers", "Developers", "Viewers"];

/// The 16 group to policy attachments lakeFS creates, in order.
pub const ATTACHMENTS: &[(&str, &str)] = &[
    ("Admins", "FSFullAccess"),
    ("Admins", "CatalogReadWriteAll"),
    ("Admins", "AuthFullAccess"),
    ("Admins", "RepoManagementFullAccess"),
    ("SuperUsers", "FSFullAccess"),
    ("SuperUsers", "CatalogReadWriteAll"),
    ("SuperUsers", "AuthManageOwnCredentials"),
    ("SuperUsers", "RepoManagementReadAll"),
    ("Developers", "FSReadWriteAll"),
    ("Developers", "PRReadWriteAll"),
    ("Developers", "CatalogReadWriteAll"),
    ("Developers", "AuthManageOwnCredentials"),
    ("Developers", "RepoManagementReadAll"),
    ("Viewers", "FSReadAll"),
    ("Viewers", "CatalogReadAll"),
    ("Viewers", "AuthManageOwnCredentials"),
];

/// The names of the 10 policies, sorted the way a list returns them.
pub const POLICY_NAMES_SORTED: &[&str] = &[
    "AuthFullAccess",
    "AuthManageOwnCredentials",
    "CatalogReadAll",
    "CatalogReadWriteAll",
    "FSFullAccess",
    "FSReadAll",
    "FSReadWriteAll",
    "PRReadWriteAll",
    "RepoManagementFullAccess",
    "RepoManagementReadAll",
];

fn allow(actions: &[&str], resource: &str) -> Value {
    json!([{ "effect": "allow", "action": actions, "resource": resource }])
}

/// The exact policy bodies lakeFS sends during setup, from `pkg/auth/base.go`
/// and `pkg/auth/setup/setup.go` of v1.86.0.
pub fn base_policies() -> Vec<Value> {
    vec![
        json!({ "name": "FSFullAccess", "statement": allow(&["fs:*"], "*") }),
        json!({
            "name": "FSReadWriteAll",
            "statement": allow(
                &[
                    "fs:Read*",
                    "fs:List*",
                    "fs:WriteObject",
                    "fs:DeleteObject",
                    "fs:RevertBranch",
                    "fs:CreateBranch",
                    "fs:CreateTag",
                    "fs:DeleteBranch",
                    "fs:DeleteTag",
                    "fs:CreateCommit",
                ],
                "*",
            )
        }),
        json!({ "name": "FSReadAll", "statement": allow(&["fs:List*", "fs:Read*"], "*") }),
        json!({
            "name": "RepoManagementFullAccess",
            "statement": allow(&["ci:*", "retention:*", "branches:*", "pr:*", "fs:ReadConfig"], "*")
        }),
        json!({ "name": "PRReadWriteAll", "statement": allow(&["pr:*"], "*") }),
        json!({
            "name": "CatalogReadAll",
            "statement": allow(
                &[
                    "catalog:ListNamespaces",
                    "catalog:GetNamespace",
                    "catalog:ListTables",
                    "catalog:ReadTable",
                    "catalog:ListViews",
                    "catalog:ReadView",
                ],
                "*",
            )
        }),
        json!({ "name": "CatalogReadWriteAll", "statement": allow(&["catalog:*"], "*") }),
        json!({
            "name": "RepoManagementReadAll",
            "statement": allow(
                &["ci:Read*", "retention:Get*", "branches:Get*", "pr:Read*", "pr:List*", "fs:ReadConfig"],
                "*",
            )
        }),
        json!({ "name": "AuthFullAccess", "statement": allow(&["auth:*"], "*") }),
        json!({
            "name": "AuthManageOwnCredentials",
            "statement": allow(
                &[
                    "auth:CreateCredentials",
                    "auth:DeleteCredentials",
                    "auth:ListCredentials",
                    "auth:ReadCredentials",
                ],
                "arn:lakefs:auth:::user/${user}",
            )
        }),
    ]
}

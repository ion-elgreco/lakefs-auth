//! The bootstrap file: one transaction, create only what is missing, and the
//! result is visible through the API.

mod common;

use axum::http::StatusCode;
use common::{SECRET, TestServer, names};
use lakefs_auth_core::crypto::SecretBox;
use lakefs_authz::bootstrap;

const FILE: &str = r#"
version: 1
policies:
  - name: ReadOnly
    statement:
      - effect: allow
        action: ["fs:Read*", "fs:List*"]
        resource: "*"
  - name: OwnCredentials
    statement:
      - effect: allow
        action: ["auth:CreateCredentials", "auth:ListCredentials"]
        resource: "arn:lakefs:auth:::user/${user}"
groups:
  - id: Readers
    description: read only access
    policies: [ReadOnly, OwnCredentials]
users:
  - username: alice
    email: alice@example.com
    friendly_name: Alice
    source: internal
    groups: [Readers]
    policies: [OwnCredentials]
    credentials:
      - access_key_id: AKIAJBOOTSTRAPKEYQ
        secret_access_key: bootstrap-secret
"#;

fn secrets() -> SecretBox {
    SecretBox::derive(SECRET.as_bytes())
}

#[tokio::test]
async fn a_bootstrap_file_creates_everything_once() {
    let server = TestServer::new();
    let plan = bootstrap::parse_plan(FILE, &secrets()).expect("parse");

    let first = bootstrap::apply(server.store.as_ref(), &plan).await.expect("apply");
    assert_eq!(first.created.policies, 2);
    assert_eq!(first.created.groups, 1);
    assert_eq!(first.created.users, 1);
    assert_eq!(first.created.memberships, 1);
    assert_eq!(first.created.attachments, 3, "two on the group, one on the user");
    assert_eq!(first.created.credentials, 1);
    assert_eq!(first.skipped, Default::default());

    // Everything is reachable over the API.
    let user = server.get("/auth/users/alice").await;
    assert_eq!(user.status, StatusCode::OK);
    assert_eq!(user.json()["email"], "alice@example.com");
    assert_eq!(user.json()["friendly_name"], "Alice");
    assert_eq!(user.json()["source"], "internal");

    let groups = server.get("/auth/users/alice/groups").await;
    assert_eq!(groups.json()["results"][0]["name"], "Readers");

    let effective = server.get("/auth/users/alice/policies?effective=true").await;
    assert_eq!(names(&effective.json(), "name"), ["OwnCredentials", "ReadOnly"]);

    // The stored secret decrypts with the configured key.
    let credentials = server.get("/auth/credentials/AKIAJBOOTSTRAPKEYQ").await;
    assert_eq!(credentials.status, StatusCode::OK);
    assert_eq!(credentials.json()["secret_access_key"], "bootstrap-secret");
    assert_eq!(credentials.json()["user_name"], "alice");
}

#[tokio::test]
async fn a_second_run_reports_every_row_as_skipped() {
    let server = TestServer::new();
    let plan = bootstrap::parse_plan(FILE, &secrets()).expect("parse");

    bootstrap::apply(server.store.as_ref(), &plan).await.expect("first run");
    let second = bootstrap::apply(server.store.as_ref(), &plan)
        .await
        .expect("second run");

    assert_eq!(second.created, Default::default(), "nothing new");
    assert_eq!(second.skipped.policies, 2);
    assert_eq!(second.skipped.groups, 1);
    assert_eq!(second.skipped.users, 1);
    assert_eq!(second.skipped.memberships, 1);
    assert_eq!(second.skipped.attachments, 3);
    assert_eq!(second.skipped.credentials, 1);

    let summary = format!("{second}");
    assert!(summary.contains("created/skipped"), "{summary}");

    let policies = server.get("/auth/policies").await;
    assert_eq!(policies.json()["pagination"]["results"], 2, "no duplicates");
}

#[tokio::test]
async fn bootstrap_never_overwrites_an_existing_row() {
    let server = TestServer::new();
    server
        .post(
            "/auth/users",
            serde_json::json!({ "username": "alice", "friendlyName": "Set by the API" }),
        )
        .await;

    let plan = bootstrap::parse_plan(FILE, &secrets()).expect("parse");
    let report = bootstrap::apply(server.store.as_ref(), &plan).await.expect("apply");
    assert_eq!(report.skipped.users, 1);
    assert_eq!(report.created.users, 0);

    let user = server.get("/auth/users/alice").await;
    assert_eq!(
        user.json()["friendly_name"],
        "Set by the API",
        "bootstrap never updates"
    );
    // The row is the same identity (no external id on either side), so the
    // entry's memberships, attachments, and credentials still apply to it.
    assert_eq!(report.created.memberships, 1);
    assert_eq!(report.created.credentials, 1);
    let groups = server.get("/auth/users/alice/groups").await;
    assert_eq!(groups.json()["results"][0]["name"], "Readers");
    assert_eq!(
        server.get("/auth/credentials/AKIAJBOOTSTRAPKEYQ").await.status,
        StatusCode::OK
    );
}

/// An identity provider login that claimed the name first must not inherit the
/// groups, policies, and access key of a bootstrap entry written later.
#[tokio::test]
async fn bootstrap_refuses_to_decorate_a_user_that_belongs_to_another_identity() {
    let server = TestServer::new();
    let claimed = server
        .post(
            "/auth/users",
            serde_json::json!({ "username": "alice", "source": "oidc", "external_id": "attacker-sub" }),
        )
        .await;
    assert_eq!(claimed.status, StatusCode::CREATED);

    let plan = bootstrap::parse_plan(FILE, &secrets()).expect("parse");
    let error = bootstrap::apply(server.store.as_ref(), &plan)
        .await
        .expect_err("the plan must be refused");
    assert!(format!("{error:#}").contains("alice"), "{error:#}");

    let groups = server.get("/auth/users/alice/groups").await;
    assert_eq!(groups.json()["pagination"]["results"], 0, "no group was granted");
    let policies = server.get("/auth/users/alice/policies").await;
    assert_eq!(policies.json()["pagination"]["results"], 0, "no policy was attached");
    assert_eq!(
        server.get("/auth/credentials/AKIAJBOOTSTRAPKEYQ").await.status,
        StatusCode::NOT_FOUND,
        "the operator's access key was not bound to the attacker's row"
    );
    assert_eq!(
        server.get("/auth/groups/Readers").await.status,
        StatusCode::NOT_FOUND,
        "the failed plan rolled back as a whole"
    );
}

#[tokio::test]
async fn a_file_on_disk_is_read_and_validated() {
    let path = std::env::temp_dir().join(format!("lakefs-authz-bootstrap-{}.yaml", uuid::Uuid::new_v4()));
    std::fs::write(&path, FILE).expect("write bootstrap file");
    let plan = bootstrap::load_plan(&path, &secrets()).expect("load");
    assert_eq!(plan.users.len(), 1);
    std::fs::remove_file(&path).expect("clean up");

    let missing = bootstrap::load_plan(std::path::Path::new("/nonexistent/bootstrap.yaml"), &secrets());
    assert!(missing.is_err(), "a missing file is an error");
}

#[tokio::test]
async fn an_empty_plan_is_a_no_op() {
    let server = TestServer::new();
    let plan = bootstrap::parse_plan("{}", &secrets()).expect("parse an empty document");
    assert!(plan.is_empty());
    let report = bootstrap::apply(server.store.as_ref(), &plan).await.expect("apply");
    assert_eq!(report, Default::default());
}

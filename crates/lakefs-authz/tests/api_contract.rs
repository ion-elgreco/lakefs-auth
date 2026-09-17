//! The HTTP contract lakeFS relies on: the setup sequence, the status codes of
//! every route, the body shapes, and the pagination invariants.

mod common;

use axum::http::StatusCode;
use common::{ATTACHMENTS, GROUPS, POLICY_NAMES_SORTED, TestServer, base_policies, names};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

#[tokio::test]
async fn health_and_version_answer_what_lakefs_needs() {
    let server = TestServer::new();

    let health = server.get("/healthcheck").await;
    assert_eq!(health.status, StatusCode::NO_CONTENT);
    assert!(health.body.is_empty());

    let version = server.get("/config/version").await;
    assert_eq!(version.status, StatusCode::OK);
    assert_eq!(version.json(), json!({ "version": env!("CARGO_PKG_VERSION") }));
}

#[tokio::test]
async fn lakefs_setup_sequence_replays_end_to_end() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let groups = server.get("/auth/groups").await;
    assert_eq!(groups.status, StatusCode::OK);
    let mut expected: Vec<String> = GROUPS.iter().map(|g| (*g).to_owned()).collect();
    expected.sort();
    assert_eq!(names(&groups.json(), "name"), expected);
    assert_eq!(groups.json()["pagination"]["next_offset"], "");
    assert_eq!(groups.json()["pagination"]["has_more"], false);
    assert_eq!(groups.json()["pagination"]["max_per_page"], 1000);
    assert_eq!(groups.json()["pagination"]["results"], 4);

    // lakeFS re-reads the Admins group to check that setup worked.
    let admins = server.get("/auth/groups/Admins").await;
    assert_eq!(admins.status, StatusCode::OK);
    assert_eq!(admins.json()["id"], "Admins");
    assert_eq!(admins.json()["name"], "Admins");
    assert!(admins.json()["creation_date"].is_i64());

    let policies = server.get("/auth/policies").await;
    assert_eq!(names(&policies.json(), "name"), POLICY_NAMES_SORTED);

    // The 16 attachments landed on the right groups.
    for group in GROUPS {
        let attached = server.get(&format!("/auth/groups/{group}/policies")).await;
        assert_eq!(attached.status, StatusCode::OK);
        let mut expected: Vec<String> = ATTACHMENTS
            .iter()
            .filter(|(g, _)| g == group)
            .map(|(_, p)| (*p).to_owned())
            .collect();
        expected.sort();
        assert_eq!(names(&attached.json(), "name"), expected, "policies of {group}");
    }

    let members = server.get("/auth/groups/Admins/members").await;
    assert_eq!(names(&members.json(), "username"), vec!["admin"]);
    let admin_groups = server.get("/auth/users/admin/groups").await;
    assert_eq!(names(&admin_groups.json(), "name"), vec!["Admins"]);

    // A policy body is echoed back exactly as it was sent, plus a creation date.
    let stored = server.get("/auth/policies/AuthManageOwnCredentials").await;
    let sent = base_policies()
        .into_iter()
        .find(|p| p["name"] == "AuthManageOwnCredentials")
        .expect("fixture");
    assert_eq!(stored.json()["statement"], sent["statement"]);
    assert!(stored.json()["creation_date"].is_i64());
}

#[tokio::test]
async fn effective_policies_page_until_the_offset_is_empty() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let direct = server.get("/auth/users/admin/policies").await;
    assert_eq!(direct.status, StatusCode::OK);
    assert!(names(&direct.json(), "name").is_empty(), "nothing is attached directly");

    // The walk lakeFS performs, with a page size that divides the result exactly.
    let mut seen = Vec::new();
    let mut after = String::new();
    let mut pages = 0;
    loop {
        let path = format!("/auth/users/admin/policies?effective=true&amount=2&after={after}");
        let response = server.get(&path).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = response.json();
        seen.extend(names(&body, "name"));
        pages += 1;
        assert!(pages < 10, "the walk must terminate");
        let next = body["pagination"]["next_offset"]
            .as_str()
            .expect("next_offset")
            .to_owned();
        assert_eq!(
            body["pagination"]["has_more"],
            !next.is_empty(),
            "has_more must follow next_offset"
        );
        if next.is_empty() {
            break;
        }
        after = next;
    }
    assert_eq!(
        seen,
        vec![
            "AuthFullAccess",
            "CatalogReadWriteAll",
            "FSFullAccess",
            "RepoManagementFullAccess"
        ]
    );
    assert_eq!(pages, 2, "four policies in pages of two");
}

#[tokio::test]
async fn credentials_carry_the_secret_user_id_and_user_name() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let created = server.post_empty("/auth/users/admin/credentials").await;
    assert_eq!(created.status, StatusCode::CREATED);
    let body = created.json();
    let access_key_id = body["access_key_id"].as_str().expect("access key").to_owned();
    let secret = body["secret_access_key"].as_str().expect("secret").to_owned();
    assert!(access_key_id.starts_with("AKIAJ") && access_key_id.ends_with('Q'));
    assert_eq!(access_key_id.len(), 20);
    assert_eq!(secret.len(), 40);
    assert_eq!(body["user_name"], "admin");
    assert!(body["user_id"].as_i64().expect("user_id") > 0);
    assert!(body["creation_date"].is_i64());

    // The hot path returns the decrypted secret with both identifiers.
    let fetched = server.get(&format!("/auth/credentials/{access_key_id}")).await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.json()["secret_access_key"], secret);
    assert_eq!(fetched.json()["user_name"], "admin");
    assert_eq!(fetched.json()["user_id"], body["user_id"]);

    // The per-user view never carries a secret.
    let scoped = server
        .get(&format!("/auth/users/admin/credentials/{access_key_id}"))
        .await;
    assert_eq!(scoped.status, StatusCode::OK);
    assert_eq!(scoped.json()["access_key_id"], access_key_id);
    assert!(scoped.json().get("secret_access_key").is_none());

    let listed = server.get("/auth/users/admin/credentials").await;
    assert_eq!(names(&listed.json(), "access_key_id"), vec![access_key_id.clone()]);

    let deleted = server
        .delete(&format!("/auth/users/admin/credentials/{access_key_id}"))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = server.get(&format!("/auth/credentials/{access_key_id}")).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn supplied_keys_are_stored_and_partial_input_generates_both() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let supplied = server
        .post_empty("/auth/users/admin/credentials?access_key=AKIAJTESTTESTTESTQ&secret_key=my-secret")
        .await;
    assert_eq!(supplied.status, StatusCode::CREATED);
    assert_eq!(supplied.json()["access_key_id"], "AKIAJTESTTESTTESTQ");
    assert_eq!(supplied.json()["secret_access_key"], "my-secret");
    let fetched = server.get("/auth/credentials/AKIAJTESTTESTTESTQ").await;
    assert_eq!(fetched.json()["secret_access_key"], "my-secret");

    // An empty value on either side means "generate both".
    let generated = server
        .post_empty("/auth/users/admin/credentials?access_key=&secret_key=")
        .await;
    assert_eq!(generated.status, StatusCode::CREATED);
    assert_ne!(generated.json()["access_key_id"], "AKIAJTESTTESTTESTQ");

    let half = server
        .post_empty("/auth/users/admin/credentials?access_key=AKIAJOTHERKEYHEREQ")
        .await;
    assert_eq!(half.status, StatusCode::CREATED);
    assert_ne!(half.json()["access_key_id"], "AKIAJOTHERKEYHEREQ");

    let duplicate = server
        .post_empty("/auth/users/admin/credentials?access_key=AKIAJTESTTESTTESTQ&secret_key=other")
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn the_user_body_always_carries_encrypted_password() {
    let server = TestServer::new();
    let created = server
        .post(
            "/auth/users",
            json!({ "username": "alice", "email": "alice@example.com", "friendlyName": "Alice",
                    "source": "oidc", "external_id": "sub-1" }),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let body = created.json();
    assert_eq!(body["username"], "alice");
    assert_eq!(body["friendly_name"], "Alice", "the response uses snake_case");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["source"], "oidc");
    assert_eq!(body["external_id"], "sub-1");
    assert!(
        body.as_object().expect("object").contains_key("encryptedPassword"),
        "the key must be present because the spec marks it required"
    );
    assert_eq!(body["encryptedPassword"], Value::Null);

    let listed = server.get("/auth/users").await;
    let first = &listed.json()["results"][0];
    assert!(first.as_object().expect("object").contains_key("encryptedPassword"));

    // An encrypted password round trips as base64.
    let with_password = server
        .post(
            "/auth/users",
            json!({ "username": "bob", "encryptedPassword": "aGVsbG8=" }),
        )
        .await;
    assert_eq!(with_password.json()["encryptedPassword"], "aGVsbG8=");
}

#[tokio::test]
async fn user_lookups_return_at_most_one_result() {
    let server = TestServer::new();
    server
        .post(
            "/auth/users",
            json!({ "username": "alice", "email": "alice@example.com", "external_id": "sub-1" }),
        )
        .await;
    let bob = server
        .post("/auth/users", json!({ "username": "bob", "email": "bob@example.com" }))
        .await;
    assert_eq!(bob.status, StatusCode::CREATED);

    let by_email = server.get("/auth/users?email=alice@example.com").await;
    assert_eq!(by_email.status, StatusCode::OK);
    assert_eq!(names(&by_email.json(), "username"), vec!["alice"]);

    let by_external = server.get("/auth/users?external_id=sub-1").await;
    assert_eq!(names(&by_external.json(), "username"), vec!["alice"]);

    // lakeFS looks a user up by the numeric identity column.
    let credentials = server.post_empty("/auth/users/alice/credentials").await;
    let user_id = credentials.json()["user_id"].as_i64().expect("user_id");
    let by_id = server.get(&format!("/auth/users?id={user_id}")).await;
    assert_eq!(names(&by_id.json(), "username"), vec!["alice"]);

    for query in [
        "?email=nobody@example.com",
        "?external_id=nosuchsub",
        "?id=999999",
        "?id=not-a-number",
    ] {
        let response = server.get(&format!("/auth/users{query}")).await;
        assert_eq!(response.status, StatusCode::OK, "{query} must not be an error");
        assert_eq!(response.json()["results"], json!([]), "{query}");
        assert_eq!(response.json()["pagination"]["next_offset"], "", "{query}");
        assert_eq!(response.json()["pagination"]["has_more"], false, "{query}");
    }
}

#[tokio::test]
async fn listing_honours_prefix_after_and_amount() {
    let server = TestServer::new();
    for name in ["p-a", "p-b", "p-c", "q-a"] {
        server.post("/auth/users", json!({ "username": name })).await;
    }

    let all = server.get("/auth/users").await;
    assert_eq!(names(&all.json(), "username"), vec!["p-a", "p-b", "p-c", "q-a"]);

    let prefixed = server.get("/auth/users?prefix=p-").await;
    assert_eq!(names(&prefixed.json(), "username"), vec!["p-a", "p-b", "p-c"]);

    let first = server.get("/auth/users?prefix=p-&amount=2").await;
    assert_eq!(names(&first.json(), "username"), vec!["p-a", "p-b"]);
    assert_eq!(first.json()["pagination"]["next_offset"], "p-b");
    assert_eq!(first.json()["pagination"]["has_more"], true);

    let second = server.get("/auth/users?prefix=p-&after=p-b&amount=2").await;
    assert_eq!(names(&second.json(), "username"), vec!["p-c"]);
    assert_eq!(second.json()["pagination"]["next_offset"], "");

    // An amount outside 1..=1000 means the maximum, and an empty one too.
    for query in ["?amount=0", "?amount=-1", "?amount=5000", "?amount="] {
        let response = server.get(&format!("/auth/users{query}")).await;
        assert_eq!(response.status, StatusCode::OK, "{query}");
        assert_eq!(response.json()["pagination"]["results"], 4, "{query}");
    }
}

#[tokio::test]
async fn creates_conflict_and_validation_failures_use_the_right_codes() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    // 409 on every duplicate create whose content differs from the stored row.
    assert_eq!(
        server
            .post(
                "/auth/groups",
                json!({ "id": "Admins", "description": "not the stored one" })
            )
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        server
            .post(
                "/auth/users",
                json!({ "username": "admin", "email": "admin@example.com" })
            )
            .await
            .status,
        StatusCode::CONFLICT
    );
    let mut changed = base_policies()[0].clone();
    changed["statement"] = json!([{ "effect": "deny", "action": ["fs:*"], "resource": "*" }]);
    assert_eq!(
        server.post("/auth/policies", changed).await.status,
        StatusCode::CONFLICT
    );

    // 400 on anything the API refuses.
    let invited = server
        .post("/auth/users", json!({ "username": "invitee", "invite": true }))
        .await;
    assert_eq!(invited.status, StatusCode::BAD_REQUEST);
    assert!(invited.message().contains("invitation"), "{}", invited.message());

    assert_eq!(
        server.post("/auth/users", json!({ "username": "a/b" })).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        server.post("/auth/groups", json!({ "id": "" })).await.status,
        StatusCode::BAD_REQUEST
    );
    let bad_action = json!({
        "name": "Bad",
        "statement": [{ "effect": "allow", "action": ["nosuch:Thing"], "resource": "*" }]
    });
    assert_eq!(
        server.post("/auth/policies", bad_action).await.status,
        StatusCode::BAD_REQUEST
    );
    let empty_statement = json!({ "name": "Empty", "statement": [] });
    assert_eq!(
        server.post("/auth/policies", empty_statement).await.status,
        StatusCode::BAD_REQUEST
    );
    let bad_resource = json!({
        "name": "BadResource",
        "statement": [{ "effect": "allow", "action": ["fs:*"], "resource": "not-an-arn" }]
    });
    assert_eq!(
        server.post("/auth/policies", bad_resource).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn missing_entities_answer_404() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let gets = [
        "/auth/users/nobody",
        "/auth/groups/nogroup",
        "/auth/policies/nopolicy",
        "/auth/credentials/AKIAJNOSUCHKEYXXXQ",
        "/auth/users/nobody/groups",
        "/auth/users/nobody/policies",
        "/auth/users/nobody/policies?effective=true",
        "/auth/users/nobody/credentials",
        "/auth/users/admin/credentials/AKIAJNOSUCHKEYXXXQ",
        "/auth/groups/nogroup/members",
        "/auth/groups/nogroup/policies",
    ];
    for path in gets {
        let response = server.get(path).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "GET {path}");
        assert!(!response.message().is_empty(), "GET {path} needs a message");
    }

    let puts = [
        "/auth/groups/nogroup/members/admin",
        "/auth/groups/Admins/members/nobody",
        "/auth/users/nobody/policies/FSFullAccess",
        "/auth/users/admin/policies/nopolicy",
        "/auth/groups/nogroup/policies/FSFullAccess",
        "/auth/groups/Admins/policies/nopolicy",
    ];
    for path in puts {
        assert_eq!(server.put(path).await.status, StatusCode::NOT_FOUND, "PUT {path}");
    }

    let deletes = [
        "/auth/users/nobody",
        "/auth/groups/nogroup",
        "/auth/policies/nopolicy",
        "/auth/groups/Admins/members/nobody",
        "/auth/users/admin/policies/FSFullAccess",
        "/auth/groups/Viewers/policies/FSFullAccess",
        "/auth/users/admin/credentials/AKIAJNOSUCHKEYXXXQ",
    ];
    for path in deletes {
        assert_eq!(server.delete(path).await.status, StatusCode::NOT_FOUND, "DELETE {path}");
    }

    assert_eq!(
        server.post_empty("/auth/users/nobody/credentials").await.status,
        StatusCode::NOT_FOUND
    );
    let update = server
        .put_json("/auth/policies/nopolicy", base_policies()[0].clone())
        .await;
    assert_eq!(update.status, StatusCode::NOT_FOUND);
    let rename = server
        .put_json("/auth/users/nobody/friendly_name", json!({ "friendly_name": "x" }))
        .await;
    assert_eq!(rename.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deletes_detaches_and_renames_answer_204() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let rename = server
        .put_json(
            "/auth/users/admin/friendly_name",
            json!({ "friendly_name": "Administrator" }),
        )
        .await;
    assert_eq!(rename.status, StatusCode::NO_CONTENT);
    assert!(rename.body.is_empty());
    assert_eq!(
        server.get("/auth/users/admin").await.json()["friendly_name"],
        "Administrator"
    );

    assert_eq!(
        server.delete("/auth/groups/Admins/members/admin").await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.delete("/auth/groups/Viewers/policies/FSReadAll").await.status,
        StatusCode::NO_CONTENT
    );

    let attach = server.put("/auth/users/admin/policies/FSReadAll").await;
    assert_eq!(attach.status, StatusCode::CREATED);
    assert!(attach.body.is_empty());
    // PUT is idempotent.
    assert_eq!(
        server.put("/auth/users/admin/policies/FSReadAll").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        server.delete("/auth/users/admin/policies/FSReadAll").await.status,
        StatusCode::NO_CONTENT
    );

    assert_eq!(
        server.delete("/auth/policies/FSReadAll").await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.delete("/auth/groups/Viewers").await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(server.delete("/auth/users/admin").await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_policy_answers_200_with_the_new_body() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let updated = json!({
        "name": "FSReadAll",
        "creation_date": 1_700_000_000,
        "statement": [{ "effect": "deny", "action": ["fs:DeleteObject"], "resource": "*" }],
        "acl": "read"
    });
    let response = server.put_json("/auth/policies/FSReadAll", updated.clone()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["statement"], updated["statement"]);
    assert_eq!(response.json()["creation_date"], 1_700_000_000);
    assert_eq!(response.json()["acl"], "read");

    let stored = server.get("/auth/policies/FSReadAll").await;
    assert_eq!(stored.json(), response.json());
}

#[tokio::test]
async fn token_ids_can_be_claimed_once() {
    let server = TestServer::new();
    let body = json!({ "token_id": "jti-1", "expires_at": now_unix() + 3600 });

    let first = server.post("/auth/tokenid/claim", body.clone()).await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert!(first.body.is_empty());

    let second = server.post("/auth/tokenid/claim", body).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert!(!second.message().is_empty());
}

fn now_unix() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[tokio::test]
async fn unsupported_routes_answer_501() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let response = server.put("/auth/users/admin/password").await;
    assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
    assert!(!response.message().is_empty());
}

/// The four external principal operations of the specification, on the store
/// that always existed behind them.
#[tokio::test]
async fn external_principals_round_trip_over_the_api() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;
    let principal = "arn:aws:iam::123456789012:role/data";
    let encoded = "arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fdata";

    let created = server
        .post_empty(&format!("/auth/users/admin/external/principals?principalId={encoded}"))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.message());
    assert!(created.body.is_empty());

    let repeated = server
        .post_empty(&format!("/auth/users/admin/external/principals?principalId={encoded}"))
        .await;
    assert_eq!(repeated.status, StatusCode::CONFLICT);

    let fetched = server
        .get(&format!("/auth/external/principals?principalId={encoded}"))
        .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.json(), json!({ "id": principal, "user_id": "admin" }));

    let listed = server.get("/auth/users/admin/external/principals/ls").await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(
        listed.json()["results"],
        json!([{ "id": principal, "user_id": "admin" }])
    );
    assert_eq!(listed.json()["pagination"]["next_offset"], "");

    let missing_id = server.post_empty("/auth/users/admin/external/principals").await;
    assert_eq!(missing_id.status, StatusCode::BAD_REQUEST);
    let unknown_user = server
        .post_empty(&format!("/auth/users/nobody/external/principals?principalId={encoded}"))
        .await;
    assert_eq!(unknown_user.status, StatusCode::NOT_FOUND);

    let deleted = server
        .delete(&format!("/auth/users/admin/external/principals?principalId={encoded}"))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = server
        .get(&format!("/auth/external/principals?principalId={encoded}"))
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    let listed = server.get("/auth/users/admin/external/principals/ls").await;
    assert_eq!(listed.json()["pagination"]["results"], 0);
}

/// A `PUT` that leaves `creation_date` or `acl` out keeps the stored values;
/// the specification requires only `name` and `statement` in the body.
#[tokio::test]
async fn update_policy_keeps_creation_date_and_acl_when_the_body_omits_them() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let with_acl = json!({
        "name": "FSReadAll",
        "creation_date": 1_600_000_000,
        "statement": [{ "effect": "allow", "action": ["fs:Read*"], "resource": "*" }],
        "acl": "read"
    });
    assert_eq!(
        server.put_json("/auth/policies/FSReadAll", with_acl).await.status,
        StatusCode::OK
    );

    let minimal = json!({
        "name": "FSReadAll",
        "statement": [{ "effect": "allow", "action": ["fs:List*"], "resource": "*" }]
    });
    let response = server.put_json("/auth/policies/FSReadAll", minimal.clone()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["statement"], minimal["statement"]);
    assert_eq!(
        response.json()["creation_date"],
        1_600_000_000,
        "the stored date survives"
    );
    assert_eq!(response.json()["acl"], "read", "the stored acl survives");
    let stored = server.get("/auth/policies/FSReadAll").await;
    assert_eq!(stored.json(), response.json());
}

/// A timestamp outside the storable years is a 400, never silently "now".
#[tokio::test]
async fn out_of_range_timestamps_are_rejected() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    let policy = json!({
        "name": "FSReadAll",
        "creation_date": 9_000_000_000_000_000_000_i64,
        "statement": [{ "effect": "allow", "action": ["fs:Read*"], "resource": "*" }]
    });
    let response = server.put_json("/auth/policies/FSReadAll", policy).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.message().contains("creation_date"), "{}", response.message());

    let claim = json!({ "token_id": "jti-huge", "expires_at": i64::MAX });
    let response = server.post("/auth/tokenid/claim", claim).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.message().contains("expires_at"), "{}", response.message());
}

/// A whitespace-only secret is as missing as an empty one; the server
/// generates a fresh pair instead of storing the spaces.
#[tokio::test]
async fn a_whitespace_secret_counts_as_missing() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;
    let response = server
        .post_empty("/auth/users/admin/credentials?access_key=AKIAJTESTTESTTESTQ&secret_key=%20%20%20")
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    assert_ne!(response.json()["access_key_id"], "AKIAJTESTTESTTESTQ");
    assert_eq!(response.json()["secret_access_key"].as_str().expect("secret").len(), 40);

    let trimmed = server
        .post_empty("/auth/users/admin/credentials?access_key=%20AKIAJTRIMMEDKEYXQ%20&secret_key=%20padded-secret%20")
        .await;
    assert_eq!(trimmed.status, StatusCode::CREATED);
    assert_eq!(trimmed.json()["access_key_id"], "AKIAJTRIMMEDKEYXQ");
    assert_eq!(trimmed.json()["secret_access_key"], "padded-secret");
}

/// Blank optional fields are stored as absent, so two users may both send
/// `"email": ""`, and a padded value is stored trimmed, the way the lookups read it.
#[tokio::test]
async fn blank_optional_fields_are_stored_as_absent_and_padded_ones_trimmed() {
    let server = TestServer::new();
    for name in ["e1", "e2"] {
        let response = server
            .post(
                "/auth/users",
                json!({ "username": name, "email": "", "external_id": "  " }),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{name}: {}", response.message());
        assert!(response.json().get("email").is_none(), "{name} carries no email");
        assert!(
            response.json().get("external_id").is_none(),
            "{name} carries no external id"
        );
    }
    let padded = server
        .post(
            "/auth/users",
            json!({ "username": "e3", "email": " e3@example.com ", "external_id": " sub-e3 " }),
        )
        .await;
    assert_eq!(padded.status, StatusCode::CREATED);
    assert_eq!(padded.json()["email"], "e3@example.com");
    assert_eq!(padded.json()["external_id"], "sub-e3");
    let found = server.get("/auth/users?email=e3@example.com").await;
    assert_eq!(names(&found.json(), "username"), vec!["e3"]);
    let found = server.get("/auth/users?external_id=sub-e3").await;
    assert_eq!(names(&found.json(), "username"), vec!["e3"]);
}

/// A collision on the email index is reported as such, not as a taken username.
#[tokio::test]
async fn an_email_collision_names_the_email() {
    let server = TestServer::new();
    server
        .post(
            "/auth/users",
            json!({ "username": "alice", "email": "shared@example.com" }),
        )
        .await;
    let response = server
        .post(
            "/auth/users",
            json!({ "username": "bob", "email": "shared@example.com" }),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert!(response.message().contains("email"), "{}", response.message());
    assert!(!response.message().contains("bob"), "{}", response.message());
    assert_eq!(server.get("/auth/users/bob").await.status, StatusCode::NOT_FOUND);
}

/// A body the server cannot read is a 400 with the `Error` shape the
/// specification declares, not axum's plain text 422 or 415.
#[tokio::test]
async fn malformed_bodies_answer_400_with_an_error_body() {
    let server = TestServer::new();
    let cases = [
        ("POST", "/auth/users", "application/json", "{not json"),
        ("POST", "/auth/users", "application/json", r#"{"username": 7}"#),
        ("POST", "/auth/users", "text/plain", r#"{"username": "x"}"#),
        ("POST", "/auth/groups", "application/json", ""),
        ("POST", "/auth/policies", "application/json", "[]"),
        ("PUT", "/auth/policies/FSReadAll", "application/json", "null"),
        ("PUT", "/auth/users/admin/friendly_name", "application/json", "{}"),
        (
            "POST",
            "/auth/tokenid/claim",
            "application/json",
            r#"{"token_id": "x"}"#,
        ),
    ];
    for (method, path, content_type, body) in cases {
        let response = server.send_raw(method, path, content_type, body).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{method} {path} {body:?}");
        assert!(!response.message().is_empty(), "{method} {path} needs a JSON message");
    }
}

/// Without `amount` a list answers the 100 rows the specification defaults to,
/// while `0` and `-1` still mean the maximum.
#[tokio::test]
async fn a_missing_amount_pages_at_the_default_of_100() {
    let server = TestServer::new();
    for index in 0..101 {
        let response = server
            .post("/auth/users", json!({ "username": format!("bulk-{index:03}") }))
            .await;
        assert_eq!(response.status, StatusCode::CREATED);
    }
    let default_page = server.get("/auth/users").await;
    assert_eq!(default_page.json()["pagination"]["results"], 100);
    assert_eq!(default_page.json()["pagination"]["next_offset"], "bulk-099");
    for query in ["?amount=0", "?amount=-1", "?amount=1000"] {
        let response = server.get(&format!("/auth/users{query}")).await;
        assert_eq!(response.json()["pagination"]["results"], 101, "{query}");
        assert_eq!(response.json()["pagination"]["next_offset"], "", "{query}");
    }
}

/// `/readyz` reports the store, so a pod with an unreachable database leaves
/// the Service until the database is back.
#[tokio::test]
async fn readyz_reflects_the_store() {
    let server = TestServer::new();
    let ready = server.get_root("/readyz").await;
    assert_eq!(ready.status, StatusCode::OK);

    server.mem.set_unavailable(true);
    let not_ready = server.get_root("/readyz").await;
    assert_eq!(not_ready.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!not_ready.message().is_empty());

    server.mem.set_unavailable(false);
    assert_eq!(server.get_root("/readyz").await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_repeated_create_succeeds_only_with_the_same_content() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;

    // A second full setup run succeeds instead of failing on the Admins group,
    // and creates nothing twice.
    server.run_lakefs_setup().await;
    let groups = server.get("/auth/groups").await;
    assert_eq!(groups.json()["pagination"]["results"], 4, "no duplicate groups");
    let policies = server.get("/auth/policies").await;
    assert_eq!(policies.json()["pagination"]["results"], 10, "no duplicate policies");

    // Policies: the same statements in another order match; other statements conflict.
    let readers = |actions: Vec<&str>| json!({ "name": "Readers", "statement": [{ "effect": "allow", "action": actions, "resource": "*" }] });
    let created = server
        .post(
            "/auth/policies",
            readers(vec!["fs:ListRepositories", "fs:ReadRepository"]),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let repeated = server
        .post(
            "/auth/policies",
            readers(vec!["fs:ReadRepository", "fs:ListRepositories"]),
        )
        .await;
    assert_eq!(repeated.status, StatusCode::CREATED);
    assert_eq!(
        repeated.json()["creation_date"],
        created.json()["creation_date"],
        "the stored row is returned"
    );
    assert_eq!(
        server.post("/auth/policies", readers(vec!["fs:*"])).await.status,
        StatusCode::CONFLICT
    );

    // Groups: no description matches; a different description conflicts.
    assert_eq!(
        server.post("/auth/groups", json!({ "id": "Admins" })).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        server
            .post(
                "/auth/groups",
                json!({ "id": "Admins", "description": "something else" })
            )
            .await
            .status,
        StatusCode::CONFLICT
    );

    // Users: fields the request leaves out do not count; fields it sets must match.
    let alice = json!({ "username": "alice", "email": "alice@example.com" });
    assert_eq!(
        server.post("/auth/users", alice.clone()).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        server.post("/auth/users", json!({ "username": "alice" })).await.status,
        StatusCode::CREATED
    );
    assert_eq!(server.post("/auth/users", alice).await.status, StatusCode::CREATED);
    assert_eq!(
        server
            .post(
                "/auth/users",
                json!({ "username": "alice", "email": "other@example.com" })
            )
            .await
            .status,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn deleting_a_user_removes_its_credentials_and_memberships() {
    let server = TestServer::new();
    server.run_lakefs_setup().await;
    let credentials = server.post_empty("/auth/users/admin/credentials").await;
    let access_key_id = credentials.json()["access_key_id"].as_str().expect("key").to_owned();

    assert_eq!(server.delete("/auth/users/admin").await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        server.get(&format!("/auth/credentials/{access_key_id}")).await.status,
        StatusCode::NOT_FOUND
    );
    let members = server.get("/auth/groups/Admins/members").await;
    assert_eq!(members.json()["pagination"]["results"], 0);
}

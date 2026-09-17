use std::time::Duration;

use lakefs_auth_core::model::User;
use lakefs_auth_core::pagination::PageOf;
use lakefs_authz_client::{AuthzClient, AuthzClientConfig, ClientAuth, ClientError, EnsureUserSpec};
use pretty_assertions::assert_eq;
use serde_json::json;
use wiremock::matchers::{body_json_schema, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn user_json(username: &str, external_id: &str) -> serde_json::Value {
    json!({
        "username": username,
        "creation_date": 1_700_000_000,
        "source": "oidc",
        "encryptedPassword": null,
        "external_id": external_id
    })
}

/// One last page, in the shape the server renders it.
fn page(results: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::to_value(PageOf::last(results).into_response()).expect("the page serializes")
}

async fn client(server: &MockServer, auth: ClientAuth) -> AuthzClient {
    let endpoint = format!("{}/api/v1", server.uri()).parse().unwrap();
    let mut config = AuthzClientConfig::new(endpoint, auth);
    config.timeout = Duration::from_secs(2);
    AuthzClient::new(config).unwrap()
}

#[tokio::test]
async fn get_user_maps_200_and_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users/alice%40example.com"))
        .and(header("authorization", "Bearer static-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_json("alice@example.com", "sub-1")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users/nobody"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "user not found"})))
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::Static("static-token".into())).await;
    let user: User = client.get_user("alice@example.com").await.unwrap().unwrap();
    assert_eq!(user.external_id.as_deref(), Some("sub-1"));
    assert!(client.get_user("nobody").await.unwrap().is_none());
}

#[tokio::test]
async fn internal_jwt_is_sent_as_bearer() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/healthcheck"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::internal_jwt(b"shared")).await;
    client.healthcheck().await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let auth = requests[0].headers.get("authorization").unwrap().to_str().unwrap();
    assert!(auth.starts_with("Bearer eyJ"), "{auth}");
}

#[tokio::test]
async fn find_by_external_id_handles_zero_one_and_many() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .and(query_param("external_id", "none"))
        .and(query_param("amount", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .and(query_param("external_id", "one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![user_json("alice", "one")])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .and(query_param("external_id", "many"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page(vec![user_json("a", "many"), user_json("b", "many")])),
        )
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    assert!(client.find_user_by_external_id("none").await.unwrap().is_none());
    assert_eq!(
        client.find_user_by_external_id("one").await.unwrap().unwrap().username,
        "alice"
    );
    assert!(matches!(
        client.find_user_by_external_id("many").await,
        Err(ClientError::NonUnique)
    ));
}

#[tokio::test]
async fn ensure_user_creates_and_adds_groups() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .and(body_json_schema::<serde_json::Value>)
        .respond_with(|req: &Request| {
            let body: serde_json::Value = req.body_json().unwrap();
            assert_eq!(body["username"], "alice");
            assert_eq!(body["friendlyName"], "Alice");
            assert_eq!(body["external_id"], "sub-1");
            assert_eq!(body["source"], "oidc");
            ResponseTemplate::new(201).set_body_json(user_json("alice", "sub-1"))
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/auth/groups/Developers/members/alice"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/auth/groups/Viewers/members/alice"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({"message": "already exists"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/auth/groups/Missing/members/alice"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "group not found"})))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    let ensured = client
        .ensure_user(&EnsureUserSpec {
            external_id: "sub-1".into(),
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            friendly_name: Some("Alice".into()),
            source: "oidc".into(),
            groups: vec!["Developers".into(), "Viewers".into(), "Missing".into()],
        })
        .await
        .unwrap();
    assert!(ensured.created);
    assert_eq!(ensured.user.username, "alice");
}

#[tokio::test]
async fn ensure_user_returns_existing_user_without_create() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .and(query_param("external_id", "sub-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![user_json("alice", "sub-1")])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    let ensured = client
        .ensure_user(&EnsureUserSpec {
            external_id: "sub-1".into(),
            username: "alice".into(),
            email: None,
            friendly_name: None,
            source: "oidc".into(),
            groups: vec!["Developers".into()],
        })
        .await
        .unwrap();
    assert!(!ensured.created);
}

#[tokio::test]
async fn ensure_user_recovers_from_create_race() {
    let server = MockServer::start().await;
    // First lookup misses, second lookup (after the 409) finds the user created by the other replica.
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![user_json("alice", "sub-1")])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({"message": "already exists"})))
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    let ensured = client
        .ensure_user(&EnsureUserSpec {
            external_id: "sub-1".into(),
            username: "alice".into(),
            email: None,
            friendly_name: None,
            source: "oidc".into(),
            groups: vec![],
        })
        .await
        .unwrap();
    assert!(!ensured.created);
    assert_eq!(ensured.user.username, "alice");
}

#[tokio::test]
async fn retries_server_errors_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/healthcheck"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/healthcheck"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::None).await;
    client.healthcheck().await.unwrap();
}

#[tokio::test]
async fn status_codes_map_to_typed_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "invite not supported"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/config/version"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "invalid bearer token"})))
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::None).await;
    let creation = lakefs_auth_core::model::UserCreation {
        username: "x".into(),
        ..Default::default()
    };
    assert!(
        matches!(client.create_user(&creation).await, Err(ClientError::BadRequest(m)) if m == "invite not supported")
    );
    assert!(matches!(client.version().await, Err(ClientError::Unauthorized)));
}

fn group_json(name: &str) -> serde_json::Value {
    json!({ "id": name, "name": name, "creation_date": 1_700_000_000 })
}

fn credentials_json() -> serde_json::Value {
    json!({
        "access_key_id": "AKIAJGENERATEDKEYQ",
        "secret_access_key": "generated-secret",
        "creation_date": 1_700_000_000,
        "user_id": 7,
        "user_name": "alice"
    })
}

fn spec(groups: &[&str]) -> EnsureUserSpec {
    EnsureUserSpec {
        external_id: "sub-1".into(),
        username: "alice".into(),
        email: Some("alice@example.com".into()),
        friendly_name: None,
        source: "oidc".into(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    }
}

/// `.` and `..` would collapse the request path through `Url::join`, and the
/// server refuses wildcards, slashes, control characters, and oversize ids
/// with a 400, so none of them may reach the URL builder.
#[tokio::test]
async fn dot_segments_and_empty_ids_are_refused_before_a_request_is_built() {
    let server = MockServer::start().await;
    let client = client(&server, ClientAuth::None).await;
    let oversize = "a".repeat(513);
    for bad in [".", "..", "", "a*b", "adm?n", "a/b", "a\nb", oversize.as_str()] {
        assert!(
            matches!(client.get_user(bad).await, Err(ClientError::InvalidId(_))),
            "get_user({bad:?})"
        );
        assert!(
            matches!(
                client.add_group_membership("Developers", bad).await,
                Err(ClientError::InvalidId(_))
            ),
            "membership user {bad:?}"
        );
        assert!(
            matches!(
                client.add_group_membership(bad, "alice").await,
                Err(ClientError::InvalidId(_))
            ),
            "membership group {bad:?}"
        );
        assert!(
            matches!(client.list_user_groups(bad).await, Err(ClientError::InvalidId(_))),
            "list_user_groups({bad:?})"
        );
        assert!(
            matches!(client.create_credentials(bad).await, Err(ClientError::InvalidId(_))),
            "create_credentials({bad:?})"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request may leave the client"
    );
}

/// The server reads an empty filter as "no filter" and lists everyone, so the
/// client answers "nobody" without asking.
#[tokio::test]
async fn an_empty_lookup_value_never_reaches_the_server() {
    let server = MockServer::start().await;
    let client = client(&server, ClientAuth::None).await;
    assert!(client.find_user_by_email("").await.unwrap().is_none());
    assert!(client.find_user_by_email("   ").await.unwrap().is_none());
    assert!(client.find_user_by_external_id("").await.unwrap().is_none());
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// A membership failure after the user row is committed would leave a user
/// with no groups forever, because later logins find the user and return
/// early. The create is rolled back instead, so the next login retries.
#[tokio::test]
async fn a_failed_group_assignment_rolls_the_create_back() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(201).set_body_json(user_json("alice", "sub-1")))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/auth/groups/Developers/members/alice"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"message": "store is down"})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/auth/users/alice"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    let result = client.ensure_user(&spec(&["Developers"])).await;
    assert!(
        matches!(result, Err(ClientError::Status { status: 503, .. })),
        "{result:?}"
    );
}

/// A missing group stays a warning: with lenient group mapping an identity
/// provider group that lakeFS does not know is expected, and the login goes on.
#[tokio::test]
async fn a_missing_group_does_not_roll_the_create_back() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(201).set_body_json(user_json("alice", "sub-1")))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/auth/groups/Missing/members/alice"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "group not found"})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/auth/users/alice"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    let ensured = client.ensure_user(&spec(&["Missing"])).await.unwrap();
    assert!(ensured.created);
}

/// An email that another identity already holds must not lock this identity
/// out forever: the user is created without the email instead.
#[tokio::test]
async fn ensure_user_drops_an_email_that_belongs_to_another_identity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .and(query_param("external_id", "sub-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .and(query_param("email", "alice@example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![user_json("old-alice", "sub-0")])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({"message": "user with email already exists"})))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(|req: &Request| {
            let body: serde_json::Value = req.body_json().unwrap();
            assert_eq!(body["username"], "alice");
            assert!(
                body.get("email").is_none(),
                "the retry must not carry the email: {body}"
            );
            ResponseTemplate::new(201).set_body_json(user_json("alice", "sub-1"))
        })
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    let ensured = client.ensure_user(&spec(&[])).await.unwrap();
    assert!(ensured.created);
    assert_eq!(ensured.user.username, "alice");
}

/// A username that another identity holds is still a collision, email or not.
#[tokio::test]
async fn ensure_user_keeps_a_real_username_collision() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({"message": "user already exists: alice"})))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server, ClientAuth::None).await;
    assert!(matches!(
        client.ensure_user(&spec(&[])).await,
        Err(ClientError::AlreadyExists)
    ));
}

/// One ten-year token per process is a decade of access for whoever captures
/// it. Each request gets its own short-lived token instead.
#[tokio::test]
async fn the_internal_token_is_short_lived_and_minted_per_request() {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    #[derive(serde::Deserialize)]
    struct Claims {
        jti: String,
        exp: i64,
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/healthcheck"))
        .respond_with(ResponseTemplate::new(204))
        .expect(2)
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::internal_jwt(b"shared")).await;
    client.healthcheck().await.unwrap();
    client.healthcheck().await.unwrap();

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["auth-client"]);
    let claims: Vec<Claims> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            let header = request.headers.get("authorization").unwrap().to_str().unwrap();
            let token = header.strip_prefix("Bearer ").expect("bearer scheme");
            jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(b"shared"), &validation)
                .expect("the token verifies")
                .claims
        })
        .collect();
    assert_eq!(claims.len(), 2);
    assert_ne!(claims[0].jti, claims[1].jti, "every request carries its own token");
    let now = now_unix();
    for claim in &claims {
        assert!(claim.exp > now, "the token is not expired");
        assert!(
            claim.exp <= now + 600,
            "the token lives at most ten minutes, exp {}",
            claim.exp
        );
    }
}

fn now_unix() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// The server may have committed before the client gave up waiting. A replayed
/// POST would mint a second credential pair nobody knows about.
#[tokio::test]
async fn a_post_that_times_out_is_not_replayed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/users/alice/credentials"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_delay(Duration::from_millis(800))
                .set_body_json(credentials_json()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let endpoint = format!("{}/api/v1", server.uri()).parse().unwrap();
    let mut config = AuthzClientConfig::new(endpoint, ClientAuth::None);
    config.timeout = Duration::from_millis(200);
    let client = AuthzClient::new(config).unwrap();

    let result = client.create_credentials("alice").await;
    assert!(matches!(result, Err(ClientError::Transport(_))), "{result:?}");
    // Give a wrong retry the time it would need to arrive before the expectation is checked.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// Idempotent requests keep their retry on a timeout.
#[tokio::test]
async fn a_get_that_times_out_is_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/healthcheck"))
        .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(800)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/healthcheck"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let endpoint = format!("{}/api/v1", server.uri()).parse().unwrap();
    let mut config = AuthzClientConfig::new(endpoint, ClientAuth::None);
    config.timeout = Duration::from_millis(200);
    let client = AuthzClient::new(config).unwrap();
    client.healthcheck().await.unwrap();
}

/// A server, or a proxy in front of it, that repeats a cursor must not spin the
/// client forever and grow the result without bound.
#[tokio::test]
async fn a_repeated_cursor_ends_the_group_walk_with_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users/alice/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pagination": { "has_more": true, "next_offset": "stuck", "results": 1, "max_per_page": 1000 },
            "results": [group_json("Developers")]
        })))
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::None).await;
    let result = client.list_user_groups("alice").await;
    assert!(matches!(result, Err(ClientError::Pagination(_))), "{result:?}");
    assert!(server.received_requests().await.unwrap().len() <= 3);
}

/// A cursor that always advances is capped by a page limit.
#[tokio::test]
async fn an_endless_group_walk_is_capped() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users/alice/groups"))
        .respond_with(|req: &Request| {
            let after = req
                .url
                .query_pairs()
                .find(|(key, _)| key == "after")
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default();
            ResponseTemplate::new(200).set_body_json(json!({
                "pagination": { "has_more": true, "next_offset": format!("{after}x"), "results": 1, "max_per_page": 1000 },
                "results": [group_json(&format!("g{after}"))]
            }))
        })
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::None).await;
    let result = client.list_user_groups("alice").await;
    assert!(matches!(result, Err(ClientError::Pagination(_))), "{result:?}");
    assert!(server.received_requests().await.unwrap().len() <= 50);
}

/// A well-behaved server is still walked to the end.
#[tokio::test]
async fn a_finite_group_walk_collects_every_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users/alice/groups"))
        .and(query_param("after", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pagination": { "has_more": true, "next_offset": "Admins", "results": 1, "max_per_page": 1000 },
            "results": [group_json("Admins")]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/users/alice/groups"))
        .and(query_param("after", "Admins"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pagination": { "has_more": false, "next_offset": "", "results": 1, "max_per_page": 1000 },
            "results": [group_json("Developers")]
        })))
        .mount(&server)
        .await;
    let client = client(&server, ClientAuth::None).await;
    let groups = client.list_user_groups("alice").await.unwrap();
    let names: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
    assert_eq!(names, ["Admins", "Developers"]);
}

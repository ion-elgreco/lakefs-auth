//! A wiremock stand-in for the lakeFS authorization API, with just enough state
//! for the provisioning paths the authentication server uses.

use std::sync::{Arc, Mutex};

use lakefs_auth_core::model::{User, UserCreation};
use lakefs_auth_core::pagination::PageOf;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Debug, Default)]
struct AuthzState {
    users: Vec<User>,
    memberships: Vec<(String, String)>,
    friendly_names: Vec<(String, String)>,
    requests: Vec<(String, String)>,
    /// Turns every create into a 409, which is how a username collision looks.
    always_conflict: bool,
    /// Makes every request fail, to exercise the internal error path.
    broken: bool,
    /// Added to the answer of every user create, to outlast a request timeout.
    create_delay: std::time::Duration,
}

#[derive(Clone)]
struct Responder {
    state: Arc<Mutex<AuthzState>>,
}

pub struct MockAuthz {
    server: MockServer,
    state: Arc<Mutex<AuthzState>>,
}

impl MockAuthz {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(AuthzState::default()));
        Mock::given(any())
            .respond_with(Responder { state: state.clone() })
            .mount(&server)
            .await;
        Self { server, state }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn add_user(&self, user: User) {
        self.state.lock().unwrap().users.push(user);
    }

    pub fn users(&self) -> Vec<User> {
        self.state.lock().unwrap().users.clone()
    }

    pub fn user(&self, username: &str) -> Option<User> {
        self.users().into_iter().find(|user| user.username == username)
    }

    pub fn memberships(&self) -> Vec<(String, String)> {
        self.state.lock().unwrap().memberships.clone()
    }

    pub fn friendly_names(&self) -> Vec<(String, String)> {
        self.state.lock().unwrap().friendly_names.clone()
    }

    /// Every request as a `(method, path)` pair, in order.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.state.lock().unwrap().requests.clone()
    }

    pub fn set_always_conflict(&self, value: bool) {
        self.state.lock().unwrap().always_conflict = value;
    }

    pub fn set_broken(&self, value: bool) {
        self.state.lock().unwrap().broken = value;
    }

    /// Delays the answer of every user create. The user is recorded before the
    /// delay, the way a committed insert is, so a caller that gives up while
    /// waiting still leaves the user behind.
    pub fn set_create_delay(&self, delay: std::time::Duration) {
        self.state.lock().unwrap().create_delay = delay;
    }
}

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.state.lock().unwrap();
        let path = request.url.path().to_owned();
        let method = request.method.to_string();
        state.requests.push((method.clone(), path.clone()));
        if state.broken {
            return ResponseTemplate::new(500).set_body_json(json!({"message": "the store is down"}));
        }
        let segments: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
            .collect();
        let tail: Vec<&str> = segments.iter().map(String::as_str).collect();

        match (method.as_str(), tail.as_slice()) {
            ("GET", ["api", "v1", "healthcheck"]) => ResponseTemplate::new(204),
            ("GET", ["api", "v1", "auth", "users"]) => {
                let filters: Vec<(String, String)> = request
                    .url
                    .query_pairs()
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect();
                let matched: Vec<User> = state
                    .users
                    .iter()
                    .filter(|user| {
                        filters.iter().all(|(key, value)| match key.as_str() {
                            "external_id" => user.external_id.as_deref() == Some(value.as_str()),
                            "email" => user.email.as_deref() == Some(value.as_str()),
                            _ => true,
                        })
                    })
                    .cloned()
                    .collect();
                ResponseTemplate::new(200).set_body_json(page(matched))
            }
            ("GET", ["api", "v1", "auth", "users", username]) => {
                match state.users.iter().find(|user| user.username == *username) {
                    Some(user) => ResponseTemplate::new(200).set_body_json(user),
                    None => not_found(),
                }
            }
            ("POST", ["api", "v1", "auth", "users"]) => {
                let Ok(creation) = serde_json::from_slice::<UserCreation>(&request.body) else {
                    return ResponseTemplate::new(400).set_body_json(json!({"message": "bad body"}));
                };
                if state.always_conflict || state.users.iter().any(|user| user.username == creation.username) {
                    return ResponseTemplate::new(409).set_body_json(json!({"message": "already exists"}));
                }
                let user = User {
                    username: creation.username,
                    creation_date: 1_767_225_600,
                    friendly_name: creation.friendly_name,
                    email: creation.email,
                    source: creation.source,
                    encrypted_password: None,
                    external_id: creation.external_id,
                };
                state.users.push(user.clone());
                ResponseTemplate::new(201)
                    .set_delay(state.create_delay)
                    .set_body_json(user)
            }
            ("PUT", ["api", "v1", "auth", "users", username, "friendly_name"]) => {
                let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
                    return ResponseTemplate::new(400).set_body_json(json!({"message": "bad body"}));
                };
                let name = body["friendly_name"].as_str().unwrap_or_default().to_owned();
                let username = (*username).to_owned();
                if let Some(user) = state.users.iter_mut().find(|user| user.username == username) {
                    user.friendly_name = Some(name.clone());
                } else {
                    return not_found();
                }
                state.friendly_names.push((username, name));
                ResponseTemplate::new(204)
            }
            ("PUT", ["api", "v1", "auth", "groups", group, "members", username]) => {
                let pair = ((*group).to_owned(), (*username).to_owned());
                if state.memberships.contains(&pair) {
                    return ResponseTemplate::new(409).set_body_json(json!({"message": "already a member"}));
                }
                state.memberships.push(pair);
                ResponseTemplate::new(201)
            }
            _ => not_found(),
        }
    }
}

/// One last page, in the shape the server renders it.
fn page(users: Vec<User>) -> Value {
    serde_json::to_value(PageOf::last(users).into_response()).expect("the page serializes")
}

fn not_found() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({"message": "not found"}))
}

/// A user the authorization API would already hold.
pub fn existing_user(username: &str, external_id: &str) -> User {
    User {
        username: username.to_owned(),
        creation_date: 1_700_000_000,
        friendly_name: None,
        email: None,
        source: Some("oidc".to_owned()),
        encrypted_password: None,
        external_id: Some(external_id.to_owned()),
    }
}

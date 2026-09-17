//! A wiremock identity provider: discovery, JWKS, and a token endpoint that signs RS256.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::testkey;

/// How the token endpoint should answer the next call.
#[derive(Debug, Clone)]
pub enum TokenBehaviour {
    /// 200 with an ID token carrying the configured claims.
    Issue,
    /// 200 without an `id_token` field.
    NoIdToken,
    /// The given status with the given body.
    Fail(u16, Value),
}

#[derive(Debug)]
struct IdpState {
    issuer: String,
    claims: Value,
    /// Key id put in the header of every issued token.
    key_id: String,
    /// Key id the JWKS advertises, which a rotation moves ahead of `key_id`.
    jwks_key_id: String,
    unsigned: bool,
    discovery_broken: bool,
    /// Added to every discovery and JWKS answer.
    discovery_delay: Duration,
    /// Added to every token endpoint answer.
    token_delay: Duration,
    /// Advertised instead of the real token endpoint, to simulate an outage.
    token_endpoint_override: Option<String>,
    behaviour: TokenBehaviour,
    token_requests: Vec<BTreeMap<String, String>>,
    discovery_hits: usize,
    jwks_hits: usize,
}

#[derive(Clone)]
struct Responder {
    state: Arc<Mutex<IdpState>>,
}

pub struct MockIdp {
    server: MockServer,
    state: Arc<Mutex<IdpState>>,
}

impl MockIdp {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let state = Arc::new(Mutex::new(IdpState {
            claims: json!({}),
            key_id: testkey::KEY_ID.to_owned(),
            jwks_key_id: testkey::KEY_ID.to_owned(),
            unsigned: false,
            discovery_broken: false,
            discovery_delay: Duration::ZERO,
            token_delay: Duration::ZERO,
            token_endpoint_override: None,
            behaviour: TokenBehaviour::Issue,
            token_requests: Vec::new(),
            discovery_hits: 0,
            jwks_hits: 0,
            issuer,
        }));
        Mock::given(any())
            .respond_with(Responder { state: state.clone() })
            .mount(&server)
            .await;
        Self { server, state }
    }

    pub fn issuer(&self) -> String {
        self.state.lock().unwrap().issuer.clone()
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer())
    }

    pub fn end_session_endpoint(&self) -> String {
        format!("{}/logout", self.issuer())
    }

    /// Claims of the next ID token. `iss`, `aud`, `exp`, and `iat` fill in when absent.
    pub fn set_claims(&self, claims: Value) {
        self.state.lock().unwrap().claims = claims;
    }

    /// Signs the next token with this key id while the JWKS keeps the old one.
    pub fn set_key_id(&self, key_id: &str) {
        self.state.lock().unwrap().key_id = key_id.to_owned();
    }

    /// Publishes a new key id in the JWKS, as a provider does after a rotation.
    pub fn rotate_jwks_key_id(&self, key_id: &str) {
        self.state.lock().unwrap().jwks_key_id = key_id.to_owned();
    }

    pub fn set_unsigned(&self, unsigned: bool) {
        self.state.lock().unwrap().unsigned = unsigned;
    }

    pub fn set_discovery_broken(&self, broken: bool) {
        self.state.lock().unwrap().discovery_broken = broken;
    }

    /// Slows every discovery and JWKS answer down, to observe overlapping refreshes.
    pub fn set_discovery_delay(&self, delay: Duration) {
        self.state.lock().unwrap().discovery_delay = delay;
    }

    /// Slows the token endpoint down, to hit the request timeout of the server.
    pub fn set_token_delay(&self, delay: Duration) {
        self.state.lock().unwrap().token_delay = delay;
    }

    pub fn set_token_behaviour(&self, behaviour: TokenBehaviour) {
        self.state.lock().unwrap().behaviour = behaviour;
    }

    /// Advertises a token endpoint nobody listens on, so the next discovery
    /// round makes every code exchange fail at the transport level.
    pub fn set_token_endpoint_unreachable(&self) {
        self.state.lock().unwrap().token_endpoint_override = Some("http://127.0.0.1:1/token".to_owned());
    }

    pub fn token_requests(&self) -> Vec<BTreeMap<String, String>> {
        self.state.lock().unwrap().token_requests.clone()
    }

    pub fn last_token_request(&self) -> BTreeMap<String, String> {
        self.token_requests()
            .pop()
            .expect("the token endpoint was called at least once")
    }

    pub fn discovery_hits(&self) -> usize {
        self.state.lock().unwrap().discovery_hits
    }

    pub fn jwks_hits(&self) -> usize {
        self.state.lock().unwrap().jwks_hits
    }
}

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.state.lock().unwrap();
        match (request.method.as_str(), request.url.path()) {
            ("GET", "/.well-known/openid-configuration") => {
                state.discovery_hits += 1;
                if state.discovery_broken {
                    return ResponseTemplate::new(500).set_body_string("provider is down");
                }
                let issuer = state.issuer.clone();
                let mut document = discovery_document(&issuer);
                if let Some(endpoint) = &state.token_endpoint_override {
                    document["token_endpoint"] = json!(endpoint);
                }
                ResponseTemplate::new(200)
                    .set_delay(state.discovery_delay)
                    .set_body_json(document)
            }
            ("GET", "/jwks") => {
                state.jwks_hits += 1;
                if state.discovery_broken {
                    return ResponseTemplate::new(500).set_body_string("provider is down");
                }
                let key_id = state.jwks_key_id.clone();
                ResponseTemplate::new(200)
                    .set_delay(state.discovery_delay)
                    .set_body_json(testkey::jwks(&key_id))
            }
            ("POST", "/token") => {
                let form: Vec<(String, String)> = serde_urlencoded::from_bytes(&request.body).unwrap_or_default();
                state.token_requests.push(form.into_iter().collect());
                let response = match state.behaviour.clone() {
                    TokenBehaviour::Fail(status, body) => ResponseTemplate::new(status).set_body_json(body),
                    TokenBehaviour::NoIdToken => ResponseTemplate::new(200).set_body_json(json!({
                        "access_token": "access-token",
                        "token_type": "Bearer",
                        "expires_in": 300,
                    })),
                    TokenBehaviour::Issue => {
                        let claims = complete_claims(&state);
                        let id_token = if state.unsigned {
                            testkey::unsigned(&claims)
                        } else {
                            testkey::sign_rs256(&claims, &state.key_id)
                        };
                        ResponseTemplate::new(200).set_body_json(json!({
                            "access_token": "access-token",
                            "token_type": "Bearer",
                            "expires_in": 300,
                            "id_token": id_token,
                        }))
                    }
                };
                response.set_delay(state.token_delay)
            }
            _ => ResponseTemplate::new(404).set_body_string("no such endpoint"),
        }
    }
}

fn complete_claims(state: &IdpState) -> Value {
    let now = jiff::Timestamp::now().as_second();
    let mut claims = state.claims.clone();
    let object = claims.as_object_mut().expect("claims are an object");
    object.entry("iss").or_insert_with(|| json!(state.issuer));
    object.entry("aud").or_insert_with(|| json!(super::app::CLIENT_ID));
    object.entry("sub").or_insert_with(|| json!("subject-1"));
    object.entry("iat").or_insert_with(|| json!(now));
    object.entry("exp").or_insert_with(|| json!(now + 300));
    claims
}

fn discovery_document(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "preferred_username", "name", "groups"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"]
    })
}

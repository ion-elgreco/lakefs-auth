//! Runs the server in process and drives it with `tower::ServiceExt::oneshot`.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use http_body_util::BodyExt;
use lakefs_authn::lakefs::SESSION_COOKIE;
use lakefs_authn::oidc::claims::raw_payload;
use lakefs_authn::{AppState, Config, build_router};
use tower::ServiceExt;

/// Shared secret every test uses; the same value lakeFS would put in `auth.encrypt.secret_key`.
pub const SECRET: &str = "test-shared-secret-value";
pub const PUBLIC_URL: &str = "http://authn.test";
pub const CLIENT_ID: &str = "lakefs";

/// Builds a configuration with the mandatory flags filled in.
///
/// A flag that `extra` already carries is dropped from the defaults, so callers can
/// override the public URL or the client id without a clap argument conflict.
pub fn config(issuer: &str, authz_url: &str, extra: &[&str]) -> Config {
    let defaults: [(&str, String); 5] = [
        ("--secret-key", SECRET.to_owned()),
        ("--public-url", PUBLIC_URL.to_owned()),
        ("--oidc-issuer", issuer.to_owned()),
        ("--oidc-client-id", CLIENT_ID.to_owned()),
        ("--authz-url", format!("{authz_url}/api/v1")),
    ];
    let overridden: Vec<&str> = extra.iter().copied().filter(|item| item.starts_with("--")).collect();
    let mut args: Vec<String> = vec!["lakefs-authn".to_owned()];
    for (flag, value) in defaults {
        if !overridden.contains(&flag) {
            args.push(flag.to_owned());
            args.push(value);
        }
    }
    args.extend(extra.iter().map(|item| (*item).to_owned()));
    Config::try_from_args(args).expect("the test configuration parses")
}

pub struct TestApp {
    pub state: AppState,
    router: Router,
}

impl TestApp {
    /// Builds the application without running discovery.
    pub async fn new(config: Config) -> Self {
        let state = AppState::from_config(config).await.expect("state builds");
        Self {
            router: build_router(state.clone()),
            state,
        }
    }

    /// Builds the application and waits for one successful discovery round.
    pub async fn discovered(config: Config) -> Self {
        let app = Self::new(config).await;
        app.state.oidc.discover().await.expect("discovery succeeds");
        app
    }

    pub async fn get(&self, uri: &str) -> TestResponse {
        self.send(Request::get(uri).body(Body::empty()).unwrap()).await
    }

    pub async fn get_with_cookies(&self, uri: &str, cookies: &[String]) -> TestResponse {
        let mut request = Request::get(uri);
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies.join("; "));
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    pub async fn post_json(&self, uri: &str, body: &serde_json::Value) -> TestResponse {
        self.send(
            Request::post(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
    }

    pub async fn post_empty(&self, uri: &str) -> TestResponse {
        self.send(
            Request::post(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
    }

    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self.router.clone().oneshot(request).await.expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.expect("body reads").to_bytes();
        TestResponse {
            status,
            headers,
            body: body.to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl TestResponse {
    pub fn location(&self) -> String {
        location(&self.headers).unwrap_or_else(|| panic!("no Location header, status {}", self.status))
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| panic!("body is not JSON ({error}): {}", self.text()))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn message(&self) -> String {
        self.json()["message"].as_str().unwrap_or_default().to_owned()
    }

    pub fn set_cookie_headers(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect()
    }

    /// The `name=value` pair of one `Set-Cookie` header.
    pub fn cookie(&self, name: &str) -> Option<String> {
        set_cookie_pair(&self.headers, name)
    }

    /// The whole `Set-Cookie` header of one cookie, attributes included.
    pub fn cookie_header(&self, name: &str) -> Option<String> {
        self.set_cookie_headers()
            .into_iter()
            .find(|header| header.starts_with(&format!("{name}=")))
    }

    /// The value of one `Set-Cookie` header exactly as it went out. The lakeFS
    /// session cookie must open from this form: lakeFS never percent decodes it.
    pub fn raw_cookie_value(&self, name: &str) -> Option<String> {
        self.cookie(name).map(|pair| {
            pair.split_once('=')
                .map(|(_, value)| value)
                .unwrap_or_default()
                .to_owned()
        })
    }

    /// The value of one `Set-Cookie` header, percent decoding included.
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.raw_cookie_value(name).map(|raw| {
            percent_encoding::percent_decode_str(&raw)
                .decode_utf8_lossy()
                .into_owned()
        })
    }

    pub fn header(&self, name: &str) -> Option<&HeaderValue> {
        self.headers.get(name)
    }
}

/// The `Location` header, when there is one.
pub fn location(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The `name=value` pair of one `Set-Cookie` header, exactly as the server sent it.
pub fn set_cookie_pair(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .map(|value| value.split(';').next().unwrap_or_default().to_owned())
}

/// Opens a session cookie value and returns the `sub` of the login JWT.
pub fn session_username(cookie_value: &str) -> String {
    use lakefs_authn::lakefs::gob;
    use lakefs_authn::lakefs::securecookie::CookieCodec;

    let payload = CookieCodec::new(SECRET.as_bytes())
        .decode(SESSION_COOKIE, cookie_value)
        .expect("the cookie opens");
    let token = gob::decode_token_map(&payload).expect("the gob decodes");
    let claims = raw_payload(&token).expect("JSON claims");
    assert_eq!(claims["iss"], "auth");
    assert_eq!(claims["aud"], "login");
    claims["sub"].as_str().expect("a subject").to_owned()
}

/// Percent-encodes a query value the way a browser does.
pub fn urlencode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Parses the query string of a URL into pairs.
pub fn query_pairs(url: &str) -> std::collections::BTreeMap<String, String> {
    url::Url::parse(url)
        .expect("an absolute URL")
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

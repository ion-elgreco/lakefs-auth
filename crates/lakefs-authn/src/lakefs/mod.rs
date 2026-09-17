//! The lakeFS browser session: a Go gob payload inside a gorilla securecookie envelope.

pub mod gob;
pub mod jwt;
pub mod securecookie;
pub mod session;

pub use jwt::{LoginClaims, mint_login_token};
pub use securecookie::{CookieCodec, CookieError};
pub use session::{FLOW_COOKIE, ID_TOKEN_COOKIE, SESSION_COOKIE, SessionCookies, SessionOptions};

#[cfg(test)]
mod fixture_tests {
    //! Golden data from `fixtures/sessions.json`, produced by Go and gorilla itself.

    use pretty_assertions::assert_eq;
    use serde::Deserialize;

    use super::gob;
    use super::securecookie::{CookieCodec, CookieError};

    const FIXTURE: &str = include_str!("../../fixtures/sessions.json");

    #[derive(Debug, Deserialize)]
    struct Fixture {
        go_version: String,
        cookie_name: String,
        hash_key: String,
        pinned_timestamp: i64,
        map_type_id: i64,
        cases: Vec<Case>,
    }

    #[derive(Debug, Deserialize)]
    struct Case {
        name: String,
        #[serde(default)]
        token: String,
        #[serde(default)]
        token_repeat: String,
        token_len: usize,
        gob_hex: String,
        #[serde(default)]
        envelope: String,
        #[serde(default)]
        store_cookie: String,
        #[serde(default)]
        store_timestamp: i64,
    }

    impl Case {
        fn token(&self) -> String {
            if self.token_repeat.is_empty() {
                self.token.clone()
            } else {
                self.token_repeat.repeat(self.token_len)
            }
        }
    }

    fn fixture() -> Fixture {
        serde_json::from_str(FIXTURE).expect("fixtures/sessions.json parses")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_fixture_describes_the_expected_stack() {
        let fixture = fixture();
        assert!(fixture.go_version.starts_with("go1."), "{}", fixture.go_version);
        assert_eq!(fixture.cookie_name, super::SESSION_COOKIE);
        assert_eq!(fixture.map_type_id, gob::MAP_TYPE_ID);
        assert_eq!(fixture.cases.len(), 15);
    }

    #[test]
    fn the_gob_bytes_match_go_for_every_length() {
        for case in fixture().cases {
            let token = case.token();
            assert_eq!(token.len(), case.token_len, "{}", case.name);
            let encoded = gob::encode_token_map(&token);
            assert_eq!(hex(&encoded), case.gob_hex, "gob bytes differ for {}", case.name);
            assert_eq!(gob::decode_token_map(&encoded).unwrap(), token, "{}", case.name);
            // The Go bytes decode with our decoder too, not just our own output.
            assert_eq!(
                gob::decode_token_map(&unhex(&case.gob_hex)).unwrap(),
                token,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn the_pinned_envelopes_match_gorilla() {
        let fixture = fixture();
        let codec = CookieCodec::new(fixture.hash_key.as_bytes()).with_max_length(0);
        let mut checked = 0;
        for case in &fixture.cases {
            if case.envelope.is_empty() {
                continue;
            }
            let payload = unhex(&case.gob_hex);
            let sealed = codec
                .encode_at(&fixture.cookie_name, &payload, fixture.pinned_timestamp)
                .expect("sealing works");
            assert_eq!(sealed, case.envelope, "envelope differs for {}", case.name);
            let opened = codec
                .decode_at(&fixture.cookie_name, &case.envelope, fixture.pinned_timestamp)
                .expect("opening works");
            assert_eq!(opened, payload, "{}", case.name);
            checked += 1;
        }
        assert!(checked >= 13, "checked only {checked} envelopes");
    }

    #[test]
    fn real_session_store_cookies_decode() {
        let fixture = fixture();
        let codec = CookieCodec::new(fixture.hash_key.as_bytes()).with_max_length(0);
        for case in &fixture.cases {
            if case.store_cookie.is_empty() {
                continue;
            }
            let payload = codec
                .decode_at(&fixture.cookie_name, &case.store_cookie, case.store_timestamp)
                .unwrap_or_else(|error| panic!("{} did not open: {error}", case.name));
            assert_eq!(gob::decode_token_map(&payload).unwrap(), case.token(), "{}", case.name);
        }
    }

    #[test]
    fn a_tampered_fixture_cookie_is_refused() {
        let fixture = fixture();
        let codec = CookieCodec::new(fixture.hash_key.as_bytes());
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == "realistic-jwt")
            .expect("the realistic JWT case exists");
        assert!(case.envelope.len() < 700, "cookie length {}", case.envelope.len());
        let mut flipped: Vec<u8> = case.envelope.bytes().collect();
        // Flip a bit inside the base64 alphabet so that decoding still succeeds.
        let last = flipped.len() - 2;
        flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(flipped).unwrap();
        assert_eq!(
            codec.decode_at(&fixture.cookie_name, &tampered, fixture.pinned_timestamp),
            Err(CookieError::BadSignature)
        );
        // The untouched fixture still opens, so the flip is what broke it.
        assert!(
            codec
                .decode_at(&fixture.cookie_name, &case.envelope, fixture.pinned_timestamp)
                .is_ok()
        );
    }
}

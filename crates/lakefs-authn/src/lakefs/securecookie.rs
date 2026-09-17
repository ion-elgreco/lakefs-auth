//! Port of gorilla `securecookie` in the configuration lakeFS uses: HMAC-SHA256, no encryption.
//!
//! `Encode` builds `base64url(timestamp | base64url(value) | <raw mac>)` where the MAC
//! covers `name|timestamp|base64url(value)` without the trailing pipe. `Decode` splits
//! on at most three pipes because the raw MAC may itself contain a pipe byte.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// gorilla's default `maxLength`.
const DEFAULT_MAX_LENGTH: usize = 4096;
/// gorilla's default `maxAge`, 30 days in seconds.
const DEFAULT_MAX_AGE: i64 = 86400 * 30;
/// Length of an HMAC-SHA256 tag.
const MAC_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CookieError {
    #[error("the encoded cookie value is too long")]
    TooLong,
    #[error("the cookie value is not valid base64")]
    NotBase64,
    #[error("the cookie value is malformed")]
    Malformed,
    #[error("the cookie signature does not match")]
    BadSignature,
    #[error("the cookie timestamp is not a number")]
    BadTimestamp,
    #[error("the cookie has expired")]
    Expired,
}

/// Signs and verifies gorilla session cookies with the lakeFS shared secret.
/// The HMAC is keyed once; each cookie clones the keyed state instead of
/// running the key schedule again.
#[derive(Clone)]
pub struct CookieCodec {
    mac: HmacSha256,
    max_length: usize,
    max_age: i64,
}

impl std::fmt::Debug for CookieCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieCodec")
            .field("max_length", &self.max_length)
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

impl CookieCodec {
    pub fn new(hash_key: &[u8]) -> Self {
        Self {
            mac: HmacSha256::new_from_slice(hash_key).expect("HMAC accepts any key length"),
            max_length: DEFAULT_MAX_LENGTH,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    /// `0` disables the length check, like gorilla's `MaxLength(0)`.
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// `0` disables the age check, like gorilla's `MaxAge(0)`.
    #[cfg(test)]
    fn with_max_age(mut self, max_age: i64) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn encode(&self, name: &str, value: &[u8]) -> Result<String, CookieError> {
        self.encode_at(name, value, now())
    }

    pub fn encode_at(&self, name: &str, value: &[u8], timestamp: i64) -> Result<String, CookieError> {
        let encoded_value = URL_SAFE.encode(value);
        let signed = format!("{name}|{timestamp}|{encoded_value}");
        let mac = self.mac(signed.as_bytes());
        // gorilla keeps the trailing pipe and drops the leading `name|`.
        let mut payload = Vec::with_capacity(signed.len() + 1 + MAC_LEN);
        payload.extend_from_slice(&signed.as_bytes()[name.len() + 1..]);
        payload.push(b'|');
        payload.extend_from_slice(&mac);
        let out = URL_SAFE.encode(&payload);
        if self.max_length != 0 && out.len() > self.max_length {
            return Err(CookieError::TooLong);
        }
        Ok(out)
    }

    pub fn decode(&self, name: &str, value: &str) -> Result<Vec<u8>, CookieError> {
        self.decode_at(name, value, now())
    }

    pub fn decode_at(&self, name: &str, value: &str, now: i64) -> Result<Vec<u8>, CookieError> {
        if self.max_length != 0 && value.len() > self.max_length {
            return Err(CookieError::TooLong);
        }
        let raw = URL_SAFE.decode(value.as_bytes()).map_err(|_| CookieError::NotBase64)?;
        // The MAC is raw bytes and may contain a pipe, so only the first two are separators.
        let mut parts = raw.splitn(3, |byte| *byte == b'|');
        let timestamp = parts.next().ok_or(CookieError::Malformed)?;
        let encoded_value = parts.next().ok_or(CookieError::Malformed)?;
        let mac = parts.next().ok_or(CookieError::Malformed)?;
        let mut signed = Vec::with_capacity(name.len() + 1 + timestamp.len() + 1 + encoded_value.len());
        signed.extend_from_slice(name.as_bytes());
        signed.push(b'|');
        signed.extend_from_slice(timestamp);
        signed.push(b'|');
        signed.extend_from_slice(encoded_value);
        let expected = self.mac(&signed);
        if !bool::from(expected.as_slice().ct_eq(mac)) {
            return Err(CookieError::BadSignature);
        }
        let issued: i64 = std::str::from_utf8(timestamp)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or(CookieError::BadTimestamp)?;
        // gorilla also has a `MinAge`; lakeFS never sets it, so it is not ported.
        if self.max_age != 0 && issued < now - self.max_age {
            return Err(CookieError::Expired);
        }
        URL_SAFE.decode(encoded_value).map_err(|_| CookieError::NotBase64)
    }

    fn mac(&self, message: &[u8]) -> [u8; MAC_LEN] {
        let mut mac = self.mac.clone();
        mac.update(message);
        mac.finalize().into_bytes().into()
    }
}

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const NAME: &str = lakefs_auth_core::SESSION_COOKIE;
    const KEY: &[u8] = b"a shared lakeFS secret";
    const TS: i64 = 1_767_225_600;

    fn codec() -> CookieCodec {
        CookieCodec::new(KEY)
    }

    #[test]
    fn round_trips_a_payload() {
        let sealed = codec().encode_at(NAME, b"hello gorilla", TS).unwrap();
        assert_eq!(codec().decode_at(NAME, &sealed, TS).unwrap(), b"hello gorilla");
    }

    #[test]
    fn envelope_layout_matches_gorilla() {
        let sealed = codec().encode_at(NAME, b"payload", TS).unwrap();
        let raw = URL_SAFE.decode(sealed.as_bytes()).unwrap();
        let text = String::from_utf8_lossy(&raw[..raw.len() - MAC_LEN]);
        assert_eq!(text, format!("{TS}|{}|", URL_SAFE.encode(b"payload")));
        assert_eq!(raw.len() - text.len(), MAC_LEN);
    }

    #[test]
    fn a_flipped_mac_is_rejected() {
        let sealed = codec().encode_at(NAME, b"payload", TS).unwrap();
        let mut raw = URL_SAFE.decode(sealed.as_bytes()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = URL_SAFE.encode(&raw);
        assert_eq!(codec().decode_at(NAME, &tampered, TS), Err(CookieError::BadSignature));
    }

    #[test]
    fn another_cookie_name_is_rejected() {
        let sealed = codec().encode_at(NAME, b"payload", TS).unwrap();
        assert_eq!(
            codec().decode_at("other_cookie", &sealed, TS),
            Err(CookieError::BadSignature)
        );
    }

    #[test]
    fn another_key_is_rejected() {
        let sealed = codec().encode_at(NAME, b"payload", TS).unwrap();
        assert_eq!(
            CookieCodec::new(b"different key").decode_at(NAME, &sealed, TS),
            Err(CookieError::BadSignature)
        );
    }

    #[test]
    fn a_thirty_one_day_old_cookie_expires() {
        let sealed = codec().encode_at(NAME, b"payload", TS).unwrap();
        let now = TS + 31 * 86400;
        assert_eq!(codec().decode_at(NAME, &sealed, now), Err(CookieError::Expired));
        // One day inside the window still works.
        assert!(codec().decode_at(NAME, &sealed, TS + 29 * 86400).is_ok());
        // With the age check off it stays valid.
        assert!(codec().with_max_age(0).decode_at(NAME, &sealed, now).is_ok());
    }

    #[test]
    fn oversize_payloads_are_refused_in_both_directions() {
        let big = vec![b'x'; 4096];
        assert_eq!(codec().encode_at(NAME, &big, TS), Err(CookieError::TooLong));
        let sealed = codec().with_max_length(0).encode_at(NAME, &big, TS).unwrap();
        assert!(sealed.len() > DEFAULT_MAX_LENGTH);
        assert_eq!(codec().decode_at(NAME, &sealed, TS), Err(CookieError::TooLong));
        assert!(codec().with_max_length(0).decode_at(NAME, &sealed, TS).is_ok());
    }

    #[test]
    fn malformed_values_are_refused() {
        assert_eq!(
            codec().decode_at(NAME, "not base64 !!", TS),
            Err(CookieError::NotBase64)
        );
        let no_pipes = URL_SAFE.encode(b"nopipeshere");
        assert_eq!(codec().decode_at(NAME, &no_pipes, TS), Err(CookieError::Malformed));
        let one_pipe = URL_SAFE.encode(b"123|abc");
        assert_eq!(codec().decode_at(NAME, &one_pipe, TS), Err(CookieError::Malformed));
    }

    #[test]
    fn a_non_numeric_timestamp_is_refused() {
        // Sign a well formed envelope whose timestamp is not a number.
        let encoded_value = URL_SAFE.encode(b"payload");
        let signed = format!("{NAME}|nan|{encoded_value}");
        let mac = codec().mac(signed.as_bytes());
        let mut payload = format!("nan|{encoded_value}|").into_bytes();
        payload.extend_from_slice(&mac);
        let sealed = URL_SAFE.encode(&payload);
        assert_eq!(codec().decode_at(NAME, &sealed, TS), Err(CookieError::BadTimestamp));
    }

    #[test]
    fn a_typical_session_cookie_is_well_under_the_limit() {
        let token = format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}.{}",
            "x".repeat(180),
            "y".repeat(43)
        );
        let gob = crate::lakefs::gob::encode_token_map(&token);
        let sealed = codec().encode_at(NAME, &gob, TS).unwrap();
        assert!(sealed.len() < 700, "cookie length {}", sealed.len());
    }
}

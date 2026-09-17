//! Claim handling: the raw verified payload, flattening, and `--oidc-validate-claims`.
//!
//! Claims come from the raw JWT payload rather than from a re-serialized struct so
//! that `aud`, timestamps, and provider specific shapes keep their original form.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

pub type Claims = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsError {
    #[error("the ID token is not a three part JWT")]
    Malformed,
    #[error("the ID token payload is not valid base64url")]
    NotBase64,
    #[error("the ID token payload is not a JSON object")]
    NotAnObject,
}

/// Decodes the payload of a JWT whose signature another component already verified.
pub fn raw_payload(token: &str) -> Result<Claims, ClaimsError> {
    let mut parts = token.split('.');
    let payload = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(_header), Some(payload), Some(_signature), None) => payload,
        _ => return Err(ClaimsError::Malformed),
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ClaimsError::NotBase64)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(ClaimsError::NotAnObject),
    }
}

/// Renders every claim as a string, which is what the STS response allows.
///
/// Null claims are dropped, numbers and booleans use their natural rendering,
/// arrays of strings join with commas, and anything else becomes compact JSON.
pub fn flatten_claims(claims: &Claims) -> BTreeMap<String, String> {
    claims
        .iter()
        .filter_map(|(name, value)| flatten_value(value).map(|text| (name.clone(), text)))
        .collect()
}

pub fn flatten_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Array(items) if items.iter().all(Value::is_string) => {
            Some(items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
        }
        other => Some(other.to_string()),
    }
}

/// First claim in `names` that renders to a non-empty string.
pub fn first_claim<'a>(claims: &Claims, names: impl IntoIterator<Item = &'a String>) -> Option<(String, String)> {
    names
        .into_iter()
        .find_map(|name| claim_text(claims, name).map(|text| (name.clone(), text)))
}

/// One claim rendered as a string, if present and not empty.
pub fn claim_text(claims: &Claims, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(flatten_value)
        .filter(|text| !text.trim().is_empty())
}

/// Enforces `--oidc-validate-claims`.
///
/// A claim matches when its flattened value equals the expected value exactly,
/// which is how lakeFS compares the flattened claims it receives from the STS
/// login. An array therefore matches as a whole, `a,b`, never by membership.
pub fn validate_claims(claims: &Claims, expected: &BTreeMap<String, String>) -> Result<(), String> {
    for (name, want) in expected {
        let Some(value) = claims.get(name) else {
            return Err(format!("claim {name:?} is missing"));
        };
        if flatten_value(value).as_deref() != Some(want.as_str()) {
            return Err(format!("claim {name:?} does not have the expected value"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    fn sample() -> Claims {
        match json!({
            "sub": "user-1",
            "email_verified": true,
            "iat": 1767225600,
            "score": 1.5,
            "nothing": null,
            "aud": ["lakefs", "other"],
            "address": {"country": "NL"},
            "mixed": [1, "two"],
            "empty_list": []
        }) {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    #[test]
    fn flattening_follows_the_contract() {
        let flat = flatten_claims(&sample());
        assert_eq!(flat["sub"], "user-1");
        assert_eq!(flat["email_verified"], "true");
        assert_eq!(flat["iat"], "1767225600");
        assert_eq!(flat["score"], "1.5");
        assert_eq!(flat["aud"], "lakefs,other");
        assert_eq!(flat["address"], r#"{"country":"NL"}"#);
        assert_eq!(flat["mixed"], r#"[1,"two"]"#);
        assert_eq!(flat["empty_list"], "");
        assert!(!flat.contains_key("nothing"), "null claims are dropped");
    }

    #[test]
    fn payload_comes_from_the_raw_token() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"abc","aud":"single"}"#);
        let token = format!("header.{payload}.signature");
        let claims = raw_payload(&token).unwrap();
        assert_eq!(claims["sub"], "abc");
        assert_eq!(claims["aud"], "single");
        assert_eq!(raw_payload("only.two"), Err(ClaimsError::Malformed));
        assert_eq!(raw_payload("a.b.c.d"), Err(ClaimsError::Malformed));
        assert_eq!(raw_payload("a.!!!.c"), Err(ClaimsError::NotBase64));
        let not_object = URL_SAFE_NO_PAD.encode(b"[1,2]");
        assert_eq!(raw_payload(&format!("a.{not_object}.c")), Err(ClaimsError::NotAnObject));
    }

    #[test]
    fn username_claims_fall_back_in_order() {
        let claims = sample();
        let order = vec!["preferred_username".to_owned(), "email".to_owned(), "sub".to_owned()];
        assert_eq!(
            first_claim(&claims, &order),
            Some(("sub".to_owned(), "user-1".to_owned()))
        );
        assert_eq!(first_claim(&claims, &["missing".to_owned()]), None);
        assert_eq!(claim_text(&claims, "nothing"), None);
    }

    /// A check compares the flattened value exactly, the way lakeFS compares
    /// the flattened claims it receives, so an array matches only as a whole.
    #[test]
    fn claim_validation_compares_the_flattened_value_exactly() {
        let claims = sample();
        let mut expected = BTreeMap::new();
        expected.insert("sub".to_owned(), "user-1".to_owned());
        assert!(validate_claims(&claims, &expected).is_ok());
        expected.insert("email_verified".to_owned(), "true".to_owned());
        assert!(validate_claims(&claims, &expected).is_ok());
        expected.insert("aud".to_owned(), "lakefs,other".to_owned());
        assert!(validate_claims(&claims, &expected).is_ok());
        expected.insert("aud".to_owned(), "lakefs".to_owned());
        assert!(
            validate_claims(&claims, &expected).is_err(),
            "membership in an array is not a match"
        );
        expected.remove("aud");
        expected.insert("sub".to_owned(), "someone-else".to_owned());
        assert!(validate_claims(&claims, &expected).is_err());
        let mut missing = BTreeMap::new();
        missing.insert("hd".to_owned(), "example.com".to_owned());
        assert!(validate_claims(&claims, &missing).is_err());
    }
}

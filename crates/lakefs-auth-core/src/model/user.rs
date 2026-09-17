use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A user as returned by the authorization API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    /// Unix epoch seconds.
    pub creation_date: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Always present on the wire because the spec marks it required.
    /// `None` serializes as `null`, which the lakeFS client reads as an empty byte slice.
    #[serde(rename = "encryptedPassword", default)]
    pub encrypted_password: Option<Base64Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// Body of `POST /auth/users`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCreation {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "friendlyName", default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "encryptedPassword", default, skip_serializing_if = "Option::is_none")]
    pub encrypted_password: Option<Base64Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<bool>,
}

/// Body of `PUT /auth/users/{userId}/friendly_name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriendlyNameUpdate {
    pub friendly_name: String,
}

/// Bytes carried as standard base64 on the wire (OpenAPI `format: byte`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Base64Bytes(pub Vec<u8>);

impl Serialize for Base64Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD
            .decode(text.as_bytes())
            .map(Base64Bytes)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn user_emits_null_password_and_snake_case_friendly_name() {
        let user = User {
            username: "alice".into(),
            creation_date: 1,
            friendly_name: Some("Alice".into()),
            email: None,
            source: Some("oidc".into()),
            encrypted_password: None,
            external_id: Some("sub-1".into()),
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "username": "alice",
                "creation_date": 1,
                "friendly_name": "Alice",
                "source": "oidc",
                "encryptedPassword": null,
                "external_id": "sub-1"
            })
        );
    }

    #[test]
    fn user_creation_reads_camel_case_friendly_name() {
        let created: UserCreation = serde_json::from_value(serde_json::json!({
            "username": "bob",
            "friendlyName": "Bob",
            "encryptedPassword": "aGVsbG8=",
            "invite": false
        }))
        .unwrap();
        assert_eq!(created.friendly_name.as_deref(), Some("Bob"));
        assert_eq!(created.encrypted_password, Some(Base64Bytes(b"hello".to_vec())));
        assert_eq!(created.invite, Some(false));
    }
}

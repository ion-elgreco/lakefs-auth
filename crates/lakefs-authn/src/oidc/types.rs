//! Typestate aliases for the OpenID Connect client and the groups claim we read.
//!
//! The client types no extra claim. The verifier only checks the signature,
//! the audience, the nonce, and the timestamps; the provisioner then reads the
//! claims it needs from the raw payload and accepts any shape, so no typed
//! field can refuse a whole token because a provider spells a claim differently.

use lakefs_auth_core::config::CommaList;
use lakefs_auth_core::text::non_blank;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    Client, EmptyAdditionalClaims, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdToken,
    IdTokenFields, StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

/// A groups claim, either a JSON array or one comma separated string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GroupsClaim {
    List(Vec<String>),
    Text(String),
}

impl GroupsClaim {
    /// The group names, trimmed, without the blank ones.
    pub fn values(&self) -> Vec<String> {
        match self {
            Self::List(items) => items
                .iter()
                .filter_map(|item| non_blank(item))
                .map(str::to_owned)
                .collect(),
            Self::Text(text) => {
                let Ok(CommaList(items)) = text.parse();
                items
            }
        }
    }
}

pub type AuthnIdTokenFields = IdTokenFields<
    EmptyAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type AuthnTokenResponse = StandardTokenResponse<AuthnIdTokenFields, CoreTokenType>;

pub type AuthnIdToken =
    IdToken<EmptyAdditionalClaims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;

pub type AuthnErrorResponse = StandardErrorResponse<CoreErrorResponseType>;

/// The client `from_provider_metadata` yields: the authorization endpoint is always
/// set, the token and userinfo endpoints may be, and nothing else is.
pub type AuthnClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    AuthnErrorResponse,
    AuthnTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn groups_claim_reads_both_shapes() {
        let list: GroupsClaim = serde_json::from_value(serde_json::json!(["a", " b ", ""])).unwrap();
        assert_eq!(list.values(), ["a", "b"]);
        let text: GroupsClaim = serde_json::from_value(serde_json::json!("a, b ,,c")).unwrap();
        assert_eq!(text.values(), ["a", "b", "c"]);
    }
}

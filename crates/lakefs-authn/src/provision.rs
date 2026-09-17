//! Turns verified OIDC claims into a lakeFS user through the authorization API.

use std::collections::BTreeMap;

use lakefs_auth_core::error::ApiError;
use lakefs_auth_core::validate::validate_entity_id;
use lakefs_authz_client::{AuthzClient, ClientError, EnsureUserSpec, EnsuredUser};
use serde::Deserialize as _;

use crate::oidc::claims::{Claims, claim_text, first_claim, flatten_value};
use crate::oidc::types::GroupsClaim;

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("the ID token has no subject")]
    MissingSubject,
    #[error("no claim in {0} carries a username")]
    NoUsernameClaim(String),
    #[error("the derived username {username:?} is not usable: {reason}")]
    InvalidUsername { username: String, reason: String },
    #[error("the username derived for this identity already belongs to another identity")]
    UsernameCollision,
    #[error("the identity is not known and automatic provisioning is off")]
    UnknownIdentity,
    #[error("the authorization server rejected the request")]
    Authz(#[from] ClientError),
    #[error("the provisioning task did not finish: {0}")]
    TaskFailed(String),
}

impl From<ProvisionError> for ApiError {
    fn from(error: ProvisionError) -> Self {
        match error {
            ProvisionError::Authz(inner) => ApiError::internal(anyhow::Error::new(inner)),
            ProvisionError::TaskFailed(reason) => ApiError::internal(anyhow::anyhow!(reason)),
            other => ApiError::unauthorized(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProvisionSettings {
    /// Claims tried in order when deriving the username.
    pub username_claims: Vec<String>,
    pub friendly_name_claim: String,
    pub persist_friendly_name: bool,
    pub initial_groups: Vec<String>,
    pub groups_claim: Option<String>,
    pub group_map: BTreeMap<String, String>,
    pub group_map_strict: bool,
    pub source: String,
    /// Create a user at the first login of an unknown identity.
    pub auto_provision: bool,
}

pub struct Provisioner {
    client: AuthzClient,
    settings: ProvisionSettings,
}

impl std::fmt::Debug for Provisioner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provisioner").field("settings", &self.settings).finish()
    }
}

impl Provisioner {
    pub fn new(client: AuthzClient, settings: ProvisionSettings) -> Self {
        Self { client, settings }
    }

    /// First non-empty configured claim, rejected when it cannot be a lakeFS
    /// username. An unverified `email` claim is skipped: see [`Self::verified_email`].
    pub fn derive_username(&self, claims: &Claims) -> Result<String, ProvisionError> {
        let email_unverified = email_is_unverified(claims);
        let candidates = self
            .settings
            .username_claims
            .iter()
            .filter(|name| !(email_unverified && name.as_str() == "email"));
        let (claim, value) = first_claim(claims, candidates)
            .ok_or_else(|| ProvisionError::NoUsernameClaim(self.settings.username_claims.join(", ")))?;
        let username = value.trim().to_owned();
        validate_username(&username)?;
        tracing::debug!(claim = %claim, "derived the username from a claim");
        Ok(username)
    }

    /// The `email` claim, unless the provider marks it unverified.
    ///
    /// A self-service provider lets its users type any address and sends
    /// `email_verified: false` until they prove it. Such an address names no
    /// lakeFS user and is not stored, or an attacker could take a colleague's
    /// address, which is unique in the store, and lock the real owner out.
    pub fn verified_email(claims: &Claims) -> Option<String> {
        if email_is_unverified(claims) {
            return None;
        }
        claim_text(claims, "email")
    }

    /// Groups the user joins on creation.
    ///
    /// A configured groups claim wins. In strict mode only groups the map
    /// mentions survive, and when none does the user joins no group at all.
    /// The fallback to `--initial-groups` applies when the claim is absent or
    /// unreadable, where no mapping was attempted, and in lenient mode.
    pub fn resolve_groups(&self, claims: &Claims) -> Vec<String> {
        let Some(name) = &self.settings.groups_claim else {
            return self.settings.initial_groups.clone();
        };
        let Some(raw) = claims.get(name) else {
            tracing::debug!(claim = %name, "groups claim is absent, using the initial groups");
            return self.settings.initial_groups.clone();
        };
        let Ok(parsed) = GroupsClaim::deserialize(raw) else {
            tracing::warn!(claim = %name, "groups claim is neither a string list nor a comma separated string");
            return self.settings.initial_groups.clone();
        };
        let mut groups = Vec::new();
        for group in parsed.values() {
            match self.settings.group_map.get(&group) {
                Some(mapped) => groups.push(mapped.clone()),
                None if self.settings.group_map_strict => {
                    tracing::info!(group = %group, "dropping a group that the group map does not mention");
                }
                None => groups.push(group),
            }
        }
        groups.sort();
        groups.dedup();
        if groups.is_empty() {
            if self.settings.group_map_strict {
                tracing::info!("no group survived the strict mapping; the user joins no group");
                return groups;
            }
            tracing::debug!("the groups claim is empty, using the initial groups");
            return self.settings.initial_groups.clone();
        }
        groups
    }

    /// Finds or creates the lakeFS user behind these claims.
    ///
    /// The create runs in its own task. The request that started it may be
    /// dropped half way, by the request timeout or by a browser that went
    /// away, and a user that was created without its groups would keep no
    /// groups: a returning identity is never re-synced. The task finishes,
    /// or rolls the create back, whatever happens to the request.
    pub async fn ensure_user(&self, claims: &Claims) -> Result<EnsuredUser, ProvisionError> {
        let subject = claim_text(claims, "sub").ok_or(ProvisionError::MissingSubject)?;
        let friendly_name = claim_text(claims, &self.settings.friendly_name_claim);

        if let Some(user) = self.client.find_user_by_external_id(&subject).await? {
            if self.settings.persist_friendly_name
                && let Some(name) = &friendly_name
                && user.friendly_name.as_deref() != Some(name.as_str())
                && let Err(error) = self.client.update_friendly_name(&user.username, name).await
            {
                tracing::warn!(error = %error, username = %user.username, "could not update the friendly name");
            }
            return Ok(EnsuredUser { user, created: false });
        }
        if !self.settings.auto_provision {
            tracing::warn!(subject = %subject, "refusing the login: unknown identity and automatic provisioning is off");
            return Err(ProvisionError::UnknownIdentity);
        }

        let username = self.derive_username(claims)?;
        let groups = self.resolve_groups(claims);
        let spec = EnsureUserSpec {
            external_id: subject.clone(),
            username: username.clone(),
            email: Self::verified_email(claims),
            friendly_name: friendly_name.filter(|_| self.settings.persist_friendly_name),
            source: self.settings.source.clone(),
            groups,
        };
        let client = self.client.clone();
        let created = tokio::spawn(async move { client.create_user_with_groups(&spec).await })
            .await
            .map_err(|error| ProvisionError::TaskFailed(error.to_string()))?;
        match created {
            Ok(ensured) => {
                if ensured.created {
                    tracing::info!(username = %ensured.user.username, "provisioned a new lakeFS user");
                }
                Ok(ensured)
            }
            Err(ClientError::AlreadyExists) => {
                tracing::error!(
                    username = %username,
                    subject = %subject,
                    "refusing the login: the username already belongs to another identity"
                );
                Err(ProvisionError::UsernameCollision)
            }
            Err(other) => Err(ProvisionError::Authz(other)),
        }
    }
}

/// True when the provider says the email is not verified. A missing claim is
/// trusted, because many providers never send it.
fn email_is_unverified(claims: &Claims) -> bool {
    claims
        .get("email_verified")
        .and_then(flatten_value)
        .is_some_and(|value| value.eq_ignore_ascii_case("false"))
}

/// The rules of the authorization API, so that a name it would refuse with a
/// 400 is a 401 here instead of a 500 from the create call, plus no whitespace.
fn validate_username(username: &str) -> Result<(), ProvisionError> {
    let invalid = |reason: String| ProvisionError::InvalidUsername {
        username: username.to_owned(),
        reason,
    };
    validate_entity_id("user", username).map_err(|error| invalid(error.to_string()))?;
    if username.chars().any(char::is_whitespace) {
        return Err(invalid("it contains whitespace".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::{Value, json};

    fn claims(value: Value) -> Claims {
        match value {
            Value::Object(map) => map,
            _ => unreachable!("claims are an object"),
        }
    }

    fn settings() -> ProvisionSettings {
        ProvisionSettings {
            username_claims: vec!["preferred_username".to_owned(), "email".to_owned(), "sub".to_owned()],
            friendly_name_claim: "name".to_owned(),
            persist_friendly_name: true,
            initial_groups: vec!["Developers".to_owned()],
            groups_claim: None,
            group_map: BTreeMap::new(),
            group_map_strict: true,
            source: "oidc".to_owned(),
            auto_provision: true,
        }
    }

    fn provisioner(settings: ProvisionSettings) -> Provisioner {
        let config = lakefs_authz_client::AuthzClientConfig::new(
            url::Url::parse("http://127.0.0.1:1/api/v1").unwrap(),
            lakefs_authz_client::ClientAuth::None,
        );
        Provisioner::new(AuthzClient::new(config).unwrap(), settings)
    }

    #[test]
    fn username_falls_back_through_the_claim_order() {
        let prov = provisioner(settings());
        assert_eq!(
            prov.derive_username(&claims(
                json!({"preferred_username": "alice", "email": "a@b.c", "sub": "s"})
            ))
            .unwrap(),
            "alice"
        );
        assert_eq!(
            prov.derive_username(&claims(json!({"email": "a@b.c", "sub": "s"})))
                .unwrap(),
            "a@b.c"
        );
        assert_eq!(prov.derive_username(&claims(json!({"sub": "s"}))).unwrap(), "s");
        assert!(matches!(
            prov.derive_username(&claims(json!({"other": "x"}))),
            Err(ProvisionError::NoUsernameClaim(_))
        ));
        // Empty and whitespace-only claims are skipped, not used.
        assert_eq!(
            prov.derive_username(&claims(json!({"preferred_username": "  ", "sub": "s"})))
                .unwrap(),
            "s"
        );
    }

    /// The same rules as the authorization API, plus no whitespace: a name the
    /// API would refuse must be a 401 here, not a 500 from the create call.
    #[test]
    fn unusable_usernames_are_rejected() {
        let prov = provisioner(settings());
        let long = "a".repeat(513);
        for bad in ["a/b", "a b", "a\tb", "a\u{0007}b", ".", "..", "*", "a*b", long.as_str()] {
            let result = prov.derive_username(&claims(json!({"preferred_username": bad, "sub": "s"})));
            assert!(matches!(result, Err(ProvisionError::InvalidUsername { .. })), "{bad}");
        }
    }

    /// An email the provider marks unverified is attacker-chosen at a
    /// self-service provider, so it names no user and is not stored.
    #[test]
    fn an_unverified_email_is_neither_a_username_nor_stored() {
        let prov = provisioner(settings());
        let unverified = claims(json!({"email": "victim@corp.com", "email_verified": false, "sub": "s"}));
        assert_eq!(prov.derive_username(&unverified).unwrap(), "s");
        assert_eq!(Provisioner::verified_email(&unverified), None);

        let verified = claims(json!({"email": "alice@corp.com", "email_verified": true, "sub": "s"}));
        assert_eq!(prov.derive_username(&verified).unwrap(), "alice@corp.com");
        assert_eq!(
            Provisioner::verified_email(&verified).as_deref(),
            Some("alice@corp.com")
        );

        // A provider that says nothing about verification is trusted, as before.
        let silent = claims(json!({"email": "bob@corp.com", "sub": "s"}));
        assert_eq!(prov.derive_username(&silent).unwrap(), "bob@corp.com");
        assert_eq!(Provisioner::verified_email(&silent).as_deref(), Some("bob@corp.com"));

        // The string spelling some providers use counts as well.
        let spelled = claims(json!({"email": "x@corp.com", "email_verified": "false", "sub": "s"}));
        assert_eq!(Provisioner::verified_email(&spelled), None);
    }

    #[test]
    fn groups_default_to_the_initial_list() {
        let prov = provisioner(settings());
        assert_eq!(prov.resolve_groups(&claims(json!({"groups": ["x"]}))), ["Developers"]);
    }

    #[test]
    fn groups_come_from_the_claim_in_both_shapes() {
        let mut config = settings();
        config.groups_claim = Some("groups".to_owned());
        config.group_map_strict = false;
        let prov = provisioner(config);
        assert_eq!(prov.resolve_groups(&claims(json!({"groups": ["b", "a"]}))), ["a", "b"]);
        assert_eq!(prov.resolve_groups(&claims(json!({"groups": "a, b"}))), ["a", "b"]);
        assert_eq!(prov.resolve_groups(&claims(json!({}))), ["Developers"]);
        assert_eq!(prov.resolve_groups(&claims(json!({"groups": 7}))), ["Developers"]);
    }

    /// Strict mode means "only what the map names". When nothing maps, the
    /// answer is no group at all, not the default group with its write access.
    /// The fallback stays for a claim that is absent or unreadable, where no
    /// mapping was attempted.
    #[test]
    fn strict_mapping_drops_unknown_groups_without_falling_back() {
        let mut config = settings();
        config.groups_claim = Some("groups".to_owned());
        config.group_map = BTreeMap::from([("idp-admins".to_owned(), "Admins".to_owned())]);
        let prov = provisioner(config);
        assert_eq!(
            prov.resolve_groups(&claims(json!({"groups": ["idp-admins", "unknown"]}))),
            ["Admins"]
        );
        assert_eq!(
            prov.resolve_groups(&claims(json!({"groups": ["unknown"]}))),
            Vec::<String>::new()
        );
        assert_eq!(
            prov.resolve_groups(&claims(json!({"groups": []}))),
            Vec::<String>::new()
        );
        assert_eq!(prov.resolve_groups(&claims(json!({}))), ["Developers"]);
        assert_eq!(prov.resolve_groups(&claims(json!({"groups": 7}))), ["Developers"]);
    }

    #[test]
    fn lenient_mapping_keeps_unknown_groups() {
        let mut config = settings();
        config.groups_claim = Some("groups".to_owned());
        config.group_map = BTreeMap::from([("idp-admins".to_owned(), "Admins".to_owned())]);
        config.group_map_strict = false;
        let prov = provisioner(config);
        assert_eq!(
            prov.resolve_groups(&claims(json!({"groups": ["idp-admins", "unknown"]}))),
            ["Admins", "unknown"]
        );
    }

    #[test]
    fn provision_errors_map_onto_http_statuses() {
        assert_eq!(
            ApiError::from(ProvisionError::UsernameCollision).status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::from(ProvisionError::MissingSubject).status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::from(ProvisionError::UnknownIdentity).status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::from(ProvisionError::Authz(ClientError::NotFound)).status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

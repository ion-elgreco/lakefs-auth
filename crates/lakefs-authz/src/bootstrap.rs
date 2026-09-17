//! Optional bootstrap file.
//!
//! The file describes policies, groups, and users that should exist. It is
//! applied in one transaction with "create if missing" semantics: bootstrap
//! never updates and never deletes, so re-running it is safe.

use std::path::Path;

use anyhow::{Context as _, bail};
use jiff::Timestamp;
use lakefs_auth_core::crypto::SecretBox;
use lakefs_auth_core::model::Statement;
use lakefs_auth_core::text::non_blank;
use lakefs_auth_core::validate::validate_entity_id;
use serde::Deserialize;

use crate::store::traits::Store;
use crate::store::types::{BootstrapPlan, BootstrapReport, NewCredential, NewGroup, NewPolicy, NewUser, UserFields};

/// The current file format. A file may state it, and must state `1` if it does.
pub const BOOTSTRAP_VERSION: u32 = 1;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapFile {
    /// Optional format marker, for a later format change.
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub policies: Vec<PolicySpec>,
    #[serde(default)]
    pub groups: Vec<GroupSpec>,
    #[serde(default)]
    pub users: Vec<UserSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    pub name: String,
    pub statement: Vec<Statement>,
    #[serde(default)]
    pub acl: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Policies attached to the group.
    #[serde(default)]
    pub policies: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub friendly_name: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub credentials: Vec<CredentialSpec>,
}

/// The secret comes from a literal or from an environment variable. Exactly one
/// of the two must be given: a generated secret would be stored encrypted and
/// shown to nobody, so the access key could never be used.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub secret_access_key_env: Option<String>,
}

impl CredentialSpec {
    fn resolve_secret(&self, env: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<String> {
        match (&self.secret_access_key, &self.secret_access_key_env) {
            (Some(_), Some(_)) => bail!(
                "credential {}: set secret_access_key or secret_access_key_env, not both",
                self.access_key_id
            ),
            (Some(literal), None) => Ok(literal.clone()),
            (None, Some(variable)) => env(variable).with_context(|| {
                format!(
                    "credential {}: environment variable {variable} is not set",
                    self.access_key_id
                )
            }),
            (None, None) => bail!(
                "credential {}: set secret_access_key or secret_access_key_env; a generated secret could never be read back",
                self.access_key_id
            ),
        }
    }
}

/// True for a file with no content: empty, or blank lines and comments only.
fn is_blank_document(yaml: &str) -> bool {
    yaml.lines()
        .map(str::trim)
        .all(|line| line.is_empty() || line.starts_with('#'))
}

/// Reads and validates a bootstrap file, encrypting the credential secrets.
pub fn load_plan(path: &Path, secrets: &SecretBox) -> anyhow::Result<BootstrapPlan> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read bootstrap file {}", path.display()))?;
    parse_plan(&text, secrets).with_context(|| format!("bootstrap file {}", path.display()))
}

/// Validates with the same rules as the API, so a bootstrap file cannot create
/// anything the API would reject.
pub fn parse_plan(yaml: &str, secrets: &SecretBox) -> anyhow::Result<BootstrapPlan> {
    parse_plan_with_env(yaml, secrets, &|name| std::env::var(name).ok())
}

/// Same as [`parse_plan`] with the environment lookup injected, which keeps the
/// tests free of process-wide state.
pub fn parse_plan_with_env(
    yaml: &str,
    secrets: &SecretBox,
    env: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<BootstrapPlan> {
    let file: BootstrapFile = if is_blank_document(yaml) {
        BootstrapFile::default()
    } else {
        serde_saphyr::from_str(yaml).context("parse YAML")?
    };
    if let Some(version) = file.version
        && version != BOOTSTRAP_VERSION
    {
        bail!("unsupported bootstrap file version {version}, expected {BOOTSTRAP_VERSION}");
    }
    let now = Timestamp::now();
    let mut plan = BootstrapPlan::default();

    for policy in file.policies {
        plan.policies
            .push(NewPolicy::validated(&policy.name, policy.statement, policy.acl, now)?);
    }

    for group in file.groups {
        let group_id = group.id;
        for policy in group.policies {
            validate_entity_id("policy", &policy)?;
            plan.group_policies.push((group_id.clone(), policy));
        }
        plan.groups.push(NewGroup::validated(group_id, group.description, now)?);
    }

    for user in file.users {
        let username = user.username;
        for group in user.groups {
            validate_entity_id("group", &group)?;
            plan.memberships.push((group, username.clone()));
        }
        for policy in user.policies {
            validate_entity_id("policy", &policy)?;
            plan.user_policies.push((username.clone(), policy));
        }
        for credential in &user.credentials {
            let Some(access_key_id) = non_blank(&credential.access_key_id) else {
                bail!("user {username}: access_key_id must not be empty");
            };
            let secret = credential.resolve_secret(env)?;
            let sealed = NewCredential::sealed(&username, access_key_id.to_owned(), &secret, secrets, now)
                .map_err(|error| anyhow::anyhow!("encrypt bootstrap secret: {error}"))?;
            plan.credentials.push(sealed);
        }
        let fields = UserFields {
            friendly_name: user.friendly_name,
            email: user.email,
            source: user.source,
            external_id: user.external_id,
            encrypted_password: None,
        };
        plan.users.push(NewUser::validated(username, fields, now)?);
    }

    Ok(plan)
}

/// Applies a plan and logs what was created and what was already there.
pub async fn apply(store: &dyn Store, plan: &BootstrapPlan) -> anyhow::Result<BootstrapReport> {
    if plan.is_empty() {
        tracing::info!("bootstrap file is empty, nothing to apply");
        return Ok(BootstrapReport::default());
    }
    let report = store.apply_bootstrap(plan).await.context("apply bootstrap")?;
    tracing::info!(summary = %report, "bootstrap applied");
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
version: 1
policies:
  - name: ReadOnly
    statement:
      - effect: allow
        action: ["fs:Read*", "fs:List*"]
        resource: "*"
groups:
  - id: Readers
    description: read only
    policies: [ReadOnly]
users:
  - username: alice
    email: alice@example.com
    friendly_name: Alice
    source: internal
    groups: [Readers]
    policies: [ReadOnly]
    credentials:
      - access_key_id: AKIAJTESTTESTTESTQ
        secret_access_key: literal-secret
"#;

    fn secrets() -> SecretBox {
        SecretBox::derive(b"test secret")
    }

    #[test]
    fn a_full_file_becomes_a_plan() {
        let plan = parse_plan(YAML, &secrets()).expect("parse");
        assert_eq!(plan.policies.len(), 1);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.users.len(), 1);
        assert_eq!(plan.memberships, vec![("Readers".to_owned(), "alice".to_owned())]);
        assert_eq!(plan.user_policies, vec![("alice".to_owned(), "ReadOnly".to_owned())]);
        assert_eq!(plan.group_policies, vec![("Readers".to_owned(), "ReadOnly".to_owned())]);
        assert_eq!(plan.credentials.len(), 1);

        let secret = secrets()
            .open_str(&plan.credentials[0].secret_ciphertext)
            .expect("decrypt");
        assert_eq!(secret, "literal-secret");
    }

    #[test]
    fn secrets_can_come_from_the_environment() {
        let yaml = r#"
users:
  - username: bob
    credentials:
      - access_key_id: AKIAJTESTTESTTESTQ
        secret_access_key_env: BOB_SECRET
"#;
        let env = |name: &str| (name == "BOB_SECRET").then(|| "from-env".to_owned());
        let plan = parse_plan_with_env(yaml, &secrets(), &env).expect("parse");
        let secret = secrets()
            .open_str(&plan.credentials[0].secret_ciphertext)
            .expect("decrypt");
        assert_eq!(secret, "from-env");

        let missing = parse_plan_with_env(yaml, &secrets(), &|_| None);
        assert!(missing.is_err(), "a missing variable must fail the bootstrap");
    }

    #[test]
    fn invalid_input_is_rejected() {
        let bad_statement = r#"
policies:
  - name: Broken
    statement:
      - effect: allow
        action: ["nosuchservice:Read"]
        resource: "*"
"#;
        assert!(parse_plan(bad_statement, &secrets()).is_err());

        let bad_name = r#"
users:
  - username: "a/b"
"#;
        assert!(parse_plan(bad_name, &secrets()).is_err());

        let unknown_field = r#"
users:
  - username: alice
    nickname: al
"#;
        assert!(parse_plan(unknown_field, &secrets()).is_err());

        let both_secrets = r#"
users:
  - username: alice
    credentials:
      - access_key_id: AKIAJTESTTESTTESTQ
        secret_access_key: a
        secret_access_key_env: B
"#;
        assert!(parse_plan(both_secrets, &secrets()).is_err());
    }

    #[test]
    fn only_version_1_is_accepted() {
        assert!(parse_plan("version: 1\nusers: []\n", &secrets()).is_ok());
        assert!(parse_plan("version: 2\n", &secrets()).is_err());
    }

    #[test]
    fn an_empty_file_is_an_empty_plan() {
        for text in ["", "\n", "# only a comment\n", "{}"] {
            let plan = parse_plan(text, &secrets()).unwrap_or_else(|error| panic!("{text:?}: {error:#}"));
            assert!(plan.is_empty(), "{text:?}");
        }
    }

    /// A generated secret would be stored encrypted and shown to nobody, so a
    /// credential without a secret source is a mistake the file must not hide.
    #[test]
    fn a_credential_needs_a_secret_source() {
        let yaml = r#"
users:
  - username: alice
    credentials:
      - access_key_id: AKIAJTESTTESTTESTQ
"#;
        let error = parse_plan(yaml, &secrets()).expect_err("no secret source");
        let text = format!("{error:#}");
        assert!(text.contains("AKIAJTESTTESTTESTQ"), "{text}");
        assert!(text.contains("secret_access_key"), "{text}");
    }

    /// A blank email is stored as absent, so two entries may both leave it blank.
    #[test]
    fn blank_optional_fields_are_absent() {
        let yaml = r#"
users:
  - username: alice
    email: ""
    external_id: "  "
  - username: bob
    email: " bob@example.com "
"#;
        let plan = parse_plan(yaml, &secrets()).expect("parse");
        assert_eq!(plan.users[0].email, None);
        assert_eq!(plan.users[0].external_id, None);
        assert_eq!(plan.users[1].email.as_deref(), Some("bob@example.com"));
    }
}

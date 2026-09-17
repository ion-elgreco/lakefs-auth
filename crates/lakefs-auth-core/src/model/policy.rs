use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Statement effect. lakeFS accepts exactly `allow` and `deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// `{"Operator": {"Field": ["value", ...]}}`, for example `{"IpAddress": {"SourceIp": ["10.0.0.0/8"]}}`.
pub type Condition = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// One policy statement. `resource` is an ARN, `*`, or a JSON array of ARNs encoded as a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub effect: Effect,
    pub resource: String,
    pub action: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

/// A policy. `acl` is for ACL servers only; an RBAC server stores and echoes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,
    pub statement: Vec<Statement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_round_trips_lowercase_effect() {
        let json = r#"{"effect":"allow","resource":"*","action":["fs:*"],"condition":{"IpAddress":{"SourceIp":["10.0.0.0/8"]}}}"#;
        let statement: Statement = serde_json::from_str(json).unwrap();
        assert_eq!(statement.effect, Effect::Allow);
        assert_eq!(serde_json::to_string(&statement).unwrap(), json);
    }

    #[test]
    fn capitalised_effect_is_rejected() {
        let json = r#"{"effect":"Allow","resource":"*","action":["fs:*"]}"#;
        assert!(serde_json::from_str::<Statement>(json).is_err());
    }
}

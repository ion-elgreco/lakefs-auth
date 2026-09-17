//! Validation rules that mirror what lakeFS itself accepts.
//!
//! The rules are deliberately no stricter than lakeFS: a rejected policy is a
//! 400 that aborts lakeFS setup. Actions are checked only for the
//! `service:Name` shape, resources for the ARN shape, and unknown condition
//! operators are accepted with a warning.

use crate::error::ApiError;
use crate::model::Statement;

/// Services that lakeFS accepts in actions (`pkg/permissions/actions.go`).
pub const SERVICES: &[&str] = &["fs", "auth", "ci", "retention", "branches", "pr", "catalog"];

/// Condition operators that open-source lakeFS evaluates.
pub const CONDITION_OPERATORS: &[&str] = &["IpAddress", "NotIpAddress", "StringLike", "StringNotLike"];

/// The wildcard resource.
pub const ALL_RESOURCES: &str = "*";

const MAX_ID_LEN: usize = 512;

/// Users, groups, and policies share the same identifier rules: non-empty, at
/// most 512 bytes, not `.` or `..`, no `/`, no `*` or `?`, no control characters.
///
/// `.` and `..` would collapse the request path of a client that joins the id
/// onto a URL. `*` and `?` would turn a policy resource such as
/// `arn:lakefs:auth:::user/${user}` into a wildcard when lakeFS expands it:
/// its matcher treats `*` as any sequence and `?` as any single character.
pub fn validate_entity_id(kind: &str, id: &str) -> Result<(), ApiError> {
    if id.is_empty() {
        return Err(ApiError::invalid(format!("{kind} id must not be empty")));
    }
    if id.len() > MAX_ID_LEN {
        return Err(ApiError::invalid(format!(
            "{kind} id is longer than {MAX_ID_LEN} bytes"
        )));
    }
    if id == "." || id == ".." {
        return Err(ApiError::invalid(format!("{kind} id must not be '.' or '..'")));
    }
    if id.contains('/') {
        return Err(ApiError::invalid(format!("{kind} id must not contain '/'")));
    }
    if id.contains(['*', '?']) {
        return Err(ApiError::invalid(format!("{kind} id must not contain '*' or '?'")));
    }
    if id.chars().any(char::is_control) {
        return Err(ApiError::invalid(format!(
            "{kind} id must not contain control characters"
        )));
    }
    Ok(())
}

/// An action is `service:Name` where the service is known. The name itself may hold wildcards.
pub fn validate_action(action: &str) -> Result<(), ApiError> {
    let mut parts = action.splitn(3, ':');
    let (Some(service), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ApiError::invalid(format!(
            "action must have the form service:Action: {action}"
        )));
    };
    if !SERVICES.contains(&service) {
        return Err(ApiError::invalid(format!("unknown service in action: {action}")));
    }
    if name.is_empty() {
        return Err(ApiError::invalid(format!("action name must not be empty: {action}")));
    }
    Ok(())
}

/// Checks an ARN the way lakeFS parses one: six colon-separated fields,
/// partition `lakefs`, non-empty service and resource. Region and account are
/// usually empty.
pub fn validate_arn(text: &str) -> Result<(), ApiError> {
    let parts: Vec<&str> = text.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" {
        return Err(ApiError::invalid(format!("invalid ARN: {text}")));
    }
    if parts[1] != "lakefs" {
        return Err(ApiError::invalid(format!("ARN partition must be lakefs: {text}")));
    }
    if parts[2].is_empty() {
        return Err(ApiError::invalid(format!("ARN service must not be empty: {text}")));
    }
    if parts[5].is_empty() {
        return Err(ApiError::invalid(format!("ARN resource must not be empty: {text}")));
    }
    Ok(())
}

/// A resource is `*`, an ARN, or a JSON array of ARNs encoded as a string.
pub fn validate_resource(resource: &str) -> Result<(), ApiError> {
    if resource == ALL_RESOURCES {
        return Ok(());
    }
    if resource.starts_with('[') && resource.ends_with(']') {
        let list: Vec<String> = serde_json::from_str(resource)
            .map_err(|err| ApiError::invalid(format!("resource list is not a JSON array of strings: {err}")))?;
        if list.is_empty() {
            return Err(ApiError::invalid("resource list must not be empty"));
        }
        for item in &list {
            if item != ALL_RESOURCES {
                validate_arn(item)?;
            }
        }
        return Ok(());
    }
    validate_arn(resource)
}

pub fn validate_statement(statement: &Statement) -> Result<(), ApiError> {
    if statement.action.is_empty() {
        return Err(ApiError::invalid("statement needs at least one action"));
    }
    for action in &statement.action {
        validate_action(action)?;
    }
    validate_resource(&statement.resource)?;
    if let Some(condition) = &statement.condition {
        for operator in condition.keys() {
            if !CONDITION_OPERATORS.contains(&operator.as_str()) {
                tracing::warn!(operator = %operator, "unknown condition operator accepted");
            }
        }
    }
    Ok(())
}

pub fn validate_statements(statements: &[Statement]) -> Result<(), ApiError> {
    if statements.is_empty() {
        return Err(ApiError::invalid("policy needs at least one statement"));
    }
    statements.iter().try_for_each(validate_statement)
}

/// Everything a policy must satisfy before it is stored or forwarded: the name
/// is an entity id and the statements are well formed. The authorization API
/// and the policy builder both call this, so neither accepts what the other
/// refuses.
pub fn validate_policy(name: &str, statements: &[Statement]) -> Result<(), ApiError> {
    validate_entity_id("policy", name)?;
    validate_statements(statements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Effect;

    #[test]
    fn actions_follow_lakefs_rules() {
        for ok in [
            "fs:*",
            "ci:*",
            "retention:*",
            "branches:*",
            "pr:*",
            "catalog:*",
            "auth:*",
            "fs:ReadConfig",
            "fs:Read*",
        ] {
            assert!(validate_action(ok).is_ok(), "{ok}");
        }
        for bad in ["foo:Bar", "fsReadObject", "a:b:c", "fs:", ":ReadObject"] {
            assert!(validate_action(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resources_follow_lakefs_rules() {
        assert!(validate_resource("*").is_ok());
        assert!(validate_resource("arn:lakefs:auth:::user/${user}").is_ok());
        assert!(validate_resource("arn:lakefs:fs:::repository/repo/object/a:b").is_ok());
        assert!(validate_resource(r#"["arn:lakefs:fs:::repository/a","arn:lakefs:fs:::repository/b"]"#).is_ok());
        assert!(validate_resource("arn:aws:s3:::bucket").is_err());
        assert!(validate_resource("arn:lakefs:fs:::").is_err());
        assert!(validate_resource("repository/foo").is_err());
        assert!(validate_resource("[]").is_err());
    }

    #[test]
    fn entity_ids_reject_slashes() {
        assert!(validate_entity_id("user", "alice@example.com").is_ok());
        assert!(validate_entity_id("user", "").is_err());
        assert!(validate_entity_id("user", "a/b").is_err());
        assert!(validate_entity_id("user", "a\nb").is_err());
    }

    /// `.` and `..` collapse a request path through `Url::join`, and `*` or
    /// `?` widen a policy resource such as `arn:lakefs:auth:::user/${user}`
    /// into a wildcard: lakeFS matches resources with both characters.
    #[test]
    fn entity_ids_reject_dot_segments_wildcards_and_oversize() {
        for bad in [".", "..", "*", "a*b", "*admin", "admin*", "?", "adm?n", "a?"] {
            assert!(validate_entity_id("user", bad).is_err(), "{bad:?} must be refused");
        }
        for ok in ["a.b", "...", "a..b", ".hidden", "a-b_c~d"] {
            assert!(validate_entity_id("user", ok).is_ok(), "{ok:?} must pass");
        }
        assert!(validate_entity_id("user", &"a".repeat(512)).is_ok());
        assert!(validate_entity_id("user", &"a".repeat(513)).is_err());
    }

    #[test]
    fn statements_need_actions_and_valid_resources() {
        let statement = Statement {
            effect: Effect::Allow,
            resource: "*".into(),
            action: vec![],
            condition: None,
        };
        assert!(validate_statement(&statement).is_err());
        assert!(validate_statements(&[]).is_err());
    }
}

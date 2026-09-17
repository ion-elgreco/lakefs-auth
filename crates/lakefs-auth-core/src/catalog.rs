//! The lakeFS action catalog: every action, and the resource each one is checked against.
//!
//! The action names come from `pkg/permissions/actions.gen.go` in lakeFS. The
//! resource kinds come from the `permissions.Node` literals in
//! `pkg/api/controller.go`, which decide what ARN lakeFS builds for a request.
//! [`validate`](crate::validate) only checks the shape of an action, so this
//! catalog is what lets a caller pick a correct action and a matching ARN.
//!
//! [`as_json`] renders the catalog for a user interface. The policy builder page
//! in `lakefs-authz` carries that output, and a test there compares the two.

use serde_json::{Value, json};

/// The resource an action is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceKind {
    /// Every resource. lakeFS accepts it for any action.
    All,
    /// One repository, or a pattern over repository names.
    Repository,
    /// Objects under a path. The ARN carries no branch.
    Object,
    /// One branch, or a pattern over branch names.
    Branch,
    /// One tag, or a pattern over tag names.
    Tag,
    /// A storage namespace, such as `s3://bucket/prefix`.
    Namespace,
    /// One user. `${user}` expands to the caller.
    User,
    /// One group.
    Group,
    /// One policy.
    Policy,
    /// One external principal.
    ExternalPrincipal,
    /// An Iceberg catalog namespace.
    CatalogNamespace,
    /// An Iceberg catalog table.
    CatalogTable,
    /// An Iceberg catalog view.
    CatalogView,
}

/// Every kind, in the order [`as_json`] writes them.
pub const RESOURCE_KINDS: &[ResourceKind] = &[
    ResourceKind::All,
    ResourceKind::Repository,
    ResourceKind::Object,
    ResourceKind::Branch,
    ResourceKind::Tag,
    ResourceKind::Namespace,
    ResourceKind::User,
    ResourceKind::Group,
    ResourceKind::Policy,
    ResourceKind::ExternalPrincipal,
    ResourceKind::CatalogNamespace,
    ResourceKind::CatalogTable,
    ResourceKind::CatalogView,
];

/// The `snake_case` id, the ARN template, and the placeholder names of a kind.
struct KindSpec {
    id: &'static str,
    template: &'static str,
    fields: &'static [&'static str],
}

impl ResourceKind {
    const fn spec(self) -> KindSpec {
        macro_rules! spec {
            ($id:literal, $template:literal, [$($field:literal),*]) => {
                KindSpec { id: $id, template: $template, fields: &[$($field),*] }
            };
        }
        match self {
            Self::All => spec!("all", "*", []),
            Self::Repository => spec!("repository", "arn:lakefs:fs:::repository/{repository}", ["repository"]),
            Self::Object => spec!(
                "object",
                "arn:lakefs:fs:::repository/{repository}/object/{path}",
                ["repository", "path"]
            ),
            Self::Branch => spec!(
                "branch",
                "arn:lakefs:fs:::repository/{repository}/branch/{branch}",
                ["repository", "branch"]
            ),
            Self::Tag => spec!(
                "tag",
                "arn:lakefs:fs:::repository/{repository}/tag/{tag}",
                ["repository", "tag"]
            ),
            Self::Namespace => spec!("namespace", "arn:lakefs:fs:::namespace/{namespace}", ["namespace"]),
            Self::User => spec!("user", "arn:lakefs:auth:::user/{user}", ["user"]),
            Self::Group => spec!("group", "arn:lakefs:auth:::group/{group}", ["group"]),
            Self::Policy => spec!("policy", "arn:lakefs:auth:::policy/{policy}", ["policy"]),
            Self::ExternalPrincipal => spec!(
                "external_principal",
                "arn:lakefs:auth:::externalPrincipal/{principal}",
                ["principal"]
            ),
            Self::CatalogNamespace => spec!(
                "catalog_namespace",
                "arn:lakefs:catalog:::namespace/{repository}/{namespace}",
                ["repository", "namespace"]
            ),
            Self::CatalogTable => spec!(
                "catalog_table",
                "arn:lakefs:catalog:::table/{repository}/{namespace}/{table}",
                ["repository", "namespace", "table"]
            ),
            Self::CatalogView => spec!(
                "catalog_view",
                "arn:lakefs:catalog:::view/{repository}/{namespace}/{view}",
                ["repository", "namespace", "view"]
            ),
        }
    }

    /// The ARN template, with `{field}` placeholders the caller fills in.
    pub const fn template(self) -> &'static str {
        self.spec().template
    }

    /// The placeholder names in [`Self::template`], in the order they appear.
    pub const fn fields(self) -> &'static [&'static str] {
        self.spec().fields
    }

    /// The `snake_case` name used in [`as_json`] and in the builder page.
    pub const fn id(self) -> &'static str {
        self.spec().id
    }
}

/// One action and the resource kinds lakeFS checks it against.
///
/// `resources` holds more than one kind when different endpoints check the same
/// action against different ARNs. The entries run from the most specific kind to
/// the least, so the first one is the scope a policy normally wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSpec {
    pub name: &'static str,
    pub resources: &'static [ResourceKind],
}

impl ActionSpec {
    /// The service prefix of the name, such as `fs` in `fs:ReadObject`.
    pub fn service(&self) -> &'static str {
        self.name.split_once(':').map_or(self.name, |(service, _)| service)
    }
}

/// Every action lakeFS defines, in the order of `actions.gen.go`.
pub const ACTIONS: &[ActionSpec] = &[
    ActionSpec {
        name: "fs:ReadRepository",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:CreateRepository",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:UpdateRepository",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:AttachStorageNamespace",
        resources: &[ResourceKind::Namespace],
    },
    ActionSpec {
        name: "fs:ImportFromStorage",
        resources: &[ResourceKind::Namespace],
    },
    ActionSpec {
        name: "fs:ImportCancel",
        resources: &[ResourceKind::Branch],
    },
    ActionSpec {
        name: "fs:DeleteRepository",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:ListRepositories",
        resources: &[ResourceKind::All],
    },
    ActionSpec {
        name: "fs:ReadObject",
        resources: &[ResourceKind::Object],
    },
    ActionSpec {
        name: "fs:WriteObject",
        resources: &[ResourceKind::Object, ResourceKind::Branch],
    },
    ActionSpec {
        name: "fs:DeleteObject",
        resources: &[ResourceKind::Object],
    },
    ActionSpec {
        name: "fs:ListObjects",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:CreateCommit",
        resources: &[ResourceKind::Branch, ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:ReadCommit",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:ListCommits",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:CreateBranch",
        resources: &[ResourceKind::Branch, ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:DeleteBranch",
        resources: &[ResourceKind::Branch],
    },
    ActionSpec {
        name: "fs:ReadBranch",
        resources: &[ResourceKind::Branch],
    },
    ActionSpec {
        name: "fs:RevertBranch",
        resources: &[ResourceKind::Branch],
    },
    ActionSpec {
        name: "fs:ListBranches",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:CreateTag",
        resources: &[ResourceKind::Tag, ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:DeleteTag",
        resources: &[ResourceKind::Tag],
    },
    ActionSpec {
        name: "fs:ReadTag",
        resources: &[ResourceKind::Tag],
    },
    ActionSpec {
        name: "fs:ListTags",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "fs:ReadConfig",
        resources: &[ResourceKind::All],
    },
    ActionSpec {
        name: "auth:ReadUser",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:CreateUser",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:DeleteUser",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:ListUsers",
        resources: &[ResourceKind::All],
    },
    ActionSpec {
        name: "auth:ReadGroup",
        resources: &[ResourceKind::Group],
    },
    ActionSpec {
        name: "auth:CreateGroup",
        resources: &[ResourceKind::Group],
    },
    ActionSpec {
        name: "auth:DeleteGroup",
        resources: &[ResourceKind::Group],
    },
    ActionSpec {
        name: "auth:ListGroups",
        resources: &[ResourceKind::All],
    },
    ActionSpec {
        name: "auth:AddGroupMember",
        resources: &[ResourceKind::Group],
    },
    ActionSpec {
        name: "auth:RemoveGroupMember",
        resources: &[ResourceKind::Group],
    },
    ActionSpec {
        name: "auth:ReadPolicy",
        resources: &[ResourceKind::Policy],
    },
    ActionSpec {
        name: "auth:CreatePolicy",
        resources: &[ResourceKind::Policy],
    },
    ActionSpec {
        name: "auth:UpdatePolicy",
        resources: &[ResourceKind::Policy],
    },
    ActionSpec {
        name: "auth:DeletePolicy",
        resources: &[ResourceKind::Policy],
    },
    ActionSpec {
        name: "auth:ListPolicies",
        resources: &[ResourceKind::All],
    },
    ActionSpec {
        name: "auth:AttachPolicy",
        resources: &[ResourceKind::User, ResourceKind::Group, ResourceKind::Policy],
    },
    ActionSpec {
        name: "auth:DetachPolicy",
        resources: &[ResourceKind::User, ResourceKind::Group, ResourceKind::Policy],
    },
    ActionSpec {
        name: "auth:ReadCredentials",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:CreateCredentials",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:DeleteCredentials",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:ListCredentials",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:CreateUserExternalPrincipal",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:DeleteUserExternalPrincipal",
        resources: &[ResourceKind::User],
    },
    ActionSpec {
        name: "auth:ReadExternalPrincipal",
        resources: &[ResourceKind::ExternalPrincipal],
    },
    ActionSpec {
        name: "ci:ReadAction",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "retention:PrepareGarbageCollectionCommits",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "retention:GetGarbageCollectionRules",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "retention:SetGarbageCollectionRules",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "retention:PrepareGarbageCollectionUncommitted",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "branches:GetBranchProtectionRules",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "branches:SetBranchProtectionRules",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "pr:ReadPullRequest",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "pr:WritePullRequest",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "pr:ListPullRequests",
        resources: &[ResourceKind::Repository],
    },
    ActionSpec {
        name: "catalog:ListNamespaces",
        resources: &[ResourceKind::CatalogNamespace],
    },
    ActionSpec {
        name: "catalog:GetNamespace",
        resources: &[ResourceKind::CatalogNamespace],
    },
    ActionSpec {
        name: "catalog:CreateNamespace",
        resources: &[ResourceKind::CatalogNamespace],
    },
    ActionSpec {
        name: "catalog:UpdateNamespace",
        resources: &[ResourceKind::CatalogNamespace],
    },
    ActionSpec {
        name: "catalog:DeleteNamespace",
        resources: &[ResourceKind::CatalogNamespace],
    },
    ActionSpec {
        name: "catalog:ListTables",
        resources: &[ResourceKind::CatalogTable],
    },
    ActionSpec {
        name: "catalog:ReadTable",
        resources: &[ResourceKind::CatalogTable],
    },
    ActionSpec {
        name: "catalog:CreateTable",
        resources: &[ResourceKind::CatalogTable],
    },
    ActionSpec {
        name: "catalog:UpdateTable",
        resources: &[ResourceKind::CatalogTable],
    },
    ActionSpec {
        name: "catalog:DeleteTable",
        resources: &[ResourceKind::CatalogTable],
    },
    ActionSpec {
        name: "catalog:ListViews",
        resources: &[ResourceKind::CatalogView],
    },
    ActionSpec {
        name: "catalog:ReadView",
        resources: &[ResourceKind::CatalogView],
    },
    ActionSpec {
        name: "catalog:CreateView",
        resources: &[ResourceKind::CatalogView],
    },
    ActionSpec {
        name: "catalog:UpdateView",
        resources: &[ResourceKind::CatalogView],
    },
    ActionSpec {
        name: "catalog:DeleteView",
        resources: &[ResourceKind::CatalogView],
    },
];

/// The whole catalog as the shape a user interface consumes.
///
/// `kinds` maps a kind id to its template and fields. `actions` lists every
/// action with the ids of the kinds it matches.
pub fn as_json() -> Value {
    let kinds: serde_json::Map<String, Value> = RESOURCE_KINDS
        .iter()
        .map(|kind| {
            (
                kind.id().to_owned(),
                json!({ "template": kind.template(), "fields": kind.fields() }),
            )
        })
        .collect();
    let actions: Vec<Value> = ACTIONS
        .iter()
        .map(|action| {
            let resources: Vec<&str> = action.resources.iter().map(|kind| kind.id()).collect();
            json!({ "name": action.name, "service": action.service(), "resources": resources })
        })
        .collect();
    json!({ "kinds": kinds, "actions": actions })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::validate::{SERVICES, validate_action};

    /// `pkg/permissions/actions.gen.go` of lakeFS v1.86.0, vendored so that a
    /// transcription error or an upstream change fails the build here.
    const UPSTREAM_ACTIONS: &str = include_str!("../tests/fixtures/actions.gen.go");

    fn find(name: &str) -> Option<&'static ActionSpec> {
        ACTIONS.iter().find(|action| action.name == name)
    }

    #[test]
    fn the_catalog_matches_the_vendored_lakefs_action_list() {
        let upstream: BTreeSet<&str> = UPSTREAM_ACTIONS
            .lines()
            .filter_map(|line| line.trim().strip_prefix('"')?.strip_suffix("\","))
            .collect();
        assert!(upstream.len() > 50, "the fixture parsed into too few actions");
        let ours: BTreeSet<&str> = ACTIONS.iter().map(|action| action.name).collect();
        assert_eq!(ours, upstream, "ACTIONS drifted from actions.gen.go");
    }

    #[test]
    fn every_action_passes_validation_and_uses_a_known_service() {
        for action in ACTIONS {
            validate_action(action.name).unwrap_or_else(|error| panic!("{}: {error:?}", action.name));
            assert!(
                SERVICES.contains(&action.service()),
                "unknown service in {}",
                action.name
            );
            assert!(!action.resources.is_empty(), "{} has no resource kind", action.name);
        }
    }

    #[test]
    fn names_are_unique_and_every_service_is_covered() {
        let mut names: Vec<&str> = ACTIONS.iter().map(|action| action.name).collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total, "the catalog holds a duplicate action");

        for service in SERVICES {
            assert!(
                ACTIONS.iter().any(|action| action.service() == *service),
                "no action for service {service}"
            );
        }
    }

    #[test]
    fn templates_declare_every_placeholder_they_use() {
        for kind in RESOURCE_KINDS {
            let template = kind.template();
            assert_eq!(
                template.matches('{').count(),
                kind.fields().len(),
                "{kind:?} declares the wrong number of fields for {template}"
            );
            for field in kind.fields() {
                assert!(template.contains(&format!("{{{field}}}")), "{template} misses {field}");
            }
        }
    }

    /// Every kind must appear in `RESOURCE_KINDS`, or `as_json` would omit one
    /// that an action refers to.
    #[test]
    fn every_kind_an_action_uses_is_listed_and_has_a_unique_id() {
        let mut ids: Vec<&str> = RESOURCE_KINDS.iter().map(|kind| kind.id()).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "two kinds share an id");

        for action in ACTIONS {
            for kind in action.resources {
                assert!(RESOURCE_KINDS.contains(kind), "{kind:?} is missing from RESOURCE_KINDS");
            }
        }
    }

    #[test]
    fn lookup_finds_a_known_action_and_rejects_an_unknown_one() {
        let spec = find("fs:ReadObject").expect("fs:ReadObject is in the catalog");
        assert_eq!(spec.resources, &[ResourceKind::Object]);
        assert_eq!(ResourceKind::Object.fields(), &["repository", "path"]);
        assert!(find("fs:NoSuchAction").is_none());
    }

    /// `fs:WriteObject` is checked against an object ARN on every upload path and
    /// against a branch ARN only by the import endpoint, so the object kind must
    /// come first.
    #[test]
    fn a_multi_resource_action_offers_the_specific_kind_first() {
        let write = find("fs:WriteObject").expect("fs:WriteObject is in the catalog");
        assert_eq!(write.resources, &[ResourceKind::Object, ResourceKind::Branch]);
        let tag = find("fs:CreateTag").expect("fs:CreateTag is in the catalog");
        assert_eq!(tag.resources, &[ResourceKind::Tag, ResourceKind::Repository]);
    }

    /// lakeFS checks attach and detach with the same AND node: the user or group
    /// ARN and the policy ARN. The catalog must offer the policy kind for both.
    #[test]
    fn attach_and_detach_policy_are_checked_against_the_same_resources() {
        let attach = find("auth:AttachPolicy").expect("auth:AttachPolicy is in the catalog");
        let detach = find("auth:DetachPolicy").expect("auth:DetachPolicy is in the catalog");
        assert_eq!(detach.resources, attach.resources);
        assert!(detach.resources.contains(&ResourceKind::Policy));
    }

    #[test]
    fn as_json_describes_every_action_and_kind() {
        let value = as_json();
        assert_eq!(
            value["actions"].as_array().expect("actions is an array").len(),
            ACTIONS.len()
        );
        assert_eq!(
            value["kinds"].as_object().expect("kinds is an object").len(),
            RESOURCE_KINDS.len()
        );
        assert_eq!(value["kinds"]["object"]["template"], ResourceKind::Object.template());
        assert_eq!(value["actions"][0]["name"], ACTIONS[0].name);
    }
}

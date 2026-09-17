//! Compares `ROUTE_TABLE` with the vendored `api/authorization.yml` of lakeFS
//! v1.86.0. The specification is committed under `tests/fixtures`, so the test
//! downloads nothing.

use std::collections::{BTreeMap, BTreeSet};

use lakefs_authz::routes::ROUTE_TABLE;
use pretty_assertions::assert_eq;
use serde::Deserialize;
use serde::de::IgnoredAny;

/// Only the shape we need: path, then the keys under it. Everything else is skipped.
#[derive(Debug, Deserialize)]
struct Spec {
    paths: BTreeMap<String, BTreeMap<String, IgnoredAny>>,
}

const METHODS: &[&str] = &["get", "put", "post", "delete", "patch", "head", "options", "trace"];

const SPEC: &str = include_str!("fixtures/authorization.yml");

fn spec_operations() -> BTreeSet<(String, String)> {
    let spec: Spec = serde_saphyr::from_str(SPEC).expect("parse authorization.yml");
    spec.paths
        .iter()
        .flat_map(|(path, item)| {
            item.keys()
                .filter(|key| METHODS.contains(&key.as_str()))
                .map(move |method| (method.to_uppercase(), path.clone()))
        })
        .collect()
}

fn route_table() -> BTreeSet<(String, String)> {
    ROUTE_TABLE
        .iter()
        .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
        .collect()
}

#[test]
fn the_route_table_matches_the_specification() {
    let spec = spec_operations();
    let routes = route_table();

    let missing: Vec<_> = spec.difference(&routes).collect();
    assert!(missing.is_empty(), "operations in the spec but not served: {missing:?}");

    let extra: Vec<_> = routes.difference(&spec).collect();
    assert!(extra.is_empty(), "routes served but not in the spec: {extra:?}");

    assert_eq!(routes, spec);
    assert_eq!(routes.len(), 37, "the spec has 37 operations");
}

#[test]
fn the_specification_fixture_is_the_pinned_version() {
    assert!(
        SPEC.contains("title: lakeFS authorization API"),
        "the fixture must be api/authorization.yml"
    );
    assert!(
        SPEC.contains(r#"- url: "/api/v1""#),
        "the server URL carries the base path lakeFS appends"
    );
    // The health check is the one operation without a security requirement.
    assert!(SPEC.contains("security: [ ]"), "healthcheck must stay unauthenticated");
}

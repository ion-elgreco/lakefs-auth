//! Writes the action catalog into the policy builder page.
//!
//! The page carries the catalog so that it also works when it is opened from
//! the documentation, with no server behind it. This example is what keeps that
//! copy honest: run `just sync-catalog` after the catalog changes. A test in
//! `lakefs_authz::builder` fails while the copy is stale.

use std::path::Path;

const PAGE: &str = "crates/lakefs-authz/assets/policy-builder.html";
const OPEN: &str = "// <catalog>";
const CLOSE: &str = "// </catalog>";

fn main() -> anyhow::Result<()> {
    let path = Path::new(PAGE);
    let page = std::fs::read_to_string(path)?;

    let start = page
        .find(OPEN)
        .ok_or_else(|| anyhow::anyhow!("{PAGE} has no {OPEN} marker"))?;
    let end = page
        .find(CLOSE)
        .ok_or_else(|| anyhow::anyhow!("{PAGE} has no {CLOSE} marker"))?;

    let block = format!(
        "{OPEN} Generated from lakefs-auth-core::catalog. Run `just sync-catalog` after changing it.\n\
         const CATALOG = {};\n",
        serde_json::to_string(&lakefs_auth_core::catalog::as_json())?
    );

    let updated = format!("{}{block}{}", &page[..start], &page[end..]);
    if updated == page {
        println!("{PAGE} is already up to date");
        return Ok(());
    }
    std::fs::write(path, updated)?;
    println!(
        "{PAGE} now carries {} actions",
        lakefs_auth_core::catalog::ACTIONS.len()
    );
    Ok(())
}

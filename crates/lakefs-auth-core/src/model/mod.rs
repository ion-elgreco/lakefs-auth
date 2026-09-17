//! Wire models of the lakeFS authorization API (`api/authorization.yml`).
//!
//! Field names follow the spec exactly, including its inconsistencies:
//! `UserCreation.friendlyName` is camelCase while `User.friendly_name` is snake_case.

mod credentials;
mod group;
mod list;
mod meta;
mod policy;
mod principal;
mod token;
mod user;

pub use credentials::{Credentials, CredentialsWithSecret};
pub use group::{Group, GroupCreation};
pub use list::{DEFAULT_PAGE, ListResponse, MAX_PAGE, Pagination};
pub use meta::{ErrorBody, VersionConfig};
pub use policy::{Condition, Effect, Policy, Statement};
pub use principal::ExternalPrincipal;
pub use token::ClaimTokenId;
pub use user::{Base64Bytes, FriendlyNameUpdate, User, UserCreation};

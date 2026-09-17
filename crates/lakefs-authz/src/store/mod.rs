//! Storage for users, groups, policies, credentials, and token ids.
//!
//! [`Store`] is the umbrella trait the handlers use as `Arc<dyn Store>`. The
//! PostgreSQL store is the production implementation; the in-memory store keeps
//! the API tests free of a database. One conformance suite runs against both.

pub mod bootstrap;
pub mod error;
pub mod pg;
pub mod traits;
pub mod types;

#[cfg(feature = "testkit")]
pub mod mem;
#[cfg(feature = "testkit")]
pub mod testsuite;

pub use error::{StoreError, StoreResult};
pub use pg::{MIGRATOR, PgStore};
pub use traits::{
    AdminStore, AttachmentStore, CredentialStore, ExternalPrincipalStore, GroupStore, MembershipStore, PolicyStore,
    Store, TokenIdStore, UserStore,
};
pub use types::{
    BootstrapCounts, BootstrapPlan, BootstrapReport, CredentialRecord, ExternalPrincipalRecord, GroupRecord,
    NewCredential, NewGroup, NewPolicy, NewUser, PolicyRecord, UserRecord,
};

#[cfg(feature = "testkit")]
pub use mem::MemStore;

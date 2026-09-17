//! HTTP handlers. Each one keeps the exact status code lakeFS expects: 201 for
//! creates, attachments, memberships, and token claims, 204 for deletes,
//! detaches, friendly name updates, and the health check, 200 for everything
//! else.

pub mod attachments;
pub mod credentials;
pub mod external;
pub mod groups;
pub mod memberships;
pub mod meta;
pub mod policies;
pub mod tokenid;
pub mod users;

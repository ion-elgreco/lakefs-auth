//! Small helpers shared by the configuration and the routes.

pub mod cookie_key;
pub mod redirect;

pub use cookie_key::derive_cookie_key;
pub use redirect::{RedirectError, resolve_next, safe_next};

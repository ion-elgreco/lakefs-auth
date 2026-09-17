//! Shared helpers for the integration tests.
//!
//! Each test binary pulls in the whole module, so unused items are expected.
#![allow(dead_code)]

pub mod app;
pub mod authz;
pub mod idp;
pub mod testkey;

#[cfg(feature = "docker-tests")]
pub mod ferriskey;

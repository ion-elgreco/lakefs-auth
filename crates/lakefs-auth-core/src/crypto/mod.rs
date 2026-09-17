//! Secret encryption at rest and lakeFS-style access key generation.

mod keygen;
mod secretbox;

pub use keygen::{AKIA_ALPHABET, is_well_formed_access_key_id, new_access_key_id, new_secret_access_key};
pub use secretbox::{CryptoError, SecretBox};

//! The private-cookie key derivation.

use axum_extra::extract::cookie::Key;
use sha2::{Digest, Sha512};

/// Domain separator for the key that encrypts our own flow cookies.
const COOKIE_KEY_CONTEXT: &[u8] = b"lakefs-authn/private-cookie/v1";

/// Derives the 64-byte key `cookie::Key` needs from an arbitrary shared secret.
///
/// `Key::from` panics on anything shorter than 64 bytes, and operators pick short
/// secrets, so the secret goes through SHA-512 with a domain separator first.
pub fn derive_cookie_key(secret: &[u8]) -> Key {
    let mut hasher = Sha512::new();
    hasher.update(COOKIE_KEY_CONTEXT);
    hasher.update(secret);
    let bytes = hasher.finalize();
    Key::from(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_key_is_stable_and_secret_specific() {
        let a = derive_cookie_key(b"short");
        let b = derive_cookie_key(b"short");
        let c = derive_cookie_key(b"other");
        assert_eq!(a.master(), b.master());
        assert_ne!(a.master(), c.master());
        assert_eq!(a.master().len(), 64);
    }
}

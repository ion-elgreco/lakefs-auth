use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand::{Rng, RngExt};

/// Alphabet lakeFS uses for the random part of an access key id (`pkg/auth/keys`).
pub const AKIA_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const ACCESS_KEY_PREFIX: &str = "AKIAJ";
const ACCESS_KEY_SUFFIX: &str = "Q";
const ACCESS_KEY_RANDOM_LEN: usize = 14;
const SECRET_KEY_BYTES: usize = 30;

/// `AKIAJ` + 14 alphabet characters + `Q`, 20 characters in total.
pub fn new_access_key_id() -> String {
    let mut rng = rand::rng();
    let mut key = String::with_capacity(ACCESS_KEY_PREFIX.len() + ACCESS_KEY_RANDOM_LEN + ACCESS_KEY_SUFFIX.len());
    key.push_str(ACCESS_KEY_PREFIX);
    for _ in 0..ACCESS_KEY_RANDOM_LEN {
        let index = rng.random_range(0..AKIA_ALPHABET.len());
        key.push(char::from(AKIA_ALPHABET[index]));
    }
    key.push_str(ACCESS_KEY_SUFFIX);
    key
}

/// Standard base64 of 30 random bytes, 40 characters in total.
pub fn new_secret_access_key() -> String {
    let mut bytes = [0u8; SECRET_KEY_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

/// True when the id has the lakeFS shape. Used for validation of caller-supplied keys.
pub fn is_well_formed_access_key_id(id: &str) -> bool {
    id.len() == ACCESS_KEY_PREFIX.len() + ACCESS_KEY_RANDOM_LEN + ACCESS_KEY_SUFFIX.len()
        && id.starts_with(ACCESS_KEY_PREFIX)
        && id.ends_with(ACCESS_KEY_SUFFIX)
        && id[ACCESS_KEY_PREFIX.len()..id.len() - ACCESS_KEY_SUFFIX.len()]
            .bytes()
            .all(|b| AKIA_ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_keys_have_lakefs_shape() {
        for _ in 0..100 {
            let key = new_access_key_id();
            assert_eq!(key.len(), 20);
            assert!(is_well_formed_access_key_id(&key), "{key}");
        }
        assert!(!is_well_formed_access_key_id("AKIAJ0000000000000Q"));
        assert!(!is_well_formed_access_key_id("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn secret_keys_are_40_chars_of_base64() {
        let secret = new_secret_access_key();
        assert_eq!(secret.len(), 40);
        assert_eq!(STANDARD.decode(&secret).unwrap().len(), 30);
        assert_ne!(secret, new_secret_access_key());
    }
}

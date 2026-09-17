use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"lakefs-auth/hkdf/v1";
const HKDF_INFO: &[u8] = b"lakefs-authz/credentials-secret/v1";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext is too short")]
    TooShort,
    #[error("unsupported ciphertext version {0}")]
    UnsupportedVersion(u8),
    #[error("decryption failed")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("decrypted value is not valid UTF-8")]
    NotUtf8,
}

/// AES-256-GCM with a key derived from the shared secret.
///
/// Blob layout: `0x01 || nonce (12 bytes) || ciphertext || tag`. The version
/// byte leaves room for key rotation later. The cipher holds the expanded
/// key, so a seal or an open runs no key schedule; `open` sits on the path
/// lakeFS takes for every S3 request.
pub struct SecretBox {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBox(..)")
    }
}

impl SecretBox {
    /// Derives the encryption key with HKDF-SHA256 from an arbitrary shared secret.
    pub fn derive(shared_secret: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(HKDF_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self {
            cipher: Aes256Gcm::new(key.as_ref().into()),
        }
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| CryptoError::Encrypt)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        if blob[0] != VERSION {
            return Err(CryptoError::UnsupportedVersion(blob[0]));
        }
        let (nonce, ciphertext) = blob[1..].split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at yields exactly NONCE_LEN bytes");
        self.cipher
            .decrypt(&Nonce::from(nonce), ciphertext)
            .map_err(|_| CryptoError::Decrypt)
    }

    pub fn seal_str(&self, plaintext: &str) -> Result<Vec<u8>, CryptoError> {
        self.seal(plaintext.as_bytes())
    }

    pub fn open_str(&self, blob: &[u8]) -> Result<String, CryptoError> {
        String::from_utf8(self.open(blob)?).map_err(|_| CryptoError::NotUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_unique_nonces() {
        let sb = SecretBox::derive(b"shared secret");
        let a = sb.seal(b"secret-value").unwrap();
        let b = sb.seal(b"secret-value").unwrap();
        assert_ne!(a, b, "nonces must differ");
        assert_eq!(sb.open(&a).unwrap(), b"secret-value");
        assert_eq!(sb.open_str(&b).unwrap(), "secret-value");
    }

    #[test]
    fn derivation_is_deterministic_and_secret_specific() {
        let plaintext = b"value";
        let blob = SecretBox::derive(b"k1").seal(plaintext).unwrap();
        assert_eq!(SecretBox::derive(b"k1").open(&blob).unwrap(), plaintext);
        assert!(matches!(
            SecretBox::derive(b"k2").open(&blob),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn rejects_tampering_and_bad_versions() {
        let sb = SecretBox::derive(b"k");
        let mut blob = sb.seal(b"value").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(sb.open(&blob), Err(CryptoError::Decrypt)));
        blob[0] = 9;
        assert!(matches!(sb.open(&blob), Err(CryptoError::UnsupportedVersion(9))));
        assert!(matches!(sb.open(&[1, 2, 3]), Err(CryptoError::TooShort)));
    }
}

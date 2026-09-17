//! A committed RSA-2048 key so that the mock identity provider is deterministic.
//!
//! Generated once with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`.
//! It signs nothing outside the test suite.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// Key id the mock provider advertises in its JWKS and in every token header.
pub const KEY_ID: &str = "authn-test-key-1";

const PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDT5SAfzSDt4QbB\n\
mzdTiEzWNFkNdFaWnaXhLXLaSD4Q6rXeHK//EFz4EWmExibrQW18OlOrzazRSTr3\n\
BIryhrLG72ysnVhdPThXaxmQlf/GI9euHrugwWPRpMyOufOepFBWFh/wTmHDsTuK\n\
7SGyj0Gla9wMxPT0BO/QvfQ1I3n2B9F4IEZLZ2QsnJCiMm1qiJlJOyGR8SIdp2cd\n\
WA9mQsbTKpadGlNQ4pFtgWoVzHGm0275JNpKAhkau3FDVqAGCKiawZPMuTabrgIu\n\
4nuFj1Z9e0qbFtcHiYzC1JwQ+qcZD8xoZjvC32lVn+fxDygU3rAwlYVpEDjk0/iX\n\
ev4dYHyFAgMBAAECggEAI5GNj+kGAwhH8w3T/rCdfUNyQ2Do/AVgh+jyI5QG3x4X\n\
Az67iEw93uJFXSVJ+SmVcEn2K5uty7/IJxjbHhTgQ6aDDoKnB5e0MnBm7S9QrPjt\n\
RmwgQL7Vu6Y3NCogq9uXJKw4FkWCAbBpd0uQ4YFMmrD9UiNpnuCJRPft21GmMlcV\n\
P8jquEBUwE/eniWRiswqksdF9bbxtDV/41zE+T2FMlLU+Dx7hNXxo5If7F3tvVAE\n\
H6519yx3RUT9mBLLbEeprwxYSwiPdvZKEHiqTi5lVQSMPBocKZmsSNKqLbTjY6k8\n\
HKVt0c9l5C5zopclUMk2FRJh78fdy3BtPmTxifD1wQKBgQD5raI3AkU1HCt5u/46\n\
Hw5EVqYSbwEx8rfiVH8BpWMw7Vi2VHwvNBIJfYT4wn7qTJKfAuwEiafJlRTMwxBG\n\
GcooeblcKa69SGfR1Hn4UqS0uLZnl0SNBCwluRjkd7ICFq4a4fbEOnhbHAaKoseP\n\
7LTZvjMmrN1JZnbPH0Ee3FoKlQKBgQDZQpaTP9jtiuCUoUWjJe0GJ5KxDb1uYkqq\n\
28ZcDw0XumVtoLWyVcsk+pRpWvxP0sEL6ffTOS/gwpcxrrDNgZfKamFh4zOO6IOr\n\
UhVrGBer/4HEuYibsyGxWlIRjecjcvNHmZ7/eWNQ4b6aCoVPah+UEouJG21I6luQ\n\
Tn9cFIseMQKBgQC2gU5eyWEPVl0NKfbGQ2cpWvEf7lZATXxOi5ce++bKn+PFu3Hf\n\
Cz/YAhFNyNX+rCRM6VTeaETmm/vNRRTDORzFg1yT2sApCiEhhx/0/Wv50j86756j\n\
OZaPqIJiln/e+PchHWVEwLyzVIQPmLcpJEx6EYbQUXGbsrNL6TuvtEB5FQKBgH6o\n\
ul4IB/CcWUdtKcrublt7MKL17qzusrcfP2omAC0IJt+dpK/eInthdqphN91VceP/\n\
N9K1cTsoVrrJLBvy5EpGcJV/vmwfE7wKM6BmwE4uvDmzLHgRG6BolpXTU6AwALKK\n\
Vc58tzDNGrB1V7ivls9dbGm3SqQKtOzRRqCo/V3RAoGBAIQN1oj0IZQSzCgYZJUD\n\
cq347s0Lc9RBzx/CMzVsLMdnAofpO0ebGsK63kAWGuEAF/DmAVOPsixT2myWtyKe\n\
88Bb11vwZLW6QhF3P90EgW9f9Gk9W3tbrA3HbENTUT9mJ0qoC5T2HDCGM0UJNZvh\n\
tyzg5SV4JKFs+nmw/CxKX/LW\n\
-----END PRIVATE KEY-----";

/// Base64url modulus of the public key.
pub const MODULUS: &str = "0-UgH80g7eEGwZs3U4hM1jRZDXRWlp2l4S1y2kg-EOq13hyv_xBc-BFphMYm60FtfDpTq82s0Uk69wSK8oayxu9srJ1YXT04V2sZkJX_xiPXrh67oMFj0aTMjrnznqRQVhYf8E5hw7E7iu0hso9BpWvcDMT09ATv0L30NSN59gfReCBGS2dkLJyQojJtaoiZSTshkfEiHadnHVgPZkLG0yqWnRpTUOKRbYFqFcxxptNu-STaSgIZGrtxQ1agBgiomsGTzLk2m64CLuJ7hY9WfXtKmxbXB4mMwtScEPqnGQ_MaGY7wt9pVZ_n8Q8oFN6wMJWFaRA45NP4l3r-HWB8hQ";
/// Base64url public exponent.
pub const EXPONENT: &str = "AQAB";

pub fn encoding_key() -> EncodingKey {
    EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM.as_bytes()).expect("the committed test key parses")
}

/// The JWKS document the mock provider serves.
pub fn jwks(key_id: &str) -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": key_id,
            "n": MODULUS,
            "e": EXPONENT,
        }]
    })
}

/// Signs claims as an RS256 ID token with the given key id in the header.
pub fn sign_rs256<C: Serialize>(claims: &C, key_id: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key_id.to_owned());
    jsonwebtoken::encode(&header, claims, &encoding_key()).expect("signing works")
}

/// An unsigned token, which a verifier must refuse.
pub fn unsigned<C: Serialize>(claims: &C) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
    format!("{header}.{payload}.")
}

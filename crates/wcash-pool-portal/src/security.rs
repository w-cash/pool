//! Credential, token, CSRF, and TOTP primitives.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

const RANDOM_TOKEN_BYTES: usize = 32;
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_NONCE_BYTES: usize = 24;
const TOTP_PERIOD_SECS: u64 = 30;
const TOTP_DIGITS_MODULUS: u32 = 1_000_000;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Credential operation failure without secret-bearing details.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// Host entropy source failed.
    #[error("secure random source is unavailable")]
    Random,
    /// Password does not meet the bounded policy.
    #[error("password must contain 12 to 256 characters")]
    PasswordPolicy,
    /// Password hash operation failed.
    #[error("password credential operation failed")]
    PasswordHash,
    /// Authenticator secret could not be protected or opened.
    #[error("authenticator secret operation failed")]
    AuthenticatorSecret,
}

pub(crate) fn validate_password(password: &str) -> Result<(), SecurityError> {
    if !(12..=256).contains(&password.chars().count()) {
        return Err(SecurityError::PasswordPolicy);
    }
    Ok(())
}

pub(crate) fn hash_password(password: &str) -> Result<String, SecurityError> {
    validate_password(password)?;
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|_| SecurityError::PasswordHash)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| SecurityError::PasswordHash)?;
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|value| value.to_string())
        .map_err(|_| SecurityError::PasswordHash)
}

pub(crate) fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub(crate) fn random_token(prefix: &str) -> Result<String, SecurityError> {
    let mut bytes = [0u8; RANDOM_TOKEN_BYTES];
    fill_random(&mut bytes)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

pub(crate) fn keyed_digest(pepper: &[u8; 32], domain: &[u8], value: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper)
        .unwrap_or_else(|_| unreachable!("HMAC accepts every key length"));
    mac.update(domain);
    mac.update(&[0]);
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().into()
}

pub(crate) fn constant_time_digest_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

pub(crate) fn new_totp_secret() -> Result<[u8; TOTP_SECRET_BYTES], SecurityError> {
    let mut secret = [0u8; TOTP_SECRET_BYTES];
    fill_random(&mut secret)?;
    Ok(secret)
}

pub(crate) fn encode_totp_secret(secret: &[u8; TOTP_SECRET_BYTES]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

pub(crate) fn encrypt_totp_secret(
    key: &[u8; 32],
    account_binding: &[u8],
    secret: &[u8; TOTP_SECRET_BYTES],
) -> Result<Vec<u8>, SecurityError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; TOTP_NONCE_BYTES];
    fill_random(&mut nonce)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: account_binding,
            },
        )
        .map_err(|_| SecurityError::AuthenticatorSecret)?;
    let mut sealed = Vec::with_capacity(TOTP_NONCE_BYTES + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

pub(crate) fn decrypt_totp_secret(
    key: &[u8; 32],
    account_binding: &[u8],
    sealed: &[u8],
) -> Result<[u8; TOTP_SECRET_BYTES], SecurityError> {
    let (nonce, ciphertext) = sealed
        .split_at_checked(TOTP_NONCE_BYTES)
        .ok_or(SecurityError::AuthenticatorSecret)?;
    let plaintext = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: account_binding,
            },
        )
        .map_err(|_| SecurityError::AuthenticatorSecret)?;
    plaintext
        .try_into()
        .map_err(|_| SecurityError::AuthenticatorSecret)
}

pub(crate) fn verify_totp(secret: &[u8; TOTP_SECRET_BYTES], code: &str, now: u64) -> bool {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let supplied = code.as_bytes();
    let step = now / TOTP_PERIOD_SECS;
    [step.saturating_sub(1), step, step.saturating_add(1)]
        .iter()
        .any(|counter| {
            let expected = totp_at(secret, *counter);
            expected.as_bytes().ct_eq(supplied).into()
        })
}

fn totp_at(secret: &[u8], counter: u64) -> String {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret)
        .unwrap_or_else(|_| unreachable!("HMAC accepts every key length"));
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", value % TOTP_DIGITS_MODULUS)
}

fn fill_random(bytes: &mut [u8]) -> Result<(), SecurityError> {
    getrandom::fill(bytes).map_err(|_| SecurityError::Random)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_argon2id_and_verifies() {
        let encoded = hash_password("correct horse battery staple").expect("valid hash");
        assert!(encoded.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("correct horse battery staple", &encoded));
        assert!(!verify_password("wrong password", &encoded));
    }

    #[test]
    fn password_policy_is_bounded() {
        assert!(matches!(
            hash_password("too short"),
            Err(SecurityError::PasswordPolicy)
        ));
        assert!(matches!(
            hash_password(&"x".repeat(257)),
            Err(SecurityError::PasswordPolicy)
        ));
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vector_after_six_digit_reduction() {
        let secret: [u8; 20] = *b"12345678901234567890";
        assert_eq!(totp_at(&secret, 59 / 30), "287082");
        assert!(verify_totp(&secret, "287082", 59));
        assert!(!verify_totp(&secret, "287083", 59));
    }

    #[test]
    fn authenticator_secret_is_bound_and_encrypted() {
        let key = [7; 32];
        let secret = [9; 20];
        let sealed = encrypt_totp_secret(&key, b"account-a", &secret).expect("seal");
        assert!(!sealed.windows(secret.len()).any(|window| window == secret));
        assert_eq!(
            decrypt_totp_secret(&key, b"account-a", &sealed).expect("open"),
            secret
        );
        assert!(decrypt_totp_secret(&key, b"account-b", &sealed).is_err());
    }

    #[test]
    fn digests_are_domain_separated() {
        let pepper = [3; 32];
        assert_ne!(
            keyed_digest(&pepper, b"session", "same"),
            keyed_digest(&pepper, b"worker", "same")
        );
    }
}

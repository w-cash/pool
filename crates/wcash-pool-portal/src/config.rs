//! Validated portal configuration and secret material.

use std::fmt;
use zeroize::Zeroize;

use crate::ChainNetwork;

/// Runtime portal policy. Monetary production must use a separate deployment.
#[derive(Clone, Debug)]
pub struct PortalConfig {
    /// Exact HTTPS origin allowed to issue browser mutations.
    pub canonical_origin: String,
    /// Only addresses for this chain environment are accepted.
    pub network: ChainNetwork,
    /// Absolute browser-session lifetime.
    pub session_ttl_secs: u64,
    /// Maximum inactivity before a session expires.
    pub session_idle_secs: u64,
    /// Safety hold applied to replacement payout destinations.
    pub payout_change_hold_secs: u64,
    /// Failed logins before a temporary lock.
    pub max_login_attempts: u32,
    /// Temporary account lock duration.
    pub login_lock_secs: u64,
    /// Permit self-service account registration.
    pub allow_registration: bool,
}

impl PortalConfig {
    /// Conservative Testnet defaults.
    pub fn testnet() -> Self {
        Self {
            canonical_origin: "https://testnet.zecwec.com".to_owned(),
            network: ChainNetwork::Testnet,
            session_ttl_secs: 12 * 60 * 60,
            session_idle_secs: 30 * 60,
            payout_change_hold_secs: 48 * 60 * 60,
            max_login_attempts: 5,
            login_lock_secs: 15 * 60,
            allow_registration: true,
        }
    }

    /// Rejects configurations that weaken core browser controls.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.canonical_origin.starts_with("https://")
            || self.canonical_origin.ends_with('/')
            || self
                .canonical_origin
                .contains(|character: char| character.is_whitespace())
        {
            return Err(ConfigError::CanonicalOrigin);
        }
        if self.session_ttl_secs < 300 || self.session_ttl_secs > 24 * 60 * 60 {
            return Err(ConfigError::SessionTtl);
        }
        if self.session_idle_secs < 60 || self.session_idle_secs > self.session_ttl_secs {
            return Err(ConfigError::SessionIdle);
        }
        if self.payout_change_hold_secs > 7 * 24 * 60 * 60 {
            return Err(ConfigError::PayoutHold);
        }
        if !(3..=20).contains(&self.max_login_attempts) {
            return Err(ConfigError::LoginAttempts);
        }
        if !(60..=24 * 60 * 60).contains(&self.login_lock_secs) {
            return Err(ConfigError::LoginLock);
        }
        Ok(())
    }
}

/// Configuration validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// Portal browser origin is not one exact HTTPS origin.
    #[error("canonical portal origin must be one exact HTTPS origin without a trailing slash")]
    CanonicalOrigin,
    /// Runtime secret keys were missing, all-zero, or reused.
    #[error("portal secret keys must be nonzero and independently generated")]
    WeakSecrets,
    /// Invalid absolute session lifetime.
    #[error("session TTL must be between five minutes and 24 hours")]
    SessionTtl,
    /// Invalid inactivity timeout.
    #[error("session idle timeout is outside the permitted range")]
    SessionIdle,
    /// Invalid payout safety hold.
    #[error("payout change hold exceeds seven days")]
    PayoutHold,
    /// Invalid login-attempt policy.
    #[error("maximum login attempts must be between 3 and 20")]
    LoginAttempts,
    /// Invalid account-lock duration.
    #[error("login lock duration must be between one minute and one day")]
    LoginLock,
}

/// Process secret material loaded from a protected deployment secret source.
///
/// These values must be independently generated for Testnet and Mainnet. They
/// are never read from command-line arguments or included in diagnostics.
pub struct PortalSecrets {
    token_pepper: [u8; 32],
    totp_encryption_key: [u8; 32],
}

impl PortalSecrets {
    /// Creates a secret set from externally supplied random bytes.
    pub const fn new(token_pepper: [u8; 32], totp_encryption_key: [u8; 32]) -> Self {
        Self {
            token_pepper,
            totp_encryption_key,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.token_pepper.iter().all(|byte| *byte == 0)
            || self.totp_encryption_key.iter().all(|byte| *byte == 0)
            || self.token_pepper == self.totp_encryption_key
        {
            return Err(ConfigError::WeakSecrets);
        }
        Ok(())
    }

    pub(crate) const fn token_pepper(&self) -> &[u8; 32] {
        &self.token_pepper
    }

    pub(crate) const fn totp_encryption_key(&self) -> &[u8; 32] {
        &self.totp_encryption_key
    }
}

impl fmt::Debug for PortalSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortalSecrets")
            .field("token_pepper", &"[REDACTED]")
            .field("totp_encryption_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PortalSecrets {
    fn drop(&mut self) {
        self.token_pepper.zeroize();
        self.totp_encryption_key.zeroize();
    }
}

//! Testnet-only signer policy and bounded native-call configuration.

use std::{
    fmt,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use uuid::Uuid;

use crate::{SeedSource, WecPayoutError};

const DEFAULT_MAX_OUTPUTS: usize = 50;
const MAX_NATIVE_OUTPUTS: usize = 100;
const MIN_CONFIRMATIONS: u32 = 100;
const MAX_FEE_ZAT: u64 = 100_000_000;
const MIN_RESPONSE_BYTES: usize = 1_024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SIGN_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_INSPECTION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BROADCAST_TIMEOUT: Duration = Duration::from_secs(60);

/// Wall-clock and response-size bounds carried by every native call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCallLimits {
    recovery_timeout: Duration,
    sign_timeout: Duration,
    inspection_timeout: Duration,
    broadcast_timeout: Duration,
    max_response_bytes: usize,
}

impl NativeCallLimits {
    /// Creates explicit bounds for recovery, proving/signing, inspection, and
    /// broadcast calls.
    pub fn new(
        recovery_timeout: Duration,
        sign_timeout: Duration,
        inspection_timeout: Duration,
        broadcast_timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, WecPayoutError> {
        let limits = Self {
            recovery_timeout,
            sign_timeout,
            inspection_timeout,
            broadcast_timeout,
            max_response_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Bound for a seedless exact-batch recovery call.
    pub const fn recovery_timeout(self) -> Duration {
        self.recovery_timeout
    }

    /// Bound for transaction construction, proving, signing, and persistence.
    pub const fn sign_timeout(self) -> Duration {
        self.sign_timeout
    }

    /// Bound for independent persisted-intent inspection.
    pub const fn inspection_timeout(self) -> Duration {
        self.inspection_timeout
    }

    /// Bound for exact-byte node broadcast and status reconciliation.
    pub const fn broadcast_timeout(self) -> Duration {
        self.broadcast_timeout
    }

    /// Maximum accepted fully buffered native response.
    pub const fn max_response_bytes(self) -> usize {
        self.max_response_bytes
    }

    fn validate(self) -> Result<(), WecPayoutError> {
        if self.recovery_timeout.is_zero()
            || self.recovery_timeout > MAX_RECOVERY_TIMEOUT
            || self.sign_timeout.is_zero()
            || self.sign_timeout > MAX_SIGN_TIMEOUT
            || self.inspection_timeout.is_zero()
            || self.inspection_timeout > MAX_INSPECTION_TIMEOUT
            || self.broadcast_timeout.is_zero()
            || self.broadcast_timeout > MAX_BROADCAST_TIMEOUT
            || !(MIN_RESPONSE_BYTES..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            return Err(WecPayoutError::InvalidRequest);
        }
        Ok(())
    }
}

impl Default for NativeCallLimits {
    fn default() -> Self {
        Self {
            recovery_timeout: Duration::from_secs(15),
            sign_timeout: Duration::from_secs(300),
            inspection_timeout: Duration::from_secs(30),
            broadcast_timeout: Duration::from_secs(15),
            max_response_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Immutable policy for one Wcash Testnet collector signer.
pub struct WecSignerConfig {
    journal_directory: PathBuf,
    source_account: Uuid,
    seed_source: SeedSource,
    confirmations: u32,
    max_outputs: usize,
    max_fee_zat: u64,
    limits: NativeCallLimits,
}

impl WecSignerConfig {
    /// Creates conservative public-Testnet policy for one native wallet account.
    pub fn new(
        journal_directory: impl Into<PathBuf>,
        source_account: Uuid,
        seed_source: SeedSource,
    ) -> Result<Self, WecPayoutError> {
        let config = Self {
            journal_directory: journal_directory.into(),
            source_account,
            seed_source,
            confirmations: MIN_CONFIRMATIONS,
            max_outputs: DEFAULT_MAX_OUTPUTS,
            max_fee_zat: 5_000_000,
            limits: NativeCallLimits::default(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Replaces the mature-note confirmation floor. Public Testnet never
    /// permits fewer than 100 confirmations.
    pub fn with_confirmations(mut self, confirmations: u32) -> Result<Self, WecPayoutError> {
        self.confirmations = confirmations;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the output bound, capped by Wolf's native transfer maximum.
    pub fn with_max_outputs(mut self, max_outputs: usize) -> Result<Self, WecPayoutError> {
        self.max_outputs = max_outputs;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the maximum accepted ZIP 317 transaction fee.
    pub fn with_max_fee_zat(mut self, max_fee_zat: u64) -> Result<Self, WecPayoutError> {
        self.max_fee_zat = max_fee_zat;
        self.validate()?;
        Ok(self)
    }

    /// Replaces native-call bounds.
    pub fn with_limits(mut self, limits: NativeCallLimits) -> Result<Self, WecPayoutError> {
        self.limits = limits;
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), WecPayoutError> {
        self.limits.validate()?;
        if !self.journal_directory.is_absolute()
            || self
                .journal_directory
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || self.source_account.is_nil()
            || self.confirmations < MIN_CONFIRMATIONS
            || !(1..=MAX_NATIVE_OUTPUTS).contains(&self.max_outputs)
            || self.max_fee_zat == 0
            || self.max_fee_zat > MAX_FEE_ZAT
        {
            return Err(WecPayoutError::InvalidRequest);
        }
        Ok(())
    }

    pub(crate) fn journal_directory(&self) -> &Path {
        &self.journal_directory
    }

    pub(crate) const fn source_account(&self) -> Uuid {
        self.source_account
    }

    pub(crate) const fn seed_source(&self) -> &SeedSource {
        &self.seed_source
    }

    pub(crate) const fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub(crate) const fn max_outputs(&self) -> usize {
        self.max_outputs
    }

    pub(crate) const fn max_fee_zat(&self) -> u64 {
        self.max_fee_zat
    }

    pub(crate) const fn limits(&self) -> NativeCallLimits {
        self.limits
    }
}

impl fmt::Debug for WecSignerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WecSignerConfig")
            .field("journal_directory", &self.journal_directory)
            .field("source_account", &self.source_account)
            .field("seed_source", &"[REDACTED]")
            .field("confirmations", &self.confirmations)
            .field("max_outputs", &self.max_outputs)
            .field("max_fee_zat", &self.max_fee_zat)
            .field("limits", &self.limits)
            .finish()
    }
}

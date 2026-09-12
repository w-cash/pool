//! Static fencing for the isolated wallet and bounded RPC work.

use std::{
    fs::File,
    io::{Read, Take},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use uuid::Uuid;

use crate::ZecPayoutError;

/// Zallet RPC surface this implementation is pinned to.
pub const ZALLET_API_VERSION: &str = "0.1.0-beta.3";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MIN_RPC_RESPONSE_BYTES: usize = 1024;
const MAX_RPC_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_ORDINARY_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_PROVE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_BROADCAST_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_OUTPUTS: usize = 50;
const MAX_CONFIGURED_OUTPUTS: usize = 200;
const MIN_COINBASE_CONFIRMATIONS: u32 = 100;
const MAX_FEE_ZAT: u64 = 100_000_000;

/// Per-service timeout and response limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcLimits {
    ordinary_timeout: Duration,
    prove_timeout: Duration,
    broadcast_timeout: Duration,
    max_response_bytes: usize,
}

impl RpcLimits {
    /// Creates validated RPC bounds.
    pub fn new(
        ordinary_timeout: Duration,
        prove_timeout: Duration,
        broadcast_timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, ZecPayoutError> {
        let limits = Self {
            ordinary_timeout,
            prove_timeout,
            broadcast_timeout,
            max_response_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub(crate) const fn ordinary_timeout(self) -> Duration {
        self.ordinary_timeout
    }

    pub(crate) const fn prove_timeout(self) -> Duration {
        self.prove_timeout
    }

    pub(crate) const fn broadcast_timeout(self) -> Duration {
        self.broadcast_timeout
    }

    pub(crate) const fn max_response_bytes(self) -> usize {
        self.max_response_bytes
    }

    fn validate(self) -> Result<(), ZecPayoutError> {
        if self.ordinary_timeout.is_zero()
            || self.ordinary_timeout > MAX_ORDINARY_TIMEOUT
            || self.prove_timeout.is_zero()
            || self.prove_timeout > MAX_PROVE_TIMEOUT
            || self.broadcast_timeout.is_zero()
            || self.broadcast_timeout > MAX_BROADCAST_TIMEOUT
            || !(MIN_RPC_RESPONSE_BYTES..=MAX_RPC_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            return Err(ZecPayoutError::InvalidRequest);
        }
        Ok(())
    }
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            ordinary_timeout: Duration::from_secs(30),
            prove_timeout: Duration::from_secs(180),
            broadcast_timeout: Duration::from_secs(15),
            max_response_bytes: MAX_RPC_RESPONSE_BYTES,
        }
    }
}

/// Immutable signer policy and local wallet fencing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZecSignerConfig {
    journal_directory: PathBuf,
    zallet_configuration: PathBuf,
    account_id: Uuid,
    min_confirmations: u32,
    max_outputs: usize,
    max_fee_zat: u64,
    rpc_limits: RpcLimits,
}

impl ZecSignerConfig {
    /// Creates a Testnet-only configuration with conservative defaults.
    pub fn new(
        journal_directory: impl Into<PathBuf>,
        zallet_configuration: impl Into<PathBuf>,
        account_id: Uuid,
    ) -> Result<Self, ZecPayoutError> {
        let config = Self {
            journal_directory: journal_directory.into(),
            zallet_configuration: zallet_configuration.into(),
            account_id,
            min_confirmations: MIN_COINBASE_CONFIRMATIONS,
            max_outputs: DEFAULT_MAX_OUTPUTS,
            max_fee_zat: 5_000_000,
            rpc_limits: RpcLimits::default(),
        };
        config.validate_policy()?;
        Ok(config)
    }

    /// Replaces the RPC bounds.
    pub fn with_rpc_limits(mut self, limits: RpcLimits) -> Result<Self, ZecPayoutError> {
        limits.validate()?;
        self.rpc_limits = limits;
        self.validate_policy()?;
        Ok(self)
    }

    /// Replaces the mature-input confirmation floor.
    pub fn with_min_confirmations(
        mut self,
        min_confirmations: u32,
    ) -> Result<Self, ZecPayoutError> {
        self.min_confirmations = min_confirmations;
        self.validate_policy()?;
        Ok(self)
    }

    /// Replaces the output-count bound, up to the portal's hard maximum.
    pub fn with_max_outputs(mut self, max_outputs: usize) -> Result<Self, ZecPayoutError> {
        self.max_outputs = max_outputs;
        self.validate_policy()?;
        Ok(self)
    }

    /// Replaces the maximum fee accepted from inspected PCZTs.
    pub fn with_max_fee_zat(mut self, max_fee_zat: u64) -> Result<Self, ZecPayoutError> {
        self.max_fee_zat = max_fee_zat;
        self.validate_policy()?;
        Ok(self)
    }

    pub(crate) fn validate_policy(&self) -> Result<(), ZecPayoutError> {
        self.rpc_limits.validate()?;
        if self.account_id.is_nil()
            || self.journal_directory.as_os_str().is_empty()
            || self.zallet_configuration.as_os_str().is_empty()
            || self.min_confirmations < MIN_COINBASE_CONFIRMATIONS
            || !(1..=MAX_CONFIGURED_OUTPUTS).contains(&self.max_outputs)
            || self.max_fee_zat == 0
            || self.max_fee_zat > MAX_FEE_ZAT
        {
            return Err(ZecPayoutError::InvalidRequest);
        }
        Ok(())
    }

    pub(crate) const fn account_id(&self) -> Uuid {
        self.account_id
    }

    pub(crate) const fn min_confirmations(&self) -> u32 {
        self.min_confirmations
    }

    pub(crate) const fn max_outputs(&self) -> usize {
        self.max_outputs
    }

    pub(crate) const fn max_fee_zat(&self) -> u64 {
        self.max_fee_zat
    }

    pub(crate) const fn rpc_limits(&self) -> RpcLimits {
        self.rpc_limits
    }

    pub(crate) fn journal_directory(&self) -> &Path {
        &self.journal_directory
    }

    pub(crate) fn zallet_configuration(&self) -> &Path {
        &self.zallet_configuration
    }
}

/// Verifies that a Zallet configuration explicitly disables wallet broadcast,
/// selects public Testnet, pins the expected beta API, and binds RPC to
/// loopback addresses only.
pub fn validate_zallet_configuration(path: &Path) -> Result<(), ZecPayoutError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ZecPayoutError::UnsafeWalletConfiguration)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ZecPayoutError::UnsafeWalletConfiguration);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ZecPayoutError::UnsafeWalletConfiguration);
    }

    let file = File::open(path).map_err(|_| ZecPayoutError::UnsafeWalletConfiguration)?;
    let mut bytes = Vec::new();
    let mut bounded: Take<File> = file.take(MAX_CONFIG_BYTES + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| ZecPayoutError::UnsafeWalletConfiguration)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ZecPayoutError::UnsafeWalletConfiguration);
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| ZecPayoutError::UnsafeWalletConfiguration)?;
    let config: toml::Value =
        toml::from_str(text).map_err(|_| ZecPayoutError::UnsafeWalletConfiguration)?;

    if config
        .get("consensus")
        .and_then(|value| value.get("network"))
        .and_then(toml::Value::as_str)
        != Some("test")
        || config
            .get("external")
            .and_then(|value| value.get("broadcast"))
            .and_then(toml::Value::as_bool)
            != Some(false)
        || config
            .get("features")
            .and_then(|value| value.get("as_of_version"))
            .and_then(toml::Value::as_str)
            != Some(ZALLET_API_VERSION)
    {
        return Err(ZecPayoutError::UnsafeWalletConfiguration);
    }

    let binds = config
        .get("rpc")
        .and_then(|value| value.get("bind"))
        .and_then(toml::Value::as_array)
        .ok_or(ZecPayoutError::UnsafeWalletConfiguration)?;
    if binds.is_empty()
        || binds.iter().any(|bind| {
            bind.as_str()
                .and_then(|text| text.parse::<SocketAddr>().ok())
                .is_none_or(|address| {
                    !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
                        && !matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback())
                })
        })
    {
        return Err(ZecPayoutError::UnsafeWalletConfiguration);
    }

    Ok(())
}

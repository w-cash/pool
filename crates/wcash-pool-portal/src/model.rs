//! Public domain types used by the portal boundary.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A separately accounted mined asset.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Asset {
    /// Wcash, paid in WEC.
    Wec,
    /// Zcash, paid in ZEC.
    Zec,
}

impl Asset {
    /// Stable database and route representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wec => "wec",
            Self::Zec => "zec",
        }
    }
}

impl FromStr for Asset {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "wec" => Ok(Self::Wec),
            "zec" => Ok(Self::Zec),
            _ => Err(()),
        }
    }
}

/// Chain environment to which an address belongs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainNetwork {
    /// Valueless public test network.
    Testnet,
    /// Monetary production network.
    Mainnet,
}

impl ChainNetwork {
    /// Stable database representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

impl FromStr for ChainNetwork {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "testnet" => Ok(Self::Testnet),
            "mainnet" => Ok(Self::Mainnet),
            _ => Err(()),
        }
    }
}

/// Receiver class returned by an authoritative chain address parser.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverKind {
    /// Wcash or Zcash transparent receiver.
    Transparent,
    /// Unified Address with an Ironwood-capable receiver.
    Ironwood,
}

impl ReceiverKind {
    /// Stable database representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::Ironwood => "ironwood",
        }
    }
}

impl FromStr for ReceiverKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "transparent" => Ok(Self::Transparent),
            "ironwood" => Ok(Self::Ironwood),
            _ => Err(()),
        }
    }
}

/// Address proven by the configured chain-specific validation authority.
///
/// Portal code never infers validity from a textual prefix. A Wolf/Zcash
/// adapter must create this value only after parsing the full encoding,
/// checksum, network, and supported receiver set.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedDestination {
    asset: Asset,
    network: ChainNetwork,
    canonical_address: String,
    receiver_kind: ReceiverKind,
}

impl ValidatedDestination {
    /// Builds the result of an authoritative validation adapter.
    pub fn from_authoritative_validation(
        asset: Asset,
        network: ChainNetwork,
        canonical_address: String,
        receiver_kind: ReceiverKind,
    ) -> Result<Self, AddressValidationError> {
        if !(8..=512).contains(&canonical_address.len())
            || canonical_address.chars().any(char::is_whitespace)
        {
            return Err(AddressValidationError::Malformed);
        }
        Ok(Self {
            asset,
            network,
            canonical_address,
            receiver_kind,
        })
    }

    /// Validated asset.
    pub const fn asset(&self) -> Asset {
        self.asset
    }

    /// Validated network.
    pub const fn network(&self) -> ChainNetwork {
        self.network
    }

    /// Canonical address required by the isolated payout service.
    pub fn canonical_address(&self) -> &str {
        &self.canonical_address
    }

    /// Validated receiver class.
    pub const fn receiver_kind(&self) -> ReceiverKind {
        self.receiver_kind
    }
}

impl fmt::Debug for ValidatedDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedDestination")
            .field("asset", &self.asset)
            .field("network", &self.network)
            .field("canonical_address", &"[REDACTED]")
            .field("receiver_kind", &self.receiver_kind)
            .finish()
    }
}

/// Fail-closed chain address validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AddressValidationError {
    /// Encoding or checksum is invalid.
    #[error("destination is not a valid chain address")]
    Malformed,
    /// Address belongs to another asset.
    #[error("destination belongs to another chain")]
    WrongAsset,
    /// Address belongs to another network.
    #[error("destination belongs to another network")]
    WrongNetwork,
    /// Address has no payout receiver supported by this release.
    #[error("destination has no supported payout receiver")]
    UnsupportedReceiver,
    /// Validation authority is unavailable; input must not be accepted.
    #[error("address validation authority is unavailable")]
    AuthorityUnavailable,
}

/// Adapter to authoritative Wcash and Zcash address parsing.
pub trait AddressValidator: Send + Sync {
    /// Confirms that authoritative parsing is available for this chain.
    fn readiness(&self, asset: Asset, network: ChainNetwork) -> Result<(), AddressValidationError>;

    /// Validates and canonicalizes a miner payout destination.
    fn validate(
        &self,
        asset: Asset,
        network: ChainNetwork,
        candidate: &str,
    ) -> Result<ValidatedDestination, AddressValidationError>;
}

/// Immutable account identity returned to the authenticated UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AccountSummary {
    /// Internal opaque account identifier.
    pub id: Uuid,
    /// Canonical public login name.
    pub username: String,
    /// Whether TOTP is required at login and payout reauthentication.
    pub totp_enabled: bool,
}

/// Public-safe worker summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerSummary {
    /// Internal worker identifier.
    pub id: Uuid,
    /// Miner-configured bounded label.
    pub label: String,
    /// ZIP-301 username copied to the ASIC.
    pub mining_username: String,
    /// Creation time as a Unix timestamp.
    pub created_at: u64,
    /// Revocation time, if the worker can no longer authenticate.
    pub revoked_at: Option<u64>,
}

/// Safe payout setting returned to the browser.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PayoutSettingSummary {
    /// Independently settled asset.
    pub asset: Asset,
    /// Address network.
    pub network: ChainNetwork,
    /// Masked active destination, if configured.
    pub active_destination: Option<String>,
    /// Active receiver class.
    pub active_receiver: Option<ReceiverKind>,
    /// Masked replacement waiting for the safety hold.
    pub pending_destination: Option<String>,
    /// When the pending destination becomes active.
    pub pending_effective_at: Option<u64>,
    /// Automatic-payout threshold in the asset's smallest unit.
    pub threshold_zat: u64,
    /// Whether eligible balances enter scheduled batches automatically.
    pub automatic: bool,
    /// Monotonic configuration revision.
    pub revision: u64,
}

/// Masks a destination while retaining enough characters to distinguish it.
pub fn mask_destination(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 12 {
        return "••••••••".to_owned();
    }
    format!(
        "{}…{}",
        chars.iter().take(6).collect::<String>(),
        chars.iter().skip(chars.len() - 6).collect::<String>()
    )
}

/// Browser-facing aggregate pool data. No miner-private values are public.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PoolOverview {
    /// Data-source health; false must be rendered explicitly.
    pub available: bool,
    /// Last read-model update time.
    pub updated_at: Option<u64>,
    /// Current pool hashrate in solutions per second.
    pub hashrate_sol_s: Option<u64>,
    /// Connected worker count.
    pub active_workers: Option<u64>,
    /// Wcash chain height.
    pub wcash_height: Option<u64>,
    /// Zcash chain height.
    pub zcash_height: Option<u64>,
    /// Published WEC pool fee in basis points; zero at Testnet launch.
    pub wec_fee_bps: Option<u16>,
    /// Published ZEC pool fee in basis points; zero at Testnet launch.
    pub zec_fee_bps: Option<u16>,
    /// Monotonic fee-policy revision shared by the displayed rates.
    pub fee_policy_revision: Option<u64>,
}

/// Read-only projection consumed by portal overview pages.
pub trait PoolDataSource: Send + Sync {
    /// Returns aggregate pool telemetry without private miner information.
    fn overview(&self) -> PoolOverview;
}

/// A fail-closed read model used until the durable projector is connected.
#[derive(Debug, Default)]
pub struct UnavailablePoolData;

impl PoolDataSource for UnavailablePoolData {
    fn overview(&self) -> PoolOverview {
        PoolOverview::default()
    }
}

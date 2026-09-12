//! Secure Testnet miner portal and payout-signing boundary for ZecWec.
//!
//! This crate owns browser identity, mining-only worker credentials, masked
//! payout preferences, and the explicit interface to an isolated signer. It
//! never decides whether a share, block, reward, or maturity event is valid.

#![forbid(unsafe_code)]

mod clock;
mod config;
mod model;
mod security;
mod signer;
mod store;
mod web;

pub use clock::{Clock, SystemClock};
pub use config::{ConfigError, PortalConfig, PortalSecrets};
pub use model::{
    mask_destination, AccountSummary, AddressValidationError, AddressValidator, Asset,
    ChainNetwork, MinerBlockSummary, MinerPayoutSummary, Page, PageRequest, PayoutSettingSummary,
    PoolDataSource, PoolOverview, ReceiverKind, RewardSummary, UnavailablePoolData,
    ValidatedDestination, WorkerSummary,
};
pub use signer::{
    BroadcastReceipt, DisabledPayoutSigner, IsolatedPayoutSigner, PayoutBatchRequest, PayoutOutput,
    SignerError, TestnetPayoutBoundary, MAX_PAYOUT_OUTPUTS,
};
pub use store::{
    AccountCredential, AuthenticatedSession, NewSession, PayoutPreferenceChange, PortalRepository,
    ProvisionedWorker, RepositoryError, RepositoryFuture,
};
pub use web::{serve, serve_until_shutdown, PortalApp, PortalBuildError};

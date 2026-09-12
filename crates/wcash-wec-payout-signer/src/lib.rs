//! Crash-safe Wcash Testnet payout coordination through Wolf's native wallet.
//!
//! This crate binds an accounting-frozen WEC batch to one native wallet
//! operation, independently verifies the wallet's persisted intent, journals
//! the exact transaction before broadcast, and only ever retries those bytes.
//! It intentionally contains no Mainnet mode and no general-purpose wallet.

#![forbid(unsafe_code)]

mod config;
mod credential;
mod error;
mod journal;
mod pipeline;
mod transport;

pub use config::{NativeCallLimits, WecSignerConfig};
pub use credential::{SecretSeed, SeedSource};
pub use error::{WecPayoutError, WecPipelineStage};
pub use pipeline::{
    Checkpoint, CheckpointHook, WecPayoutExecution, WecPayoutRequest, WecPayoutSigner,
};
pub use transport::{
    BroadcastDisposition, BroadcastFailure, BroadcastOutcome, NativeWalletError,
    NativeWalletTransport, PersistedIntent, WalletBroadcastCall, WalletFundSource, WalletIdentity,
    WalletInspectionCall, WalletNetwork, WalletOutput, WalletRecoveryCall, WalletSignCall,
    WalletSignedTransaction, WCASH_TESTNET_BRANCH_ID, WCASH_TESTNET_GENESIS_HASH,
};

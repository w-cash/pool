//! Crash-safe Wcash payout coordination through Wolf's native wallet.
//!
//! This crate binds an accounting-frozen WEC batch to one native wallet
//! operation, independently verifies the wallet's persisted intent, journals
//! the exact transaction before broadcast, and only ever retries those bytes.
//! It is a narrowly pinned payout signer, not a general-purpose wallet.

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
    WecPreparedPayout, WecPreparedRecovery,
};
pub use transport::{
    BroadcastDisposition, BroadcastFailure, BroadcastOutcome, NativeWalletError,
    NativeWalletTransport, PersistedIntent, WalletBroadcastCall, WalletFundSource, WalletIdentity,
    WalletInspectionCall, WalletNetwork, WalletOutput, WalletRecoveryCall, WalletSignCall,
    WalletSignedTransaction, WCASH_MAINNET_BRANCH_ID, WCASH_MAINNET_GENESIS_HASH,
    WCASH_TESTNET_BRANCH_ID, WCASH_TESTNET_GENESIS_HASH,
};
#[cfg(feature = "regtest")]
pub use transport::{WCASH_REGTEST_BRANCH_ID, WCASH_REGTEST_GENESIS_HASH};

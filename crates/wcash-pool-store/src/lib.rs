//! Durable non-consensus state for the ZecWec pool.
//!
//! This crate owns account and mining-token verification, deployment identity
//! fencing, reserved nonce ranges, backend-journal projection, and the monetary
//! ledger. It never validates Equihash or decides whether a block is canonical;
//! those facts remain authoritative only when delivered by Wolf.

#![forbid(unsafe_code)]

mod accounting;
mod auth;
mod postgres;

pub use accounting::{
    allocate_pplns, target_work, AccountAllocation, AllocationPlan, PplnsError, WeightedShare,
};
pub use auth::{
    generate_mining_token, hash_mining_token, MiningToken, MiningTokenError,
    PostgresAuthenticationProvider,
};
pub use postgres::{
    AccountCredentialRecord, AuthenticatedPortalSession, Chain, ChainPolicy, DeploymentIdentity,
    DeploymentNetwork, NewPortalSessionRecord, NonceRange, PayoutBatch, PayoutBatchState,
    PayoutConfigurationReadiness, PayoutConfirmation, PayoutInstruction, PayoutReorg,
    PostgresStore, ProjectionResult, ReceiverKind, SignedPayoutArtifact, StoreError,
};

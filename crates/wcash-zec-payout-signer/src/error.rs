//! Public, privacy-preserving error types.

/// A durable PCZT pipeline stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineStage {
    /// The exact request commitment was reserved.
    Reserved,
    /// Zallet created the PCZT.
    Created,
    /// The created PCZT passed recipient and amount inspection.
    CreatedVerified,
    /// Zallet proved the PCZT.
    Proved,
    /// The proved PCZT passed inspection.
    ProvedVerified,
    /// Zallet signed the PCZT with strict input ownership enabled.
    Signed,
    /// The signed PCZT passed inspection.
    SignedVerified,
    /// Zallet extracted and stored the final transaction.
    Extracted,
    /// Parent-node broadcast returned without a durable local resolution.
    BroadcastUnresolved,
    /// The parent node explicitly rejected the transaction.
    Rejected,
    /// The parent node accepted or already knew the transaction.
    Completed,
}

/// Fail-closed payout execution error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ZecPayoutError {
    /// The batch violates a size, value, identity, or address bound.
    #[error("invalid Zcash payout request")]
    InvalidRequest,
    /// Only the ZEC asset is accepted by this signer.
    #[error("payout signer rejected the asset")]
    WrongAsset,
    /// Only public Zcash Testnet is accepted.
    #[error("payout signer rejected the network")]
    WrongNetwork,
    /// The batch named an account other than the configured collector account.
    #[error("payout signer rejected the source account")]
    WrongAccount,
    /// The source was not the isolating Orchard-family shielded source.
    #[error("payout signer rejected the fund source")]
    WrongFundSource,
    /// The local Zallet configuration is absent, unsafe, or not Testnet.
    #[error("isolated Zallet configuration is unsafe")]
    UnsafeWalletConfiguration,
    /// A batch identifier is already bound to different facts.
    #[error("payout batch conflicts with an earlier request")]
    IdempotencyConflict,
    /// The durable journal could not be read, locked, or synchronized.
    #[error("payout journal is unavailable")]
    JournalUnavailable,
    /// Existing journal data failed structural or integrity checks.
    #[error("payout journal is corrupt")]
    JournalCorrupt,
    /// A wallet RPC failed or timed out without producing a durable next stage.
    #[error("isolated wallet RPC did not complete")]
    WalletRpcUnavailable,
    /// A wallet RPC explicitly rejected the requested operation.
    #[error("isolated wallet rejected the payout")]
    WalletRejected,
    /// A wallet response did not match the pinned PCZT protocol or exact batch.
    #[error("isolated wallet response violated the payout contract")]
    WalletProtocolViolation,
    /// The parent node explicitly rejected the exact transaction.
    #[error("parent node rejected the payout transaction")]
    BroadcastRejected,
    /// Broadcast might have succeeded and requires an exact-byte retry or reconciliation.
    #[error("payout broadcast outcome is unresolved")]
    BroadcastAmbiguous,
    /// A deterministic fault-injection checkpoint interrupted execution.
    #[error("payout pipeline interrupted at a checkpoint")]
    Interrupted,
}

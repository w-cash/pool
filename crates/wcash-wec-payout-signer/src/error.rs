//! Public, privacy-preserving failure types.

/// Durable WEC payout pipeline stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WecPipelineStage {
    /// The exact accounting request is durably reserved.
    Reserved,
    /// Exact signed bytes and their verified native intent are durable.
    Signed,
    /// Broadcast may have succeeded and requires exact-byte reconciliation.
    BroadcastUnresolved,
    /// The Wcash node explicitly rejected the exact transaction.
    Rejected,
    /// The Wcash node accepted or already knew the exact transaction.
    Completed,
}

/// Fail-closed Wcash payout execution error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WecPayoutError {
    /// The batch violates a count, value, identity, or receiver bound.
    #[error("invalid Wcash payout request")]
    InvalidRequest,
    /// Only the WEC asset is accepted by this signer.
    #[error("payout signer rejected the asset")]
    WrongAsset,
    /// Only public Wcash Testnet is accepted.
    #[error("payout signer rejected the network")]
    WrongNetwork,
    /// The request named a wallet account other than the configured collector.
    #[error("payout signer rejected the source account")]
    WrongAccount,
    /// Only spendable Ironwood collector funds may fund payouts.
    #[error("payout signer rejected the fund source")]
    WrongFundSource,
    /// The seed source is absent, unsafe, malformed, or inaccessible.
    #[error("Wcash spending credential is unavailable")]
    UnsafeCredential,
    /// A batch identifier is already bound to different exact facts.
    #[error("payout batch conflicts with an earlier request")]
    IdempotencyConflict,
    /// The durable journal could not be read, locked, or synchronized.
    #[error("payout journal is unavailable")]
    JournalUnavailable,
    /// Existing journal data failed integrity or structural checks.
    #[error("payout journal is corrupt")]
    JournalCorrupt,
    /// The native wallet is unavailable or timed out before a recoverable result.
    #[error("native Wcash wallet did not complete")]
    WalletUnavailable,
    /// The native wallet explicitly rejected the payout request.
    #[error("native Wcash wallet rejected the payout")]
    WalletRejected,
    /// Native wallet facts did not exactly match the accounting-frozen intent.
    #[error("native Wcash wallet response violated the payout contract")]
    WalletProtocolViolation,
    /// Signing might have committed in the native wallet and must be recovered.
    #[error("native Wcash signing outcome requires batch recovery")]
    WalletAmbiguous,
    /// The Wcash node explicitly rejected the exact transaction.
    #[error("Wcash node rejected the payout transaction")]
    BroadcastRejected,
    /// Broadcast might have succeeded; only the durable bytes may be retried.
    #[error("Wcash payout broadcast outcome is unresolved")]
    BroadcastAmbiguous,
    /// A deterministic fault-injection checkpoint interrupted execution.
    #[error("Wcash payout pipeline interrupted at a checkpoint")]
    Interrupted,
}

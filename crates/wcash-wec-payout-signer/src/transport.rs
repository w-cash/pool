//! Narrow, timeout-bounded boundary to Wolf's native `wcash-wallet` service.

use std::{fmt, time::Duration};

use uuid::Uuid;
use wcash_pool_portal::ReceiverKind;

use crate::SecretSeed;

/// Frozen display-order Wcash Testnet genesis block identifier.
pub const WCASH_TESTNET_GENESIS_HASH: &str =
    "0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a";
/// Frozen Wcash Testnet V1 transaction-signature branch identifier.
pub const WCASH_TESTNET_BRANCH_ID: &str = "b3cfd27e";

/// Network identity returned by the native wallet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletNetwork {
    /// Public Wcash Testnet.
    Testnet,
    /// Local Wcash Regtest, never accepted by this signer.
    Regtest,
    /// Future Wcash Mainnet, deliberately unsupported here.
    Mainnet,
}

/// Wallet value source selected for a payout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletFundSource {
    /// Ironwood shielded notes.
    Ironwood,
    /// Legacy Sapling notes, disabled for Wcash payouts.
    Sapling,
    /// Transparent value, which must first be shielded.
    Transparent,
}

/// Seedless identity and synchronization attestation from `wcash-wallet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletIdentity {
    /// Selected Wcash network.
    pub network: WalletNetwork,
    /// Frozen display-order genesis hash.
    pub genesis_hash: String,
    /// Consensus transaction branch identifier.
    pub branch_id: String,
    /// Exact collector account UUID.
    pub account_id: Uuid,
    /// Pool from which the wallet will select value.
    pub fund_source: WalletFundSource,
    /// Whether the wallet has scanned the attested node tip.
    pub synchronized: bool,
}

/// One exact ordered output sent to and returned by the native wallet.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletOutput {
    /// Stable accounting allocation identifier.
    pub allocation_id: Uuid,
    /// Canonical Wcash Testnet Unified Address.
    pub canonical_address: String,
    /// Receiver selected by the authoritative Wolf parser.
    pub receiver_kind: ReceiverKind,
    /// Exact value in zatoshis.
    pub amount_zat: u64,
    /// Deterministic private memo binding the output to the batch.
    pub memo: Vec<u8>,
}

impl fmt::Debug for WalletOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletOutput")
            .field("allocation_id", &self.allocation_id)
            .field("canonical_address", &"[REDACTED]")
            .field("receiver_kind", &self.receiver_kind)
            .field("amount_zat", &self.amount_zat)
            .field("memo", &"[REDACTED]")
            .finish()
    }
}

/// Seedless lookup for a prior durable native-wallet operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletRecoveryCall {
    /// Stable payout identity.
    pub batch_id: Uuid,
    /// Exact signer commitment bound to that identity.
    pub request_commitment: [u8; 32],
    /// Maximum wall-clock duration.
    pub timeout: Duration,
    /// Maximum fully buffered response bytes.
    pub max_response_bytes: usize,
}

/// Exact multi-output construction request.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletSignCall {
    /// Stable payout identity.
    pub batch_id: Uuid,
    /// Exact signer commitment bound to that identity.
    pub request_commitment: [u8; 32],
    /// Required wallet identity and source.
    pub identity: WalletIdentity,
    /// Exact ordered recipients, amounts, and binding memos.
    pub outputs: Vec<WalletOutput>,
    /// Required mature-note confirmations.
    pub confirmations: u32,
    /// Maximum fee accepted by the caller.
    pub max_fee_zat: u64,
    /// Maximum wall-clock duration including proving.
    pub timeout: Duration,
    /// Maximum fully buffered response bytes.
    pub max_response_bytes: usize,
}

impl fmt::Debug for WalletSignCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSignCall")
            .field("batch_id", &self.batch_id)
            .field("request_commitment", &self.request_commitment)
            .field("identity", &self.identity)
            .field("outputs", &"[REDACTED]")
            .field("confirmations", &self.confirmations)
            .field("max_fee_zat", &self.max_fee_zat)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Exact signed transaction durably produced or recovered by the wallet.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletSignedTransaction {
    /// Stable payout identity.
    pub batch_id: Uuid,
    /// Exact signer commitment stored by the wallet.
    pub request_commitment: [u8; 32],
    /// Consensus transaction identifier in display order.
    pub transaction_id: String,
    /// Exact signed transaction serialization as lowercase hexadecimal.
    pub raw_transaction_hex: String,
    /// Digest of the exact unsigned transaction intent.
    pub unsigned_digest: [u8; 32],
    /// ZIP 317 fee in zatoshis.
    pub fee_zat: u64,
    /// Proposal target height.
    pub target_height: u32,
    /// Signed transaction expiry height.
    pub expiry_height: u32,
    /// True only after the wallet committed batch binding and bytes durably.
    pub stored: bool,
    /// True only after Wolf checked deterministic Ironwood change authority.
    pub internal_change_receiver_verified: bool,
}

impl fmt::Debug for WalletSignedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSignedTransaction")
            .field("batch_id", &self.batch_id)
            .field("request_commitment", &self.request_commitment)
            .field("transaction_id", &self.transaction_id)
            .field("raw_transaction_hex", &"[REDACTED]")
            .field("unsigned_digest", &self.unsigned_digest)
            .field("fee_zat", &self.fee_zat)
            .field("target_height", &self.target_height)
            .field("expiry_height", &self.expiry_height)
            .field("stored", &self.stored)
            .field(
                "internal_change_receiver_verified",
                &self.internal_change_receiver_verified,
            )
            .finish()
    }
}

/// Seedless request to independently inspect the wallet's persisted binding.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletInspectionCall {
    /// Stable payout identity.
    pub batch_id: Uuid,
    /// Exact signer commitment expected in wallet storage.
    pub request_commitment: [u8; 32],
    /// Exact signed transaction identifier.
    pub transaction_id: String,
    /// Exact signed bytes to inspect.
    pub raw_transaction_hex: String,
    /// Maximum wall-clock duration.
    pub timeout: Duration,
    /// Maximum fully buffered response bytes.
    pub max_response_bytes: usize,
}

impl fmt::Debug for WalletInspectionCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletInspectionCall")
            .field("batch_id", &self.batch_id)
            .field("request_commitment", &self.request_commitment)
            .field("transaction_id", &self.transaction_id)
            .field("raw_transaction_hex", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Independently inspected durable intent for exact signed bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct PersistedIntent {
    /// Attested wallet and chain identity.
    pub identity: WalletIdentity,
    /// Stable payout identity stored beside the transaction.
    pub batch_id: Uuid,
    /// Stored exact signer commitment.
    pub request_commitment: [u8; 32],
    /// Exact requested outputs in accounting order.
    pub ordered_outputs: Vec<WalletOutput>,
    /// Digest of the exact unsigned transaction intent.
    pub unsigned_digest: [u8; 32],
    /// Consensus transaction identifier in display order.
    pub transaction_id: String,
    /// SHA-256 of decoded signed transaction bytes.
    pub raw_transaction_sha256: [u8; 32],
    /// Exact transaction fee.
    pub fee_zat: u64,
    /// Proposal target height.
    pub target_height: u32,
    /// Signed transaction expiry height.
    pub expiry_height: u32,
    /// True only when the native batch mapping and bytes are durable.
    pub stored: bool,
    /// True only after checking deterministic Ironwood change authority.
    pub internal_change_receiver_verified: bool,
}

impl fmt::Debug for PersistedIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedIntent")
            .field("identity", &self.identity)
            .field("batch_id", &self.batch_id)
            .field("request_commitment", &self.request_commitment)
            .field("ordered_outputs", &"[REDACTED]")
            .field("unsigned_digest", &self.unsigned_digest)
            .field("transaction_id", &self.transaction_id)
            .field("raw_transaction_sha256", &self.raw_transaction_sha256)
            .field("fee_zat", &self.fee_zat)
            .field("target_height", &self.target_height)
            .field("expiry_height", &self.expiry_height)
            .field("stored", &self.stored)
            .field(
                "internal_change_receiver_verified",
                &self.internal_change_receiver_verified,
            )
            .finish()
    }
}

/// Exact-byte broadcast request to the attested Wcash node adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletBroadcastCall {
    /// Expected display-order transaction identifier.
    pub transaction_id: String,
    /// Previously journaled signed bytes.
    pub raw_transaction_hex: String,
    /// Maximum wall-clock duration including exact-txid reconciliation.
    pub timeout: Duration,
    /// Maximum fully buffered response bytes.
    pub max_response_bytes: usize,
}

impl fmt::Debug for WalletBroadcastCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletBroadcastCall")
            .field("transaction_id", &self.transaction_id)
            .field("raw_transaction_hex", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Successful node disposition for an exact transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastDisposition {
    /// The node accepted the transaction during this call.
    Accepted,
    /// The exact transaction was already in the live mempool or best chain.
    AlreadyKnown,
}

/// Resolved successful broadcast response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastOutcome {
    /// Exact transaction identifier confirmed by the adapter.
    pub transaction_id: String,
    /// Accepted or already-known disposition.
    pub disposition: BroadcastDisposition,
}

/// Fail-closed node broadcast class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastFailure {
    /// The node explicitly rejected validly delivered bytes.
    Rejected,
    /// The call exceeded its deadline; submission may have reached the node.
    Timeout,
    /// Transport failed; submission may have reached the node.
    Unavailable,
    /// The adapter could not reconcile an exact transaction status.
    Ambiguous,
    /// Node response violated the exact-txid protocol.
    ProtocolViolation,
}

/// Fail-closed native-wallet operation class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWalletError {
    /// Operation exceeded its deadline.
    Timeout,
    /// Wallet boundary was unavailable.
    Unavailable,
    /// Wallet explicitly rejected the request without persisting a transaction.
    Rejected,
    /// Batch identity is already bound to a different request commitment.
    IdempotencyConflict,
    /// Operation may have persisted and must be recovered by batch identity.
    Ambiguous,
    /// Wallet response violated the versioned boundary.
    ProtocolViolation,
}

/// Timeout-bounded native Wcash wallet and node boundary.
///
/// The current Wolf one-shot `transfer` command is deliberately not an
/// implementation of this trait: it cannot recover by batch identity. A valid
/// implementation must atomically store `(batch_id, request_commitment,
/// transaction_id, raw_transaction)` before `sign_exact` returns. Exact calls
/// then return those same bytes from `recover_exact`; different content
/// under the same batch identifier is a rejection.
pub trait NativeWalletTransport: Send + Sync {
    /// Returns seedless chain, account, source-pool, and synchronization facts.
    fn identity(
        &self,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<WalletIdentity, NativeWalletError>;

    /// Recovers a previously persisted exact batch without reading a seed.
    fn recover_exact(
        &self,
        call: &WalletRecoveryCall,
    ) -> Result<Option<WalletSignedTransaction>, NativeWalletError>;

    /// Builds one multi-output transaction and atomically persists its batch
    /// binding and signed bytes before returning.
    ///
    /// `seed` must only cross an in-process private boundary or be written to
    /// the isolated wallet's standard input; never put it in argv, env, debug,
    /// error text, or ordinary logs.
    fn sign_exact(
        &self,
        call: &WalletSignCall,
        seed: &SecretSeed,
    ) -> Result<WalletSignedTransaction, NativeWalletError>;

    /// Independently verifies the stored intent and exact signed bytes.
    fn inspect_persisted(
        &self,
        call: &WalletInspectionCall,
    ) -> Result<PersistedIntent, NativeWalletError>;

    /// Submits only the exact journaled bytes and reconciles accepted,
    /// already-known, rejected, and ambiguous node outcomes.
    fn broadcast_exact(
        &self,
        call: &WalletBroadcastCall,
    ) -> Result<BroadcastOutcome, BroadcastFailure>;
}

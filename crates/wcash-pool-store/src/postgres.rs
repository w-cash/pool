//! PostgreSQL deployment fencing and append-only event projection.

use std::{future::Future, pin::Pin, str::FromStr, time::Duration};

use futures_util::TryStreamExt;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;
use wcash_pool_backend_client::{BackendAuthority, DeliveredBackendEvent};
use wcash_pool_core::{NonceCursor, NonceNamespaceLease, NoncePrefixAllocator};
use wcash_pool_edge::{BackendEventConsumer, BackendEventConsumerError};
use wcash_pool_portal::{
    Asset, ChainNetwork, PayoutBatchRequest, PayoutOutput, ReceiverKind as PortalReceiverKind,
};
use wcash_pool_protocol::{
    BackendEvent, MergedChain, NonceProfile, ProtocolError, WinnerDescriptor,
};

use crate::auth::validate_argon2id_verifier;
use crate::{
    allocate_pplns, generate_mining_token, hash_mining_token, target_work, MiningToken,
    MiningTokenError, PplnsError, WeightedShare,
};

const MAX_DATABASE_CONNECTIONS: u32 = 64;
const MAX_REPLAY_BATCH: usize = 1_024;
const MAX_PPLNS_SHARES: i64 = 100_001;
const MAX_SIGNED_TRANSACTION_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_WALLET_RECONCILIATION_AGE_SECS: u64 = 5 * 60;
const MIN_NONCE_NAMESPACE_LEASE_SECS: u64 = 1;
const MAX_NONCE_NAMESPACE_LEASE_SECS: u64 = 5 * 60;
const LEDGER_SNAPSHOT_DOMAIN: &[u8] = b"zecwec/ledger-snapshot/v1";

/// Explicit chain environment for a deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentNetwork {
    /// Valueless Wcash/Zcash testing networks.
    Testnet,
    /// Value-bearing production networks.
    Mainnet,
}

impl DeploymentNetwork {
    /// Stable database/configuration representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

/// One independently accounted merged-mining chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chain {
    /// Wcash auxiliary chain.
    Wcash,
    /// Zcash parent chain.
    Zcash,
}

impl Chain {
    /// Stable database representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wcash => "wcash",
            Self::Zcash => "zcash",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "wcash" => Ok(Self::Wcash),
            "zcash" => Ok(Self::Zcash),
            _ => Err(StoreError::CorruptDatabaseState("chain")),
        }
    }
}

impl From<MergedChain> for Chain {
    fn from(chain: MergedChain) -> Self {
        match chain {
            MergedChain::Wcash => Self::Wcash,
            MergedChain::Zcash => Self::Zcash,
        }
    }
}

/// Exact chain-wallet state observed by a separately authenticated wallet
/// adapter. The store derives the ledger facts and checkpoint identity; a
/// caller cannot supply either one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletObservation {
    /// Chain whose wallet and accounting ledger were inspected.
    pub chain: Chain,
    /// Digest of the wallet adapter's canonical state response.
    pub wallet_state_digest: [u8; 32],
    /// Spendable collector balance reported by the wallet, in atomic units.
    pub wallet_spendable_zat: u64,
    /// Canonical best-chain tip hash in chain wire byte order.
    pub best_tip_hash: [u8; 32],
    /// Canonical best-chain tip height.
    pub best_tip_height: u32,
    /// Time at which the wallet snapshot was taken, as Unix seconds.
    pub observed_at: u64,
    /// Short expiry selected by the wallet adapter, as Unix seconds.
    pub valid_until: u64,
}

/// Database-issued reconciliation checkpoint binding wallet state to one exact
/// immutable accounting snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletReconciliation {
    /// Store-generated checkpoint identity.
    pub id: Uuid,
    /// Reconciled chain.
    pub chain: Chain,
    /// Hash of every sealed chain ledger line visible in the checkpoint.
    pub ledger_root: [u8; 32],
    /// Number of sealed ledger transactions committed by the root.
    pub ledger_transaction_count: u64,
    /// Spendable wallet balance proven equal to the internal collector asset.
    pub wallet_spendable_zat: u64,
    /// Best-chain tip used by the wallet observation.
    pub best_tip_hash: [u8; 32],
    /// Best-chain height used by the wallet observation.
    pub best_tip_height: u32,
    /// Observation time as Unix seconds.
    pub observed_at: u64,
    /// Expiry after which no new payout batch may consume this checkpoint.
    pub valid_until: u64,
}

/// Immutable database and backend identity for one Testnet or Mainnet service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentIdentity {
    /// Operator-assigned database namespace.
    pub id: Uuid,
    /// Explicit value-bearing boundary.
    pub network: DeploymentNetwork,
    /// Wcash genesis hash in backend wire byte order.
    pub wcash_genesis: [u8; 32],
    /// Zcash genesis hash in backend wire byte order.
    pub zcash_genesis: [u8; 32],
    /// Wcash chain identifier.
    pub chain_id: u32,
    /// Exact Wcash collector-recipient commitment.
    pub wcash_payout_commitment: [u8; 32],
    /// Exact Zcash collector-recipient commitment.
    pub zcash_payout_commitment: [u8; 32],
    /// Persisted Wolf installation identity.
    pub backend_instance: Uuid,
    /// Persisted Wolf journal namespace.
    pub journal_stream: Uuid,
}

impl DeploymentIdentity {
    /// Rejects empty or collapsed security-domain identifiers.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.id.is_nil()
            || self.wcash_genesis == [0; 32]
            || self.zcash_genesis == [0; 32]
            || self.chain_id == 0
            || self.wcash_payout_commitment == [0; 32]
            || self.zcash_payout_commitment == [0; 32]
            || self.backend_instance.is_nil()
            || self.journal_stream.is_nil()
            || self.backend_instance == self.journal_stream
        {
            return Err(StoreError::InvalidDeploymentIdentity);
        }
        Ok(())
    }

    fn matches_authority(&self, authority: &BackendAuthority) -> bool {
        self.wcash_genesis == *authority.wcash_genesis().as_bytes()
            && self.zcash_genesis == *authority.zcash_genesis().as_bytes()
            && self.chain_id == authority.chain_id()
            && self.wcash_payout_commitment == *authority.wcash_payout_commitment().as_bytes()
            && self.zcash_payout_commitment == *authority.zcash_payout_commitment().as_bytes()
            && self.backend_instance == authority.backend_instance().get()
            && self.journal_stream == authority.journal_stream().get()
    }
}

/// A transactionally reserved, never-reused nonce-prefix interval.
///
/// Fields are deliberately private: callers can inspect a reservation but
/// cannot forge one or substitute a different negotiated nonce profile.
///
/// ```compile_fail
/// use wcash_pool_store::NonceRange;
///
/// fn duplicate_reservation(reservation: NonceRange) {
///     let _first = reservation.allocator();
///     let _duplicate = reservation.allocator();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct NonceRange {
    id: Uuid,
    profile: NonceProfile,
    namespace: NonceNamespaceLease,
    start: u64,
    end: u64,
}

impl NonceRange {
    /// Returns the durable audit identity of this reservation.
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the nonce profile atomically bound to the database cursor.
    pub const fn profile(&self) -> NonceProfile {
        self.profile
    }

    /// Returns the externally fenced namespace encoded into every prefix.
    pub const fn namespace(&self) -> NonceNamespaceLease {
        self.namespace
    }

    /// Returns the first counter reserved for this process.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the exclusive local exhaustion fence.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Creates an allocator that cannot escape this exact durable reservation.
    pub fn allocator(self) -> Result<NoncePrefixAllocator, StoreError> {
        let cursor = NonceCursor::new(self.profile, self.namespace, self.start)?;
        NoncePrefixAllocator::restore_reserved(cursor, self.namespace, self.end)
            .map_err(StoreError::from)
    }
}

/// Database-issued ownership proof for one global nonce-prefix namespace.
///
/// The ownership boundary is the exact Wolf backend installation and journal,
/// not an accounting deployment. A lease generation changes on every takeover
/// so a token retained by a stopped process cannot become valid again if a
/// holder UUID is accidentally reused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceNamespaceClaim {
    deployment_id: Uuid,
    holder_id: Uuid,
    profile: NonceProfile,
    namespace: NonceNamespaceLease,
    generation: u64,
    expires_at: u64,
}

impl NonceNamespaceClaim {
    /// Returns the process-lifetime UUID that owns this lease.
    pub const fn holder_id(&self) -> Uuid {
        self.holder_id
    }

    /// Returns the deployment recorded for operational audit.
    pub const fn deployment_id(&self) -> Uuid {
        self.deployment_id
    }

    /// Returns the negotiated nonce profile protected by this lease.
    pub const fn profile(&self) -> NonceProfile {
        self.profile
    }

    /// Returns the encoded nonce namespace protected by this lease.
    pub const fn namespace(&self) -> NonceNamespaceLease {
        self.namespace
    }

    /// Returns the monotonic database lease generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the database-clock expiry as Unix seconds.
    ///
    /// This value is informational. Every operation rechecks ownership and
    /// expiry against the database clock inside its transaction.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Durable payout-batch lifecycle. Signing and chain submission occur through a
/// separate wallet boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayoutBatchState {
    /// Payable liabilities have been moved to pending.
    Draft,
    /// An isolated signer returned a transaction identity.
    Signed,
    /// The exact transaction was accepted for broadcast.
    Broadcast,
    /// The transaction reached the configured confirmation policy.
    Confirmed,
    /// A previously confirmed transaction left the best chain; chain payouts
    /// remain frozen pending authoritative wallet reconciliation.
    Reorged,
    /// A pre-confirmation batch was released back to payable balances.
    Cancelled,
}

impl PayoutBatchState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Signed => "signed",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Reorged => "reorged",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "draft" => Ok(Self::Draft),
            "signed" => Ok(Self::Signed),
            "broadcast" => Ok(Self::Broadcast),
            "confirmed" => Ok(Self::Confirmed),
            "reorged" => Ok(Self::Reorged),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(StoreError::CorruptDatabaseState("payout batch state")),
        }
    }
}

/// One durable payout batch returned to the isolated wallet coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutBatch {
    /// Stable batch identity.
    pub id: Uuid,
    /// Chain whose liabilities are reserved.
    pub chain: Chain,
    /// Current one-way state.
    pub state: PayoutBatchState,
    /// Immutable chain-policy revision used to build and validate this batch.
    pub policy_version: u64,
    /// Database-issued wallet reconciliation consumed by this batch.
    pub reconciliation_id: Uuid,
    /// Exact post-reservation ledger snapshot committed to the signer request.
    pub ledger_root: [u8; 32],
    /// Last immutable ledger sequence included in `ledger_root`.
    pub ledger_sequence_cutoff: u64,
    /// Sum of miner outputs in atomic units.
    pub miner_total_zat: u64,
    /// Exact outputs approved by the accounting transaction.
    pub outputs: Vec<PayoutInstruction>,
}

/// One exact output in an accounting-reserved payout batch.
#[derive(Clone, Eq, PartialEq)]
pub struct PayoutInstruction {
    /// Stable signer-output identity unique within the batch.
    pub allocation_id: Uuid,
    /// Miner account whose liability is being settled.
    pub account_id: Uuid,
    /// Versioned destination row frozen into this batch.
    pub destination_id: Uuid,
    /// Receiver class attested when the immutable destination was stored.
    pub receiver_kind: ReceiverKind,
    /// Full destination passed only to the isolated wallet builder.
    pub address: String,
    /// Exact output amount in atomic units.
    pub amount_zat: u64,
}

impl std::fmt::Debug for PayoutInstruction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayoutInstruction")
            .field("allocation_id", &self.allocation_id)
            .field("account_id", &self.account_id)
            .field("destination_id", &self.destination_id)
            .field("receiver_kind", &self.receiver_kind)
            .field("address", &"[REDACTED]")
            .field("amount_zat", &self.amount_zat)
            .finish()
    }
}

/// Persisted signer result sufficient to resume or reconcile broadcast after a
/// process crash. The transaction bytes are public chain data but are omitted
/// from debug output to avoid accidental address disclosure in logs.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedPayoutArtifact {
    /// Durable payout batch identity.
    pub batch_id: Uuid,
    /// Chain whose parser and broadcaster must consume the bytes.
    pub chain: Chain,
    /// Current durable payout lifecycle state.
    pub state: PayoutBatchState,
    /// Digest of the unsigned transaction approved by the isolated signer.
    pub unsigned_digest: [u8; 32],
    /// Consensus transaction identifier returned by the isolated signer.
    pub transaction_id: [u8; 32],
    /// Exact signed transaction bytes to rebroadcast after a crash.
    pub signed_transaction: Vec<u8>,
    /// Exact network fee reconciled against the collector asset.
    pub network_fee_zat: u64,
}

/// Exact best-chain evidence authoritatively observed for a payout transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutConfirmation {
    /// Containing best-chain block hash in chain wire byte order.
    pub block_hash: [u8; 32],
    /// Height of the containing block.
    pub block_height: u32,
    /// Confirmations computed against the same best-chain snapshot.
    pub confirmations: u32,
}

impl PayoutConfirmation {
    fn validate(&self) -> Result<(), StoreError> {
        if self.block_hash == [0; 32] || self.block_height == 0 || self.confirmations == 0 {
            Err(StoreError::InvalidPayoutConfirmation)
        } else {
            Ok(())
        }
    }
}

/// Exact evidence that a previously confirmed payout left the best chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutReorg {
    /// Previously recorded confirmation that is no longer canonical.
    pub prior_confirmation: PayoutConfirmation,
    /// Current replacement best-chain tip hash.
    pub replacement_tip_hash: [u8; 32],
    /// Current replacement best-chain tip height.
    pub replacement_tip_height: u32,
    /// Observation time as Unix seconds.
    pub observed_at: u64,
}

impl PayoutReorg {
    fn validate(&self) -> Result<(), StoreError> {
        self.prior_confirmation.validate()?;
        if self.replacement_tip_hash == [0; 32]
            || self.replacement_tip_hash == self.prior_confirmation.block_hash
            || self.replacement_tip_height == 0
            || self.observed_at == 0
        {
            Err(StoreError::InvalidPayoutConfirmation)
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for SignedPayoutArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedPayoutArtifact")
            .field("batch_id", &self.batch_id)
            .field("chain", &self.chain)
            .field("state", &self.state)
            .field("unsigned_digest", &self.unsigned_digest)
            .field("transaction_id", &self.transaction_id)
            .field("signed_transaction", &"[REDACTED]")
            .field("network_fee_zat", &self.network_fee_zat)
            .finish()
    }
}

/// Versioned, chain-specific public accounting policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainPolicy {
    /// Independently accounted chain.
    pub chain: Chain,
    /// Exact accumulated target-work in the PPLNS window.
    pub pplns_window_work: BigUint,
    /// Pool fee in basis points. Launch policy is zero for both chains.
    pub fee_bps: u16,
    /// Automatic payout floor in atomic units.
    pub payout_threshold_zat: u64,
    /// Pool confirmation policy, in addition to backend maturity; never below
    /// the 100-block launch coinbase floor.
    pub required_confirmations: u32,
    /// Maximum deterministic outputs reserved into one payout transaction.
    pub maximum_payout_outputs: u32,
    /// Absolute network-fee ceiling accepted from the isolated signer.
    pub maximum_network_fee_zat: u64,
    /// Relative network-fee ceiling against frozen miner outputs.
    pub maximum_network_fee_bps: u16,
    /// Monotonic policy revision displayed to miners.
    pub policy_version: u64,
}

impl ChainPolicy {
    fn validate(&self) -> Result<(), StoreError> {
        if self.pplns_window_work == BigUint::default()
            || self.fee_bps > 1_000
            || self.payout_threshold_zat == 0
            || self.required_confirmations < 100
            || self.required_confirmations > 1_000_000
            || !(1..=u32::try_from(wcash_pool_portal::MAX_PAYOUT_OUTPUTS).unwrap_or(u32::MAX))
                .contains(&self.maximum_payout_outputs)
            || self.maximum_network_fee_bps == 0
            || self.maximum_network_fee_bps > 1_000
            || self.policy_version == 0
        {
            return Err(StoreError::InvalidChainPolicy);
        }
        Ok(())
    }
}

/// Receiver class attested by an authoritative chain address parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverKind {
    /// Public P2PKH/P2SH receiver.
    Transparent,
    /// Current shielded Ironwood receiver.
    Ironwood,
}

impl ReceiverKind {
    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "transparent" => Ok(Self::Transparent),
            "ironwood" => Ok(Self::Ironwood),
            _ => Err(StoreError::CorruptDatabaseState("payout receiver kind")),
        }
    }
}

/// Production readiness of payout-destination configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayoutConfigurationReadiness {
    /// No destination may be stored until Wolf and Zcash authoritative address
    /// decoders are composed into the portal adapter.
    DisabledMissingAuthoritativeValidators,
}

/// Portal-only credential row. Verifiers and sealed TOTP bytes must never be
/// serialized to a browser or debug log.
#[derive(Clone)]
pub struct AccountCredentialRecord {
    /// Stable account ID shared with mining attribution.
    pub id: Uuid,
    /// Canonical login.
    pub login: String,
    /// Argon2id portal-password verifier.
    pub password_verifier: String,
    /// Application-encrypted confirmed TOTP secret.
    pub totp_secret_sealed: Option<Vec<u8>>,
    /// Application-encrypted unconfirmed enrollment.
    pub totp_pending_sealed: Option<Vec<u8>>,
    /// Pending enrollment expiry as Unix seconds.
    pub totp_pending_expires_at: Option<u64>,
    /// Brute-force lock expiry as Unix seconds.
    pub locked_until: Option<u64>,
    /// Session invalidation fence.
    pub security_version: u64,
}

impl std::fmt::Debug for AccountCredentialRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountCredentialRecord")
            .field("id", &self.id)
            .field("login", &self.login)
            .field("password_verifier", &"[REDACTED]")
            .field(
                "totp_secret_sealed",
                &self.totp_secret_sealed.as_ref().map(|_| "[SEALED]"),
            )
            .field(
                "totp_pending_sealed",
                &self.totp_pending_sealed.as_ref().map(|_| "[SEALED]"),
            )
            .field("totp_pending_expires_at", &self.totp_pending_expires_at)
            .field("locked_until", &self.locked_until)
            .field("security_version", &self.security_version)
            .finish()
    }
}

/// Keyed-digest browser session to persist. Raw cookie and CSRF tokens never
/// cross this boundary.
pub struct NewPortalSessionRecord<'a> {
    /// Keyed session-token digest.
    pub token_digest: &'a [u8; 32],
    /// Keyed CSRF-token digest.
    pub csrf_digest: &'a [u8; 32],
    /// Owning account.
    pub account_id: Uuid,
    /// Account security fence captured after authentication.
    pub security_version: u64,
    /// Primary authentication time, Unix seconds.
    pub authenticated_at: u64,
    /// Second-factor authentication time, Unix seconds.
    pub second_factor_at: Option<u64>,
    /// Absolute expiry, Unix seconds.
    pub expires_at: u64,
    /// Sliding idle expiry, Unix seconds.
    pub idle_expires_at: u64,
}

/// Valid browser session returned after digest, expiry, and security-version
/// validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPortalSession {
    /// Owning account.
    pub account_id: Uuid,
    /// Canonical account login.
    pub login: String,
    /// Expected keyed CSRF digest.
    pub csrf_digest: [u8; 32],
    /// Primary authentication time as Unix seconds.
    pub authenticated_at: u64,
}

/// Whether a journal event was newly committed or was an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionResult {
    /// Event and every derived row were durably committed.
    Applied,
    /// The exact canonical payload was already committed at this cursor.
    Replayed,
}

/// Cloneable PostgreSQL authority for one immutable deployment.
#[derive(Clone, Debug)]
pub struct PostgresStore {
    pub(crate) pool: PgPool,
    pub(crate) identity: DeploymentIdentity,
}

impl PostgresStore {
    /// Opens a finite PostgreSQL pool. The caller should read the connection
    /// string from a protected credential file rather than argv or environment.
    pub async fn connect(
        database_url: &str,
        maximum_connections: u32,
        identity: DeploymentIdentity,
    ) -> Result<Self, StoreError> {
        identity.validate()?;
        if !(1..=MAX_DATABASE_CONNECTIONS).contains(&maximum_connections) {
            return Err(StoreError::InvalidConnectionLimit(maximum_connections));
        }
        let pool = PgPoolOptions::new()
            .max_connections(maximum_connections)
            .connect(database_url)
            .await?;
        Ok(Self { pool, identity })
    }

    /// Applies embedded, append-only schema migrations.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!().run(&self.pool).await?;
        Ok(())
    }

    /// Inserts this deployment once and rejects every later identity mismatch.
    pub async fn bind_deployment(&self) -> Result<(), StoreError> {
        let identity = &self.identity;
        sqlx::query(
            "INSERT INTO deployments \
             (id, network, wcash_genesis, zcash_genesis, chain_id, wcash_payout_commitment, \
              zcash_payout_commitment, backend_instance, journal_stream) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING",
        )
        .bind(identity.id)
        .bind(identity.network.as_str())
        .bind(identity.wcash_genesis.as_slice())
        .bind(identity.zcash_genesis.as_slice())
        .bind(i64::from(identity.chain_id))
        .bind(identity.wcash_payout_commitment.as_slice())
        .bind(identity.zcash_payout_commitment.as_slice())
        .bind(identity.backend_instance)
        .bind(identity.journal_stream)
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT network, wcash_genesis, zcash_genesis, chain_id, wcash_payout_commitment, \
                    zcash_payout_commitment, backend_instance, journal_stream \
             FROM deployments WHERE id=$1",
        )
        .bind(identity.id)
        .fetch_one(&self.pool)
        .await?;
        let matches = row.try_get::<String, _>("network")? == identity.network.as_str()
            && row.try_get::<Vec<u8>, _>("wcash_genesis")? == identity.wcash_genesis
            && row.try_get::<Vec<u8>, _>("zcash_genesis")? == identity.zcash_genesis
            && row.try_get::<i64, _>("chain_id")? == i64::from(identity.chain_id)
            && row.try_get::<Vec<u8>, _>("wcash_payout_commitment")?
                == identity.wcash_payout_commitment
            && row.try_get::<Vec<u8>, _>("zcash_payout_commitment")?
                == identity.zcash_payout_commitment
            && row.try_get::<Uuid, _>("backend_instance")? == identity.backend_instance
            && row.try_get::<Uuid, _>("journal_stream")? == identity.journal_stream;
        if !matches {
            return Err(StoreError::DeploymentIdentityMismatch);
        }
        sqlx::query(
            "INSERT INTO backend_cursors (deployment_id, last_event_seq) VALUES ($1,0) \
             ON CONFLICT (deployment_id) DO NOTHING",
        )
        .bind(identity.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the mandatory namespace for every adapter query.
    pub const fn deployment_id(&self) -> Uuid {
        self.identity.id
    }

    /// Creates a portal account with a separately generated Argon2id password
    /// verifier. Mining tokens are never valid here.
    pub async fn create_portal_account(
        &self,
        id: Uuid,
        login: &str,
        password_verifier: &str,
        created_at: u64,
    ) -> Result<(), StoreError> {
        if id.is_nil() || !validate_argon2id_verifier(password_verifier) {
            return Err(StoreError::InvalidPortalCredential);
        }
        validate_component(login, 64)?;
        sqlx::query(
            "INSERT INTO accounts \
             (deployment_id,id,login,password_verifier,created_at) \
             VALUES ($1,$2,$3,$4,to_timestamp($5))",
        )
        .bind(self.identity.id)
        .bind(id)
        .bind(login)
        .bind(password_verifier)
        .bind(unix_i64(created_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Loads secret account material only for the portal authentication layer.
    pub async fn portal_account_by_login(
        &self,
        login: &str,
    ) -> Result<Option<AccountCredentialRecord>, StoreError> {
        validate_component(login, 64)?;
        let row = sqlx::query(
            "SELECT id,login,password_verifier,totp_secret_sealed,totp_pending_sealed, \
                    EXTRACT(EPOCH FROM totp_pending_expires_at)::BIGINT AS totp_pending_expires_at, \
                    EXTRACT(EPOCH FROM locked_until)::BIGINT AS locked_until,security_version \
             FROM accounts WHERE deployment_id=$1 AND login=$2 AND enabled",
        )
        .bind(self.identity.id)
        .bind(login)
        .fetch_optional(&self.pool)
        .await?;
        row.map(account_credential_from_row).transpose()
    }

    /// Atomically records one failed known-account login and installs a bounded
    /// lock when the configured attempt count is reached.
    pub async fn record_failed_portal_login(
        &self,
        account_id: Uuid,
        maximum_attempts: u32,
        locked_until: u64,
    ) -> Result<(), StoreError> {
        if account_id.is_nil() || !(1..=100).contains(&maximum_attempts) {
            return Err(StoreError::InvalidPortalCredential);
        }
        let result = sqlx::query(
            "UPDATE accounts SET failed_login_attempts=failed_login_attempts+1, \
               locked_until=CASE WHEN failed_login_attempts+1 >= $3 \
                                 THEN to_timestamp($4) ELSE locked_until END \
             WHERE deployment_id=$1 AND id=$2 AND enabled",
        )
        .bind(self.identity.id)
        .bind(account_id)
        .bind(i32::try_from(maximum_attempts).map_err(|_| StoreError::InvalidPortalCredential)?)
        .bind(unix_i64(locked_until)?)
        .execute(&self.pool)
        .await?;
        exactly_one(result.rows_affected())
    }

    /// Clears temporary portal login failure state after complete authentication.
    pub async fn clear_failed_portal_login(&self, account_id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE accounts SET failed_login_attempts=0,locked_until=NULL \
             WHERE deployment_id=$1 AND id=$2 AND enabled",
        )
        .bind(self.identity.id)
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        exactly_one(result.rows_affected())
    }

    /// Persists only keyed browser-token and CSRF digests.
    pub async fn create_portal_session(
        &self,
        session: NewPortalSessionRecord<'_>,
    ) -> Result<(), StoreError> {
        if session.account_id.is_nil()
            || session.security_version == 0
            || session.authenticated_at >= session.expires_at
            || session.idle_expires_at > session.expires_at
        {
            return Err(StoreError::InvalidPortalSession);
        }
        sqlx::query(
            "INSERT INTO portal_sessions \
             (deployment_id,token_digest,csrf_digest,account_id,security_version,authenticated_at, \
              second_factor_at,expires_at,idle_expires_at) \
             VALUES ($1,$2,$3,$4,$5,to_timestamp($6),to_timestamp($7),to_timestamp($8),to_timestamp($9))",
        )
        .bind(self.identity.id)
        .bind(session.token_digest.as_slice())
        .bind(session.csrf_digest.as_slice())
        .bind(session.account_id)
        .bind(i64::try_from(session.security_version).map_err(|_| StoreError::InvalidPortalSession)?)
        .bind(unix_i64(session.authenticated_at)?)
        .bind(session.second_factor_at.map(unix_i64).transpose()?)
        .bind(unix_i64(session.expires_at)?)
        .bind(unix_i64(session.idle_expires_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Authenticates and refreshes one unexpired, security-version-bound session.
    pub async fn authenticate_portal_session(
        &self,
        token_digest: &[u8; 32],
        now: u64,
        new_idle_expiry: u64,
    ) -> Result<Option<AuthenticatedPortalSession>, StoreError> {
        if new_idle_expiry <= now {
            return Err(StoreError::InvalidPortalSession);
        }
        let row = sqlx::query(
            "UPDATE portal_sessions s SET idle_expires_at=LEAST(to_timestamp($4),s.expires_at) \
             FROM accounts a \
             WHERE s.deployment_id=$1 AND s.token_digest=$2 \
               AND (a.deployment_id,a.id)=(s.deployment_id,s.account_id) \
               AND a.enabled AND a.security_version=s.security_version \
               AND s.expires_at > to_timestamp($3) AND s.idle_expires_at > to_timestamp($3) \
             RETURNING s.account_id,a.login,s.csrf_digest, \
                       EXTRACT(EPOCH FROM s.authenticated_at)::BIGINT AS authenticated_at",
        )
        .bind(self.identity.id)
        .bind(token_digest.as_slice())
        .bind(unix_i64(now)?)
        .bind(unix_i64(new_idle_expiry)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let csrf = row.try_get::<Vec<u8>, _>("csrf_digest")?;
            Ok(AuthenticatedPortalSession {
                account_id: row.try_get("account_id")?,
                login: row.try_get("login")?,
                csrf_digest: csrf
                    .try_into()
                    .map_err(|_| StoreError::CorruptDatabaseState("CSRF digest"))?,
                authenticated_at: unix_u64(row.try_get("authenticated_at")?)?,
            })
        })
        .transpose()
    }

    /// Deletes one exact browser session digest.
    pub async fn delete_portal_session(&self, token_digest: &[u8; 32]) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM portal_sessions WHERE deployment_id=$1 AND token_digest=$2")
            .bind(self.identity.id)
            .bind(token_digest.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revokes all browser sessions for an account.
    pub async fn delete_account_sessions(&self, account_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM portal_sessions WHERE deployment_id=$1 AND account_id=$2")
            .bind(self.identity.id)
            .bind(account_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stores an application-encrypted, expiring TOTP enrollment value.
    pub async fn save_pending_totp(
        &self,
        account_id: Uuid,
        sealed_secret: &[u8],
        expires_at: u64,
    ) -> Result<(), StoreError> {
        if sealed_secret.is_empty() || sealed_secret.len() > 4_096 {
            return Err(StoreError::InvalidPortalCredential);
        }
        let result = sqlx::query(
            "UPDATE accounts SET totp_pending_sealed=$3,totp_pending_expires_at=to_timestamp($4) \
             WHERE deployment_id=$1 AND id=$2 AND enabled",
        )
        .bind(self.identity.id)
        .bind(account_id)
        .bind(sealed_secret)
        .bind(unix_i64(expires_at)?)
        .execute(&self.pool)
        .await?;
        exactly_one(result.rows_affected())
    }

    /// Activates a non-expired TOTP enrollment, fences existing sessions, and
    /// returns false when the enrollment expired or did not exist.
    pub async fn activate_pending_totp(
        &self,
        account_id: Uuid,
        now: u64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE accounts SET totp_secret_sealed=totp_pending_sealed, \
               totp_pending_sealed=NULL,totp_pending_expires_at=NULL, \
               security_version=security_version+1 \
             WHERE deployment_id=$1 AND id=$2 AND enabled \
               AND totp_pending_sealed IS NOT NULL AND totp_pending_expires_at > to_timestamp($3)",
        )
        .bind(self.identity.id)
        .bind(account_id)
        .bind(unix_i64(now)?)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 1 {
            sqlx::query("DELETE FROM portal_sessions WHERE deployment_id=$1 AND account_id=$2")
                .bind(self.identity.id)
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            Ok(true)
        } else {
            transaction.rollback().await?;
            Ok(false)
        }
    }

    /// Returns the last completely projected Wolf cursor.
    pub async fn last_event_seq(&self) -> Result<u64, StoreError> {
        let cursor = sqlx::query_scalar::<_, i64>(
            "SELECT last_event_seq FROM backend_cursors WHERE deployment_id=$1",
        )
        .bind(self.identity.id)
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(cursor).map_err(|_| StoreError::CorruptDatabaseState("event cursor"))
    }

    /// Binds immutable launch accounting policy. Repeating the exact policy is
    /// idempotent; changing it requires a future audited policy-change path.
    pub async fn bind_chain_policy(&self, policy: &ChainPolicy) -> Result<(), StoreError> {
        policy.validate()?;
        sqlx::query(
            "INSERT INTO chain_policies \
             (deployment_id,chain,pplns_window_work,fee_bps,payout_threshold_zat,required_confirmations, \
              maximum_payout_outputs,maximum_network_fee_zat,maximum_network_fee_bps,policy_version) \
             VALUES ($1,$2,CAST($3 AS NUMERIC),$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
        )
        .bind(self.identity.id)
        .bind(policy.chain.as_str())
        .bind(policy.pplns_window_work.to_string())
        .bind(i32::from(policy.fee_bps))
        .bind(as_i64(policy.payout_threshold_zat)?)
        .bind(i32::try_from(policy.required_confirmations).map_err(|_| StoreError::InvalidChainPolicy)?)
        .bind(i32::try_from(policy.maximum_payout_outputs).map_err(|_| StoreError::InvalidChainPolicy)?)
        .bind(as_i64(policy.maximum_network_fee_zat)?)
        .bind(i32::from(policy.maximum_network_fee_bps))
        .bind(i64::try_from(policy.policy_version).map_err(|_| StoreError::InvalidChainPolicy)?)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO chain_safety_state (deployment_id,chain) VALUES ($1,$2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(self.identity.id)
        .bind(policy.chain.as_str())
        .execute(&self.pool)
        .await?;
        if self.chain_policy(policy.chain).await?.as_ref() == Some(policy) {
            Ok(())
        } else {
            Err(StoreError::ChainPolicyMismatch)
        }
    }

    /// Binds both launch chains with an explicit zero-fee policy.
    pub async fn bind_zero_fee_launch_policies(
        &self,
        wcash: &ChainPolicy,
        zcash: &ChainPolicy,
    ) -> Result<(), StoreError> {
        if wcash.chain != Chain::Wcash
            || zcash.chain != Chain::Zcash
            || wcash.fee_bps != 0
            || zcash.fee_bps != 0
        {
            return Err(StoreError::NonZeroLaunchFee);
        }
        let mut transaction = self.pool.begin().await?;
        for policy in [wcash, zcash] {
            policy.validate()?;
            sqlx::query(
                "INSERT INTO chain_policies \
                 (deployment_id,chain,pplns_window_work,fee_bps,payout_threshold_zat,required_confirmations, \
                  maximum_payout_outputs,maximum_network_fee_zat,maximum_network_fee_bps,policy_version) \
                 VALUES ($1,$2,CAST($3 AS NUMERIC),0,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
            )
            .bind(self.identity.id)
            .bind(policy.chain.as_str())
            .bind(policy.pplns_window_work.to_string())
            .bind(as_i64(policy.payout_threshold_zat)?)
            .bind(i32::try_from(policy.required_confirmations).map_err(|_| StoreError::InvalidChainPolicy)?)
            .bind(i32::try_from(policy.maximum_payout_outputs).map_err(|_| StoreError::InvalidChainPolicy)?)
            .bind(as_i64(policy.maximum_network_fee_zat)?)
            .bind(i32::from(policy.maximum_network_fee_bps))
            .bind(i64::try_from(policy.policy_version).map_err(|_| StoreError::InvalidChainPolicy)?)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO chain_safety_state (deployment_id,chain) VALUES ($1,$2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(self.identity.id)
            .bind(policy.chain.as_str())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        for policy in [wcash, zcash] {
            if self.chain_policy(policy.chain).await?.as_ref() != Some(policy) {
                return Err(StoreError::ChainPolicyMismatch);
            }
        }
        Ok(())
    }

    /// Returns public policy state for the miner UI and payout engine.
    pub async fn chain_policy(&self, chain: Chain) -> Result<Option<ChainPolicy>, StoreError> {
        let row = sqlx::query(
            "SELECT pplns_window_work::TEXT AS pplns_window_work,fee_bps,\
                    payout_threshold_zat,required_confirmations,maximum_payout_outputs, \
                    maximum_network_fee_zat,maximum_network_fee_bps,policy_version \
             FROM chain_policies WHERE deployment_id=$1 AND chain=$2",
        )
        .bind(self.identity.id)
        .bind(chain.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let policy = ChainPolicy {
                chain,
                pplns_window_work: BigUint::from_str(
                    &row.try_get::<String, _>("pplns_window_work")?,
                )
                .map_err(|_| StoreError::CorruptDatabaseState("PPLNS work window"))?,
                fee_bps: u16::try_from(row.try_get::<i32, _>("fee_bps")?)
                    .map_err(|_| StoreError::CorruptDatabaseState("pool fee"))?,
                payout_threshold_zat: u64::try_from(row.try_get::<i64, _>("payout_threshold_zat")?)
                    .map_err(|_| StoreError::CorruptDatabaseState("payout threshold"))?,
                required_confirmations: u32::try_from(
                    row.try_get::<i32, _>("required_confirmations")?,
                )
                .map_err(|_| StoreError::CorruptDatabaseState("required confirmations"))?,
                maximum_payout_outputs: u32::try_from(
                    row.try_get::<i32, _>("maximum_payout_outputs")?,
                )
                .map_err(|_| StoreError::CorruptDatabaseState("maximum payout outputs"))?,
                maximum_network_fee_zat: u64::try_from(
                    row.try_get::<i64, _>("maximum_network_fee_zat")?,
                )
                .map_err(|_| StoreError::CorruptDatabaseState("maximum network fee"))?,
                maximum_network_fee_bps: u16::try_from(
                    row.try_get::<i32, _>("maximum_network_fee_bps")?,
                )
                .map_err(|_| StoreError::CorruptDatabaseState("maximum network fee rate"))?,
                policy_version: u64::try_from(row.try_get::<i64, _>("policy_version")?)
                    .map_err(|_| StoreError::CorruptDatabaseState("policy version"))?,
            };
            policy.validate()?;
            Ok(policy)
        })
        .transpose()
    }

    /// Checks a backend connection against the persisted network, collector, and
    /// journal authority before accepting an event.
    pub fn verify_authority(&self, authority: &BackendAuthority) -> Result<(), StoreError> {
        if self.identity.matches_authority(authority) {
            Ok(())
        } else {
            Err(StoreError::BackendAuthorityMismatch)
        }
    }

    /// Provisions an account, worker, and one revocable mining-only token.
    /// Existing identities are never overwritten.
    pub async fn provision_worker(
        &self,
        account_login: &str,
        worker_label: &str,
    ) -> Result<(Uuid, Uuid, MiningToken), StoreError> {
        validate_component(account_login, 64)?;
        validate_component(worker_label, 63)?;
        let account_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let canonical_login = format!("{account_login}.{worker_label}");
        let token = generate_mining_token()?;
        let verifier = hash_mining_token(&token)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,$3)")
            .bind(self.identity.id)
            .bind(account_id)
            .bind(account_login)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO workers (deployment_id,id,account_id,label,canonical_login) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(self.identity.id)
        .bind(worker_id)
        .bind(account_id)
        .bind(worker_label)
        .bind(canonical_login)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO mining_tokens (deployment_id,id,worker_id,verifier) VALUES ($1,$2,$3,$4)",
        )
        .bind(self.identity.id)
        .bind(token.id())
        .bind(worker_id)
        .bind(verifier)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok((account_id, worker_id, token))
    }

    /// Adds a worker to an existing portal account and returns its mining token
    /// exactly once. The supplied login must still match the owned account row.
    pub async fn provision_worker_for_account(
        &self,
        account_id: Uuid,
        account_login: &str,
        worker_label: &str,
    ) -> Result<(Uuid, MiningToken), StoreError> {
        validate_component(account_login, 64)?;
        validate_component(worker_label, 63)?;
        let worker_id = Uuid::new_v4();
        let canonical_login = format!("{account_login}.{worker_label}");
        let token = generate_mining_token()?;
        let verifier = hash_mining_token(&token)?;
        let mut transaction = self.pool.begin().await?;
        let persisted_login = sqlx::query_scalar::<_, String>(
            "SELECT login FROM accounts WHERE deployment_id=$1 AND id=$2 AND enabled FOR UPDATE",
        )
        .bind(self.identity.id)
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::UnknownAccount)?;
        if persisted_login != account_login {
            return Err(StoreError::AccountOwnershipMismatch);
        }
        sqlx::query(
            "INSERT INTO workers (deployment_id,id,account_id,label,canonical_login) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(self.identity.id)
        .bind(worker_id)
        .bind(account_id)
        .bind(worker_label)
        .bind(canonical_login)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO mining_tokens (deployment_id,id,worker_id,verifier) VALUES ($1,$2,$3,$4)",
        )
        .bind(self.identity.id)
        .bind(token.id())
        .bind(worker_id)
        .bind(verifier)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok((worker_id, token))
    }

    /// Disables one worker and revokes all of its mining tokens atomically.
    pub async fn revoke_worker(
        &self,
        account_id: Uuid,
        worker_id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE workers SET enabled=FALSE,revoked_at=clock_timestamp() \
             WHERE deployment_id=$1 AND id=$2 AND account_id=$3 AND enabled",
        )
        .bind(self.identity.id)
        .bind(worker_id)
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 1 {
            sqlx::query(
                "UPDATE mining_tokens SET revoked_at=clock_timestamp() \
                 WHERE deployment_id=$1 AND worker_id=$2 AND revoked_at IS NULL",
            )
            .bind(self.identity.id)
            .bind(worker_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(true)
        } else {
            transaction.rollback().await?;
            Ok(false)
        }
    }

    /// Revokes a token without revealing or changing its verifier.
    pub async fn revoke_mining_token(&self, token_id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE mining_tokens SET revoked_at=clock_timestamp() \
             WHERE deployment_id=$1 AND id=$2 AND revoked_at IS NULL",
        )
        .bind(self.identity.id)
        .bind(token_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Reports the explicit fail-closed destination boundary for this milestone.
    /// Pool and portal readiness must remain false while this value is returned.
    pub const fn payout_configuration_readiness(&self) -> PayoutConfigurationReadiness {
        PayoutConfigurationReadiness::DisabledMissingAuthoritativeValidators
    }

    /// Activates every elapsed replacement hold for one chain. The active row is
    /// switched in the same transaction, so payout selection sees one version.
    pub async fn activate_due_payout_destinations(
        &self,
        chain: Chain,
        now: u64,
    ) -> Result<u64, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let pending = sqlx::query(
            "SELECT id,account_id FROM payout_destinations \
             WHERE deployment_id=$1 AND chain=$2 AND state='pending' \
               AND active_after <= to_timestamp($3) FOR UPDATE",
        )
        .bind(self.identity.id)
        .bind(chain.as_str())
        .bind(unix_i64(now)?)
        .fetch_all(&mut *transaction)
        .await?;
        for row in &pending {
            let account_id = row.try_get::<Uuid, _>("account_id")?;
            sqlx::query(
                "UPDATE payout_destinations SET state='disabled',disabled_at=to_timestamp($4) \
                 WHERE deployment_id=$1 AND account_id=$2 AND chain=$3 AND state='active'",
            )
            .bind(self.identity.id)
            .bind(account_id)
            .bind(chain.as_str())
            .bind(unix_i64(now)?)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE payout_destinations SET state='active' \
                 WHERE deployment_id=$1 AND id=$2 AND state='pending'",
            )
            .bind(self.identity.id)
            .bind(row.try_get::<Uuid, _>("id")?)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        u64::try_from(pending.len()).map_err(|_| StoreError::MoneyOverflow)
    }

    /// Records one short-lived, chain-specific wallet reconciliation. The
    /// ledger root and checkpoint UUID are always derived inside this store.
    /// A mismatch is committed as durable evidence and freezes new payouts.
    pub async fn record_wallet_reconciliation(
        &self,
        observation: &WalletObservation,
    ) -> Result<WalletReconciliation, StoreError> {
        if observation.wallet_state_digest == [0; 32]
            || observation.best_tip_hash == [0; 32]
            || observation.best_tip_height == 0
            || observation.observed_at == 0
            || observation.valid_until <= observation.observed_at
            || observation
                .valid_until
                .saturating_sub(observation.observed_at)
                > MAX_WALLET_RECONCILIATION_AGE_SECS
        {
            return Err(StoreError::InvalidWalletObservation);
        }

        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        let lock_key = format!("zecwec:{}:{}", self.identity.id, observation.chain.as_str());
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT payouts_frozen FROM chain_safety_state \
             WHERE deployment_id=$1 AND chain=$2 FOR UPDATE",
        )
        .bind(self.identity.id)
        .bind(observation.chain.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::MissingChainPolicy(observation.chain))?;

        let database_now = unix_u64(
            sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT")
                .fetch_one(&mut *transaction)
                .await?,
        )?;
        if observation.observed_at > database_now
            || database_now.saturating_sub(observation.observed_at)
                > MAX_WALLET_RECONCILIATION_AGE_SECS
            || observation.valid_until <= database_now
        {
            return Err(StoreError::InvalidWalletObservation);
        }

        let has_ambiguous_payout = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM payout_batches \
             WHERE deployment_id=$1 AND chain=$2 \
               AND state IN ('signed','broadcast','reorged'))",
        )
        .bind(self.identity.id)
        .bind(observation.chain.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        if has_ambiguous_payout {
            return Err(StoreError::WalletReconciliationBlocked);
        }

        let snapshot =
            ledger_snapshot(&mut transaction, self.identity.id, observation.chain, None).await?;
        let checkpoint_id = Uuid::new_v4();
        let matched = snapshot.collector_spendable_zat == observation.wallet_spendable_zat;
        sqlx::query(
            "INSERT INTO wallet_reconciliations \
             (deployment_id,id,chain,ledger_root,ledger_transaction_count,wallet_state_digest, \
              wallet_spendable_zat,ledger_spendable_zat,best_tip_hash,best_tip_height, \
              observed_at,valid_until,status) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,to_timestamp($11),to_timestamp($12),$13)",
        )
        .bind(self.identity.id)
        .bind(checkpoint_id)
        .bind(observation.chain.as_str())
        .bind(snapshot.root.as_slice())
        .bind(as_i64(snapshot.transaction_count)?)
        .bind(observation.wallet_state_digest.as_slice())
        .bind(as_i64(observation.wallet_spendable_zat)?)
        .bind(as_i64(snapshot.collector_spendable_zat)?)
        .bind(observation.best_tip_hash.as_slice())
        .bind(i64::from(observation.best_tip_height))
        .bind(unix_i64(observation.observed_at)?)
        .bind(unix_i64(observation.valid_until)?)
        .bind(if matched { "matched" } else { "mismatch" })
        .execute(&mut *transaction)
        .await?;

        if !matched {
            sqlx::query(
                "UPDATE chain_safety_state SET payouts_frozen=TRUE, \
                 frozen_by_backend_event_seq=CASE WHEN payouts_frozen \
                     THEN frozen_by_backend_event_seq ELSE NULL END, \
                 freeze_reason=CASE WHEN payouts_frozen THEN freeze_reason \
                     ELSE 'wallet_reconciliation_mismatch' END, \
                 updated_at=clock_timestamp() WHERE deployment_id=$1 AND chain=$2",
            )
            .bind(self.identity.id)
            .bind(observation.chain.as_str())
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Err(StoreError::CollectorReconciliationFailed);
        }

        transaction.commit().await?;
        Ok(WalletReconciliation {
            id: checkpoint_id,
            chain: observation.chain,
            ledger_root: snapshot.root,
            ledger_transaction_count: snapshot.transaction_count,
            wallet_spendable_zat: observation.wallet_spendable_zat,
            best_tip_hash: observation.best_tip_hash,
            best_tip_height: observation.best_tip_height,
            observed_at: observation.observed_at,
            valid_until: observation.valid_until,
        })
    }

    /// Reserves all automatic balances at or above their versioned threshold.
    /// A chain-scoped PostgreSQL advisory lock serializes concurrent builders.
    pub async fn create_payout_batch(
        &self,
        chain: Chain,
        idempotency_key: Uuid,
        reconciliation_id: Uuid,
    ) -> Result<PayoutBatch, StoreError> {
        if idempotency_key.is_nil() || reconciliation_id.is_nil() {
            return Err(StoreError::InvalidPayoutBatch);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        let lock_key = format!("zecwec:{}:{}", self.identity.id, chain.as_str());
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .execute(&mut *transaction)
            .await?;
        if let Some(batch_id) = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM payout_batches WHERE deployment_id=$1 AND idempotency_key=$2",
        )
        .bind(self.identity.id)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let batch = load_payout_batch(&mut transaction, self.identity.id, batch_id).await?;
            if batch.chain != chain || batch.reconciliation_id != reconciliation_id {
                return Err(StoreError::PayoutIdempotencyConflict);
            }
            transaction.rollback().await?;
            return Ok(batch);
        }
        lock_unfrozen_chain(&mut transaction, self.identity.id, chain).await?;
        let checkpoint = load_usable_wallet_reconciliation(
            &mut transaction,
            self.identity.id,
            chain,
            reconciliation_id,
        )
        .await?;
        let current_snapshot =
            ledger_snapshot(&mut transaction, self.identity.id, chain, None).await?;
        if checkpoint.ledger_root != current_snapshot.root
            || checkpoint.ledger_transaction_count != current_snapshot.transaction_count
            || checkpoint.wallet_spendable_zat != current_snapshot.collector_spendable_zat
        {
            return Err(StoreError::WalletReconciliationStale);
        }
        let policy = sqlx::query(
            "SELECT maximum_payout_outputs,policy_version FROM chain_policies \
             WHERE deployment_id=$1 AND chain=$2 FOR SHARE",
        )
        .bind(self.identity.id)
        .bind(chain.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::MissingChainPolicy(chain))?;
        let maximum_outputs = policy.try_get::<i32, _>("maximum_payout_outputs")?;
        let policy_version = u64::try_from(policy.try_get::<i64, _>("policy_version")?)
            .map_err(|_| StoreError::CorruptDatabaseState("policy version"))?;
        let rows = sqlx::query(
            "SELECT e.account_id,(-SUM(e.amount_zat))::BIGINT AS amount_zat, \
                    d.id AS destination_id,d.address,d.receiver_kind \
             FROM ledger_entries e \
             JOIN ledger_transactions t \
               ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
             JOIN payout_destinations d \
               ON (d.deployment_id,d.account_id)=(e.deployment_id,e.account_id) \
              AND d.chain=$2 AND d.state='active' AND d.automatic \
             WHERE e.deployment_id=$1 AND t.chain=$2 \
               AND e.ledger_account='miner_payable' \
             GROUP BY e.account_id,d.id,d.address,d.receiver_kind,d.payout_threshold_zat \
             HAVING -SUM(e.amount_zat) >= d.payout_threshold_zat \
             ORDER BY e.account_id LIMIT $3",
        )
        .bind(self.identity.id)
        .bind(chain.as_str())
        .bind(maximum_outputs)
        .fetch_all(&mut *transaction)
        .await?;
        if rows.is_empty() {
            return Err(StoreError::NoPayableBalances);
        }
        let mut outputs = Vec::with_capacity(rows.len());
        let mut total = 0u64;
        for row in rows {
            let amount_zat = u64::try_from(row.try_get::<i64, _>("amount_zat")?)
                .map_err(|_| StoreError::MoneyOverflow)?;
            total = total
                .checked_add(amount_zat)
                .ok_or(StoreError::MoneyOverflow)?;
            outputs.push(PayoutInstruction {
                allocation_id: Uuid::new_v4(),
                account_id: row.try_get("account_id")?,
                destination_id: row.try_get("destination_id")?,
                receiver_kind: ReceiverKind::parse(&row.try_get::<String, _>("receiver_kind")?)?,
                address: row.try_get("address")?,
                amount_zat,
            });
        }
        let batch_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO payout_batches \
             (deployment_id,id,chain,policy_version,idempotency_key,state) \
             VALUES ($1,$2,$3,$4,$5,'draft')",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .bind(chain.as_str())
        .bind(i64::try_from(policy_version).map_err(|_| StoreError::InvalidChainPolicy)?)
        .bind(idempotency_key)
        .execute(&mut *transaction)
        .await?;
        let mut entries = Vec::with_capacity(outputs.len() * 2);
        for output in &outputs {
            sqlx::query(
                "INSERT INTO payout_items \
                 (deployment_id,batch_id,account_id,destination_id,amount_zat,allocation_id) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(self.identity.id)
            .bind(batch_id)
            .bind(output.account_id)
            .bind(output.destination_id)
            .bind(as_i64(output.amount_zat)?)
            .bind(output.allocation_id)
            .execute(&mut *transaction)
            .await?;
            entries.push((
                Some(output.account_id),
                "miner_payable".to_owned(),
                as_i64(output.amount_zat)?,
            ));
            entries.push((
                Some(output.account_id),
                "payout_pending".to_owned(),
                -as_i64(output.amount_zat)?,
            ));
        }
        let reservation_transaction_id = insert_owned_ledger_transaction(
            &mut transaction,
            self.identity.id,
            chain,
            "payout_reserved",
            None,
            &batch_id.to_string(),
            &entries,
        )
        .await?;
        let ledger_sequence_cutoff = u64::try_from(
            sqlx::query_scalar::<_, i64>(
                "SELECT ledger_sequence FROM ledger_transactions \
                 WHERE deployment_id=$1 AND id=$2",
            )
            .bind(self.identity.id)
            .bind(reservation_transaction_id)
            .fetch_one(&mut *transaction)
            .await?,
        )
        .map_err(|_| StoreError::CorruptDatabaseState("ledger sequence"))?;
        let post_reservation_snapshot = ledger_snapshot(
            &mut transaction,
            self.identity.id,
            chain,
            Some(ledger_sequence_cutoff),
        )
        .await?;
        let updated = sqlx::query(
            "UPDATE payout_batches SET reconciliation_id=$3,ledger_root=$4,ledger_sequence_cutoff=$5 \
             WHERE deployment_id=$1 AND id=$2 AND state='draft'",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .bind(reconciliation_id)
        .bind(post_reservation_snapshot.root.as_slice())
        .bind(as_i64(ledger_sequence_cutoff)?)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::InvalidPayoutBatch);
        }
        transaction.commit().await?;
        Ok(PayoutBatch {
            id: batch_id,
            chain,
            state: PayoutBatchState::Draft,
            policy_version,
            reconciliation_id,
            ledger_root: post_reservation_snapshot.root,
            ledger_sequence_cutoff,
            miner_total_zat: total,
            outputs,
        })
    }

    /// Constructs the exact signer request from immutable database facts. No
    /// caller can inject a reconciliation UUID, ledger root, receiver class,
    /// address, or amount.
    pub async fn build_signer_request(
        &self,
        batch_id: Uuid,
    ) -> Result<PayoutBatchRequest, StoreError> {
        if batch_id.is_nil() {
            return Err(StoreError::InvalidPayoutBatch);
        }
        let mut transaction = self.pool.begin().await?;
        let batch = load_payout_batch(&mut transaction, self.identity.id, batch_id).await?;
        if batch.state != PayoutBatchState::Draft {
            return Err(StoreError::InvalidPayoutTransition);
        }
        lock_unfrozen_chain(&mut transaction, self.identity.id, batch.chain).await?;
        load_usable_wallet_reconciliation(
            &mut transaction,
            self.identity.id,
            batch.chain,
            batch.reconciliation_id,
        )
        .await?;
        let derived_snapshot = ledger_snapshot(
            &mut transaction,
            self.identity.id,
            batch.chain,
            Some(batch.ledger_sequence_cutoff),
        )
        .await?;
        if derived_snapshot.root != batch.ledger_root {
            return Err(StoreError::WalletReconciliationStale);
        }
        let reservation_matches = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ledger_transactions \
             WHERE deployment_id=$1 AND ledger_sequence=$2 AND chain=$3 \
               AND kind='payout_reserved' AND reference=$4)",
        )
        .bind(self.identity.id)
        .bind(as_i64(batch.ledger_sequence_cutoff)?)
        .bind(batch.chain.as_str())
        .bind(batch.id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if !reservation_matches {
            return Err(StoreError::CorruptDatabaseState(
                "payout ledger sequence fence",
            ));
        }
        let request = PayoutBatchRequest {
            batch_id: batch.id,
            asset: asset_for_chain(batch.chain),
            network: network_for_deployment(self.identity.network),
            ledger_root: batch.ledger_root,
            reconciliation_id: batch.reconciliation_id,
            outputs: batch
                .outputs
                .into_iter()
                .map(|output| PayoutOutput {
                    allocation_id: output.allocation_id,
                    canonical_address: output.address,
                    receiver_kind: portal_receiver_kind(output.receiver_kind),
                    amount_zat: output.amount_zat,
                })
                .collect(),
        };
        request
            .validate()
            .map_err(|_| StoreError::CorruptDatabaseState("payout signer request"))?;
        transaction.rollback().await?;
        Ok(request)
    }

    /// Records the isolated signer's exact unsigned digest, transaction ID,
    /// signed transaction bytes, and network fee. The wallet boundary must parse
    /// and match every frozen output before calling this transition.
    pub async fn mark_payout_signed(
        &self,
        batch_id: Uuid,
        unsigned_digest: &[u8; 32],
        transaction_id: &[u8; 32],
        signed_transaction: &[u8],
        network_fee_zat: u64,
    ) -> Result<(), StoreError> {
        if unsigned_digest == &[0; 32]
            || transaction_id == &[0; 32]
            || signed_transaction.is_empty()
            || signed_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES
        {
            return Err(StoreError::InvalidPayoutBatch);
        }
        transition_payout(
            &self.pool,
            self.identity.id,
            batch_id,
            PayoutBatchState::Draft,
            PayoutBatchState::Signed,
            Some(SignedTransitionFacts {
                unsigned_digest,
                transaction_id,
                signed_transaction,
                network_fee_zat,
            }),
        )
        .await
    }

    /// Marks the exact signed transaction as handed to the chain broadcaster.
    pub async fn mark_payout_broadcast(&self, batch_id: Uuid) -> Result<(), StoreError> {
        transition_payout(
            &self.pool,
            self.identity.id,
            batch_id,
            PayoutBatchState::Signed,
            PayoutBatchState::Broadcast,
            None,
        )
        .await
    }

    /// Loads the exact signed artifact needed to reconcile or safely retry a
    /// broadcaster after a process crash. Draft and cancelled batches have no
    /// signed artifact and return `None`.
    pub async fn signed_payout_artifact(
        &self,
        batch_id: Uuid,
    ) -> Result<Option<SignedPayoutArtifact>, StoreError> {
        let row = sqlx::query(
            "SELECT chain,state,unsigned_digest,transaction_id,signed_transaction,network_fee_zat \
             FROM payout_batches WHERE deployment_id=$1 AND id=$2",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::UnknownPayoutBatch)?;
        let state = PayoutBatchState::parse(&row.try_get::<String, _>("state")?)?;
        if matches!(state, PayoutBatchState::Draft | PayoutBatchState::Cancelled) {
            return Ok(None);
        }
        let unsigned_digest = exact_digest(
            row.try_get::<Option<Vec<u8>>, _>("unsigned_digest")?,
            "unsigned payout digest",
        )?;
        let transaction_id = exact_digest(
            row.try_get::<Option<Vec<u8>>, _>("transaction_id")?,
            "payout transaction ID",
        )?;
        let signed_transaction = row
            .try_get::<Option<Vec<u8>>, _>("signed_transaction")?
            .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_SIGNED_TRANSACTION_BYTES)
            .ok_or(StoreError::CorruptDatabaseState(
                "signed payout transaction",
            ))?;
        let network_fee_zat = u64::try_from(
            row.try_get::<Option<i64>, _>("network_fee_zat")?
                .ok_or(StoreError::CorruptDatabaseState("payout network fee"))?,
        )
        .map_err(|_| StoreError::CorruptDatabaseState("payout network fee"))?;
        Ok(Some(SignedPayoutArtifact {
            batch_id,
            chain: Chain::parse(&row.try_get::<String, _>("chain")?)?,
            state,
            unsigned_digest,
            transaction_id,
            signed_transaction,
            network_fee_zat,
        }))
    }

    /// Enumerates incomplete batches after an orchestrator restart. Rows are
    /// ordered by creation and identity; every subsequent transition remains
    /// transactionally idempotent, so losing an in-memory batch ID cannot lose
    /// or duplicate liabilities.
    pub async fn list_resumable_payout_batches(
        &self,
        chain: Chain,
        maximum: u32,
    ) -> Result<Vec<PayoutBatch>, StoreError> {
        if !(1..=1_000).contains(&maximum) {
            return Err(StoreError::InvalidPayoutBatch);
        }
        let mut transaction = self.pool.begin().await?;
        let ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM payout_batches \
             WHERE deployment_id=$1 AND chain=$2 AND state IN ('draft','signed','broadcast','reorged') \
             ORDER BY created_at,id LIMIT $3",
        )
        .bind(self.identity.id)
        .bind(chain.as_str())
        .bind(i64::from(maximum))
        .fetch_all(&mut *transaction)
        .await?;
        let mut batches = Vec::with_capacity(ids.len());
        for id in ids {
            batches.push(load_payout_batch(&mut transaction, self.identity.id, id).await?);
        }
        transaction.commit().await?;
        Ok(batches)
    }

    /// Confirms a broadcast payout with exact best-chain evidence and removes
    /// its miner liabilities and wallet asset with an explicit pool-paid fee.
    pub async fn confirm_payout(
        &self,
        batch_id: Uuid,
        confirmation: &PayoutConfirmation,
    ) -> Result<(), StoreError> {
        confirmation.validate()?;
        let mut transaction = self.pool.begin().await?;
        let batch = load_payout_batch(&mut transaction, self.identity.id, batch_id).await?;
        if batch.state == PayoutBatchState::Confirmed {
            let row = sqlx::query(
                "SELECT confirmation_block_hash,confirmation_height,confirmation_count \
                 FROM payout_batches WHERE deployment_id=$1 AND id=$2",
            )
            .bind(self.identity.id)
            .bind(batch_id)
            .fetch_one(&mut *transaction)
            .await?;
            let replay_matches = row.try_get::<Vec<u8>, _>("confirmation_block_hash")?
                == confirmation.block_hash
                && row.try_get::<i64, _>("confirmation_height")?
                    == i64::from(confirmation.block_height)
                && row.try_get::<i32, _>("confirmation_count")?
                    == i32::try_from(confirmation.confirmations)
                        .map_err(|_| StoreError::InvalidPayoutConfirmation)?;
            transaction.rollback().await?;
            return if replay_matches {
                Ok(())
            } else {
                Err(StoreError::PayoutReplayConflict)
            };
        }
        if batch.state != PayoutBatchState::Broadcast {
            return Err(StoreError::InvalidPayoutTransition);
        }
        let required_confirmations = sqlx::query_scalar::<_, i32>(
            "SELECT required_confirmations FROM chain_policies \
             WHERE deployment_id=$1 AND chain=$2 AND policy_version=$3",
        )
        .bind(self.identity.id)
        .bind(batch.chain.as_str())
        .bind(i64::try_from(batch.policy_version).map_err(|_| StoreError::InvalidChainPolicy)?)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::CorruptDatabaseState("payout policy"))?;
        let required_confirmations = u32::try_from(required_confirmations)
            .map_err(|_| StoreError::CorruptDatabaseState("required confirmations"))?;
        if confirmation.confirmations < required_confirmations {
            return Err(StoreError::PrematurePayoutConfirmation {
                required: required_confirmations,
                actual: confirmation.confirmations,
            });
        }
        let fee = sqlx::query_scalar::<_, i64>(
            "SELECT network_fee_zat FROM payout_batches WHERE deployment_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .fetch_one(&mut *transaction)
        .await?;
        let fee = u64::try_from(fee).map_err(|_| StoreError::MoneyOverflow)?;
        let total_asset = batch
            .miner_total_zat
            .checked_add(fee)
            .ok_or(StoreError::MoneyOverflow)?;
        let available_asset = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(SUM(amount_zat),0)::BIGINT FROM ledger_entries e \
             JOIN ledger_transactions t ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
             WHERE e.deployment_id=$1 AND t.chain=$2 \
               AND e.ledger_account='collector_spendable_asset'",
        )
        .bind(self.identity.id)
        .bind(batch.chain.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        let outstanding_liabilities = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(-SUM(e.amount_zat),0)::BIGINT FROM ledger_entries e \
             JOIN ledger_transactions t ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
             WHERE e.deployment_id=$1 AND t.chain=$2 \
               AND e.ledger_account IN ('miner_payable','payout_pending')",
        )
        .bind(self.identity.id)
        .bind(batch.chain.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        let required_asset = outstanding_liabilities
            .checked_add(as_i64(fee)?)
            .ok_or(StoreError::MoneyOverflow)?;
        if outstanding_liabilities < 0
            || available_asset < required_asset
            || available_asset < as_i64(total_asset)?
        {
            return Err(StoreError::CollectorReconciliationFailed);
        }
        let mut entries = Vec::with_capacity(batch.outputs.len() + 2);
        for output in &batch.outputs {
            entries.push((
                Some(output.account_id),
                "payout_pending".to_owned(),
                as_i64(output.amount_zat)?,
            ));
        }
        if fee > 0 {
            entries.push((None, "network_fee_expense".to_owned(), as_i64(fee)?));
        }
        entries.push((
            None,
            "collector_spendable_asset".to_owned(),
            -as_i64(total_asset)?,
        ));
        insert_owned_ledger_transaction(
            &mut transaction,
            self.identity.id,
            batch.chain,
            "payout_confirmed",
            None,
            &batch_id.to_string(),
            &entries,
        )
        .await?;
        let state = sqlx::query(
            "UPDATE payout_batches SET state='confirmed',confirmation_block_hash=$4, \
             confirmation_height=$5,confirmation_count=$6,updated_at=clock_timestamp() \
             WHERE deployment_id=$1 AND id=$2 AND state=$3",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .bind(PayoutBatchState::Broadcast.as_str())
        .bind(confirmation.block_hash.as_slice())
        .bind(i64::from(confirmation.block_height))
        .bind(
            i32::try_from(confirmation.confirmations)
                .map_err(|_| StoreError::InvalidPayoutConfirmation)?,
        )
        .execute(&mut *transaction)
        .await?;
        if state.rows_affected() != 1 {
            return Err(StoreError::InvalidPayoutTransition);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Records that a confirmed payout left the best chain. No liability is
    /// recreated because the same signed transaction can re-enter the mempool;
    /// instead all new chain payouts freeze until wallet reconciliation.
    pub async fn mark_confirmed_payout_reorged(
        &self,
        batch_id: Uuid,
        evidence: &PayoutReorg,
    ) -> Result<(), StoreError> {
        evidence.validate()?;
        let mut transaction = self.pool.begin().await?;
        let batch = load_payout_batch(&mut transaction, self.identity.id, batch_id).await?;
        if batch.state == PayoutBatchState::Reorged {
            let row = sqlx::query(
                "SELECT prior_block_hash,prior_block_height,prior_confirmations, \
                        replacement_tip_hash,replacement_tip_height, \
                        EXTRACT(EPOCH FROM observed_at)::BIGINT AS observed_at \
                 FROM payout_reorg_events WHERE deployment_id=$1 AND batch_id=$2 \
                 ORDER BY observed_at DESC,id DESC LIMIT 1",
            )
            .bind(self.identity.id)
            .bind(batch_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(StoreError::CorruptDatabaseState("payout reorg evidence"))?;
            let replay_matches = row.try_get::<Vec<u8>, _>("prior_block_hash")?
                == evidence.prior_confirmation.block_hash
                && row.try_get::<i64, _>("prior_block_height")?
                    == i64::from(evidence.prior_confirmation.block_height)
                && row.try_get::<i32, _>("prior_confirmations")?
                    == i32::try_from(evidence.prior_confirmation.confirmations)
                        .map_err(|_| StoreError::InvalidPayoutConfirmation)?
                && row.try_get::<Vec<u8>, _>("replacement_tip_hash")?
                    == evidence.replacement_tip_hash
                && row.try_get::<i64, _>("replacement_tip_height")?
                    == i64::from(evidence.replacement_tip_height)
                && row.try_get::<i64, _>("observed_at")? == unix_i64(evidence.observed_at)?;
            transaction.rollback().await?;
            return if replay_matches {
                Ok(())
            } else {
                Err(StoreError::PayoutReplayConflict)
            };
        }
        if batch.state != PayoutBatchState::Confirmed {
            return Err(StoreError::InvalidPayoutTransition);
        }
        let confirmation = sqlx::query(
            "SELECT confirmation_block_hash,confirmation_height,confirmation_count \
             FROM payout_batches WHERE deployment_id=$1 AND id=$2",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .fetch_one(&mut *transaction)
        .await?;
        if confirmation.try_get::<Vec<u8>, _>("confirmation_block_hash")?
            != evidence.prior_confirmation.block_hash
            || confirmation.try_get::<i64, _>("confirmation_height")?
                != i64::from(evidence.prior_confirmation.block_height)
            || confirmation.try_get::<i32, _>("confirmation_count")?
                != i32::try_from(evidence.prior_confirmation.confirmations)
                    .map_err(|_| StoreError::InvalidPayoutConfirmation)?
        {
            return Err(StoreError::PayoutReplayConflict);
        }
        sqlx::query(
            "SELECT payouts_frozen FROM chain_safety_state \
             WHERE deployment_id=$1 AND chain=$2 FOR UPDATE",
        )
        .bind(self.identity.id)
        .bind(batch.chain.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO payout_reorg_events \
             (deployment_id,id,batch_id,prior_block_hash,prior_block_height,prior_confirmations, \
              replacement_tip_hash,replacement_tip_height,observed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9))",
        )
        .bind(self.identity.id)
        .bind(Uuid::new_v4())
        .bind(batch_id)
        .bind(evidence.prior_confirmation.block_hash.as_slice())
        .bind(i64::from(evidence.prior_confirmation.block_height))
        .bind(
            i32::try_from(evidence.prior_confirmation.confirmations)
                .map_err(|_| StoreError::InvalidPayoutConfirmation)?,
        )
        .bind(evidence.replacement_tip_hash.as_slice())
        .bind(i64::from(evidence.replacement_tip_height))
        .bind(unix_i64(evidence.observed_at)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE payout_batches SET state='reorged',updated_at=clock_timestamp() \
             WHERE deployment_id=$1 AND id=$2 AND state='confirmed'",
        )
        .bind(self.identity.id)
        .bind(batch_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE chain_safety_state SET payouts_frozen=TRUE, \
             frozen_by_backend_event_seq=NULL,freeze_reason='confirmed_payout_reorg', \
             updated_at=clock_timestamp() WHERE deployment_id=$1 AND chain=$2",
        )
        .bind(self.identity.id)
        .bind(batch.chain.as_str())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Cancels only an unsigned draft and releases every pending liability.
    pub async fn cancel_payout_draft(&self, batch_id: Uuid) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        let batch = load_payout_batch(&mut transaction, self.identity.id, batch_id).await?;
        if batch.state == PayoutBatchState::Cancelled {
            transaction.rollback().await?;
            return Ok(());
        }
        if batch.state != PayoutBatchState::Draft {
            return Err(StoreError::InvalidPayoutTransition);
        }
        let mut entries = Vec::with_capacity(batch.outputs.len() * 2);
        for output in &batch.outputs {
            entries.push((
                Some(output.account_id),
                "payout_pending".to_owned(),
                as_i64(output.amount_zat)?,
            ));
            entries.push((
                Some(output.account_id),
                "miner_payable".to_owned(),
                -as_i64(output.amount_zat)?,
            ));
        }
        insert_owned_ledger_transaction(
            &mut transaction,
            self.identity.id,
            batch.chain,
            "payout_released",
            None,
            &batch_id.to_string(),
            &entries,
        )
        .await?;
        update_payout_state(
            &mut transaction,
            self.identity.id,
            batch_id,
            PayoutBatchState::Draft,
            PayoutBatchState::Cancelled,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Claims exclusive ownership of a backend-global nonce namespace.
    ///
    /// `holder_id` must be a fresh UUID for this process lifetime. An exact
    /// retry by the active holder is idempotent and returns the existing lease.
    /// A different holder can take over only after database-clock expiry or an
    /// explicit release, and takeover never resets the monotonic cursor.
    pub async fn claim_nonce_namespace(
        &self,
        holder_id: Uuid,
        profile: NonceProfile,
        namespace: NonceNamespaceLease,
        lease_duration: Duration,
    ) -> Result<NonceNamespaceClaim, StoreError> {
        if holder_id.is_nil() {
            return Err(StoreError::InvalidNonceReservation);
        }
        let lease_seconds = nonce_lease_seconds(lease_duration)?;
        let profile_bytes = nonce_profile_bytes(profile)?;
        let namespace_id = i16::from(namespace.namespace());
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO nonce_namespace_fences \
             (backend_instance,journal_stream,profile,namespace,next_counter) \
             VALUES ($1,$2,$3,$4,0) ON CONFLICT DO NOTHING",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .execute(&mut *transaction)
        .await?;

        let row = sqlx::query(
            "SELECT holder_id,holder_deployment_id,lease_generation, \
                    EXTRACT(EPOCH FROM lease_expires_at)::BIGINT AS lease_expires_at, \
                    COALESCE(lease_expires_at > clock_timestamp(),FALSE) AS lease_active \
             FROM nonce_namespace_fences \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=$3 AND namespace=$4 \
             FOR UPDATE",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .fetch_one(&mut *transaction)
        .await?;
        let active = row.try_get::<bool, _>("lease_active")?;
        let current_holder = row.try_get::<Option<Uuid>, _>("holder_id")?;
        let current_deployment = row.try_get::<Option<Uuid>, _>("holder_deployment_id")?;
        if active {
            if current_holder != Some(holder_id) || current_deployment != Some(self.identity.id) {
                return Err(StoreError::NonceNamespaceAlreadyHeld);
            }
            let claim = NonceNamespaceClaim {
                deployment_id: self.identity.id,
                holder_id,
                profile,
                namespace,
                generation: unix_u64(row.try_get::<i64, _>("lease_generation")?)?,
                expires_at: unix_u64(
                    row.try_get::<Option<i64>, _>("lease_expires_at")?
                        .ok_or(StoreError::CorruptDatabaseState("nonce lease expiry"))?,
                )?,
            };
            transaction.commit().await?;
            return Ok(claim);
        }

        let previous_generation = row.try_get::<i64, _>("lease_generation")?;
        let generation = previous_generation
            .checked_add(1)
            .ok_or(StoreError::NonceNamespaceLeaseGenerationExhausted)?;
        let claimed = sqlx::query(
            "UPDATE nonce_namespace_fences \
             SET holder_id=$5,holder_deployment_id=$6,lease_generation=$7, \
                 lease_acquired_at=clock_timestamp(), \
                 lease_expires_at=clock_timestamp() + ($8 * INTERVAL '1 second'), \
                 updated_at=clock_timestamp() \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=$3 AND namespace=$4 \
             RETURNING EXTRACT(EPOCH FROM lease_expires_at)::BIGINT AS lease_expires_at",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .bind(holder_id)
        .bind(self.identity.id)
        .bind(generation)
        .bind(lease_seconds)
        .fetch_one(&mut *transaction)
        .await?;
        let expires_at = claimed.try_get::<i64, _>("lease_expires_at")?;
        insert_nonce_claim_event(
            &mut transaction,
            &self.identity,
            profile_bytes,
            namespace_id,
            holder_id,
            generation,
            "claimed",
        )
        .await?;
        transaction.commit().await?;
        Ok(NonceNamespaceClaim {
            deployment_id: self.identity.id,
            holder_id,
            profile,
            namespace,
            generation: unix_u64(generation)?,
            expires_at: unix_u64(expires_at)?,
        })
    }

    /// Extends an active claim using the database clock.
    ///
    /// An expired claim cannot be revived by renewal; it must compete for a
    /// fresh generation through [`Self::claim_nonce_namespace`].
    pub async fn renew_nonce_namespace(
        &self,
        claim: &NonceNamespaceClaim,
        lease_duration: Duration,
    ) -> Result<NonceNamespaceClaim, StoreError> {
        self.validate_nonce_claim(claim)?;
        let lease_seconds = nonce_lease_seconds(lease_duration)?;
        let profile_bytes = nonce_profile_bytes(claim.profile)?;
        let namespace_id = i16::from(claim.namespace.namespace());
        let generation =
            i64::try_from(claim.generation).map_err(|_| StoreError::InvalidNonceReservation)?;
        let mut transaction = self.pool.begin().await?;
        let renewed = sqlx::query(
            "UPDATE nonce_namespace_fences \
             SET lease_expires_at=GREATEST( \
                     lease_expires_at,clock_timestamp() + ($8 * INTERVAL '1 second')), \
                 updated_at=clock_timestamp() \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=$3 AND namespace=$4 \
               AND holder_id=$5 AND holder_deployment_id=$6 AND lease_generation=$7 \
               AND lease_expires_at > clock_timestamp() \
             RETURNING EXTRACT(EPOCH FROM lease_expires_at)::BIGINT AS lease_expires_at",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .bind(claim.holder_id)
        .bind(self.identity.id)
        .bind(generation)
        .bind(lease_seconds)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NonceNamespaceLeaseLost)?;
        let expires_at = renewed.try_get::<i64, _>("lease_expires_at")?;
        insert_nonce_claim_event(
            &mut transaction,
            &self.identity,
            profile_bytes,
            namespace_id,
            claim.holder_id,
            generation,
            "renewed",
        )
        .await?;
        transaction.commit().await?;
        Ok(NonceNamespaceClaim {
            expires_at: unix_u64(expires_at)?,
            ..claim.clone()
        })
    }

    /// Releases an active namespace claim without changing its cursor.
    pub async fn release_nonce_namespace(
        &self,
        claim: &NonceNamespaceClaim,
    ) -> Result<(), StoreError> {
        self.validate_nonce_claim(claim)?;
        let profile_bytes = nonce_profile_bytes(claim.profile)?;
        let namespace_id = i16::from(claim.namespace.namespace());
        let generation =
            i64::try_from(claim.generation).map_err(|_| StoreError::InvalidNonceReservation)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query_scalar::<_, i64>(
            "UPDATE nonce_namespace_fences \
             SET holder_id=NULL,holder_deployment_id=NULL,lease_acquired_at=NULL, \
                 lease_expires_at=NULL,last_released_at=clock_timestamp(), \
                 updated_at=clock_timestamp() \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=$3 AND namespace=$4 \
               AND holder_id=$5 AND holder_deployment_id=$6 AND lease_generation=$7 \
               AND lease_expires_at > clock_timestamp() \
             RETURNING next_counter",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .bind(claim.holder_id)
        .bind(self.identity.id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NonceNamespaceLeaseLost)?;
        insert_nonce_claim_event(
            &mut transaction,
            &self.identity,
            profile_bytes,
            namespace_id,
            claim.holder_id,
            generation,
            "released",
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically reserves a unique local counter range under an active global
    /// claim before any prefix can be shown to a miner. A crash wastes the
    /// unused tail but never reuses it.
    pub async fn reserve_nonce_range(
        &self,
        claim: &NonceNamespaceClaim,
        count: u64,
    ) -> Result<NonceRange, StoreError> {
        self.validate_nonce_claim(claim)?;
        if count == 0 {
            return Err(StoreError::InvalidNonceReservation);
        }
        let capacity = match claim.profile {
            NonceProfile::FourByte => 1u64 << 24,
            NonceProfile::EightByte => 1u64 << 56,
        };
        let profile_bytes = nonce_profile_bytes(claim.profile)?;
        let namespace_id = i16::from(claim.namespace.namespace());
        let generation =
            i64::try_from(claim.generation).map_err(|_| StoreError::InvalidNonceReservation)?;
        let mut transaction = self.pool.begin().await?;
        let start = sqlx::query_scalar::<_, i64>(
            "SELECT next_counter FROM nonce_namespace_fences \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=$3 AND namespace=$4 \
               AND holder_id=$5 AND holder_deployment_id=$6 AND lease_generation=$7 \
               AND lease_expires_at > clock_timestamp() \
             FOR UPDATE",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .bind(claim.holder_id)
        .bind(self.identity.id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NonceNamespaceLeaseLost)?;
        let start = u64::try_from(start).map_err(|_| StoreError::InvalidNonceReservation)?;
        let end = start
            .checked_add(count)
            .filter(|end| *end <= capacity)
            .ok_or(StoreError::NonceNamespaceExhausted)?;
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO nonce_global_range_reservations \
             (backend_instance,journal_stream,profile,namespace,id,deployment_id,holder_id, \
              lease_generation,range_start,range_end) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .bind(id)
        .bind(self.identity.id)
        .bind(claim.holder_id)
        .bind(generation)
        .bind(i64::try_from(start).map_err(|_| StoreError::InvalidNonceReservation)?)
        .bind(i64::try_from(end).map_err(|_| StoreError::InvalidNonceReservation)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE nonce_namespace_fences SET next_counter=$5,updated_at=clock_timestamp() \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=$3 AND namespace=$4",
        )
        .bind(self.identity.backend_instance)
        .bind(self.identity.journal_stream)
        .bind(profile_bytes)
        .bind(namespace_id)
        .bind(i64::try_from(end).map_err(|_| StoreError::InvalidNonceReservation)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(NonceRange {
            id,
            profile: claim.profile,
            namespace: claim.namespace,
            start,
            end,
        })
    }

    fn validate_nonce_claim(&self, claim: &NonceNamespaceClaim) -> Result<(), StoreError> {
        if claim.deployment_id != self.identity.id
            || claim.holder_id.is_nil()
            || claim.generation == 0
        {
            return Err(StoreError::NonceNamespaceLeaseLost);
        }
        Ok(())
    }

    /// Projects one validated backend event and all accounting effects.
    pub async fn project_event(
        &self,
        authority: &BackendAuthority,
        event: &BackendEvent,
    ) -> Result<ProjectionResult, StoreError> {
        self.verify_authority(authority)?;
        project_one(&self.pool, &self.identity, event).await
    }

    /// Projects a bounded contiguous historical page before live subscription.
    pub async fn project_replay_page(
        &self,
        authority: &BackendAuthority,
        events: &[BackendEvent],
    ) -> Result<(), StoreError> {
        self.verify_authority(authority)?;
        if events.len() > MAX_REPLAY_BATCH {
            return Err(StoreError::ReplayBatchTooLarge(events.len()));
        }
        for event in events {
            self.project_event(authority, event).await?;
        }
        Ok(())
    }

    /// Returns a database-backed miner authentication provider for this exact
    /// deployment. Every clone shares the explicit Argon2 concurrency fence.
    pub fn authentication_provider(
        &self,
        maximum_parallel_verifications: usize,
    ) -> Result<crate::PostgresAuthenticationProvider, StoreError> {
        Ok(crate::PostgresAuthenticationProvider::new(
            self.pool.clone(),
            self.identity.id,
            maximum_parallel_verifications,
        )?)
    }
}

impl BackendEventConsumer for PostgresStore {
    fn consume<'a>(
        &'a self,
        authority: &'a BackendAuthority,
        events: &'a [DeliveredBackendEvent],
    ) -> Pin<Box<dyn Future<Output = Result<(), BackendEventConsumerError>> + Send + 'a>> {
        Box::pin(async move {
            if events.len() > MAX_REPLAY_BATCH || self.verify_authority(authority).is_err() {
                return Err(BackendEventConsumerError);
            }
            for delivered in events {
                if delivered.connection_binding().authority() != authority
                    || self
                        .project_event(authority, delivered.event())
                        .await
                        .is_err()
                {
                    return Err(BackendEventConsumerError);
                }
            }
            Ok(())
        })
    }
}

pub(crate) fn validate_component(value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(StoreError::InvalidLoginComponent);
    }
    Ok(())
}

fn account_credential_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<AccountCredentialRecord, StoreError> {
    let password_verifier = row
        .try_get::<Option<String>, _>("password_verifier")?
        .ok_or(StoreError::InvalidPortalCredential)?;
    if !validate_argon2id_verifier(&password_verifier) {
        return Err(StoreError::CorruptDatabaseState("portal password verifier"));
    }
    Ok(AccountCredentialRecord {
        id: row.try_get("id")?,
        login: row.try_get("login")?,
        password_verifier,
        totp_secret_sealed: row.try_get("totp_secret_sealed")?,
        totp_pending_sealed: row.try_get("totp_pending_sealed")?,
        totp_pending_expires_at: row
            .try_get::<Option<i64>, _>("totp_pending_expires_at")?
            .map(unix_u64)
            .transpose()?,
        locked_until: row
            .try_get::<Option<i64>, _>("locked_until")?
            .map(unix_u64)
            .transpose()?,
        security_version: u64::try_from(row.try_get::<i64, _>("security_version")?)
            .map_err(|_| StoreError::CorruptDatabaseState("account security version"))?,
    })
}

fn nonce_profile_bytes(profile: NonceProfile) -> Result<i16, StoreError> {
    i16::try_from(profile.prefix_bytes()).map_err(|_| StoreError::InvalidNonceReservation)
}

fn nonce_lease_seconds(duration: Duration) -> Result<i64, StoreError> {
    let seconds = duration.as_secs();
    if duration.subsec_nanos() != 0
        || !(MIN_NONCE_NAMESPACE_LEASE_SECS..=MAX_NONCE_NAMESPACE_LEASE_SECS).contains(&seconds)
    {
        return Err(StoreError::InvalidNonceLeaseDuration);
    }
    i64::try_from(seconds).map_err(|_| StoreError::InvalidNonceLeaseDuration)
}

async fn insert_nonce_claim_event(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &DeploymentIdentity,
    profile: i16,
    namespace: i16,
    holder_id: Uuid,
    generation: i64,
    event_kind: &str,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "INSERT INTO nonce_namespace_claim_events \
         (backend_instance,journal_stream,profile,namespace,deployment_id,holder_id, \
          lease_generation,event_kind,lease_expires_at,next_counter) \
         SELECT $1,$2,$3,$4,$5,$6,$7,$8,fence.lease_expires_at,fence.next_counter \
           FROM nonce_namespace_fences fence \
          WHERE fence.backend_instance=$1 AND fence.journal_stream=$2 \
            AND fence.profile=$3 AND fence.namespace=$4",
    )
    .bind(identity.backend_instance)
    .bind(identity.journal_stream)
    .bind(profile)
    .bind(namespace)
    .bind(identity.id)
    .bind(holder_id)
    .bind(generation)
    .bind(event_kind)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StoreError::CorruptDatabaseState("nonce claim audit"));
    }
    Ok(())
}

pub(crate) fn unix_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidTimestamp)
}

pub(crate) fn unix_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptDatabaseState("timestamp"))
}

fn exactly_one(rows: u64) -> Result<(), StoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::UnknownAccount)
    }
}

async fn load_payout_batch(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    batch_id: Uuid,
) -> Result<PayoutBatch, StoreError> {
    let row = sqlx::query(
        "SELECT chain,state,policy_version,reconciliation_id,ledger_root,ledger_sequence_cutoff \
         FROM payout_batches \
         WHERE deployment_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(deployment_id)
    .bind(batch_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::UnknownPayoutBatch)?;
    let chain = Chain::parse(&row.try_get::<String, _>("chain")?)?;
    let state = PayoutBatchState::parse(&row.try_get::<String, _>("state")?)?;
    let policy_version = u64::try_from(row.try_get::<i64, _>("policy_version")?)
        .map_err(|_| StoreError::CorruptDatabaseState("payout policy version"))?;
    let reconciliation_id = row.try_get::<Option<Uuid>, _>("reconciliation_id")?.ok_or(
        StoreError::CorruptDatabaseState("payout reconciliation identity"),
    )?;
    let ledger_root = exact_hash(
        row.try_get::<Option<Vec<u8>>, _>("ledger_root")?
            .ok_or(StoreError::CorruptDatabaseState("payout ledger root"))?,
        "payout ledger root",
    )?;
    let ledger_sequence_cutoff = u64::try_from(
        row.try_get::<Option<i64>, _>("ledger_sequence_cutoff")?
            .ok_or(StoreError::CorruptDatabaseState(
                "payout ledger sequence cutoff",
            ))?,
    )
    .map_err(|_| StoreError::CorruptDatabaseState("payout ledger sequence cutoff"))?;
    let rows = sqlx::query(
        "SELECT i.allocation_id,i.account_id,i.destination_id,i.amount_zat, \
                d.address,d.receiver_kind \
         FROM payout_items i JOIN payout_destinations d \
           ON (d.deployment_id,d.id)=(i.deployment_id,i.destination_id) \
         WHERE i.deployment_id=$1 AND i.batch_id=$2 ORDER BY i.account_id,i.allocation_id",
    )
    .bind(deployment_id)
    .bind(batch_id)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.is_empty() {
        return Err(StoreError::CorruptDatabaseState("empty payout batch"));
    }
    let mut outputs = Vec::with_capacity(rows.len());
    let mut miner_total_zat = 0u64;
    for row in rows {
        let amount_zat = u64::try_from(row.try_get::<i64, _>("amount_zat")?)
            .map_err(|_| StoreError::CorruptDatabaseState("payout amount"))?;
        miner_total_zat = miner_total_zat
            .checked_add(amount_zat)
            .ok_or(StoreError::MoneyOverflow)?;
        outputs.push(PayoutInstruction {
            allocation_id: row.try_get("allocation_id")?,
            account_id: row.try_get("account_id")?,
            destination_id: row.try_get("destination_id")?,
            receiver_kind: ReceiverKind::parse(&row.try_get::<String, _>("receiver_kind")?)?,
            address: row.try_get("address")?,
            amount_zat,
        });
    }
    Ok(PayoutBatch {
        id: batch_id,
        chain,
        state,
        policy_version,
        reconciliation_id,
        ledger_root,
        ledger_sequence_cutoff,
        miner_total_zat,
        outputs,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LedgerSnapshot {
    root: [u8; 32],
    transaction_count: u64,
    collector_spendable_zat: u64,
}

async fn ledger_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    chain: Chain,
    sequence_cutoff: Option<u64>,
) -> Result<LedgerSnapshot, StoreError> {
    let mut hasher = Sha256::new();
    hasher.update(LEDGER_SNAPSHOT_DOMAIN);
    hasher.update(deployment_id.as_bytes());
    hasher.update([match chain {
        Chain::Wcash => 1,
        Chain::Zcash => 2,
    }]);
    let mut transaction_count = 0u64;
    let mut previous_transaction = None;
    {
        let mut rows = sqlx::query(
            "SELECT t.id,t.ledger_sequence,t.kind,t.backend_event_seq,t.reference,t.sealed_entry_count, \
                    e.line_no,e.account_id,e.ledger_account,e.amount_zat \
             FROM ledger_transactions t JOIN ledger_entries e \
               ON (e.deployment_id,e.transaction_id)=(t.deployment_id,t.id) \
             WHERE t.deployment_id=$1 AND t.chain=$2 AND t.sealed_at IS NOT NULL \
               AND ($3::BIGINT IS NULL OR t.ledger_sequence <= $3) \
             ORDER BY t.ledger_sequence,e.line_no",
        )
        .bind(deployment_id)
        .bind(chain.as_str())
        .bind(sequence_cutoff.map(as_i64).transpose()?)
        .fetch(&mut **transaction);
        while let Some(row) = rows.try_next().await? {
            let transaction_id = row.try_get::<Uuid, _>("id")?;
            let ledger_sequence = row.try_get::<i64, _>("ledger_sequence")?;
            if ledger_sequence <= 0 {
                return Err(StoreError::CorruptDatabaseState("ledger sequence"));
            }
            if previous_transaction != Some(transaction_id) {
                transaction_count = transaction_count
                    .checked_add(1)
                    .ok_or(StoreError::MoneyOverflow)?;
                previous_transaction = Some(transaction_id);
            }
            hasher.update(ledger_sequence.to_be_bytes());
            hasher.update(transaction_id.as_bytes());
            hash_bounded_text(&mut hasher, &row.try_get::<String, _>("kind")?, 64)?;
            match row.try_get::<Option<i64>, _>("backend_event_seq")? {
                Some(sequence) if sequence > 0 => {
                    hasher.update([1]);
                    hasher.update(sequence.to_be_bytes());
                }
                None => hasher.update([0]),
                _ => return Err(StoreError::CorruptDatabaseState("ledger event sequence")),
            }
            hash_bounded_text(&mut hasher, &row.try_get::<String, _>("reference")?, 256)?;
            let sealed_entry_count = row.try_get::<i32, _>("sealed_entry_count")?;
            let line_no = row.try_get::<i32, _>("line_no")?;
            if sealed_entry_count < 2 || line_no <= 0 {
                return Err(StoreError::CorruptDatabaseState("ledger seal"));
            }
            hasher.update(sealed_entry_count.to_be_bytes());
            hasher.update(line_no.to_be_bytes());
            match row.try_get::<Option<Uuid>, _>("account_id")? {
                Some(account_id) => {
                    hasher.update([1]);
                    hasher.update(account_id.as_bytes());
                }
                None => hasher.update([0]),
            }
            hash_bounded_text(
                &mut hasher,
                &row.try_get::<String, _>("ledger_account")?,
                64,
            )?;
            let amount_zat = row.try_get::<i64, _>("amount_zat")?;
            if amount_zat == 0 {
                return Err(StoreError::CorruptDatabaseState("zero ledger line"));
            }
            hasher.update(amount_zat.to_be_bytes());
        }
    }
    hasher.update(transaction_count.to_be_bytes());
    let collector_spendable = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(e.amount_zat),0)::BIGINT FROM ledger_entries e \
         JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND t.chain=$2 \
           AND t.sealed_at IS NOT NULL \
           AND ($3::BIGINT IS NULL OR t.ledger_sequence <= $3) \
           AND e.ledger_account='collector_spendable_asset'",
    )
    .bind(deployment_id)
    .bind(chain.as_str())
    .bind(sequence_cutoff.map(as_i64).transpose()?)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(LedgerSnapshot {
        root: hasher.finalize().into(),
        transaction_count,
        collector_spendable_zat: u64::try_from(collector_spendable)
            .map_err(|_| StoreError::CollectorReconciliationFailed)?,
    })
}

fn hash_bounded_text(
    hasher: &mut Sha256,
    value: &str,
    maximum_length: usize,
) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > maximum_length {
        return Err(StoreError::CorruptDatabaseState("ledger text"));
    }
    let length = u16::try_from(value.len())
        .map_err(|_| StoreError::CorruptDatabaseState("ledger text length"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

async fn load_usable_wallet_reconciliation(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    chain: Chain,
    reconciliation_id: Uuid,
) -> Result<WalletReconciliation, StoreError> {
    let row = sqlx::query(
        "SELECT chain,ledger_root,ledger_transaction_count,wallet_spendable_zat, \
                ledger_spendable_zat,best_tip_hash,best_tip_height, \
                EXTRACT(EPOCH FROM observed_at)::BIGINT AS observed_at, \
                EXTRACT(EPOCH FROM valid_until)::BIGINT AS valid_until,status, \
                valid_until > clock_timestamp() AS unexpired \
         FROM wallet_reconciliations WHERE deployment_id=$1 AND id=$2 FOR SHARE",
    )
    .bind(deployment_id)
    .bind(reconciliation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::WalletReconciliationStale)?;
    let stored_chain = Chain::parse(&row.try_get::<String, _>("chain")?)?;
    let status = row.try_get::<String, _>("status")?;
    let unexpired = row.try_get::<bool, _>("unexpired")?;
    let wallet_spendable_zat = u64::try_from(row.try_get::<i64, _>("wallet_spendable_zat")?)
        .map_err(|_| StoreError::CorruptDatabaseState("wallet balance"))?;
    let ledger_spendable_zat = u64::try_from(row.try_get::<i64, _>("ledger_spendable_zat")?)
        .map_err(|_| StoreError::CorruptDatabaseState("ledger balance"))?;
    if stored_chain != chain
        || status != "matched"
        || !unexpired
        || wallet_spendable_zat != ledger_spendable_zat
    {
        return Err(StoreError::WalletReconciliationStale);
    }
    Ok(WalletReconciliation {
        id: reconciliation_id,
        chain,
        ledger_root: exact_hash(row.try_get("ledger_root")?, "wallet ledger root")?,
        ledger_transaction_count: u64::try_from(row.try_get::<i64, _>("ledger_transaction_count")?)
            .map_err(|_| StoreError::CorruptDatabaseState("ledger transaction count"))?,
        wallet_spendable_zat,
        best_tip_hash: exact_hash(row.try_get("best_tip_hash")?, "wallet best tip")?,
        best_tip_height: u32::try_from(row.try_get::<i64, _>("best_tip_height")?)
            .map_err(|_| StoreError::CorruptDatabaseState("wallet best tip height"))?,
        observed_at: unix_u64(row.try_get("observed_at")?)?,
        valid_until: unix_u64(row.try_get("valid_until")?)?,
    })
}

fn exact_hash(value: Vec<u8>, field: &'static str) -> Result<[u8; 32], StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::CorruptDatabaseState(field))
}

const fn asset_for_chain(chain: Chain) -> Asset {
    match chain {
        Chain::Wcash => Asset::Wec,
        Chain::Zcash => Asset::Zec,
    }
}

const fn network_for_deployment(network: DeploymentNetwork) -> ChainNetwork {
    match network {
        DeploymentNetwork::Testnet => ChainNetwork::Testnet,
        DeploymentNetwork::Mainnet => ChainNetwork::Mainnet,
    }
}

const fn portal_receiver_kind(receiver: ReceiverKind) -> PortalReceiverKind {
    match receiver {
        ReceiverKind::Transparent => PortalReceiverKind::Transparent,
        ReceiverKind::Ironwood => PortalReceiverKind::Ironwood,
    }
}

struct SignedTransitionFacts<'a> {
    unsigned_digest: &'a [u8; 32],
    transaction_id: &'a [u8; 32],
    signed_transaction: &'a [u8],
    network_fee_zat: u64,
}

async fn transition_payout(
    pool: &PgPool,
    deployment_id: Uuid,
    batch_id: Uuid,
    expected: PayoutBatchState,
    next: PayoutBatchState,
    signed: Option<SignedTransitionFacts<'_>>,
) -> Result<(), StoreError> {
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT chain,policy_version,state,unsigned_digest,transaction_id,signed_transaction,network_fee_zat \
         FROM payout_batches WHERE deployment_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(deployment_id)
    .bind(batch_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(StoreError::UnknownPayoutBatch)?;
    let state = PayoutBatchState::parse(&row.try_get::<String, _>("state")?)?;
    if state == next {
        let replay_matches = signed.as_ref().is_none_or(|facts| {
            row.try_get::<Option<Vec<u8>>, _>("unsigned_digest")
                .ok()
                .flatten()
                .as_deref()
                == Some(facts.unsigned_digest.as_slice())
                && row
                    .try_get::<Option<Vec<u8>>, _>("transaction_id")
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(facts.transaction_id.as_slice())
                && row
                    .try_get::<Option<Vec<u8>>, _>("signed_transaction")
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(facts.signed_transaction)
                && row
                    .try_get::<Option<i64>, _>("network_fee_zat")
                    .ok()
                    .flatten()
                    .and_then(|stored| u64::try_from(stored).ok())
                    == Some(facts.network_fee_zat)
        });
        transaction.rollback().await?;
        return if replay_matches {
            Ok(())
        } else {
            Err(StoreError::PayoutReplayConflict)
        };
    }
    if state != expected {
        return Err(StoreError::InvalidPayoutTransition);
    }
    let chain = Chain::parse(&row.try_get::<String, _>("chain")?)?;
    lock_unfrozen_chain(&mut transaction, deployment_id, chain).await?;
    if let Some(facts) = &signed {
        let transaction_id_in_use = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM payout_batches \
             WHERE deployment_id=$1 AND chain=$2 AND transaction_id=$3 AND id<>$4)",
        )
        .bind(deployment_id)
        .bind(chain.as_str())
        .bind(facts.transaction_id.as_slice())
        .bind(batch_id)
        .fetch_one(&mut *transaction)
        .await?;
        if transaction_id_in_use {
            return Err(StoreError::PayoutTransactionConflict);
        }
        let policy = sqlx::query(
            "SELECT maximum_network_fee_zat,maximum_network_fee_bps \
             FROM chain_policies WHERE deployment_id=$1 AND chain=$2 AND policy_version=$3",
        )
        .bind(deployment_id)
        .bind(chain.as_str())
        .bind(row.try_get::<i64, _>("policy_version")?)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::CorruptDatabaseState("payout policy"))?;
        let absolute = u64::try_from(policy.try_get::<i64, _>("maximum_network_fee_zat")?)
            .map_err(|_| StoreError::CorruptDatabaseState("maximum network fee"))?;
        let relative = u16::try_from(policy.try_get::<i32, _>("maximum_network_fee_bps")?)
            .map_err(|_| StoreError::CorruptDatabaseState("maximum network fee rate"))?;
        let miner_total = sqlx::query_scalar::<_, i64>(
            "SELECT SUM(amount_zat)::BIGINT FROM payout_items \
             WHERE deployment_id=$1 AND batch_id=$2",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .fetch_one(&mut *transaction)
        .await?;
        let miner_total = u64::try_from(miner_total)
            .map_err(|_| StoreError::CorruptDatabaseState("payout total"))?;
        if facts.network_fee_zat > absolute
            || u128::from(facts.network_fee_zat) * 10_000
                > u128::from(miner_total) * u128::from(relative)
        {
            return Err(StoreError::ExcessivePayoutFee);
        }
    }
    let fee = signed
        .as_ref()
        .map(|facts| as_i64(facts.network_fee_zat))
        .transpose()?;
    let result = match sqlx::query(
        "UPDATE payout_batches SET state=$4, \
         unsigned_digest=COALESCE($5,unsigned_digest), \
         transaction_id=COALESCE($6,transaction_id), \
         signed_transaction=COALESCE($7,signed_transaction), \
         network_fee_zat=COALESCE($8,network_fee_zat), \
         updated_at=clock_timestamp() \
         WHERE deployment_id=$1 AND id=$2 AND state=$3",
    )
    .bind(deployment_id)
    .bind(batch_id)
    .bind(expected.as_str())
    .bind(next.as_str())
    .bind(
        signed
            .as_ref()
            .map(|facts| facts.unsigned_digest.as_slice()),
    )
    .bind(signed.as_ref().map(|facts| facts.transaction_id.as_slice()))
    .bind(signed.as_ref().map(|facts| facts.signed_transaction))
    .bind(fee)
    .execute(&mut *transaction)
    .await
    {
        Ok(result) => result,
        Err(sqlx::Error::Database(error))
            if error.constraint() == Some("payout_batches_chain_transaction_idx") =>
        {
            return Err(StoreError::PayoutTransactionConflict);
        }
        Err(error) => return Err(StoreError::Database(error)),
    };
    if result.rows_affected() != 1 {
        return Err(StoreError::InvalidPayoutTransition);
    }
    transaction.commit().await?;
    Ok(())
}

fn exact_digest(value: Option<Vec<u8>>, name: &'static str) -> Result<[u8; 32], StoreError> {
    value
        .ok_or(StoreError::CorruptDatabaseState(name))?
        .try_into()
        .map_err(|_| StoreError::CorruptDatabaseState(name))
}

async fn lock_unfrozen_chain(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    chain: Chain,
) -> Result<(), StoreError> {
    let frozen = sqlx::query_scalar::<_, bool>(
        "SELECT payouts_frozen FROM chain_safety_state \
         WHERE deployment_id=$1 AND chain=$2 FOR UPDATE",
    )
    .bind(deployment_id)
    .bind(chain.as_str())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::MissingChainPolicy(chain))?;
    if frozen {
        Err(StoreError::PayoutsFrozen(chain))
    } else {
        Ok(())
    }
}

async fn update_payout_state(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    batch_id: Uuid,
    expected: PayoutBatchState,
    next: PayoutBatchState,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "UPDATE payout_batches SET state=$4,updated_at=clock_timestamp() \
         WHERE deployment_id=$1 AND id=$2 AND state=$3",
    )
    .bind(deployment_id)
    .bind(batch_id)
    .bind(expected.as_str())
    .bind(next.as_str())
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(StoreError::InvalidPayoutTransition)
    }
}

async fn project_one(
    pool: &PgPool,
    identity: &DeploymentIdentity,
    event: &BackendEvent,
) -> Result<ProjectionResult, StoreError> {
    event.validate()?;
    let event_seq = i64::try_from(event.event_seq()).map_err(|_| StoreError::EventSeqOverflow)?;
    let payload_bytes = serde_json::to_vec(event)?;
    let payload = serde_json::to_value(event)?;
    let payload_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
    let mut transaction = pool.begin().await?;
    let last_event_seq = sqlx::query_scalar::<_, i64>(
        "SELECT last_event_seq FROM backend_cursors WHERE deployment_id=$1 FOR UPDATE",
    )
    .bind(identity.id)
    .fetch_one(&mut *transaction)
    .await?;

    if event_seq <= last_event_seq {
        let stored = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT payload_sha256 FROM backend_events WHERE deployment_id=$1 AND event_seq=$2",
        )
        .bind(identity.id)
        .bind(event_seq)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.rollback().await?;
        return if stored.as_deref() == Some(payload_hash.as_slice()) {
            Ok(ProjectionResult::Replayed)
        } else {
            Err(StoreError::EventReplayConflict(event.event_seq()))
        };
    }
    let expected = last_event_seq
        .checked_add(1)
        .ok_or(StoreError::EventSeqOverflow)?;
    if event_seq != expected {
        return Err(StoreError::EventSequenceGap {
            expected: u64::try_from(expected).map_err(|_| StoreError::EventSeqOverflow)?,
            actual: event.event_seq(),
        });
    }

    sqlx::query(
        "INSERT INTO backend_events \
         (deployment_id,event_seq,event_kind,payload,payload_sha256) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(identity.id)
    .bind(event_seq)
    .bind(event_kind(event))
    .bind(payload)
    .bind(payload_hash.as_slice())
    .execute(&mut *transaction)
    .await?;

    match event {
        BackendEvent::JobActivated { job, .. } => {
            sqlx::query(
                "INSERT INTO jobs (deployment_id,job_id,activation_event_seq,descriptor) \
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(identity.id)
            .bind(job.job_id.as_bytes().as_slice())
            .bind(event_seq)
            .bind(serde_json::to_value(job)?)
            .execute(&mut *transaction)
            .await?;
        }
        BackendEvent::ShareCommitted {
            receipt,
            job_id,
            identity: worker,
            target_le,
        } => {
            let descriptor_value = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT descriptor FROM jobs WHERE deployment_id=$1 AND job_id=$2",
            )
            .bind(identity.id)
            .bind(job_id.as_bytes().as_slice())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(StoreError::UnknownJob)?;
            let descriptor = serde_json::from_value(descriptor_value)?;
            receipt.validate_for_job(&descriptor)?;
            import_worker(&mut transaction, identity.id, worker).await?;
            let work = target_work(target_le)?;
            sqlx::query(
                "INSERT INTO shares \
                 (deployment_id,share_id,event_seq,job_id,account_id,worker_id,target_le,work,parent_hash_le) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,CAST($8 AS NUMERIC),$9)",
            )
            .bind(identity.id)
            .bind(receipt.share_id.as_bytes().as_slice())
            .bind(event_seq)
            .bind(job_id.as_bytes().as_slice())
            .bind(worker.account_id.get())
            .bind(worker.worker_id.get())
            .bind(target_le.as_bytes().as_slice())
            .bind(work.to_string())
            .bind(receipt.parent_hash_le.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await?;
            for winner in &receipt.winners {
                insert_winner(&mut transaction, identity.id, receipt, job_id, winner).await?;
            }
        }
        BackendEvent::WinnerObserved {
            share_id,
            job_id,
            winner,
            confirmations,
            ..
        } => {
            observe_winner(
                &mut transaction,
                identity.id,
                event_seq,
                share_id.as_bytes(),
                job_id.as_bytes(),
                winner,
                *confirmations,
            )
            .await?;
        }
        BackendEvent::WinnerMatured {
            share_id,
            job_id,
            winner,
            confirmations,
            ..
        } => {
            mature_winner(
                &mut transaction,
                identity.id,
                event_seq,
                share_id.as_bytes(),
                job_id.as_bytes(),
                winner,
                *confirmations,
            )
            .await?;
        }
        BackendEvent::WinnerOrphaned {
            share_id,
            job_id,
            winner,
            ..
        } => {
            reverse_winner(
                &mut transaction,
                identity.id,
                event_seq,
                WinnerReference {
                    share_id: share_id.as_bytes(),
                    job_id: job_id.as_bytes(),
                    winner,
                },
                WinnerReversal {
                    ledger_kind: "winner_orphaned",
                    next_state: "orphaned",
                },
            )
            .await?;
        }
        BackendEvent::WinnerQuarantined {
            share_id,
            job_id,
            winner,
            ..
        } => {
            if winner.chain != MergedChain::Wcash {
                return Err(StoreError::InvalidWinnerTransition);
            }
            reverse_winner(
                &mut transaction,
                identity.id,
                event_seq,
                WinnerReference {
                    share_id: share_id.as_bytes(),
                    job_id: job_id.as_bytes(),
                    winner,
                },
                WinnerReversal {
                    ledger_kind: "winner_quarantined",
                    next_state: "quarantined",
                },
            )
            .await?;
        }
        BackendEvent::WinnerRequeued {
            share_id,
            job_id,
            winner,
            ..
        } => {
            let row = load_winner(
                &mut transaction,
                identity.id,
                share_id.as_bytes(),
                job_id.as_bytes(),
                winner,
            )
            .await?;
            if row.state != "quarantined" || row.observation_event_seq.is_some() {
                return Err(StoreError::InvalidWinnerTransition);
            }
            update_winner_state(
                &mut transaction,
                identity.id,
                winner,
                "requeued",
                None,
                None,
            )
            .await?;
        }
        BackendEvent::JobInvalidated { .. } | BackendEvent::GenerationClosed { .. } => {}
    }

    sqlx::query(
        "UPDATE backend_cursors SET last_event_seq=$2, updated_at=clock_timestamp() \
         WHERE deployment_id=$1 AND last_event_seq=$3",
    )
    .bind(identity.id)
    .bind(event_seq)
    .bind(last_event_seq)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(ProjectionResult::Applied)
}

const fn event_kind(event: &BackendEvent) -> &'static str {
    match event {
        BackendEvent::JobActivated { .. } => "job_activated",
        BackendEvent::JobInvalidated { .. } => "job_invalidated",
        BackendEvent::GenerationClosed { .. } => "generation_closed",
        BackendEvent::ShareCommitted { .. } => "share_committed",
        BackendEvent::WinnerObserved { .. } => "winner_observed",
        BackendEvent::WinnerOrphaned { .. } => "winner_orphaned",
        BackendEvent::WinnerQuarantined { .. } => "winner_quarantined",
        BackendEvent::WinnerRequeued { .. } => "winner_requeued",
        BackendEvent::WinnerMatured { .. } => "winner_matured",
    }
}

async fn import_worker(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    worker: &wcash_pool_protocol::WorkerIdentity,
) -> Result<(), StoreError> {
    let account_id = worker.account_id.get();
    let worker_id = worker.worker_id.get();
    let account_login = format!("imported_{}", &account_id.simple().to_string()[..16]);
    let worker_label = format!("legacy_{}", &worker_id.simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO accounts (deployment_id,id,login,enabled) VALUES ($1,$2,$3,FALSE) \
         ON CONFLICT (deployment_id,id) DO NOTHING",
    )
    .bind(deployment_id)
    .bind(account_id)
    .bind(&account_login)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO workers \
         (deployment_id,id,account_id,label,canonical_login,enabled,revoked_at) \
         VALUES ($1,$2,$3,$4,$5,FALSE,clock_timestamp()) \
         ON CONFLICT (deployment_id,id) DO NOTHING",
    )
    .bind(deployment_id)
    .bind(worker_id)
    .bind(account_id)
    .bind(worker_label)
    .bind(&worker.label)
    .execute(&mut **transaction)
    .await?;
    let row = sqlx::query(
        "SELECT account_id, canonical_login FROM workers WHERE deployment_id=$1 AND id=$2",
    )
    .bind(deployment_id)
    .bind(worker_id)
    .fetch_one(&mut **transaction)
    .await?;
    if row.try_get::<Uuid, _>("account_id")? != account_id
        || row.try_get::<String, _>("canonical_login")? != worker.label
    {
        return Err(StoreError::WorkerAttributionConflict);
    }
    Ok(())
}

async fn insert_winner(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    receipt: &wcash_pool_protocol::ShareReceipt,
    job_id: &wcash_pool_protocol::Hex32,
    winner: &WinnerDescriptor,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO winners \
         (deployment_id,chain,block_hash_le,share_id,job_id,height,coinbase_txid_le,reward_zat, \
          maturity_confirmations,state) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'submitted')",
    )
    .bind(deployment_id)
    .bind(Chain::from(winner.chain).as_str())
    .bind(winner.block_hash_le.as_bytes().as_slice())
    .bind(receipt.share_id.as_bytes().as_slice())
    .bind(job_id.as_bytes().as_slice())
    .bind(i64::from(winner.height))
    .bind(winner.coinbase_txid_le.as_bytes().as_slice())
    .bind(i64::try_from(winner.reward_zat).map_err(|_| StoreError::MoneyOverflow)?)
    .bind(i32::try_from(winner.maturity_confirmations).map_err(|_| StoreError::MoneyOverflow)?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

struct WinnerRow {
    state: String,
    observation_event_seq: Option<i64>,
    maturity_event_seq: Option<i64>,
    share_event_seq: i64,
}

async fn load_winner(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    share_id: &[u8; 32],
    job_id: &[u8; 32],
    winner: &WinnerDescriptor,
) -> Result<WinnerRow, StoreError> {
    let row = sqlx::query(
        "SELECT w.share_id,w.job_id,w.height,w.coinbase_txid_le,w.reward_zat,w.maturity_confirmations, \
                w.state,w.active_observation_event_seq,w.active_maturity_event_seq,s.event_seq AS share_event_seq \
         FROM winners w JOIN shares s \
           ON (s.deployment_id,s.share_id)=(w.deployment_id,w.share_id) \
         WHERE w.deployment_id=$1 AND w.chain=$2 AND w.block_hash_le=$3 FOR UPDATE OF w",
    )
    .bind(deployment_id)
    .bind(Chain::from(winner.chain).as_str())
    .bind(winner.block_hash_le.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::UnknownWinner)?;
    let matches = row.try_get::<Vec<u8>, _>("share_id")? == share_id
        && row.try_get::<Vec<u8>, _>("job_id")? == job_id
        && row.try_get::<i64, _>("height")? == i64::from(winner.height)
        && row.try_get::<Vec<u8>, _>("coinbase_txid_le")? == winner.coinbase_txid_le.as_bytes()
        && row.try_get::<i64, _>("reward_zat")?
            == i64::try_from(winner.reward_zat).map_err(|_| StoreError::MoneyOverflow)?
        && row.try_get::<i32, _>("maturity_confirmations")?
            == i32::try_from(winner.maturity_confirmations)
                .map_err(|_| StoreError::MoneyOverflow)?;
    if !matches {
        return Err(StoreError::WinnerFactConflict);
    }
    Ok(WinnerRow {
        state: row.try_get("state")?,
        observation_event_seq: row.try_get("active_observation_event_seq")?,
        maturity_event_seq: row.try_get("active_maturity_event_seq")?,
        share_event_seq: row.try_get("share_event_seq")?,
    })
}

async fn observe_winner(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    event_seq: i64,
    share_id: &[u8; 32],
    job_id: &[u8; 32],
    winner: &WinnerDescriptor,
    confirmations: u32,
) -> Result<(), StoreError> {
    let row = load_winner(transaction, deployment_id, share_id, job_id, winner).await?;
    if !matches!(
        row.state.as_str(),
        "submitted" | "requeued" | "orphaned" | "quarantined"
    ) || row.observation_event_seq.is_some()
        || row.maturity_event_seq.is_some()
        || confirmations == 0
    {
        return Err(StoreError::InvalidWinnerTransition);
    }
    let chain = Chain::from(winner.chain);
    let policy = sqlx::query(
        "SELECT pplns_window_work::TEXT AS window_work,fee_bps,policy_version \
         FROM chain_policies WHERE deployment_id=$1 AND chain=$2",
    )
    .bind(deployment_id)
    .bind(chain.as_str())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::MissingChainPolicy(chain))?;
    let window_work = BigUint::from_str(&policy.try_get::<String, _>("window_work")?)
        .map_err(|_| StoreError::CorruptDatabaseState("PPLNS work window"))?;
    let fee_bps = u16::try_from(policy.try_get::<i32, _>("fee_bps")?)
        .map_err(|_| StoreError::CorruptDatabaseState("pool fee"))?;
    let policy_version = policy.try_get::<i64, _>("policy_version")?;

    let rows = sqlx::query(
        "SELECT share_id,account_id,work::TEXT AS work FROM shares \
         WHERE deployment_id=$1 AND event_seq <= $2 ORDER BY event_seq DESC LIMIT $3",
    )
    .bind(deployment_id)
    .bind(row.share_event_seq)
    .bind(MAX_PPLNS_SHARES)
    .fetch_all(&mut **transaction)
    .await?;
    let mut shares = Vec::with_capacity(rows.len());
    let mut available_work = BigUint::default();
    for row in &rows {
        let share_bytes = row.try_get::<Vec<u8>, _>("share_id")?;
        let share_id: [u8; 32] = share_bytes
            .try_into()
            .map_err(|_| StoreError::CorruptDatabaseState("share ID"))?;
        let work = BigUint::from_str(&row.try_get::<String, _>("work")?)
            .map_err(|_| StoreError::CorruptDatabaseState("share work"))?;
        available_work += &work;
        shares.push(WeightedShare {
            share_id,
            account_id: row.try_get("account_id")?,
            work,
        });
    }
    if i64::try_from(rows.len()).ok() == Some(MAX_PPLNS_SHARES) && available_work < window_work {
        return Err(StoreError::PplnsWindowTooLarge);
    }
    let plan = allocate_pplns(&shares, &window_work, winner.reward_zat, fee_bps)?;
    for allocation in &plan.accounts {
        sqlx::query(
            "INSERT INTO winner_allocations \
             (deployment_id,chain,block_hash_le,observation_event_seq,policy_version,account_id,selected_work,amount_zat) \
             VALUES ($1,$2,$3,$4,$5,$6,CAST($7 AS NUMERIC),$8)",
        )
        .bind(deployment_id)
        .bind(chain.as_str())
        .bind(winner.block_hash_le.as_bytes().as_slice())
        .bind(event_seq)
        .bind(policy_version)
        .bind(allocation.account_id)
        .bind(allocation.work.to_string())
        .bind(i64::try_from(allocation.amount_zat).map_err(|_| StoreError::MoneyOverflow)?)
        .execute(&mut **transaction)
        .await?;
    }
    let mut entries = Vec::with_capacity(plan.accounts.len() + 2);
    entries.push((None, "collector_immature_asset", as_i64(winner.reward_zat)?));
    for allocation in &plan.accounts {
        if allocation.amount_zat > 0 {
            entries.push((
                Some(allocation.account_id),
                "miner_immature",
                -as_i64(allocation.amount_zat)?,
            ));
        }
    }
    if plan.pool_fee_zat > 0 {
        entries.push((None, "pool_fee_unearned", -as_i64(plan.pool_fee_zat)?));
    }
    insert_ledger_transaction(
        transaction,
        deployment_id,
        chain,
        "winner_observed",
        Some(event_seq),
        &format!("{}:{}", chain.as_str(), winner.block_hash_le),
        &entries,
    )
    .await?;
    update_winner_state(
        transaction,
        deployment_id,
        winner,
        "observed",
        Some(event_seq),
        None,
    )
    .await
}

async fn mature_winner(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    event_seq: i64,
    share_id: &[u8; 32],
    job_id: &[u8; 32],
    winner: &WinnerDescriptor,
    confirmations: u32,
) -> Result<(), StoreError> {
    let row = load_winner(transaction, deployment_id, share_id, job_id, winner).await?;
    let observation = row
        .observation_event_seq
        .filter(|_| row.state == "observed" && row.maturity_event_seq.is_none())
        .ok_or(StoreError::InvalidWinnerTransition)?;
    let chain = Chain::from(winner.chain);
    let policy_confirmations = sqlx::query_scalar::<_, i32>(
        "SELECT required_confirmations FROM chain_policies WHERE deployment_id=$1 AND chain=$2",
    )
    .bind(deployment_id)
    .bind(chain.as_str())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::MissingChainPolicy(chain))?;
    let required = winner.maturity_confirmations.max(
        u32::try_from(policy_confirmations)
            .map_err(|_| StoreError::CorruptDatabaseState("required confirmations"))?,
    );
    if confirmations < required {
        return Err(StoreError::PrematureWinner {
            required,
            actual: confirmations,
        });
    }
    let allocations = sqlx::query(
        "SELECT account_id,amount_zat FROM winner_allocations \
         WHERE deployment_id=$1 AND chain=$2 AND block_hash_le=$3 AND observation_event_seq=$4 \
         ORDER BY account_id",
    )
    .bind(deployment_id)
    .bind(chain.as_str())
    .bind(winner.block_hash_le.as_bytes().as_slice())
    .bind(observation)
    .fetch_all(&mut **transaction)
    .await?;
    if allocations.is_empty() {
        return Err(StoreError::CorruptDatabaseState("winner allocations"));
    }
    let mut entries = Vec::with_capacity(allocations.len() * 2 + 2);
    entries.push((
        None,
        "collector_immature_asset",
        -as_i64(winner.reward_zat)?,
    ));
    entries.push((
        None,
        "collector_spendable_asset",
        as_i64(winner.reward_zat)?,
    ));
    let mut miner_total = 0u64;
    for allocation in allocations {
        let amount = u64::try_from(allocation.try_get::<i64, _>("amount_zat")?)
            .map_err(|_| StoreError::MoneyOverflow)?;
        miner_total = miner_total
            .checked_add(amount)
            .ok_or(StoreError::MoneyOverflow)?;
        if amount > 0 {
            let account_id = allocation.try_get::<Uuid, _>("account_id")?;
            entries.push((Some(account_id), "miner_immature", as_i64(amount)?));
            entries.push((Some(account_id), "miner_payable", -as_i64(amount)?));
        }
    }
    let pool_fee = winner
        .reward_zat
        .checked_sub(miner_total)
        .ok_or(StoreError::MoneyOverflow)?;
    if pool_fee > 0 {
        entries.push((None, "pool_fee_unearned", as_i64(pool_fee)?));
        entries.push((None, "pool_equity", -as_i64(pool_fee)?));
    }
    insert_ledger_transaction(
        transaction,
        deployment_id,
        chain,
        "winner_matured",
        Some(event_seq),
        &format!("{}:{}", chain.as_str(), winner.block_hash_le),
        &entries,
    )
    .await?;
    update_winner_state(
        transaction,
        deployment_id,
        winner,
        "matured",
        Some(observation),
        Some(event_seq),
    )
    .await
}

struct WinnerReference<'a> {
    share_id: &'a [u8; 32],
    job_id: &'a [u8; 32],
    winner: &'a WinnerDescriptor,
}

struct WinnerReversal {
    ledger_kind: &'static str,
    next_state: &'static str,
}

async fn reverse_winner(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    event_seq: i64,
    reference: WinnerReference<'_>,
    reversal: WinnerReversal,
) -> Result<(), StoreError> {
    let winner = reference.winner;
    let row = load_winner(
        transaction,
        deployment_id,
        reference.share_id,
        reference.job_id,
        winner,
    )
    .await?;
    if !matches!(row.state.as_str(), "observed" | "matured") {
        if reversal.next_state == "quarantined"
            && matches!(row.state.as_str(), "submitted" | "requeued" | "orphaned")
        {
            return update_winner_state(
                transaction,
                deployment_id,
                winner,
                reversal.next_state,
                None,
                None,
            )
            .await;
        }
        return Err(StoreError::InvalidWinnerTransition);
    }
    let chain = Chain::from(winner.chain);
    if row.maturity_event_seq.is_some() {
        // Serialize against batch creation/signing/broadcast. A deep coinbase
        // reorg with any payout exposure freezes new money movement until an
        // authoritative wallet reconciliation is implemented and audited.
        sqlx::query(
            "SELECT payouts_frozen FROM chain_safety_state \
             WHERE deployment_id=$1 AND chain=$2 FOR UPDATE",
        )
        .bind(deployment_id)
        .bind(chain.as_str())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(StoreError::MissingChainPolicy(chain))?;
        let exposed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM payout_batches \
             WHERE deployment_id=$1 AND chain=$2 AND state <> 'cancelled')",
        )
        .bind(deployment_id)
        .bind(chain.as_str())
        .fetch_one(&mut **transaction)
        .await?;
        if exposed {
            sqlx::query(
                "UPDATE chain_safety_state SET payouts_frozen=TRUE, \
                 frozen_by_backend_event_seq=$3,freeze_reason='matured_winner_reorg', \
                 updated_at=clock_timestamp() WHERE deployment_id=$1 AND chain=$2",
            )
            .bind(deployment_id)
            .bind(chain.as_str())
            .bind(event_seq)
            .execute(&mut **transaction)
            .await?;
        }
    }
    let mut source_events = Vec::with_capacity(2);
    if let Some(maturity) = row.maturity_event_seq {
        source_events.push(maturity);
    }
    if let Some(observation) = row.observation_event_seq {
        source_events.push(observation);
    }
    if source_events.is_empty() {
        return Err(StoreError::CorruptDatabaseState("active winner ledger"));
    }
    let rows = sqlx::query(
        "SELECT e.account_id,e.ledger_account,e.amount_zat \
         FROM ledger_entries e JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE t.deployment_id=$1 AND t.backend_event_seq = ANY($2) \
         ORDER BY t.backend_event_seq,e.line_no",
    )
    .bind(deployment_id)
    .bind(&source_events)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.is_empty() {
        return Err(StoreError::CorruptDatabaseState("active winner ledger"));
    }
    let entries = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<Option<Uuid>, _>("account_id")?,
                row.try_get::<String, _>("ledger_account")?,
                row.try_get::<i64, _>("amount_zat")?
                    .checked_neg()
                    .ok_or(StoreError::MoneyOverflow)?,
            ))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    insert_owned_ledger_transaction(
        transaction,
        deployment_id,
        chain,
        reversal.ledger_kind,
        Some(event_seq),
        &format!(
            "{}:{}",
            Chain::from(winner.chain).as_str(),
            winner.block_hash_le
        ),
        &entries,
    )
    .await?;
    update_winner_state(
        transaction,
        deployment_id,
        winner,
        reversal.next_state,
        None,
        None,
    )
    .await
}

async fn update_winner_state(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    winner: &WinnerDescriptor,
    state: &'static str,
    observation_event_seq: Option<i64>,
    maturity_event_seq: Option<i64>,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "UPDATE winners SET state=$4,active_observation_event_seq=$5,active_maturity_event_seq=$6 \
         WHERE deployment_id=$1 AND chain=$2 AND block_hash_le=$3",
    )
    .bind(deployment_id)
    .bind(Chain::from(winner.chain).as_str())
    .bind(winner.block_hash_le.as_bytes().as_slice())
    .bind(state)
    .bind(observation_event_seq)
    .bind(maturity_event_seq)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StoreError::UnknownWinner);
    }
    Ok(())
}

async fn insert_ledger_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    chain: Chain,
    kind: &'static str,
    backend_event_seq: Option<i64>,
    reference: &str,
    entries: &[(Option<Uuid>, &'static str, i64)],
) -> Result<Uuid, StoreError> {
    let owned = entries
        .iter()
        .map(|(account, ledger_account, amount)| (*account, (*ledger_account).to_owned(), *amount))
        .collect::<Vec<_>>();
    insert_owned_ledger_transaction(
        transaction,
        deployment_id,
        chain,
        kind,
        backend_event_seq,
        reference,
        &owned,
    )
    .await
}

async fn insert_owned_ledger_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    chain: Chain,
    kind: &'static str,
    backend_event_seq: Option<i64>,
    reference: &str,
    entries: &[(Option<Uuid>, String, i64)],
) -> Result<Uuid, StoreError> {
    if entries.is_empty()
        || entries.iter().any(|(_, _, amount)| *amount == 0)
        || entries.iter().try_fold(0i128, |sum, (_, _, amount)| {
            sum.checked_add(i128::from(*amount))
        }) != Some(0)
    {
        return Err(StoreError::UnbalancedLedger);
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,backend_event_seq,reference) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(deployment_id)
    .bind(id)
    .bind(chain.as_str())
    .bind(kind)
    .bind(backend_event_seq)
    .bind(reference)
    .execute(&mut **transaction)
    .await?;
    for (index, (account_id, ledger_account, amount_zat)) in entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO ledger_entries \
             (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(deployment_id)
        .bind(id)
        .bind(i32::try_from(index + 1).map_err(|_| StoreError::MoneyOverflow)?)
        .bind(account_id)
        .bind(ledger_account)
        .bind(amount_zat)
        .execute(&mut **transaction)
        .await?;
    }
    let seal = sqlx::query(
        "UPDATE ledger_transactions \
         SET sealed_at=clock_timestamp(),sealed_entry_count=$3 \
         WHERE deployment_id=$1 AND id=$2 AND sealed_at IS NULL",
    )
    .bind(deployment_id)
    .bind(id)
    .bind(i32::try_from(entries.len()).map_err(|_| StoreError::MoneyOverflow)?)
    .execute(&mut **transaction)
    .await?;
    if seal.rows_affected() != 1 {
        return Err(StoreError::UnbalancedLedger);
    }
    Ok(id)
}

fn as_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::MoneyOverflow)
}

/// Persistence, projection, or accounting failure. Every variant is terminal to
/// the current live event consumer; detailed causes belong only in private logs.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Deployment identifiers were missing or internally inconsistent.
    #[error("invalid deployment identity")]
    InvalidDeploymentIdentity,
    /// A stored deployment row did not exactly match runtime policy.
    #[error("persisted deployment identity does not match runtime policy")]
    DeploymentIdentityMismatch,
    /// A connected backend did not match the bound deployment.
    #[error("backend authority does not match the persisted deployment")]
    BackendAuthorityMismatch,
    /// PostgreSQL connection count was outside the reviewed range.
    #[error("database connection limit {0} is outside 1..=64")]
    InvalidConnectionLimit(u32),
    /// A replay page exceeded the bounded client contract.
    #[error("historical replay page contains {0} events; maximum is 1024")]
    ReplayBatchTooLarge(usize),
    /// Event sequence exceeded PostgreSQL's signed cursor representation.
    #[error("backend event sequence exceeds durable cursor capacity")]
    EventSeqOverflow,
    /// The projector observed a non-contiguous authoritative event.
    #[error("backend event sequence gap: expected {expected}, received {actual}")]
    EventSequenceGap {
        /// Next expected sequence.
        expected: u64,
        /// Supplied sequence.
        actual: u64,
    },
    /// A prior cursor carried different canonical event bytes.
    #[error("backend event {0} replayed with different content")]
    EventReplayConflict(u64),
    /// A share referred to a job not retained by the projector.
    #[error("share refers to an unknown job")]
    UnknownJob,
    /// A lifecycle event referred to an unknown winning proof.
    #[error("winner lifecycle refers to an unknown winner")]
    UnknownWinner,
    /// Immutable winner facts changed between backend events.
    #[error("winner lifecycle changed immutable block facts")]
    WinnerFactConflict,
    /// Backend attribution conflicts with an existing account/worker binding.
    #[error("backend worker attribution conflicts with persisted identity")]
    WorkerAttributionConflict,
    /// A winner lifecycle transition was out of order or ambiguous.
    #[error("invalid winner lifecycle transition")]
    InvalidWinnerTransition,
    /// Maturity was announced below either chain or pool confirmation policy.
    #[error("winner has {actual} confirmations; {required} are required")]
    PrematureWinner {
        /// Effective confirmation policy.
        required: u32,
        /// Backend observation.
        actual: u32,
    },
    /// A chain policy must exist before rewards can be credited.
    #[error("missing accounting policy for {0:?}")]
    MissingChainPolicy(Chain),
    /// A configured PPLNS window exceeded the bounded projection query.
    #[error("PPLNS window exceeds the maximum bounded share scan")]
    PplnsWindowTooLarge,
    /// A signed monetary value could not represent an atomic amount.
    #[error("monetary amount exceeds durable signed representation")]
    MoneyOverflow,
    /// Code attempted to create a non-conserving transaction.
    #[error("ledger transaction is empty, contains zero lines, or is unbalanced")]
    UnbalancedLedger,
    /// A login component was non-canonical.
    #[error("account and worker names must be lowercase ASCII letters, digits, '-' or '_'")]
    InvalidLoginComponent,
    /// Portal password verifier or account identity was malformed.
    #[error("invalid portal account credential")]
    InvalidPortalCredential,
    /// Browser session timestamps or security fence were invalid.
    #[error("invalid portal session")]
    InvalidPortalSession,
    /// A Unix timestamp did not fit PostgreSQL's signed representation.
    #[error("timestamp is outside the durable representation")]
    InvalidTimestamp,
    /// Requested account did not exist in this deployment.
    #[error("account does not exist")]
    UnknownAccount,
    /// Account ID and canonical login did not identify the same owner.
    #[error("account login does not match the requested owner")]
    AccountOwnershipMismatch,
    /// One account reached the reviewed bound on retained worker identities.
    #[error("account worker limit reached")]
    WorkerLimitReached,
    /// Chain address attestation or payout policy was malformed.
    #[error("invalid payout destination")]
    InvalidPayoutDestination,
    /// A replacement address did not use the required 24-72 hour hold.
    #[error("replacement payout destination requires a 24-72 hour hold")]
    InvalidReplacementHold,
    /// Chain accounting policy was malformed.
    #[error("invalid chain accounting policy")]
    InvalidChainPolicy,
    /// Persisted chain policy disagrees with immutable launch configuration.
    #[error("persisted chain accounting policy does not match launch configuration")]
    ChainPolicyMismatch,
    /// Launch must not silently introduce a pool or protocol fee.
    #[error("launch policy requires zero fees for both chains")]
    NonZeroLaunchFee,
    /// Batch request was malformed or incomplete.
    #[error("invalid payout batch")]
    InvalidPayoutBatch,
    /// No active, automatic destination currently has a payable balance at its threshold.
    #[error("no payable balances meet the active payout policy")]
    NoPayableBalances,
    /// Requested payout batch did not exist in this deployment.
    #[error("payout batch does not exist")]
    UnknownPayoutBatch,
    /// A payout state transition was out of order.
    #[error("invalid payout state transition")]
    InvalidPayoutTransition,
    /// Payout confirmation evidence was empty or outside durable bounds.
    #[error("invalid payout confirmation evidence")]
    InvalidPayoutConfirmation,
    /// Payout confirmation has not reached the immutable policy depth.
    #[error("payout has {actual} confirmations; {required} are required")]
    PrematurePayoutConfirmation {
        /// Required confirmation depth.
        required: u32,
        /// Observed confirmation depth.
        actual: u32,
    },
    /// A repeated request disagreed with immutable payout facts.
    #[error("payout replay changed immutable signed transaction facts")]
    PayoutReplayConflict,
    /// The signer proposed a network fee above the frozen chain-policy ceiling.
    #[error("payout network fee exceeds the immutable chain-policy ceiling")]
    ExcessivePayoutFee,
    /// A deployment-wide idempotency key was reused for the opposite chain.
    #[error("payout idempotency key is already bound to another chain")]
    PayoutIdempotencyConflict,
    /// The same on-chain transaction ID was attached to another chain batch.
    #[error("payout transaction ID is already attached to another batch")]
    PayoutTransactionConflict,
    /// Deep-reorg or wallet reconciliation safety gate blocks new movement.
    #[error("payout operations are frozen for {0:?}")]
    PayoutsFrozen(Chain),
    /// The collector wallet asset is smaller than the confirmed liability plus fee.
    #[error("collector wallet asset does not reconcile with the payout")]
    CollectorReconciliationFailed,
    /// Wallet observation lacked a current nonzero tip, digest, or bounded time window.
    #[error("wallet reconciliation observation is invalid or stale")]
    InvalidWalletObservation,
    /// An unresolved signed, broadcast, or reorged payment makes wallet balance ambiguous.
    #[error("wallet reconciliation is blocked by an unresolved payout")]
    WalletReconciliationBlocked,
    /// Reconciliation expired, belongs to another chain, or no longer matches the ledger.
    #[error("wallet reconciliation no longer matches the current ledger")]
    WalletReconciliationStale,
    /// A nonce reservation lacked an owner or positive count.
    #[error("invalid durable nonce reservation")]
    InvalidNonceReservation,
    /// A namespace lease duration was fractional or outside the reviewed bound.
    #[error("nonce namespace lease duration must be a whole 1..=300 seconds")]
    InvalidNonceLeaseDuration,
    /// Another live process currently owns this backend-global namespace.
    #[error("nonce namespace is already held by another live process")]
    NonceNamespaceAlreadyHeld,
    /// The claim expired, was released, or was superseded by another process.
    #[error("nonce namespace lease is no longer active")]
    NonceNamespaceLeaseLost,
    /// The monotonic acquisition generation exceeded PostgreSQL capacity.
    #[error("nonce namespace lease generation is exhausted")]
    NonceNamespaceLeaseGenerationExhausted,
    /// A nonce namespace has no remaining disjoint ranges.
    #[error("nonce namespace is exhausted")]
    NonceNamespaceExhausted,
    /// A database row violated an invariant expected by this revision.
    #[error("database contains invalid {0}")]
    CorruptDatabaseState(&'static str),
    /// PostgreSQL operation failed.
    #[error("PostgreSQL operation failed: {0}")]
    Database(#[from] sqlx::Error),
    /// Embedded schema migration failed.
    #[error("PostgreSQL migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// Strict backend protocol validation failed.
    #[error("backend event validation failed: {0}")]
    Protocol(#[from] ProtocolError),
    /// Canonical event serialization failed.
    #[error("backend event serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    /// PPLNS weighting or conservation failed.
    #[error(transparent)]
    Pplns(#[from] PplnsError),
    /// Mining token provisioning failed.
    #[error(transparent)]
    MiningToken(#[from] MiningTokenError),
    /// Core nonce range validation failed.
    #[error("invalid nonce cursor: {0}")]
    Nonce(#[from] wcash_pool_core::NoncePrefixError),
}

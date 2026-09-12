//! Crash-safe, chain-separated payout recovery.
//!
//! This module deliberately starts from payout batches already reserved by the
//! accounting store. Creating a batch requires a fresh, authenticated wallet
//! observation and is therefore outside this recovery boundary. At most one
//! incomplete batch is advanced per chain and call.

use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc};

use thiserror::Error;
use uuid::Uuid;
use wcash_pool_portal::{Asset, PayoutBatchRequest};
use wcash_pool_store::{
    Chain, PayoutBatch, PayoutBatchState, PostgresStore, SignedPayoutArtifact, StoreError,
};
use wcash_wec_payout_signer::{
    WalletFundSource, WecPayoutError, WecPayoutExecution, WecPayoutRequest, WecPayoutSigner,
};

const MAX_SIGNED_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;

/// Boxed asynchronous operation used by the settlement persistence boundary.
pub type SettlementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SettlementError>> + Send + 'a>>;

/// Boxed asynchronous operation used by a chain-specific wallet boundary.
pub type BoundaryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, BoundaryFailure>> + Send + 'a>>;

/// Privacy-preserving classification of a chain wallet failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum BoundaryFailure {
    /// No durable external result was produced; the exact operation may retry.
    #[error("wallet boundary is temporarily unavailable")]
    Retryable,
    /// An external operation may have committed; only the same batch may retry.
    #[error("wallet boundary outcome is ambiguous")]
    Ambiguous,
    /// The exact transaction was explicitly rejected and needs operator review.
    #[error("wallet boundary rejected the exact transaction")]
    Rejected,
    /// The batch identifier was previously bound to different immutable facts.
    #[error("wallet boundary detected an idempotency conflict")]
    Conflict,
    /// A response or durable journal violated the settlement contract.
    #[error("wallet boundary violated the settlement contract")]
    Invariant,
}

/// Failure to resume one exact payout batch.
#[derive(Debug, Error)]
pub enum SettlementError {
    /// PostgreSQL or its immutable payout facts could not be read or advanced.
    #[error("payout persistence operation {operation} failed")]
    Persistence {
        /// Stable operation label without miner or wallet data.
        operation: &'static str,
        /// Private diagnostic source; callers must not expose it to miners.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// The selected chain wallet did not safely complete the exact operation.
    #[error("{chain:?} payout boundary failed: {failure}")]
    Boundary {
        /// Chain whose wallet boundary failed.
        chain: Chain,
        /// Privacy-preserving failure class.
        failure: BoundaryFailure,
    },
    /// Store, signer, and transaction facts did not agree exactly.
    #[error("settlement invariant failed: {0}")]
    Invariant(&'static str),
}

impl SettlementError {
    fn persistence(operation: &'static str, source: StoreError) -> Self {
        Self::Persistence {
            operation,
            source: Box::new(source),
        }
    }
}

/// Rich signer result which can be persisted before the SQL state is marked
/// broadcast.
#[derive(Clone, Eq, PartialEq)]
pub struct RichPayoutExecution {
    /// Stable accounting batch identity.
    pub batch_id: Uuid,
    /// Asset attested by the chain-specific signer.
    pub asset: Asset,
    /// Commitment to the exact store-authored request.
    pub request_commitment: [u8; 32],
    /// Lowercase display-order transaction identifier.
    pub transaction_id: String,
    /// Display-order transaction identifier bytes.
    pub transaction_id_bytes: [u8; 32],
    /// Sum of the exact miner outputs.
    pub output_total_zat: u64,
    /// Digest of the unsigned transaction, not merely the accounting request.
    pub unsigned_digest: [u8; 32],
    /// Exact signed consensus transaction serialization.
    pub signed_transaction: Vec<u8>,
    /// Independently verified network fee in atomic units.
    pub network_fee_zat: u64,
}

impl RichPayoutExecution {
    #[allow(clippy::too_many_arguments)]
    fn new(
        batch_id: Uuid,
        asset: Asset,
        request_commitment: [u8; 32],
        transaction_id: String,
        transaction_id_bytes: [u8; 32],
        output_total_zat: u64,
        unsigned_digest: [u8; 32],
        signed_transaction: Vec<u8>,
        network_fee_zat: u64,
    ) -> Self {
        Self {
            batch_id,
            asset,
            request_commitment,
            transaction_id,
            transaction_id_bytes,
            output_total_zat,
            unsigned_digest,
            signed_transaction,
            network_fee_zat,
        }
    }

    fn validate_against(&self, request: &PayoutBatchRequest) -> Result<(), SettlementError> {
        let total = request
            .validate()
            .map_err(|_| SettlementError::Invariant("store-authored signer request"))?;
        let commitment = request
            .commitment()
            .map_err(|_| SettlementError::Invariant("store-authored request commitment"))?;
        if self.batch_id != request.batch_id
            || self.asset != request.asset
            || self.request_commitment != commitment
            || self.output_total_zat != total
            || self.unsigned_digest == [0; 32]
            || self.transaction_id_bytes == [0; 32]
            || self.signed_transaction.is_empty()
            || self.signed_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES
            || hex::encode(self.transaction_id_bytes) != self.transaction_id
        {
            return Err(SettlementError::Invariant("rich signer artifact"));
        }
        Ok(())
    }

    fn as_store_artifact(&self, chain: Chain) -> SignedPayoutArtifact {
        SignedPayoutArtifact {
            batch_id: self.batch_id,
            chain,
            state: PayoutBatchState::Signed,
            unsigned_digest: self.unsigned_digest,
            transaction_id: self.transaction_id_bytes,
            signed_transaction: self.signed_transaction.clone(),
            network_fee_zat: self.network_fee_zat,
        }
    }
}

impl fmt::Debug for RichPayoutExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RichPayoutExecution")
            .field("batch_id", &self.batch_id)
            .field("asset", &self.asset)
            .field("request_commitment", &self.request_commitment)
            .field("transaction_id", &self.transaction_id)
            .field("output_total_zat", &self.output_total_zat)
            .field("unsigned_digest", &self.unsigned_digest)
            .field("signed_transaction", &"[REDACTED]")
            .field("network_fee_zat", &self.network_fee_zat)
            .finish()
    }
}

impl From<WecPayoutExecution> for RichPayoutExecution {
    fn from(execution: WecPayoutExecution) -> Self {
        Self::new(
            execution.receipt.batch_id,
            execution.receipt.asset,
            execution.receipt.request_commitment,
            execution.receipt.transaction_id,
            execution.transaction_id_bytes,
            execution.receipt.output_total_zat,
            execution.unsigned_digest,
            execution.signed_transaction,
            execution.network_fee_zat,
        )
    }
}

/// Durable operations required by payout recovery.
pub trait SettlementStore: Send + Sync {
    /// Loads the oldest incomplete batch for one chain.
    fn oldest_resumable(&self, chain: Chain) -> SettlementFuture<'_, Option<PayoutBatch>>;

    /// Builds a signer request exclusively from immutable database facts.
    fn build_signer_request(&self, batch_id: Uuid) -> SettlementFuture<'_, PayoutBatchRequest>;

    /// Persists every rich signer artifact in the Draft-to-Signed transition.
    fn mark_signed(&self, artifact: &SignedPayoutArtifact) -> SettlementFuture<'_, ()>;

    /// Loads exact transaction bytes previously persisted by `mark_signed`.
    fn signed_artifact(&self, batch_id: Uuid)
        -> SettlementFuture<'_, Option<SignedPayoutArtifact>>;

    /// Advances Signed to Broadcast after a resolved exact-byte submission.
    fn mark_broadcast(&self, batch_id: Uuid) -> SettlementFuture<'_, ()>;
}

impl SettlementStore for PostgresStore {
    fn oldest_resumable(&self, chain: Chain) -> SettlementFuture<'_, Option<PayoutBatch>> {
        Box::pin(async move {
            let mut batches = self
                .list_resumable_payout_batches(chain, 1)
                .await
                .map_err(|error| SettlementError::persistence("list_resumable", error))?;
            Ok(batches.pop())
        })
    }

    fn build_signer_request(&self, batch_id: Uuid) -> SettlementFuture<'_, PayoutBatchRequest> {
        Box::pin(async move {
            PostgresStore::build_signer_request(self, batch_id)
                .await
                .map_err(|error| SettlementError::persistence("build_signer_request", error))
        })
    }

    fn mark_signed(&self, artifact: &SignedPayoutArtifact) -> SettlementFuture<'_, ()> {
        let artifact = artifact.clone();
        Box::pin(async move {
            self.mark_payout_signed(
                artifact.batch_id,
                &artifact.unsigned_digest,
                &artifact.transaction_id,
                &artifact.signed_transaction,
                artifact.network_fee_zat,
            )
            .await
            .map_err(|error| SettlementError::persistence("mark_signed", error))
        })
    }

    fn signed_artifact(
        &self,
        batch_id: Uuid,
    ) -> SettlementFuture<'_, Option<SignedPayoutArtifact>> {
        Box::pin(async move {
            self.signed_payout_artifact(batch_id)
                .await
                .map_err(|error| SettlementError::persistence("signed_artifact", error))
        })
    }

    fn mark_broadcast(&self, batch_id: Uuid) -> SettlementFuture<'_, ()> {
        Box::pin(async move {
            self.mark_payout_broadcast(batch_id)
                .await
                .map_err(|error| SettlementError::persistence("mark_broadcast", error))
        })
    }
}

/// A journaled chain signer which resolves the first broadcast before return.
///
/// An ambiguous return must retain the exact batch binding and signed bytes in
/// its own durable journal. A retry with the same batch must recover or submit
/// those bytes and must never construct a replacement.
pub trait ExactExecutionSigner: Send + Sync {
    /// Chain exclusively served by this signer.
    fn chain(&self) -> Chain;

    /// Executes or resumes one exact store-authored request.
    fn execute_exact(
        &self,
        request: &PayoutBatchRequest,
    ) -> BoundaryFuture<'_, RichPayoutExecution>;
}

/// Chain submission boundary for transaction bytes already persisted in SQL.
pub trait ExactTransactionBroadcaster: Send + Sync {
    /// Chain exclusively served by this broadcaster.
    fn chain(&self) -> Chain;

    /// Accepts or recognizes the exact transaction; ambiguity leaves Signed.
    fn rebroadcast_exact(&self, artifact: &SignedPayoutArtifact) -> BoundaryFuture<'_, ()>;
}

/// Adapter exposing the Wcash signer's rich, journaled execution.
pub struct WecExecutionSigner {
    signer: Arc<WecPayoutSigner>,
    source_account: Uuid,
}

impl WecExecutionSigner {
    /// Binds execution to one Wcash collector account.
    pub fn new(signer: Arc<WecPayoutSigner>, source_account: Uuid) -> Self {
        Self {
            signer,
            source_account,
        }
    }
}

impl ExactExecutionSigner for WecExecutionSigner {
    fn chain(&self) -> Chain {
        Chain::Wcash
    }

    fn execute_exact(
        &self,
        request: &PayoutBatchRequest,
    ) -> BoundaryFuture<'_, RichPayoutExecution> {
        let signer = Arc::clone(&self.signer);
        let source_account = self.source_account;
        let request = request.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                signer.execute(&WecPayoutRequest {
                    batch: request,
                    source_account,
                    fund_source: WalletFundSource::Ironwood,
                })
            })
            .await
            .map_err(|_| BoundaryFailure::Ambiguous)?
            .map(RichPayoutExecution::from)
            .map_err(map_wec_error)
        })
    }
}

/// Observable result of advancing the oldest incomplete batch on one chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeOutcome {
    /// No incomplete batch exists.
    Idle,
    /// A draft or signed batch is now durably recorded as broadcast.
    Broadcast {
        /// Exact batch identity.
        batch_id: Uuid,
        /// Independently settled chain.
        chain: Chain,
        /// Display-order transaction identifier.
        transaction_id: [u8; 32],
    },
    /// Broadcast is already durable; confirmation remains chain-authoritative.
    AwaitingConfirmation {
        /// Exact batch identity.
        batch_id: Uuid,
        /// Independently settled chain.
        chain: Chain,
        /// Display-order transaction identifier.
        transaction_id: [u8; 32],
    },
    /// A confirmed payout was reorged and the chain remains frozen.
    FrozenAfterReorg {
        /// Exact batch identity.
        batch_id: Uuid,
        /// Independently settled chain.
        chain: Chain,
        /// Display-order transaction identifier.
        transaction_id: [u8; 32],
    },
    /// A terminal row was returned unexpectedly and was not changed.
    Terminal {
        /// Exact batch identity.
        batch_id: Uuid,
        /// Terminal state.
        state: PayoutBatchState,
    },
}

struct ChainBoundary {
    signer: Arc<dyn ExactExecutionSigner>,
    broadcaster: Arc<dyn ExactTransactionBroadcaster>,
}

/// Resumes exact payouts without crossing wallet, asset, or chain boundaries.
pub struct SettlementOrchestrator {
    store: Arc<dyn SettlementStore>,
    wec: ChainBoundary,
    zec: ChainBoundary,
}

impl SettlementOrchestrator {
    /// Constructs a coordinator only when all four boundaries advertise their
    /// required chain. This prevents fallback to the other chain's wallet.
    pub fn new(
        store: Arc<dyn SettlementStore>,
        wec_signer: Arc<dyn ExactExecutionSigner>,
        wec_broadcaster: Arc<dyn ExactTransactionBroadcaster>,
        zec_signer: Arc<dyn ExactExecutionSigner>,
        zec_broadcaster: Arc<dyn ExactTransactionBroadcaster>,
    ) -> Result<Self, SettlementError> {
        if wec_signer.chain() != Chain::Wcash
            || wec_broadcaster.chain() != Chain::Wcash
            || zec_signer.chain() != Chain::Zcash
            || zec_broadcaster.chain() != Chain::Zcash
        {
            return Err(SettlementError::Invariant("chain boundary binding"));
        }
        Ok(Self {
            store,
            wec: ChainBoundary {
                signer: wec_signer,
                broadcaster: wec_broadcaster,
            },
            zec: ChainBoundary {
                signer: zec_signer,
                broadcaster: zec_broadcaster,
            },
        })
    }

    /// Advances at most the oldest incomplete batch for `chain`.
    ///
    /// Keeping a single in-flight batch per chain prevents a later payout from
    /// overtaking an ambiguous or reorged transaction. WEC and ZEC may call this
    /// method independently, so a fault on one chain does not invoke or mutate
    /// the other chain's wallet.
    pub async fn resume_next(&self, chain: Chain) -> Result<ResumeOutcome, SettlementError> {
        let Some(batch) = self.store.oldest_resumable(chain).await? else {
            return Ok(ResumeOutcome::Idle);
        };
        if batch.chain != chain {
            return Err(SettlementError::Invariant("resumable batch chain"));
        }
        let boundary = self.boundary(chain);
        match batch.state {
            PayoutBatchState::Draft => self.resume_draft(batch, boundary).await,
            PayoutBatchState::Signed => self.resume_signed(batch, boundary).await,
            PayoutBatchState::Broadcast => {
                let artifact = self.load_exact_artifact(&batch).await?;
                Ok(ResumeOutcome::AwaitingConfirmation {
                    batch_id: batch.id,
                    chain,
                    transaction_id: artifact.transaction_id,
                })
            }
            PayoutBatchState::Reorged => {
                let artifact = self.load_exact_artifact(&batch).await?;
                Ok(ResumeOutcome::FrozenAfterReorg {
                    batch_id: batch.id,
                    chain,
                    transaction_id: artifact.transaction_id,
                })
            }
            PayoutBatchState::Confirmed | PayoutBatchState::Cancelled => {
                Ok(ResumeOutcome::Terminal {
                    batch_id: batch.id,
                    state: batch.state,
                })
            }
        }
    }

    fn boundary(&self, chain: Chain) -> &ChainBoundary {
        match chain {
            Chain::Wcash => &self.wec,
            Chain::Zcash => &self.zec,
        }
    }

    async fn resume_draft(
        &self,
        batch: PayoutBatch,
        boundary: &ChainBoundary,
    ) -> Result<ResumeOutcome, SettlementError> {
        let request = self.store.build_signer_request(batch.id).await?;
        if request.batch_id != batch.id || request.asset != asset_for_chain(batch.chain) {
            return Err(SettlementError::Invariant("signer request batch binding"));
        }
        let execution = boundary
            .signer
            .execute_exact(&request)
            .await
            .map_err(|failure| SettlementError::Boundary {
                chain: batch.chain,
                failure,
            })?;
        execution.validate_against(&request)?;
        let artifact = execution.as_store_artifact(batch.chain);
        self.store.mark_signed(&artifact).await?;
        self.store.mark_broadcast(batch.id).await?;
        Ok(ResumeOutcome::Broadcast {
            batch_id: batch.id,
            chain: batch.chain,
            transaction_id: artifact.transaction_id,
        })
    }

    async fn resume_signed(
        &self,
        batch: PayoutBatch,
        boundary: &ChainBoundary,
    ) -> Result<ResumeOutcome, SettlementError> {
        let artifact = self.load_exact_artifact(&batch).await?;
        boundary
            .broadcaster
            .rebroadcast_exact(&artifact)
            .await
            .map_err(|failure| SettlementError::Boundary {
                chain: batch.chain,
                failure,
            })?;
        self.store.mark_broadcast(batch.id).await?;
        Ok(ResumeOutcome::Broadcast {
            batch_id: batch.id,
            chain: batch.chain,
            transaction_id: artifact.transaction_id,
        })
    }

    async fn load_exact_artifact(
        &self,
        batch: &PayoutBatch,
    ) -> Result<SignedPayoutArtifact, SettlementError> {
        let artifact = self
            .store
            .signed_artifact(batch.id)
            .await?
            .ok_or(SettlementError::Invariant("missing signed payout artifact"))?;
        if artifact.batch_id != batch.id
            || artifact.chain != batch.chain
            || artifact.state != batch.state
            || artifact.unsigned_digest == [0; 32]
            || artifact.transaction_id == [0; 32]
            || artifact.signed_transaction.is_empty()
            || artifact.signed_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES
        {
            return Err(SettlementError::Invariant("stored payout artifact"));
        }
        Ok(artifact)
    }
}

fn asset_for_chain(chain: Chain) -> Asset {
    match chain {
        Chain::Wcash => Asset::Wec,
        Chain::Zcash => Asset::Zec,
    }
}

fn map_wec_error(error: WecPayoutError) -> BoundaryFailure {
    match error {
        WecPayoutError::WalletUnavailable | WecPayoutError::JournalUnavailable => {
            BoundaryFailure::Retryable
        }
        WecPayoutError::WalletAmbiguous
        | WecPayoutError::BroadcastAmbiguous
        | WecPayoutError::Interrupted => BoundaryFailure::Ambiguous,
        WecPayoutError::WalletRejected | WecPayoutError::BroadcastRejected => {
            BoundaryFailure::Rejected
        }
        WecPayoutError::IdempotencyConflict => BoundaryFailure::Conflict,
        WecPayoutError::InvalidRequest
        | WecPayoutError::WrongAsset
        | WecPayoutError::WrongNetwork
        | WecPayoutError::WrongAccount
        | WecPayoutError::WrongFundSource
        | WecPayoutError::UnsafeCredential
        | WecPayoutError::JournalCorrupt
        | WecPayoutError::WalletProtocolViolation => BoundaryFailure::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::Mutex,
    };

    use wcash_pool_portal::{ChainNetwork, PayoutOutput, ReceiverKind as PortalReceiverKind};
    use wcash_pool_store::{PayoutInstruction, ReceiverKind as StoreReceiverKind};

    use super::*;

    #[derive(Default)]
    struct FakeState {
        batches: HashMap<ChainKey, PayoutBatch>,
        requests: HashMap<Uuid, PayoutBatchRequest>,
        artifacts: HashMap<Uuid, SignedPayoutArtifact>,
        transitions: Vec<&'static str>,
        fail_mark_signed_after_commit: bool,
        fail_mark_broadcast_before_commit: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum ChainKey {
        Wec,
        Zec,
    }

    impl From<Chain> for ChainKey {
        fn from(chain: Chain) -> Self {
            match chain {
                Chain::Wcash => Self::Wec,
                Chain::Zcash => Self::Zec,
            }
        }
    }

    #[derive(Default)]
    struct FakeStore {
        state: Mutex<FakeState>,
    }

    #[derive(Debug, Error)]
    #[error("injected persistence failure")]
    struct InjectedStoreError;

    fn injected(operation: &'static str) -> SettlementError {
        SettlementError::Persistence {
            operation,
            source: Box::new(InjectedStoreError),
        }
    }

    impl SettlementStore for FakeStore {
        fn oldest_resumable(&self, chain: Chain) -> SettlementFuture<'_, Option<PayoutBatch>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .map_err(|_| SettlementError::Invariant("fake store lock"))?
                    .batches
                    .get(&chain.into())
                    .cloned())
            })
        }

        fn build_signer_request(&self, batch_id: Uuid) -> SettlementFuture<'_, PayoutBatchRequest> {
            Box::pin(async move {
                self.state
                    .lock()
                    .map_err(|_| SettlementError::Invariant("fake store lock"))?
                    .requests
                    .get(&batch_id)
                    .cloned()
                    .ok_or(SettlementError::Invariant("fake signer request"))
            })
        }

        fn mark_signed(&self, artifact: &SignedPayoutArtifact) -> SettlementFuture<'_, ()> {
            let artifact = artifact.clone();
            Box::pin(async move {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| SettlementError::Invariant("fake store lock"))?;
                let batch = state
                    .batches
                    .get_mut(&artifact.chain.into())
                    .ok_or(SettlementError::Invariant("fake batch"))?;
                batch.state = PayoutBatchState::Signed;
                state.artifacts.insert(artifact.batch_id, artifact);
                state.transitions.push("signed");
                if state.fail_mark_signed_after_commit {
                    state.fail_mark_signed_after_commit = false;
                    return Err(injected("mark_signed"));
                }
                Ok(())
            })
        }

        fn signed_artifact(
            &self,
            batch_id: Uuid,
        ) -> SettlementFuture<'_, Option<SignedPayoutArtifact>> {
            Box::pin(async move {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| SettlementError::Invariant("fake store lock"))?;
                let mut artifact = state.artifacts.get(&batch_id).cloned();
                if let Some(artifact) = &mut artifact {
                    if let Some(batch) = state.batches.get(&artifact.chain.into()) {
                        artifact.state = batch.state;
                    }
                }
                Ok(artifact)
            })
        }

        fn mark_broadcast(&self, batch_id: Uuid) -> SettlementFuture<'_, ()> {
            Box::pin(async move {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| SettlementError::Invariant("fake store lock"))?;
                if state.fail_mark_broadcast_before_commit {
                    state.fail_mark_broadcast_before_commit = false;
                    return Err(injected("mark_broadcast"));
                }
                let key = state
                    .batches
                    .iter()
                    .find_map(|(key, batch)| (batch.id == batch_id).then_some(*key))
                    .ok_or(SettlementError::Invariant("fake batch"))?;
                state
                    .batches
                    .get_mut(&key)
                    .ok_or(SettlementError::Invariant("fake batch"))?
                    .state = PayoutBatchState::Broadcast;
                state.transitions.push("broadcast");
                Ok(())
            })
        }
    }

    struct FakeSigner {
        chain: Chain,
        calls: Mutex<Vec<PayoutBatchRequest>>,
        results: Mutex<VecDeque<Result<RichPayoutExecution, BoundaryFailure>>>,
    }

    impl FakeSigner {
        fn new(
            chain: Chain,
            results: impl IntoIterator<Item = Result<RichPayoutExecution, BoundaryFailure>>,
        ) -> Self {
            Self {
                chain,
                calls: Mutex::new(Vec::new()),
                results: Mutex::new(results.into_iter().collect()),
            }
        }

        fn calls(&self) -> Vec<PayoutBatchRequest> {
            self.calls
                .lock()
                .map_or_else(|_| Vec::new(), |calls| calls.clone())
        }
    }

    impl ExactExecutionSigner for FakeSigner {
        fn chain(&self) -> Chain {
            self.chain
        }

        fn execute_exact(
            &self,
            request: &PayoutBatchRequest,
        ) -> BoundaryFuture<'_, RichPayoutExecution> {
            let request = request.clone();
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| BoundaryFailure::Invariant)?
                    .push(request);
                self.results
                    .lock()
                    .map_err(|_| BoundaryFailure::Invariant)?
                    .pop_front()
                    .unwrap_or(Err(BoundaryFailure::Invariant))
            })
        }
    }

    struct FakeBroadcaster {
        chain: Chain,
        calls: Mutex<Vec<SignedPayoutArtifact>>,
        results: Mutex<VecDeque<Result<(), BoundaryFailure>>>,
    }

    impl FakeBroadcaster {
        fn new(
            chain: Chain,
            results: impl IntoIterator<Item = Result<(), BoundaryFailure>>,
        ) -> Self {
            Self {
                chain,
                calls: Mutex::new(Vec::new()),
                results: Mutex::new(results.into_iter().collect()),
            }
        }

        fn calls(&self) -> Vec<SignedPayoutArtifact> {
            self.calls
                .lock()
                .map_or_else(|_| Vec::new(), |calls| calls.clone())
        }
    }

    impl ExactTransactionBroadcaster for FakeBroadcaster {
        fn chain(&self) -> Chain {
            self.chain
        }

        fn rebroadcast_exact(&self, artifact: &SignedPayoutArtifact) -> BoundaryFuture<'_, ()> {
            let artifact = artifact.clone();
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| BoundaryFailure::Invariant)?
                    .push(artifact);
                self.results
                    .lock()
                    .map_err(|_| BoundaryFailure::Invariant)?
                    .pop_front()
                    .unwrap_or(Err(BoundaryFailure::Invariant))
            })
        }
    }

    struct Fixture {
        store: Arc<FakeStore>,
        wec_signer: Arc<FakeSigner>,
        zec_signer: Arc<FakeSigner>,
        wec_broadcaster: Arc<FakeBroadcaster>,
        zec_broadcaster: Arc<FakeBroadcaster>,
        orchestrator: SettlementOrchestrator,
    }

    impl Fixture {
        fn new(
            wec_results: Vec<Result<RichPayoutExecution, BoundaryFailure>>,
        ) -> Result<Self, SettlementError> {
            let store = Arc::new(FakeStore::default());
            let wec_request = request(Asset::Wec);
            let zec_request = request(Asset::Zec);
            {
                let mut state = store
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                state.batches.insert(ChainKey::Wec, batch(&wec_request));
                state.batches.insert(ChainKey::Zec, batch(&zec_request));
                state
                    .requests
                    .insert(wec_request.batch_id, wec_request.clone());
                state
                    .requests
                    .insert(zec_request.batch_id, zec_request.clone());
            }
            let wec_signer = Arc::new(FakeSigner::new(Chain::Wcash, wec_results));
            let zec_signer = Arc::new(FakeSigner::new(
                Chain::Zcash,
                [Ok(execution(&zec_request, 0x22))],
            ));
            let wec_broadcaster = Arc::new(FakeBroadcaster::new(Chain::Wcash, [Ok(()), Ok(())]));
            let zec_broadcaster = Arc::new(FakeBroadcaster::new(Chain::Zcash, [Ok(()), Ok(())]));
            let orchestrator = SettlementOrchestrator::new(
                store.clone(),
                wec_signer.clone(),
                wec_broadcaster.clone(),
                zec_signer.clone(),
                zec_broadcaster.clone(),
            )?;
            Ok(Self {
                store,
                wec_signer,
                zec_signer,
                wec_broadcaster,
                zec_broadcaster,
                orchestrator,
            })
        }
    }

    fn request(asset: Asset) -> PayoutBatchRequest {
        PayoutBatchRequest {
            batch_id: Uuid::new_v4(),
            asset,
            network: ChainNetwork::Testnet,
            ledger_root: [0x31; 32],
            reconciliation_id: Uuid::new_v4(),
            outputs: vec![PayoutOutput {
                allocation_id: Uuid::new_v4(),
                canonical_address: match asset {
                    Asset::Wec => "wtestsapling1recipient".to_owned(),
                    Asset::Zec => "ztestsapling1recipient".to_owned(),
                },
                receiver_kind: PortalReceiverKind::Ironwood,
                amount_zat: 12_500,
            }],
        }
    }

    fn batch(request: &PayoutBatchRequest) -> PayoutBatch {
        let chain = match request.asset {
            Asset::Wec => Chain::Wcash,
            Asset::Zec => Chain::Zcash,
        };
        PayoutBatch {
            id: request.batch_id,
            chain,
            state: PayoutBatchState::Draft,
            policy_version: 1,
            reconciliation_id: request.reconciliation_id,
            ledger_root: request.ledger_root,
            ledger_sequence_cutoff: 7,
            miner_total_zat: 12_500,
            outputs: vec![PayoutInstruction {
                allocation_id: request.outputs[0].allocation_id,
                account_id: Uuid::new_v4(),
                destination_id: Uuid::new_v4(),
                receiver_kind: StoreReceiverKind::Ironwood,
                address: request.outputs[0].canonical_address.clone(),
                amount_zat: request.outputs[0].amount_zat,
            }],
        }
    }

    fn execution(request: &PayoutBatchRequest, byte: u8) -> RichPayoutExecution {
        RichPayoutExecution::new(
            request.batch_id,
            request.asset,
            request.commitment().unwrap_or([0; 32]),
            hex::encode([byte; 32]),
            [byte; 32],
            request.validate().unwrap_or_default(),
            [byte.wrapping_add(1); 32],
            vec![byte; 96],
            10,
        )
    }

    #[tokio::test]
    async fn draft_persists_rich_artifact_before_broadcast_state() -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let fixture = Fixture::new(vec![Ok(execution(&request, 0x11))])?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.batches.insert(ChainKey::Wec, batch(&request));
            state.requests.insert(request.batch_id, request.clone());
        }
        let outcome = fixture.orchestrator.resume_next(Chain::Wcash).await?;
        assert!(matches!(outcome, ResumeOutcome::Broadcast { .. }));
        let state = fixture
            .store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.transitions, ["signed", "broadcast"]);
        assert_eq!(
            state
                .artifacts
                .get(&request.batch_id)
                .map(|artifact| artifact.signed_transaction.as_slice()),
            Some(vec![0x11; 96].as_slice())
        );
        assert!(fixture.zec_signer.calls().is_empty());
        assert!(fixture.zec_broadcaster.calls().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn zec_never_falls_back_to_wec_boundaries() -> Result<(), SettlementError> {
        let fixture = Fixture::new(vec![Err(BoundaryFailure::Invariant)])?;
        let outcome = fixture.orchestrator.resume_next(Chain::Zcash).await?;
        assert!(matches!(
            outcome,
            ResumeOutcome::Broadcast {
                chain: Chain::Zcash,
                ..
            }
        ));
        assert!(fixture.wec_signer.calls().is_empty());
        assert!(fixture.wec_broadcaster.calls().is_empty());
        assert_eq!(fixture.zec_signer.calls().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn ambiguous_draft_retries_the_identical_store_request() -> Result<(), SettlementError> {
        let seed_request = request(Asset::Wec);
        let fixture = Fixture::new(vec![
            Err(BoundaryFailure::Ambiguous),
            Ok(execution(&seed_request, 0x44)),
        ])?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.batches.insert(ChainKey::Wec, batch(&seed_request));
            state
                .requests
                .insert(seed_request.batch_id, seed_request.clone());
        }
        let first = fixture.orchestrator.resume_next(Chain::Wcash).await;
        assert!(matches!(
            first,
            Err(SettlementError::Boundary {
                failure: BoundaryFailure::Ambiguous,
                ..
            })
        ));
        assert!(fixture
            .store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .transitions
            .is_empty());
        fixture.orchestrator.resume_next(Chain::Wcash).await?;
        let calls = fixture.wec_signer.calls();
        assert_eq!(calls, [seed_request.clone(), seed_request]);
        Ok(())
    }

    #[tokio::test]
    async fn committed_signed_state_after_lost_ack_rebroadcasts_only_stored_bytes(
    ) -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let fixture = Fixture::new(vec![Ok(execution(&request, 0x55))])?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.batches.insert(ChainKey::Wec, batch(&request));
            state.requests.insert(request.batch_id, request.clone());
            state.fail_mark_signed_after_commit = true;
        }
        assert!(matches!(
            fixture.orchestrator.resume_next(Chain::Wcash).await,
            Err(SettlementError::Persistence {
                operation: "mark_signed",
                ..
            })
        ));
        assert_eq!(fixture.wec_signer.calls().len(), 1);
        fixture.orchestrator.resume_next(Chain::Wcash).await?;
        assert_eq!(fixture.wec_signer.calls().len(), 1);
        let calls = fixture.wec_broadcaster.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].signed_transaction, vec![0x55; 96]);
        Ok(())
    }

    #[tokio::test]
    async fn mark_broadcast_failure_keeps_signed_artifact_for_exact_retry(
    ) -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let fixture = Fixture::new(vec![Ok(execution(&request, 0x66))])?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.batches.insert(ChainKey::Wec, batch(&request));
            state.requests.insert(request.batch_id, request);
            state.fail_mark_broadcast_before_commit = true;
        }
        assert!(matches!(
            fixture.orchestrator.resume_next(Chain::Wcash).await,
            Err(SettlementError::Persistence {
                operation: "mark_broadcast",
                ..
            })
        ));
        fixture.orchestrator.resume_next(Chain::Wcash).await?;
        assert_eq!(fixture.wec_signer.calls().len(), 1);
        assert_eq!(fixture.wec_broadcaster.calls().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn ambiguous_signed_rebroadcast_never_returns_to_signer() -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let store = Arc::new(FakeStore::default());
        {
            let mut state = store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let mut payout = batch(&request);
            payout.state = PayoutBatchState::Signed;
            state.batches.insert(ChainKey::Wec, payout);
            state.artifacts.insert(
                request.batch_id,
                execution(&request, 0x6a).as_store_artifact(Chain::Wcash),
            );
        }
        let wec_signer = Arc::new(FakeSigner::new(Chain::Wcash, Vec::new()));
        let wec_broadcaster = Arc::new(FakeBroadcaster::new(
            Chain::Wcash,
            [Err(BoundaryFailure::Ambiguous), Ok(())],
        ));
        let orchestrator = SettlementOrchestrator::new(
            store,
            wec_signer.clone(),
            wec_broadcaster.clone(),
            Arc::new(FakeSigner::new(Chain::Zcash, Vec::new())),
            Arc::new(FakeBroadcaster::new(Chain::Zcash, Vec::new())),
        )?;
        assert!(matches!(
            orchestrator.resume_next(Chain::Wcash).await,
            Err(SettlementError::Boundary {
                failure: BoundaryFailure::Ambiguous,
                ..
            })
        ));
        orchestrator.resume_next(Chain::Wcash).await?;
        assert!(wec_signer.calls().is_empty());
        let calls = wec_broadcaster.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].signed_transaction, calls[1].signed_transaction);
        assert_eq!(calls[0].transaction_id, calls[1].transaction_id);
        Ok(())
    }

    #[tokio::test]
    async fn broadcast_waits_for_authoritative_confirmation_without_resigning(
    ) -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let fixture = Fixture::new(Vec::new())?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let mut payout = batch(&request);
            payout.state = PayoutBatchState::Broadcast;
            state.batches.insert(ChainKey::Wec, payout);
            let mut artifact = execution(&request, 0x77).as_store_artifact(Chain::Wcash);
            artifact.state = PayoutBatchState::Broadcast;
            state.artifacts.insert(request.batch_id, artifact);
        }
        let outcome = fixture.orchestrator.resume_next(Chain::Wcash).await?;
        assert!(matches!(
            outcome,
            ResumeOutcome::AwaitingConfirmation { .. }
        ));
        assert!(fixture.wec_signer.calls().is_empty());
        assert!(fixture.wec_broadcaster.calls().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn reorged_batch_stays_frozen_for_authoritative_reconciliation(
    ) -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let fixture = Fixture::new(Vec::new())?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let mut payout = batch(&request);
            payout.state = PayoutBatchState::Reorged;
            state.batches.insert(ChainKey::Wec, payout);
            let mut artifact = execution(&request, 0x78).as_store_artifact(Chain::Wcash);
            artifact.state = PayoutBatchState::Reorged;
            state.artifacts.insert(request.batch_id, artifact);
        }
        let outcome = fixture.orchestrator.resume_next(Chain::Wcash).await?;
        assert!(matches!(outcome, ResumeOutcome::FrozenAfterReorg { .. }));
        assert!(fixture.wec_signer.calls().is_empty());
        assert!(fixture.wec_broadcaster.calls().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn signer_artifact_mismatch_never_reaches_persistence() -> Result<(), SettlementError> {
        let request = request(Asset::Wec);
        let mut wrong = execution(&request, 0x33);
        wrong.output_total_zat += 1;
        let fixture = Fixture::new(vec![Ok(wrong)])?;
        {
            let mut state = fixture
                .store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.batches.insert(ChainKey::Wec, batch(&request));
            state.requests.insert(request.batch_id, request);
        }
        assert!(matches!(
            fixture.orchestrator.resume_next(Chain::Wcash).await,
            Err(SettlementError::Invariant("rich signer artifact"))
        ));
        assert!(fixture
            .store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .transitions
            .is_empty());
        Ok(())
    }

    #[test]
    fn constructor_rejects_cross_chain_boundary_wiring() {
        let store = Arc::new(FakeStore::default());
        let wrong = Arc::new(FakeSigner::new(Chain::Zcash, Vec::new()));
        let wec_broadcaster = Arc::new(FakeBroadcaster::new(Chain::Wcash, Vec::new()));
        let zec_signer = Arc::new(FakeSigner::new(Chain::Zcash, Vec::new()));
        let zec_broadcaster = Arc::new(FakeBroadcaster::new(Chain::Zcash, Vec::new()));
        assert!(matches!(
            SettlementOrchestrator::new(store, wrong, wec_broadcaster, zec_signer, zec_broadcaster,),
            Err(SettlementError::Invariant("chain boundary binding"))
        ));
    }

    #[test]
    fn debug_output_never_contains_signed_transaction_bytes() {
        let request = request(Asset::Wec);
        let execution = execution(&request, 0xab);
        let debug = format!("{execution:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&"ab".repeat(96)));
    }
}

//! Conservative WEC-only recovery of expired signed payouts.
//!
//! Quarantine retains the entire original pending liability. Only authoritative
//! non-inclusion beyond the pinned Wolf finalized frontier permits its release.
//! Fresh payments never borrow that reserve. This module has no mining handle.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;
use wcash_pool_store::{
    Chain, PayoutBatchState, PayoutConfirmation, PayoutExpiryCandidate, PayoutExpiryEvidence,
    PostgresStore, StoreError,
};
use wcash_wec_payout_signer::{
    WalletFundSource, WecPayoutRequest, WecPayoutSigner, WecPreparedPayout,
};

use crate::payout_runtime::{ObservationFailure, ObservationFuture, PayoutRuntimeError};

/// One held payout plus one active payout. Further recovery is fail-closed,
/// rather than growing the worker's bounded shutdown/lease duration.
pub(crate) const MAX_EXPIRY_CANDIDATES: u32 = 2;
/// Pinned Wolf WEC state rollback window (3e708002), plus one completed writer
/// iteration. This is node-local finality, not universal chain finality.
pub(crate) const WCASH_EXPIRY_FINALITY_DEPTH: u32 = 1_001;

type RecoveryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PayoutRuntimeError>> + Send + 'a>>;

/// Optional gate executed before reconciliation, signing or broadcasting.
pub(crate) trait PayoutExpiryDriver: Send + Sync {
    /// `false` means a safe observation/transition pass completed, but fresh
    /// settlement must wait for the next poll.
    fn recover(&self) -> RecoveryFuture<'_, bool>;
}

pub(crate) trait ExpiryStore: Send + Sync {
    fn candidates(&self) -> RecoveryFuture<'_, Vec<PayoutExpiryCandidate>>;
    fn hold(&self, id: Uuid, evidence: PayoutExpiryEvidence) -> RecoveryFuture<'_, ()>;
    fn expire(&self, id: Uuid, evidence: PayoutExpiryEvidence) -> RecoveryFuture<'_, ()>;
    fn confirm(&self, id: Uuid, evidence: PayoutConfirmation) -> RecoveryFuture<'_, bool>;
}

fn store_failure(operation: &'static str, error: StoreError) -> PayoutRuntimeError {
    use crate::payout_runtime::{classify_store_error, LifecycleStoreFailure};
    match classify_store_error(error) {
        LifecycleStoreFailure::Frozen => PayoutRuntimeError::Frozen {
            chain: Chain::Wcash,
        },
        LifecycleStoreFailure::Invariant | LifecycleStoreFailure::NoPayableBalances => {
            invariant(operation)
        }
        _ => PayoutRuntimeError::StoreUnavailable {
            chain: Chain::Wcash,
            operation,
        },
    }
}

impl ExpiryStore for PostgresStore {
    fn candidates(&self) -> RecoveryFuture<'_, Vec<PayoutExpiryCandidate>> {
        Box::pin(async move {
            self.list_payout_expiry_candidates(MAX_EXPIRY_CANDIDATES)
                .await
                .map_err(|e| store_failure("expiry_candidates", e))
        })
    }

    fn hold(&self, id: Uuid, evidence: PayoutExpiryEvidence) -> RecoveryFuture<'_, ()> {
        Box::pin(async move {
            self.hold_expired_payout(id, &evidence)
                .await
                .map_err(|e| store_failure("hold_expired", e))
        })
    }

    fn expire(&self, id: Uuid, evidence: PayoutExpiryEvidence) -> RecoveryFuture<'_, ()> {
        Box::pin(async move {
            self.expire_held_payout(id, &evidence)
                .await
                .map_err(|e| store_failure("expire_held", e))
        })
    }

    fn confirm(&self, id: Uuid, evidence: PayoutConfirmation) -> RecoveryFuture<'_, bool> {
        Box::pin(async move {
            match self.confirm_payout(id, &evidence).await {
                Ok(()) => Ok(true),
                Err(StoreError::PrematurePayoutConfirmation { .. }) => Ok(false),
                Err(e) => Err(store_failure("confirm_held", e)),
            }
        })
    }
}

pub(crate) trait ExpiryInspector: Send + Sync {
    fn inspect(&self, candidate: PayoutExpiryCandidate) -> RecoveryFuture<'_, WecPreparedPayout>;
}

pub(crate) struct WecExpiryInspector {
    signer: Arc<WecPayoutSigner>,
    account: Uuid,
}

impl WecExpiryInspector {
    pub(crate) fn new(signer: Arc<WecPayoutSigner>, account: Uuid) -> Self {
        Self { signer, account }
    }
}

impl ExpiryInspector for WecExpiryInspector {
    fn inspect(&self, candidate: PayoutExpiryCandidate) -> RecoveryFuture<'_, WecPreparedPayout> {
        let signer = Arc::clone(&self.signer);
        let account = self.account;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                signer.inspect_prepared(&WecPayoutRequest {
                    batch: candidate.request,
                    source_account: account,
                    fund_source: WalletFundSource::Ironwood,
                })
            })
            .await
            .map_err(|_| invariant("expiry_inspection_task"))?
            .map_err(|error| {
                use wcash_wec_payout_signer::WecPayoutError;
                if matches!(
                    error,
                    WecPayoutError::WalletUnavailable | WecPayoutError::JournalUnavailable
                ) {
                    PayoutRuntimeError::AuthorityUnavailable {
                        chain: Chain::Wcash,
                        operation: "expiry_wallet_inspection",
                    }
                } else {
                    invariant("expiry_wallet_binding")
                }
            })
        })
    }
}

#[derive(Clone)]
pub(crate) struct ExpiryWatch {
    pub(crate) candidate: PayoutExpiryCandidate,
    pub(crate) expiry_height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExpiryChainState {
    /// Active, unexpired artifact; normal settlement continues.
    Unexpired,
    /// Held transaction remains missing beyond expiry, with its reserve intact.
    Missing(PayoutExpiryEvidence),
    /// The exact original reached the authority's canonical chain.
    Mined(PayoutConfirmation),
    /// Present in mempool/orphan storage, or rollback makes it unexpired.
    Unresolved,
    /// Whole-chain indexed and mempool absence, after the expiry is finalized.
    FinalMissing(PayoutExpiryEvidence),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpiryObservation {
    pub(crate) batch_id: Uuid,
    pub(crate) state: ExpiryChainState,
}

pub(crate) trait ExpiryAuthority: Send + Sync {
    fn expiry_snapshot(
        &self,
        watches: Vec<ExpiryWatch>,
    ) -> ObservationFuture<'_, Vec<ExpiryObservation>>;
}

#[derive(Clone, Eq, PartialEq)]
struct InspectedExpiry {
    transaction_id: [u8; 32],
    raw_digest: [u8; 32],
    request_commitment: [u8; 32],
    expiry_height: u32,
    unsigned_digest: [u8; 32],
    network_fee_zat: u64,
}

pub(crate) struct WecPayoutExpiryRecovery {
    store: Arc<dyn ExpiryStore>,
    inspector: Arc<dyn ExpiryInspector>,
    authority: Arc<dyn ExpiryAuthority>,
    inspected: Mutex<HashMap<Uuid, InspectedExpiry>>,
}

impl WecPayoutExpiryRecovery {
    pub(crate) fn new(
        store: Arc<dyn ExpiryStore>,
        inspector: Arc<dyn ExpiryInspector>,
        authority: Arc<dyn ExpiryAuthority>,
    ) -> Self {
        Self {
            store,
            inspector,
            authority,
            inspected: Mutex::new(HashMap::new()),
        }
    }

    async fn pass(&self) -> Result<bool, PayoutRuntimeError> {
        let candidates = self.store.candidates().await?;
        if candidates.len() > MAX_EXPIRY_CANDIDATES as usize {
            return Err(invariant("expiry_candidate_bound"));
        }
        if candidates.is_empty() {
            self.inspected.lock().await.clear();
            return Ok(true);
        }
        let mut inspected = self.inspected.lock().await;
        inspected.retain(|id, _| candidates.iter().any(|c| c.artifact.batch_id == *id));
        let mut did_inspect = false;
        let mut watches = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let artifact = &candidate.artifact;
            if artifact.chain != Chain::Wcash
                || artifact.batch_id.is_nil()
                || artifact.transaction_id == [0; 32]
                || artifact.unsigned_digest == [0; 32]
                || candidate.request.batch_id != artifact.batch_id
                || candidate.request.asset != wcash_pool_portal::Asset::Wec
                || artifact.signed_transaction.is_empty()
                || artifact.signed_transaction.len() > 4 * 1024 * 1024
                || !matches!(
                    artifact.state,
                    PayoutBatchState::Signed
                        | PayoutBatchState::Broadcasting
                        | PayoutBatchState::Broadcast
                        | PayoutBatchState::ExpiryPending
                )
                || (artifact.state == PayoutBatchState::ExpiryPending)
                    != candidate.quarantine.is_some()
                || watches.iter().any(|w: &ExpiryWatch| {
                    w.candidate.artifact.batch_id == artifact.batch_id
                        || w.candidate.artifact.transaction_id == artifact.transaction_id
                })
            {
                return Err(invariant("expiry_candidate_binding"));
            }
            let digest: [u8; 32] = Sha256::digest(&artifact.signed_transaction).into();
            let commitment = candidate
                .request
                .commitment()
                .map_err(|_| invariant("expiry_request_commitment"))?;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                inspected.entry(artifact.batch_id)
            {
                let verified = self.inspector.inspect(candidate.clone()).await?;
                if verified.receipt.batch_id != artifact.batch_id
                    || verified.receipt.asset != wcash_pool_portal::Asset::Wec
                    || verified.receipt.transaction_id != hex::encode(artifact.transaction_id)
                    || verified.receipt.request_commitment != commitment
                    || candidate
                        .request
                        .outputs
                        .iter()
                        .try_fold(0u64, |sum, output| sum.checked_add(output.amount_zat))
                        != Some(verified.receipt.output_total_zat)
                    || verified.transaction_id_bytes != artifact.transaction_id
                    || verified.signed_transaction != artifact.signed_transaction
                    || verified.unsigned_digest != artifact.unsigned_digest
                    || verified.network_fee_zat != artifact.network_fee_zat
                    || verified.target_height == 0
                    || verified
                        .expiry_height
                        .checked_sub(verified.target_height)
                        .is_none_or(|d| !(1..=100).contains(&d))
                {
                    return Err(invariant("expiry_inspected_artifact"));
                }
                entry.insert(InspectedExpiry {
                    transaction_id: artifact.transaction_id,
                    raw_digest: digest,
                    request_commitment: commitment,
                    expiry_height: verified.expiry_height,
                    unsigned_digest: artifact.unsigned_digest,
                    network_fee_zat: artifact.network_fee_zat,
                });
                did_inspect = true;
            }
            let verified = inspected
                .get(&artifact.batch_id)
                .ok_or_else(|| invariant("expiry_inspection_cache"))?;
            if verified.transaction_id != artifact.transaction_id
                || verified.raw_digest != digest
                || verified.request_commitment != commitment
                || verified.unsigned_digest != artifact.unsigned_digest
                || verified.network_fee_zat != artifact.network_fee_zat
                || candidate.quarantine.as_ref().is_some_and(|e| {
                    e.transaction_id != artifact.transaction_id
                        || e.signed_transaction_sha256 != digest
                        || e.expiry_height != verified.expiry_height
                })
            {
                return Err(invariant("expiry_cached_binding"));
            }
            watches.push(ExpiryWatch {
                expiry_height: verified.expiry_height,
                candidate,
            });
        }
        drop(inspected);
        // Inspection is its own bounded pass; never accumulate its child-process
        // deadlines with a wallet sync/prove/sign pass under the worker lease.
        if did_inspect {
            return Ok(false);
        }
        let observations = self
            .authority
            .expiry_snapshot(watches.clone())
            .await
            .map_err(|e| match e {
                ObservationFailure::Unavailable => PayoutRuntimeError::AuthorityUnavailable {
                    chain: Chain::Wcash,
                    operation: "expiry_snapshot",
                },
                ObservationFailure::Invariant => invariant("expiry_snapshot"),
            })?;
        if observations.len() != watches.len() {
            return Err(invariant("expiry_result_set"));
        }
        let mut ready = true;
        let mut seen = Vec::new();
        // Validate the complete authenticated result set before making even
        // the first durable transition. A malformed later result must not
        // partially apply a snapshot.
        for observation in &observations {
            let watch = watches
                .iter()
                .find(|w| w.candidate.artifact.batch_id == observation.batch_id)
                .ok_or_else(|| invariant("expiry_result_binding"))?;
            if seen.contains(&observation.batch_id) {
                return Err(invariant("expiry_duplicate_result"));
            }
            seen.push(observation.batch_id);
            let held = watch.candidate.artifact.state == PayoutBatchState::ExpiryPending;
            match &observation.state {
                ExpiryChainState::Unexpired if !held => {}
                ExpiryChainState::Mined(confirmation) => {
                    if confirmation.block_hash == [0; 32]
                        || confirmation.block_height == 0
                        || confirmation.confirmations == 0
                    {
                        return Err(invariant("expiry_confirmation_binding"));
                    }
                }
                ExpiryChainState::Unresolved => {}
                ExpiryChainState::Missing(evidence) => validate_evidence(watch, evidence, false)?,
                ExpiryChainState::FinalMissing(evidence) => {
                    validate_evidence(watch, evidence, held)?
                }
                _ => return Err(invariant("expiry_state_transition")),
            }
        }
        for observation in observations {
            let watch = watches
                .iter()
                .find(|w| w.candidate.artifact.batch_id == observation.batch_id)
                .ok_or_else(|| invariant("expiry_result_binding"))?;
            let held = watch.candidate.artifact.state == PayoutBatchState::ExpiryPending;
            match observation.state {
                ExpiryChainState::Unexpired if !held => {}
                ExpiryChainState::Mined(confirmation) if held => {
                    if self
                        .store
                        .confirm(observation.batch_id, confirmation)
                        .await?
                    {
                        eprintln!(
                            "Wcash held payout confirmed: batch={}",
                            observation.batch_id
                        );
                    }
                    ready = false;
                }
                ExpiryChainState::Mined(_) if !held => {}
                ExpiryChainState::Unresolved => {
                    ready &= !held;
                }
                ExpiryChainState::Missing(evidence) | ExpiryChainState::FinalMissing(evidence)
                    if !held =>
                {
                    validate_evidence(watch, &evidence, false)?;
                    self.store.hold(observation.batch_id, evidence).await?;
                    eprintln!(
                        "Wcash expired payout held; full liability remains reserved: batch={}",
                        observation.batch_id
                    );
                    ready = false;
                }
                ExpiryChainState::Missing(evidence) if held => {
                    validate_evidence(watch, &evidence, false)?;
                }
                ExpiryChainState::FinalMissing(evidence) if held => {
                    validate_evidence(watch, &evidence, true)?;
                    self.store.expire(observation.batch_id, evidence).await?;
                    eprintln!("Wcash expired payout released exactly once after finalized non-inclusion: batch={}", observation.batch_id);
                    ready = false;
                }
                _ => return Err(invariant("expiry_state_transition")),
            }
        }
        // Two held reserves exhaust the bounded recovery allowance. Keep
        // observing them without repeatedly attempting a knowingly blocked
        // reconciliation or crashing the healthy waiting worker.
        let held_count = watches
            .iter()
            .filter(|w| w.candidate.artifact.state == PayoutBatchState::ExpiryPending)
            .count();
        Ok(ready && held_count < MAX_EXPIRY_CANDIDATES as usize)
    }
}

impl PayoutExpiryDriver for WecPayoutExpiryRecovery {
    fn recover(&self) -> RecoveryFuture<'_, bool> {
        Box::pin(self.pass())
    }
}

fn validate_evidence(
    watch: &ExpiryWatch,
    evidence: &PayoutExpiryEvidence,
    finality: bool,
) -> Result<(), PayoutRuntimeError> {
    let artifact = &watch.candidate.artifact;
    let raw_digest: [u8; 32] = Sha256::digest(&artifact.signed_transaction).into();
    if evidence.transaction_id != artifact.transaction_id
        || evidence.signed_transaction_sha256 != raw_digest
        || evidence.expiry_height != watch.expiry_height
        || evidence.tip_hash == [0; 32]
        || evidence.observed_at == 0
        || evidence.tip_height <= evidence.expiry_height
        || (finality
            && evidence
                .expiry_height
                .checked_add(WCASH_EXPIRY_FINALITY_DEPTH)
                .is_none_or(|h| evidence.tip_height < h))
    {
        return Err(invariant("expiry_evidence_binding"));
    }
    Ok(())
}

fn invariant(operation: &'static str) -> PayoutRuntimeError {
    PayoutRuntimeError::Invariant {
        chain: Chain::Wcash,
        operation,
    }
}

#[cfg(test)]
#[path = "payout_expiry_tests.rs"]
mod tests;

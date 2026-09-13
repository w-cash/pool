//! Fail-closed automatic payout lifecycle composition.
//!
//! Chain-specific adapters authenticate wallet and validator responses. This
//! module independently binds those responses to one configured chain, creates
//! one database-idempotent batch from each reconciliation, resumes exact signed
//! bytes after crashes, and accepts confirmation or reorganization evidence
//! only from the matching validator snapshot.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{sync::watch, time};
use uuid::Uuid;
use wcash_pool_store::{
    Chain, ConfirmedPayoutWatchCursor, PayoutBatch, PayoutBatchState, PayoutConfirmation,
    PayoutReorg, PayoutWatch, PayoutWatchPage, PostgresStore, StoreError, WalletObservation,
    WalletReconciliation,
};
use wcash_wec_payout_signer::NativeWalletError;

use crate::settlement::{BoundaryFailure, ResumeOutcome, SettlementError, SettlementOrchestrator};
use crate::wcash_observation::{WcashObservationError, WcashWalletObserver};

const IDEMPOTENCY_DOMAIN: &[u8] = b"ZECWEC-PAYOUT-BATCH-IDEMPOTENCY-V1\0";

/// Boxed asynchronous store operation.
pub type LifecycleStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LifecycleStoreFailure>> + Send + 'a>>;

/// Boxed asynchronous authenticated observation operation.
pub type ObservationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ObservationFailure>> + Send + 'a>>;

/// Boxed asynchronous settlement operation.
pub type SettlementDriverFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResumeOutcome, SettlementError>> + Send + 'a>>;

/// Privacy-preserving classification of a lifecycle persistence result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LifecycleStoreFailure {
    /// No automatic balance currently meets its payout threshold.
    #[error("no payable balance is ready")]
    NoPayableBalances,
    /// A current reconciliation or confirmation race should be retried later.
    #[error("payout operation is temporarily deferred")]
    Deferred,
    /// PostgreSQL was temporarily unavailable.
    #[error("payout persistence is temporarily unavailable")]
    Unavailable,
    /// Durable safety state has frozen this chain's payouts.
    #[error("chain payouts are frozen")]
    Frozen,
    /// Persisted facts or a requested transition violated an invariant.
    #[error("payout persistence invariant failed")]
    Invariant,
}

/// Authenticated wallet or validator adapter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ObservationFailure {
    /// The exact authority is temporarily unavailable.
    #[error("observation authority is temporarily unavailable")]
    Unavailable,
    /// The authority response violated its fixed machine contract.
    #[error("observation authority violated its contract")]
    Invariant,
}

/// Durable operations used by the automatic lifecycle.
pub trait PayoutLifecycleStore: Send + Sync {
    /// Records a short-lived wallet observation against an exact ledger root.
    fn record_reconciliation(
        &self,
        observation: &WalletObservation,
    ) -> LifecycleStoreFuture<'_, WalletReconciliation>;

    /// Creates or replays one deterministic batch for a reconciliation.
    fn create_batch(
        &self,
        chain: Chain,
        idempotency_key: Uuid,
        reconciliation_id: Uuid,
    ) -> LifecycleStoreFuture<'_, PayoutBatch>;

    /// Lists transactions which the chain authority must currently observe.
    fn payout_watches(
        &self,
        chain: Chain,
        maximum: u32,
    ) -> LifecycleStoreFuture<'_, PayoutWatchPage>;

    /// Acknowledges the confirmed page after a complete valid chain snapshot.
    fn advance_confirmed_watch_cursor(
        &self,
        chain: Chain,
        cursor: &ConfirmedPayoutWatchCursor,
    ) -> LifecycleStoreFuture<'_, ()>;

    /// Confirms a broadcast transaction using exact best-chain evidence.
    fn confirm(
        &self,
        batch_id: Uuid,
        confirmation: &PayoutConfirmation,
    ) -> LifecycleStoreFuture<'_, ()>;

    /// Freezes a chain after a confirmed transaction leaves its best chain.
    fn mark_reorged(&self, batch_id: Uuid, evidence: &PayoutReorg) -> LifecycleStoreFuture<'_, ()>;
}

impl PayoutLifecycleStore for PostgresStore {
    fn record_reconciliation(
        &self,
        observation: &WalletObservation,
    ) -> LifecycleStoreFuture<'_, WalletReconciliation> {
        let observation = observation.clone();
        Box::pin(async move {
            self.record_wallet_reconciliation(&observation)
                .await
                .map_err(classify_store_error)
        })
    }

    fn create_batch(
        &self,
        chain: Chain,
        idempotency_key: Uuid,
        reconciliation_id: Uuid,
    ) -> LifecycleStoreFuture<'_, PayoutBatch> {
        Box::pin(async move {
            self.create_payout_batch(chain, idempotency_key, reconciliation_id)
                .await
                .map_err(classify_store_error)
        })
    }

    fn payout_watches(
        &self,
        chain: Chain,
        maximum: u32,
    ) -> LifecycleStoreFuture<'_, PayoutWatchPage> {
        Box::pin(async move {
            self.list_payout_watches(chain, maximum)
                .await
                .map_err(classify_store_error)
        })
    }

    fn advance_confirmed_watch_cursor(
        &self,
        chain: Chain,
        cursor: &ConfirmedPayoutWatchCursor,
    ) -> LifecycleStoreFuture<'_, ()> {
        let cursor = cursor.clone();
        Box::pin(async move {
            self.advance_confirmed_payout_watch_cursor(chain, &cursor)
                .await
                .map_err(classify_store_error)
        })
    }

    fn confirm(
        &self,
        batch_id: Uuid,
        confirmation: &PayoutConfirmation,
    ) -> LifecycleStoreFuture<'_, ()> {
        let confirmation = confirmation.clone();
        Box::pin(async move {
            self.confirm_payout(batch_id, &confirmation)
                .await
                .map_err(classify_store_error)
        })
    }

    fn mark_reorged(&self, batch_id: Uuid, evidence: &PayoutReorg) -> LifecycleStoreFuture<'_, ()> {
        let evidence = evidence.clone();
        Box::pin(async move {
            self.mark_confirmed_payout_reorged(batch_id, &evidence)
                .await
                .map_err(classify_store_error)
        })
    }
}

fn classify_store_error(error: StoreError) -> LifecycleStoreFailure {
    match error {
        StoreError::NoPayableBalances => LifecycleStoreFailure::NoPayableBalances,
        StoreError::WalletReconciliationBlocked
        | StoreError::PrematurePayoutConfirmation { .. } => LifecycleStoreFailure::Deferred,
        StoreError::InvalidWalletObservation
        | StoreError::WalletReconciliationStale
        | StoreError::Database(_) => LifecycleStoreFailure::Unavailable,
        StoreError::PayoutsFrozen(_) | StoreError::CollectorReconciliationFailed => {
            LifecycleStoreFailure::Frozen
        }
        _ => LifecycleStoreFailure::Invariant,
    }
}

/// Authenticated, chain-specific collector wallet observer.
pub trait WalletObservationSource: Send + Sync {
    /// Chain exclusively served by this observer.
    fn chain(&self) -> Chain;

    /// Returns one short-lived, seedless wallet state observation.
    fn observe(&self) -> ObservationFuture<'_, WalletObservation>;
}

/// Bounded adapter from the integrity-pinned Wolf observer to the generic
/// automatic lifecycle.
pub struct WcashObservationSource {
    observer: WcashWalletObserver,
    timeout: Duration,
    maximum_response_bytes: usize,
}

impl WcashObservationSource {
    /// Binds fixed response and execution limits to one verified observer.
    pub fn new(
        observer: WcashWalletObserver,
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Self, ObservationFailure> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(30)
            || !(1..=1024 * 1024).contains(&maximum_response_bytes)
        {
            return Err(ObservationFailure::Invariant);
        }
        Ok(Self {
            observer,
            timeout,
            maximum_response_bytes,
        })
    }
}

impl WalletObservationSource for WcashObservationSource {
    fn chain(&self) -> Chain {
        Chain::Wcash
    }

    fn observe(&self) -> ObservationFuture<'_, WalletObservation> {
        let observer = self.observer.clone();
        let timeout = self.timeout;
        let maximum_response_bytes = self.maximum_response_bytes;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || observer.observe(timeout, maximum_response_bytes))
                .await
                .map_err(|_| ObservationFailure::Unavailable)?
                .map_err(classify_wcash_observation_error)
        })
    }
}

fn classify_wcash_observation_error(error: WcashObservationError) -> ObservationFailure {
    match error {
        WcashObservationError::Wallet(
            NativeWalletError::ProtocolViolation | NativeWalletError::IdempotencyConflict,
        ) => ObservationFailure::Invariant,
        WcashObservationError::Wallet(
            NativeWalletError::Timeout
            | NativeWalletError::Unavailable
            | NativeWalletError::Rejected
            | NativeWalletError::Ambiguous,
        )
        | WcashObservationError::WorkerUnavailable
        | WcashObservationError::Store(_) => ObservationFailure::Unavailable,
    }
}

/// One transaction's status in an authoritative, single-tip snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityPayoutState {
    /// Transaction is not yet confirmed in the snapshot's best chain.
    Pending,
    /// Transaction is mined in the snapshot's best chain.
    Mined(PayoutConfirmation),
    /// A previously recorded confirmation is absent from the replacement chain.
    Reorged(PayoutReorg),
}

/// Authority response for one exact payout watch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPayoutObservation {
    /// Stable accounting batch identity copied from the request.
    pub batch_id: Uuid,
    /// Exact transaction identifier copied from the request.
    pub transaction_id: [u8; 32],
    /// Best-chain status at the containing snapshot.
    pub state: AuthorityPayoutState,
}

/// Atomic response from one independently authenticated chain validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshot {
    /// Chain served by the validator endpoint.
    pub chain: Chain,
    /// Exact best-tip hash in chain wire byte order.
    pub best_tip_hash: [u8; 32],
    /// Exact best-tip height.
    pub best_tip_height: u32,
    /// Nonzero observation time as Unix seconds.
    pub observed_at: u64,
    /// Exactly one result for every requested watch.
    pub payouts: Vec<AuthorityPayoutObservation>,
}

/// Independently authenticated best-chain authority.
pub trait PayoutConfirmationAuthority: Send + Sync {
    /// Chain exclusively served by this authority.
    fn chain(&self) -> Chain;

    /// Observes all requested transactions against one exact best-chain tip.
    /// Implementations must still return a live tip when `watches` is empty.
    fn snapshot(&self, watches: &[PayoutWatch]) -> ObservationFuture<'_, AuthoritySnapshot>;
}

/// Abstraction over crash-safe exact-byte settlement, allowing deterministic
/// lifecycle testing without a wallet process.
pub trait SettlementDriver: Send + Sync {
    /// Advances at most the oldest incomplete batch for one chain.
    fn resume_next(&self, chain: Chain) -> SettlementDriverFuture<'_>;
}

impl SettlementDriver for SettlementOrchestrator {
    fn resume_next(&self, chain: Chain) -> SettlementDriverFuture<'_> {
        Box::pin(SettlementOrchestrator::resume_next(self, chain))
    }
}

/// Bounded scheduling and retry policy for an automatic chain worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayoutLoopPolicy {
    /// Delay after a successful or safely deferred pass.
    pub poll_interval: Duration,
    /// First retry delay after a transient failure.
    pub retry_initial: Duration,
    /// Maximum deterministic retry delay.
    pub retry_maximum: Duration,
    /// Consecutive transient failures allowed before process shutdown.
    pub maximum_consecutive_failures: u32,
    /// Independent per-pass maximum for broadcasts and rotating confirmations.
    pub maximum_confirmation_watches: u32,
}

impl PayoutLoopPolicy {
    fn validate(self) -> Result<Self, PayoutRuntimeError> {
        if self.poll_interval.is_zero()
            || self.poll_interval > Duration::from_secs(5 * 60)
            || self.retry_initial.is_zero()
            || self.retry_maximum < self.retry_initial
            || self.retry_maximum > Duration::from_secs(5 * 60)
            || self.maximum_consecutive_failures == 0
            || self.maximum_consecutive_failures > 100
            || !(1..=10_000).contains(&self.maximum_confirmation_watches)
        {
            return Err(PayoutRuntimeError::InvalidConfiguration);
        }
        Ok(self)
    }

    fn retry_delay(self, consecutive_failures: u32) -> Duration {
        let shifts = consecutive_failures.saturating_sub(1).min(31);
        self.retry_initial
            .checked_mul(1_u32 << shifts)
            .unwrap_or(self.retry_maximum)
            .min(self.retry_maximum)
    }
}

/// Observable result of one complete, chain-isolated lifecycle pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutTick {
    /// Number of validator watches checked against one exact tip.
    pub watches_checked: usize,
    /// Number of newly durable confirmations.
    pub confirmations_recorded: usize,
    /// Newly reserved deterministic batch, if any.
    pub batch_created: Option<Uuid>,
    /// Exact settlement state after this pass.
    pub settlement: ResumeOutcome,
}

/// Automatic payout lifecycle for exactly one chain.
pub struct AutomaticPayoutRuntime {
    chain: Chain,
    idempotency_namespace: Uuid,
    policy: PayoutLoopPolicy,
    store: Arc<dyn PayoutLifecycleStore>,
    wallet: Arc<dyn WalletObservationSource>,
    authority: Arc<dyn PayoutConfirmationAuthority>,
    settlement: Arc<dyn SettlementDriver>,
}

impl AutomaticPayoutRuntime {
    /// Constructs a runtime only when wallet and validator adapters advertise
    /// the exact configured chain.
    pub fn new(
        chain: Chain,
        idempotency_namespace: Uuid,
        policy: PayoutLoopPolicy,
        store: Arc<dyn PayoutLifecycleStore>,
        wallet: Arc<dyn WalletObservationSource>,
        authority: Arc<dyn PayoutConfirmationAuthority>,
        settlement: Arc<dyn SettlementDriver>,
    ) -> Result<Self, PayoutRuntimeError> {
        let policy = policy.validate()?;
        if idempotency_namespace.is_nil() || wallet.chain() != chain || authority.chain() != chain {
            return Err(PayoutRuntimeError::InvalidConfiguration);
        }
        Ok(Self {
            chain,
            idempotency_namespace,
            policy,
            store,
            wallet,
            authority,
            settlement,
        })
    }

    /// Runs one ordered lifecycle pass.
    ///
    /// Validator readiness and every existing transaction are checked first.
    /// An unresolved broadcast prevents another wallet snapshot or batch. Only
    /// an idle settlement path may reconcile, reserve, and sign fresh outputs.
    pub async fn tick(&self) -> Result<PayoutTick, PayoutRuntimeError> {
        let page = self
            .store
            .payout_watches(self.chain, self.policy.maximum_confirmation_watches)
            .await
            .map_err(|failure| self.store_error("list_watches", failure))?;
        validate_watch_page(self.chain, self.policy.maximum_confirmation_watches, &page)?;
        let watches = &page.watches;
        let snapshot = self
            .authority
            .snapshot(watches)
            .await
            .map_err(|failure| self.observation_error("validator_snapshot", failure))?;
        let confirmations_recorded = self.apply_snapshot(watches, &snapshot).await?;
        if let Some(cursor) = &page.confirmed_cursor {
            self.store
                .advance_confirmed_watch_cursor(self.chain, cursor)
                .await
                .map_err(|failure| self.store_error("advance_watch_cursor", failure))?;
        }

        let settlement = self.resume_settlement().await?;
        validate_resume_outcome(self.chain, &settlement)?;
        match settlement {
            ResumeOutcome::Broadcast { .. } | ResumeOutcome::AwaitingConfirmation { .. } => {
                return Ok(PayoutTick {
                    watches_checked: watches.len(),
                    confirmations_recorded,
                    batch_created: None,
                    settlement,
                });
            }
            ResumeOutcome::FrozenAfterReorg { .. } => {
                return Err(PayoutRuntimeError::Frozen { chain: self.chain });
            }
            ResumeOutcome::Terminal { .. } => {
                return Err(PayoutRuntimeError::Invariant {
                    chain: self.chain,
                    operation: "terminal_resumable_batch",
                });
            }
            ResumeOutcome::Idle => {}
        }

        let observation = self
            .wallet
            .observe()
            .await
            .map_err(|failure| self.observation_error("wallet_observe", failure))?;
        validate_wallet_observation(self.chain, &observation, &snapshot)?;
        let reconciliation = match self.store.record_reconciliation(&observation).await {
            Ok(reconciliation) => reconciliation,
            Err(LifecycleStoreFailure::Deferred) => {
                return Ok(PayoutTick {
                    watches_checked: watches.len(),
                    confirmations_recorded,
                    batch_created: None,
                    settlement: ResumeOutcome::Idle,
                });
            }
            Err(failure) => return Err(self.store_error("record_reconciliation", failure)),
        };
        if reconciliation.chain != self.chain
            || reconciliation.id.is_nil()
            || reconciliation.best_tip_hash != observation.best_tip_hash
            || reconciliation.best_tip_height != observation.best_tip_height
        {
            return Err(PayoutRuntimeError::Invariant {
                chain: self.chain,
                operation: "reconciliation_binding",
            });
        }
        let idempotency_key =
            deterministic_batch_key(self.idempotency_namespace, self.chain, &reconciliation);
        let batch = match self
            .store
            .create_batch(self.chain, idempotency_key, reconciliation.id)
            .await
        {
            Ok(batch) => batch,
            Err(LifecycleStoreFailure::NoPayableBalances | LifecycleStoreFailure::Deferred) => {
                return Ok(PayoutTick {
                    watches_checked: watches.len(),
                    confirmations_recorded,
                    batch_created: None,
                    settlement: ResumeOutcome::Idle,
                });
            }
            Err(failure) => return Err(self.store_error("create_batch", failure)),
        };
        let derived_payout_total = batch
            .outputs
            .iter()
            .try_fold(0u64, |sum, output| sum.checked_add(output.amount_zat));
        let derived_liability_total = batch.outputs.iter().try_fold(0u64, |sum, output| {
            (output.liability_amount_zat >= output.amount_zat)
                .then(|| sum.checked_add(output.liability_amount_zat))
                .flatten()
        });
        if batch.chain != self.chain
            || batch.reconciliation_id != reconciliation.id
            || batch.id.is_nil()
            || batch.state != PayoutBatchState::Draft
            || batch.policy_version == 0
            || batch.ledger_root == [0; 32]
            || batch.ledger_sequence_cutoff == 0
            || batch.miner_total_zat == 0
            || batch.payout_total_zat == 0
            || batch.maximum_network_fee_zat == 0
            || batch
                .payout_total_zat
                .checked_add(batch.maximum_network_fee_zat)
                != Some(batch.miner_total_zat)
            || derived_payout_total != Some(batch.payout_total_zat)
            || derived_liability_total != Some(batch.miner_total_zat)
            || batch.outputs.is_empty()
        {
            return Err(PayoutRuntimeError::Invariant {
                chain: self.chain,
                operation: "created_batch_binding",
            });
        }
        let resumed = self.resume_settlement().await?;
        validate_resume_outcome(self.chain, &resumed)?;
        let resumes_created_batch = match &resumed {
            ResumeOutcome::Broadcast {
                batch_id, chain, ..
            } => *batch_id == batch.id && *chain == self.chain,
            ResumeOutcome::Idle
            | ResumeOutcome::AwaitingConfirmation { .. }
            | ResumeOutcome::FrozenAfterReorg { .. }
            | ResumeOutcome::Terminal { .. } => false,
        };
        if !resumes_created_batch {
            return Err(PayoutRuntimeError::Invariant {
                chain: self.chain,
                operation: "created_batch_resume_binding",
            });
        }
        Ok(PayoutTick {
            watches_checked: watches.len(),
            confirmations_recorded,
            batch_created: Some(batch.id),
            settlement: resumed,
        })
    }

    /// Runs until shutdown, a durable freeze/invariant, or exhaustion of the
    /// bounded transient-failure budget. Shutdown never cancels an in-flight
    /// signing or persistence operation; the current journaled pass completes
    /// before the signal is observed.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), PayoutRuntimeError> {
        let mut consecutive_failures = 0_u32;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let delay = match self.tick().await {
                Ok(_) => {
                    consecutive_failures = 0;
                    self.policy.poll_interval
                }
                Err(error) if error.is_retryable() => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if consecutive_failures >= self.policy.maximum_consecutive_failures {
                        return Err(PayoutRuntimeError::FailureBudgetExhausted {
                            chain: self.chain,
                            attempts: consecutive_failures,
                        });
                    }
                    self.policy.retry_delay(consecutive_failures)
                }
                Err(error) => return Err(error),
            };
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                () = time::sleep(delay) => {}
            }
        }
    }

    async fn resume_settlement(&self) -> Result<ResumeOutcome, PayoutRuntimeError> {
        self.settlement
            .resume_next(self.chain)
            .await
            .map_err(|source| PayoutRuntimeError::Settlement {
                chain: self.chain,
                source,
            })
    }

    async fn apply_snapshot(
        &self,
        watches: &[PayoutWatch],
        snapshot: &AuthoritySnapshot,
    ) -> Result<usize, PayoutRuntimeError> {
        let observations = validate_authority_snapshot(self.chain, watches, snapshot)?;
        let mut confirmations = 0_usize;
        for watch in watches {
            let observation =
                observations
                    .get(&watch.batch_id)
                    .ok_or(PayoutRuntimeError::Invariant {
                        chain: self.chain,
                        operation: "validator_result_set",
                    })?;
            match (&watch.state, &observation.state) {
                (PayoutBatchState::Broadcast, AuthorityPayoutState::Pending) => {}
                (PayoutBatchState::Broadcast, AuthorityPayoutState::Mined(evidence)) => {
                    match self.store.confirm(watch.batch_id, evidence).await {
                        Ok(()) => confirmations = confirmations.saturating_add(1),
                        Err(LifecycleStoreFailure::Deferred) => {}
                        Err(failure) => {
                            return Err(self.store_error("confirm_payout", failure));
                        }
                    }
                }
                (PayoutBatchState::Confirmed, AuthorityPayoutState::Mined(_)) => {}
                (PayoutBatchState::Confirmed, AuthorityPayoutState::Reorged(evidence)) => {
                    self.store
                        .mark_reorged(watch.batch_id, evidence)
                        .await
                        .map_err(|failure| self.store_error("mark_reorged", failure))?;
                    return Err(PayoutRuntimeError::Frozen { chain: self.chain });
                }
                _ => {
                    return Err(PayoutRuntimeError::Invariant {
                        chain: self.chain,
                        operation: "validator_state_transition",
                    });
                }
            }
        }
        Ok(confirmations)
    }

    fn store_error(
        &self,
        operation: &'static str,
        failure: LifecycleStoreFailure,
    ) -> PayoutRuntimeError {
        match failure {
            LifecycleStoreFailure::Frozen => PayoutRuntimeError::Frozen { chain: self.chain },
            LifecycleStoreFailure::Invariant | LifecycleStoreFailure::NoPayableBalances => {
                PayoutRuntimeError::Invariant {
                    chain: self.chain,
                    operation,
                }
            }
            LifecycleStoreFailure::Deferred | LifecycleStoreFailure::Unavailable => {
                PayoutRuntimeError::StoreUnavailable {
                    chain: self.chain,
                    operation,
                }
            }
        }
    }

    fn observation_error(
        &self,
        operation: &'static str,
        failure: ObservationFailure,
    ) -> PayoutRuntimeError {
        match failure {
            ObservationFailure::Unavailable => PayoutRuntimeError::AuthorityUnavailable {
                chain: self.chain,
                operation,
            },
            ObservationFailure::Invariant => PayoutRuntimeError::Invariant {
                chain: self.chain,
                operation,
            },
        }
    }
}

fn validate_wallet_observation(
    chain: Chain,
    observation: &WalletObservation,
    snapshot: &AuthoritySnapshot,
) -> Result<(), PayoutRuntimeError> {
    if observation.chain != chain
        || observation.wallet_state_digest == [0; 32]
        || observation.best_tip_hash == [0; 32]
        || observation.best_tip_height == 0
        || observation.observed_at == 0
        || observation.valid_until <= observation.observed_at
    {
        return Err(PayoutRuntimeError::Invariant {
            chain,
            operation: "wallet_observation",
        });
    }
    if observation.best_tip_hash != snapshot.best_tip_hash
        || observation.best_tip_height != snapshot.best_tip_height
    {
        return Err(PayoutRuntimeError::AuthorityUnavailable {
            chain,
            operation: "wallet_validator_tip_race",
        });
    }
    Ok(())
}

fn validate_resume_outcome(
    chain: Chain,
    outcome: &ResumeOutcome,
) -> Result<(), PayoutRuntimeError> {
    let valid = match outcome {
        ResumeOutcome::Idle => true,
        ResumeOutcome::Broadcast {
            batch_id,
            chain: outcome_chain,
            transaction_id,
        }
        | ResumeOutcome::AwaitingConfirmation {
            batch_id,
            chain: outcome_chain,
            transaction_id,
        }
        | ResumeOutcome::FrozenAfterReorg {
            batch_id,
            chain: outcome_chain,
            transaction_id,
        } => !batch_id.is_nil() && *outcome_chain == chain && *transaction_id != [0; 32],
        ResumeOutcome::Terminal { batch_id, .. } => !batch_id.is_nil(),
    };
    if valid {
        Ok(())
    } else {
        Err(PayoutRuntimeError::Invariant {
            chain,
            operation: "settlement_outcome_binding",
        })
    }
}

fn validate_authority_snapshot<'a>(
    chain: Chain,
    watches: &'a [PayoutWatch],
    snapshot: &'a AuthoritySnapshot,
) -> Result<HashMap<Uuid, &'a AuthorityPayoutObservation>, PayoutRuntimeError> {
    let invalid = |operation| PayoutRuntimeError::Invariant { chain, operation };
    if snapshot.chain != chain
        || snapshot.best_tip_hash == [0; 32]
        || snapshot.best_tip_height == 0
        || snapshot.observed_at == 0
        || snapshot.payouts.len() != watches.len()
    {
        return Err(invalid("validator_snapshot"));
    }
    let mut requested = HashMap::with_capacity(watches.len());
    for watch in watches {
        if watch.chain != chain
            || watch.batch_id.is_nil()
            || watch.transaction_id == [0; 32]
            || !matches!(
                watch.state,
                PayoutBatchState::Broadcast | PayoutBatchState::Confirmed
            )
            || (watch.state == PayoutBatchState::Confirmed) != watch.prior_confirmation.is_some()
            || requested.insert(watch.batch_id, watch).is_some()
        {
            return Err(invalid("payout_watch"));
        }
    }
    let mut responses = HashMap::with_capacity(snapshot.payouts.len());
    let mut transaction_ids = HashSet::with_capacity(snapshot.payouts.len());
    for response in &snapshot.payouts {
        let watch = requested
            .get(&response.batch_id)
            .copied()
            .ok_or_else(|| invalid("validator_result_set"))?;
        if response.transaction_id != watch.transaction_id
            || !transaction_ids.insert(response.transaction_id)
            || responses.insert(response.batch_id, response).is_some()
        {
            return Err(invalid("validator_result_binding"));
        }
        match (&watch.state, &response.state) {
            (PayoutBatchState::Broadcast, AuthorityPayoutState::Pending) => {}
            (
                PayoutBatchState::Broadcast | PayoutBatchState::Confirmed,
                AuthorityPayoutState::Mined(confirmation),
            ) => {
                validate_confirmation(chain, snapshot, confirmation)?;
                if let Some(prior) = &watch.prior_confirmation {
                    if confirmation.block_hash != prior.block_hash
                        || confirmation.block_height != prior.block_height
                        || confirmation.confirmations < prior.confirmations
                    {
                        return Err(invalid("confirmed_payout_continuity"));
                    }
                }
            }
            (PayoutBatchState::Confirmed, AuthorityPayoutState::Reorged(evidence)) => {
                if watch.prior_confirmation.as_ref() != Some(&evidence.prior_confirmation)
                    || evidence.replacement_tip_hash != snapshot.best_tip_hash
                    || evidence.replacement_tip_height != snapshot.best_tip_height
                    || evidence.observed_at != snapshot.observed_at
                {
                    return Err(invalid("payout_reorg_evidence"));
                }
            }
            _ => return Err(invalid("validator_state_transition")),
        }
    }
    Ok(responses)
}

fn validate_watch_page(
    chain: Chain,
    maximum: u32,
    page: &PayoutWatchPage,
) -> Result<(), PayoutRuntimeError> {
    let invalid = || PayoutRuntimeError::Invariant {
        chain,
        operation: "payout_watch_page",
    };
    let maximum = usize::try_from(maximum).map_err(|_| invalid())?;
    let mut broadcast_count = 0_usize;
    let mut confirmed_count = 0_usize;
    let mut last_confirmed = None;
    let mut reached_confirmed = false;
    for watch in &page.watches {
        if watch.chain != chain {
            return Err(invalid());
        }
        match watch.state {
            PayoutBatchState::Broadcast if !reached_confirmed => {
                broadcast_count = broadcast_count.saturating_add(1);
            }
            PayoutBatchState::Confirmed => {
                reached_confirmed = true;
                confirmed_count = confirmed_count.saturating_add(1);
                last_confirmed = Some(watch.batch_id);
            }
            _ => return Err(invalid()),
        }
    }
    if broadcast_count > maximum || confirmed_count > maximum {
        return Err(invalid());
    }
    match (&page.confirmed_cursor, last_confirmed) {
        (None, None) => Ok(()),
        (Some(cursor), Some(last))
            if !cursor.checked_through_batch_id.is_nil()
                && cursor.checked_through_batch_id == last
                && !cursor
                    .previous_batch_id
                    .is_some_and(|batch_id| batch_id.is_nil()) =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

fn validate_confirmation(
    chain: Chain,
    snapshot: &AuthoritySnapshot,
    confirmation: &PayoutConfirmation,
) -> Result<(), PayoutRuntimeError> {
    let expected = snapshot
        .best_tip_height
        .checked_sub(confirmation.block_height)
        .and_then(|depth| depth.checked_add(1));
    if confirmation.block_hash == [0; 32]
        || confirmation.block_height == 0
        || expected != Some(confirmation.confirmations)
    {
        return Err(PayoutRuntimeError::Invariant {
            chain,
            operation: "payout_confirmation_evidence",
        });
    }
    Ok(())
}

/// Derives a stable RFC-4122 variant, version-8 UUID from deployment, chain,
/// and the database-issued reconciliation facts.
pub fn deterministic_batch_key(
    namespace: Uuid,
    chain: Chain,
    reconciliation: &WalletReconciliation,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_DOMAIN);
    hasher.update(namespace.as_bytes());
    hasher.update([match chain {
        Chain::Wcash => 0,
        Chain::Zcash => 1,
    }]);
    hasher.update(reconciliation.id.as_bytes());
    hasher.update(reconciliation.ledger_root);
    hasher.update(reconciliation.ledger_transaction_count.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Fatal or bounded-retry lifecycle failure.
#[derive(Debug, Error)]
pub enum PayoutRuntimeError {
    /// Static policy or chain wiring is invalid.
    #[error("automatic payout runtime configuration is invalid")]
    InvalidConfiguration,
    /// PostgreSQL is temporarily unavailable.
    #[error("{chain:?} payout store operation {operation} is unavailable")]
    StoreUnavailable {
        /// Independently settled chain.
        chain: Chain,
        /// Stable operation label.
        operation: &'static str,
    },
    /// A configured wallet or validator authority is temporarily unavailable.
    #[error("{chain:?} payout authority operation {operation} is unavailable")]
    AuthorityUnavailable {
        /// Independently settled chain.
        chain: Chain,
        /// Stable operation label.
        operation: &'static str,
    },
    /// Exact-byte signing or broadcast recovery failed.
    #[error("{chain:?} settlement failed")]
    Settlement {
        /// Independently settled chain.
        chain: Chain,
        /// Private diagnostic source.
        #[source]
        source: SettlementError,
    },
    /// Durable safety state requires operator reconciliation.
    #[error("{chain:?} payouts are frozen")]
    Frozen {
        /// Independently settled chain.
        chain: Chain,
    },
    /// An authenticated or durable fact violated a fixed invariant.
    #[error("{chain:?} payout invariant failed during {operation}")]
    Invariant {
        /// Independently settled chain.
        chain: Chain,
        /// Stable operation label.
        operation: &'static str,
    },
    /// Repeated transient failures exceeded policy and shut down the service.
    #[error("{chain:?} payout failure budget exhausted after {attempts} attempts")]
    FailureBudgetExhausted {
        /// Independently settled chain.
        chain: Chain,
        /// Exact number of consecutive failed passes.
        attempts: u32,
    },
}

impl PayoutRuntimeError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::StoreUnavailable { .. } | Self::AuthorityUnavailable { .. } => true,
            Self::Settlement { source, .. } => match source {
                SettlementError::Persistence { .. } => true,
                SettlementError::Boundary { failure, .. } => matches!(
                    failure,
                    BoundaryFailure::Retryable | BoundaryFailure::Ambiguous
                ),
                SettlementError::Invariant(_) => false,
            },
            Self::InvalidConfiguration
            | Self::Frozen { .. }
            | Self::Invariant { .. }
            | Self::FailureBudgetExhausted { .. } => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    use wcash_pool_store::{PayoutInstruction, ReceiverKind};

    use super::*;

    const RECONCILIATION_ID: Uuid = Uuid::from_u128(0x1000);
    const BATCH_ID: Uuid = Uuid::from_u128(0x2000);
    const NAMESPACE: Uuid = Uuid::from_u128(0x3000);

    #[derive(Default)]
    struct FakeStoreState {
        watches: Vec<PayoutWatch>,
        watch_failure: Option<LifecycleStoreFailure>,
        reconciliations: Vec<WalletObservation>,
        created_keys: Vec<(Chain, Uuid, Uuid)>,
        confirmations: Vec<(Uuid, PayoutConfirmation)>,
        reorgs: Vec<(Uuid, PayoutReorg)>,
        cursor_advances: Vec<(Chain, ConfirmedPayoutWatchCursor)>,
        cursor_failure: Option<LifecycleStoreFailure>,
        confirmation_failure: Option<LifecycleStoreFailure>,
        reorg_failure: Option<LifecycleStoreFailure>,
        create_failure: Option<LifecycleStoreFailure>,
    }

    #[derive(Default)]
    struct FakeStore {
        state: Mutex<FakeStoreState>,
    }

    impl PayoutLifecycleStore for FakeStore {
        fn record_reconciliation(
            &self,
            observation: &WalletObservation,
        ) -> LifecycleStoreFuture<'_, WalletReconciliation> {
            let observation = observation.clone();
            Box::pin(async move {
                self.state
                    .lock()
                    .unwrap()
                    .reconciliations
                    .push(observation.clone());
                Ok(reconciliation(observation.chain, &observation))
            })
        }

        fn create_batch(
            &self,
            chain: Chain,
            idempotency_key: Uuid,
            reconciliation_id: Uuid,
        ) -> LifecycleStoreFuture<'_, PayoutBatch> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state
                    .created_keys
                    .push((chain, idempotency_key, reconciliation_id));
                if let Some(failure) = state.create_failure {
                    return Err(failure);
                }
                Ok(batch(chain, reconciliation_id))
            })
        }

        fn payout_watches(
            &self,
            _chain: Chain,
            _maximum: u32,
        ) -> LifecycleStoreFuture<'_, PayoutWatchPage> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                if let Some(failure) = state.watch_failure {
                    Err(failure)
                } else {
                    let confirmed = state
                        .watches
                        .iter()
                        .rfind(|watch| watch.state == PayoutBatchState::Confirmed);
                    Ok(PayoutWatchPage {
                        watches: state.watches.clone(),
                        confirmed_cursor: confirmed.map(|watch| ConfirmedPayoutWatchCursor {
                            generation: u64::try_from(state.cursor_advances.len()).unwrap(),
                            previous_batch_id: state
                                .cursor_advances
                                .last()
                                .map(|(_, cursor)| cursor.checked_through_batch_id),
                            checked_through_batch_id: watch.batch_id,
                        }),
                    })
                }
            })
        }

        fn advance_confirmed_watch_cursor(
            &self,
            chain: Chain,
            cursor: &ConfirmedPayoutWatchCursor,
        ) -> LifecycleStoreFuture<'_, ()> {
            let cursor = cursor.clone();
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(failure) = state.cursor_failure {
                    return Err(failure);
                }
                state.cursor_advances.push((chain, cursor));
                Ok(())
            })
        }

        fn confirm(
            &self,
            batch_id: Uuid,
            confirmation: &PayoutConfirmation,
        ) -> LifecycleStoreFuture<'_, ()> {
            let confirmation = confirmation.clone();
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(failure) = state.confirmation_failure {
                    return Err(failure);
                }
                state.confirmations.push((batch_id, confirmation));
                Ok(())
            })
        }

        fn mark_reorged(
            &self,
            batch_id: Uuid,
            evidence: &PayoutReorg,
        ) -> LifecycleStoreFuture<'_, ()> {
            let evidence = evidence.clone();
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(failure) = state.reorg_failure {
                    return Err(failure);
                }
                state.reorgs.push((batch_id, evidence));
                Ok(())
            })
        }
    }

    struct FakeWallet {
        chain: Chain,
        observation: Result<WalletObservation, ObservationFailure>,
        calls: AtomicUsize,
    }

    impl WalletObservationSource for FakeWallet {
        fn chain(&self) -> Chain {
            self.chain
        }

        fn observe(&self) -> ObservationFuture<'_, WalletObservation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.observation.clone();
            Box::pin(async move { result })
        }
    }

    struct FakeAuthority {
        chain: Chain,
        snapshot: Result<AuthoritySnapshot, ObservationFailure>,
        calls: AtomicUsize,
    }

    impl PayoutConfirmationAuthority for FakeAuthority {
        fn chain(&self) -> Chain {
            self.chain
        }

        fn snapshot(&self, _watches: &[PayoutWatch]) -> ObservationFuture<'_, AuthoritySnapshot> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.snapshot.clone();
            Box::pin(async move { result })
        }
    }

    struct FakeSettlement {
        outcomes: Mutex<VecDeque<Result<ResumeOutcome, SettlementError>>>,
        calls: Mutex<Vec<Chain>>,
    }

    impl SettlementDriver for FakeSettlement {
        fn resume_next(&self, chain: Chain) -> SettlementDriverFuture<'_> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(chain);
                self.outcomes
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Ok(ResumeOutcome::Idle))
            })
        }
    }

    fn policy() -> PayoutLoopPolicy {
        PayoutLoopPolicy {
            poll_interval: Duration::from_millis(1),
            retry_initial: Duration::from_millis(1),
            retry_maximum: Duration::from_millis(4),
            maximum_consecutive_failures: 3,
            maximum_confirmation_watches: 32,
        }
    }

    fn observation(chain: Chain) -> WalletObservation {
        WalletObservation {
            chain,
            wallet_state_digest: [0x41; 32],
            wallet_spendable_zat: 50_000,
            best_tip_hash: [0x51; 32],
            best_tip_height: 200,
            observed_at: 1_000,
            valid_until: 1_240,
        }
    }

    fn reconciliation(chain: Chain, observed: &WalletObservation) -> WalletReconciliation {
        WalletReconciliation {
            id: RECONCILIATION_ID,
            chain,
            ledger_root: [0x61; 32],
            ledger_transaction_count: 7,
            wallet_spendable_zat: observed.wallet_spendable_zat,
            best_tip_hash: observed.best_tip_hash,
            best_tip_height: observed.best_tip_height,
            observed_at: observed.observed_at,
            valid_until: observed.valid_until,
        }
    }

    fn batch(chain: Chain, reconciliation_id: Uuid) -> PayoutBatch {
        PayoutBatch {
            id: BATCH_ID,
            chain,
            state: PayoutBatchState::Draft,
            policy_version: 1,
            reconciliation_id,
            ledger_root: [0x62; 32],
            ledger_sequence_cutoff: 8,
            miner_total_zat: 10_001,
            payout_total_zat: 10_000,
            maximum_network_fee_zat: 1,
            outputs: vec![PayoutInstruction {
                allocation_id: Uuid::from_u128(0x2001),
                account_id: Uuid::from_u128(0x2002),
                destination_id: Uuid::from_u128(0x2003),
                receiver_kind: ReceiverKind::Ironwood,
                address: "test-only-recipient".to_owned(),
                liability_amount_zat: 10_001,
                amount_zat: 10_000,
            }],
        }
    }

    fn snapshot(chain: Chain, payouts: Vec<AuthorityPayoutObservation>) -> AuthoritySnapshot {
        AuthoritySnapshot {
            chain,
            best_tip_hash: [0x51; 32],
            best_tip_height: 200,
            observed_at: 1_001,
            payouts,
        }
    }

    fn runtime(
        chain: Chain,
        store: Arc<FakeStore>,
        wallet: Arc<FakeWallet>,
        authority: Arc<FakeAuthority>,
        outcomes: impl IntoIterator<Item = Result<ResumeOutcome, SettlementError>>,
    ) -> Result<(AutomaticPayoutRuntime, Arc<FakeSettlement>), PayoutRuntimeError> {
        let settlement = Arc::new(FakeSettlement {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        });
        let result = AutomaticPayoutRuntime::new(
            chain,
            NAMESPACE,
            policy(),
            store,
            wallet,
            authority,
            settlement.clone(),
        )?;
        Ok((result, settlement))
    }

    #[tokio::test]
    async fn idle_chain_reconciles_creates_and_broadcasts_one_exact_batch() {
        let chain = Chain::Wcash;
        let store = Arc::new(FakeStore::default());
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(chain, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let (runtime, settlement) = runtime(
            chain,
            store.clone(),
            wallet.clone(),
            authority,
            [
                Ok(ResumeOutcome::Idle),
                Ok(ResumeOutcome::Broadcast {
                    batch_id: BATCH_ID,
                    chain,
                    transaction_id: [0x71; 32],
                }),
            ],
        )
        .unwrap();

        let result = runtime.tick().await.unwrap();
        assert_eq!(result.batch_created, Some(BATCH_ID));
        assert!(matches!(result.settlement, ResumeOutcome::Broadcast { .. }));
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
        assert_eq!(*settlement.calls.lock().unwrap(), [chain, chain]);
        let state = store.state.lock().unwrap();
        assert_eq!(state.reconciliations, [observation(chain)]);
        assert_eq!(state.created_keys.len(), 1);
        let expected = deterministic_batch_key(
            NAMESPACE,
            chain,
            &reconciliation(chain, &observation(chain)),
        );
        assert_eq!(state.created_keys[0], (chain, expected, RECONCILIATION_ID));
    }

    #[tokio::test]
    async fn pending_broadcast_never_observes_wallet_or_creates_another_batch() {
        let chain = Chain::Zcash;
        let watch = PayoutWatch {
            batch_id: BATCH_ID,
            chain,
            state: PayoutBatchState::Broadcast,
            transaction_id: [0x72; 32],
            prior_confirmation: None,
        };
        let store = Arc::new(FakeStore::default());
        store.state.lock().unwrap().watches.push(watch.clone());
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(
                chain,
                vec![AuthorityPayoutObservation {
                    batch_id: watch.batch_id,
                    transaction_id: watch.transaction_id,
                    state: AuthorityPayoutState::Pending,
                }],
            )),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(
            chain,
            store.clone(),
            wallet.clone(),
            authority,
            [Ok(ResumeOutcome::AwaitingConfirmation {
                batch_id: BATCH_ID,
                chain,
                transaction_id: watch.transaction_id,
            })],
        )
        .unwrap();

        let result = runtime.tick().await.unwrap();
        assert_eq!(result.watches_checked, 1);
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
        assert!(store.state.lock().unwrap().created_keys.is_empty());
    }

    #[tokio::test]
    async fn mined_broadcast_is_confirmed_only_with_exact_snapshot_depth() {
        let chain = Chain::Wcash;
        let confirmation = PayoutConfirmation {
            block_hash: [0x81; 32],
            block_height: 101,
            confirmations: 100,
        };
        let watch = PayoutWatch {
            batch_id: BATCH_ID,
            chain,
            state: PayoutBatchState::Broadcast,
            transaction_id: [0x82; 32],
            prior_confirmation: None,
        };
        let store = Arc::new(FakeStore::default());
        {
            let mut state = store.state.lock().unwrap();
            state.watches.push(watch.clone());
            state.create_failure = Some(LifecycleStoreFailure::NoPayableBalances);
        }
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(
                chain,
                vec![AuthorityPayoutObservation {
                    batch_id: BATCH_ID,
                    transaction_id: watch.transaction_id,
                    state: AuthorityPayoutState::Mined(confirmation.clone()),
                }],
            )),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(
            chain,
            store.clone(),
            wallet,
            authority,
            [Ok(ResumeOutcome::Idle)],
        )
        .unwrap();

        let result = runtime.tick().await.unwrap();
        assert_eq!(result.confirmations_recorded, 1);
        assert_eq!(
            store.state.lock().unwrap().confirmations,
            [(BATCH_ID, confirmation)]
        );
    }

    #[tokio::test]
    async fn confirmed_reorg_freezes_before_wallet_or_settlement_activity() {
        let chain = Chain::Zcash;
        let prior = PayoutConfirmation {
            block_hash: [0x91; 32],
            block_height: 100,
            confirmations: 100,
        };
        let watch = PayoutWatch {
            batch_id: BATCH_ID,
            chain,
            state: PayoutBatchState::Confirmed,
            transaction_id: [0x92; 32],
            prior_confirmation: Some(prior.clone()),
        };
        let evidence = PayoutReorg {
            prior_confirmation: prior,
            replacement_tip_hash: [0x51; 32],
            replacement_tip_height: 200,
            observed_at: 1_001,
        };
        let store = Arc::new(FakeStore::default());
        store.state.lock().unwrap().watches.push(watch.clone());
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(
                chain,
                vec![AuthorityPayoutObservation {
                    batch_id: BATCH_ID,
                    transaction_id: watch.transaction_id,
                    state: AuthorityPayoutState::Reorged(evidence.clone()),
                }],
            )),
            calls: AtomicUsize::new(0),
        });
        let (runtime, settlement) =
            runtime(chain, store.clone(), wallet.clone(), authority, []).unwrap();

        assert!(matches!(
            runtime.tick().await,
            Err(PayoutRuntimeError::Frozen {
                chain: Chain::Zcash
            })
        ));
        assert_eq!(store.state.lock().unwrap().reorgs, [(BATCH_ID, evidence)]);
        assert!(store.state.lock().unwrap().cursor_advances.is_empty());
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
        assert!(settlement.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn confirmed_cursor_advances_only_after_a_complete_valid_snapshot() {
        let chain = Chain::Wcash;
        let prior = PayoutConfirmation {
            block_hash: [0x93; 32],
            block_height: 101,
            confirmations: 100,
        };
        let watch = PayoutWatch {
            batch_id: BATCH_ID,
            chain,
            state: PayoutBatchState::Confirmed,
            transaction_id: [0x94; 32],
            prior_confirmation: Some(prior.clone()),
        };
        let store = Arc::new(FakeStore::default());
        {
            let mut state = store.state.lock().unwrap();
            state.watches.push(watch.clone());
            state.create_failure = Some(LifecycleStoreFailure::NoPayableBalances);
        }
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(
                chain,
                vec![AuthorityPayoutObservation {
                    batch_id: BATCH_ID,
                    transaction_id: watch.transaction_id,
                    state: AuthorityPayoutState::Mined(prior),
                }],
            )),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(
            chain,
            store.clone(),
            wallet,
            authority,
            [Ok(ResumeOutcome::Idle)],
        )
        .unwrap();

        runtime.tick().await.unwrap();
        let state = store.state.lock().unwrap();
        assert_eq!(state.cursor_advances.len(), 1);
        assert_eq!(state.cursor_advances[0].0, chain);
        assert_eq!(
            state.cursor_advances[0].1.checked_through_batch_id,
            BATCH_ID
        );
    }

    #[tokio::test]
    async fn invalid_confirmed_snapshot_and_failed_reorg_never_advance_cursor() {
        let chain = Chain::Zcash;
        let prior = PayoutConfirmation {
            block_hash: [0x95; 32],
            block_height: 100,
            confirmations: 101,
        };
        let watch = PayoutWatch {
            batch_id: BATCH_ID,
            chain,
            state: PayoutBatchState::Confirmed,
            transaction_id: [0x96; 32],
            prior_confirmation: Some(prior.clone()),
        };
        let store = Arc::new(FakeStore::default());
        store.state.lock().unwrap().watches.push(watch.clone());
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let incomplete = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(chain, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let (invalid_runtime, _) =
            runtime(chain, store.clone(), wallet.clone(), incomplete, []).unwrap();
        assert!(invalid_runtime.tick().await.is_err());
        assert!(store.state.lock().unwrap().cursor_advances.is_empty());

        store.state.lock().unwrap().reorg_failure = Some(LifecycleStoreFailure::Unavailable);
        let failed_reorg = PayoutReorg {
            prior_confirmation: prior,
            replacement_tip_hash: [0x51; 32],
            replacement_tip_height: 200,
            observed_at: 1_001,
        };
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(
                chain,
                vec![AuthorityPayoutObservation {
                    batch_id: BATCH_ID,
                    transaction_id: watch.transaction_id,
                    state: AuthorityPayoutState::Reorged(failed_reorg),
                }],
            )),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(chain, store.clone(), wallet, authority, []).unwrap();
        assert!(matches!(
            runtime.tick().await,
            Err(PayoutRuntimeError::StoreUnavailable {
                operation: "mark_reorged",
                ..
            })
        ));
        assert!(store.state.lock().unwrap().cursor_advances.is_empty());
    }

    #[tokio::test]
    async fn incomplete_or_substituted_validator_results_fail_closed() {
        let chain = Chain::Wcash;
        let store = Arc::new(FakeStore::default());
        store.state.lock().unwrap().watches.push(PayoutWatch {
            batch_id: BATCH_ID,
            chain,
            state: PayoutBatchState::Broadcast,
            transaction_id: [0xa1; 32],
            prior_confirmation: None,
        });
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(chain, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let (runtime, settlement) = runtime(chain, store, wallet.clone(), authority, []).unwrap();

        assert!(matches!(
            runtime.tick().await,
            Err(PayoutRuntimeError::Invariant {
                operation: "validator_snapshot",
                ..
            })
        ));
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
        assert!(settlement.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wallet_and_validator_must_report_the_same_exact_tip() {
        let chain = Chain::Wcash;
        let store = Arc::new(FakeStore::default());
        let mut stale = observation(chain);
        stale.best_tip_height -= 1;
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(stale),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(chain, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(
            chain,
            store.clone(),
            wallet,
            authority,
            [Ok(ResumeOutcome::Idle)],
        )
        .unwrap();

        assert!(matches!(
            runtime.tick().await,
            Err(PayoutRuntimeError::AuthorityUnavailable {
                operation: "wallet_validator_tip_race",
                ..
            })
        ));
        assert!(store.state.lock().unwrap().reconciliations.is_empty());
    }

    #[tokio::test]
    async fn settlement_result_can_never_cross_the_configured_chain() {
        let chain = Chain::Wcash;
        let store = Arc::new(FakeStore::default());
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(chain, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(
            chain,
            store,
            wallet,
            authority,
            [Ok(ResumeOutcome::Broadcast {
                batch_id: BATCH_ID,
                chain: Chain::Zcash,
                transaction_id: [0xb1; 32],
            })],
        )
        .unwrap();

        assert!(matches!(
            runtime.tick().await,
            Err(PayoutRuntimeError::Invariant {
                operation: "settlement_outcome_binding",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn repeated_transient_failure_exhausts_bounded_budget() {
        let chain = Chain::Wcash;
        let store = Arc::new(FakeStore::default());
        store.state.lock().unwrap().watch_failure = Some(LifecycleStoreFailure::Unavailable);
        let wallet = Arc::new(FakeWallet {
            chain,
            observation: Ok(observation(chain)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain,
            snapshot: Ok(snapshot(chain, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let (runtime, _) = runtime(chain, store, wallet, authority, []).unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        assert!(matches!(
            runtime.run(shutdown_rx).await,
            Err(PayoutRuntimeError::FailureBudgetExhausted { attempts: 3, .. })
        ));
    }

    #[test]
    fn deterministic_keys_are_stable_and_chain_separated() {
        let observed = observation(Chain::Wcash);
        let checkpoint = reconciliation(Chain::Wcash, &observed);
        let first = deterministic_batch_key(NAMESPACE, Chain::Wcash, &checkpoint);
        let replay = deterministic_batch_key(NAMESPACE, Chain::Wcash, &checkpoint);
        let zec = deterministic_batch_key(NAMESPACE, Chain::Zcash, &checkpoint);
        let other_namespace =
            deterministic_batch_key(Uuid::from_u128(0x3001), Chain::Wcash, &checkpoint);
        assert_eq!(first, replay);
        assert_ne!(first, zec);
        assert_ne!(first, other_namespace);
        assert_eq!(first.get_version_num(), 8);
    }

    #[test]
    fn constructor_rejects_cross_chain_observers() {
        let store = Arc::new(FakeStore::default());
        let wallet = Arc::new(FakeWallet {
            chain: Chain::Zcash,
            observation: Ok(observation(Chain::Zcash)),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(FakeAuthority {
            chain: Chain::Wcash,
            snapshot: Ok(snapshot(Chain::Wcash, Vec::new())),
            calls: AtomicUsize::new(0),
        });
        let settlement = Arc::new(FakeSettlement {
            outcomes: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        });
        assert!(matches!(
            AutomaticPayoutRuntime::new(
                Chain::Wcash,
                NAMESPACE,
                policy(),
                store,
                wallet,
                authority,
                settlement,
            ),
            Err(PayoutRuntimeError::InvalidConfiguration)
        ));
    }
}

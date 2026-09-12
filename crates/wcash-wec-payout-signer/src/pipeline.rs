//! Exact, resumable Wcash Testnet payout orchestration.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;
use wcash_pool_portal::{
    Asset, BroadcastReceipt, ChainNetwork, IsolatedPayoutSigner, PayoutBatchRequest, ReceiverKind,
    SignerError,
};

use crate::{
    journal::{Journal, JournalRecord, StoredArtifact, StoredStage},
    BroadcastDisposition, BroadcastFailure, NativeWalletError, NativeWalletTransport,
    PersistedIntent, WalletBroadcastCall, WalletFundSource, WalletIdentity, WalletInspectionCall,
    WalletNetwork, WalletOutput, WalletRecoveryCall, WalletSignCall, WalletSignedTransaction,
    WecPayoutError, WecPipelineStage, WecSignerConfig, WCASH_TESTNET_BRANCH_ID,
    WCASH_TESTNET_GENESIS_HASH,
};

const PIPELINE_COMMITMENT_DOMAIN: &[u8] = b"zecwec/wec-payout-pipeline/v1";
const OUTPUT_MEMO_DOMAIN: &[u8] = b"ZECWEC-WEC-PAYOUT-V1";
const MAX_WEC_ZAT: u64 = 2_100_000_000_000_000;
const MAX_RAW_TRANSACTION_HEX_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXPIRY_DELTA: u32 = 100;

/// Exact accounting batch plus its explicitly fenced Wcash source wallet.
#[derive(Clone, Eq, PartialEq)]
pub struct WecPayoutRequest {
    /// Accounting-frozen payout batch.
    pub batch: PayoutBatchRequest,
    /// Exact native wallet account UUID.
    pub source_account: Uuid,
    /// Shielded value pool from which funds may be selected.
    pub fund_source: WalletFundSource,
}

impl fmt::Debug for WecPayoutRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WecPayoutRequest")
            .field("batch", &self.batch)
            .field("source_account", &self.source_account)
            .field("fund_source", &self.fund_source)
            .finish()
    }
}

/// Successful payout plus the exact artifact needed by the durable store.
#[derive(Clone, Eq, PartialEq)]
pub struct WecPayoutExecution {
    /// Portal-compatible public receipt.
    pub receipt: BroadcastReceipt,
    /// Digest of the wallet-verified unsigned intent.
    pub unsigned_digest: [u8; 32],
    /// Decoded display-order transaction identifier.
    pub transaction_id_bytes: [u8; 32],
    /// Exact signed transaction bytes.
    pub signed_transaction: Vec<u8>,
    /// Exact network fee reconciled against WEC collector value.
    pub network_fee_zat: u64,
    /// Accepted or already-known result.
    pub disposition: BroadcastDisposition,
}

impl fmt::Debug for WecPayoutExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WecPayoutExecution")
            .field("receipt", &self.receipt)
            .field("unsigned_digest", &self.unsigned_digest)
            .field("transaction_id_bytes", &self.transaction_id_bytes)
            .field("signed_transaction", &"[REDACTED]")
            .field("network_fee_zat", &self.network_fee_zat)
            .field("disposition", &self.disposition)
            .finish()
    }
}

/// One deterministic interruption point around native calls and durable writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Checkpoint {
    /// Wallet identity was returned and verified.
    IdentityReturned,
    /// Seedless recovery returned.
    RecoveryReturned,
    /// Proving/signing returned a wallet-persisted transaction.
    SigningReturned,
    /// Independent persisted-intent inspection returned and verified.
    InspectionReturned,
    /// Node broadcast returned a resolved or unresolved class.
    BroadcastReturned(WecPipelineStage),
    /// A stage file and its parent directory were synchronized.
    StagePersisted(WecPipelineStage),
}

/// Optional deterministic crash-injection hook.
pub trait CheckpointHook: Send + Sync {
    /// Returns `true` to emulate interruption at this exact point.
    fn should_interrupt(&self, checkpoint: Checkpoint) -> bool;
}

#[derive(Debug, Default)]
struct NoopCheckpoint;

impl CheckpointHook for NoopCheckpoint {
    fn should_interrupt(&self, _checkpoint: Checkpoint) -> bool {
        false
    }
}

/// Testnet-only WEC payout signer coordinator.
pub struct WecPayoutSigner {
    config: WecSignerConfig,
    journal: Journal,
    wallet: Arc<dyn NativeWalletTransport>,
    checkpoint_hook: Arc<dyn CheckpointHook>,
    process_lock: Mutex<()>,
}

impl WecPayoutSigner {
    /// Creates a signer around an idempotent native-wallet boundary.
    pub fn new(
        config: WecSignerConfig,
        wallet: Arc<dyn NativeWalletTransport>,
    ) -> Result<Self, WecPayoutError> {
        config.validate()?;
        let journal = Journal::open(config.journal_directory())?;
        Ok(Self {
            config,
            journal,
            wallet,
            checkpoint_hook: Arc::new(NoopCheckpoint),
            process_lock: Mutex::new(()),
        })
    }

    /// Installs a deterministic checkpoint hook, primarily for restart tests.
    pub fn with_checkpoint_hook(mut self, hook: Arc<dyn CheckpointHook>) -> Self {
        self.checkpoint_hook = hook;
        self
    }

    /// Confirms the exact public-Testnet identity and a synchronized Ironwood
    /// collector without reading spending authority.
    pub fn readiness(&self) -> Result<(), WecPayoutError> {
        self.config.validate()?;
        let limits = self.config.limits();
        let identity = self
            .wallet
            .identity(limits.recovery_timeout(), limits.max_response_bytes())
            .map_err(map_readonly_wallet_error)?;
        self.verify_identity(&identity)
    }

    /// Executes or resumes one exact accounting batch.
    ///
    /// Exact retries recover or rebroadcast the original transaction. A batch
    /// identifier previously bound to different facts is always fatal.
    pub fn execute(
        &self,
        request: &WecPayoutRequest,
    ) -> Result<WecPayoutExecution, WecPayoutError> {
        self.config.validate()?;
        let validated = self.validate_request(request)?;
        let _process_guard = lock_without_poison(&self.process_lock);
        self.journal
            .with_exclusive_lock(|| self.execute_locked(request, validated))
    }

    fn execute_locked(
        &self,
        request: &WecPayoutRequest,
        validated: ValidatedRequest,
    ) -> Result<WecPayoutExecution, WecPayoutError> {
        let mut record = match self.journal.load(request.batch.batch_id)? {
            Some(record) => {
                if record.pipeline_commitment != validated.pipeline_commitment
                    || record.portal_commitment != validated.portal_commitment
                    || record.output_total_zat != validated.output_total_zat
                {
                    return Err(WecPayoutError::IdempotencyConflict);
                }
                record
            }
            None => {
                let record = JournalRecord {
                    batch_id: request.batch.batch_id,
                    pipeline_commitment: validated.pipeline_commitment,
                    portal_commitment: validated.portal_commitment,
                    output_total_zat: validated.output_total_zat,
                    stage: StoredStage::Reserved,
                };
                self.persist(&record)?;
                record
            }
        };

        loop {
            match record.stage.clone() {
                StoredStage::Reserved => {
                    let artifact = self.create_or_recover(request, &validated)?;
                    record.stage = StoredStage::Signed { artifact };
                    self.persist(&record)?;
                }
                StoredStage::Signed { artifact }
                | StoredStage::BroadcastUnresolved { artifact } => {
                    let call = WalletBroadcastCall {
                        batch_id: record.batch_id,
                        request_commitment: record.pipeline_commitment,
                        transaction_id: artifact.transaction_id.clone(),
                        raw_transaction_hex: artifact.raw_transaction_hex.clone(),
                        timeout: self.config.limits().broadcast_timeout(),
                        max_response_bytes: self.config.limits().max_response_bytes(),
                    };
                    match self.wallet.broadcast_exact(&call) {
                        Ok(outcome) => {
                            if outcome.transaction_id != artifact.transaction_id {
                                record.stage = StoredStage::BroadcastUnresolved { artifact };
                                self.persist_broadcast_result(
                                    &record,
                                    WecPipelineStage::BroadcastUnresolved,
                                )?;
                                return Err(WecPayoutError::BroadcastAmbiguous);
                            }
                            self.checkpoint(Checkpoint::BroadcastReturned(
                                WecPipelineStage::Completed,
                            ))?;
                            let disposition = outcome.disposition;
                            record.stage = StoredStage::Completed {
                                artifact,
                                disposition: disposition.into(),
                            };
                            self.persist(&record)?;
                            return execution_from_record(&record, disposition);
                        }
                        Err(BroadcastFailure::Rejected) => {
                            self.checkpoint(Checkpoint::BroadcastReturned(
                                WecPipelineStage::Rejected,
                            ))?;
                            record.stage = StoredStage::Rejected { artifact };
                            self.persist(&record)?;
                            return Err(WecPayoutError::BroadcastRejected);
                        }
                        Err(
                            BroadcastFailure::Timeout
                            | BroadcastFailure::Unavailable
                            | BroadcastFailure::Ambiguous
                            | BroadcastFailure::ProtocolViolation,
                        ) => {
                            self.checkpoint(Checkpoint::BroadcastReturned(
                                WecPipelineStage::BroadcastUnresolved,
                            ))?;
                            record.stage = StoredStage::BroadcastUnresolved { artifact };
                            self.persist(&record)?;
                            return Err(WecPayoutError::BroadcastAmbiguous);
                        }
                    }
                }
                StoredStage::Rejected { .. } => return Err(WecPayoutError::BroadcastRejected),
                StoredStage::Completed { disposition, .. } => {
                    return execution_from_record(&record, disposition.into());
                }
            }
        }
    }

    fn create_or_recover(
        &self,
        request: &WecPayoutRequest,
        validated: &ValidatedRequest,
    ) -> Result<StoredArtifact, WecPayoutError> {
        let limits = self.config.limits();
        let identity = self
            .wallet
            .identity(limits.recovery_timeout(), limits.max_response_bytes())
            .map_err(map_readonly_wallet_error)?;
        self.verify_identity(&identity)?;
        self.checkpoint(Checkpoint::IdentityReturned)?;

        let recovery = WalletRecoveryCall {
            batch_id: request.batch.batch_id,
            request_commitment: validated.pipeline_commitment,
            timeout: limits.recovery_timeout(),
            max_response_bytes: limits.max_response_bytes(),
        };
        let recovered = self
            .wallet
            .recover_exact(&recovery)
            .map_err(map_recovery_error)?;
        self.checkpoint(Checkpoint::RecoveryReturned)?;

        let signed = match recovered {
            Some(signed) => signed,
            None => {
                let seed = self.config.seed_source().read()?;
                let sign_call = WalletSignCall {
                    batch_id: request.batch.batch_id,
                    request_commitment: validated.pipeline_commitment,
                    identity,
                    outputs: validated.outputs.clone(),
                    confirmations: self.config.confirmations(),
                    max_fee_zat: self.config.max_fee_zat(),
                    timeout: limits.sign_timeout(),
                    max_response_bytes: limits.max_response_bytes(),
                };
                let signed = self
                    .wallet
                    .sign_exact(&sign_call, &seed)
                    .map_err(map_signing_error)?;
                self.checkpoint(Checkpoint::SigningReturned)?;
                signed
            }
        };
        self.verify_signed(&signed, request, validated)?;

        let inspection_call = WalletInspectionCall {
            batch_id: request.batch.batch_id,
            request_commitment: validated.pipeline_commitment,
            transaction_id: signed.transaction_id.clone(),
            raw_transaction_hex: signed.raw_transaction_hex.clone(),
            timeout: limits.inspection_timeout(),
            max_response_bytes: limits.max_response_bytes(),
        };
        let inspected = self
            .wallet
            .inspect_persisted(&inspection_call)
            .map_err(map_inspection_error)?;
        self.verify_inspection(&inspected, &signed, request, validated)?;
        self.checkpoint(Checkpoint::InspectionReturned)?;

        Ok(StoredArtifact {
            raw_transaction_hex: signed.raw_transaction_hex,
            transaction_id: signed.transaction_id,
            unsigned_digest: signed.unsigned_digest,
            fee_zat: signed.fee_zat,
            target_height: signed.target_height,
            expiry_height: signed.expiry_height,
        })
    }

    fn validate_request(
        &self,
        request: &WecPayoutRequest,
    ) -> Result<ValidatedRequest, WecPayoutError> {
        if request.batch.asset != Asset::Wec {
            return Err(WecPayoutError::WrongAsset);
        }
        if request.batch.network != ChainNetwork::Testnet {
            return Err(WecPayoutError::WrongNetwork);
        }
        if request.source_account != self.config.source_account() {
            return Err(WecPayoutError::WrongAccount);
        }
        if request.fund_source != WalletFundSource::Ironwood {
            return Err(WecPayoutError::WrongFundSource);
        }
        let output_total_zat = request
            .batch
            .validate()
            .map_err(|_| WecPayoutError::InvalidRequest)?;
        if request.batch.outputs.len() > self.config.max_outputs()
            || output_total_zat > MAX_WEC_ZAT
            || output_total_zat
                .checked_add(self.config.max_fee_zat())
                .is_none_or(|total| total > MAX_WEC_ZAT)
            || request
                .batch
                .outputs
                .iter()
                .any(|output| output.receiver_kind != ReceiverKind::Ironwood)
        {
            return Err(WecPayoutError::InvalidRequest);
        }
        let portal_commitment = request
            .batch
            .commitment()
            .map_err(|_| WecPayoutError::InvalidRequest)?;
        let pipeline_commitment = pipeline_commitment(request, portal_commitment, &self.config);
        let outputs = request
            .batch
            .outputs
            .iter()
            .enumerate()
            .map(|(ordinal, output)| {
                Ok(WalletOutput {
                    allocation_id: output.allocation_id,
                    canonical_address: output.canonical_address.clone(),
                    receiver_kind: output.receiver_kind,
                    amount_zat: output.amount_zat,
                    memo: output_memo(
                        request.batch.batch_id,
                        portal_commitment,
                        output.allocation_id,
                        ordinal,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, WecPayoutError>>()?;
        Ok(ValidatedRequest {
            portal_commitment,
            pipeline_commitment,
            output_total_zat,
            outputs,
        })
    }

    fn verify_identity(&self, identity: &WalletIdentity) -> Result<(), WecPayoutError> {
        if identity.network != WalletNetwork::Testnet
            || identity.genesis_hash != WCASH_TESTNET_GENESIS_HASH
            || identity.branch_id != WCASH_TESTNET_BRANCH_ID
        {
            return Err(WecPayoutError::WrongNetwork);
        }
        if identity.account_id != self.config.source_account() {
            return Err(WecPayoutError::WrongAccount);
        }
        if identity.fund_source != WalletFundSource::Ironwood {
            return Err(WecPayoutError::WrongFundSource);
        }
        if !identity.synchronized {
            return Err(WecPayoutError::WalletUnavailable);
        }
        Ok(())
    }

    fn verify_signed(
        &self,
        signed: &WalletSignedTransaction,
        request: &WecPayoutRequest,
        validated: &ValidatedRequest,
    ) -> Result<(), WecPayoutError> {
        let valid_expiry = signed
            .expiry_height
            .checked_sub(signed.target_height)
            .is_some_and(|delta| (1..=MAX_EXPIRY_DELTA).contains(&delta));
        if signed.batch_id != request.batch.batch_id
            || signed.request_commitment != validated.pipeline_commitment
            || !valid_transaction_id(&signed.transaction_id)
            || !valid_raw_transaction(&signed.raw_transaction_hex)
            || signed.unsigned_digest == [0; 32]
            || signed.fee_zat == 0
            || signed.fee_zat > self.config.max_fee_zat()
            || signed.target_height == 0
            || !valid_expiry
            || !signed.stored
            || !signed.internal_change_receiver_verified
        {
            return Err(WecPayoutError::WalletProtocolViolation);
        }
        Ok(())
    }

    fn verify_inspection(
        &self,
        inspected: &PersistedIntent,
        signed: &WalletSignedTransaction,
        request: &WecPayoutRequest,
        validated: &ValidatedRequest,
    ) -> Result<(), WecPayoutError> {
        self.verify_identity(&inspected.identity)
            .map_err(|_| WecPayoutError::WalletProtocolViolation)?;
        let raw = hex::decode(&signed.raw_transaction_hex)
            .map_err(|_| WecPayoutError::WalletProtocolViolation)?;
        let raw_digest: [u8; 32] = Sha256::digest(raw).into();
        if inspected.batch_id != request.batch.batch_id
            || inspected.request_commitment != validated.pipeline_commitment
            || inspected.ordered_outputs != validated.outputs
            || inspected.unsigned_digest != signed.unsigned_digest
            || inspected.transaction_id != signed.transaction_id
            || inspected.raw_transaction_sha256 != raw_digest
            || inspected.fee_zat != signed.fee_zat
            || inspected.target_height != signed.target_height
            || inspected.expiry_height != signed.expiry_height
            || !inspected.stored
            || !inspected.internal_change_receiver_verified
        {
            return Err(WecPayoutError::WalletProtocolViolation);
        }
        Ok(())
    }

    fn persist(&self, record: &JournalRecord) -> Result<(), WecPayoutError> {
        self.journal.store(record)?;
        self.checkpoint(Checkpoint::StagePersisted(record.stage.public_stage()))
    }

    fn persist_broadcast_result(
        &self,
        record: &JournalRecord,
        stage: WecPipelineStage,
    ) -> Result<(), WecPayoutError> {
        self.checkpoint(Checkpoint::BroadcastReturned(stage))?;
        self.persist(record)
    }

    fn checkpoint(&self, checkpoint: Checkpoint) -> Result<(), WecPayoutError> {
        if self.checkpoint_hook.should_interrupt(checkpoint) {
            Err(WecPayoutError::Interrupted)
        } else {
            Ok(())
        }
    }
}

impl IsolatedPayoutSigner for WecPayoutSigner {
    fn readiness(&self) -> Result<(), SignerError> {
        WecPayoutSigner::readiness(self).map_err(map_portal_error)
    }

    fn sign_and_broadcast(
        &self,
        request: &PayoutBatchRequest,
    ) -> Result<BroadcastReceipt, SignerError> {
        let execution = self
            .execute(&WecPayoutRequest {
                batch: request.clone(),
                source_account: self.config.source_account(),
                fund_source: WalletFundSource::Ironwood,
            })
            .map_err(map_portal_error)?;
        Ok(execution.receipt)
    }
}

struct ValidatedRequest {
    portal_commitment: [u8; 32],
    pipeline_commitment: [u8; 32],
    output_total_zat: u64,
    outputs: Vec<WalletOutput>,
}

fn pipeline_commitment(
    request: &WecPayoutRequest,
    portal_commitment: [u8; 32],
    config: &WecSignerConfig,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PIPELINE_COMMITMENT_DOMAIN);
    hasher.update(portal_commitment);
    hasher.update(request.source_account.as_bytes());
    hasher.update([fund_source_tag(request.fund_source)]);
    hasher.update(config.confirmations().to_be_bytes());
    hasher.update(config.max_fee_zat().to_be_bytes());
    hasher.update(WCASH_TESTNET_GENESIS_HASH.as_bytes());
    hasher.update(WCASH_TESTNET_BRANCH_ID.as_bytes());
    hasher.finalize().into()
}

fn fund_source_tag(source: WalletFundSource) -> u8 {
    match source {
        WalletFundSource::Ironwood => 1,
        WalletFundSource::Sapling => 2,
        WalletFundSource::Transparent => 3,
    }
}

fn output_memo(
    batch_id: Uuid,
    portal_commitment: [u8; 32],
    allocation_id: Uuid,
    ordinal: usize,
) -> Result<Vec<u8>, WecPayoutError> {
    let ordinal = u16::try_from(ordinal).map_err(|_| WecPayoutError::InvalidRequest)?;
    let mut memo = Vec::with_capacity(OUTPUT_MEMO_DOMAIN.len() + 1 + 16 + 32 + 16 + 2);
    memo.extend_from_slice(OUTPUT_MEMO_DOMAIN);
    memo.push(0);
    memo.extend_from_slice(batch_id.as_bytes());
    memo.extend_from_slice(&portal_commitment);
    memo.extend_from_slice(allocation_id.as_bytes());
    memo.extend_from_slice(&ordinal.to_be_bytes());
    Ok(memo)
}

fn valid_transaction_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_raw_transaction(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RAW_TRANSACTION_HEX_BYTES
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn execution_from_record(
    record: &JournalRecord,
    disposition: BroadcastDisposition,
) -> Result<WecPayoutExecution, WecPayoutError> {
    let artifact = record
        .stage
        .artifact()
        .ok_or(WecPayoutError::JournalCorrupt)?;
    let signed_transaction =
        hex::decode(&artifact.raw_transaction_hex).map_err(|_| WecPayoutError::JournalCorrupt)?;
    let transaction_id =
        hex::decode(&artifact.transaction_id).map_err(|_| WecPayoutError::JournalCorrupt)?;
    let transaction_id_bytes: [u8; 32] = transaction_id
        .try_into()
        .map_err(|_| WecPayoutError::JournalCorrupt)?;
    Ok(WecPayoutExecution {
        receipt: BroadcastReceipt {
            batch_id: record.batch_id,
            request_commitment: record.portal_commitment,
            asset: Asset::Wec,
            transaction_id: artifact.transaction_id.clone(),
            output_total_zat: record.output_total_zat,
        },
        unsigned_digest: artifact.unsigned_digest,
        transaction_id_bytes,
        signed_transaction,
        network_fee_zat: artifact.fee_zat,
        disposition,
    })
}

fn map_readonly_wallet_error(error: NativeWalletError) -> WecPayoutError {
    match error {
        NativeWalletError::IdempotencyConflict => WecPayoutError::IdempotencyConflict,
        NativeWalletError::Rejected | NativeWalletError::ProtocolViolation => {
            WecPayoutError::WalletProtocolViolation
        }
        NativeWalletError::Timeout
        | NativeWalletError::Unavailable
        | NativeWalletError::Ambiguous => WecPayoutError::WalletUnavailable,
    }
}

fn map_recovery_error(error: NativeWalletError) -> WecPayoutError {
    match error {
        NativeWalletError::IdempotencyConflict => WecPayoutError::IdempotencyConflict,
        NativeWalletError::ProtocolViolation | NativeWalletError::Rejected => {
            WecPayoutError::WalletProtocolViolation
        }
        NativeWalletError::Timeout
        | NativeWalletError::Unavailable
        | NativeWalletError::Ambiguous => WecPayoutError::WalletAmbiguous,
    }
}

fn map_signing_error(error: NativeWalletError) -> WecPayoutError {
    match error {
        NativeWalletError::IdempotencyConflict => WecPayoutError::IdempotencyConflict,
        NativeWalletError::Rejected => WecPayoutError::WalletRejected,
        NativeWalletError::ProtocolViolation => WecPayoutError::WalletProtocolViolation,
        NativeWalletError::Timeout
        | NativeWalletError::Unavailable
        | NativeWalletError::Ambiguous => WecPayoutError::WalletAmbiguous,
    }
}

fn map_inspection_error(error: NativeWalletError) -> WecPayoutError {
    match error {
        NativeWalletError::IdempotencyConflict => WecPayoutError::IdempotencyConflict,
        NativeWalletError::ProtocolViolation | NativeWalletError::Rejected => {
            WecPayoutError::WalletProtocolViolation
        }
        NativeWalletError::Timeout
        | NativeWalletError::Unavailable
        | NativeWalletError::Ambiguous => WecPayoutError::WalletUnavailable,
    }
}

fn map_portal_error(error: WecPayoutError) -> SignerError {
    match error {
        WecPayoutError::WrongNetwork => SignerError::WrongNetwork,
        WecPayoutError::IdempotencyConflict => SignerError::IdempotencyConflict,
        WecPayoutError::BroadcastAmbiguous | WecPayoutError::WalletAmbiguous => {
            SignerError::AmbiguousBroadcast
        }
        WecPayoutError::BroadcastRejected | WecPayoutError::WalletRejected => SignerError::Rejected,
        WecPayoutError::InvalidRequest
        | WecPayoutError::WrongAsset
        | WecPayoutError::WrongAccount
        | WecPayoutError::WrongFundSource
        | WecPayoutError::UnsafeCredential
        | WecPayoutError::JournalUnavailable
        | WecPayoutError::JournalCorrupt
        | WecPayoutError::WalletUnavailable
        | WecPayoutError::WalletProtocolViolation
        | WecPayoutError::Interrupted => SignerError::Rejected,
    }
}

fn lock_without_poison(lock: &Mutex<()>) -> MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

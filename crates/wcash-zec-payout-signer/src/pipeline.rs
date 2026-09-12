//! Exact, resumable Zallet PCZT orchestration.

use std::{
    collections::HashSet,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use serde::Deserialize;
use serde_json::{json, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wcash_pool_portal::{
    Asset, BroadcastReceipt, ChainNetwork, IsolatedPayoutSigner, PayoutBatchRequest, ReceiverKind,
    SignerError,
};

use crate::{
    address::validate_destination,
    journal::{Journal, JournalRecord, StoredStage},
    JsonRpcTransport, PipelineStage, RpcCall, ZecPayoutError, ZecSignerConfig, ZALLET_API_VERSION,
};

const PIPELINE_COMMITMENT_DOMAIN: &[u8] = b"zecwec/zec-pczt-pipeline/v1";
const MAX_ZEC_ZAT: u64 = 2_100_000_000_000_000;
const PCZT_CREATE: &str = "pczt_create";
const PCZT_INSPECT: &str = "pczt_inspect";
const PCZT_PROVE: &str = "pczt_prove";
const PCZT_SIGN: &str = "pczt_sign";
const PCZT_EXTRACT: &str = "pczt_extract";
const GET_WALLET_STATUS: &str = "getwalletstatus";
const SEND_RAW_TRANSACTION: &str = "sendrawtransaction";

/// The only source accepted for private collector payouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZecFundSource {
    /// Zallet's isolating Orchard-family source, including Ironwood funds.
    Orchard,
    /// Legacy Sapling funds, deliberately unsupported by this signer.
    Sapling,
    /// Transparent account funds, deliberately unsupported by this signer.
    AnyTransparent,
}

impl ZecFundSource {
    const fn commitment_tag(self) -> u8 {
        match self {
            Self::Orchard => 1,
            Self::Sapling => 2,
            Self::AnyTransparent => 3,
        }
    }

    const fn rpc_value(self) -> &'static str {
        match self {
            Self::Orchard => "orchard",
            Self::Sapling => "sapling",
            Self::AnyTransparent => "any_transparent",
        }
    }
}

/// Exact accounting batch plus its explicitly fenced source wallet facts.
#[derive(Clone, Eq, PartialEq)]
pub struct ZecPayoutRequest {
    /// Reconciled accounting payout batch.
    pub batch: PayoutBatchRequest,
    /// Zallet account UUID from which funds must be isolated.
    pub source_account: Uuid,
    /// Named isolating Zallet fund source.
    pub fund_source: ZecFundSource,
}

impl fmt::Debug for ZecPayoutRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZecPayoutRequest")
            .field("batch", &self.batch)
            .field("source_account", &self.source_account)
            .field("fund_source", &self.fund_source)
            .finish()
    }
}

/// Successful, durably resolved ZEC payout receipt.
pub type ZecPayoutReceipt = BroadcastReceipt;

/// A fault-injection observation point around external calls and durable writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Checkpoint {
    /// An external RPC returned, but its result is not yet journaled.
    RpcReturned(PipelineStage),
    /// A stage is durable and its parent directory has been synchronized.
    StagePersisted(PipelineStage),
}

/// Optional deterministic crash-injection hook.
pub trait CheckpointHook: Send + Sync {
    /// Returns `true` to emulate process interruption at this exact point.
    fn should_interrupt(&self, checkpoint: Checkpoint) -> bool;
}

#[derive(Debug, Default)]
struct NoopCheckpoint;

impl CheckpointHook for NoopCheckpoint {
    fn should_interrupt(&self, _checkpoint: Checkpoint) -> bool {
        false
    }
}

/// Testnet ZEC signer orchestration without custody of spending keys.
pub struct ZecPcztSigner {
    config: ZecSignerConfig,
    journal: Journal,
    zallet: Arc<dyn JsonRpcTransport>,
    zebra: Arc<dyn JsonRpcTransport>,
    checkpoint_hook: Arc<dyn CheckpointHook>,
    process_lock: Mutex<()>,
}

impl ZecPcztSigner {
    /// Creates a signer after validating the local wallet fence and journal.
    pub fn new(
        config: ZecSignerConfig,
        zallet: Arc<dyn JsonRpcTransport>,
        zebra: Arc<dyn JsonRpcTransport>,
    ) -> Result<Self, ZecPayoutError> {
        config.validate_policy()?;
        crate::validate_zallet_configuration(config.zallet_configuration())?;
        let journal = Journal::open(config.journal_directory())?;
        Ok(Self {
            config,
            journal,
            zallet,
            zebra,
            checkpoint_hook: Arc::new(NoopCheckpoint),
            process_lock: Mutex::new(()),
        })
    }

    /// Installs a deterministic checkpoint hook, primarily for crash testing.
    pub fn with_checkpoint_hook(mut self, hook: Arc<dyn CheckpointHook>) -> Self {
        self.checkpoint_hook = hook;
        self
    }

    /// Verifies the static fence and confirms that Zallet reports an unlocked,
    /// synchronized wallet boundary.
    pub fn readiness(&self) -> Result<(), ZecPayoutError> {
        crate::validate_zallet_configuration(self.config.zallet_configuration())?;
        let value = self.wallet_call(
            GET_WALLET_STATUS,
            json!([]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        let status: WalletStatus =
            serde_json::from_value(value).map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        if status.locked {
            return Err(ZecPayoutError::WalletRpcUnavailable);
        }
        Ok(())
    }

    /// Executes or resumes one exact batch.
    ///
    /// Every exact retry resumes from durable bytes. A retry after an ambiguous
    /// parent-node result re-broadcasts the same raw transaction; it never
    /// creates or signs a replacement.
    pub fn execute(&self, request: &ZecPayoutRequest) -> Result<ZecPayoutReceipt, ZecPayoutError> {
        crate::validate_zallet_configuration(self.config.zallet_configuration())?;
        let (portal_commitment, pipeline_commitment, output_total_zat) =
            self.validate_request(request)?;
        let _process_guard = lock_without_poison(&self.process_lock);
        self.journal.with_exclusive_lock(|| {
            self.execute_locked(
                request,
                portal_commitment,
                pipeline_commitment,
                output_total_zat,
            )
        })
    }

    fn execute_locked(
        &self,
        request: &ZecPayoutRequest,
        portal_commitment: [u8; 32],
        pipeline_commitment: [u8; 32],
        output_total_zat: u64,
    ) -> Result<ZecPayoutReceipt, ZecPayoutError> {
        let mut record = match self.journal.load(request.batch.batch_id)? {
            Some(record) => {
                if record.pipeline_commitment != pipeline_commitment
                    || record.portal_commitment != portal_commitment
                    || record.output_total_zat != output_total_zat
                {
                    return Err(ZecPayoutError::IdempotencyConflict);
                }
                record
            }
            None => {
                let record = JournalRecord {
                    batch_id: request.batch.batch_id,
                    pipeline_commitment,
                    portal_commitment,
                    output_total_zat,
                    stage: StoredStage::Reserved,
                };
                self.persist(&record)?;
                record
            }
        };

        loop {
            match record.stage.clone() {
                StoredStage::Reserved => {
                    let created = self.create_pczt(request)?;
                    self.rpc_checkpoint(PipelineStage::Created)?;
                    validate_privacy_policy(&created.privacy_policy, request)?;
                    validate_pczt(&created.pczt)?;
                    record.stage = StoredStage::Created {
                        pczt: created.pczt,
                        privacy_policy: created.privacy_policy,
                    };
                    self.persist(&record)?;
                }
                StoredStage::Created {
                    pczt,
                    privacy_policy,
                } => {
                    let inspected = self.inspect_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::CreatedVerified)?;
                    self.verify_inspection(
                        request,
                        &privacy_policy,
                        &inspected,
                        ProofRequirement::MayBeMissing,
                    )?;
                    record.stage = StoredStage::CreatedVerified {
                        pczt,
                        privacy_policy,
                    };
                    self.persist(&record)?;
                }
                StoredStage::CreatedVerified {
                    pczt,
                    privacy_policy,
                } => {
                    let proved = self.prove_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::Proved)?;
                    validate_pczt(&proved.pczt)?;
                    let _proof_report = (
                        proved.sapling_proven,
                        proved.orchard_proven,
                        proved.ironwood_proven,
                    );
                    record.stage = StoredStage::Proved {
                        pczt: proved.pczt,
                        privacy_policy,
                    };
                    self.persist(&record)?;
                }
                StoredStage::Proved {
                    pczt,
                    privacy_policy,
                } => {
                    let inspected = self.inspect_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::ProvedVerified)?;
                    self.verify_inspection(
                        request,
                        &privacy_policy,
                        &inspected,
                        ProofRequirement::Complete,
                    )?;
                    record.stage = StoredStage::ProvedVerified {
                        pczt,
                        privacy_policy,
                    };
                    self.persist(&record)?;
                }
                StoredStage::ProvedVerified {
                    pczt,
                    privacy_policy,
                } => {
                    let signed = self.sign_pczt(&pczt, &privacy_policy)?;
                    self.rpc_checkpoint(PipelineStage::Signed)?;
                    signed.validate()?;
                    validate_pczt(&signed.pczt)?;
                    record.stage = StoredStage::Signed {
                        pczt: signed.pczt,
                        privacy_policy,
                    };
                    self.persist(&record)?;
                }
                StoredStage::Signed {
                    pczt,
                    privacy_policy,
                } => {
                    let inspected = self.inspect_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::SignedVerified)?;
                    self.verify_inspection(
                        request,
                        &privacy_policy,
                        &inspected,
                        ProofRequirement::Complete,
                    )?;
                    record.stage = StoredStage::SignedVerified {
                        pczt,
                        privacy_policy,
                    };
                    self.persist(&record)?;
                }
                StoredStage::SignedVerified {
                    pczt,
                    privacy_policy: _,
                } => {
                    let extracted = self.extract_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::Extracted)?;
                    extracted.validate()?;
                    record.stage = StoredStage::Extracted {
                        raw_transaction: extracted.hex,
                        transaction_id: extracted.txid,
                    };
                    self.persist(&record)?;
                }
                StoredStage::Extracted {
                    raw_transaction,
                    transaction_id,
                }
                | StoredStage::BroadcastUnresolved {
                    raw_transaction,
                    transaction_id,
                } => match self.broadcast(&raw_transaction, &transaction_id) {
                    BroadcastOutcome::Accepted | BroadcastOutcome::AlreadyKnown => {
                        self.rpc_checkpoint(PipelineStage::Completed)?;
                        record.stage = StoredStage::Completed {
                            transaction_id: transaction_id.clone(),
                        };
                        self.persist(&record)?;
                        return Ok(receipt(&record, transaction_id));
                    }
                    BroadcastOutcome::Rejected => {
                        self.rpc_checkpoint(PipelineStage::Rejected)?;
                        record.stage = StoredStage::Rejected { transaction_id };
                        self.persist(&record)?;
                        return Err(ZecPayoutError::BroadcastRejected);
                    }
                    BroadcastOutcome::Ambiguous => {
                        self.rpc_checkpoint(PipelineStage::BroadcastUnresolved)?;
                        record.stage = StoredStage::BroadcastUnresolved {
                            raw_transaction,
                            transaction_id,
                        };
                        self.persist(&record)?;
                        return Err(ZecPayoutError::BroadcastAmbiguous);
                    }
                },
                StoredStage::Rejected { .. } => {
                    return Err(ZecPayoutError::BroadcastRejected);
                }
                StoredStage::Completed { transaction_id } => {
                    return Ok(receipt(&record, transaction_id));
                }
            }
        }
    }

    fn validate_request(
        &self,
        request: &ZecPayoutRequest,
    ) -> Result<([u8; 32], [u8; 32], u64), ZecPayoutError> {
        if request.batch.asset != Asset::Zec {
            return Err(ZecPayoutError::WrongAsset);
        }
        if request.batch.network != ChainNetwork::Testnet {
            return Err(ZecPayoutError::WrongNetwork);
        }
        if request.source_account != self.config.account_id() {
            return Err(ZecPayoutError::WrongAccount);
        }
        if request.fund_source != ZecFundSource::Orchard {
            return Err(ZecPayoutError::WrongFundSource);
        }
        if request.batch.outputs.len() > self.config.max_outputs() {
            return Err(ZecPayoutError::InvalidRequest);
        }
        let output_total_zat = request
            .batch
            .validate()
            .map_err(|_| ZecPayoutError::InvalidRequest)?;
        if output_total_zat > MAX_ZEC_ZAT
            || output_total_zat
                .checked_add(self.config.max_fee_zat())
                .is_none_or(|total| total > MAX_ZEC_ZAT)
        {
            return Err(ZecPayoutError::InvalidRequest);
        }
        let mut destinations = HashSet::with_capacity(request.batch.outputs.len());
        for output in &request.batch.outputs {
            if output.amount_zat > MAX_ZEC_ZAT {
                return Err(ZecPayoutError::InvalidRequest);
            }
            if !destinations.insert(output.canonical_address.as_str()) {
                return Err(ZecPayoutError::InvalidRequest);
            }
            validate_destination(&output.canonical_address, output.receiver_kind)?;
        }

        let portal_commitment = request
            .batch
            .commitment()
            .map_err(|_| ZecPayoutError::InvalidRequest)?;
        let mut hasher = Sha256::new();
        hasher.update(PIPELINE_COMMITMENT_DOMAIN);
        hasher.update(portal_commitment);
        hasher.update(request.source_account.as_bytes());
        hasher.update([request.fund_source.commitment_tag()]);
        hasher.update(self.config.min_confirmations().to_be_bytes());
        hasher.update(
            u16::try_from(self.config.max_outputs())
                .map_err(|_| ZecPayoutError::InvalidRequest)?
                .to_be_bytes(),
        );
        hasher.update(self.config.max_fee_zat().to_be_bytes());
        hasher.update(ZALLET_API_VERSION.as_bytes());
        Ok((
            portal_commitment,
            hasher.finalize().into(),
            output_total_zat,
        ))
    }

    fn create_pczt(&self, request: &ZecPayoutRequest) -> Result<CreateResult, ZecPayoutError> {
        let amounts: Result<Vec<Value>, ZecPayoutError> = request
            .batch
            .outputs
            .iter()
            .map(|output| {
                Ok(json!({
                    "address": output.canonical_address,
                    "amount": exact_zec_number(output.amount_zat)?,
                }))
            })
            .collect();
        let result = self.wallet_call(
            PCZT_CREATE,
            json!([
                request.source_account.to_string(),
                amounts?,
                self.config.min_confirmations(),
                "NoPrivacy",
                request.fund_source.rpc_value(),
            ]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        serde_json::from_value(result).map_err(|_| ZecPayoutError::WalletProtocolViolation)
    }

    fn inspect_pczt(&self, pczt: &str) -> Result<InspectResult, ZecPayoutError> {
        let result = self.wallet_call(
            PCZT_INSPECT,
            json!([pczt]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        serde_json::from_value(result).map_err(|_| ZecPayoutError::WalletProtocolViolation)
    }

    fn prove_pczt(&self, pczt: &str) -> Result<ProveResult, ZecPayoutError> {
        let result = self.wallet_call(
            PCZT_PROVE,
            json!([pczt]),
            self.config.rpc_limits().prove_timeout(),
        )?;
        serde_json::from_value(result).map_err(|_| ZecPayoutError::WalletProtocolViolation)
    }

    fn sign_pczt(&self, pczt: &str, privacy_policy: &str) -> Result<SignResult, ZecPayoutError> {
        let result = self.wallet_call(
            PCZT_SIGN,
            json!([pczt, privacy_policy, true]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        serde_json::from_value(result).map_err(|_| ZecPayoutError::WalletProtocolViolation)
    }

    fn extract_pczt(&self, pczt: &str) -> Result<ExtractResult, ZecPayoutError> {
        let result = self.wallet_call(
            PCZT_EXTRACT,
            json!([pczt]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        serde_json::from_value(result).map_err(|_| ZecPayoutError::WalletProtocolViolation)
    }

    fn wallet_call(
        &self,
        method: &'static str,
        params: Value,
        timeout: std::time::Duration,
    ) -> Result<Value, ZecPayoutError> {
        let limit = self.config.rpc_limits().max_response_bytes();
        let result = self
            .zallet
            .call(RpcCall::new(method, params, timeout, limit))
            .map_err(|error| {
                if error.is_server() {
                    ZecPayoutError::WalletRejected
                } else {
                    ZecPayoutError::WalletRpcUnavailable
                }
            })?;
        ensure_response_bound(&result, limit)?;
        Ok(result)
    }

    fn verify_inspection(
        &self,
        request: &ZecPayoutRequest,
        privacy_policy: &str,
        inspected: &InspectResult,
        proof_requirement: ProofRequirement,
    ) -> Result<(), ZecPayoutError> {
        let signing_hints = inspected
            .signing_hints
            .as_ref()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        if !inspected.wallet_created
            || signing_hints.seed_fingerprint.is_empty()
            || signing_hints.seed_fingerprint.len() > 128
            || !signing_hints
                .seed_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || signing_hints.account_index >= (1 << 31)
            || inspected.privacy_policy.as_deref() != Some(privacy_policy)
            || inspected.tx_version == 0
            || inspected.expiry_height == 0
            || inspected.consensus_branch_id.len() != 8
            || !inspected
                .consensus_branch_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || inspected.fee_zat < 0
            || inspected.fee_zat > i128::from(self.config.max_fee_zat())
            || !inspected.transparent.inputs.is_empty()
            || inspected.sapling.spends != 0
            || !inspected.sapling.outputs.is_empty()
            || inspected.sapling.value_balance_zat != 0
            || inspected
                .orchard
                .outputs
                .iter()
                .any(|output| output.user_address.is_some())
            || !orchard_bundle_is_structural(&inspected.orchard)
            || !orchard_bundle_is_structural(&inspected.ironwood)
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        if proof_requirement == ProofRequirement::Complete
            && (!inspected.sapling.proofs_complete
                || !inspected.orchard.proof_complete
                || !inspected.ironwood.proof_complete)
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        let expected_transparent: Vec<(&str, u64)> = request
            .batch
            .outputs
            .iter()
            .filter(|output| output.receiver_kind == ReceiverKind::Transparent)
            .map(|output| (output.canonical_address.as_str(), output.amount_zat))
            .collect();
        let actual_transparent: Option<Vec<(&str, u64)>> = inspected
            .transparent
            .outputs
            .iter()
            .map(|output| {
                let user_address = output.user_address.as_deref()?;
                if output.address.as_deref() != Some(user_address) {
                    return None;
                }
                Some((user_address, output.value_zat))
            })
            .collect();
        if actual_transparent.as_deref() != Some(expected_transparent.as_slice()) {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        let expected_ironwood: Vec<(&str, u64)> = request
            .batch
            .outputs
            .iter()
            .filter(|output| output.receiver_kind == ReceiverKind::Ironwood)
            .map(|output| (output.canonical_address.as_str(), output.amount_zat))
            .collect();
        let actual_ironwood: Option<Vec<(&str, u64)>> = inspected
            .ironwood
            .outputs
            .iter()
            .filter(|output| output.user_address.is_some())
            .map(|output| Some((output.user_address.as_deref()?, output.value_zat?)))
            .collect();
        if actual_ironwood.as_deref() != Some(expected_ironwood.as_slice()) {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        let transparent_out: i128 = inspected
            .transparent
            .outputs
            .iter()
            .map(|output| i128::from(output.value_zat))
            .sum();
        let recomputed_fee = -transparent_out
            + inspected.sapling.value_balance_zat
            + inspected.orchard.value_balance_zat
            + inspected.ironwood.value_balance_zat;
        if recomputed_fee != inspected.fee_zat {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        Ok(())
    }

    fn broadcast(&self, raw_transaction: &str, transaction_id: &str) -> BroadcastOutcome {
        let limit = self.config.rpc_limits().max_response_bytes();
        match self.zebra.call(RpcCall::new(
            SEND_RAW_TRANSACTION,
            json!([raw_transaction]),
            self.config.rpc_limits().broadcast_timeout(),
            limit,
        )) {
            Ok(value) => {
                if ensure_response_bound(&value, limit).is_ok()
                    && value.as_str() == Some(transaction_id)
                {
                    BroadcastOutcome::Accepted
                } else {
                    BroadcastOutcome::Ambiguous
                }
            }
            Err(error) if error.is_already_known() => BroadcastOutcome::AlreadyKnown,
            Err(error) if error.is_explicit_validation_rejection() => BroadcastOutcome::Rejected,
            Err(_) => BroadcastOutcome::Ambiguous,
        }
    }

    fn persist(&self, record: &JournalRecord) -> Result<(), ZecPayoutError> {
        self.journal.store(record)?;
        if self
            .checkpoint_hook
            .should_interrupt(Checkpoint::StagePersisted(record.stage.public_stage()))
        {
            return Err(ZecPayoutError::Interrupted);
        }
        Ok(())
    }

    fn rpc_checkpoint(&self, stage: PipelineStage) -> Result<(), ZecPayoutError> {
        if self
            .checkpoint_hook
            .should_interrupt(Checkpoint::RpcReturned(stage))
        {
            return Err(ZecPayoutError::Interrupted);
        }
        Ok(())
    }
}

impl fmt::Debug for ZecPcztSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZecPcztSigner")
            .field("config", &self.config)
            .field("zallet", &"[ISOLATED RPC]")
            .field("zebra", &"[PARENT RPC]")
            .finish_non_exhaustive()
    }
}

impl IsolatedPayoutSigner for ZecPcztSigner {
    fn readiness(&self) -> Result<(), SignerError> {
        ZecPcztSigner::readiness(self).map_err(map_portal_error)
    }

    fn sign_and_broadcast(
        &self,
        request: &PayoutBatchRequest,
    ) -> Result<BroadcastReceipt, SignerError> {
        self.execute(&ZecPayoutRequest {
            batch: request.clone(),
            source_account: self.config.account_id(),
            fund_source: ZecFundSource::Orchard,
        })
        .map_err(map_portal_error)
    }
}

fn lock_without_poison(lock: &Mutex<()>) -> MutexGuard<'_, ()> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn map_portal_error(error: ZecPayoutError) -> SignerError {
    match error {
        ZecPayoutError::WrongNetwork => SignerError::WrongNetwork,
        ZecPayoutError::InvalidRequest
        | ZecPayoutError::WrongAsset
        | ZecPayoutError::WrongAccount
        | ZecPayoutError::WrongFundSource => SignerError::InvalidRequest,
        ZecPayoutError::IdempotencyConflict => SignerError::IdempotencyConflict,
        ZecPayoutError::UnsafeWalletConfiguration => SignerError::NotConfigured,
        ZecPayoutError::BroadcastAmbiguous
        | ZecPayoutError::JournalUnavailable
        | ZecPayoutError::JournalCorrupt
        | ZecPayoutError::WalletRpcUnavailable
        | ZecPayoutError::Interrupted => SignerError::AmbiguousBroadcast,
        ZecPayoutError::WalletRejected
        | ZecPayoutError::WalletProtocolViolation
        | ZecPayoutError::BroadcastRejected => SignerError::Rejected,
    }
}

fn receipt(record: &JournalRecord, transaction_id: String) -> BroadcastReceipt {
    BroadcastReceipt {
        batch_id: record.batch_id,
        request_commitment: record.portal_commitment,
        asset: Asset::Zec,
        transaction_id,
        output_total_zat: record.output_total_zat,
    }
}

fn exact_zec_number(amount_zat: u64) -> Result<Number, ZecPayoutError> {
    let whole = amount_zat / 100_000_000;
    let fractional = amount_zat % 100_000_000;
    Number::from_str(&format!("{whole}.{fractional:08}"))
        .map_err(|_| ZecPayoutError::InvalidRequest)
}

fn ensure_response_bound(value: &Value, maximum: usize) -> Result<(), ZecPayoutError> {
    let length = serde_json::to_vec(value)
        .map_err(|_| ZecPayoutError::WalletProtocolViolation)?
        .len();
    if length > maximum {
        return Err(ZecPayoutError::WalletProtocolViolation);
    }
    Ok(())
}

fn validate_pczt(pczt: &str) -> Result<(), ZecPayoutError> {
    if pczt.is_empty()
        || pczt.len() > 8 * 1024 * 1024
        || !pczt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(ZecPayoutError::WalletProtocolViolation);
    }
    Ok(())
}

fn validate_privacy_policy(
    privacy_policy: &str,
    request: &ZecPayoutRequest,
) -> Result<(), ZecPayoutError> {
    let has_transparent = request
        .batch
        .outputs
        .iter()
        .any(|output| output.receiver_kind == ReceiverKind::Transparent);
    let accepted = if has_transparent {
        matches!(privacy_policy, "FullPrivacy" | "AllowRevealedRecipients")
    } else {
        matches!(privacy_policy, "FullPrivacy" | "AllowRevealedAmounts")
    };
    if !accepted {
        return Err(ZecPayoutError::WalletProtocolViolation);
    }
    Ok(())
}

fn orchard_bundle_is_structural(bundle: &OrchardInfo) -> bool {
    bundle.outputs.len() == bundle.actions
        && bundle.signed_actions <= bundle.actions
        && bundle.value_balance_zat.unsigned_abs() <= u128::from(MAX_ZEC_ZAT)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProofRequirement {
    MayBeMissing,
    Complete,
}

enum BroadcastOutcome {
    Accepted,
    AlreadyKnown,
    Rejected,
    Ambiguous,
}

#[derive(Deserialize)]
struct WalletStatus {
    locked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateResult {
    pczt: String,
    privacy_policy: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveResult {
    pczt: String,
    sapling_proven: bool,
    orchard_proven: bool,
    ironwood_proven: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignResult {
    pczt: String,
    transparent_signed: usize,
    sapling_signed: usize,
    orchard_signed: usize,
    ironwood_signed: usize,
    unsigned_transparent: Vec<usize>,
    unsigned_sapling: Vec<usize>,
    unsigned_orchard: Vec<usize>,
    unsigned_ironwood: Vec<usize>,
}

impl SignResult {
    fn validate(&self) -> Result<(), ZecPayoutError> {
        let _signed_counts = (
            self.transparent_signed,
            self.sapling_signed,
            self.orchard_signed,
            self.ironwood_signed,
        );
        if !self.unsigned_transparent.is_empty()
            || !self.unsigned_sapling.is_empty()
            || !self.unsigned_orchard.is_empty()
            || !self.unsigned_ironwood.is_empty()
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractResult {
    hex: String,
    txid: String,
    stored: bool,
}

impl ExtractResult {
    fn validate(&self) -> Result<(), ZecPayoutError> {
        if !self.stored
            || self.hex.is_empty()
            || self.hex.len() > 4 * 1024 * 1024
            || !self.hex.len().is_multiple_of(2)
            || !self
                .hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.txid.len() != 64
            || !self
                .txid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectResult {
    tx_version: u32,
    consensus_branch_id: String,
    expiry_height: u32,
    privacy_policy: Option<String>,
    signing_hints: Option<SigningHints>,
    wallet_created: bool,
    fee_zat: i128,
    transparent: TransparentInfo,
    sapling: SaplingInfo,
    orchard: OrchardInfo,
    ironwood: OrchardInfo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningHints {
    seed_fingerprint: String,
    account_index: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparentInfo {
    inputs: Vec<Value>,
    outputs: Vec<TransparentOutput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparentOutput {
    value_zat: u64,
    address: Option<String>,
    user_address: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShieldedOutput {
    value_zat: Option<u64>,
    user_address: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaplingInfo {
    spends: usize,
    outputs: Vec<ShieldedOutput>,
    value_balance_zat: i128,
    proofs_complete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardInfo {
    actions: usize,
    signed_actions: usize,
    outputs: Vec<ShieldedOutput>,
    value_balance_zat: i128,
    proof_complete: bool,
}

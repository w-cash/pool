//! Exact, resumable Zallet PCZT orchestration.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    io::Cursor,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use orchard::{
    circuit::{OrchardCircuitVersion, VerifyingKey},
    keys::FullViewingKey,
    note::{NoteVersion, Rho},
    Note,
};
use pczt::{
    roles::{
        signer::Signer as PcztSigner, tx_extractor::TransactionExtractor,
        verifier::Verifier as PcztVerifier,
    },
    Pczt,
};
use serde::{de::IgnoredAny, Deserialize, Deserializer};
use serde_json::{json, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wcash_pool_portal::{
    Asset, BroadcastReceipt, ChainNetwork, IsolatedPayoutSigner, PayoutBatchRequest, ReceiverKind,
    SignerError,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{try_output_recovery_with_pkd_esk, Domain};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::{
    consensus::{BranchId, TEST_NETWORK},
    constants::{
        testnet::COIN_TYPE as ZCASH_TESTNET_COIN_TYPE, V6_TX_VERSION, V6_VERSION_GROUP_ID,
    },
    memo::MemoBytes,
};
use zip32::{fingerprint::SeedFingerprint, AccountId, ChildIndex};

use crate::{
    address::{decode_destination, validate_destination, Destination},
    journal::{Journal, JournalRecord, StoredStage},
    JsonRpcTransport, PipelineStage, RpcCall, ZecPayoutError, ZecSignerConfig, ZALLET_API_VERSION,
};

const PIPELINE_COMMITMENT_DOMAIN: &[u8] = b"zecwec/zec-pczt-pipeline/v2";
/// Must remain byte-for-byte identical to
/// `wcash_zcash_aux::PARENT_PAYOUT_COMMITMENT_DOMAIN`.
pub const PARENT_PAYOUT_COMMITMENT_DOMAIN: &[u8] = b"Wcash/Zcash parent payout address/v1\0";
const MAX_ZEC_ZAT: u64 = 2_100_000_000_000_000;
const PCZT_CREATE: &str = "pczt_create";
const PCZT_INSPECT: &str = "pczt_inspect";
const PCZT_PROVE: &str = "pczt_prove";
const PCZT_SIGN: &str = "pczt_sign";
const PCZT_EXTRACT: &str = "pczt_extract";
const GET_WALLET_STATUS: &str = "getwalletstatus";
const GET_ACCOUNT: &str = "z_getaccount";
const GET_BALANCES: &str = "z_getbalances";
const EXPORT_VIEWING_KEY: &str = "z_exportviewingkey";
const SEND_RAW_TRANSACTION: &str = "sendrawtransaction";
const ZCASH_NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
const PCZT_V2_HEADER: &[u8; 8] = b"PCZT\x02\0\0\0";
const MAX_EXPIRY_DELTA: u32 = 100;
const PROP_SEED_FINGERPRINT: &str = "zallet.v1.seed_fingerprint";
const PROP_ACCOUNT_INDEX: &str = "zallet.v1.account_index";
const PROP_PRIVACY_POLICY: &str = "zallet.v1.privacy_policy";
const PROP_BACKEND_PROPOSAL_INFO: &str = "zcash_client_backend:proposal_info";

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

/// Exact signed ZEC payout artifact required by the PostgreSQL settlement
/// boundary after any crash or exact retry. [`ZecPcztSigner::prepare`] returns
/// it before broadcast; [`ZecPcztSigner::execute`] returns it only after a
/// resolved broadcast.
#[derive(Clone, Eq, PartialEq)]
pub struct ZecPayoutExecution {
    /// Portal-compatible public receipt.
    pub receipt: BroadcastReceipt,
    /// Zcash consensus shielded-signature hash of the exact transaction effects
    /// approved before signing.
    pub unsigned_digest: [u8; 32],
    /// Display-order transaction identifier bytes.
    pub transaction_id_bytes: [u8; 32],
    /// Exact signed transaction bytes that were submitted.
    pub signed_transaction: Vec<u8>,
    /// Exact fee verified from the signed PCZT.
    pub network_fee_zat: u64,
}

/// Prepare-only journal recovery result used to order startup reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZecPreparedRecovery {
    /// Exact durable payout bytes.
    pub payout: ZecPayoutExecution,
}

impl ZecPayoutExecution {
    /// Returns the Zcash consensus shielded-signature/effects digest.
    ///
    /// The `unsigned_digest` field name is retained for the settlement-store
    /// interface; it is not the portal request commitment or a hash of mutable
    /// PCZT role metadata.
    pub const fn consensus_effects_digest(&self) -> [u8; 32] {
        self.unsigned_digest
    }
}

impl fmt::Debug for ZecPayoutExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZecPayoutExecution")
            .field("receipt", &self.receipt)
            .field("consensus_effects_digest", &self.unsigned_digest)
            .field("transaction_id_bytes", &self.transaction_id_bytes)
            .field("signed_transaction", &"[REDACTED]")
            .field("network_fee_zat", &self.network_fee_zat)
            .finish()
    }
}

impl std::ops::Deref for ZecPayoutExecution {
    type Target = BroadcastReceipt;

    fn deref(&self) -> &Self::Target {
        &self.receipt
    }
}

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

    /// Verifies the static Testnet fence, exact configured account, sync-engine
    /// state, and availability of the account's exported viewing key.
    pub fn readiness(&self) -> Result<(), ZecPayoutError> {
        crate::validate_zallet_configuration(self.config.zallet_configuration())?;
        self.wallet_context()?;
        Ok(())
    }

    fn wallet_context(&self) -> Result<WalletContext, ZecPayoutError> {
        let value = self.wallet_call(
            GET_WALLET_STATUS,
            json!([]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        let status: WalletStatus =
            serde_json::from_value(value).map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        if !status.is_fully_synchronized() {
            return Err(ZecPayoutError::WalletRpcUnavailable);
        }

        let value = self.wallet_call(
            GET_ACCOUNT,
            json!([self.config.account_id().to_string()]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        let account: WalletAccount =
            serde_json::from_value(value).map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        let identity = account.signing_identity(
            self.config.account_id(),
            self.config.expected_parent_payout_commitment(),
        )?;

        let value = self.wallet_call(
            GET_BALANCES,
            json!([self.config.min_confirmations()]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        let balances: WalletBalances =
            serde_json::from_value(value).map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        balances.require_no_legacy_orchard(self.config.account_id())?;

        let value = self.wallet_call(
            EXPORT_VIEWING_KEY,
            json!([identity.unified_address, false]),
            self.config.rpc_limits().ordinary_timeout(),
        )?;
        let encoded_ufvk = value
            .as_str()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        let ufvk = UnifiedFullViewingKey::decode(&TEST_NETWORK, encoded_ufvk)
            .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        let orchard_fvk = ufvk
            .orchard()
            .cloned()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        if orchard_fvk
            .scope_for_address(&identity.unified_receiver)
            .is_none()
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        Ok(WalletContext {
            node_height: status.node_tip.height,
            seed_fingerprint: identity.seed_fingerprint,
            account_index: identity.account_index,
            orchard_fvk,
        })
    }

    /// Executes or resumes one exact batch.
    ///
    /// Every exact retry resumes from durable bytes. A retry after an ambiguous
    /// parent-node result re-broadcasts the same raw transaction; it never
    /// creates or signs a replacement.
    pub fn execute(
        &self,
        request: &ZecPayoutRequest,
    ) -> Result<ZecPayoutExecution, ZecPayoutError> {
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
                true,
            )
        })
    }

    /// Creates or recovers the exact signed transaction and durably journals
    /// its consensus bytes without broadcasting them.
    ///
    /// Existing unresolved/completed journal entries return their original
    /// bytes, allowing a database that crashed before `mark_signed` to recover
    /// without creating a replacement transaction.
    pub fn prepare(
        &self,
        request: &ZecPayoutRequest,
    ) -> Result<ZecPayoutExecution, ZecPayoutError> {
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
                false,
            )
        })
    }

    /// Inspects the signer journal without creating, proving, signing,
    /// extracting, or broadcasting anything.
    ///
    /// Only a complete raw transaction can be recovered. Legacy `extracted`
    /// state is conservatively ambiguous because the old executor could crash
    /// after node submission before advancing its journal.
    pub fn recover_prepared(
        &self,
        request: &ZecPayoutRequest,
    ) -> Result<Option<ZecPreparedRecovery>, ZecPayoutError> {
        crate::validate_zallet_configuration(self.config.zallet_configuration())?;
        let (portal_commitment, pipeline_commitment, output_total_zat) =
            self.validate_request(request)?;
        let _process_guard = lock_without_poison(&self.process_lock);
        self.journal.with_exclusive_lock(|| {
            let Some(record) = self.journal.load(request.batch.batch_id)? else {
                return Ok(None);
            };
            if record.pipeline_commitment != pipeline_commitment
                || record.portal_commitment != portal_commitment
                || record.output_total_zat != output_total_zat
            {
                return Err(ZecPayoutError::IdempotencyConflict);
            }
            let (raw_transaction, transaction_id, network_fee_zat) = match &record.stage {
                StoredStage::Prepared {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                } => (raw_transaction, transaction_id, *network_fee_zat),
                StoredStage::Extracted {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                }
                | StoredStage::BroadcastUnresolved {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                }
                | StoredStage::Completed {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                } => (raw_transaction, transaction_id, *network_fee_zat),
                StoredStage::Rejected { .. } => {
                    return Err(ZecPayoutError::BroadcastRejected);
                }
                StoredStage::Reserved
                | StoredStage::Created { .. }
                | StoredStage::CreatedVerified { .. }
                | StoredStage::Proved { .. }
                | StoredStage::ProvedVerified { .. }
                | StoredStage::Signed { .. }
                | StoredStage::SignedVerified { .. } => return Ok(None),
            };
            Ok(Some(ZecPreparedRecovery {
                payout: execution(
                    &record,
                    transaction_id.clone(),
                    raw_transaction.clone(),
                    network_fee_zat,
                )?,
            }))
        })
    }

    fn execute_locked(
        &self,
        request: &ZecPayoutRequest,
        portal_commitment: [u8; 32],
        pipeline_commitment: [u8; 32],
        output_total_zat: u64,
        broadcast: bool,
    ) -> Result<ZecPayoutExecution, ZecPayoutError> {
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
                    consensus_effects_digest: None,
                    consensus_network_fee_zat: None,
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
                    let wallet = self.wallet_context()?;
                    let effects =
                        self.verify_created_pczt(request, &privacy_policy, &pczt, &wallet)?;
                    let inspected = self.inspect_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::CreatedVerified)?;
                    let claimed_fee_zat = self.verify_inspection(
                        request,
                        &privacy_policy,
                        &inspected,
                        ProofRequirement::MayBeMissing,
                    )?;
                    if claimed_fee_zat != effects.network_fee_zat {
                        return Err(ZecPayoutError::WalletProtocolViolation);
                    }
                    record.consensus_effects_digest = Some(effects.digest);
                    record.consensus_network_fee_zat = Some(effects.network_fee_zat);
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
                    self.verify_consensus_effects(&record, &pczt)?;
                    let proved = self.prove_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::Proved)?;
                    validate_pczt(&proved.pczt)?;
                    self.verify_consensus_effects(&record, &proved.pczt)?;
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
                    self.verify_consensus_effects(&record, &pczt)?;
                    let inspected = self.inspect_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::ProvedVerified)?;
                    let network_fee_zat = self.verify_inspection(
                        request,
                        &privacy_policy,
                        &inspected,
                        ProofRequirement::Complete,
                    )?;
                    if Some(network_fee_zat) != record.consensus_network_fee_zat {
                        return Err(ZecPayoutError::WalletProtocolViolation);
                    }
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
                    self.verify_consensus_effects(&record, &pczt)?;
                    let signed = self.sign_pczt(&pczt, &privacy_policy)?;
                    self.rpc_checkpoint(PipelineStage::Signed)?;
                    signed.validate()?;
                    validate_pczt(&signed.pczt)?;
                    self.verify_consensus_effects(&record, &signed.pczt)?;
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
                    self.verify_consensus_effects(&record, &pczt)?;
                    let inspected = self.inspect_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::SignedVerified)?;
                    let network_fee_zat = self.verify_inspection(
                        request,
                        &privacy_policy,
                        &inspected,
                        ProofRequirement::Complete,
                    )?;
                    if Some(network_fee_zat) != record.consensus_network_fee_zat {
                        return Err(ZecPayoutError::WalletProtocolViolation);
                    }
                    record.stage = StoredStage::SignedVerified {
                        pczt,
                        privacy_policy,
                        network_fee_zat,
                    };
                    self.persist(&record)?;
                }
                StoredStage::SignedVerified {
                    pczt,
                    privacy_policy: _,
                    network_fee_zat,
                } => {
                    self.verify_consensus_effects(&record, &pczt)?;
                    let approved_transaction_id = extractable_consensus_txid(&pczt)?;
                    let extracted = self.extract_pczt(&pczt)?;
                    self.rpc_checkpoint(PipelineStage::Extracted)?;
                    extracted.validate_against(&approved_transaction_id)?;
                    record.stage = StoredStage::Prepared {
                        raw_transaction: extracted.hex,
                        transaction_id: extracted.txid,
                        network_fee_zat,
                    };
                    self.persist(&record)?;
                }
                StoredStage::Prepared {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                } => {
                    if !broadcast {
                        return execution(
                            &record,
                            transaction_id,
                            raw_transaction,
                            network_fee_zat,
                        );
                    }
                    // Cross an explicit durable ambiguity boundary before the
                    // first node RPC. A crash can only retry these exact bytes.
                    record.stage = StoredStage::BroadcastUnresolved {
                        raw_transaction,
                        transaction_id,
                        network_fee_zat,
                    };
                    self.persist(&record)?;
                }
                StoredStage::Extracted {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                }
                | StoredStage::BroadcastUnresolved {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                } => {
                    if !broadcast {
                        return execution(
                            &record,
                            transaction_id,
                            raw_transaction,
                            network_fee_zat,
                        );
                    }
                    match self.broadcast(&raw_transaction, &transaction_id) {
                        BroadcastOutcome::Accepted | BroadcastOutcome::AlreadyKnown => {
                            self.rpc_checkpoint(PipelineStage::Completed)?;
                            record.stage = StoredStage::Completed {
                                raw_transaction: raw_transaction.clone(),
                                transaction_id: transaction_id.clone(),
                                network_fee_zat,
                            };
                            self.persist(&record)?;
                            return execution(
                                &record,
                                transaction_id,
                                raw_transaction,
                                network_fee_zat,
                            );
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
                                network_fee_zat,
                            };
                            self.persist(&record)?;
                            return Err(ZecPayoutError::BroadcastAmbiguous);
                        }
                    }
                }
                StoredStage::Rejected { .. } => {
                    return Err(ZecPayoutError::BroadcastRejected);
                }
                StoredStage::Completed {
                    raw_transaction,
                    transaction_id,
                    network_fee_zat,
                } => {
                    return execution(&record, transaction_id, raw_transaction, network_fee_zat);
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
        if request.batch.outputs.len() > self.config.max_outputs()
            || request.batch.maximum_network_fee_zat > self.config.max_fee_zat()
        {
            return Err(ZecPayoutError::InvalidRequest);
        }
        let output_total_zat = request
            .batch
            .validate()
            .map_err(|_| ZecPayoutError::InvalidRequest)?;
        if output_total_zat > MAX_ZEC_ZAT
            || output_total_zat
                .checked_add(request.batch.maximum_network_fee_zat)
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
        hasher.update(self.config.expected_parent_payout_commitment());
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

    fn verify_created_pczt(
        &self,
        request: &ZecPayoutRequest,
        privacy_policy: &str,
        pczt_base64: &str,
        wallet: &WalletContext,
    ) -> Result<VerifiedEffects, ZecPayoutError> {
        let pczt = parse_pczt(pczt_base64)?;
        let global = pczt.global();
        let expiry_height = *global.expiry_height();
        if *global.tx_version() != V6_TX_VERSION
            || *global.version_group_id() != V6_VERSION_GROUP_ID
            || *global.consensus_branch_id() != ZCASH_NU6_3_BRANCH_ID
            || pczt_v2_coin_type(pczt_base64)? != ZCASH_TESTNET_COIN_TYPE
            || expiry_height <= wallet.node_height
            || expiry_height
                > wallet
                    .node_height
                    .checked_add(MAX_EXPIRY_DELTA)
                    .ok_or(ZecPayoutError::WalletProtocolViolation)?
            || global.inputs_modifiable()
            || global.outputs_modifiable()
            || global.shielded_modifiable()
            || global.has_sighash_single()
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        let proprietary = global.proprietary();
        let expected_account = wallet.account_index.to_le_bytes();
        if proprietary.get(PROP_SEED_FINGERPRINT).map(Vec::as_slice)
            != Some(wallet.seed_fingerprint.to_bytes().as_slice())
            || proprietary.get(PROP_ACCOUNT_INDEX).map(Vec::as_slice)
                != Some(expected_account.as_slice())
            || proprietary.get(PROP_PRIVACY_POLICY).map(Vec::as_slice)
                != Some(privacy_policy.as_bytes())
            || proprietary
                .get(PROP_BACKEND_PROPOSAL_INFO)
                .is_none_or(Vec::is_empty)
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        // `fund_source = orchard` in beta.3 includes both Orchard-family pools.
        // The pool policy is stricter: all value-bearing source effects must be
        // Ironwood, with no transparent inputs and no legacy Sapling/Orchard data.
        if !pczt.transparent().inputs().is_empty()
            || !pczt.sapling().spends().is_empty()
            || !pczt.sapling().outputs().is_empty()
            || *pczt.sapling().value_sum() != 0
            || !pczt.orchard().actions().is_empty()
            || signed_value_sum(pczt.orchard().value_sum()) != 0
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        let mut matched = vec![false; request.batch.outputs.len()];
        let mut transparent_total = 0u64;
        for output in pczt.transparent().outputs() {
            let address = output
                .user_address()
                .as_deref()
                .ok_or(ZecPayoutError::WalletProtocolViolation)?;
            let index = request
                .batch
                .outputs
                .iter()
                .enumerate()
                .find_map(|(index, expected)| {
                    (!matched[index]
                        && expected.receiver_kind == ReceiverKind::Transparent
                        && expected.canonical_address == address
                        && expected.amount_zat == *output.value())
                    .then_some(index)
                })
                .ok_or(ZecPayoutError::WalletProtocolViolation)?;
            let Destination::Transparent { script_pubkey } = decode_destination(address)? else {
                return Err(ZecPayoutError::WalletProtocolViolation);
            };
            if output.script_pubkey() != &script_pubkey {
                return Err(ZecPayoutError::WalletProtocolViolation);
            }
            transparent_total = transparent_total
                .checked_add(*output.value())
                .ok_or(ZecPayoutError::WalletProtocolViolation)?;
            matched[index] = true;
        }

        let expected_account_id = AccountId::try_from(wallet.account_index)
            .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        let expected_coin_type = ChildIndex::hardened(ZCASH_TESTNET_COIN_TYPE);
        let mut positive_change_outputs = 0usize;
        let mut spend_total = 0u64;
        let mut shielded_output_total = 0u64;
        PcztVerifier::new(pczt.clone())
            .with_ironwood::<(), _>(|bundle| {
                bundle.verify_cross_address_restriction()?;
                for action in bundle.actions() {
                    if action.spend().dummy_sk().is_some() {
                        return Err(pczt::roles::verifier::OrchardError::Custom(()));
                    }
                    action.verify_cv_net()?;
                    action.output().verify_note_commitment(action.spend())?;

                    let spend_value = action
                        .spend()
                        .value()
                        .as_ref()
                        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?
                        .inner();
                    let output_value = action
                        .output()
                        .value()
                        .as_ref()
                        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?
                        .inner();
                    spend_total = spend_total
                        .checked_add(spend_value)
                        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
                    shielded_output_total = shielded_output_total
                        .checked_add(output_value)
                        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;

                    if spend_value > 0 {
                        action.spend().verify_nullifier(Some(&wallet.orchard_fvk))?;
                        action.spend().verify_rk(Some(&wallet.orchard_fvk))?;
                        let derived_account =
                            action
                                .spend()
                                .zip32_derivation()
                                .as_ref()
                                .and_then(|derivation| {
                                    derivation.extract_account_index(
                                        &wallet.seed_fingerprint,
                                        expected_coin_type,
                                    )
                                });
                        if derived_account != Some(expected_account_id) {
                            return Err(pczt::roles::verifier::OrchardError::Custom(()));
                        }
                    }

                    if output_value > 0 {
                        verify_ironwood_ciphertext(action)?;
                        let recipient = action
                            .output()
                            .recipient()
                            .as_ref()
                            .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
                        if let Some(address) = action.output().user_address().as_deref() {
                            let index = request
                                .batch
                                .outputs
                                .iter()
                                .enumerate()
                                .find_map(|(index, expected)| {
                                    (!matched[index]
                                        && expected.receiver_kind == ReceiverKind::Ironwood
                                        && expected.canonical_address == address
                                        && expected.amount_zat == output_value)
                                        .then_some(index)
                                })
                                .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
                            let Destination::Ironwood {
                                receiver: expected_receiver,
                            } = decode_destination(address)
                                .map_err(|_| pczt::roles::verifier::OrchardError::Custom(()))?
                            else {
                                return Err(pczt::roles::verifier::OrchardError::Custom(()));
                            };
                            if recipient.to_raw_address_bytes() != expected_receiver {
                                return Err(pczt::roles::verifier::OrchardError::Custom(()));
                            }
                            matched[index] = true;
                        } else {
                            positive_change_outputs += 1;
                            if positive_change_outputs > 1
                                || wallet.orchard_fvk.scope_for_address(recipient).is_none()
                            {
                                return Err(pczt::roles::verifier::OrchardError::Custom(()));
                            }
                        }
                    } else if action.output().user_address().is_some() {
                        return Err(pczt::roles::verifier::OrchardError::Custom(()));
                    }
                }
                Ok(())
            })
            .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;

        if matched.iter().any(|is_matched| !is_matched) {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        let computed_value_sum = i128::from(spend_total) - i128::from(shielded_output_total);
        let declared_value_sum = signed_value_sum(pczt.ironwood().value_sum());
        if computed_value_sum != declared_value_sum {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        let fee = declared_value_sum - i128::from(transparent_total);
        let network_fee_zat = u64::try_from(fee)
            .ok()
            .filter(|fee| *fee > 0 && *fee <= request.batch.maximum_network_fee_zat)
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;

        Ok(VerifiedEffects {
            digest: consensus_effects_digest_from_pczt(pczt)?,
            network_fee_zat,
        })
    }

    fn verify_inspection(
        &self,
        request: &ZecPayoutRequest,
        privacy_policy: &str,
        inspected: &InspectResult,
        proof_requirement: ProofRequirement,
    ) -> Result<u64, ZecPayoutError> {
        let signing_hints = inspected
            .signing_hints
            .as_ref()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        if !inspected.wallet_created
            || signing_hints
                .seed_fingerprint
                .parse::<SeedFingerprint>()
                .is_err()
            || signing_hints.account_index >= (1 << 31)
            || inspected.privacy_policy.as_deref() != Some(privacy_policy)
            || inspected.tx_version == 0
            || inspected.expiry_height == 0
            || u32::from_str_radix(&inspected.consensus_branch_id, 16).ok()
                != Some(ZCASH_NU6_3_BRANCH_ID)
            || inspected.fee_zat < 0
            || inspected.fee_zat > i128::from(request.batch.maximum_network_fee_zat)
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
        u64::try_from(inspected.fee_zat).map_err(|_| ZecPayoutError::WalletProtocolViolation)
    }

    fn verify_consensus_effects(
        &self,
        record: &JournalRecord,
        pczt: &str,
    ) -> Result<(), ZecPayoutError> {
        let expected = record
            .consensus_effects_digest
            .ok_or(ZecPayoutError::JournalCorrupt)?;
        if pczt_v2_coin_type(pczt)? != ZCASH_TESTNET_COIN_TYPE
            || consensus_effects_digest(pczt)? != expected
        {
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
        .map(|execution| execution.receipt)
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

fn execution(
    record: &JournalRecord,
    transaction_id: String,
    raw_transaction: String,
    network_fee_zat: u64,
) -> Result<ZecPayoutExecution, ZecPayoutError> {
    let transaction_id_bytes = hex::decode(&transaction_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ZecPayoutError::JournalCorrupt)?;
    let signed_transaction =
        hex::decode(raw_transaction).map_err(|_| ZecPayoutError::JournalCorrupt)?;
    let unsigned_digest = record
        .consensus_effects_digest
        .filter(|digest| *digest != [0; 32])
        .ok_or(ZecPayoutError::JournalCorrupt)?;
    Ok(ZecPayoutExecution {
        receipt: BroadcastReceipt {
            batch_id: record.batch_id,
            request_commitment: record.portal_commitment,
            asset: Asset::Zec,
            transaction_id,
            output_total_zat: record.output_total_zat,
        },
        unsigned_digest,
        transaction_id_bytes,
        signed_transaction,
        network_fee_zat,
    })
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

fn parse_pczt(pczt_base64: &str) -> Result<Pczt, ZecPayoutError> {
    validate_pczt(pczt_base64)?;
    let encoded = BASE64_STANDARD
        .decode(pczt_base64)
        .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
    if encoded.is_empty() || BASE64_STANDARD.encode(&encoded) != pczt_base64 {
        return Err(ZecPayoutError::WalletProtocolViolation);
    }
    Pczt::parse(&encoded).map_err(|_| ZecPayoutError::WalletProtocolViolation)
}

/// Reads the non-consensus SLIP-44 marker from the exact pinned PCZT v2 wire
/// schema.
///
/// PCZT 0.9.3 does not expose `Global::coin_type()` in its logical public API,
/// but serializes the marker in the leading global record. Ironwood is v2-only,
/// so any other encoding fails closed. This compatibility decoder can be
/// removed once the pinned PCZT API exposes the field directly.
fn pczt_v2_coin_type(pczt_base64: &str) -> Result<u32, ZecPayoutError> {
    let encoded = BASE64_STANDARD
        .decode(pczt_base64)
        .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
    let body = encoded
        .strip_prefix(PCZT_V2_HEADER)
        .ok_or(ZecPayoutError::WalletProtocolViolation)?;
    let (global, _remaining) = postcard::take_from_bytes::<PcztV2Global>(body)
        .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
    Ok(global.coin_type)
}

fn signed_value_sum(&(magnitude, is_negative): &(u64, bool)) -> i128 {
    if is_negative {
        -i128::from(magnitude)
    } else {
        i128::from(magnitude)
    }
}

fn verify_ironwood_ciphertext(
    action: &orchard::pczt::Action,
) -> Result<(), pczt::roles::verifier::OrchardError<()>> {
    let spend = action.spend();
    let output = action.output();
    if *output.note_version() != NoteVersion::V3 {
        return Err(pczt::roles::verifier::OrchardError::Custom(()));
    }
    let recipient = *output
        .recipient()
        .as_ref()
        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
    let value = *output
        .value()
        .as_ref()
        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&spend.nullifier().to_bytes()))
        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
    let rseed = *output
        .rseed()
        .as_ref()
        .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        value,
        rho,
        rseed,
        NoteVersion::V3,
    ))
    .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
    let domain = orchard::note_encryption::IronwoodDomain::for_pczt_action(action);
    let recovered = try_output_recovery_with_pkd_esk(
        &domain,
        orchard::note_encryption::IronwoodDomain::get_pk_d(&note),
        orchard::note_encryption::IronwoodDomain::derive_esk(&note)
            .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?,
        action,
    )
    .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
    if recovered.0 != note
        || recovered.1 != recipient
        || recovered.2 != MemoBytes::empty().into_bytes()
    {
        return Err(pczt::roles::verifier::OrchardError::Custom(()));
    }
    Ok(())
}

/// Derives the Zcash consensus shielded-signature hash from a canonical PCZT.
///
/// This is the digest authorized by every shielded spend signature. It commits
/// to transaction effects (including the consensus branch, expiry, inputs,
/// recipients, amounts, and fee) while excluding proof and signature bytes, so
/// it must remain identical through the prove and sign roles. The PCZT parser
/// and signer are the same version used by the pinned Zallet beta.3 protocol.
fn consensus_effects_digest(pczt_base64: &str) -> Result<[u8; 32], ZecPayoutError> {
    consensus_effects_digest_from_pczt(parse_pczt(pczt_base64)?)
}

fn consensus_effects_digest_from_pczt(pczt: Pczt) -> Result<[u8; 32], ZecPayoutError> {
    let digest = PcztSigner::new(pczt)
        .map_err(|_| ZecPayoutError::WalletProtocolViolation)?
        .shielded_sighash();
    if digest == [0; 32] {
        return Err(ZecPayoutError::WalletProtocolViolation);
    }
    Ok(digest)
}

/// Proves that the signed PCZT can produce a valid transaction and returns the
/// nonmalleable identifier of its exact effects.
///
/// The extractor independently requires and verifies all proofs and spend
/// authorizations before it creates a randomized binding signature. V6 excludes
/// authorization material from its ZIP-244 transaction identifier, so the ID
/// remains identical to any separately extracted transaction with these effects.
fn extractable_consensus_txid(pczt_base64: &str) -> Result<String, ZecPayoutError> {
    TransactionExtractor::new(parse_pczt(pczt_base64)?)
        .with_orchard(ironwood_verifying_key())
        .extract()
        .map(|transaction| transaction.txid().to_string())
        .map_err(|_| ZecPayoutError::WalletProtocolViolation)
}

fn ironwood_verifying_key() -> &'static VerifyingKey {
    static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();
    VERIFYING_KEY.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
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

struct VerifiedEffects {
    digest: [u8; 32],
    network_fee_zat: u64,
}

struct WalletContext {
    node_height: u32,
    seed_fingerprint: SeedFingerprint,
    account_index: u32,
    orchard_fvk: FullViewingKey,
}

/// Serialized field order of `pczt::common::Global` in pinned PCZT v2.
#[derive(Deserialize)]
struct PcztV2Global {
    #[serde(rename = "tx_version")]
    _tx_version: u32,
    #[serde(rename = "version_group_id")]
    _version_group_id: u32,
    #[serde(rename = "consensus_branch_id")]
    _consensus_branch_id: u32,
    #[serde(rename = "fallback_lock_time")]
    _fallback_lock_time: Option<u32>,
    #[serde(rename = "expiry_height")]
    _expiry_height: u32,
    coin_type: u32,
    #[serde(rename = "tx_modifiable")]
    _tx_modifiable: u8,
    #[serde(rename = "proprietary")]
    _proprietary: BTreeMap<String, Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletStatus {
    node_tip: ChainTip,
    wallet_tip: Option<ChainTip>,
    fully_synced_height: Option<u32>,
    #[serde(
        default,
        rename = "sync_work_remaining",
        deserialize_with = "field_is_present"
    )]
    sync_work_remaining_present: bool,
    locked: bool,
}

impl WalletStatus {
    fn is_fully_synchronized(&self) -> bool {
        let Some(wallet_tip) = self.wallet_tip.as_ref() else {
            return false;
        };
        !self.locked
            && !self.sync_work_remaining_present
            && valid_block_hash(&self.node_tip.blockhash)
            && valid_block_hash(&wallet_tip.blockhash)
            && self.node_tip == *wallet_tip
            && self.fully_synced_height == Some(wallet_tip.height)
    }
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ChainTip {
    blockhash: String,
    height: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletAccount {
    account_uuid: Uuid,
    #[serde(rename = "name")]
    _name: Option<String>,
    seedfp: Option<String>,
    zip32_account_index: Option<u32>,
    addresses: Vec<WalletAddress>,
}

impl WalletAccount {
    fn signing_identity(
        &self,
        expected_account: Uuid,
        expected_parent_payout_commitment: [u8; 32],
    ) -> Result<WalletSigningIdentity, ZecPayoutError> {
        if self.account_uuid != expected_account {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        let seed_fingerprint = self
            .seedfp
            .as_deref()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?
            .parse::<SeedFingerprint>()
            .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        let account_index = self
            .zip32_account_index
            .filter(|index| *index < (1 << 31))
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        let mut matching_addresses = self.addresses.iter().filter_map(|address| {
            address.ua.as_deref().and_then(|unified_address| {
                (parent_payout_address_commitment(unified_address)
                    == expected_parent_payout_commitment)
                    .then_some(unified_address)
            })
        });
        let unified_address = matching_addresses
            .next()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        if matching_addresses.next().is_some() {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        let Destination::Ironwood {
            receiver: unified_receiver,
        } = decode_destination(unified_address)?
        else {
            return Err(ZecPayoutError::WalletProtocolViolation);
        };
        let unified_receiver = Option::<orchard::Address>::from(
            orchard::Address::from_raw_address_bytes(&unified_receiver),
        )
        .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        Ok(WalletSigningIdentity {
            seed_fingerprint,
            account_index,
            unified_address: unified_address.to_owned(),
            unified_receiver,
        })
    }
}

/// Domain-separated commitment used by Zebra's private parent-template
/// payout-address attestation.
pub fn parent_payout_address_commitment(encoded_address: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PARENT_PAYOUT_COMMITMENT_DOMAIN);
    hasher.update(encoded_address.as_bytes());
    hasher.finalize().into()
}

/// Validates one canonical Zcash Testnet UA with an Ironwood-capable receiver
/// before returning the parent-template commitment.
pub fn validated_parent_payout_address_commitment(
    encoded_address: &str,
) -> Result<[u8; 32], ZecPayoutError> {
    if !matches!(
        decode_destination(encoded_address)?,
        Destination::Ironwood { .. }
    ) {
        return Err(ZecPayoutError::WalletProtocolViolation);
    }
    Ok(parent_payout_address_commitment(encoded_address))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletAddress {
    #[serde(rename = "diversifier_index")]
    _diversifier_index: Option<u128>,
    ua: Option<String>,
    #[serde(rename = "sapling")]
    _sapling: Option<String>,
    #[serde(rename = "transparent")]
    _transparent: Option<String>,
}

struct WalletSigningIdentity {
    seed_fingerprint: SeedFingerprint,
    account_index: u32,
    unified_address: String,
    unified_receiver: orchard::Address,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletBalances {
    accounts: Vec<WalletAccountBalance>,
    #[serde(default, rename = "legacy_transparent")]
    _legacy_transparent: Option<Value>,
    #[serde(default, rename = "legacy_transparent_watchonly")]
    _legacy_transparent_watchonly: Option<Value>,
}

impl WalletBalances {
    fn require_no_legacy_orchard(&self, expected_account: Uuid) -> Result<(), ZecPayoutError> {
        let mut matches = self
            .accounts
            .iter()
            .filter(|account| account.account_uuid == expected_account);
        let account = matches
            .next()
            .ok_or(ZecPayoutError::WalletProtocolViolation)?;
        if matches.next().is_some() || account.legacy_orchard_present {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletAccountBalance {
    account_uuid: Uuid,
    #[serde(default, rename = "transparent")]
    _transparent: Option<Value>,
    #[serde(default, rename = "transparent_watchonly")]
    _transparent_watchonly: Vec<Value>,
    #[serde(default, rename = "sapling")]
    _sapling: Option<Value>,
    #[serde(default, rename = "orchard", deserialize_with = "field_is_present")]
    legacy_orchard_present: bool,
    #[serde(default, rename = "ironwood")]
    _ironwood: Option<Value>,
    #[serde(rename = "total")]
    _total: Value,
}

fn field_is_present<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

fn valid_block_hash(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    fn validate_against(&self, approved_transaction_id: &str) -> Result<(), ZecPayoutError> {
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

        let raw = hex::decode(&self.hex).map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        let mut cursor = Cursor::new(raw.as_slice());
        let transaction = Transaction::read(&mut cursor, BranchId::Nu6_3)
            .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        if usize::try_from(cursor.position()).ok() != Some(raw.len())
            || transaction.txid().to_string() != self.txid
            || self.txid != approved_transaction_id
        {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }
        let mut canonical = Vec::with_capacity(raw.len());
        transaction
            .write(&mut canonical)
            .map_err(|_| ZecPayoutError::WalletProtocolViolation)?;
        if canonical != raw {
            return Err(ZecPayoutError::WalletProtocolViolation);
        }

        let transaction = transaction.into_data();
        if transaction.version() != TxVersion::V6
            || transaction.consensus_branch_id() != BranchId::Nu6_3
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

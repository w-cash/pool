//! Deterministic native-wallet, restart, tamper, and broadcast tests.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;
use wcash_pool_portal::{Asset, ChainNetwork, PayoutBatchRequest, PayoutOutput, ReceiverKind};
use wcash_wec_payout_signer::{
    BroadcastDisposition, BroadcastFailure, BroadcastOutcome, Checkpoint, CheckpointHook,
    NativeCallLimits, NativeWalletError, NativeWalletTransport, PersistedIntent, SecretSeed,
    SeedSource, WalletBroadcastCall, WalletFundSource, WalletIdentity, WalletInspectionCall,
    WalletNetwork, WalletRecoveryCall, WalletSignCall, WalletSignedTransaction, WecPayoutError,
    WecPayoutRequest, WecPayoutSigner, WecPipelineStage, WecSignerConfig, WCASH_TESTNET_BRANCH_ID,
    WCASH_TESTNET_GENESIS_HASH,
};

const TXID: &str = "abababababababababababababababababababababababababababababababab";
const RAW_TRANSACTION: &str = "06000000deadbeef";

struct Fixture {
    _directory: TempDir,
    journal: PathBuf,
    seed: PathBuf,
    account: Uuid,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let canonical = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let seed = canonical.join("wallet.seed");
        fs::write(&seed, format!("{}\n", "42".repeat(32))).expect("seed file");
        #[cfg(unix)]
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).expect("seed mode");
        Self {
            _directory: directory,
            journal: canonical.join("journal"),
            seed,
            account: Uuid::from_u128(0x100),
        }
    }

    fn config(&self) -> WecSignerConfig {
        #[cfg(unix)]
        let uid = fs::metadata(&self.seed).expect("seed metadata").uid();
        #[cfg(not(unix))]
        let uid = 0;
        WecSignerConfig::new(
            &self.journal,
            self.account,
            SeedSource::protected_file(&self.seed, uid),
        )
        .expect("valid test config")
    }
}

#[derive(Clone, Copy)]
enum Tamper {
    None,
    OutputAmount,
    OutputAddress,
    OutputOrder,
    Network,
    Account,
    FundSource,
    RawDigest,
    Fee,
    Stored,
    TransactionId,
}

struct BoundTransaction {
    commitment: [u8; 32],
    signed: WalletSignedTransaction,
    intent: PersistedIntent,
}

struct MockState {
    identity: WalletIdentity,
    bound: Option<BoundTransaction>,
    tamper: Tamper,
    recovery_failures: VecDeque<NativeWalletError>,
    sign_after_store_failure: Option<NativeWalletError>,
    broadcasts: VecDeque<Result<BroadcastOutcome, BroadcastFailure>>,
    recovery_calls: usize,
    sign_calls: usize,
    inspection_calls: usize,
    broadcast_calls: Vec<WalletBroadcastCall>,
    last_sign_call: Option<WalletSignCall>,
}

struct MockWallet {
    state: Mutex<MockState>,
}

impl MockWallet {
    fn new(account: Uuid) -> Self {
        Self {
            state: Mutex::new(MockState {
                identity: identity(account),
                bound: None,
                tamper: Tamper::None,
                recovery_failures: VecDeque::new(),
                sign_after_store_failure: None,
                broadcasts: VecDeque::new(),
                recovery_calls: 0,
                sign_calls: 0,
                inspection_calls: 0,
                broadcast_calls: Vec::new(),
                last_sign_call: None,
            }),
        }
    }

    fn tamper(&self, tamper: Tamper) {
        self.state.lock().expect("mock mutex").tamper = tamper;
    }

    fn mutate_identity(&self, mutate: impl FnOnce(&mut WalletIdentity)) {
        mutate(&mut self.state.lock().expect("mock mutex").identity);
    }

    fn push_broadcast(&self, result: Result<BroadcastOutcome, BroadcastFailure>) {
        self.state
            .lock()
            .expect("mock mutex")
            .broadcasts
            .push_back(result);
    }

    fn push_recovery_failure(&self, error: NativeWalletError) {
        self.state
            .lock()
            .expect("mock mutex")
            .recovery_failures
            .push_back(error);
    }

    fn fail_sign_after_store(&self, error: NativeWalletError) {
        self.state
            .lock()
            .expect("mock mutex")
            .sign_after_store_failure = Some(error);
    }

    fn counts(&self) -> (usize, usize, usize, usize) {
        let state = self.state.lock().expect("mock mutex");
        (
            state.recovery_calls,
            state.sign_calls,
            state.inspection_calls,
            state.broadcast_calls.len(),
        )
    }

    fn broadcasts(&self) -> Vec<WalletBroadcastCall> {
        self.state
            .lock()
            .expect("mock mutex")
            .broadcast_calls
            .clone()
    }

    fn last_outputs(&self) -> Vec<wcash_wec_payout_signer::WalletOutput> {
        self.state
            .lock()
            .expect("mock mutex")
            .last_sign_call
            .as_ref()
            .expect("sign call")
            .outputs
            .clone()
    }
}

impl NativeWalletTransport for MockWallet {
    fn identity(
        &self,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<WalletIdentity, NativeWalletError> {
        assert!(!timeout.is_zero());
        assert!(max_response_bytes >= 1_024);
        Ok(self.state.lock().expect("mock mutex").identity.clone())
    }

    fn recover_exact(
        &self,
        call: &WalletRecoveryCall,
    ) -> Result<Option<WalletSignedTransaction>, NativeWalletError> {
        assert!(!call.timeout.is_zero());
        assert!(call.max_response_bytes >= 1_024);
        let mut state = self.state.lock().expect("mock mutex");
        state.recovery_calls += 1;
        if let Some(error) = state.recovery_failures.pop_front() {
            return Err(error);
        }
        match &state.bound {
            Some(bound) if bound.commitment != call.request_commitment => {
                Err(NativeWalletError::IdempotencyConflict)
            }
            Some(bound) if bound.signed.batch_id == call.batch_id => Ok(Some(bound.signed.clone())),
            Some(_) => Err(NativeWalletError::ProtocolViolation),
            None => Ok(None),
        }
    }

    fn sign_exact(
        &self,
        call: &WalletSignCall,
        seed: &SecretSeed,
    ) -> Result<WalletSignedTransaction, NativeWalletError> {
        assert!(!call.timeout.is_zero());
        assert!(call.max_response_bytes >= 1_024);
        assert_eq!(seed.expose_secret(), &[0x42; 32]);
        let mut state = self.state.lock().expect("mock mutex");
        state.sign_calls += 1;
        state.last_sign_call = Some(call.clone());
        if let Some(bound) = &state.bound {
            if bound.commitment != call.request_commitment {
                return Err(NativeWalletError::IdempotencyConflict);
            }
            return Ok(bound.signed.clone());
        }

        let signed = WalletSignedTransaction {
            batch_id: call.batch_id,
            request_commitment: call.request_commitment,
            transaction_id: TXID.to_owned(),
            raw_transaction_hex: RAW_TRANSACTION.to_owned(),
            unsigned_digest: [0x33; 32],
            fee_zat: 10_000,
            target_height: 1_000,
            expiry_height: 1_040,
            stored: true,
            internal_change_receiver_verified: true,
        };
        let raw = hex::decode(RAW_TRANSACTION).expect("test raw transaction");
        let intent = PersistedIntent {
            identity: call.identity.clone(),
            batch_id: call.batch_id,
            request_commitment: call.request_commitment,
            ordered_outputs: call.outputs.clone(),
            unsigned_digest: signed.unsigned_digest,
            transaction_id: signed.transaction_id.clone(),
            raw_transaction_sha256: Sha256::digest(raw).into(),
            fee_zat: signed.fee_zat,
            target_height: signed.target_height,
            expiry_height: signed.expiry_height,
            stored: true,
            internal_change_receiver_verified: true,
        };
        state.bound = Some(BoundTransaction {
            commitment: call.request_commitment,
            signed: signed.clone(),
            intent,
        });
        if let Some(error) = state.sign_after_store_failure.take() {
            return Err(error);
        }
        Ok(signed)
    }

    fn inspect_persisted(
        &self,
        call: &WalletInspectionCall,
    ) -> Result<PersistedIntent, NativeWalletError> {
        assert!(!call.timeout.is_zero());
        assert!(call.max_response_bytes >= 1_024);
        let mut state = self.state.lock().expect("mock mutex");
        state.inspection_calls += 1;
        let bound = state.bound.as_ref().ok_or(NativeWalletError::Unavailable)?;
        if call.batch_id != bound.signed.batch_id
            || call.request_commitment != bound.commitment
            || call.transaction_id != bound.signed.transaction_id
            || call.raw_transaction_hex != bound.signed.raw_transaction_hex
        {
            return Err(NativeWalletError::ProtocolViolation);
        }
        let mut intent = bound.intent.clone();
        match state.tamper {
            Tamper::None => {}
            Tamper::OutputAmount => intent.ordered_outputs[0].amount_zat += 1,
            Tamper::OutputAddress => intent.ordered_outputs[0].canonical_address.push('x'),
            Tamper::OutputOrder => intent.ordered_outputs.swap(0, 1),
            Tamper::Network => intent.identity.network = WalletNetwork::Regtest,
            Tamper::Account => intent.identity.account_id = Uuid::from_u128(0x999),
            Tamper::FundSource => intent.identity.fund_source = WalletFundSource::Transparent,
            Tamper::RawDigest => intent.raw_transaction_sha256[0] ^= 1,
            Tamper::Fee => intent.fee_zat += 1,
            Tamper::Stored => intent.stored = false,
            Tamper::TransactionId => intent.transaction_id = "cd".repeat(32),
        }
        Ok(intent)
    }

    fn broadcast_exact(
        &self,
        call: &WalletBroadcastCall,
    ) -> Result<BroadcastOutcome, BroadcastFailure> {
        assert!(!call.timeout.is_zero());
        assert!(call.max_response_bytes >= 1_024);
        let mut state = self.state.lock().expect("mock mutex");
        state.broadcast_calls.push(call.clone());
        state.broadcasts.pop_front().unwrap_or_else(|| {
            Ok(BroadcastOutcome {
                transaction_id: call.transaction_id.clone(),
                disposition: BroadcastDisposition::Accepted,
            })
        })
    }
}

#[derive(Debug)]
struct InterruptOnce {
    target: Checkpoint,
    fired: AtomicBool,
}

impl InterruptOnce {
    fn new(target: Checkpoint) -> Self {
        Self {
            target,
            fired: AtomicBool::new(false),
        }
    }
}

impl CheckpointHook for InterruptOnce {
    fn should_interrupt(&self, checkpoint: Checkpoint) -> bool {
        checkpoint == self.target && !self.fired.swap(true, Ordering::SeqCst)
    }
}

fn identity(account: Uuid) -> WalletIdentity {
    WalletIdentity {
        network: WalletNetwork::Testnet,
        genesis_hash: WCASH_TESTNET_GENESIS_HASH.to_owned(),
        branch_id: WCASH_TESTNET_BRANCH_ID.to_owned(),
        account_id: account,
        fund_source: WalletFundSource::Ironwood,
        synchronized: true,
    }
}

fn request(account: Uuid) -> WecPayoutRequest {
    WecPayoutRequest {
        batch: PayoutBatchRequest {
            batch_id: Uuid::from_u128(1),
            asset: Asset::Wec,
            network: ChainNetwork::Testnet,
            ledger_root: [0x11; 32],
            reconciliation_id: Uuid::from_u128(2),
            outputs: vec![
                PayoutOutput {
                    allocation_id: Uuid::from_u128(3),
                    canonical_address: "wctest1ironwood-destination-one".to_owned(),
                    receiver_kind: ReceiverKind::Ironwood,
                    amount_zat: 100_000_000,
                },
                PayoutOutput {
                    allocation_id: Uuid::from_u128(4),
                    canonical_address: "wctest1ironwood-destination-two".to_owned(),
                    receiver_kind: ReceiverKind::Ironwood,
                    amount_zat: 200_000_000,
                },
            ],
        },
        source_account: account,
        fund_source: WalletFundSource::Ironwood,
    }
}

fn make_signer(fixture: &Fixture, wallet: Arc<MockWallet>) -> WecPayoutSigner {
    WecPayoutSigner::new(fixture.config(), wallet).expect("test signer")
}

fn accepted() -> Result<BroadcastOutcome, BroadcastFailure> {
    Ok(BroadcastOutcome {
        transaction_id: TXID.to_owned(),
        disposition: BroadcastDisposition::Accepted,
    })
}

#[test]
fn exact_multi_output_success_is_store_compatible_and_redacted() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    let request = request(fixture.account);
    let signer = make_signer(&fixture, wallet.clone());
    signer.readiness().expect("ready");
    let execution = signer.execute(&request).expect("payout succeeds");

    assert_eq!(execution.receipt.output_total_zat, 300_000_000);
    assert_eq!(
        execution.receipt.request_commitment,
        request.batch.commitment().unwrap()
    );
    assert_eq!(execution.receipt.transaction_id, TXID);
    assert_eq!(
        execution.signed_transaction,
        hex::decode(RAW_TRANSACTION).unwrap()
    );
    assert_eq!(execution.network_fee_zat, 10_000);
    assert_eq!(execution.disposition, BroadcastDisposition::Accepted);
    let outputs = wallet.last_outputs();
    assert_eq!(outputs.len(), 2);
    assert_eq!(
        outputs[0].allocation_id,
        request.batch.outputs[0].allocation_id
    );
    assert_eq!(outputs[1].amount_zat, 200_000_000);
    assert_ne!(outputs[0].memo, outputs[1].memo);
    assert!(outputs.iter().all(|output| output.memo.len() < 512));
    let debug = format!("{execution:?} {:?}", fixture.config());
    assert!(!debug.contains(RAW_TRANSACTION));
    assert!(!debug.contains("wctest1ironwood"));
    assert!(!debug.contains("wallet.seed"));
}

#[test]
fn every_success_crash_boundary_resumes_without_duplicate_signing() {
    let checkpoints = [
        Checkpoint::StagePersisted(WecPipelineStage::Reserved),
        Checkpoint::IdentityReturned,
        Checkpoint::RecoveryReturned,
        Checkpoint::SigningReturned,
        Checkpoint::InspectionReturned,
        Checkpoint::StagePersisted(WecPipelineStage::Signed),
        Checkpoint::BroadcastReturned(WecPipelineStage::Completed),
        Checkpoint::StagePersisted(WecPipelineStage::Completed),
    ];
    for checkpoint in checkpoints {
        let fixture = Fixture::new();
        let wallet = Arc::new(MockWallet::new(fixture.account));
        let interrupted = WecPayoutSigner::new(fixture.config(), wallet.clone())
            .expect("signer")
            .with_checkpoint_hook(Arc::new(InterruptOnce::new(checkpoint)));
        assert_eq!(
            interrupted.execute(&request(fixture.account)).unwrap_err(),
            WecPayoutError::Interrupted,
            "checkpoint {checkpoint:?}"
        );
        let execution = make_signer(&fixture, wallet.clone())
            .execute(&request(fixture.account))
            .expect("restart succeeds");
        assert_eq!(execution.receipt.transaction_id, TXID);
        let (_, sign_calls, _, _) = wallet.counts();
        assert!(sign_calls <= 1, "checkpoint {checkpoint:?}");
        let broadcasts = wallet.broadcasts();
        assert!(broadcasts.windows(2).all(|pair| pair[0] == pair[1]));
    }
}

#[test]
fn unresolved_broadcast_boundaries_replay_only_exact_bytes() {
    for checkpoint in [
        Checkpoint::BroadcastReturned(WecPipelineStage::BroadcastUnresolved),
        Checkpoint::StagePersisted(WecPipelineStage::BroadcastUnresolved),
    ] {
        let fixture = Fixture::new();
        let wallet = Arc::new(MockWallet::new(fixture.account));
        wallet.push_broadcast(Err(BroadcastFailure::Timeout));
        wallet.push_broadcast(accepted());
        let first = WecPayoutSigner::new(fixture.config(), wallet.clone())
            .expect("signer")
            .with_checkpoint_hook(Arc::new(InterruptOnce::new(checkpoint)));
        assert_eq!(
            first.execute(&request(fixture.account)).unwrap_err(),
            WecPayoutError::Interrupted
        );
        make_signer(&fixture, wallet.clone())
            .execute(&request(fixture.account))
            .expect("exact rebroadcast succeeds");
        let calls = wallet.broadcasts();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert_eq!(wallet.counts().1, 1);
    }
}

#[test]
fn explicit_rejection_is_durable_across_restart() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    wallet.push_broadcast(Err(BroadcastFailure::Rejected));
    let signer = make_signer(&fixture, wallet.clone());
    assert_eq!(
        signer.execute(&request(fixture.account)).unwrap_err(),
        WecPayoutError::BroadcastRejected
    );
    assert_eq!(
        make_signer(&fixture, wallet.clone())
            .execute(&request(fixture.account))
            .unwrap_err(),
        WecPayoutError::BroadcastRejected
    );
    assert_eq!(wallet.counts().3, 1);
}

#[test]
fn rejection_crash_boundaries_never_create_a_replacement() {
    for checkpoint in [
        Checkpoint::BroadcastReturned(WecPipelineStage::Rejected),
        Checkpoint::StagePersisted(WecPipelineStage::Rejected),
    ] {
        let fixture = Fixture::new();
        let wallet = Arc::new(MockWallet::new(fixture.account));
        wallet.push_broadcast(Err(BroadcastFailure::Rejected));
        wallet.push_broadcast(Err(BroadcastFailure::Rejected));
        let request = request(fixture.account);
        let interrupted = WecPayoutSigner::new(fixture.config(), wallet.clone())
            .expect("signer")
            .with_checkpoint_hook(Arc::new(InterruptOnce::new(checkpoint)));
        assert_eq!(
            interrupted.execute(&request).unwrap_err(),
            WecPayoutError::Interrupted
        );
        assert_eq!(
            make_signer(&fixture, wallet.clone())
                .execute(&request)
                .unwrap_err(),
            WecPayoutError::BroadcastRejected
        );
        assert_eq!(wallet.counts().1, 1);
        let calls = wallet.broadcasts();
        assert!(calls.windows(2).all(|pair| pair[0] == pair[1]));
    }
}

#[test]
fn exact_replay_returns_receipt_and_conflicting_retry_is_fatal() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    let signer = make_signer(&fixture, wallet.clone());
    let original = request(fixture.account);
    let first = signer.execute(&original).expect("first payout");
    let counts = wallet.counts();
    let replay = signer.execute(&original).expect("exact replay");
    assert_eq!(first, replay);
    assert_eq!(wallet.counts(), counts);

    let mut conflict = original;
    conflict.batch.outputs[0].amount_zat += 1;
    assert_eq!(
        signer.execute(&conflict).unwrap_err(),
        WecPayoutError::IdempotencyConflict
    );
    assert_eq!(wallet.counts(), counts);
}

#[test]
fn every_tampered_inspection_fact_fails_before_broadcast() {
    let tampers = [
        Tamper::OutputAmount,
        Tamper::OutputAddress,
        Tamper::OutputOrder,
        Tamper::Network,
        Tamper::Account,
        Tamper::FundSource,
        Tamper::RawDigest,
        Tamper::Fee,
        Tamper::Stored,
        Tamper::TransactionId,
    ];
    for tamper in tampers {
        let fixture = Fixture::new();
        let wallet = Arc::new(MockWallet::new(fixture.account));
        wallet.tamper(tamper);
        assert_eq!(
            make_signer(&fixture, wallet.clone())
                .execute(&request(fixture.account))
                .unwrap_err(),
            WecPayoutError::WalletProtocolViolation
        );
        assert_eq!(wallet.counts().3, 0);
    }
}

#[test]
fn wrong_request_and_wallet_identities_fail_closed() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    let signer = make_signer(&fixture, wallet.clone());

    let mut wrong = request(fixture.account);
    wrong.batch.network = ChainNetwork::Mainnet;
    assert_eq!(
        signer.execute(&wrong).unwrap_err(),
        WecPayoutError::WrongNetwork
    );
    wrong = request(fixture.account);
    wrong.source_account = Uuid::from_u128(0x777);
    assert_eq!(
        signer.execute(&wrong).unwrap_err(),
        WecPayoutError::WrongAccount
    );
    wrong = request(fixture.account);
    wrong.fund_source = WalletFundSource::Transparent;
    assert_eq!(
        signer.execute(&wrong).unwrap_err(),
        WecPayoutError::WrongFundSource
    );
    wrong = request(fixture.account);
    wrong.batch.outputs[0].receiver_kind = ReceiverKind::Transparent;
    assert_eq!(
        signer.execute(&wrong).unwrap_err(),
        WecPayoutError::InvalidRequest
    );

    for expected in [
        WecPayoutError::WrongNetwork,
        WecPayoutError::WrongAccount,
        WecPayoutError::WrongFundSource,
        WecPayoutError::WalletUnavailable,
    ] {
        let isolated = Fixture::new();
        let wallet = Arc::new(MockWallet::new(isolated.account));
        wallet.mutate_identity(|identity| match expected {
            WecPayoutError::WrongNetwork => identity.branch_id = "c3a6678a".to_owned(),
            WecPayoutError::WrongAccount => identity.account_id = Uuid::from_u128(0x888),
            WecPayoutError::WrongFundSource => {
                identity.fund_source = WalletFundSource::Sapling;
            }
            WecPayoutError::WalletUnavailable => identity.synchronized = false,
            _ => unreachable!(),
        });
        assert_eq!(
            make_signer(&isolated, wallet)
                .execute(&request(isolated.account))
                .unwrap_err(),
            expected
        );
    }
}

#[test]
fn signing_ambiguity_recovers_wallet_persisted_bytes_without_resigning() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    wallet.fail_sign_after_store(NativeWalletError::Timeout);
    let request = request(fixture.account);
    assert_eq!(
        make_signer(&fixture, wallet.clone())
            .execute(&request)
            .unwrap_err(),
        WecPayoutError::WalletAmbiguous
    );
    let execution = make_signer(&fixture, wallet.clone())
        .execute(&request)
        .expect("seedless recovery succeeds");
    assert_eq!(execution.receipt.transaction_id, TXID);
    assert_eq!(wallet.counts().1, 1);
}

#[test]
fn wallet_side_conflicting_batch_binding_is_fatal() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    let mut foreign = request(fixture.account);
    foreign.batch.ledger_root = [0x99; 32];
    make_signer(&fixture, wallet.clone())
        .execute(&foreign)
        .expect("foreign exact batch establishes native binding");

    fs::remove_dir_all(&fixture.journal).expect("simulate lost local journal");
    assert_eq!(
        make_signer(&fixture, wallet.clone())
            .execute(&request(fixture.account))
            .unwrap_err(),
        WecPayoutError::IdempotencyConflict
    );
    assert_eq!(wallet.counts().1, 1);
}

#[test]
fn recovery_timeout_never_falls_through_to_signing() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    wallet.push_recovery_failure(NativeWalletError::Timeout);
    assert_eq!(
        make_signer(&fixture, wallet.clone())
            .execute(&request(fixture.account))
            .unwrap_err(),
        WecPayoutError::WalletAmbiguous
    );
    assert_eq!(wallet.counts().1, 0);
    make_signer(&fixture, wallet.clone())
        .execute(&request(fixture.account))
        .expect("later exact attempt succeeds");
    assert_eq!(wallet.counts().1, 1);
}

#[test]
fn broadcast_failures_are_classified_and_ambiguous_bytes_are_stable() {
    for failure in [
        BroadcastFailure::Timeout,
        BroadcastFailure::Unavailable,
        BroadcastFailure::Ambiguous,
        BroadcastFailure::ProtocolViolation,
    ] {
        let fixture = Fixture::new();
        let wallet = Arc::new(MockWallet::new(fixture.account));
        wallet.push_broadcast(Err(failure));
        wallet.push_broadcast(Ok(BroadcastOutcome {
            transaction_id: TXID.to_owned(),
            disposition: BroadcastDisposition::AlreadyKnown,
        }));
        let request = request(fixture.account);
        assert_eq!(
            make_signer(&fixture, wallet.clone())
                .execute(&request)
                .unwrap_err(),
            WecPayoutError::BroadcastAmbiguous
        );
        let execution = make_signer(&fixture, wallet.clone())
            .execute(&request)
            .expect("exact retry succeeds");
        assert_eq!(execution.disposition, BroadcastDisposition::AlreadyKnown);
        let calls = wallet.broadcasts();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
    }
}

#[test]
fn wrong_success_txid_is_ambiguous_and_never_completed() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    wallet.push_broadcast(Ok(BroadcastOutcome {
        transaction_id: "cd".repeat(32),
        disposition: BroadcastDisposition::Accepted,
    }));
    wallet.push_broadcast(accepted());
    let request = request(fixture.account);
    assert_eq!(
        make_signer(&fixture, wallet.clone())
            .execute(&request)
            .unwrap_err(),
        WecPayoutError::BroadcastAmbiguous
    );
    make_signer(&fixture, wallet.clone())
        .execute(&request)
        .expect("exact retry succeeds");
    assert_eq!(wallet.broadcasts()[0], wallet.broadcasts()[1]);
}

#[cfg(unix)]
#[test]
fn credential_and_journal_permissions_are_enforced() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.seed, fs::Permissions::from_mode(0o640)).expect("unsafe mode");
    let wallet = Arc::new(MockWallet::new(fixture.account));
    assert_eq!(
        make_signer(&fixture, wallet)
            .execute(&request(fixture.account))
            .unwrap_err(),
        WecPayoutError::UnsafeCredential
    );

    fs::set_permissions(&fixture.seed, fs::Permissions::from_mode(0o600)).expect("safe mode");
    let wallet = Arc::new(MockWallet::new(fixture.account));
    make_signer(&fixture, wallet)
        .execute(&request(fixture.account))
        .expect("payout succeeds");
    assert_eq!(
        fs::metadata(&fixture.journal)
            .expect("journal metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for entry in fs::read_dir(&fixture.journal).expect("journal directory") {
        let metadata = entry
            .expect("journal entry")
            .metadata()
            .expect("entry metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn policy_and_call_bounds_reject_unsafe_values() {
    let fixture = Fixture::new();
    #[cfg(unix)]
    let uid = fs::metadata(&fixture.seed).unwrap().uid();
    #[cfg(not(unix))]
    let uid = 0;
    assert_eq!(
        WecSignerConfig::new(
            &fixture.journal,
            fixture.account,
            SeedSource::protected_file(&fixture.seed, uid),
        )
        .unwrap()
        .with_max_outputs(101)
        .err(),
        Some(WecPayoutError::InvalidRequest)
    );
    assert_eq!(
        WecSignerConfig::new(
            "relative/journal",
            fixture.account,
            SeedSource::protected_file(&fixture.seed, uid),
        )
        .err(),
        Some(WecPayoutError::InvalidRequest)
    );
    assert_eq!(
        NativeCallLimits::new(
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
        .err(),
        Some(WecPayoutError::InvalidRequest)
    );
}

#[test]
fn wallet_fee_above_the_exact_cap_never_reaches_broadcast() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    let config = fixture
        .config()
        .with_max_fee_zat(9_999)
        .expect("valid strict fee cap");
    let signer = WecPayoutSigner::new(config, wallet.clone()).expect("signer");
    assert_eq!(
        signer.execute(&request(fixture.account)).unwrap_err(),
        WecPayoutError::WalletProtocolViolation
    );
    assert_eq!(wallet.counts().3, 0);
}

#[test]
fn corrupt_journal_never_reaches_wallet_or_node() {
    let fixture = Fixture::new();
    let wallet = Arc::new(MockWallet::new(fixture.account));
    let request = request(fixture.account);
    make_signer(&fixture, wallet.clone())
        .execute(&request)
        .expect("initial payout");
    let record = fixture
        .journal
        .join(format!("{}.json", request.batch.batch_id.simple()));
    let mut bytes = fs::read(&record).expect("journal record");
    let index = bytes.len() / 2;
    bytes[index] ^= 1;
    fs::write(&record, bytes).expect("tampered journal");
    let counts = wallet.counts();
    assert_eq!(
        make_signer(&fixture, wallet.clone())
            .execute(&request)
            .unwrap_err(),
        WecPayoutError::JournalCorrupt
    );
    assert_eq!(wallet.counts(), counts);
}

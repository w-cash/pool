//! End-to-end payout lifecycle over the production PostgreSQL projector and
//! settlement coordinator.
//!
//! The backend event source, prevalidated address result, native-wallet
//! transport, and chain-node observations are deterministic test doubles: no
//! test can spend funds or depend on a live node. Authentication, authority
//! matching, event validation, projection, accounting, the WEC signer journal,
//! settlement, and every durable transition between those boundaries use the
//! real production implementation.

#![forbid(unsafe_code)]
#![cfg(unix)]
#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::{Arc, Mutex},
    time::Duration,
};

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Row};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use uuid::Uuid;
use wcash_pool_backend_client::{BackendClient, BackendClientConfig, ExpectedBackend};
use wcash_pool_portal::{Asset, PageRequest, PortalRepository};
use wcash_pool_protocol::{
    canonical_attribution_id, decode_backend_request, encode_backend_message, BackendEvent,
    BackendMessage, BackendRequest, CanonicalUuid, ChainTip, Hex108, Hex32, JobDescriptor,
    MergedChain, ShareReceipt, TargetBe, TargetLe, WinnerDescriptor, WorkerIdentity,
    BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, REQUIRED_BACKEND_CAPABILITIES,
};
use wcash_pool_store::{
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PayoutBatchState,
    PayoutConfirmation, PostgresStore, ProjectionResult, WalletObservation,
};
use wcash_wec_payout_signer::{
    BroadcastDisposition, BroadcastFailure, BroadcastOutcome, NativeWalletError,
    NativeWalletTransport, PersistedIntent, SecretSeed, SeedSource, WalletBroadcastCall,
    WalletFundSource, WalletIdentity, WalletInspectionCall, WalletNetwork, WalletRecoveryCall,
    WalletSignCall, WalletSignedTransaction, WecPayoutSigner, WecSignerConfig,
    WCASH_TESTNET_BRANCH_ID, WCASH_TESTNET_GENESIS_HASH,
};

use super::settlement::{
    BoundaryFailure, BoundaryFuture, ExactExecutionSigner, ExactTransactionBroadcaster,
    RecoveredPayoutExecution, ResumeOutcome, RichPayoutExecution, SettlementOrchestrator,
    WecExecutionSigner,
};

const REWARD_ZAT: u64 = 625_000_000;
// Stable Wcash Testnet Ironwood address from Wolf's native wallet golden vectors.
// Parsing remains outside this lifecycle test because the deployed validator is
// an integrity-pinned process boundary, but the fixture itself is not a made-up
// or legacy-prefix address.
const PAYOUT_ADDRESS: &str =
    "wutest17mvne4ygv9v8rkjf6yxnrveceejh8nutee8svp8swkgj7s7ac9ga36u2av8hgpc28cc42u474ypjq2jsdt64utcxtztm2jr6guvaryhh";
const SIGNED_TRANSACTION_HEX: &str = "06000000deadbeef";
const TRANSACTION_ID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TRANSACTION_ID_BYTES: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn deployment_identity() -> DeploymentIdentity {
    DeploymentIdentity {
        id: Uuid::new_v4(),
        network: DeploymentNetwork::Testnet,
        wcash_genesis: [0x11; 32],
        zcash_genesis: [0x12; 32],
        chain_id: 0x5745_4301,
        wcash_payout_commitment: [0x13; 32],
        zcash_payout_commitment: [0x14; 32],
        backend_instance: Uuid::new_v4(),
        journal_stream: Uuid::new_v4(),
    }
}

fn policy(chain: Chain) -> ChainPolicy {
    ChainPolicy {
        chain,
        pplns_window_work: BigUint::from(1_000_000_u64),
        fee_bps: 0,
        payout_threshold_zat: 1,
        required_confirmations: 100,
        payout_confirmations: 3,
        maximum_payout_outputs: 10,
        minimum_payout_zat: 1_000_000_000_000,
        maximum_payout_zat: 1_000_000_000_000,
        payout_skip_bps: 0,
        maximum_network_fee_zat: 1,
        maximum_network_fee_bps: 1_000,
        policy_version: 1,
    }
}

fn job() -> JobDescriptor {
    let mut header = [0x21; 108];
    header[..4].copy_from_slice(&4_u32.to_le_bytes());
    header[4..36].copy_from_slice(&[0x22; 32]);
    header[100..104].copy_from_slice(&1_725_000_000_u32.to_le_bytes());
    JobDescriptor {
        job_id: Hex32::new([0x20; 32]),
        wcash_candidate_hash_le: Hex32::new([0x61; 32]),
        header_input: Hex108::new(header),
        wcash_previous_hash_le: Hex32::new([0x23; 32]),
        zcash_previous_hash_le: Hex32::new([0x22; 32]),
        wcash_coinbase_txid_le: Hex32::new([0x62; 32]),
        zcash_coinbase_txid_le: Hex32::new([0x63; 32]),
        wcash_target_le: TargetLe::new([0x7f; 32]),
        zcash_target_le: TargetLe::new([0x3f; 32]),
        wcash_height: 11,
        zcash_height: 22,
        wcash_reward_zat: REWARD_ZAT,
        zcash_reward_zat: 312_500_000,
        wcash_maturity_confirmations: 100,
        zcash_maturity_confirmations: 100,
        max_age_ms: 45_000,
    }
}

fn wcash_winner(job: &JobDescriptor) -> WinnerDescriptor {
    WinnerDescriptor {
        chain: MergedChain::Wcash,
        block_hash_le: job.wcash_candidate_hash_le.clone(),
        height: job.wcash_height,
        coinbase_txid_le: job.wcash_coinbase_txid_le.clone(),
        reward_zat: job.wcash_reward_zat,
        maturity_confirmations: job.wcash_maturity_confirmations,
    }
}

async fn read_backend_request(stream: &mut UnixStream) -> BackendRequest {
    let mut prefix = [0_u8; BACKEND_LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut prefix)
        .await
        .expect("backend request prefix reads");
    let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stream
        .read_exact(&mut payload)
        .await
        .expect("backend request body reads");
    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&payload);
    decode_backend_request(&frame).expect("backend request validates")
}

async fn backend_authority(
    identity: &DeploymentIdentity,
) -> wcash_pool_backend_client::BackendAuthority {
    let directory = tempfile::tempdir().expect("temporary backend directory creates");
    let socket_path = directory.path().join("backend.sock");
    let listener = UnixListener::bind(&socket_path).expect("test backend socket binds");
    let server_identity = identity.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("backend client connects");
        let BackendRequest::Hello { id, .. } = read_backend_request(&mut stream).await else {
            panic!("first backend request must be Hello");
        };
        let hello = BackendMessage::HelloOk {
            version: BACKEND_PROTOCOL_VERSION,
            id,
            backend_session: CanonicalUuid::new(Uuid::new_v4()),
            backend_instance: CanonicalUuid::new(server_identity.backend_instance),
            journal_stream: CanonicalUuid::new(server_identity.journal_stream),
            capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
            wcash_genesis: Hex32::new(server_identity.wcash_genesis),
            zcash_genesis: Hex32::new(server_identity.zcash_genesis),
            wcash_payout_commitment: Hex32::new(server_identity.wcash_payout_commitment),
            zcash_payout_commitment: Hex32::new(server_identity.zcash_payout_commitment),
            share_target_ceiling_be: TargetBe::new([0x7f; 32]),
            chain_id: server_identity.chain_id,
            current_event_seq: 0,
        };
        stream
            .write_all(&encode_backend_message(&hello).expect("backend HelloOk encodes"))
            .await
            .expect("backend HelloOk writes");

        let BackendRequest::SubscribeJobs { id, .. } = read_backend_request(&mut stream).await
        else {
            panic!("second backend request must be SubscribeJobs");
        };
        let snapshot = BackendMessage::JobSnapshot {
            version: BACKEND_PROTOCOL_VERSION,
            id,
            event_seq: 0,
            current: None,
            recent: Vec::new(),
        };
        stream
            .write_all(&encode_backend_message(&snapshot).expect("job snapshot encodes"))
            .await
            .expect("job snapshot writes");
    });

    let expected = ExpectedBackend::new(
        Hex32::new(identity.wcash_genesis),
        Hex32::new(identity.zcash_genesis),
        identity.chain_id,
        Hex32::new(identity.wcash_payout_commitment),
        Hex32::new(identity.zcash_payout_commitment),
        TargetBe::new([0x7f; 32]),
    )
    .expect("expected backend validates")
    .with_backend_instance(CanonicalUuid::new(identity.backend_instance))
    .with_journal_stream(CanonicalUuid::new(identity.journal_stream));
    let config = BackendClientConfig::new(&socket_path, expected).expect("client config validates");
    let mut client = BackendClient::connect(config, CanonicalUuid::new(Uuid::new_v4()), 0)
        .await
        .expect("exact backend authority authenticates");
    let snapshot = client.subscribe_jobs(0).await.expect("job snapshot binds");
    let authority = snapshot.authority().clone();
    server.await.expect("backend server completes");
    authority
}

#[derive(Clone)]
struct BoundWalletTransaction {
    request_commitment: [u8; 32],
    signed: WalletSignedTransaction,
    intent: PersistedIntent,
}

struct WalletState {
    identity: WalletIdentity,
    bound: Option<BoundWalletTransaction>,
    last_sign_call: Option<WalletSignCall>,
}

struct DeterministicWallet {
    state: Mutex<WalletState>,
}

impl DeterministicWallet {
    fn new(identity: WalletIdentity) -> Self {
        Self {
            state: Mutex::new(WalletState {
                identity,
                bound: None,
                last_sign_call: None,
            }),
        }
    }

    fn last_sign_call(&self) -> WalletSignCall {
        self.state
            .lock()
            .expect("wallet state lock")
            .last_sign_call
            .clone()
            .expect("production signer called the wallet boundary")
    }
}

impl NativeWalletTransport for DeterministicWallet {
    fn identity(
        &self,
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<WalletIdentity, NativeWalletError> {
        assert!(!timeout.is_zero());
        assert!(maximum_response_bytes >= 1_024);
        Ok(self
            .state
            .lock()
            .expect("wallet state lock")
            .identity
            .clone())
    }

    fn recover_exact(
        &self,
        call: &WalletRecoveryCall,
    ) -> Result<Option<WalletSignedTransaction>, NativeWalletError> {
        let state = self.state.lock().expect("wallet state lock");
        match &state.bound {
            Some(bound) if bound.request_commitment != call.request_commitment => {
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
        assert_eq!(seed.expose_secret(), &[0x42; 32]);
        let mut state = self.state.lock().expect("wallet state lock");
        state.last_sign_call = Some(call.clone());
        if let Some(bound) = &state.bound {
            if bound.request_commitment != call.request_commitment {
                return Err(NativeWalletError::IdempotencyConflict);
            }
            return Ok(bound.signed.clone());
        }
        let signed = WalletSignedTransaction {
            batch_id: call.batch_id,
            request_commitment: call.request_commitment,
            transaction_id: TRANSACTION_ID.to_owned(),
            raw_transaction_hex: SIGNED_TRANSACTION_HEX.to_owned(),
            unsigned_digest: [0x33; 32],
            fee_zat: call.max_fee_zat,
            target_height: 50_001,
            expiry_height: 50_041,
            stored: true,
            internal_change_receiver_verified: true,
        };
        let intent = PersistedIntent {
            identity: call.identity.clone(),
            batch_id: call.batch_id,
            request_commitment: call.request_commitment,
            ordered_outputs: call.outputs.clone(),
            unsigned_digest: signed.unsigned_digest,
            transaction_id: signed.transaction_id.clone(),
            raw_transaction_sha256: Sha256::digest(
                hex::decode(SIGNED_TRANSACTION_HEX).expect("signed transaction fixture decodes"),
            )
            .into(),
            fee_zat: signed.fee_zat,
            target_height: signed.target_height,
            expiry_height: signed.expiry_height,
            stored: true,
            internal_change_receiver_verified: true,
        };
        state.bound = Some(BoundWalletTransaction {
            request_commitment: call.request_commitment,
            signed: signed.clone(),
            intent,
        });
        Ok(signed)
    }

    fn inspect_persisted(
        &self,
        call: &WalletInspectionCall,
    ) -> Result<PersistedIntent, NativeWalletError> {
        let state = self.state.lock().expect("wallet state lock");
        let bound = state.bound.as_ref().ok_or(NativeWalletError::Unavailable)?;
        if call.batch_id != bound.signed.batch_id
            || call.request_commitment != bound.request_commitment
            || call.transaction_id != bound.signed.transaction_id
            || call.raw_transaction_hex != bound.signed.raw_transaction_hex
        {
            return Err(NativeWalletError::ProtocolViolation);
        }
        Ok(bound.intent.clone())
    }

    fn broadcast_exact(
        &self,
        call: &WalletBroadcastCall,
    ) -> Result<BroadcastOutcome, BroadcastFailure> {
        Ok(BroadcastOutcome {
            transaction_id: call.transaction_id.clone(),
            disposition: BroadcastDisposition::Accepted,
        })
    }
}

struct UnusedSigner(Chain);

impl ExactExecutionSigner for UnusedSigner {
    fn chain(&self) -> Chain {
        self.0
    }

    fn prepare_exact(
        &self,
        _request: &wcash_pool_portal::PayoutBatchRequest,
    ) -> BoundaryFuture<'_, RichPayoutExecution> {
        Box::pin(async { Err(BoundaryFailure::Invariant) })
    }

    fn recover_exact(
        &self,
        _request: &wcash_pool_portal::PayoutBatchRequest,
    ) -> BoundaryFuture<'_, Option<RecoveredPayoutExecution>> {
        Box::pin(async { Err(BoundaryFailure::Invariant) })
    }
}

#[derive(Clone)]
struct DeterministicBroadcaster {
    chain: Chain,
    submissions: Arc<Mutex<Vec<wcash_pool_store::SignedPayoutArtifact>>>,
}

impl DeterministicBroadcaster {
    fn new(chain: Chain) -> Self {
        Self {
            chain,
            submissions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn submissions(&self) -> Vec<wcash_pool_store::SignedPayoutArtifact> {
        self.submissions
            .lock()
            .expect("broadcast state lock")
            .clone()
    }
}

impl ExactTransactionBroadcaster for DeterministicBroadcaster {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn rebroadcast_exact(
        &self,
        artifact: &wcash_pool_store::SignedPayoutArtifact,
    ) -> BoundaryFuture<'_, ()> {
        let artifact = artifact.clone();
        let expected_chain = self.chain;
        let submissions = Arc::clone(&self.submissions);
        Box::pin(async move {
            if artifact.chain != expected_chain {
                return Err(BoundaryFailure::Conflict);
            }
            let mut submissions = submissions.lock().expect("broadcast state lock");
            if submissions.iter().any(|submitted| {
                submitted.transaction_id == artifact.transaction_id
                    && submitted.signed_transaction != artifact.signed_transaction
            }) {
                return Err(BoundaryFailure::Conflict);
            }
            submissions.push(artifact);
            Ok(())
        })
    }
}

async fn record_reconciliation(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    observed_wallet_spendable_zat: u64,
) -> wcash_pool_store::WalletReconciliation {
    let now = sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT")
        .fetch_one(pool)
        .await
        .expect("database clock reads");
    let spendable = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(e.amount_zat),0)::BIGINT FROM ledger_entries e \
         JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND t.chain='wcash' \
           AND e.ledger_account='collector_spendable_asset'",
    )
    .bind(store.deployment_id())
    .fetch_one(pool)
    .await
    .expect("collector balance reads");
    assert_eq!(
        u64::try_from(spendable).expect("collector balance is nonnegative"),
        observed_wallet_spendable_zat,
        "the independently observed wallet balance must match the collector ledger"
    );
    let now = u64::try_from(now).expect("database timestamp is nonnegative");
    store
        .record_wallet_reconciliation(&WalletObservation {
            chain: Chain::Wcash,
            wallet_state_digest: [0x91; 32],
            wallet_spendable_zat: observed_wallet_spendable_zat,
            best_tip_hash: [0xa1; 32],
            best_tip_height: 50_000,
            observed_at: now,
            valid_until: now + 240,
        })
        .await
        .expect("wallet state reconciles against the real ledger")
}

#[tokio::test]
#[ignore = "requires WCASH_POOL_TEST_DATABASE_URL for a disposable PostgreSQL database"]
async fn authenticated_winner_reaches_confirmed_recipient_ledger() {
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL")
        .expect("WCASH_POOL_TEST_DATABASE_URL identifies a disposable database");
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("disposable PostgreSQL is available");
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&admin)
        .await
        .expect("disposable schema resets");

    let identity = deployment_identity();
    let store = PostgresStore::connect(&database_url, 4, identity.clone())
        .await
        .expect("production store connects");
    store.migrate().await.expect("production migrations apply");
    store
        .bind_deployment()
        .await
        .expect("deployment identity binds");
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("chain-separated zero-fee policies bind");

    let (account_id, worker_id, mining_token) = store
        .provision_worker("miner", "z15")
        .await
        .expect("production worker provisioning succeeds");
    let authenticator = store
        .authentication_provider(1, wcash_pool_store::MiningAuthenticationMode::Token)
        .expect("production Argon2 authentication provider builds");
    let grant = authenticator
        .authenticate_credentials("miner.z15", mining_token.expose_secret())
        .await
        .expect("issued mining credential authenticates");
    assert_eq!(grant.worker().account_id(), account_id);
    assert_eq!(grant.worker().worker_id(), worker_id);
    authenticator
        .revalidate_worker(&grant)
        .await
        .expect("authenticated worker remains live at share attribution");

    // Address parsing belongs to the isolated, integrity-pinned Wolf wallet
    // validator. Seed its canonical golden-vector result; all selection,
    // immutability, threshold, recipient, and amount handling after this row
    // are real.
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by,validated_at, \
          active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
         VALUES ($1,$2,$3,'wcash','testnet',$4,'ironwood','integration-address-authority-v1', \
                 clock_timestamp(),clock_timestamp(),$5,1,true,'active',1)",
    )
    .bind(store.deployment_id())
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(PAYOUT_ADDRESS)
    .bind([0x44_u8; 32].as_slice())
    .execute(&admin)
    .await
    .expect("authoritatively validated destination fixture persists");

    let authority = backend_authority(&identity).await;
    let job = job();
    let winner = wcash_winner(&job);
    let target = TargetLe::new([0x7f; 32]);
    let share_id = Hex32::new([0x71; 32]);
    let worker = WorkerIdentity {
        account_id: CanonicalUuid::new(grant.worker().account_id()),
        worker_id: CanonicalUuid::new(grant.worker().worker_id()),
        label: grant.worker().canonical_login().to_owned(),
    };
    let receipt = ShareReceipt {
        event_seq: 2,
        job_id: job.job_id.clone(),
        share_id: share_id.clone(),
        attribution_id: canonical_attribution_id(&worker, &target)
            .expect("authenticated attribution is canonical"),
        parent_hash_le: Hex32::new([0x72; 32]),
        winners: vec![winner.clone()],
    };
    let events = [
        BackendEvent::JobActivated {
            event_seq: 1,
            job: job.clone(),
        },
        BackendEvent::ShareCommitted {
            receipt,
            job_id: job.job_id.clone(),
            identity: worker,
            target_le: target,
        },
        BackendEvent::WinnerObserved {
            event_seq: 3,
            share_id: share_id.clone(),
            job_id: job.job_id.clone(),
            winner: winner.clone(),
            tip: ChainTip {
                block_hash_le: winner.block_hash_le.clone(),
                height: winner.height,
            },
            confirmations: 1,
        },
        BackendEvent::WinnerMatured {
            event_seq: 4,
            share_id,
            job_id: job.job_id,
            winner: winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0xa2; 32]),
                height: winner.height + 99,
            },
            confirmations: 100,
        },
    ];
    let projector = store.event_projector();
    for event in &events[..3] {
        assert_eq!(
            projector
                .project_event(&authority, event)
                .await
                .expect("backend event projects through production accounting"),
            ProjectionResult::Applied
        );
    }
    let observed_balance = PortalRepository::balances(&store, account_id)
        .await
        .expect("observed reward balance loads")
        .into_iter()
        .find(|balance| balance.asset == Asset::Wec)
        .expect("WEC balance exists");
    assert_eq!(observed_balance.immature_zat, REWARD_ZAT);
    assert_eq!(observed_balance.payable_zat, 0);

    assert_eq!(
        projector
            .project_event(&authority, &events[3])
            .await
            .expect("100-confirmation maturity projects"),
        ProjectionResult::Applied
    );
    let mature_balance = PortalRepository::balances(&store, account_id)
        .await
        .expect("mature reward balance loads")
        .into_iter()
        .find(|balance| balance.asset == Asset::Wec)
        .expect("WEC balance exists");
    assert_eq!(mature_balance.immature_zat, 0);
    assert_eq!(mature_balance.payable_zat, REWARD_ZAT);
    let rewards = PortalRepository::reward_history(
        &store,
        account_id,
        PageRequest {
            before: None,
            limit: 10,
        },
    )
    .await
    .expect("PPLNS allocation history loads");
    assert_eq!(rewards.items.len(), 1);
    assert_eq!(rewards.items[0].asset, Asset::Wec);
    assert_eq!(rewards.items[0].amount_zat, REWARD_ZAT);
    assert_eq!(rewards.items[0].state, "matured");

    let reconciliation = record_reconciliation(&store, &admin, REWARD_ZAT).await;
    let batch = store
        .create_payout_batch(Chain::Wcash, Uuid::new_v4(), reconciliation.id)
        .await
        .expect("production payout planner reserves the mature liability");
    assert_eq!(batch.state, PayoutBatchState::Draft);
    assert_eq!(batch.miner_total_zat, REWARD_ZAT);
    assert_eq!(batch.maximum_network_fee_zat, 1);
    assert_eq!(batch.payout_total_zat, REWARD_ZAT - 1);
    assert_eq!(batch.outputs.len(), 1);
    assert_eq!(batch.outputs[0].account_id, account_id);
    assert_eq!(batch.outputs[0].address, PAYOUT_ADDRESS);
    assert_eq!(batch.outputs[0].amount_zat, REWARD_ZAT - 1);

    let signer_temp = tempfile::tempdir().expect("temporary signer directory creates");
    let signer_directory =
        fs::canonicalize(signer_temp.path()).expect("signer directory canonicalizes");
    let seed_path = signer_directory.join("wallet.seed");
    fs::write(&seed_path, format!("{}\n", "42".repeat(32))).expect("test seed writes");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600))
        .expect("test seed permissions restrict");
    let source_account = Uuid::new_v4();
    let wallet = Arc::new(DeterministicWallet::new(WalletIdentity {
        network: WalletNetwork::Testnet,
        genesis_hash: WCASH_TESTNET_GENESIS_HASH.to_owned(),
        branch_id: WCASH_TESTNET_BRANCH_ID.to_owned(),
        account_id: source_account,
        collector_payout_commitment: identity.wcash_payout_commitment,
        fund_source: WalletFundSource::Ironwood,
        synchronized: true,
    }));
    let signer_config = WecSignerConfig::new(
        signer_directory.join("journal"),
        source_account,
        identity.wcash_payout_commitment,
        SeedSource::protected_file(
            &seed_path,
            fs::metadata(&seed_path).expect("seed metadata reads").uid(),
        ),
    )
    .expect("production WEC signer config validates")
    .with_max_fee_zat(1)
    .expect("test policy permits the exact fee");
    let native_signer = Arc::new(
        WecPayoutSigner::new(signer_config, wallet.clone())
            .expect("production WEC signer opens its durable journal"),
    );
    native_signer
        .readiness()
        .expect("production WEC signer verifies wallet identity");
    let wec_signer = Arc::new(WecExecutionSigner::new(native_signer, source_account));
    let wec_broadcaster = Arc::new(DeterministicBroadcaster::new(Chain::Wcash));
    let zec_signer = Arc::new(UnusedSigner(Chain::Zcash));
    let zec_broadcaster = Arc::new(DeterministicBroadcaster::new(Chain::Zcash));
    let orchestrator = SettlementOrchestrator::new(
        Arc::new(store.clone()),
        wec_signer.clone(),
        wec_broadcaster.clone(),
        zec_signer.clone(),
        zec_broadcaster.clone(),
    )
    .expect("production settlement coordinator composes");
    let ResumeOutcome::Broadcast {
        batch_id,
        chain,
        transaction_id,
    } = orchestrator
        .resume_next(Chain::Wcash)
        .await
        .expect("draft signs and broadcasts through durable fences")
    else {
        panic!("draft must reach Broadcast in one settlement pass");
    };
    assert_eq!(batch_id, batch.id);
    assert_eq!(chain, Chain::Wcash);

    let wallet_call = wallet.last_sign_call();
    assert_eq!(wallet_call.identity.network, WalletNetwork::Testnet);
    assert_eq!(wallet_call.identity.fund_source, WalletFundSource::Ironwood);
    assert_eq!(wallet_call.outputs.len(), 1);
    assert_eq!(wallet_call.outputs[0].canonical_address, PAYOUT_ADDRESS);
    assert_eq!(wallet_call.outputs[0].amount_zat, REWARD_ZAT - 1);
    let first_submissions = wec_broadcaster.submissions();
    assert_eq!(first_submissions.len(), 1);
    assert_eq!(first_submissions[0].transaction_id, transaction_id);
    assert_eq!(transaction_id, TRANSACTION_ID_BYTES);
    assert_eq!(
        first_submissions[0].signed_transaction,
        hex::decode(SIGNED_TRANSACTION_HEX).expect("signed transaction fixture decodes")
    );
    assert_eq!(first_submissions[0].state, PayoutBatchState::Broadcasting);

    // Recreate the coordinator like a process restart. It must submit the same
    // SQL-persisted bytes without access to the original signer or broadcaster.
    let restarted_wec_broadcaster = Arc::new(DeterministicBroadcaster::new(Chain::Wcash));
    let restarted = SettlementOrchestrator::new(
        Arc::new(store.clone()),
        Arc::new(UnusedSigner(Chain::Wcash)),
        restarted_wec_broadcaster.clone(),
        Arc::new(UnusedSigner(Chain::Zcash)),
        Arc::new(DeterministicBroadcaster::new(Chain::Zcash)),
    )
    .expect("settlement coordinator restarts");
    assert_eq!(
        restarted
            .resume_next(Chain::Wcash)
            .await
            .expect("restart safely resubmits exact bytes"),
        ResumeOutcome::AwaitingConfirmation {
            batch_id: batch.id,
            chain: Chain::Wcash,
            transaction_id,
        }
    );
    let restarted_submissions = restarted_wec_broadcaster.submissions();
    assert_eq!(restarted_submissions.len(), 1);
    assert_eq!(
        restarted_submissions[0].signed_transaction,
        first_submissions[0].signed_transaction
    );

    store
        .confirm_payout(
            batch.id,
            &PayoutConfirmation {
                block_hash: [0xf1; 32],
                block_height: 50_100,
                confirmations: 100,
            },
        )
        .await
        .expect("production confirmation projection settles the recipient ledger");

    let final_balance = PortalRepository::balances(&store, account_id)
        .await
        .expect("settled miner balance loads")
        .into_iter()
        .find(|balance| balance.asset == Asset::Wec)
        .expect("WEC balance exists");
    assert_eq!(final_balance.immature_zat, 0);
    assert_eq!(final_balance.payable_zat, 0);
    assert_eq!(final_balance.pending_zat, 0);
    assert_eq!(final_balance.total_zat, 0);

    let payout = PortalRepository::payout_history(
        &store,
        account_id,
        PageRequest {
            before: None,
            limit: 10,
        },
    )
    .await
    .expect("recipient payout history loads")
    .items
    .into_iter()
    .find(|payout| payout.batch_id == batch.id)
    .expect("confirmed recipient payout exists");
    assert_eq!(payout.state, "confirmed");
    assert_eq!(payout.gross_amount_zat, REWARD_ZAT);
    assert_eq!(payout.amount_zat, REWARD_ZAT - 1);
    assert_eq!(payout.reserved_network_fee_zat, Some(1));
    assert_eq!(payout.actual_network_fee_zat, Some(1));
    assert_eq!(payout.refunded_network_fee_zat, Some(0));
    assert_eq!(payout.transaction_id.as_deref(), Some(TRANSACTION_ID));
    assert_eq!(payout.confirmation_height, Some(50_100));

    let ledger = sqlx::query(
        "SELECT e.ledger_account,SUM(e.amount_zat)::BIGINT AS balance \
         FROM ledger_entries e JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND t.chain='wcash' \
         GROUP BY e.ledger_account ORDER BY e.ledger_account",
    )
    .bind(store.deployment_id())
    .fetch_all(&admin)
    .await
    .expect("final conserved ledger loads");
    let balance = |name: &str| {
        ledger
            .iter()
            .find(|row| row.get::<String, _>("ledger_account") == name)
            .map_or(0, |row| row.get::<i64, _>("balance"))
    };
    assert_eq!(balance("collector_spendable_asset"), 0);
    assert_eq!(balance("miner_payable"), 0);
    assert_eq!(balance("payout_pending"), 0);
    assert_eq!(balance("network_fee_expense"), 1);
    assert_eq!(balance("miner_network_fee_contribution"), -1);
    assert_eq!(
        ledger
            .iter()
            .map(|row| row.get::<i64, _>("balance"))
            .sum::<i64>(),
        0,
        "the full chain ledger remains conserved"
    );
}

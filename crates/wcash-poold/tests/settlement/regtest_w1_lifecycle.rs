//! Opt-in real-node Regtest gate. Wallet funds are mined, while each isolated
//! deployment's starting ledger is an explicitly labelled funding fixture.
//! Five deployments share one real wallet to test independent crash boundaries
//! before mining once. A child exits without destructors at each durable boundary;
//! its parent then recovers using freshly opened signer/store resources.
//! No production/network selection is configurable here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::{
    live_payout::{LoopbackJsonRpc, NodePayoutAuthority, RpcExactBroadcaster},
    payout_runtime::{AuthorityPayoutState, PayoutConfirmationAuthority},
    settlement::{
        BoundaryFailure, BoundaryFuture, ExactExecutionSigner, ExactTransactionBroadcaster,
        RecoveredPayoutExecution, RichPayoutExecution, SettlementOrchestrator, WecExecutionSigner,
    },
    wcash_observation::WcashWalletObserver,
    wec_wallet_transport::{PinnedWolfProgram, WolfWalletTransport},
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Row};
use std::{fs, io::Write, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;
use wcash_pool_portal::{Asset, PageRequest, PortalRepository};
use wcash_pool_store::{Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PostgresStore};
use wcash_wec_payout_signer::{
    Checkpoint, CheckpointHook, NativeWalletTransport, SeedSource, WalletFundSource, WalletNetwork,
    WecPayoutRequest, WecPayoutSigner, WecPipelineStage, WecSignerConfig, WCASH_REGTEST_BRANCH_ID,
    WCASH_REGTEST_GENESIS_HASH,
};

const GROSS: u64 = 1_000_000;
const FEE_RESERVE: u64 = 50_000;

#[derive(Deserialize)]
struct Manifest {
    wallet_binary: PathBuf,
    wallet_db: PathBuf,
    seed_file: PathBuf,
    lightwalletd_endpoint: String,
    node_rpc: String,
    node_cookie_file: PathBuf,
    source_account: Uuid,
    collector_commitment: String,
    recipient_address: String,
    recipient_script: String,
}

struct UnusedZec;
impl ExactExecutionSigner for UnusedZec {
    fn chain(&self) -> Chain {
        Chain::Zcash
    }
    fn prepare_exact(
        &self,
        _: &wcash_pool_portal::PayoutBatchRequest,
    ) -> BoundaryFuture<'_, RichPayoutExecution> {
        Box::pin(async { Err(BoundaryFailure::Invariant) })
    }
    fn recover_exact(
        &self,
        _: &wcash_pool_portal::PayoutBatchRequest,
    ) -> BoundaryFuture<'_, Option<RecoveredPayoutExecution>> {
        Box::pin(async { Err(BoundaryFailure::Invariant) })
    }
}
impl ExactTransactionBroadcaster for UnusedZec {
    fn chain(&self) -> Chain {
        Chain::Zcash
    }
    fn rebroadcast_exact(
        &self,
        _: &wcash_pool_store::SignedPayoutArtifact,
    ) -> BoundaryFuture<'_, ()> {
        Box::pin(async { Err(BoundaryFailure::Invariant) })
    }
}

fn policy(chain: Chain) -> ChainPolicy {
    ChainPolicy {
        chain,
        pplns_window_work: BigUint::from(1_000_000u64),
        fee_bps: 0,
        payout_threshold_zat: GROSS,
        required_confirmations: 100,
        payout_confirmations: 100,
        maximum_payout_outputs: 1,
        minimum_payout_zat: GROSS,
        maximum_payout_zat: GROSS,
        payout_skip_bps: 0,
        maximum_network_fee_zat: FEE_RESERVE,
        maximum_network_fee_bps: 1000,
        policy_version: 1,
    }
}

fn decode32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn native_signer(
    manifest: &Manifest,
    transport: &WolfWalletTransport,
    journal: &std::path::Path,
    enabled: bool,
) -> WecPayoutSigner {
    let config = WecSignerConfig::new(
        journal,
        manifest.source_account,
        decode32(&manifest.collector_commitment),
        SeedSource::protected_file(
            &manifest.seed_file,
            fs::metadata(&manifest.seed_file).unwrap().uid(),
        ),
    )
    .unwrap()
    .with_regtest_network()
    .unwrap()
    .with_transparent_payouts(enabled)
    .with_max_fee_zat(FEE_RESERVE)
    .unwrap();
    WecPayoutSigner::new(config, Arc::new(transport.clone())).unwrap()
}

fn signer(
    manifest: &Manifest,
    transport: &WolfWalletTransport,
    journal: &std::path::Path,
    enabled: bool,
) -> Arc<WecExecutionSigner> {
    Arc::new(WecExecutionSigner::new(
        Arc::new(native_signer(manifest, transport, journal, enabled)),
        manifest.source_account,
    ))
}

const CRASH_EXIT_CODE: i32 = 86;

#[derive(Deserialize, Serialize)]
struct CrashCase {
    index: usize,
    deployment_id: Uuid,
    backend_instance: Uuid,
    journal_stream: Uuid,
    batch_id: Uuid,
    journal: PathBuf,
    expected_bytes: PathBuf,
}

impl CrashCase {
    fn identity(&self, manifest: &Manifest, genesis: [u8; 32]) -> DeploymentIdentity {
        DeploymentIdentity {
            id: self.deployment_id,
            network: DeploymentNetwork::Regtest,
            wcash_genesis: genesis,
            zcash_genesis: [0x12; 32],
            chain_id: 0x5745_4301,
            wcash_payout_commitment: decode32(&manifest.collector_commitment),
            zcash_payout_commitment: [0x14; 32],
            backend_instance: self.backend_instance,
            journal_stream: self.journal_stream,
        }
    }
}

fn durable_write(path: &std::path::Path, bytes: &[u8]) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

struct ExitAfterReservation;
impl CheckpointHook for ExitAfterReservation {
    fn should_interrupt(&self, checkpoint: Checkpoint) -> bool {
        if checkpoint == Checkpoint::StagePersisted(WecPipelineStage::Reserved) {
            // No Rust destructors run. The journal's existing production fsync
            // has completed before this hook is called.
            std::process::exit(CRASH_EXIT_CODE);
        }
        false
    }
}

async fn crash_child(
    case: &CrashCase,
    manifest: &Manifest,
    database_url: &str,
    genesis: [u8; 32],
    transport: &WolfWalletTransport,
    broadcaster: &RpcExactBroadcaster,
) -> ! {
    let store = PostgresStore::connect(database_url, 2, case.identity(manifest, genesis))
        .await
        .unwrap();
    store.verify_deployment().await.unwrap();
    let request = store.signing_payout_request(case.batch_id).await.unwrap();
    if case.index == 0 {
        // SQL authorization alone is not signer admission. New public signing
        // remains blocked while the flag is disabled, before any reservation.
        let disabled = signer(manifest, transport, &case.journal, false);
        assert!(disabled.recover_exact(&request).await.unwrap().is_none());
        assert!(disabled.prepare_exact(&request).await.is_err());
    } else if case.index == 4 {
        let interrupted = native_signer(manifest, transport, &case.journal, true)
            .with_checkpoint_hook(Arc::new(ExitAfterReservation));
        let _ = interrupted.prepare(&WecPayoutRequest {
            batch: request,
            source_account: manifest.source_account,
            fund_source: WalletFundSource::Ironwood,
        });
        panic!("reserved checkpoint must terminate the child");
    } else {
        let initial = signer(manifest, transport, &case.journal, true);
        let prepared = initial.prepare_exact(&request).await.unwrap();
        durable_write(&case.expected_bytes, &prepared.signed_transaction);
        if case.index >= 2 {
            store
                .mark_payout_signed(
                    case.batch_id,
                    &prepared.unsigned_digest,
                    &prepared.transaction_id_bytes,
                    &prepared.signed_transaction,
                    prepared.network_fee_zat,
                )
                .await
                .unwrap();
        }
        if case.index == 3 {
            let artifact = store
                .authorize_payout_broadcast(case.batch_id)
                .await
                .unwrap();
            broadcaster.rebroadcast_exact(&artifact).await.unwrap();
            // Exit before acknowledging successful broadcast to SQL.
        }
    }
    std::process::exit(CRASH_EXIT_CODE)
}

async fn credit_fixture(store: &PostgresStore, pool: &sqlx::PgPool, account: Uuid, amount: u64) {
    let mut transaction = pool.begin().await.unwrap();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO ledger_transactions (deployment_id,id,chain,kind,reference) VALUES ($1,$2,'wcash','winner_matured','REGTEST ONLY: observed mined-wallet funding fixture')")
        .bind(store.deployment_id()).bind(id).execute(&mut *transaction).await.unwrap();
    sqlx::query("INSERT INTO ledger_entries (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES ($1,$2,1,NULL,'collector_spendable_asset',$3),($1,$2,2,$4,'miner_payable',-$3)")
        .bind(store.deployment_id()).bind(id).bind(i64::try_from(amount).unwrap()).bind(account)
        .execute(&mut *transaction).await.unwrap();
    sqlx::query("UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=2 WHERE deployment_id=$1 AND id=$2")
        .bind(store.deployment_id()).bind(id).execute(&mut *transaction).await.unwrap();
    transaction.commit().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated Regtest node, mined Ironwood wallet, manifest and disposable PostgreSQL"]
async fn real_node_w1_crash_boundaries_reach_confirmed_ledger() {
    let manifest_path =
        PathBuf::from(std::env::var("W1_REGTEST_MANIFEST").expect("manifest required"));
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL").unwrap();
    let mine_helper = PathBuf::from(std::env::var("W1_REGTEST_MINE_HELPER").unwrap());
    assert!(mine_helper.is_absolute());
    let program = PinnedWolfProgram::verify(
        &manifest.wallet_binary,
        Sha256::digest(fs::read(&manifest.wallet_binary).unwrap()).into(),
        fs::metadata(&manifest.wallet_binary).unwrap().uid(),
    )
    .unwrap();
    let transport = WolfWalletTransport::new(
        program,
        &manifest.wallet_db,
        &manifest.lightwalletd_endpoint,
    )
    .unwrap()
    .with_regtest_network();
    transport.probe_transparent_payout_capability().unwrap();
    let wallet_identity = transport.identity(Duration::from_secs(30), 65536).unwrap();
    assert_eq!(wallet_identity.network, WalletNetwork::Regtest);
    assert_eq!(wallet_identity.fund_source, WalletFundSource::Ironwood);
    assert_eq!(wallet_identity.account_id, manifest.source_account);
    assert_eq!(wallet_identity.branch_id, WCASH_REGTEST_BRANCH_ID);
    let mut genesis = decode32(WCASH_REGTEST_GENESIS_HASH);
    genesis.reverse();
    let observer = WcashWalletObserver::new(
        transport.clone(),
        WalletNetwork::Regtest,
        genesis,
        WCASH_REGTEST_BRANCH_ID,
        manifest.source_account,
        WalletFundSource::Ironwood,
        decode32(&manifest.collector_commitment),
        Duration::from_secs(900),
        16,
    )
    .unwrap();
    let rpc = Arc::new(
        LoopbackJsonRpc::new(
            manifest.node_rpc.parse().unwrap(),
            &manifest.node_cookie_file,
        )
        .unwrap(),
    );
    let authority = Arc::new(
        NodePayoutAuthority::new(Chain::Wcash, rpc.clone(), genesis)
            .unwrap()
            .with_regtest_network()
            .unwrap(),
    );
    authority.startup_probe().await.unwrap();
    let broadcaster = Arc::new(RpcExactBroadcaster::new(authority.clone()));
    if let Some(path) = std::env::var_os("W1_REGTEST_CRASH_CASE") {
        let case: CrashCase = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        crash_child(
            &case,
            &manifest,
            &database_url,
            genesis,
            &transport,
            &broadcaster,
        )
        .await;
    }
    let evidence = manifest_path
        .parent()
        .unwrap()
        .join(format!("lifecycle-{}", Uuid::new_v4()));
    fs::create_dir(&evidence).unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .unwrap();
    let mut cases = Vec::new();
    for (index, boundary) in [
        "before_signing",
        "after_signing",
        "after_sql_persistence",
        "after_broadcast",
        "after_signer_reservation",
    ]
    .into_iter()
    .enumerate()
    {
        let observation = observer.observe(Duration::from_secs(30), 65536).unwrap();
        assert!(observation.wallet_spendable_zat >= GROSS);
        let identity = DeploymentIdentity {
            id: Uuid::new_v4(),
            network: DeploymentNetwork::Regtest,
            wcash_genesis: genesis,
            zcash_genesis: [0x12; 32],
            chain_id: 0x5745_4301,
            wcash_payout_commitment: decode32(&manifest.collector_commitment),
            zcash_payout_commitment: [0x14; 32],
            backend_instance: Uuid::new_v4(),
            journal_stream: Uuid::new_v4(),
        };
        let store = PostgresStore::connect(&database_url, 2, identity.clone())
            .await
            .unwrap()
            .with_wcash_transparent_payouts(true);
        store.migrate().await.unwrap();
        store.bind_deployment().await.unwrap();
        store
            .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
            .await
            .unwrap();
        let account = Uuid::new_v4();
        sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'regtest_miner')")
            .bind(identity.id)
            .bind(account)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO payout_destinations (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by,validated_at,active_after,address_digest,payout_threshold_zat,automatic,state,revision) VALUES ($1,$2,$3,'wcash','regtest',$4,'transparent','real-wallet-regtest-gate',clock_timestamp(),clock_timestamp(),$5,$6,true,'active',1)")
            .bind(identity.id).bind(Uuid::new_v4()).bind(account).bind(&manifest.recipient_address)
            .bind(Sha256::digest(manifest.recipient_address.as_bytes()).as_slice())
            .bind(i64::try_from(GROSS).unwrap()).execute(&admin).await.unwrap();
        credit_fixture(&store, &admin, account, observation.wallet_spendable_zat).await;
        let reconciliation = store
            .record_wallet_reconciliation(&observation)
            .await
            .unwrap();
        let batch = store
            .create_payout_batch(Chain::Wcash, Uuid::new_v4(), reconciliation.id)
            .await
            .unwrap();
        assert_eq!(batch.outputs.len(), 1);
        assert_eq!(batch.outputs[0].amount_zat, GROSS - FEE_RESERVE);
        store.authorize_payout_signing(batch.id).await.unwrap();
        let journal = evidence.join(format!("{boundary}-journal"));
        let descriptor = evidence.join(format!("{boundary}-case.json"));
        let case = CrashCase {
            index,
            deployment_id: identity.id,
            backend_instance: identity.backend_instance,
            journal_stream: identity.journal_stream,
            batch_id: batch.id,
            journal: journal.clone(),
            expected_bytes: evidence.join(format!("{boundary}-signed.bin")),
        };
        durable_write(&descriptor, &serde_json::to_vec_pretty(&case).unwrap());
        drop(store);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("regtest_w1_lifecycle::real_node_w1_crash_boundaries_reach_confirmed_ledger")
            .arg("--ignored")
            .arg("--nocapture")
            .env("W1_REGTEST_CRASH_CASE", &descriptor)
            .status()
            .unwrap();
        assert_eq!(
            child.code(),
            Some(CRASH_EXIT_CODE),
            "child must reach {boundary} then exit without destructors"
        );
        let exact_before_restart = if (1..=3).contains(&index) {
            Some(fs::read(&case.expected_bytes).unwrap())
        } else {
            None
        };
        let restarted = PostgresStore::connect(&database_url, 2, identity)
            .await
            .unwrap();
        let reopened_signer = signer(&manifest, &transport, &journal, index == 0);
        let coordinator = SettlementOrchestrator::new(
            Arc::new(restarted.clone()),
            reopened_signer,
            broadcaster.clone(),
            Arc::new(UnusedZec),
            Arc::new(UnusedZec),
        )
        .unwrap();
        coordinator
            .recover_before_wallet_reconciliation(Chain::Wcash)
            .await
            .unwrap();
        coordinator.resume_next(Chain::Wcash).await.unwrap();
        let artifact = restarted
            .signed_payout_artifact(batch.id)
            .await
            .unwrap()
            .unwrap();
        if let Some(expected) = exact_before_restart {
            assert_eq!(artifact.signed_transaction, expected);
        }
        let txid = hex::encode(artifact.transaction_id);
        let raw = rpc
            .compact_call("getrawtransaction", json!([txid, 0]))
            .await
            .unwrap();
        assert_eq!(
            raw.as_str().unwrap(),
            hex::encode(&artifact.signed_transaction)
        );
        let decoded = rpc
            .compact_call("getrawtransaction", json!([txid, 1]))
            .await
            .unwrap();
        assert_eq!(decoded["version"], 6);
        for field in ["vin", "vjoinsplit", "vShieldedSpend", "vShieldedOutput"] {
            assert!(
                decoded[field].as_array().unwrap().is_empty(),
                "unexpected {field}"
            );
        }
        assert!(decoded["orchard"]["actions"].as_array().unwrap().is_empty());
        assert!(!decoded["ironwood"]["actions"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(decoded["ironwood"]["flags"]["enableSpends"], true);
        assert_eq!(decoded["ironwood"]["flags"]["enableOutputs"], true);
        assert_eq!(
            decoded["ironwood"]["valueBalanceZat"].as_u64().unwrap(),
            batch.payout_total_zat + artifact.network_fee_zat
        );
        durable_write(
            &evidence.join(format!("{boundary}-node-transaction.json")),
            &serde_json::to_vec_pretty(&decoded).unwrap(),
        );
        let outputs = decoded["vout"].as_array().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["scriptPubKey"]["hex"], manifest.recipient_script);
        assert_eq!(
            outputs[0]["valueZat"].as_u64().unwrap(),
            GROSS - FEE_RESERVE
        );
        println!(
            "W1_REGTEST_BROADCAST {}",
            json!({"boundary":boundary,"batch_id":batch.id,"txid":txid,"amount_zat":GROSS-FEE_RESERVE,"fee_zat":artifact.network_fee_zat})
        );
        cases.push((
            boundary,
            restarted,
            account,
            batch,
            artifact,
            observation.wallet_spendable_zat,
        ));
    }
    // A synchronous helper mines real blocks only on the provisioned Regtest
    // node. It receives no wallet seed or transaction-construction authority.
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(mine_helper).arg("100").status()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(status.success());
    let mut results = Vec::new();
    for (boundary, store, account, batch, artifact, initial_balance) in cases {
        let watches = store.list_payout_watches(Chain::Wcash, 10).await.unwrap();
        let snapshot = authority.snapshot(&watches.watches).await.unwrap();
        let AuthorityPayoutState::Mined(confirmation) = &snapshot.payouts[0].state else {
            panic!("real payout must be mined");
        };
        assert!(confirmation.confirmations >= 100);
        store.confirm_payout(batch.id, confirmation).await.unwrap();
        let balances = PortalRepository::balances(&store, account).await.unwrap();
        let balance = balances
            .iter()
            .find(|balance| balance.asset == Asset::Wec)
            .unwrap();
        assert_eq!(balance.pending_zat, 0);
        assert_eq!(
            balance.payable_zat,
            initial_balance - batch.payout_total_zat - artifact.network_fee_zat
        );
        let history = PortalRepository::payout_history(
            &store,
            account,
            PageRequest {
                before: None,
                limit: 10,
            },
        )
        .await
        .unwrap();
        let payout = &history.items[0];
        assert_eq!(payout.state, "confirmed");
        assert_eq!(
            payout.actual_network_fee_zat,
            Some(artifact.network_fee_zat)
        );
        assert_eq!(payout.amount_zat, GROSS - FEE_RESERVE);
        let ledger = sqlx::query("SELECT e.ledger_account,SUM(e.amount_zat)::BIGINT AS balance FROM ledger_entries e JOIN ledger_transactions t ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) WHERE e.deployment_id=$1 AND t.chain='wcash' GROUP BY e.ledger_account")
            .bind(store.deployment_id()).fetch_all(&admin).await.unwrap();
        assert_eq!(
            ledger
                .iter()
                .map(|row| row.get::<i64, _>("balance"))
                .sum::<i64>(),
            0
        );
        let collector: i64 = ledger
            .iter()
            .find(|row| row.get::<String, _>("ledger_account") == "collector_spendable_asset")
            .unwrap()
            .get("balance");
        assert_eq!(u64::try_from(collector).unwrap(), balance.payable_zat);
        results.push(json!({"boundary":boundary,"deployment_id":store.deployment_id(),"batch_id":batch.id,
            "txid":hex::encode(artifact.transaction_id),"block_hash_wire":hex::encode(confirmation.block_hash),
            "block_height":confirmation.block_height,"confirmations":confirmation.confirmations,
            "script":manifest.recipient_script,"amount_zat":GROSS-FEE_RESERVE,"fee_zat":artifact.network_fee_zat,
            "remaining_payable_zat":balance.payable_zat,"ledger_conserved":true,
            "process_boundary":"child process exit without Rust destructors; parent reopened resources",
            "ironwood_only_inputs_and_change":true}));
    }
    fs::write(
        evidence.join("results.json"),
        serde_json::to_vec_pretty(&results).unwrap(),
    )
    .unwrap();
    println!("W1_REGTEST_EVIDENCE {}", evidence.display());
}

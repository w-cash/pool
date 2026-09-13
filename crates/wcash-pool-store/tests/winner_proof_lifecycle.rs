//! Real PostgreSQL regression for multiple AuxPoW proofs of one economic winner.
//! Set WCASH_POOL_TEST_DATABASE_URL to an isolated disposable database; this test
//! recreates only that database's public schema.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use num_bigint::BigUint;
use sqlx::{postgres::PgPoolOptions, Row};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use uuid::Uuid;
use wcash_pool_backend_client::{
    BackendAuthority, BackendClient, BackendClientConfig, ExpectedBackend,
};
use wcash_pool_protocol::{
    canonical_attribution_id, decode_backend_request, encode_backend_message, BackendEvent,
    BackendMessage, BackendRequest, CanonicalUuid, ChainTip, Hex108, Hex32, JobDescriptor,
    MergedChain, ShareReceipt, TargetBe, TargetLe, WinnerDescriptor, WorkerIdentity,
    BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, REQUIRED_BACKEND_CAPABILITIES,
};
use wcash_pool_store::{
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PostgresStore, ProjectionResult,
    StoreError,
};

fn identity(seed: u8) -> DeploymentIdentity {
    DeploymentIdentity {
        id: Uuid::new_v4(),
        network: DeploymentNetwork::Testnet,
        wcash_genesis: [seed; 32],
        zcash_genesis: [seed.wrapping_add(1); 32],
        chain_id: u32::from(seed) + 1,
        wcash_payout_commitment: [seed.wrapping_add(2); 32],
        zcash_payout_commitment: [seed.wrapping_add(3); 32],
        backend_instance: Uuid::new_v4(),
        journal_stream: Uuid::new_v4(),
    }
}

fn policy(chain: Chain) -> ChainPolicy {
    ChainPolicy {
        chain,
        pplns_window_work: BigUint::from(1_000_000u64),
        fee_bps: 0,
        payout_threshold_zat: 1,
        required_confirmations: 100,
        maximum_payout_outputs: 1,
        maximum_network_fee_zat: 1_000_000,
        maximum_network_fee_bps: 1_000,
        policy_version: 1,
    }
}

fn job() -> JobDescriptor {
    let mut header = [0x21; 108];
    header[..4].copy_from_slice(&4u32.to_le_bytes());
    header[4..36].copy_from_slice(&[0x22; 32]);
    header[100..104].copy_from_slice(&1_725_000_000u32.to_le_bytes());
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
        wcash_reward_zat: 625_000_000,
        zcash_reward_zat: 312_500_000,
        wcash_maturity_confirmations: 100,
        zcash_maturity_confirmations: 100,
        max_age_ms: 45_000,
    }
}

fn winner(chain: MergedChain) -> WinnerDescriptor {
    let descriptor = job();
    match chain {
        MergedChain::Wcash => WinnerDescriptor {
            chain,
            block_hash_le: descriptor.wcash_candidate_hash_le,
            height: descriptor.wcash_height,
            coinbase_txid_le: descriptor.wcash_coinbase_txid_le,
            reward_zat: descriptor.wcash_reward_zat,
            maturity_confirmations: descriptor.wcash_maturity_confirmations,
        },
        MergedChain::Zcash => WinnerDescriptor {
            chain,
            block_hash_le: Hex32::new([0x72; 32]),
            height: descriptor.zcash_height,
            coinbase_txid_le: descriptor.zcash_coinbase_txid_le,
            reward_zat: descriptor.zcash_reward_zat,
            maturity_confirmations: descriptor.zcash_maturity_confirmations,
        },
    }
}

async fn read_backend_request(stream: &mut UnixStream) -> BackendRequest {
    let mut prefix = [0u8; BACKEND_LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut prefix)
        .await
        .expect("request prefix reads");
    let mut payload = vec![0u8; u32::from_be_bytes(prefix) as usize];
    stream
        .read_exact(&mut payload)
        .await
        .expect("request body reads");
    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&payload);
    decode_backend_request(&frame).expect("backend request validates")
}

async fn authority_for(
    identity: &DeploymentIdentity,
) -> wcash_pool_backend_client::BackendAuthority {
    let socket_path = std::env::temp_dir().join(format!("wcp-store-{}.sock", Uuid::new_v4()));
    let listener = UnixListener::bind(&socket_path).expect("test Unix socket binds");
    let server_identity = identity.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("client connects");
        let BackendRequest::Hello { id, .. } = read_backend_request(&mut stream).await else {
            panic!("first request must be hello");
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
            share_target_ceiling_be: TargetBe::new([0x55; 32]),
            chain_id: server_identity.chain_id,
            current_event_seq: 0,
        };
        stream
            .write_all(&encode_backend_message(&hello).expect("hello encodes"))
            .await
            .expect("hello writes");
        let BackendRequest::SubscribeJobs { id, .. } = read_backend_request(&mut stream).await
        else {
            panic!("second request must subscribe");
        };
        let snapshot = BackendMessage::JobSnapshot {
            version: BACKEND_PROTOCOL_VERSION,
            id,
            event_seq: 0,
            current: None,
            recent: Vec::new(),
        };
        stream
            .write_all(&encode_backend_message(&snapshot).expect("snapshot encodes"))
            .await
            .expect("snapshot writes");
    });
    let expected = ExpectedBackend::new(
        Hex32::new(identity.wcash_genesis),
        Hex32::new(identity.zcash_genesis),
        identity.chain_id,
        Hex32::new(identity.wcash_payout_commitment),
        Hex32::new(identity.zcash_payout_commitment),
        TargetBe::new([0x55; 32]),
    )
    .expect("expected backend is valid")
    .with_backend_instance(CanonicalUuid::new(identity.backend_instance))
    .with_journal_stream(CanonicalUuid::new(identity.journal_stream));
    let config = BackendClientConfig::new(&socket_path, expected).expect("client config validates");
    let mut client = BackendClient::connect(config, CanonicalUuid::new(Uuid::new_v4()), 0)
        .await
        .expect("hello authenticates exact authority");
    let snapshot = client.subscribe_jobs(0).await.expect("snapshot binds");
    let authority = snapshot.authority().clone();
    server.await.expect("server task completes");
    std::fs::remove_file(socket_path).expect("test socket removes");
    authority
}

#[derive(Clone)]
struct Proof {
    share: Hex32,
    job: JobDescriptor,
    worker: WorkerIdentity,
}

impl Proof {
    fn new(marker: u8, descriptor: &JobDescriptor) -> Self {
        Self {
            share: Hex32::new([marker; 32]),
            job: descriptor.clone(),
            worker: WorkerIdentity {
                account_id: CanonicalUuid::new(Uuid::new_v4()),
                worker_id: CanonicalUuid::new(Uuid::new_v4()),
                label: format!("alias{marker}.worker"),
            },
        }
    }

    fn committed(&self, seq: u64, winners: Vec<WinnerDescriptor>) -> BackendEvent {
        let target = TargetLe::new([0x7f; 32]);
        BackendEvent::ShareCommitted {
            receipt: ShareReceipt {
                event_seq: seq,
                job_id: self.job.job_id.clone(),
                share_id: self.share.clone(),
                attribution_id: canonical_attribution_id(&self.worker, &target).unwrap(),
                parent_hash_le: Hex32::new([self.share.as_bytes()[0].wrapping_add(1); 32]),
                winners,
            },
            job_id: self.job.job_id.clone(),
            identity: self.worker.clone(),
            target_le: target,
        }
    }

    fn positive(&self, seq: u64, depth: u32, mature: bool) -> BackendEvent {
        let winner = winner(MergedChain::Wcash);
        let tip = ChainTip {
            block_hash_le: if depth == 1 {
                winner.block_hash_le.clone()
            } else {
                Hex32::new([0xe1; 32])
            },
            height: winner.height + depth - 1,
        };
        if mature {
            BackendEvent::WinnerMatured {
                event_seq: seq,
                share_id: self.share.clone(),
                job_id: self.job.job_id.clone(),
                winner,
                tip,
                confirmations: depth,
            }
        } else {
            BackendEvent::WinnerObserved {
                event_seq: seq,
                share_id: self.share.clone(),
                job_id: self.job.job_id.clone(),
                winner,
                tip,
                confirmations: depth,
            }
        }
    }

    fn negative(&self, seq: u64, orphan: bool) -> BackendEvent {
        let winner = winner(MergedChain::Wcash);
        if orphan {
            BackendEvent::WinnerOrphaned {
                event_seq: seq,
                share_id: self.share.clone(),
                job_id: self.job.job_id.clone(),
                tip: ChainTip {
                    block_hash_le: Hex32::new([0xe2; 32]),
                    height: winner.height + 100,
                },
                winner,
            }
        } else {
            BackendEvent::WinnerQuarantined {
                event_seq: seq,
                share_id: self.share.clone(),
                job_id: self.job.job_id.clone(),
                tip: ChainTip {
                    block_hash_le: winner.block_hash_le.clone(),
                    height: winner.height,
                },
                winner,
            }
        }
    }
}

struct Fixture {
    store: PostgresStore,
    pool: sqlx::PgPool,
    authority: BackendAuthority,
    next: u64,
    original: Proof,
}

const BEFORE_PROOF_MIGRATIONS: [&str; 11] = [
    include_str!("../migrations/0001_runtime_accounting.sql"),
    include_str!("../migrations/0002_portal_read_models.sql"),
    include_str!("../migrations/0003_global_nonce_fencing.sql"),
    include_str!("../migrations/0004_portal_miner_views.sql"),
    include_str!("../migrations/0005_security_hardening.sql"),
    include_str!("../migrations/0006_public_runtime_boundaries.sql"),
    include_str!("../migrations/0007_payout_watch_rotation.sql"),
    include_str!("../migrations/0008_winner_maturity_regression.sql"),
    include_str!("../migrations/0009_payout_external_effect_fences.sql"),
    include_str!("../migrations/0010_miner_funded_network_fees.sql"),
    include_str!("../migrations/0011_isolated_regtest_network.sql"),
];

async fn migration_snapshot(pool: &sqlx::PgPool) -> serde_json::Value {
    sqlx::query_scalar("SELECT jsonb_build_object( \
        'winners',(SELECT jsonb_agg(to_jsonb(w)-'active_proof_share_id' ORDER BY w.block_hash_le) FROM winners w), \
        'allocations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.block_hash_le) FROM winner_allocations a), \
        'transactions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM ledger_transactions t), \
        'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.transaction_id,e.line_no) FROM ledger_entries e))")
        .fetch_one(pool).await.unwrap()
}

async fn assert_existing_schema_upgrade(pool: &sqlx::PgPool, database_url: &str) {
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(pool)
        .await
        .unwrap();
    for migration in BEFORE_PROOF_MIGRATIONS {
        sqlx::raw_sql(migration).execute(pool).await.unwrap();
    }
    let deployment = identity(51);
    let store = PostgresStore::connect(database_url, 1, deployment.clone())
        .await
        .unwrap();
    store.bind_deployment().await.unwrap();
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .unwrap();
    let worker = Proof::new(0x90, &job()).worker;
    sqlx::query("SELECT public.ensure_projected_worker_v1($1,$2,$3,$4)")
        .bind(deployment.id)
        .bind(worker.account_id.get())
        .bind(worker.worker_id.get())
        .bind(&worker.label)
        .execute(pool)
        .await
        .unwrap();

    for (index, state) in [
        "submitted",
        "observed",
        "matured",
        "quarantined",
        "requeued",
        "orphaned",
    ]
    .into_iter()
    .enumerate()
    {
        let marker = u8::try_from(index + 1).unwrap();
        let base = i64::from(marker) * 10;
        let mut descriptor = job();
        descriptor.job_id = Hex32::new([marker; 32]);
        descriptor.wcash_candidate_hash_le = Hex32::new([marker + 10; 32]);
        descriptor.wcash_coinbase_txid_le = Hex32::new([marker + 20; 32]);
        descriptor.wcash_reward_zat = 100;
        let share = [marker + 30; 32];
        let mut transaction = pool.begin().await.unwrap();
        for (offset, kind) in [
            (1, "job_activated"),
            (2, "share_committed"),
            (3, "winner_observed"),
            (4, "winner_matured"),
        ] {
            sqlx::query("INSERT INTO backend_events (deployment_id,event_seq,event_kind,payload,payload_sha256) VALUES ($1,$2,$3,'{}',$4)")
                .bind(deployment.id).bind(base + offset).bind(kind).bind([marker + 40; 32].as_slice())
                .execute(&mut *transaction).await.unwrap();
        }
        sqlx::query("INSERT INTO jobs (deployment_id,job_id,activation_event_seq,descriptor) VALUES ($1,$2,$3,$4)")
            .bind(deployment.id).bind(descriptor.job_id.as_bytes().as_slice()).bind(base + 1)
            .bind(serde_json::to_value(&descriptor).unwrap()).execute(&mut *transaction).await.unwrap();
        sqlx::query("INSERT INTO shares (deployment_id,share_id,event_seq,job_id,account_id,worker_id,target_le,work,parent_hash_le) VALUES ($1,$2,$3,$4,$5,$6,$7,2,$8)")
            .bind(deployment.id).bind(share.as_slice()).bind(base + 2).bind(descriptor.job_id.as_bytes().as_slice())
            .bind(worker.account_id.get()).bind(worker.worker_id.get()).bind([0x7f_u8; 32].as_slice())
            .bind([marker + 50; 32].as_slice()).execute(&mut *transaction).await.unwrap();
        let positive = matches!(state, "observed" | "matured");
        sqlx::query("INSERT INTO winners (deployment_id,chain,block_hash_le,share_id,job_id,height,coinbase_txid_le,reward_zat,maturity_confirmations,state,active_observation_event_seq,active_maturity_event_seq) VALUES ($1,'wcash',$2,$3,$4,11,$5,100,100,$6,$7,$8)")
            .bind(deployment.id).bind(descriptor.wcash_candidate_hash_le.as_bytes().as_slice()).bind(share.as_slice())
            .bind(descriptor.job_id.as_bytes().as_slice()).bind(descriptor.wcash_coinbase_txid_le.as_bytes().as_slice())
            .bind(state).bind(positive.then_some(base + 3)).bind((state == "matured").then_some(base + 4))
            .execute(&mut *transaction).await.unwrap();
        if positive {
            sqlx::query("INSERT INTO winner_allocations (deployment_id,chain,block_hash_le,observation_event_seq,policy_version,account_id,selected_work,amount_zat) VALUES ($1,'wcash',$2,$3,1,$4,2,100)")
                .bind(deployment.id).bind(descriptor.wcash_candidate_hash_le.as_bytes().as_slice()).bind(base + 3)
                .bind(worker.account_id.get()).execute(&mut *transaction).await.unwrap();
            for (kind, event, entries) in [
                (
                    "winner_observed",
                    base + 3,
                    vec![
                        (None, "collector_immature_asset", 100_i64),
                        (Some(worker.account_id.get()), "miner_immature", -100),
                    ],
                ),
                (
                    "winner_matured",
                    base + 4,
                    vec![
                        (None, "collector_immature_asset", -100),
                        (None, "collector_spendable_asset", 100),
                        (Some(worker.account_id.get()), "miner_immature", 100),
                        (Some(worker.account_id.get()), "miner_payable", -100),
                    ],
                ),
            ] {
                if kind == "winner_matured" && state != "matured" {
                    continue;
                }
                let id = Uuid::new_v4();
                sqlx::query("INSERT INTO ledger_transactions (deployment_id,id,chain,kind,backend_event_seq,reference) VALUES ($1,$2,'wcash',$3,$4,$5)")
                    .bind(deployment.id).bind(id).bind(kind).bind(event).bind(format!("wcash:{}", descriptor.wcash_candidate_hash_le))
                    .execute(&mut *transaction).await.unwrap();
                for (line, (account, name, amount)) in entries.iter().enumerate() {
                    sqlx::query("INSERT INTO ledger_entries (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES ($1,$2,$3,$4,$5,$6)")
                        .bind(deployment.id).bind(id).bind(i32::try_from(line + 1).unwrap()).bind(account).bind(name).bind(amount)
                        .execute(&mut *transaction).await.unwrap();
                }
                sqlx::query("UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=$3 WHERE deployment_id=$1 AND id=$2")
                    .bind(deployment.id).bind(id).bind(i32::try_from(entries.len()).unwrap()).execute(&mut *transaction).await.unwrap();
            }
        }
        transaction.commit().await.unwrap();
    }
    let before = migration_snapshot(pool).await;
    // A projector already holding the cursor must finish before migration can
    // read/backfill any winners. Check the real lock waiter, not elapsed sleep.
    let mut old_projector = pool.begin().await.unwrap();
    sqlx::query("SELECT last_event_seq FROM backend_cursors WHERE deployment_id=$1 FOR UPDATE")
        .bind(deployment.id)
        .fetch_one(&mut *old_projector)
        .await
        .unwrap();
    let migration_pool = pool.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let upgrade = async move {
        let mut transaction = migration_pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        sender.send(pid).unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/0012_winner_proof_lifecycle.sql"
        ))
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    };
    let release_old_projector = async {
        let pid = receiver.await.unwrap();
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.backend_cursors'::regclass AND mode='AccessExclusiveLock' AND NOT granted)")
                .bind(pid).fetch_one(pool).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let absent: bool = sqlx::query_scalar("SELECT to_regclass('public.winner_proofs') IS NULL")
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(
            absent,
            "no partial proof schema is visible while the old writer holds its cursor"
        );
        old_projector.commit().await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(upgrade, release_old_projector)
    })
    .await
    .expect("old projector and atomic migration complete without deadlock");
    assert_eq!(migration_snapshot(pool).await, before, "all old winner facts, active ledger pointers, allocations and sealed accounting survive unchanged");
    let proofs = sqlx::query("SELECT w.state,w.share_id,w.job_id,w.active_proof_share_id,p.state AS proof_state,p.share_id AS proof_share,p.job_id AS proof_job FROM winners w JOIN winner_proofs p USING(deployment_id,chain,block_hash_le) ORDER BY w.block_hash_le")
        .fetch_all(pool).await.unwrap();
    assert_eq!(proofs.len(), 6);
    for row in proofs {
        let state: String = row.get("state");
        let share: Vec<u8> = row.get("share_id");
        assert_eq!(row.get::<String, _>("proof_state"), state);
        assert_eq!(row.get::<Vec<u8>, _>("proof_share"), share);
        assert_eq!(
            row.get::<Vec<u8>, _>("proof_job"),
            row.get::<Vec<u8>, _>("job_id")
        );
        assert_eq!(
            row.get::<Option<Vec<u8>>, _>("active_proof_share_id"),
            matches!(state.as_str(), "observed" | "matured").then_some(share)
        );
    }
}

impl Fixture {
    async fn apply(&mut self, event: BackendEvent) {
        assert_eq!(event.event_seq(), self.next);
        let projector = self.store.event_projector();
        assert_eq!(
            projector
                .project_event(&self.authority, &event)
                .await
                .expect("valid exact-proof event projects"),
            ProjectionResult::Applied
        );
        assert_eq!(
            projector
                .project_event(&self.authority, &event)
                .await
                .expect("same event replay is idempotent"),
            ProjectionResult::Replayed
        );
        self.next += 1;
    }

    async fn reject(&self, event: BackendEvent) -> StoreError {
        assert_eq!(event.event_seq(), self.next);
        let error = self
            .store
            .event_projector()
            .project_event(&self.authority, &event)
            .await
            .expect_err("invalid proof evidence must not advance accounting");
        let cursor: i64 =
            sqlx::query_scalar("SELECT last_event_seq FROM backend_cursors WHERE deployment_id=$1")
                .bind(self.store.deployment_id())
                .fetch_one(&self.pool)
                .await
                .unwrap();
        assert_eq!(cursor, i64::try_from(self.next - 1).unwrap());
        let absent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM backend_events WHERE deployment_id=$1 AND event_seq=$2",
        )
        .bind(self.store.deployment_id())
        .bind(i64::try_from(self.next).unwrap())
        .fetch_one(&self.pool)
        .await
        .unwrap();
        assert_eq!(absent, 0, "rejected event rolls back its journal insertion");
        error
    }

    async fn ledger_count(&self, kind: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM ledger_transactions WHERE deployment_id=$1 AND kind=$2",
        )
        .bind(self.store.deployment_id())
        .bind(kind)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn assert_economics(
        &self,
        state: &str,
        active: Option<&Proof>,
        immature: i64,
        payable: i64,
    ) {
        let rows = sqlx::query("SELECT state,share_id,job_id,active_proof_share_id FROM winners WHERE deployment_id=$1 AND chain='wcash'")
            .bind(self.store.deployment_id()).fetch_all(&self.pool).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "one proof-independent candidate is one economic winner"
        );
        let row = &rows[0];
        assert_eq!(row.get::<String, _>("state"), state);
        assert_eq!(
            row.get::<Vec<u8>, _>("share_id"),
            self.original.share.as_bytes()
        );
        assert_eq!(
            row.get::<Vec<u8>, _>("job_id"),
            self.original.job.job_id.as_bytes()
        );
        assert_eq!(
            row.get::<Option<Vec<u8>>, _>("active_proof_share_id"),
            active.map(|proof| proof.share.as_bytes().to_vec())
        );

        let balances = sqlx::query("SELECT ledger_account,COALESCE(SUM(amount_zat),0)::BIGINT AS balance FROM ledger_entries WHERE deployment_id=$1 AND account_id=$2 GROUP BY ledger_account")
            .bind(self.store.deployment_id()).bind(self.original.worker.account_id.get()).fetch_all(&self.pool).await.unwrap();
        for (account, expected) in [("miner_immature", immature), ("miner_payable", payable)] {
            let balance = balances
                .iter()
                .find(|row| row.get::<String, _>("ledger_account") == account)
                .map_or(0, |row| row.get::<i64, _>("balance"));
            assert_eq!(
                balance, expected,
                "exact original miner liability for {account}"
            );
        }
        let other_credit: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(ABS(amount_zat)),0)::BIGINT FROM ledger_entries WHERE deployment_id=$1 AND account_id IS NOT NULL AND account_id<>$2")
            .bind(self.store.deployment_id()).bind(self.original.worker.account_id.get()).fetch_one(&self.pool).await.unwrap();
        assert_eq!(
            other_credit, 0,
            "later proof aliases never move the original PPLNS cutoff"
        );
        let allocations = sqlx::query("SELECT observation_event_seq,account_id,amount_zat,selected_work::TEXT AS work FROM winner_allocations WHERE deployment_id=$1 ORDER BY observation_event_seq")
            .bind(self.store.deployment_id()).fetch_all(&self.pool).await.unwrap();
        for allocation in allocations {
            assert_eq!(
                allocation.get::<Uuid, _>("account_id"),
                self.original.worker.account_id.get()
            );
            assert_eq!(
                allocation.get::<i64, _>("amount_zat"),
                i64::try_from(winner(MergedChain::Wcash).reward_zat).unwrap()
            );
            assert_eq!(allocation.get::<String, _>("work"), "2");
        }
        let unbalanced: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT transaction_id FROM ledger_entries WHERE deployment_id=$1 GROUP BY transaction_id HAVING SUM(amount_zat)<>0) invalid")
            .bind(self.store.deployment_id()).fetch_one(&self.pool).await.unwrap();
        assert_eq!(
            unbalanced, 0,
            "every original, restoration and reversal entry conserves value"
        );
    }
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL service in required CI"]
async fn exact_auxpow_proofs_share_one_reward_and_preserve_original_allocations() {
    let database_url =
        std::env::var("WCASH_POOL_TEST_DATABASE_URL").expect("disposable database required");
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .unwrap();
    assert_existing_schema_upgrade(&pool, &database_url).await;
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&pool)
        .await
        .unwrap();
    let identity = identity(81);
    let store = PostgresStore::connect(&database_url, 2, identity.clone())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store.bind_deployment().await.unwrap();
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .unwrap();
    let authority = authority_for(&identity).await;
    let descriptor = job();
    let a = Proof::new(0x81, &descriptor);
    let b = Proof::new(0x82, &descriptor);
    let ordinary = Proof::new(0x83, &descriptor);
    let win = winner(MergedChain::Wcash);
    let reward = i64::try_from(win.reward_zat).unwrap();
    let mut f = Fixture {
        store,
        pool,
        authority,
        next: 1,
        original: a.clone(),
    };
    f.apply(BackendEvent::JobActivated {
        event_seq: f.next,
        job: descriptor.clone(),
    })
    .await;
    f.apply(a.committed(f.next, vec![win.clone()])).await;
    f.apply(a.positive(f.next, 1, false)).await;
    f.assert_economics("observed", Some(&a), -reward, 0).await;
    f.apply(b.committed(f.next, vec![win.clone()])).await;
    assert_eq!(f.ledger_count("winner_observed").await, 1);
    f.assert_economics("observed", Some(&a), -reward, 0).await;
    f.reject(b.positive(f.next, 100, true)).await;
    f.reject(b.negative(f.next, true)).await;

    f.apply(b.negative(f.next, false)).await;
    f.assert_economics("observed", Some(&a), -reward, 0).await;
    assert_eq!(
        f.ledger_count("winner_quarantined").await,
        0,
        "unselected alias quarantine cannot reverse canonical credit"
    );
    f.apply(b.positive(f.next, 1, false)).await;
    f.assert_economics("observed", Some(&b), -reward, 0).await;
    f.apply(b.positive(f.next, 100, true)).await;
    f.assert_economics("matured", Some(&b), 0, -reward).await;
    f.reject(b.positive(f.next, 100, true)).await;
    f.reject(a.positive(f.next, 99, true)).await;
    f.apply(a.positive(f.next, 100, true)).await;
    assert_eq!(
        f.ledger_count("winner_matured").await,
        1,
        "second proof maturity cannot add another economic reward"
    );
    f.assert_economics("matured", Some(&a), 0, -reward).await;

    f.apply(a.negative(f.next, false)).await;
    f.assert_economics("quarantined", None, 0, 0).await;
    f.reject(b.positive(f.next, 100, false)).await;
    f.apply(b.positive(f.next, 50, false)).await;
    f.assert_economics("observed", Some(&b), -reward, 0).await;
    f.apply(b.positive(f.next, 100, true)).await;
    f.assert_economics("matured", Some(&b), 0, -reward).await;
    f.apply(b.positive(f.next, 50, false)).await;
    f.assert_economics("observed", Some(&b), -reward, 0).await;
    assert_eq!(f.ledger_count("winner_dematured").await, 1);
    f.apply(b.positive(f.next, 100, true)).await;
    f.assert_economics("matured", Some(&b), 0, -reward).await;

    // A fresh alternate proof can observe an already mature economic block.
    // Its later global orphan fact overrides B's cached mature state.
    f.apply(a.positive(f.next, 100, false)).await;
    f.apply(a.negative(f.next, true)).await;
    f.assert_economics("orphaned", None, 0, 0).await;
    f.apply(b.positive(f.next, 50, false)).await;
    f.apply(a.positive(f.next, 1, false)).await;
    f.apply(a.negative(f.next, true)).await;
    f.assert_economics("orphaned", None, 0, 0).await;
    let restored_at = f.next;
    f.apply(b.positive(f.next, 100, true)).await;
    f.assert_economics("matured", Some(&b), 0, -reward).await;
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM ledger_transactions WHERE deployment_id=$1 AND backend_event_seq=$2 ORDER BY kind")
        .bind(f.store.deployment_id()).bind(i64::try_from(restored_at).unwrap()).fetch_all(&f.pool).await.unwrap();
    assert_eq!(
        kinds,
        ["winner_matured", "winner_observed"],
        "one fresh maturity event atomically restores and matures the one reward"
    );
    let dematures = f.ledger_count("winner_dematured").await;
    f.apply(b.positive(f.next, 50, false)).await;
    f.assert_economics("observed", Some(&b), -reward, 0).await;
    assert_eq!(f.ledger_count("winner_dematured").await, dematures + 1);
    let orphans = f.ledger_count("winner_orphaned").await;
    f.apply(b.negative(f.next, true)).await;
    f.assert_economics("orphaned", None, 0, 0).await;
    assert_eq!(f.ledger_count("winner_orphaned").await, orphans + 1);
    f.reject(b.negative(f.next, true)).await;

    // An ordinary committed share is not a proof, even with matching job facts.
    f.apply(ordinary.committed(f.next, vec![])).await;
    assert!(matches!(
        f.reject(ordinary.positive(f.next, 1, false)).await,
        StoreError::UnknownWinner
    ));
    let mut wrong_job = a.clone();
    wrong_job.job.job_id = Hex32::new([0xf1; 32]);
    assert!(matches!(
        f.reject(wrong_job.positive(f.next, 1, false)).await,
        StoreError::WinnerFactConflict
    ));
    let mut wrong_facts = a.positive(f.next, 1, false);
    if let BackendEvent::WinnerObserved { winner, .. } = &mut wrong_facts {
        winner.reward_zat += 1;
    }
    assert!(matches!(
        f.reject(wrong_facts).await,
        StoreError::WinnerFactConflict
    ));

    // A self-consistent receipt from another job still cannot change a retained
    // candidate's economic facts. This reaches the store's alias identity gate,
    // instead of merely failing receipt-vs-job validation first.
    let mut conflicting_job = descriptor.clone();
    conflicting_job.job_id = Hex32::new([0xf3; 32]);
    conflicting_job.wcash_reward_zat += 1;
    f.apply(BackendEvent::JobActivated {
        event_seq: f.next,
        job: conflicting_job.clone(),
    })
    .await;
    let conflicting_proof = Proof::new(0x85, &conflicting_job);
    let mut conflicting_winner = win.clone();
    conflicting_winner.reward_zat += 1;
    assert!(matches!(
        f.reject(conflicting_proof.committed(f.next, vec![conflicting_winner]))
            .await,
        StoreError::WinnerFactConflict
    ));

    // Another generation may legitimately retain the identical Wcash candidate.
    let mut next_job = descriptor.clone();
    next_job.job_id = Hex32::new([0xf2; 32]);
    f.apply(BackendEvent::JobActivated {
        event_seq: f.next,
        job: next_job.clone(),
    })
    .await;
    let c = Proof::new(0x84, &next_job);
    let mut mismatched = win.clone();
    mismatched.reward_zat += 1;
    f.reject(c.committed(f.next, vec![mismatched])).await;
    f.apply(c.committed(f.next, vec![win])).await;
    f.apply(c.positive(f.next, 1, false)).await;
    f.assert_economics("observed", Some(&c), -reward, 0).await;
    let proofs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM winner_proofs WHERE deployment_id=$1")
            .bind(f.store.deployment_id())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        proofs, 3,
        "only the three committed winning receipts create proof aliases"
    );

    // A positively classified Zcash side-chain block is retained without
    // inventing canonical observation or credit. It can be observed later.
    let zcash = winner(MergedChain::Zcash);
    let z = Proof::new(0x71, &next_job); // parent hash 0x72 matches this ZEC winner.
    f.apply(z.committed(f.next, vec![zcash.clone()])).await;
    let side_chain = |seq| BackendEvent::WinnerSideChain {
        event_seq: seq,
        share_id: z.share.clone(),
        job_id: z.job.job_id.clone(),
        winner: zcash.clone(),
        tip: ChainTip {
            block_hash_le: Hex32::new([0xda; 32]),
            height: zcash.height + 1,
        },
    };
    f.apply(side_chain(f.next)).await;
    assert!(matches!(
        f.reject(side_chain(f.next)).await,
        StoreError::InvalidWinnerTransition
    ));
    let premature = BackendEvent::WinnerMatured {
        event_seq: f.next,
        share_id: z.share.clone(),
        job_id: z.job.job_id.clone(),
        winner: zcash.clone(),
        tip: ChainTip {
            block_hash_le: Hex32::new([0xdb; 32]),
            height: zcash.height + 99,
        },
        confirmations: 100,
    };
    assert!(matches!(
        f.reject(premature).await,
        StoreError::InvalidWinnerTransition
    ));
    f.store = PostgresStore::connect(&database_url, 2, identity)
        .await
        .unwrap();
    f.store.verify_deployment().await.unwrap();
    let side = sqlx::query("SELECT w.state,p.state AS proof_state,w.active_proof_share_id,w.active_observation_event_seq,w.active_maturity_event_seq FROM winners w JOIN winner_proofs p USING(deployment_id,chain,block_hash_le) WHERE w.deployment_id=$1 AND w.chain='zcash'")
        .bind(f.store.deployment_id()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(side.get::<String, _>("state"), "side_chain");
    assert_eq!(side.get::<String, _>("proof_state"), "side_chain");
    assert!(side
        .get::<Option<Vec<u8>>, _>("active_proof_share_id")
        .is_none());
    assert!(side
        .get::<Option<i64>, _>("active_observation_event_seq")
        .is_none());
    assert!(side
        .get::<Option<i64>, _>("active_maturity_event_seq")
        .is_none());
    for table in ["ledger_transactions", "winner_allocations"] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE deployment_id=$1 AND chain='zcash'"
        ))
        .bind(f.store.deployment_id())
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            count, 0,
            "retained side-chain state has no economic entry in {table}"
        );
    }
    f.apply(BackendEvent::WinnerObserved {
        event_seq: f.next,
        share_id: z.share.clone(),
        job_id: z.job.job_id.clone(),
        winner: zcash.clone(),
        tip: ChainTip {
            block_hash_le: zcash.block_hash_le.clone(),
            height: zcash.height,
        },
        confirmations: 1,
    })
    .await;
    let credit = sqlx::query("SELECT COUNT(DISTINCT t.id)::BIGINT AS entries,COALESCE(SUM(e.amount_zat) FILTER (WHERE e.ledger_account='miner_immature'),0)::BIGINT AS liability FROM ledger_transactions t JOIN ledger_entries e ON (e.deployment_id,e.transaction_id)=(t.deployment_id,t.id) WHERE t.deployment_id=$1 AND t.chain='zcash'")
        .bind(f.store.deployment_id()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(credit.get::<i64, _>("entries"), 1);
    assert_eq!(
        credit.get::<i64, _>("liability"),
        -i64::try_from(zcash.reward_zat).unwrap()
    );
}

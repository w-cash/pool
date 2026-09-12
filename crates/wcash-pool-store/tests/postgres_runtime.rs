//! Real PostgreSQL regression coverage. Set `WCASH_POOL_TEST_DATABASE_URL` to
//! an isolated, disposable database; the test recreates its public schema.

// This destructive disposable-database harness intentionally stops on the
// first violated test invariant so later statements cannot obscure the cause.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use num_bigint::BigUint;
use sqlx::{postgres::PgPoolOptions, Row};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use uuid::Uuid;
use wcash_pool_backend_client::{BackendClient, BackendClientConfig, ExpectedBackend};
use wcash_pool_edge::AuthenticationError;
use wcash_pool_protocol::{
    canonical_attribution_id, decode_backend_request, encode_backend_message, BackendEvent,
    BackendMessage, BackendRequest, CanonicalUuid, ChainTip, Hex108, Hex32, JobDescriptor,
    MergedChain, NonceProfile, ShareReceipt, TargetLe, WinnerDescriptor, WorkerIdentity,
    BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, REQUIRED_BACKEND_CAPABILITIES,
};
use wcash_pool_store::{
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PayoutConfirmation, PayoutReorg,
    PostgresStore, ProjectionResult, StoreError,
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

async fn insert_destination(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    account_id: Uuid,
    chain: Chain,
) -> Result<(), sqlx::Error> {
    let destination_id = Uuid::new_v4();
    let suffix = match chain {
        Chain::Wcash => "wcash",
        Chain::Zcash => "zcash",
    };
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by,validated_at,active_after,address_digest,payout_threshold_zat,automatic,state) \
         VALUES ($1,$2,$3,$4,'testnet',$5,'transparent','integration-authority-v1',clock_timestamp(),clock_timestamp(),$6,1,true,'active')",
    )
    .bind(store.deployment_id())
    .bind(destination_id)
    .bind(account_id)
    .bind(chain.as_str())
    .bind(format!("integration-{suffix}-address"))
    .bind([0x44u8; 32].as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

async fn credit_payable(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    account_id: Uuid,
    chain: Chain,
    amount: i64,
) -> Result<(), sqlx::Error> {
    let transaction_id = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference) VALUES ($1,$2,$3,'winner_matured',$4)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(chain.as_str())
    .bind(format!("integration-credit-{transaction_id}"))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO ledger_entries \
         (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES \
         ($1,$2,1,NULL,'collector_spendable_asset',$3),($1,$2,2,$4,'miner_payable',-$3)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(amount)
    .bind(account_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=2 \
         WHERE deployment_id=$1 AND id=$2",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}

async fn credit_immature(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    account_id: Uuid,
    chain: Chain,
    amount: i64,
) -> Result<(), sqlx::Error> {
    let transaction_id = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference) VALUES ($1,$2,$3,'winner_observed',$4)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(chain.as_str())
    .bind(format!("integration-immature-{transaction_id}"))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO ledger_entries \
         (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES \
         ($1,$2,1,NULL,'collector_immature_asset',$3),($1,$2,2,$4,'miner_immature',-$3)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(amount)
    .bind(account_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=2 \
         WHERE deployment_id=$1 AND id=$2",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}

async fn fund_operator_capital(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    chain: Chain,
    amount: i64,
) -> Result<(), sqlx::Error> {
    let transaction_id = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference) VALUES ($1,$2,$3,'operator_capital_funded',$4)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(chain.as_str())
    .bind(format!("integration-capital-{transaction_id}"))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO ledger_entries \
         (deployment_id,transaction_id,line_no,ledger_account,amount_zat) VALUES \
         ($1,$2,1,'collector_spendable_asset',$3),($1,$2,2,'pool_equity',-$3)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(amount)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=2 \
         WHERE deployment_id=$1 AND id=$2",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn durable_runtime_is_chain_scoped_conserved_and_revocable() {
    let Ok(database_url) = std::env::var("WCASH_POOL_TEST_DATABASE_URL") else {
        return;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("isolated PostgreSQL is available");
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&admin)
        .await
        .expect("isolated schema can be reset");

    let store_identity = identity(11);
    let store = PostgresStore::connect(&database_url, 4, store_identity.clone())
        .await
        .expect("store connects");
    store.migrate().await.expect("schema migrates");
    store.bind_deployment().await.expect("identity binds");
    let mut unsafe_policy = policy(Chain::Wcash);
    unsafe_policy.required_confirmations = 99;
    assert!(matches!(
        store.bind_chain_policy(&unsafe_policy).await,
        Err(StoreError::InvalidChainPolicy)
    ));
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("zero-fee policies bind");
    assert_eq!(
        store
            .chain_policy(Chain::Wcash)
            .await
            .unwrap()
            .unwrap()
            .fee_bps,
        0
    );
    assert!(
        sqlx::query(
            "UPDATE chain_policies SET fee_bps=1,policy_version=2 \
             WHERE deployment_id=$1 AND chain='wcash'",
        )
        .bind(store.deployment_id())
        .execute(&admin)
        .await
        .is_err(),
        "launch policy is sealed against updates"
    );
    assert!(
        sqlx::query("DELETE FROM chain_policies WHERE deployment_id=$1 AND chain='wcash'",)
            .bind(store.deployment_id())
            .execute(&admin)
            .await
            .is_err(),
        "launch policy is sealed against deletion"
    );

    // Exercise the complete authoritative event lifecycle through a real
    // backend-authenticated authority. The account imported from history is
    // intentionally disabled and has no payout destination, so replayed
    // history can never become an implicit live mining credential or payout.
    let authority = authority_for(&store_identity).await;
    let descriptor = job();
    let event_worker = WorkerIdentity {
        account_id: CanonicalUuid::new(Uuid::new_v4()),
        worker_id: CanonicalUuid::new(Uuid::new_v4()),
        label: "historic.z15".to_owned(),
    };
    let issued_target = TargetLe::new([0x7f; 32]);
    let share_id = Hex32::new([0x71; 32]);
    let wcash_winner = winner(MergedChain::Wcash);
    let zcash_winner = winner(MergedChain::Zcash);
    let receipt = ShareReceipt {
        event_seq: 2,
        job_id: descriptor.job_id.clone(),
        share_id: share_id.clone(),
        attribution_id: canonical_attribution_id(&event_worker, &issued_target)
            .expect("attribution is canonical"),
        parent_hash_le: zcash_winner.block_hash_le.clone(),
        winners: vec![wcash_winner.clone(), zcash_winner.clone()],
    };
    let events = [
        BackendEvent::JobActivated {
            event_seq: 1,
            job: descriptor.clone(),
        },
        BackendEvent::ShareCommitted {
            receipt,
            job_id: descriptor.job_id.clone(),
            identity: event_worker.clone(),
            target_le: issued_target,
        },
        BackendEvent::WinnerObserved {
            event_seq: 3,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: wcash_winner.block_hash_le.clone(),
                height: wcash_winner.height,
            },
            confirmations: 1,
        },
        BackendEvent::WinnerObserved {
            event_seq: 4,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: zcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: zcash_winner.block_hash_le.clone(),
                height: zcash_winner.height,
            },
            confirmations: 1,
        },
        BackendEvent::WinnerMatured {
            event_seq: 5,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0xa1; 32]),
                height: wcash_winner.height + 99,
            },
            confirmations: 100,
        },
        BackendEvent::WinnerMatured {
            event_seq: 6,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: zcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0xa2; 32]),
                height: zcash_winner.height + 99,
            },
            confirmations: 100,
        },
        BackendEvent::WinnerOrphaned {
            event_seq: 7,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0xa3; 32]),
                height: wcash_winner.height + 100,
            },
        },
    ];
    for event in &events {
        assert_eq!(
            store
                .project_event(&authority, event)
                .await
                .expect("authoritative event projects atomically"),
            ProjectionResult::Applied
        );
    }
    assert_eq!(store.last_event_seq().await.unwrap(), 7);
    let event_balances = sqlx::query(
        "SELECT t.chain,e.ledger_account,SUM(e.amount_zat)::BIGINT AS balance \
         FROM ledger_entries e JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND e.account_id=$2 \
         GROUP BY t.chain,e.ledger_account ORDER BY t.chain,e.ledger_account",
    )
    .bind(store.deployment_id())
    .bind(event_worker.account_id.get())
    .fetch_all(&admin)
    .await
    .expect("event balances load");
    let balance = |chain: &str, ledger_account: &str| {
        event_balances
            .iter()
            .find(|row| {
                row.get::<String, _>("chain") == chain
                    && row.get::<String, _>("ledger_account") == ledger_account
            })
            .map_or(0, |row| row.get::<i64, _>("balance"))
    };
    assert_eq!(balance("wcash", "miner_immature"), 0);
    assert_eq!(balance("wcash", "miner_payable"), 0);
    assert_eq!(balance("zcash", "miner_immature"), 0);
    assert_eq!(
        balance("zcash", "miner_payable"),
        -i64::try_from(zcash_winner.reward_zat).unwrap()
    );
    let wcash_state = sqlx::query_scalar::<_, String>(
        "SELECT state FROM winners WHERE deployment_id=$1 AND chain='wcash' AND block_hash_le=$2",
    )
    .bind(store.deployment_id())
    .bind(wcash_winner.block_hash_le.as_bytes().as_slice())
    .fetch_one(&admin)
    .await
    .unwrap();
    let zcash_state = sqlx::query_scalar::<_, String>(
        "SELECT state FROM winners WHERE deployment_id=$1 AND chain='zcash' AND block_hash_le=$2",
    )
    .bind(store.deployment_id())
    .bind(zcash_winner.block_hash_le.as_bytes().as_slice())
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(wcash_state, "orphaned");
    assert_eq!(zcash_state, "matured");

    let ledger_count_before_replay = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ledger_transactions WHERE deployment_id=$1",
    )
    .bind(store.deployment_id())
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(
        store.project_event(&authority, &events[6]).await.unwrap(),
        ProjectionResult::Replayed
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ledger_transactions WHERE deployment_id=$1",
        )
        .bind(store.deployment_id())
        .fetch_one(&admin)
        .await
        .unwrap(),
        ledger_count_before_replay,
        "exact replay must not credit twice"
    );
    let conflicting_replay = BackendEvent::GenerationClosed {
        event_seq: 7,
        job_id: descriptor.job_id.clone(),
    };
    assert!(matches!(
        store.project_event(&authority, &conflicting_replay).await,
        Err(StoreError::EventReplayConflict(7))
    ));
    let cursor_gap = BackendEvent::GenerationClosed {
        event_seq: 9,
        job_id: descriptor.job_id.clone(),
    };
    assert!(matches!(
        store.project_event(&authority, &cursor_gap).await,
        Err(StoreError::EventSequenceGap {
            expected: 8,
            actual: 9
        })
    ));
    let restarted = PostgresStore::connect(&database_url, 2, store_identity.clone())
        .await
        .expect("store reconnects after process restart");
    restarted
        .bind_deployment()
        .await
        .expect("restart rebinds the exact deployment");
    assert_eq!(restarted.last_event_seq().await.unwrap(), 7);
    assert_eq!(
        store
            .chain_policy(Chain::Zcash)
            .await
            .unwrap()
            .unwrap()
            .fee_bps,
        0
    );

    let (account_id, worker_id, token) = store
        .provision_worker("alice", "z15")
        .await
        .expect("worker provisions");
    let auth = store
        .authentication_provider(2)
        .expect("auth provider builds");
    let worker = auth
        .authenticate_credentials("alice.z15", token.expose_secret())
        .await
        .expect("canonical token authenticates");
    assert_eq!(worker.account_id(), account_id);
    assert_eq!(worker.worker_id(), worker_id);
    assert!(matches!(
        auth.authenticate_credentials("alice.z15", "invalid-token")
            .await,
        Err(AuthenticationError::Denied)
    ));

    let lease = wcash_pool_core::NonceNamespaceLease::new(7).expect("valid namespace");
    let first = store
        .reserve_nonce_range(Uuid::new_v4(), NonceProfile::FourByte, lease, 2)
        .await
        .expect("first range reserves");
    let second = store
        .reserve_nonce_range(Uuid::new_v4(), NonceProfile::FourByte, lease, 3)
        .await
        .expect("second range reserves");
    assert_eq!((first.start(), first.end()), (0, 2));
    assert_eq!((second.start(), second.end()), (2, 5));
    assert_eq!(first.profile(), NonceProfile::FourByte);
    let allocator = first.allocator().expect("range restores its bound profile");
    assert!(allocator.allocate().is_ok());
    assert!(allocator.allocate().is_ok());
    assert!(allocator.allocate().is_err());

    // One multi-row INSERT is accepted at commit only when its final sum is zero.
    let conserved_id = Uuid::new_v4();
    let mut conserved = admin.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference) VALUES ($1,$2,'wcash','payout_released','multi-row-conserved')",
    )
    .bind(store.deployment_id())
    .bind(conserved_id)
    .execute(&mut *conserved)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO ledger_entries \
         (deployment_id,transaction_id,line_no,ledger_account,amount_zat) VALUES \
         ($1,$2,1,'network_fee_expense',7),($1,$2,2,'pool_equity',-7)",
    )
    .bind(store.deployment_id())
    .bind(conserved_id)
    .execute(&mut *conserved)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=2 \
         WHERE deployment_id=$1 AND id=$2",
    )
    .bind(store.deployment_id())
    .bind(conserved_id)
    .execute(&mut *conserved)
    .await
    .unwrap();
    conserved
        .commit()
        .await
        .expect("multi-row ledger conserves");

    assert!(
        sqlx::query(
            "INSERT INTO ledger_entries \
             (deployment_id,transaction_id,line_no,ledger_account,amount_zat) \
             VALUES ($1,$2,3,'network_fee_expense',1)",
        )
        .bind(store.deployment_id())
        .bind(conserved_id)
        .execute(&admin)
        .await
        .is_err(),
        "a completed ledger transaction cannot receive later lines"
    );

    let empty_id = Uuid::new_v4();
    let mut empty = admin.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference) VALUES ($1,$2,'wcash','payout_released','empty-rejected')",
    )
    .bind(store.deployment_id())
    .bind(empty_id)
    .execute(&mut *empty)
    .await
    .unwrap();
    assert!(
        empty.commit().await.is_err(),
        "empty ledger transaction must fail"
    );

    insert_destination(&store, &admin, account_id, Chain::Wcash)
        .await
        .expect("WEC destination seeds");
    insert_destination(&store, &admin, account_id, Chain::Zcash)
        .await
        .expect("ZEC destination seeds");
    credit_payable(&store, &admin, account_id, Chain::Wcash, 100)
        .await
        .expect("WEC credit commits");
    credit_payable(&store, &admin, account_id, Chain::Zcash, 300)
        .await
        .expect("ZEC credit commits");
    let second_account_id = Uuid::from_u128(1);
    sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'batch_second')")
        .bind(store.deployment_id())
        .bind(second_account_id)
        .execute(&admin)
        .await
        .expect("second payout account seeds");
    insert_destination(&store, &admin, second_account_id, Chain::Wcash)
        .await
        .expect("second WEC destination seeds");
    credit_payable(&store, &admin, second_account_id, Chain::Wcash, 200)
        .await
        .expect("second WEC credit commits");
    let key = Uuid::new_v4();
    let wec_batch = store
        .create_payout_batch(Chain::Wcash, key)
        .await
        .expect("WEC batch builds");
    assert_eq!(wec_batch.outputs.len(), 1, "batch policy caps output count");
    assert_eq!(wec_batch.miner_total_zat, 200, "ZEC never enters WEC batch");
    let second_wec_batch = store
        .create_payout_batch(Chain::Wcash, Uuid::new_v4())
        .await
        .expect("deterministic pagination leaves the next WEC account payable");
    assert_eq!(second_wec_batch.outputs.len(), 1);
    assert_eq!(second_wec_batch.miner_total_zat, 100);
    assert_eq!(
        store
            .list_resumable_payout_batches(Chain::Wcash, 10)
            .await
            .expect("restart can enumerate incomplete WEC batches")
            .len(),
        2
    );
    assert!(matches!(
        store.create_payout_batch(Chain::Zcash, key).await,
        Err(StoreError::PayoutIdempotencyConflict)
    ));
    let zec_batch = store
        .create_payout_batch(Chain::Zcash, Uuid::new_v4())
        .await
        .expect("ZEC batch builds");
    assert_eq!(zec_batch.miner_total_zat, 300, "WEC never enters ZEC batch");

    let unsigned_digest = [0xb1; 32];
    let transaction_id = [0xb2; 32];
    let signed_transaction = [0xc1, 0xc2, 0xc3, 0xc4];
    assert!(matches!(
        store
            .mark_payout_signed(
                wec_batch.id,
                &unsigned_digest,
                &transaction_id,
                &signed_transaction,
                21,
            )
            .await,
        Err(StoreError::ExcessivePayoutFee)
    ));
    store
        .mark_payout_signed(
            wec_batch.id,
            &unsigned_digest,
            &transaction_id,
            &signed_transaction,
            5,
        )
        .await
        .expect("draft becomes signed");
    store
        .mark_payout_signed(
            wec_batch.id,
            &unsigned_digest,
            &transaction_id,
            &signed_transaction,
            5,
        )
        .await
        .expect("exact signer replay is idempotent");
    assert!(matches!(
        store
            .mark_payout_signed(
                wec_batch.id,
                &[0xb3; 32],
                &transaction_id,
                &signed_transaction,
                5,
            )
            .await,
        Err(StoreError::PayoutReplayConflict)
    ));

    assert!(matches!(
        store
            .mark_payout_signed(
                second_wec_batch.id,
                &[0xb4; 32],
                &transaction_id,
                &[0xd1, 0xd2],
                1,
            )
            .await,
        Err(StoreError::PayoutTransactionConflict)
    ));
    let recovered_artifact = store
        .signed_payout_artifact(wec_batch.id)
        .await
        .expect("signed artifact loads")
        .expect("signed batch has a recovery artifact");
    assert_eq!(recovered_artifact.unsigned_digest, unsigned_digest);
    assert_eq!(recovered_artifact.transaction_id, transaction_id);
    assert_eq!(recovered_artifact.signed_transaction, signed_transaction);
    assert_eq!(recovered_artifact.network_fee_zat, 5);
    store
        .mark_payout_broadcast(wec_batch.id)
        .await
        .expect("signed batch becomes broadcast");
    store
        .mark_payout_broadcast(wec_batch.id)
        .await
        .expect("broadcast replay is idempotent");
    let payout_confirmation = PayoutConfirmation {
        block_hash: [0xf1; 32],
        block_height: 50_000,
        confirmations: 100,
    };
    let shallow_confirmation = PayoutConfirmation {
        confirmations: 99,
        ..payout_confirmation.clone()
    };
    assert!(matches!(
        store
            .confirm_payout(wec_batch.id, &shallow_confirmation)
            .await,
        Err(StoreError::PrematurePayoutConfirmation {
            required: 100,
            actual: 99
        })
    ));
    credit_immature(&store, &admin, account_id, Chain::Wcash, 1_000)
        .await
        .expect("immature collector fixture commits");
    assert!(matches!(
        store
            .confirm_payout(wec_batch.id, &payout_confirmation)
            .await,
        Err(StoreError::CollectorReconciliationFailed)
    ));
    fund_operator_capital(&store, &admin, Chain::Wcash, 5)
        .await
        .expect("explicit operator fee reserve commits");
    store
        .confirm_payout(wec_batch.id, &payout_confirmation)
        .await
        .expect("collector reconciliation permits confirmation");
    store
        .confirm_payout(wec_batch.id, &payout_confirmation)
        .await
        .expect("confirmation replay is idempotent");
    assert!(matches!(
        store
            .confirm_payout(
                wec_batch.id,
                &PayoutConfirmation {
                    block_hash: [0xf2; 32],
                    ..payout_confirmation.clone()
                },
            )
            .await,
        Err(StoreError::PayoutReplayConflict)
    ));

    let payout_reorg = PayoutReorg {
        prior_confirmation: payout_confirmation.clone(),
        replacement_tip_hash: [0xf3; 32],
        replacement_tip_height: 50_101,
        observed_at: 1_725_000_500,
    };
    store
        .mark_confirmed_payout_reorged(wec_batch.id, &payout_reorg)
        .await
        .expect("confirmed payout reorg freezes its chain");
    store
        .mark_confirmed_payout_reorged(wec_batch.id, &payout_reorg)
        .await
        .expect("exact payout reorg replay is idempotent");
    assert!(matches!(
        store
            .mark_confirmed_payout_reorged(
                wec_batch.id,
                &PayoutReorg {
                    replacement_tip_hash: [0xf4; 32],
                    ..payout_reorg.clone()
                },
            )
            .await,
        Err(StoreError::PayoutReplayConflict)
    ));

    let zcash_deep_reorg = BackendEvent::WinnerOrphaned {
        event_seq: 8,
        share_id: share_id.clone(),
        job_id: descriptor.job_id.clone(),
        winner: zcash_winner.clone(),
        tip: ChainTip {
            block_hash_le: Hex32::new([0xa4; 32]),
            height: zcash_winner.height + 101,
        },
    };
    assert_eq!(
        store
            .project_event(&authority, &zcash_deep_reorg)
            .await
            .expect("deep reorg is always journaled and reversed"),
        ProjectionResult::Applied
    );
    assert!(matches!(
        store
            .mark_payout_signed(zec_batch.id, &[0xe1; 32], &[0xe2; 32], &[0xe3, 0xe4], 1,)
            .await,
        Err(StoreError::PayoutsFrozen(Chain::Zcash))
    ));
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT payouts_frozen FROM chain_safety_state \
             WHERE deployment_id=$1 AND chain='zcash'",
    )
    .bind(store.deployment_id())
    .fetch_one(&admin)
    .await
    .unwrap());
    store
        .cancel_payout_draft(zec_batch.id)
        .await
        .expect("unsigned draft releases balances");
    store
        .cancel_payout_draft(zec_batch.id)
        .await
        .expect("draft cancellation replay is idempotent");
    store
        .cancel_payout_draft(second_wec_batch.id)
        .await
        .expect("unbroadcast second page releases balances");
    let payout_states =
        sqlx::query("SELECT id,state FROM payout_batches WHERE deployment_id=$1 ORDER BY chain")
            .bind(store.deployment_id())
            .fetch_all(&admin)
            .await
            .unwrap();
    assert_eq!(payout_states.len(), 3);
    assert!(payout_states.iter().any(|row| {
        row.get::<Uuid, _>("id") == wec_batch.id && row.get::<String, _>("state") == "reorged"
    }));
    assert!(payout_states.iter().any(|row| {
        row.get::<Uuid, _>("id") == zec_batch.id && row.get::<String, _>("state") == "cancelled"
    }));
    assert!(payout_states.iter().any(|row| {
        row.get::<Uuid, _>("id") == second_wec_batch.id
            && row.get::<String, _>("state") == "cancelled"
    }));

    assert!(store
        .revoke_worker(account_id, worker_id)
        .await
        .expect("worker revokes"));
    assert!(matches!(
        auth.authenticate_credentials("alice.z15", token.expose_secret())
            .await,
        Err(AuthenticationError::Denied)
    ));

    let counts = sqlx::query(
        "SELECT \
           (SELECT COUNT(*) FROM nonce_range_leases WHERE deployment_id=$1) AS leases, \
           (SELECT COUNT(*) FROM payout_batches WHERE deployment_id=$1) AS batches",
    )
    .bind(store.deployment_id())
    .fetch_one(&admin)
    .await
    .expect("audit counts load");
    assert_eq!(counts.get::<i64, _>("leases"), 2);
    assert_eq!(counts.get::<i64, _>("batches"), 3);
}

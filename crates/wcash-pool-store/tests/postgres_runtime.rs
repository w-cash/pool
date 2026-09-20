//! Real PostgreSQL regression coverage. Set `WCASH_POOL_TEST_DATABASE_URL` to
//! an isolated, disposable database; the test recreates its public schema.

// This destructive disposable-database harness intentionally stops on the
// first violated test invariant so later statements cannot obscure the cause.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{sync::Arc, time::Duration};

use num_bigint::BigUint;
use sqlx::{postgres::PgPoolOptions, Row};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};
use uuid::Uuid;
use wcash_pool_backend_client::{BackendClient, BackendClientConfig, ExpectedBackend};
use wcash_pool_edge::AuthenticationError;
use wcash_pool_portal::{
    Asset, ChainNetwork, PageRequest, PayoutPreferenceChange, PoolDataSource, PortalRepository,
    ReceiverKind as PortalReceiverKind, ValidatedDestination,
};
use wcash_pool_protocol::{
    canonical_attribution_id, decode_backend_request, encode_backend_message, BackendEvent,
    BackendMessage, BackendRequest, CanonicalUuid, ChainTip, Hex108, Hex32, JobDescriptor,
    MergedChain, NonceProfile, ShareReceipt, TargetBe, TargetLe, WinnerDescriptor, WorkerIdentity,
    BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, REQUIRED_BACKEND_CAPABILITIES,
};
use wcash_pool_store::{
    generate_mining_token, hash_mining_token, Chain, ChainPolicy, DeploymentIdentity,
    DeploymentNetwork, NewPortalSessionRecord, PayoutBatchState, PayoutConfirmation, PayoutReorg,
    PostgresPoolDataSource, PostgresStore, ProjectionResult, StoreError, WalletObservation,
    WalletReconciliation,
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
        payout_confirmations: 3,
        maximum_payout_outputs: 1,
        maximum_payout_zat: 1_000_000_000_000,
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
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by,validated_at, \
          active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
         VALUES ($1,$2,$3,$4,'testnet',$5,'transparent','integration-authority-v1', \
                 clock_timestamp(),clock_timestamp(),$6,1,true,'active',1)",
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

async fn reconcile_wallet(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    chain: Chain,
) -> Result<WalletReconciliation, StoreError> {
    let now = sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT")
        .fetch_one(pool)
        .await?;
    let spendable = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(e.amount_zat),0)::BIGINT FROM ledger_entries e \
         JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND t.chain=$2 \
           AND e.ledger_account='collector_spendable_asset'",
    )
    .bind(store.deployment_id())
    .bind(chain.as_str())
    .fetch_one(pool)
    .await?;
    let now = u64::try_from(now).expect("database clock is positive");
    store
        .record_wallet_reconciliation(&WalletObservation {
            chain,
            wallet_state_digest: [match chain {
                Chain::Wcash => 0x91,
                Chain::Zcash => 0x92,
            }; 32],
            wallet_spendable_zat: u64::try_from(spendable)
                .expect("collector spendable balance is nonnegative"),
            best_tip_hash: [match chain {
                Chain::Wcash => 0xa1,
                Chain::Zcash => 0xa2,
            }; 32],
            best_tip_height: 50_000,
            observed_at: now,
            valid_until: now + 240,
        })
        .await
}

async fn assert_due_preferences_survive_empty_payout_selection(
    database_url: &str,
    admin: &sqlx::PgPool,
) {
    // Disabling the only recipient and raising its threshold both remove all
    // eligible outputs. The preference must still take effect durably without
    // creating a payment or changing the original payable liability.
    for (chain, seed, automatic, threshold) in [
        (Chain::Wcash, 101, false, 1_i64),
        (Chain::Zcash, 102, true, 200_i64),
    ] {
        let store = PostgresStore::connect(database_url, 2, identity(seed))
            .await
            .expect("empty-selection store connects");
        store.bind_deployment().await.expect("identity binds");
        store
            .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
            .await
            .expect("policies bind");
        let account_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'preference_owner')",
        )
        .bind(store.deployment_id())
        .bind(account_id)
        .execute(admin)
        .await
        .expect("preference owner seeds");
        insert_destination(&store, admin, account_id, chain)
            .await
            .expect("initial automatic destination seeds");
        credit_payable(&store, admin, account_id, chain, 100)
            .await
            .expect("payable liability seeds");
        let pending_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO payout_destinations \
             (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by, \
              validated_at,active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
             VALUES ($1,$2,$3,$4,'testnet','integration-due-preference','transparent', \
                     'integration-authority-v1',clock_timestamp(), \
                     clock_timestamp()-INTERVAL '1 second',$5,$6,$7,'pending',2)",
        )
        .bind(store.deployment_id())
        .bind(pending_id)
        .bind(account_id)
        .bind(chain.as_str())
        .bind([0x45_u8; 32].as_slice())
        .bind(threshold)
        .bind(automatic)
        .execute(admin)
        .await
        .expect("already-due replacement seeds");
        let before = reconcile_wallet(&store, admin, chain)
            .await
            .expect("original liability matches wallet");

        assert!(matches!(
            store
                .create_payout_batch(chain, Uuid::new_v4(), Uuid::new_v4())
                .await,
            Err(StoreError::WalletReconciliationStale)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM payout_destinations WHERE deployment_id=$1 AND id=$2",
            )
            .bind(store.deployment_id())
            .bind(pending_id)
            .fetch_one(admin)
            .await
            .expect("failed reconciliation leaves pending preference"),
            "pending",
            "the empty-selection commit must not bypass reconciliation"
        );

        let batch_key = Uuid::new_v4();
        for _ in 0..2 {
            assert!(matches!(
                store.create_payout_batch(chain, batch_key, before.id).await,
                Err(StoreError::NoPayableBalances)
            ));
            let active = sqlx::query(
                "SELECT id,automatic,payout_threshold_zat,revision \
                 FROM payout_destinations \
                 WHERE deployment_id=$1 AND account_id=$2 AND chain=$3 AND state='active'",
            )
            .bind(store.deployment_id())
            .bind(account_id)
            .bind(chain.as_str())
            .fetch_one(admin)
            .await
            .expect("replacement persists even when no batch is created");
            assert_eq!(active.get::<Uuid, _>("id"), pending_id);
            assert_eq!(active.get::<bool, _>("automatic"), automatic);
            assert_eq!(active.get::<i64, _>("payout_threshold_zat"), threshold);
            assert_eq!(active.get::<i64, _>("revision"), 2);
        }

        let counts = sqlx::query(
            "SELECT \
               (SELECT COUNT(*) FROM payout_destinations WHERE deployment_id=$1 \
                 AND state='pending') AS pending, \
               (SELECT COUNT(*) FROM payout_destinations WHERE deployment_id=$1 \
                 AND state='disabled' AND disabled_at IS NOT NULL) AS disabled, \
               (SELECT COUNT(*) FROM payout_batches WHERE deployment_id=$1) AS batches, \
               (SELECT COUNT(*) FROM payout_items WHERE deployment_id=$1) AS items",
        )
        .bind(store.deployment_id())
        .fetch_one(admin)
        .await
        .expect("empty selection has no payment artifacts");
        assert_eq!(counts.get::<i64, _>("pending"), 0);
        assert_eq!(counts.get::<i64, _>("disabled"), 1);
        assert_eq!(counts.get::<i64, _>("batches"), 0);
        assert_eq!(counts.get::<i64, _>("items"), 0);
        let after = reconcile_wallet(&store, admin, chain)
            .await
            .expect("unchanged payable liability still matches wallet");
        assert_eq!(after.ledger_root, before.ledger_root);
        assert_eq!(
            after.ledger_transaction_count,
            before.ledger_transaction_count
        );
        assert_eq!(after.wallet_spendable_zat, before.wallet_spendable_zat);
    }
}

async fn assert_full_balance_payout_is_miner_fee_funded(
    database_url: &str,
    admin: &sqlx::PgPool,
    chain: Chain,
    seed: u8,
) {
    let fee_store = PostgresStore::connect(database_url, 2, identity(seed))
        .await
        .expect("full-balance fee deployment connects");
    fee_store
        .bind_deployment()
        .await
        .expect("full-balance fee deployment binds");
    fee_store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("full-balance zero-fee policies bind");
    let account_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'full_balance_miner')",
    )
    .bind(fee_store.deployment_id())
    .bind(account_id)
    .execute(admin)
    .await
    .expect("full-balance miner account seeds");
    insert_destination(&fee_store, admin, account_id, chain)
        .await
        .expect("full-balance payout destination seeds");
    credit_payable(&fee_store, admin, account_id, chain, 1_000)
        .await
        .expect("full collector balance and liability seed together");
    let checkpoint = reconcile_wallet(&fee_store, admin, chain)
        .await
        .expect("full collector balance reconciles exactly");
    let batch = fee_store
        .create_payout_batch(chain, Uuid::new_v4(), checkpoint.id)
        .await
        .expect("full-balance payout reserves");
    assert_eq!(batch.miner_total_zat, 1_000);
    assert_eq!(batch.maximum_network_fee_zat, 100);
    assert_eq!(batch.payout_total_zat, 900);
    assert_eq!(batch.outputs[0].liability_amount_zat, 1_000);
    assert_eq!(batch.outputs[0].amount_zat, 900);
    let request = fee_store
        .authorize_payout_signing(batch.id)
        .await
        .expect("full-balance signing is authorized");
    assert_eq!(request.maximum_network_fee_zat, 100);
    assert_eq!(request.outputs[0].amount_zat, 900);
    fee_store
        .mark_payout_signed(
            batch.id,
            &[seed.wrapping_add(1); 32],
            &[seed.wrapping_add(2); 32],
            &[seed.wrapping_add(3), seed.wrapping_add(4)],
            100,
        )
        .await
        .expect("maximum authorized miner-funded fee signs");
    fee_store
        .authorize_payout_broadcast(batch.id)
        .await
        .expect("full-balance broadcast is authorized");
    fee_store
        .mark_payout_broadcast(batch.id)
        .await
        .expect("full-balance transaction broadcasts");
    fee_store
        .confirm_payout(
            batch.id,
            &PayoutConfirmation {
                block_hash: [seed.wrapping_add(5); 32],
                block_height: 70_000 + u32::from(seed),
                confirmations: 100,
            },
        )
        .await
        .expect("full-balance payout confirms without operator capital");

    let balances = sqlx::query(
        "SELECT ledger_account,SUM(e.amount_zat)::BIGINT AS balance \
         FROM ledger_entries e JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND t.chain=$2 GROUP BY ledger_account",
    )
    .bind(fee_store.deployment_id())
    .bind(chain.as_str())
    .fetch_all(admin)
    .await
    .expect("full-balance ledger reads");
    let balance = |account: &str| {
        balances
            .iter()
            .find(|row| row.get::<String, _>("ledger_account") == account)
            .map_or(0, |row| row.get::<i64, _>("balance"))
    };
    assert_eq!(balance("collector_spendable_asset"), 0);
    assert_eq!(balance("miner_payable"), 0);
    assert_eq!(balance("payout_pending"), 0);
    assert_eq!(balance("network_fee_expense"), 100);
    assert_eq!(balance("miner_network_fee_contribution"), -100);
    assert_eq!(balance("pool_equity"), 0);
    assert_eq!(
        balances
            .iter()
            .map(|row| row.get::<i64, _>("balance"))
            .sum::<i64>(),
        0
    );
}

async fn assert_nonce_fencing_migration_preserves_legacy_floor(pool: &sqlx::PgPool) {
    let mut fixture = pool.begin().await.expect("migration fixture starts");
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS nonce_migration_fixture CASCADE; \
         CREATE SCHEMA nonce_migration_fixture; \
         SET LOCAL search_path TO nonce_migration_fixture",
    )
    .execute(&mut *fixture)
    .await
    .expect("isolated migration fixture schema initializes");
    sqlx::raw_sql(include_str!("../migrations/0001_runtime_accounting.sql"))
        .execute(&mut *fixture)
        .await
        .expect("legacy accounting schema applies");
    sqlx::raw_sql(include_str!("../migrations/0002_portal_read_models.sql"))
        .execute(&mut *fixture)
        .await
        .expect("legacy portal schema applies");

    let backend_instance = Uuid::new_v4();
    let journal_stream = Uuid::new_v4();
    let first_deployment = Uuid::new_v4();
    let second_deployment = Uuid::new_v4();
    for (deployment_id, marker, chain_id) in [
        (first_deployment, 0x11_u8, 101_i64),
        (second_deployment, 0x21_u8, 102_i64),
    ] {
        sqlx::query(
            "INSERT INTO deployments \
             (id,network,wcash_genesis,zcash_genesis,chain_id,wcash_payout_commitment, \
              zcash_payout_commitment,backend_instance,journal_stream) \
             VALUES ($1,'testnet',$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(deployment_id)
        .bind([marker; 32].as_slice())
        .bind([marker.wrapping_add(1); 32].as_slice())
        .bind(chain_id)
        .bind([marker.wrapping_add(2); 32].as_slice())
        .bind([marker.wrapping_add(3); 32].as_slice())
        .bind(backend_instance)
        .bind(journal_stream)
        .execute(&mut *fixture)
        .await
        .expect("legacy deployment inserts");
    }
    sqlx::query(
        "INSERT INTO nonce_cursors (deployment_id,profile,namespace,next_counter) \
         VALUES ($1,4,9,10),($2,4,9,20)",
    )
    .bind(first_deployment)
    .bind(second_deployment)
    .execute(&mut *fixture)
    .await
    .expect("legacy cursors insert");
    sqlx::query(
        "INSERT INTO nonce_range_leases \
         (deployment_id,id,pool_instance,profile,namespace,range_start,range_end) \
         VALUES ($1,$3,$4,4,9,10,12),($2,$5,$6,4,9,20,25)",
    )
    .bind(first_deployment)
    .bind(second_deployment)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&mut *fixture)
    .await
    .expect("legacy reservations insert");

    sqlx::raw_sql(include_str!("../migrations/0003_global_nonce_fencing.sql"))
        .execute(&mut *fixture)
        .await
        .expect("global nonce fencing migration applies over legacy rows");
    let migrated_floor = sqlx::query_scalar::<_, i64>(
        "SELECT next_counter FROM nonce_namespace_fences \
         WHERE backend_instance=$1 AND journal_stream=$2 AND profile=4 AND namespace=9",
    )
    .bind(backend_instance)
    .bind(journal_stream)
    .fetch_one(&mut *fixture)
    .await
    .expect("migrated global floor reads");
    assert_eq!(migrated_floor, 25);
    fixture
        .rollback()
        .await
        .expect("migration fixture rolls back cleanly");
}

async fn assert_portal_winner_migration_backfills_existing_rows(pool: &sqlx::PgPool) {
    let mut fixture = pool.begin().await.expect("portal migration fixture starts");
    let schema = format!("portal_migration_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema},pg_catalog; \
         CREATE TABLE winners (deployment_id UUID NOT NULL, marker BIGINT NOT NULL); \
         INSERT INTO winners (deployment_id,marker) VALUES \
           ('11111111-1111-4111-8111-111111111111',1), \
           ('11111111-1111-4111-8111-111111111111',2)"
    ))
    .execute(&mut *fixture)
    .await
    .expect("populated legacy winners table seeds");
    sqlx::raw_sql(include_str!("../migrations/0004_portal_miner_views.sql"))
        .execute(&mut *fixture)
        .await
        .expect("portal cursor migration applies over populated winners");
    let sequences =
        sqlx::query_scalar::<_, i64>("SELECT portal_sequence FROM winners ORDER BY marker")
            .fetch_all(&mut *fixture)
            .await
            .expect("backfilled portal sequences read");
    assert_eq!(sequences.len(), 2);
    assert!(sequences[0] > 0);
    assert!(sequences[1] > sequences[0]);
    assert!(
        sqlx::query("UPDATE winners SET portal_sequence=portal_sequence+1 WHERE marker=1")
            .execute(&mut *fixture)
            .await
            .is_err()
    );
    fixture
        .rollback()
        .await
        .expect("portal migration fixture rolls back cleanly");
}

fn database_url_for_role(database_url: &str, role: &str, password: &str) -> String {
    let scheme_end = database_url
        .find("://")
        .map(|index| index + 3)
        .expect("PostgreSQL test URL has a scheme");
    let authority_end = database_url[scheme_end..]
        .find('/')
        .map(|index| scheme_end + index)
        .expect("PostgreSQL test URL has a database path");
    let authority = &database_url[scheme_end..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!(
        "{}{}:{}@{}{}",
        &database_url[..scheme_end],
        role,
        password,
        host,
        &database_url[authority_end..]
    )
}

async fn assert_default_acl_upgrade_reconciliation(pool: &sqlx::PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("default_acl_{suffix}");
    let migrator = format!("default_acl_owner_{suffix}");
    let runtime = format!("default_acl_runtime_{suffix}");
    let mut fixture = pool.begin().await.expect("default ACL fixture starts");
    sqlx::raw_sql(&format!(
        "CREATE ROLE {migrator} NOLOGIN; \
         CREATE ROLE {runtime} NOLOGIN; \
         CREATE SCHEMA {schema} AUTHORIZATION {migrator}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA {schema} \
             GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA {schema} \
             GRANT USAGE,SELECT,UPDATE ON SEQUENCES TO {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA {schema} \
             GRANT EXECUTE ON FUNCTIONS TO PUBLIC; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} \
             GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} \
             GRANT USAGE,SELECT,UPDATE ON SEQUENCES TO {runtime}; \
         SET LOCAL ROLE {migrator}; \
         CREATE TABLE {schema}.legacy_default_grant( \
             id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY); \
         CREATE FUNCTION {schema}.legacy_default_function() RETURNS INTEGER \
             LANGUAGE SQL IMMUTABLE AS 'SELECT 1'; \
         RESET ROLE"
    ))
    .execute(&mut *fixture)
    .await
    .expect("legacy broad default ACL fixture installs");
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT has_table_privilege($1,$2,'INSERT')")
            .bind(&runtime)
            .bind(format!("{schema}.legacy_default_grant"))
            .fetch_one(&mut *fixture)
            .await
            .expect("legacy inherited table privilege resolves"),
        "fixture must prove the old default ACL created broad table authority"
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT has_sequence_privilege($1,$2,'UPDATE')")
            .bind(&runtime)
            .bind(format!("{schema}.legacy_default_grant_id_seq"))
            .fetch_one(&mut *fixture)
            .await
            .expect("legacy inherited sequence privilege resolves"),
        "fixture must prove the old default ACL created sequence authority"
    );

    sqlx::raw_sql(&format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA {schema} \
             REVOKE ALL PRIVILEGES ON TABLES FROM {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} \
             REVOKE ALL PRIVILEGES ON TABLES FROM {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA {schema} \
             REVOKE ALL PRIVILEGES ON SEQUENCES FROM {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} \
             REVOKE ALL PRIVILEGES ON SEQUENCES FROM {runtime}; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA {schema} \
             REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC; \
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} \
             REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC; \
         REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {schema} FROM {runtime}; \
         REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {schema} FROM {runtime}; \
         SET LOCAL ROLE {migrator}; \
         CREATE TABLE {schema}.post_upgrade( \
             id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY); \
         CREATE FUNCTION {schema}.post_upgrade_function() RETURNS INTEGER \
             LANGUAGE SQL IMMUTABLE AS 'SELECT 1'; \
         RESET ROLE"
    ))
    .execute(&mut *fixture)
    .await
    .expect("least-authority default ACL reconciliation applies");
    for table in ["legacy_default_grant", "post_upgrade"] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT has_table_privilege($1,$2,'INSERT')")
                .bind(&runtime)
                .bind(format!("{schema}.{table}"))
                .fetch_one(&mut *fixture)
                .await
                .expect("reconciled table privilege resolves"),
            "current and future tables must not retain inherited runtime DML"
        );
    }
    for sequence in ["legacy_default_grant_id_seq", "post_upgrade_id_seq"] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT has_sequence_privilege($1,$2,'UPDATE')")
                .bind(&runtime)
                .bind(format!("{schema}.{sequence}"))
                .fetch_one(&mut *fixture)
                .await
                .expect("reconciled sequence privilege resolves"),
            "current and future sequences must not retain inherited runtime authority"
        );
    }
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS( \
                 SELECT 1 FROM pg_proc p, \
                    aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) privilege \
                 WHERE p.oid=to_regprocedure($1) AND privilege.grantee=0 \
                   AND privilege.privilege_type='EXECUTE')",
        )
        .bind(format!("{schema}.post_upgrade_function()"))
        .fetch_one(&mut *fixture)
        .await
        .expect("post-upgrade PUBLIC function privilege resolves"),
        "future migration functions must not regain default PUBLIC execution"
    );
    fixture
        .rollback()
        .await
        .expect("default ACL fixture rolls back cleanly");
}

async fn assert_database_privilege_boundaries(pool: &sqlx::PgPool, database_url: &str) {
    let suffix = Uuid::new_v4().simple().to_string();
    let migrator_role = format!("pool_migrator_{suffix}");
    let public_role = format!("pool_public_{suffix}");
    let projector_role = format!("pool_projector_{suffix}");
    let payout_role = format!("pool_payout_{suffix}");
    let escalation_role = format!("pool_escalation_{suffix}");
    let role_password = "temporary_acl_test_password_194";
    let role_identity = identity(0x51);
    let deployment_id = role_identity.id;
    let role_admin_store = PostgresStore::connect(database_url, 2, role_identity.clone())
        .await
        .expect("role-flow migrator store connects");
    role_admin_store
        .bind_deployment()
        .await
        .expect("role-flow deployment binds");
    role_admin_store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("role-flow policies bind");
    sqlx::raw_sql(&format!(
        "CREATE ROLE {escalation_role} NOLOGIN; \
         CREATE ROLE {migrator_role} LOGIN PASSWORD '{role_password}' NOINHERIT; \
         CREATE ROLE {public_role} LOGIN PASSWORD '{role_password}' NOINHERIT; \
         CREATE ROLE {projector_role} LOGIN PASSWORD '{role_password}' NOINHERIT; \
         CREATE ROLE {payout_role} LOGIN PASSWORD '{role_password}' NOINHERIT; \
         GRANT {escalation_role} TO {migrator_role},{public_role},{projector_role},{payout_role}; \
         DO $membership_reconcile$ \
         DECLARE role_membership RECORD; \
         BEGIN \
             IF (SELECT COUNT(*) FROM pg_auth_members membership \
                 JOIN pg_roles granted_role ON granted_role.oid=membership.roleid \
                 JOIN pg_roles member_role ON member_role.oid=membership.member \
                 WHERE granted_role.rolname='{escalation_role}' \
                   AND member_role.rolname IN ( \
                       '{migrator_role}','{public_role}','{projector_role}','{payout_role}')) <> 4 \
             THEN RAISE EXCEPTION 'membership escalation fixture was not installed'; \
             END IF; \
             FOR role_membership IN \
                 SELECT granted_role.rolname AS granted_name, \
                        member_role.rolname AS member_name \
                   FROM pg_auth_members membership \
                   JOIN pg_roles granted_role ON granted_role.oid=membership.roleid \
                   JOIN pg_roles member_role ON member_role.oid=membership.member \
                  WHERE member_role.rolname IN ( \
                      '{migrator_role}','{public_role}','{projector_role}','{payout_role}') \
             LOOP \
                 EXECUTE format('REVOKE %I FROM %I', \
                                role_membership.granted_name,role_membership.member_name); \
             END LOOP; \
         END \
         $membership_reconcile$; \
         GRANT USAGE ON SCHEMA public TO {public_role},{projector_role},{payout_role}; \
         GRANT SELECT ON deployments,backend_cursors,backend_events,chain_policies, \
             chain_safety_state,accounts,workers,mining_tokens,portal_sessions, \
             payout_destinations,payout_change_events,nonce_cursors,nonce_range_leases, \
             nonce_namespace_fences,nonce_namespace_claim_events, \
             nonce_global_range_reservations,jobs,shares,winners,winner_allocations, \
             ledger_transactions,ledger_entries,wallet_reconciliations,payout_batches, \
             payout_items,payout_reorg_events,payout_worker_leases TO {public_role}; \
         GRANT INSERT(deployment_id,id,login,password_verifier,created_at) ON accounts TO {public_role}; \
         GRANT UPDATE(failed_login_attempts,locked_until,totp_secret_sealed,totp_pending_sealed, \
             totp_pending_expires_at,security_version) ON accounts TO {public_role}; \
         GRANT INSERT(deployment_id,id,account_id,label,canonical_login,created_at) \
             ON workers TO {public_role}; \
         GRANT UPDATE(enabled,revoked_at) ON workers TO {public_role}; \
         GRANT INSERT(deployment_id,id,worker_id,verifier,created_at) \
             ON mining_tokens TO {public_role}; \
         GRANT UPDATE(revoked_at) ON mining_tokens TO {public_role}; \
         GRANT INSERT(deployment_id,token_digest,csrf_digest,account_id,security_version, \
             authenticated_at,second_factor_at,expires_at,idle_expires_at) \
             ON portal_sessions TO {public_role}; \
         GRANT UPDATE(idle_expires_at) ON portal_sessions TO {public_role}; \
         GRANT DELETE ON portal_sessions TO {public_role}; \
         GRANT INSERT,UPDATE ON nonce_cursors,nonce_range_leases,nonce_namespace_fences \
             TO {public_role}; \
         GRANT INSERT ON nonce_namespace_claim_events,nonce_global_range_reservations \
             TO {public_role}; \
         GRANT EXECUTE ON FUNCTION public.configure_payout_destination_v1( \
             UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN) TO {public_role}; \
         GRANT EXECUTE ON FUNCTION public.configure_payout_destination_v2( \
             UUID,UUID,TEXT,TEXT,TEXT,TEXT,BYTEA,BIGINT,BOOLEAN,BIGINT) TO {public_role}; \
         GRANT SELECT ON deployments,backend_cursors,backend_events,chain_policies, \
             chain_safety_state,jobs,shares,winners,winner_proofs,winner_allocations,ledger_transactions, \
             ledger_entries,payout_batches TO {projector_role}; \
         GRANT INSERT ON backend_events,jobs,shares,winners,winner_proofs,winner_allocations, \
             ledger_transactions,ledger_entries TO {projector_role}; \
         GRANT UPDATE(last_event_seq,updated_at) ON backend_cursors TO {projector_role}; \
         GRANT UPDATE(state,active_observation_event_seq,active_maturity_event_seq,active_proof_share_id) \
             ON winners TO {projector_role}; \
         GRANT UPDATE(state) ON winner_proofs TO {projector_role}; \
         GRANT UPDATE(sealed_at,sealed_entry_count) ON ledger_transactions TO {projector_role}; \
         GRANT EXECUTE ON FUNCTION public.ensure_projected_worker_v1(UUID,UUID,UUID,TEXT) \
             TO {projector_role}; \
         GRANT EXECUTE ON FUNCTION public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT) \
             TO {projector_role}; \
         GRANT EXECUTE ON FUNCTION public.lock_chain_safety_v1(UUID,TEXT) \
             TO {projector_role}; \
         GRANT SELECT ON deployments,backend_cursors,chain_policies,chain_safety_state, \
             payout_destinations,ledger_transactions,ledger_entries,wallet_reconciliations, \
             payout_batches,payout_items,payout_reorg_events,payout_watch_cursors, \
             payout_worker_leases \
             TO {payout_role}; \
         GRANT SELECT(deployment_id,event_seq,payload_sha256) ON backend_events TO {payout_role}; \
         GRANT INSERT ON wallet_reconciliations,ledger_transactions,ledger_entries, \
             payout_batches,payout_items,payout_reorg_events,payout_worker_leases TO {payout_role}; \
         GRANT UPDATE(sealed_at,sealed_entry_count) ON ledger_transactions TO {payout_role}; \
         GRANT UPDATE(reconciliation_id,ledger_root,ledger_sequence_cutoff,state,updated_at, \
             unsigned_digest,transaction_id,signed_transaction,network_fee_zat, \
             confirmation_block_hash,confirmation_height,confirmation_count) \
             ON payout_batches TO {payout_role}; \
         GRANT UPDATE(worker_instance,acquired_at,heartbeat_at,ready_at,expires_at,lease_ttl_seconds) \
             ON payout_worker_leases TO {payout_role}; \
         GRANT DELETE ON payout_worker_leases TO {payout_role}; \
         GRANT EXECUTE ON FUNCTION public.activate_due_payout_destinations_v1(UUID,TEXT) \
             TO {payout_role}; \
         GRANT EXECUTE ON FUNCTION public.freeze_chain_payouts_v1(UUID,TEXT,BIGINT,TEXT) \
             TO {payout_role}; \
         GRANT EXECUTE ON FUNCTION public.lock_backend_projection_v1(UUID) TO {payout_role}; \
         GRANT EXECUTE ON FUNCTION public.lock_chain_safety_v1(UUID,TEXT) TO {payout_role}; \
         GRANT EXECUTE ON FUNCTION public.advance_confirmed_payout_watch_cursor_v1( \
             UUID,TEXT,BIGINT,UUID,UUID) TO {payout_role}; \
         GRANT USAGE,SELECT ON SEQUENCE nonce_namespace_claim_events_event_id_seq \
             TO {public_role}; \
         GRANT USAGE,SELECT ON SEQUENCE winners_portal_sequence_seq, \
             ledger_transactions_ledger_sequence_seq TO {projector_role}; \
         GRANT USAGE,SELECT ON SEQUENCE ledger_transactions_ledger_sequence_seq, \
             payout_batches_portal_sequence_seq TO {payout_role}"
    ))
    .execute(pool)
    .await
    .expect("least-authority role fixtures install");

    let remaining_memberships = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(*) FROM pg_auth_members membership \
         JOIN pg_roles member_role ON member_role.oid=membership.member \
         WHERE member_role.rolname IN ( \
             '{migrator_role}','{public_role}','{projector_role}','{payout_role}')"
    ))
    .fetch_one(pool)
    .await
    .expect("service-role membership reconciliation reads");
    assert_eq!(
        remaining_memberships, 0,
        "service roles retain no explicit PostgreSQL memberships"
    );
    for role in [&migrator_role, &public_role, &projector_role, &payout_role] {
        let role_url = database_url_for_role(database_url, role, role_password);
        let role_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&role_url)
            .await
            .expect("membership attack role connects independently");
        let escalation = sqlx::raw_sql(&format!("SET ROLE {escalation_role}"))
            .execute(&role_pool)
            .await
            .expect_err("reconciled service role cannot SET ROLE into prior authority");
        assert_eq!(
            escalation
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("42501"),
            "{role} was denied its removed role membership"
        );
        role_pool.close().await;
    }

    for (role, table, privilege, expected) in [
        (&public_role, "deployments", "SELECT", true),
        (&public_role, "deployments", "INSERT", false),
        (&public_role, "deployments", "UPDATE", false),
        (&public_role, "chain_policies", "UPDATE", false),
        (&public_role, "chain_safety_state", "INSERT", false),
        (&public_role, "chain_safety_state", "UPDATE", false),
        (&public_role, "chain_safety_state", "DELETE", false),
        (&public_role, "backend_events", "INSERT", false),
        (&public_role, "jobs", "INSERT", false),
        (&public_role, "shares", "INSERT", false),
        (&public_role, "winners", "UPDATE", false),
        (&public_role, "winner_proofs", "SELECT", false),
        (&public_role, "winner_proofs", "INSERT", false),
        (&public_role, "winner_proofs", "UPDATE", false),
        (&public_role, "winner_proofs", "DELETE", false),
        (&public_role, "winner_allocations", "INSERT", false),
        (&public_role, "ledger_transactions", "INSERT", false),
        (&public_role, "ledger_entries", "INSERT", false),
        (&public_role, "wallet_reconciliations", "INSERT", false),
        (&public_role, "payout_destinations", "INSERT", false),
        (&public_role, "payout_destinations", "UPDATE", false),
        (&public_role, "payout_destinations", "DELETE", false),
        (&public_role, "payout_change_events", "INSERT", false),
        (&public_role, "payout_batches", "INSERT", false),
        (&public_role, "payout_batches", "UPDATE", false),
        (&public_role, "payout_items", "INSERT", false),
        (&public_role, "payout_reorg_events", "INSERT", false),
        (&public_role, "payout_watch_cursors", "SELECT", false),
        (&public_role, "payout_watch_cursors", "UPDATE", false),
        (&public_role, "payout_worker_leases", "UPDATE", false),
        (&projector_role, "backend_events", "INSERT", true),
        (&projector_role, "winner_proofs", "SELECT", true),
        (&projector_role, "winner_proofs", "INSERT", true),
        (&projector_role, "winner_proofs", "UPDATE", false),
        (&projector_role, "winner_proofs", "DELETE", false),
        (&projector_role, "ledger_entries", "INSERT", true),
        (&projector_role, "accounts", "INSERT", false),
        (&projector_role, "workers", "INSERT", false),
        (&projector_role, "mining_tokens", "INSERT", false),
        (&projector_role, "portal_sessions", "INSERT", false),
        (&projector_role, "payout_destinations", "UPDATE", false),
        (&projector_role, "payout_batches", "UPDATE", false),
        (&projector_role, "payout_watch_cursors", "SELECT", false),
        (&projector_role, "payout_watch_cursors", "UPDATE", false),
        (&payout_role, "deployments", "SELECT", true),
        (&payout_role, "deployments", "UPDATE", false),
        (&payout_role, "chain_policies", "UPDATE", false),
        (&payout_role, "chain_safety_state", "UPDATE", false),
        (&payout_role, "payout_destinations", "UPDATE", false),
        (&payout_role, "backend_events", "SELECT", false),
        (&payout_role, "winner_proofs", "SELECT", false),
        (&payout_role, "winner_proofs", "INSERT", false),
        (&payout_role, "winner_proofs", "UPDATE", false),
        (&payout_role, "winner_proofs", "DELETE", false),
        (&payout_role, "payout_watch_cursors", "SELECT", true),
        (&payout_role, "payout_watch_cursors", "INSERT", false),
        (&payout_role, "payout_watch_cursors", "UPDATE", false),
        (&payout_role, "payout_watch_cursors", "DELETE", false),
        (&payout_role, "payout_worker_leases", "INSERT", true),
        (&payout_role, "payout_worker_leases", "UPDATE", false),
        (&payout_role, "payout_worker_leases", "DELETE", true),
    ] {
        let actual = sqlx::query_scalar::<_, bool>("SELECT has_table_privilege($1,$2,$3)")
            .bind(role)
            .bind(table)
            .bind(privilege)
            .fetch_one(pool)
            .await
            .expect("table privilege resolves");
        assert_eq!(actual, expected, "{role} {privilege} privilege on {table}");
    }

    for (role, table, column, privilege, expected) in [
        (
            &public_role,
            "accounts",
            "failed_login_attempts",
            "UPDATE",
            true,
        ),
        (&public_role, "accounts", "id", "UPDATE", false),
        (&public_role, "accounts", "login", "UPDATE", false),
        (
            &public_role,
            "accounts",
            "password_verifier",
            "UPDATE",
            false,
        ),
        (&public_role, "accounts", "enabled", "UPDATE", false),
        (&public_role, "workers", "enabled", "UPDATE", true),
        (&public_role, "workers", "account_id", "UPDATE", false),
        (&public_role, "workers", "canonical_login", "UPDATE", false),
        (&public_role, "mining_tokens", "revoked_at", "UPDATE", true),
        (&public_role, "mining_tokens", "worker_id", "UPDATE", false),
        (&public_role, "mining_tokens", "verifier", "UPDATE", false),
        (&projector_role, "winner_proofs", "state", "UPDATE", true),
        (
            &projector_role,
            "winner_proofs",
            "share_id",
            "UPDATE",
            false,
        ),
        (&projector_role, "winner_proofs", "job_id", "UPDATE", false),
        (
            &projector_role,
            "winner_proofs",
            "block_hash_le",
            "UPDATE",
            false,
        ),
        (
            &projector_role,
            "winners",
            "active_proof_share_id",
            "UPDATE",
            true,
        ),
        (&projector_role, "winners", "share_id", "UPDATE", false),
        (&public_role, "winner_proofs", "state", "UPDATE", false),
        (&payout_role, "winner_proofs", "state", "UPDATE", false),
        (
            &public_role,
            "winners",
            "active_proof_share_id",
            "UPDATE",
            false,
        ),
        (
            &payout_role,
            "winners",
            "active_proof_share_id",
            "UPDATE",
            false,
        ),
        (&payout_role, "payout_batches", "state", "UPDATE", true),
        (&payout_role, "payout_batches", "chain", "UPDATE", false),
        (
            &payout_role,
            "payout_worker_leases",
            "heartbeat_at",
            "UPDATE",
            true,
        ),
        (
            &payout_role,
            "backend_events",
            "deployment_id",
            "SELECT",
            true,
        ),
        (&payout_role, "backend_events", "event_seq", "SELECT", true),
        (
            &payout_role,
            "backend_events",
            "payload_sha256",
            "SELECT",
            true,
        ),
        (&payout_role, "backend_events", "payload", "SELECT", false),
    ] {
        let actual = sqlx::query_scalar::<_, bool>("SELECT has_column_privilege($1,$2,$3,$4)")
            .bind(role)
            .bind(table)
            .bind(column)
            .bind(privilege)
            .fetch_one(pool)
            .await
            .expect("column privilege resolves");
        assert_eq!(
            actual, expected,
            "{role} {privilege} privilege on {table}.{column}"
        );
    }

    for signature in [
        "public.configure_payout_destination_v1(uuid,uuid,text,text,text,text,bytea,bigint,boolean)",
        "public.configure_payout_destination_v2(uuid,uuid,text,text,text,text,bytea,bigint,boolean,bigint)",
        "public.activate_due_payout_destinations_v1(uuid,text)",
        "public.freeze_chain_payouts_v1(uuid,text,bigint,text)",
        "public.ensure_projected_worker_v1(uuid,uuid,uuid,text)",
        "public.lock_backend_projection_v1(uuid)",
        "public.lock_chain_safety_v1(uuid,text)",
        "public.advance_confirmed_payout_watch_cursor_v1(uuid,text,bigint,uuid,uuid)",
    ] {
        let hardened = sqlx::query_scalar::<_, bool>(
            "SELECT p.prosecdef \
                    AND p.proconfig @> ARRAY['search_path=pg_catalog']::TEXT[] \
                    AND NOT EXISTS ( \
                        SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a \
                        WHERE a.grantee=0 AND a.privilege_type='EXECUTE') \
             FROM pg_proc p WHERE p.oid=to_regprocedure($1)",
        )
        .bind(signature)
        .fetch_one(pool)
        .await
        .expect("security-definer metadata resolves");
        assert!(hardened, "{signature} is definer-owned and PUBLIC-revoked");
    }
    for (role, signature, expected) in [
        (
            &public_role,
            "public.configure_payout_destination_v1(uuid,uuid,text,text,text,text,bytea,bigint,boolean)",
            true,
        ),
        (
            &public_role,
            "public.configure_payout_destination_v2(uuid,uuid,text,text,text,text,bytea,bigint,boolean,bigint)",
            true,
        ),
        (
            &public_role,
            "public.activate_due_payout_destinations_v1(uuid,text)",
            false,
        ),
        (
            &projector_role,
            "public.ensure_projected_worker_v1(uuid,uuid,uuid,text)",
            true,
        ),
        (
            &projector_role,
            "public.lock_chain_safety_v1(uuid,text)",
            true,
        ),
        (
            &projector_role,
            "public.activate_due_payout_destinations_v1(uuid,text)",
            false,
        ),
        (
            &projector_role,
            "public.advance_confirmed_payout_watch_cursor_v1(uuid,text,bigint,uuid,uuid)",
            false,
        ),
        (
            &payout_role,
            "public.activate_due_payout_destinations_v1(uuid,text)",
            true,
        ),
        (
            &payout_role,
            "public.lock_backend_projection_v1(uuid)",
            true,
        ),
        (
            &payout_role,
            "public.configure_payout_destination_v1(uuid,uuid,text,text,text,text,bytea,bigint,boolean)",
            false,
        ),
        (
            &payout_role,
            "public.configure_payout_destination_v2(uuid,uuid,text,text,text,text,bytea,bigint,boolean,bigint)",
            false,
        ),
        (
            &payout_role,
            "public.advance_confirmed_payout_watch_cursor_v1(uuid,text,bigint,uuid,uuid)",
            true,
        ),
        (
            &public_role,
            "public.advance_confirmed_payout_watch_cursor_v1(uuid,text,bigint,uuid,uuid)",
            false,
        ),
    ] {
        let actual = sqlx::query_scalar::<_, bool>("SELECT has_function_privilege($1,$2,'EXECUTE')")
            .bind(role)
            .bind(signature)
            .fetch_one(pool)
            .await
            .expect("function privilege resolves");
        assert_eq!(actual, expected, "{role} EXECUTE privilege on {signature}");
    }

    // Exercise each production capability through an independently
    // authenticated pool. This catches grant drift that has_* introspection or
    // superuser-only functional tests would otherwise hide.
    let public_url = database_url_for_role(database_url, &public_role, role_password);
    let public_store = PostgresStore::connect(&public_url, 2, role_identity.clone())
        .await
        .expect("public-role store connects");
    public_store
        .verify_deployment()
        .await
        .expect("public role verifies deployment without DML");
    let api_account = Uuid::new_v4();
    let api_password = generate_mining_token().expect("public API password material generates");
    let api_password_verifier =
        hash_mining_token(&api_password).expect("public API password hashes");
    PortalRepository::create_account(
        &public_store,
        api_account,
        "roleapi",
        &api_password_verifier,
        1_800_000_000,
    )
    .await
    .expect("public role registers through PortalRepository");
    assert_eq!(
        PortalRepository::account_by_username(&public_store, "roleapi")
            .await
            .expect("public role performs login lookup")
            .expect("registered role account exists")
            .id,
        api_account
    );
    let api_session_digest = [0x81_u8; 32];
    public_store
        .create_portal_session(NewPortalSessionRecord {
            token_digest: &api_session_digest,
            csrf_digest: &[0x82_u8; 32],
            account_id: api_account,
            security_version: 1,
            authenticated_at: 1_800_000_001,
            second_factor_at: None,
            expires_at: 1_800_003_601,
            idle_expires_at: 1_800_000_901,
        })
        .await
        .expect("public role creates login session through store API");
    assert_eq!(
        public_store
            .authenticate_portal_session(&api_session_digest, 1_800_000_002, 1_800_000_902)
            .await
            .expect("public role authenticates session through store API")
            .expect("session remains valid")
            .account_id,
        api_account
    );
    let api_worker = PortalRepository::provision_worker(
        &public_store,
        api_account,
        "roleapi",
        "rig1",
        1_800_000_003,
        Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .expect("role worker Argon2 permit"),
    )
    .await
    .expect("public role provisions worker through PortalRepository");
    assert!(public_store
        .authentication_provider(1, wcash_pool_store::MiningAuthenticationMode::Token)
        .expect("role authentication provider builds")
        .authenticate_credentials("roleapi.rig1", &api_worker.token)
        .await
        .is_ok());
    let role_destination = ValidatedDestination::from_authoritative_validation(
        Asset::Wec,
        ChainNetwork::Testnet,
        "wtestsapling1roleapipayoutdestination00000001".to_owned(),
        PortalReceiverKind::Ironwood,
    )
    .expect("role-flow destination is authoritative");
    let role_setting = PortalRepository::configure_payout(
        &public_store,
        PayoutPreferenceChange {
            account_id: api_account,
            destination: &role_destination,
            threshold_zat: 1,
            automatic: true,
            changed_at: 1,
            replacement_hold_secs: 48 * 60 * 60,
            address_digest: &[0x83_u8; 32],
        },
    )
    .await
    .expect("public role requests payout through the constrained API");
    assert!(role_setting.active_destination.is_none());
    assert_eq!(role_setting.pending_revision, Some(1));
    assert_eq!(
        PortalRepository::payout_settings(
            &public_store,
            api_account,
            ChainNetwork::Testnet,
            u64::MAX,
        )
        .await
        .expect("public role reads held payout through PortalRepository")[0]
            .pending_revision,
        Some(1)
    );
    let role_namespace =
        wcash_pool_core::NonceNamespaceLease::new(61).expect("role-flow nonce namespace is valid");
    let role_claim = public_store
        .claim_nonce_namespace(
            Uuid::new_v4(),
            NonceProfile::FourByte,
            role_namespace,
            Duration::from_secs(60),
        )
        .await
        .expect("public role claims nonce namespace through store API");
    let role_range = public_store
        .reserve_nonce_range(&role_claim, 2)
        .await
        .expect("public role reserves nonce range through store API");
    assert_eq!(role_range.end() - role_range.start(), 2);
    public_store
        .release_nonce_namespace(&role_claim)
        .await
        .expect("public role releases nonce namespace through store API");

    let projector_url = database_url_for_role(database_url, &projector_role, role_password);
    let projector_store = PostgresStore::connect(&projector_url, 2, role_identity.clone())
        .await
        .expect("projector-role store connects");
    let role_authority = authority_for(&role_identity).await;
    let role_job = job();
    let role_worker = WorkerIdentity {
        account_id: CanonicalUuid::new(Uuid::new_v4()),
        worker_id: CanonicalUuid::new(Uuid::new_v4()),
        label: "historical.z15".to_owned(),
    };
    let role_target = TargetLe::new([0x7f; 32]);
    let role_winner = winner(MergedChain::Wcash);
    let role_share_id = Hex32::new([0x91; 32]);
    let role_events = [
        BackendEvent::JobActivated {
            event_seq: 1,
            job: role_job.clone(),
        },
        BackendEvent::ShareCommitted {
            receipt: ShareReceipt {
                event_seq: 2,
                job_id: role_job.job_id.clone(),
                share_id: role_share_id.clone(),
                attribution_id: canonical_attribution_id(&role_worker, &role_target)
                    .expect("role attribution is canonical"),
                parent_hash_le: role_winner.block_hash_le.clone(),
                winners: vec![role_winner.clone()],
            },
            job_id: role_job.job_id.clone(),
            identity: role_worker.clone(),
            target_le: role_target,
        },
        BackendEvent::WinnerObserved {
            event_seq: 3,
            share_id: role_share_id,
            job_id: role_job.job_id.clone(),
            winner: role_winner.clone(),
            tip: ChainTip {
                block_hash_le: role_winner.block_hash_le.clone(),
                height: role_winner.height,
            },
            confirmations: 1,
        },
    ];
    let role_projector = projector_store.event_projector();
    for event in &role_events {
        assert_eq!(
            role_projector
                .project_event(&role_authority, event)
                .await
                .expect("projector role persists event and accounting through API"),
            ProjectionResult::Applied
        );
        assert_eq!(
            public_store
                .project_event(&role_authority, event)
                .await
                .expect("public role verifies the projector's exact payload"),
            ProjectionResult::Replayed
        );
    }
    assert!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ledger_transactions WHERE deployment_id=$1",
        )
        .bind(role_identity.id)
        .fetch_one(pool)
        .await
        .expect("role projection ledger count reads")
            > 0,
        "projector role created the winner ledger through PostgresEventProjector"
    );

    let payout_account = Uuid::new_v4();
    sqlx::query("INSERT INTO accounts(deployment_id,id,login) VALUES($1,$2,'rolepayout')")
        .bind(role_identity.id)
        .bind(payout_account)
        .execute(pool)
        .await
        .expect("role payout account fixture inserts");
    insert_destination(&role_admin_store, pool, payout_account, Chain::Wcash)
        .await
        .expect("role payout destination fixture inserts");
    credit_payable(&role_admin_store, pool, payout_account, Chain::Wcash, 100)
        .await
        .expect("role payout balance fixture inserts");
    let payout_url = database_url_for_role(database_url, &payout_role, role_password);
    let payout_store = PostgresStore::connect(&payout_url, 2, role_identity.clone())
        .await
        .expect("payout-role store connects");
    payout_store
        .project_replay_page(&role_authority, &role_events)
        .await
        .expect("payout role verifies exact projected hashes without journal DML");
    let role_reconciliation = reconcile_wallet(&payout_store, pool, Chain::Wcash)
        .await
        .expect("payout role reconciles wallet through API");
    let role_batch = payout_store
        .create_payout_batch(Chain::Wcash, Uuid::new_v4(), role_reconciliation.id)
        .await
        .expect("payout role creates batch through API");
    assert_eq!(role_batch.outputs.len(), 1);
    assert_eq!(role_batch.miner_total_zat, 100);
    assert_eq!(role_batch.payout_total_zat, 90);
    assert_eq!(role_batch.maximum_network_fee_zat, 10);
    assert_eq!(role_batch.outputs[0].account_id, payout_account);
    assert_eq!(role_batch.outputs[0].liability_amount_zat, 100);
    assert_eq!(role_batch.outputs[0].amount_zat, 90);
    payout_store
        .authorize_payout_signing(role_batch.id)
        .await
        .expect("payout role durably authorizes signing through API");
    payout_store
        .mark_payout_signed(role_batch.id, &[0xa1; 32], &[0xa2; 32], &[0xa3, 0xa4], 1)
        .await
        .expect("payout role persists a signed artifact through API");
    payout_store
        .authorize_payout_broadcast(role_batch.id)
        .await
        .expect("payout role durably authorizes broadcast through API");
    payout_store
        .mark_payout_broadcast(role_batch.id)
        .await
        .expect("payout role marks the batch broadcast through API");
    payout_store
        .confirm_payout(
            role_batch.id,
            &PayoutConfirmation {
                block_hash: [0xa5; 32],
                block_height: 50_001,
                confirmations: 100,
            },
        )
        .await
        .expect("payout role confirms the batch through API");
    let role_watch_page = payout_store
        .list_payout_watches(Chain::Wcash, 8)
        .await
        .expect("payout role reads the confirmed watch page through API");
    let role_watch_cursor = role_watch_page
        .confirmed_cursor
        .as_ref()
        .expect("confirmed role batch produces a durable watch cursor");
    assert_eq!(role_watch_cursor.checked_through_batch_id, role_batch.id);
    payout_store
        .advance_confirmed_payout_watch_cursor(Chain::Wcash, role_watch_cursor)
        .await
        .expect("payout role advances the confirmed watch cursor through API");
    let persisted_role_watch = sqlx::query(
        "SELECT last_confirmed_batch_id,generation FROM payout_watch_cursors \
         WHERE deployment_id=$1 AND chain='wcash'",
    )
    .bind(role_identity.id)
    .fetch_one(pool)
    .await
    .expect("persisted payout-role watch cursor reads");
    assert_eq!(
        persisted_role_watch
            .try_get::<Option<Uuid>, _>("last_confirmed_batch_id")
            .expect("persisted cursor batch decodes"),
        Some(role_batch.id)
    );
    assert_eq!(
        persisted_role_watch
            .try_get::<i64, _>("generation")
            .expect("persisted cursor generation decodes"),
        1
    );
    let role_payout_worker = Uuid::new_v4();
    assert!(payout_store
        .acquire_payout_worker(role_payout_worker, Duration::from_secs(2_100))
        .await
        .expect("payout role acquires lease through API"));
    assert!(payout_store
        .mark_payout_worker_ready(role_payout_worker)
        .await
        .expect("payout role marks lease ready through API"));
    assert!(payout_store
        .release_payout_worker(role_payout_worker)
        .await
        .expect("payout role releases lease through API"));

    let account_id = Uuid::new_v4();
    let account_login = format!("acl_{}", &suffix[..16]);
    let password_material = generate_mining_token().expect("ACL password material generates");
    let password_verifier = hash_mining_token(&password_material).expect("ACL password hashes");
    let worker_id = Uuid::new_v4();
    let mining_material = generate_mining_token().expect("ACL mining material generates");
    let mining_verifier = hash_mining_token(&mining_material).expect("ACL mining token hashes");
    let token_digest = [0x61_u8; 32];

    let mut public_connection = pool
        .acquire()
        .await
        .expect("dedicated public ACL connection checks out");
    sqlx::raw_sql(&format!("SET ROLE {public_role}"))
        .execute(&mut *public_connection)
        .await
        .expect("public fixture role activates");
    sqlx::query(
        "INSERT INTO accounts(deployment_id,id,login,password_verifier) VALUES($1,$2,$3,$4)",
    )
    .bind(deployment_id)
    .bind(account_id)
    .bind(&account_login)
    .bind(password_verifier)
    .execute(&mut *public_connection)
    .await
    .expect("public role may register a constrained portal account");
    sqlx::query(
        "INSERT INTO workers(deployment_id,id,account_id,label,canonical_login) \
         VALUES($1,$2,$3,'rig1',$4)",
    )
    .bind(deployment_id)
    .bind(worker_id)
    .bind(account_id)
    .bind(format!("{account_login}.rig1"))
    .execute(&mut *public_connection)
    .await
    .expect("public role may create one owned worker");
    sqlx::query(
        "INSERT INTO mining_tokens(deployment_id,id,worker_id,verifier) VALUES($1,$2,$3,$4)",
    )
    .bind(deployment_id)
    .bind(mining_material.id())
    .bind(worker_id)
    .bind(mining_verifier)
    .execute(&mut *public_connection)
    .await
    .expect("public role may create a revocable mining credential");
    sqlx::query(
        "INSERT INTO portal_sessions( \
             deployment_id,token_digest,csrf_digest,account_id,security_version,authenticated_at, \
             expires_at,idle_expires_at) \
         VALUES($1,$2,$3,$4,1,clock_timestamp(),clock_timestamp()+INTERVAL '1 hour', \
                clock_timestamp()+INTERVAL '15 minutes')",
    )
    .bind(deployment_id)
    .bind(token_digest.as_slice())
    .bind([0x62_u8; 32].as_slice())
    .bind(account_id)
    .execute(&mut *public_connection)
    .await
    .expect("public role may establish a bounded login session");
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT a.login FROM portal_sessions s JOIN accounts a \
             ON (a.deployment_id,a.id)=(s.deployment_id,s.account_id) \
             WHERE s.deployment_id=$1 AND s.token_digest=$2",
        )
        .bind(deployment_id)
        .bind(token_digest.as_slice())
        .fetch_one(&mut *public_connection)
        .await
        .expect("public role may authenticate its exact session"),
        account_login
    );
    for (statement, purpose) in [
        (
            "INSERT INTO backend_events(deployment_id,event_seq,event_kind,payload,payload_sha256) \
             VALUES ('00000000-0000-0000-0000-000000000001',999,'forged','{}',decode(repeat('11',32),'hex'))",
            "inject a backend event",
        ),
        (
            "INSERT INTO ledger_transactions(deployment_id,id,chain,kind,reference) \
             VALUES ('00000000-0000-0000-0000-000000000001',gen_random_uuid(),'wcash', \
                     'operator_capital_funded','forged')",
            "manufacture a ledger transaction",
        ),
        (
            "UPDATE payout_destinations SET state='active' WHERE FALSE",
            "activate a held destination directly",
        ),
        (
            "UPDATE payout_destinations SET address='wtestforged',address_digest=decode(repeat('22',32),'hex'), \
                     payout_threshold_zat=1,active_after=clock_timestamp() WHERE FALSE",
            "rewrite payout destination facts",
        ),
        (
            "INSERT INTO payout_change_events(deployment_id,id,account_id,chain,address_digest, \
             payout_threshold_zat,automatic,requested_at,active_after,revision) \
             VALUES ('00000000-0000-0000-0000-000000000001',gen_random_uuid(),gen_random_uuid(), \
                     'wcash',decode(repeat('33',32),'hex'),1,TRUE,clock_timestamp(),clock_timestamp(),1)",
            "forge a payout audit event",
        ),
        (
            "UPDATE payout_batches SET state='confirmed' WHERE FALSE",
            "mutate a payout lifecycle",
        ),
        (
            "UPDATE payout_watch_cursors SET generation=generation+1 WHERE FALSE",
            "rewrite the confirmed-payout watch cursor directly",
        ),
        (
            "SELECT public.advance_confirmed_payout_watch_cursor_v1( \
                 '00000000-0000-0000-0000-000000000001','wcash',0,NULL, \
                 '00000000-0000-0000-0000-000000000002')",
            "invoke the payout-only confirmed-watch cursor transition",
        ),
        (
            "UPDATE chain_safety_state SET payouts_frozen=FALSE WHERE FALSE",
            "clear payout safety state",
        ),
        (
            "UPDATE accounts SET id=gen_random_uuid() WHERE FALSE",
            "reassign an account identity",
        ),
        (
            "UPDATE workers SET account_id=gen_random_uuid() WHERE FALSE",
            "reassign worker ownership",
        ),
        (
            "UPDATE mining_tokens SET verifier='$argon2id$forged' WHERE FALSE",
            "replace a mining verifier",
        ),
    ] {
        let error = sqlx::raw_sql(statement)
            .execute(&mut *public_connection)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database| database.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("42501"),
            "public role was denied when attempting to {purpose}"
        );
    }
    let lower =
        sqlx::query_scalar::<_, i64>("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
            .fetch_one(&mut *public_connection)
            .await
            .expect("public DB clock fence reads");
    sqlx::query_scalar::<_, Uuid>(
        "SELECT public.configure_payout_destination_v1( \
             $1,$2,'wcash','testnet',$3,'ironwood',$4,100,TRUE)",
    )
    .bind(deployment_id)
    .bind(account_id)
    .bind("wtestsapling1aclboundarydestination0000000001")
    .bind([0x51_u8; 32].as_slice())
    .fetch_one(&mut *public_connection)
    .await
    .expect("public role may request only a held destination through the routine");
    let early_activation = sqlx::query_scalar::<_, i64>(
        "SELECT public.activate_due_payout_destinations_v1($1,'wcash')",
    )
    .bind(deployment_id)
    .fetch_one(&mut *public_connection)
    .await
    .expect_err("public role cannot invoke the payout-only promotion routine");
    assert_eq!(
        early_activation
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *public_connection)
        .await
        .expect("public fixture role resets");
    drop(public_connection);

    let held = sqlx::query(
        "SELECT state, \
                FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT AS created_at, \
                FLOOR(EXTRACT(EPOCH FROM active_after))::BIGINT AS active_after \
         FROM payout_destinations WHERE deployment_id=$1 AND account_id=$2",
    )
    .bind(deployment_id)
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("held destination reads");
    assert_eq!(held.get::<String, _>("state"), "pending");
    assert!(held.get::<i64, _>("created_at") >= lower);
    assert_eq!(
        held.get::<i64, _>("active_after") - held.get::<i64, _>("created_at"),
        48 * 60 * 60,
        "even a first destination receives the exact database-clock hold"
    );

    let mut projection = pool
        .begin()
        .await
        .expect("projector ACL transaction begins");
    sqlx::raw_sql(&format!("SET LOCAL ROLE {projector_role}"))
        .execute(&mut *projection)
        .await
        .expect("projector fixture role activates");
    sqlx::query(
        "INSERT INTO backend_events(deployment_id,event_seq,event_kind,payload,payload_sha256) \
         VALUES($1,4,'job_activated','{}',$2)",
    )
    .bind(deployment_id)
    .bind([0x71_u8; 32].as_slice())
    .execute(&mut *projection)
    .await
    .expect("isolated projector may persist an exact backend event");
    sqlx::query(
        "INSERT INTO jobs(deployment_id,job_id,activation_event_seq,descriptor) \
         VALUES($1,$2,4,'{}')",
    )
    .bind(deployment_id)
    .bind([0x72_u8; 32].as_slice())
    .execute(&mut *projection)
    .await
    .expect("isolated projector may persist derived job state");
    sqlx::query("UPDATE backend_cursors SET last_event_seq=4 WHERE deployment_id=$1")
        .bind(deployment_id)
        .execute(&mut *projection)
        .await
        .expect("isolated projector may advance only the durable cursor columns");
    sqlx::query("SELECT public.ensure_projected_worker_v1($1,$2,$3,'historical2.z15')")
        .bind(deployment_id)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&mut *projection)
        .await
        .expect("isolated projector may create only inert historical attribution");
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT public.lock_chain_safety_v1($1,'wcash')")
            .bind(deployment_id)
            .fetch_one(&mut *projection)
            .await
            .expect("isolated projector acquires chain safety lock through constrained routine")
    );
    let projector_cursor_read =
        sqlx::query("SELECT generation FROM payout_watch_cursors WHERE deployment_id=$1")
            .bind(deployment_id)
            .fetch_optional(&mut *projection)
            .await
            .expect_err("projector credential cannot read payout watch state");
    assert_eq!(
        projector_cursor_read
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );
    projection
        .rollback()
        .await
        .expect("projector ACL fixture leaves the live cursor untouched");

    let mut projector_attack_connection = pool
        .acquire()
        .await
        .expect("dedicated projector attack connection checks out");
    sqlx::raw_sql(&format!("SET ROLE {projector_role}"))
        .execute(&mut *projector_attack_connection)
        .await
        .expect("projector attack fixture role activates");
    let projector_cursor_advance =
        sqlx::query("SELECT public.advance_confirmed_payout_watch_cursor_v1($1,'wcash',0,NULL,$2)")
            .bind(deployment_id)
            .bind(Uuid::new_v4())
            .execute(&mut *projector_attack_connection)
            .await
            .expect_err("projector credential cannot advance payout watch state");
    assert_eq!(
        projector_cursor_advance
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *projector_attack_connection)
        .await
        .expect("projector attack fixture role resets");
    drop(projector_attack_connection);

    let mut payout_connection = pool
        .acquire()
        .await
        .expect("dedicated payout ACL connection checks out");
    sqlx::raw_sql(&format!("SET ROLE {payout_role}"))
        .execute(&mut *payout_connection)
        .await
        .expect("payout fixture role activates");
    let payout_mutation = sqlx::query(
        "UPDATE payout_destinations SET address='wtestforged', \
             address_digest=decode(repeat('44',32),'hex'),payout_threshold_zat=1, \
             active_after=clock_timestamp(),state='active' WHERE deployment_id=$1",
    )
    .bind(deployment_id)
    .execute(&mut *payout_connection)
    .await
    .expect_err("payout credential cannot rewrite destination facts or state directly");
    assert_eq!(
        payout_mutation
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );
    let payout_cursor_mutation =
        sqlx::query("UPDATE payout_watch_cursors SET generation=generation+1 WHERE FALSE")
            .execute(&mut *payout_connection)
            .await
            .expect_err("payout credential cannot rewrite its watch cursor directly");
    assert_eq!(
        payout_cursor_mutation
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT public.activate_due_payout_destinations_v1($1,'wcash')",
        )
        .bind(deployment_id)
        .fetch_one(&mut *payout_connection)
        .await
        .expect("payout role may run the constrained activation routine"),
        0,
        "the constrained routine cannot promote a destination before its hold"
    );
    let payout_worker = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payout_worker_leases( \
             deployment_id,worker_instance,expires_at,lease_ttl_seconds) \
         VALUES($1,$2,clock_timestamp()+INTERVAL '2100 seconds',2100)",
    )
    .bind(deployment_id)
    .bind(payout_worker)
    .execute(&mut *payout_connection)
    .await
    .expect("isolated payout role may acquire its lease");
    sqlx::query(
        "UPDATE payout_worker_leases SET heartbeat_at=clock_timestamp(), \
             ready_at=clock_timestamp(),expires_at=clock_timestamp()+INTERVAL '2100 seconds' \
         WHERE deployment_id=$1 AND worker_instance=$2",
    )
    .bind(deployment_id)
    .bind(payout_worker)
    .execute(&mut *payout_connection)
    .await
    .expect("isolated payout role may heartbeat its exact lease columns");
    sqlx::query("DELETE FROM payout_worker_leases WHERE deployment_id=$1 AND worker_instance=$2")
        .bind(deployment_id)
        .bind(payout_worker)
        .execute(&mut *payout_connection)
        .await
        .expect("isolated payout role may release its lease");
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *payout_connection)
        .await
        .expect("payout fixture role resets");
    drop(payout_connection);
    sqlx::raw_sql(&format!(
        "DROP OWNED BY {migrator_role}; DROP OWNED BY {public_role}; \
         DROP OWNED BY {projector_role}; DROP OWNED BY {payout_role}; \
         DROP OWNED BY {escalation_role}; DROP ROLE {migrator_role}; \
         DROP ROLE {public_role}; DROP ROLE {projector_role}; \
         DROP ROLE {payout_role}; DROP ROLE {escalation_role}"
    ))
    .execute(pool)
    .await
    .expect("privilege fixture roles clean up");
}

async fn assert_winner_depth_regression_is_reversible(pool: &sqlx::PgPool, database_url: &str) {
    let regression_identity = identity(91);
    let store = PostgresStore::connect(database_url, 2, regression_identity.clone())
        .await
        .expect("depth-regression store connects");
    store
        .bind_deployment()
        .await
        .expect("depth-regression deployment binds");
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("depth-regression policies bind");
    let authority = authority_for(&regression_identity).await;
    let projector = store.event_projector();
    let descriptor = job();
    let event_worker = WorkerIdentity {
        account_id: CanonicalUuid::new(Uuid::new_v4()),
        worker_id: CanonicalUuid::new(Uuid::new_v4()),
        label: "regression.z15".to_owned(),
    };
    let target = TargetLe::new([0x7f; 32]);
    let share_id = Hex32::new([0x92; 32]);
    let wcash_winner = winner(MergedChain::Wcash);
    let receipt = ShareReceipt {
        event_seq: 2,
        job_id: descriptor.job_id.clone(),
        share_id: share_id.clone(),
        attribution_id: canonical_attribution_id(&event_worker, &target)
            .expect("regression attribution is canonical"),
        parent_hash_le: Hex32::new([0x93; 32]),
        winners: vec![wcash_winner.clone()],
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
            target_le: target,
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
        BackendEvent::WinnerMatured {
            event_seq: 4,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0x94; 32]),
                height: wcash_winner.height + 99,
            },
            confirmations: 100,
        },
        BackendEvent::WinnerObserved {
            event_seq: 5,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0x95; 32]),
                height: wcash_winner.height + 49,
            },
            confirmations: 50,
        },
        BackendEvent::WinnerObserved {
            event_seq: 6,
            share_id: share_id.clone(),
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0x96; 32]),
                height: wcash_winner.height + 59,
            },
            confirmations: 60,
        },
        BackendEvent::WinnerMatured {
            event_seq: 7,
            share_id,
            job_id: descriptor.job_id.clone(),
            winner: wcash_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0x97; 32]),
                height: wcash_winner.height + 99,
            },
            confirmations: 100,
        },
    ];
    for (index, event) in events.iter().enumerate() {
        assert_eq!(
            projector
                .project_event(&authority, event)
                .await
                .expect("canonical depth transition projects"),
            ProjectionResult::Applied
        );
        if index == 4 {
            let dematured = sqlx::query(
                "SELECT state,active_observation_event_seq,active_maturity_event_seq \
                 FROM winners WHERE deployment_id=$1 AND chain='wcash' AND block_hash_le=$2",
            )
            .bind(store.deployment_id())
            .bind(wcash_winner.block_hash_le.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .expect("dematured winner state reads");
            assert_eq!(dematured.get::<String, _>("state"), "observed");
            assert_eq!(dematured.get::<i64, _>("active_observation_event_seq"), 3);
            assert_eq!(
                dematured.get::<Option<i64>, _>("active_maturity_event_seq"),
                None
            );
            let balances = sqlx::query(
                "SELECT ledger_account,SUM(amount_zat)::BIGINT AS balance \
                 FROM ledger_entries WHERE deployment_id=$1 AND account_id=$2 \
                 GROUP BY ledger_account",
            )
            .bind(store.deployment_id())
            .bind(event_worker.account_id.get())
            .fetch_all(pool)
            .await
            .expect("dematured balances read");
            let balance = |account: &str| {
                balances
                    .iter()
                    .find(|row| row.get::<String, _>("ledger_account") == account)
                    .map_or(0, |row| row.get::<i64, _>("balance"))
            };
            assert_eq!(
                balance("miner_immature"),
                -i64::try_from(wcash_winner.reward_zat).expect("reward fits ledger")
            );
            assert_eq!(balance("miner_payable"), 0);
            assert!(!sqlx::query_scalar::<_, bool>(
                "SELECT payouts_frozen FROM chain_safety_state \
                 WHERE deployment_id=$1 AND chain='wcash'",
            )
            .bind(store.deployment_id())
            .fetch_one(pool)
            .await
            .expect("unexposed dematurity safety state reads"));
        }
    }

    let winner_row = sqlx::query(
        "SELECT state,active_observation_event_seq,active_maturity_event_seq \
         FROM winners WHERE deployment_id=$1 AND chain='wcash' AND block_hash_le=$2",
    )
    .bind(store.deployment_id())
    .bind(wcash_winner.block_hash_le.as_bytes().as_slice())
    .fetch_one(pool)
    .await
    .expect("regression winner state reads");
    assert_eq!(winner_row.get::<String, _>("state"), "matured");
    assert_eq!(winner_row.get::<i64, _>("active_observation_event_seq"), 3);
    assert_eq!(winner_row.get::<i64, _>("active_maturity_event_seq"), 7);
    let ledger_kinds = sqlx::query(
        "SELECT kind,COUNT(*)::BIGINT AS count FROM ledger_transactions \
         WHERE deployment_id=$1 GROUP BY kind ORDER BY kind",
    )
    .bind(store.deployment_id())
    .fetch_all(pool)
    .await
    .expect("regression ledger history reads");
    let count = |kind: &str| {
        ledger_kinds
            .iter()
            .find(|row| row.get::<String, _>("kind") == kind)
            .map_or(0, |row| row.get::<i64, _>("count"))
    };
    assert_eq!(count("winner_observed"), 1);
    assert_eq!(count("winner_matured"), 2);
    assert_eq!(count("winner_dematured"), 1);
    let miner_balances = sqlx::query(
        "SELECT ledger_account,SUM(amount_zat)::BIGINT AS balance FROM ledger_entries \
         WHERE deployment_id=$1 AND account_id=$2 GROUP BY ledger_account",
    )
    .bind(store.deployment_id())
    .bind(event_worker.account_id.get())
    .fetch_all(pool)
    .await
    .expect("regression balances read");
    let balance = |account: &str| {
        miner_balances
            .iter()
            .find(|row| row.get::<String, _>("ledger_account") == account)
            .map_or(0, |row| row.get::<i64, _>("balance"))
    };
    assert_eq!(balance("miner_immature"), 0);
    assert_eq!(
        balance("miner_payable"),
        -i64::try_from(wcash_winner.reward_zat).expect("reward fits ledger")
    );

    // Race a payout reservation against canonical dematurity. The backend
    // cursor and chain-safety locks must make the result binary: either no
    // reservation is exposed, or a reservation exists and payouts are frozen.
    let exposure_identity = identity(96);
    let exposure_store = PostgresStore::connect(database_url, 4, exposure_identity.clone())
        .await
        .expect("exposure-race store connects");
    exposure_store
        .bind_deployment()
        .await
        .expect("exposure-race deployment binds");
    exposure_store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("exposure-race policies bind");
    let exposure_authority = authority_for(&exposure_identity).await;
    let exposure_projector = exposure_store.event_projector();
    let exposure_descriptor = job();
    let exposure_worker = WorkerIdentity {
        account_id: CanonicalUuid::new(Uuid::new_v4()),
        worker_id: CanonicalUuid::new(Uuid::new_v4()),
        label: "exposure.z15".to_owned(),
    };
    let exposure_target = TargetLe::new([0x7f; 32]);
    let exposure_share_id = Hex32::new([0x98; 32]);
    let exposure_winner = winner(MergedChain::Wcash);
    let exposure_receipt = ShareReceipt {
        event_seq: 2,
        job_id: exposure_descriptor.job_id.clone(),
        share_id: exposure_share_id.clone(),
        attribution_id: canonical_attribution_id(&exposure_worker, &exposure_target)
            .expect("exposure attribution is canonical"),
        parent_hash_le: Hex32::new([0x99; 32]),
        winners: vec![exposure_winner.clone()],
    };
    let exposure_events = [
        BackendEvent::JobActivated {
            event_seq: 1,
            job: exposure_descriptor.clone(),
        },
        BackendEvent::ShareCommitted {
            receipt: exposure_receipt,
            job_id: exposure_descriptor.job_id.clone(),
            identity: exposure_worker.clone(),
            target_le: exposure_target,
        },
        BackendEvent::WinnerObserved {
            event_seq: 3,
            share_id: exposure_share_id.clone(),
            job_id: exposure_descriptor.job_id.clone(),
            winner: exposure_winner.clone(),
            tip: ChainTip {
                block_hash_le: exposure_winner.block_hash_le.clone(),
                height: exposure_winner.height,
            },
            confirmations: 1,
        },
        BackendEvent::WinnerMatured {
            event_seq: 4,
            share_id: exposure_share_id.clone(),
            job_id: exposure_descriptor.job_id.clone(),
            winner: exposure_winner.clone(),
            tip: ChainTip {
                block_hash_le: Hex32::new([0x9a; 32]),
                height: exposure_winner.height + 99,
            },
            confirmations: 100,
        },
    ];
    for event in &exposure_events {
        assert_eq!(
            exposure_projector
                .project_event(&exposure_authority, event)
                .await
                .expect("exposure fixture projects"),
            ProjectionResult::Applied
        );
    }
    insert_destination(
        &exposure_store,
        pool,
        exposure_worker.account_id.get(),
        Chain::Wcash,
    )
    .await
    .expect("exposure payout destination seeds");
    let exposure_checkpoint = reconcile_wallet(&exposure_store, pool, Chain::Wcash)
        .await
        .expect("exposure collector reconciles");
    let demature = BackendEvent::WinnerObserved {
        event_seq: 5,
        share_id: exposure_share_id,
        job_id: exposure_descriptor.job_id,
        winner: exposure_winner.clone(),
        tip: ChainTip {
            block_hash_le: Hex32::new([0x9b; 32]),
            height: exposure_winner.height + 49,
        },
        confirmations: 50,
    };
    let (batch_result, projection_result) = tokio::join!(
        exposure_store.create_payout_batch(Chain::Wcash, Uuid::new_v4(), exposure_checkpoint.id,),
        exposure_projector.project_event(&exposure_authority, &demature),
    );
    assert_eq!(
        projection_result.expect("racing dematurity projects"),
        ProjectionResult::Applied
    );
    let exposed = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM payout_batches \
         WHERE deployment_id=$1 AND chain='wcash' AND state <> 'cancelled')",
    )
    .bind(exposure_store.deployment_id())
    .fetch_one(pool)
    .await
    .expect("exposure outcome reads");
    assert_eq!(batch_result.is_ok(), exposed);
    let safety = sqlx::query(
        "SELECT payouts_frozen,frozen_by_backend_event_seq,freeze_reason \
         FROM chain_safety_state WHERE deployment_id=$1 AND chain='wcash'",
    )
    .bind(exposure_store.deployment_id())
    .fetch_one(pool)
    .await
    .expect("exposure safety outcome reads");
    assert_eq!(safety.get::<bool, _>("payouts_frozen"), exposed);
    if exposed {
        assert_eq!(safety.get::<i64, _>("frozen_by_backend_event_seq"), 5);
        assert_eq!(
            safety.get::<String, _>("freeze_reason"),
            "matured_winner_depth_regression"
        );
    }

    let policy_identity = identity(98);
    let policy_store = PostgresStore::connect(database_url, 1, policy_identity.clone())
        .await
        .expect("policy-fence store connects");
    policy_store
        .bind_deployment()
        .await
        .expect("policy-fence deployment binds");
    let mut incompatible = policy(Chain::Wcash);
    incompatible.required_confirmations = 101;
    policy_store
        .bind_zero_fee_launch_policies(&incompatible, &policy(Chain::Zcash))
        .await
        .expect("individually valid policies bind");
    let policy_authority = authority_for(&policy_identity).await;
    assert!(matches!(
        policy_store
            .event_projector()
            .project_event(
                &policy_authority,
                &BackendEvent::JobActivated {
                    event_seq: 1,
                    job: descriptor,
                },
            )
            .await,
        Err(StoreError::WinnerMaturityPolicyMismatch {
            chain: Chain::Wcash,
            advertised: 100,
            configured: 101,
        })
    ));
    assert_eq!(
        policy_store
            .last_event_seq()
            .await
            .expect("rejected policy leaves cursor readable"),
        0
    );
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL service in required CI"]
#[allow(clippy::expect_used)]
async fn durable_runtime_is_chain_scoped_conserved_and_revocable() {
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL")
        .expect("ignored PostgreSQL integration test requires WCASH_POOL_TEST_DATABASE_URL");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("isolated PostgreSQL is available");
    assert_nonce_fencing_migration_preserves_legacy_floor(&admin).await;
    assert_portal_winner_migration_backfills_existing_rows(&admin).await;
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&admin)
        .await
        .expect("isolated schema can be reset");

    let store_identity = identity(11);
    let store = PostgresStore::connect(&database_url, 4, store_identity.clone())
        .await
        .expect("store connects");
    store.migrate().await.expect("schema migrates");
    assert_default_acl_upgrade_reconciliation(&admin).await;
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
    store
        .verify_deployment()
        .await
        .expect("runtime identity verifies without writes");
    store
        .verify_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("runtime policies verify without writes");
    assert_full_balance_payout_is_miner_fee_funded(&database_url, &admin, Chain::Wcash, 81).await;
    assert_full_balance_payout_is_miner_fee_funded(&database_url, &admin, Chain::Zcash, 82).await;
    assert_due_preferences_survive_empty_payout_selection(&database_url, &admin).await;
    assert_database_privilege_boundaries(&admin, &database_url).await;
    assert_winner_depth_regression_is_reversible(&admin, &database_url).await;
    let mut mismatched_identity = store_identity.clone();
    mismatched_identity.chain_id = mismatched_identity
        .chain_id
        .checked_add(1)
        .expect("fixture chain ID has room");
    let mismatched_store = PostgresStore::connect(&database_url, 1, mismatched_identity)
        .await
        .expect("mismatched verifier connects read-only");
    assert!(matches!(
        mismatched_store.verify_deployment().await,
        Err(StoreError::DeploymentIdentityMismatch)
    ));
    let mut mismatched_policy = policy(Chain::Wcash);
    mismatched_policy.payout_threshold_zat = 2;
    assert!(matches!(
        store
            .verify_zero_fee_launch_policies(&mismatched_policy, &policy(Chain::Zcash))
            .await,
        Err(StoreError::ChainPolicyMismatch)
    ));

    assert!(!store
        .payout_worker_is_live()
        .await
        .expect("an absent payout lease is not live"));
    assert!(matches!(
        store
            .acquire_payout_worker(Uuid::new_v4(), Duration::from_secs(3_601))
            .await,
        Err(StoreError::InvalidPayoutWorkerLease)
    ));
    let worker_a = Uuid::new_v4();
    let worker_b = Uuid::new_v4();
    let (acquired_a, acquired_b) = tokio::join!(
        store.acquire_payout_worker(worker_a, Duration::from_secs(2_100)),
        store.acquire_payout_worker(worker_b, Duration::from_secs(2_100)),
    );
    let acquired_a = acquired_a.expect("first concurrent lease attempt completes");
    let acquired_b = acquired_b.expect("second concurrent lease attempt completes");
    assert_ne!(acquired_a, acquired_b, "exactly one concurrent owner wins");
    let (owner, successor) = if acquired_a {
        (worker_a, worker_b)
    } else {
        (worker_b, worker_a)
    };
    assert!(!store
        .payout_worker_is_live()
        .await
        .expect("acquisition alone is only starting"));
    assert!(!store
        .mark_payout_worker_ready(successor)
        .await
        .expect("non-owner readiness attempt is rejected"));
    assert!(store
        .mark_payout_worker_ready(owner)
        .await
        .expect("exact owner becomes ready"));
    assert!(store
        .payout_worker_is_live()
        .await
        .expect("ready owner is live"));
    let lease_restart = PostgresStore::connect(&database_url, 1, store_identity.clone())
        .await
        .expect("lease observer reconnects after restart");
    assert!(lease_restart
        .payout_worker_is_live()
        .await
        .expect("ready lease survives process restart"));
    assert!(!lease_restart
        .acquire_payout_worker(successor, Duration::from_secs(2_100))
        .await
        .expect("replacement attempt observes the live exclusivity fence"));
    assert!(!store
        .payout_worker_is_live()
        .await
        .expect("replacement startup withdraws predecessor readiness"));
    assert!(store
        .heartbeat_payout_worker(owner)
        .await
        .expect("predecessor retains exclusive authority while it drains"));
    assert!(!lease_restart
        .payout_worker_is_live()
        .await
        .expect("an ownership heartbeat cannot republish withdrawn readiness"));
    assert!(store
        .mark_payout_worker_ready(owner)
        .await
        .expect("fixture restores predecessor readiness for explicit drain coverage"));
    assert!(store
        .mark_payout_worker_not_ready(owner)
        .await
        .expect("owner withdraws readiness before drain"));
    assert!(!lease_restart
        .payout_worker_is_live()
        .await
        .expect("not-ready lease remains unavailable"));
    assert!(store
        .mark_payout_worker_ready(owner)
        .await
        .expect("owner can publish readiness again"));
    sqlx::query(
        "UPDATE payout_worker_leases SET \
           acquired_at=clock_timestamp()-INTERVAL '120 seconds', \
           heartbeat_at=clock_timestamp()-INTERVAL '61 seconds', \
           ready_at=clock_timestamp()-INTERVAL '60 seconds' \
         WHERE deployment_id=$1 AND worker_instance=$2",
    )
    .bind(store.deployment_id())
    .bind(owner)
    .execute(&admin)
    .await
    .expect("fixture ages only the independent readiness heartbeat");
    assert!(!store
        .payout_worker_is_live()
        .await
        .expect("stale heartbeat disables public readiness before takeover"));
    assert!(store
        .heartbeat_payout_worker(owner)
        .await
        .expect("exact owner refreshes its heartbeat"));
    assert!(store
        .payout_worker_is_live()
        .await
        .expect("fresh heartbeat restores a ready owner"));
    sqlx::query(
        "UPDATE payout_worker_leases SET \
           acquired_at=clock_timestamp()-INTERVAL '2200 seconds', \
           heartbeat_at=clock_timestamp()-INTERVAL '2101 seconds', \
           ready_at=clock_timestamp()-INTERVAL '2100 seconds', \
           expires_at=clock_timestamp()-INTERVAL '1 second' \
         WHERE deployment_id=$1 AND worker_instance=$2",
    )
    .bind(store.deployment_id())
    .bind(owner)
    .execute(&admin)
    .await
    .expect("fixture expires the takeover fence using database time");
    assert!(store
        .acquire_payout_worker(successor, Duration::from_secs(2_100))
        .await
        .expect("stale lease is taken over"));
    assert!(!store
        .payout_worker_is_live()
        .await
        .expect("takeover resets readiness"));
    assert!(!store
        .heartbeat_payout_worker(owner)
        .await
        .expect("superseded owner cannot heartbeat"));
    assert!(!store
        .release_payout_worker(owner)
        .await
        .expect("superseded owner cannot release successor"));
    assert!(store
        .mark_payout_worker_ready(successor)
        .await
        .expect("successor explicitly becomes ready"));
    assert!(store
        .release_payout_worker(successor)
        .await
        .expect("exact owner releases its lease"));
    assert!(!store
        .payout_worker_is_live()
        .await
        .expect("released lease is not live"));
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
    let projector = store.event_projector();
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
    for (index, event) in events.iter().enumerate() {
        assert_eq!(
            projector
                .project_event(&authority, event)
                .await
                .expect("authoritative event projects atomically"),
            ProjectionResult::Applied
        );
        assert_eq!(
            store
                .project_event(&authority, event)
                .await
                .expect("public consumer verifies the exact persisted event"),
            ProjectionResult::Replayed
        );
        if index == 1 {
            let submitted = PortalRepository::found_blocks(
                &store,
                event_worker.account_id.get(),
                PageRequest {
                    before: None,
                    limit: 10,
                },
            )
            .await
            .expect("submitted winners are immediately visible");
            assert_eq!(submitted.items.len(), 2);
            assert!(submitted
                .items
                .iter()
                .all(|winner| winner.state == "submitted"));
            let not_allocated = PortalRepository::reward_history(
                &store,
                event_worker.account_id.get(),
                PageRequest {
                    before: None,
                    limit: 10,
                },
            )
            .await
            .expect("reward projection is proven empty before observation");
            assert!(not_allocated.items.is_empty());
        }
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
    let mature_balances = PortalRepository::balances(&store, event_worker.account_id.get())
        .await
        .expect("mature private balances load");
    let mature_wec = mature_balances
        .iter()
        .find(|balance| balance.asset == Asset::Wec)
        .expect("mature WEC balance exists");
    assert_eq!(mature_wec.total_zat, 0);
    let mature_zec = mature_balances
        .iter()
        .find(|balance| balance.asset == Asset::Zec)
        .expect("mature ZEC balance exists");
    assert_eq!(mature_zec.immature_zat, 0);
    assert_eq!(mature_zec.payable_zat, zcash_winner.reward_zat);
    assert_eq!(mature_zec.pending_zat, 0);
    assert_eq!(mature_zec.total_zat, zcash_winner.reward_zat);

    let ledger_count_before_replay = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ledger_transactions WHERE deployment_id=$1",
    )
    .bind(store.deployment_id())
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(
        projector
            .project_event(&authority, &events[6])
            .await
            .unwrap(),
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
    assert!(matches!(
        projector
            .project_event(&authority, &conflicting_replay)
            .await,
        Err(StoreError::EventReplayConflict(7))
    ));
    let cursor_gap = BackendEvent::GenerationClosed {
        event_seq: 9,
        job_id: descriptor.job_id.clone(),
    };
    assert!(matches!(
        projector.project_event(&authority, &cursor_gap).await,
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
        .authentication_provider(2, wcash_pool_store::MiningAuthenticationMode::Token)
        .expect("auth provider builds");
    let grant = auth
        .authenticate_credentials("alice.z15", token.expose_secret())
        .await
        .expect("canonical token authenticates");
    assert_eq!(grant.worker().account_id(), account_id);
    assert_eq!(grant.worker().worker_id(), worker_id);
    assert!(matches!(
        auth.authenticate_credentials("alice.z15", "invalid-token")
            .await,
        Err(AuthenticationError::Denied)
    ));
    let username_auth = store
        .authentication_provider(2, wcash_pool_store::MiningAuthenticationMode::UsernameOnly)
        .expect("username-only auth provider builds");
    let username_grant = username_auth
        .authenticate_credentials("alice.z15", "x")
        .await
        .expect("registered username authenticates with x");
    assert_eq!(username_grant.worker().worker_id(), worker_id);
    assert!(username_auth
        .authenticate_credentials("alice.z15", "any-password-is-ignored")
        .await
        .is_ok());
    assert!(matches!(
        username_auth
            .authenticate_credentials("alice.unknown", "x")
            .await,
        Err(AuthenticationError::Denied)
    ));
    let rotated_token = generate_mining_token().expect("rotated token material exists");
    let rotated_verifier =
        hash_mining_token(&rotated_token).expect("rotated token verifier is canonical");
    sqlx::query(
        "INSERT INTO mining_tokens (deployment_id,id,worker_id,verifier) VALUES ($1,$2,$3,$4)",
    )
    .bind(store.deployment_id())
    .bind(rotated_token.id())
    .bind(worker_id)
    .bind(rotated_verifier)
    .execute(&admin)
    .await
    .expect("second worker token persists");
    assert!(store
        .revoke_mining_token(token.id())
        .await
        .expect("connected token revokes"));
    assert!(matches!(
        auth.revalidate_worker(&grant).await,
        Err(AuthenticationError::Denied)
    ));
    assert!(matches!(
        username_auth.revalidate_worker(&username_grant).await,
        Err(AuthenticationError::Denied)
    ));
    assert!(auth
        .authenticate_credentials("alice.z15", rotated_token.expose_secret())
        .await
        .is_ok());

    let lease = wcash_pool_core::NonceNamespaceLease::new(7).expect("valid namespace");
    let holder_a = Uuid::new_v4();
    assert!(matches!(
        store
            .claim_nonce_namespace(
                holder_a,
                NonceProfile::FourByte,
                lease,
                Duration::from_millis(1_500),
            )
            .await,
        Err(StoreError::InvalidNonceLeaseDuration)
    ));
    let claim_a = store
        .claim_nonce_namespace(
            holder_a,
            NonceProfile::FourByte,
            lease,
            Duration::from_secs(300),
        )
        .await
        .expect("first deployment claims the global namespace");
    assert_eq!(
        store
            .claim_nonce_namespace(
                holder_a,
                NonceProfile::FourByte,
                lease,
                Duration::from_secs(300),
            )
            .await
            .expect("an exact claim retry is idempotent"),
        claim_a
    );
    let first = store
        .reserve_nonce_range(&claim_a, 2)
        .await
        .expect("first range reserves");

    let mut rolling_identity = store_identity.clone();
    rolling_identity.id = Uuid::new_v4();
    rolling_identity.chain_id = rolling_identity
        .chain_id
        .checked_add(100)
        .expect("test chain id remains bounded");
    let rolling_store = PostgresStore::connect(&database_url, 4, rolling_identity.clone())
        .await
        .expect("rolling deployment store connects");
    rolling_store
        .bind_deployment()
        .await
        .expect("rolling deployment binds to the same backend journal");
    let holder_b = Uuid::new_v4();
    assert!(matches!(
        rolling_store
            .claim_nonce_namespace(
                holder_b,
                NonceProfile::FourByte,
                lease,
                Duration::from_secs(300),
            )
            .await,
        Err(StoreError::NonceNamespaceAlreadyHeld)
    ));

    sqlx::query(
        "UPDATE nonce_namespace_fences \
         SET lease_acquired_at=clock_timestamp() - INTERVAL '2 seconds', \
             lease_expires_at=clock_timestamp() - INTERVAL '1 second' \
         WHERE backend_instance=$1 AND journal_stream=$2 AND profile=4 AND namespace=7",
    )
    .bind(store_identity.backend_instance)
    .bind(store_identity.journal_stream)
    .execute(&admin)
    .await
    .expect("test advances the authoritative database lease clock");
    let claim_b = rolling_store
        .claim_nonce_namespace(
            holder_b,
            NonceProfile::FourByte,
            lease,
            Duration::from_secs(300),
        )
        .await
        .expect("takeover succeeds only after expiry");
    assert!(claim_b.generation() > claim_a.generation());
    assert!(matches!(
        store.reserve_nonce_range(&claim_a, 1).await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));
    assert!(matches!(
        store
            .renew_nonce_namespace(&claim_a, Duration::from_secs(300))
            .await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));
    assert!(matches!(
        store.release_nonce_namespace(&claim_a).await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));
    assert!(matches!(
        store.release_nonce_namespace(&claim_b).await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));

    let renewed_b = rolling_store
        .renew_nonce_namespace(&claim_b, Duration::from_secs(300))
        .await
        .expect("the exact owner renews its live claim");
    assert_eq!(renewed_b.generation(), claim_b.generation());
    assert!(renewed_b.expires_at() >= claim_b.expires_at());
    let second = rolling_store
        .reserve_nonce_range(&renewed_b, 3)
        .await
        .expect("takeover resumes after the previous cursor");
    assert_eq!((first.start(), first.end()), (0, 2));
    assert_eq!((second.start(), second.end()), (2, 5));
    assert_eq!(first.profile(), NonceProfile::FourByte);
    let allocator = first.allocator().expect("range restores its bound profile");
    assert!(allocator.allocate().is_ok());
    assert!(allocator.allocate().is_ok());
    assert!(allocator.allocate().is_err());

    let mut reservations = JoinSet::new();
    for count in 1..=8 {
        let concurrent_store = rolling_store.clone();
        let concurrent_claim = renewed_b.clone();
        reservations.spawn(async move {
            concurrent_store
                .reserve_nonce_range(&concurrent_claim, count)
                .await
        });
    }
    let mut concurrent_ranges = Vec::new();
    while let Some(result) = reservations.join_next().await {
        let range = result
            .expect("reservation task does not panic")
            .expect("concurrent reservation succeeds");
        concurrent_ranges.push((range.start(), range.end()));
    }
    concurrent_ranges.sort_unstable();
    let mut expected_start = 5;
    for (start, end) in &concurrent_ranges {
        assert_eq!(*start, expected_start, "reservations remain contiguous");
        assert!(*end > *start, "every reservation remains nonempty");
        expected_start = *end;
    }
    assert_eq!(expected_start, 41);

    rolling_store
        .release_nonce_namespace(&renewed_b)
        .await
        .expect("the exact owner releases its live claim");
    assert!(matches!(
        rolling_store
            .renew_nonce_namespace(&renewed_b, Duration::from_secs(300))
            .await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));
    assert!(matches!(
        rolling_store.release_nonce_namespace(&renewed_b).await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));
    let reclaimed_a = store
        .claim_nonce_namespace(
            holder_a,
            NonceProfile::FourByte,
            lease,
            Duration::from_secs(300),
        )
        .await
        .expect("released namespace can be reclaimed with a new generation");
    assert!(reclaimed_a.generation() > renewed_b.generation());
    let resumed = store
        .reserve_nonce_range(&reclaimed_a, 1)
        .await
        .expect("release and reacquisition cannot rewind the cursor");
    assert_eq!((resumed.start(), resumed.end()), (41, 42));
    assert!(matches!(
        rolling_store.reserve_nonce_range(&renewed_b, 1).await,
        Err(StoreError::NonceNamespaceLeaseLost)
    ));
    assert!(
        sqlx::query(
            "UPDATE nonce_namespace_fences SET next_counter=0 \
             WHERE backend_instance=$1 AND journal_stream=$2 AND profile=4 AND namespace=7",
        )
        .bind(store_identity.backend_instance)
        .bind(store_identity.journal_stream)
        .execute(&admin)
        .await
        .is_err(),
        "the database rejects cursor rewind outside the application"
    );

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
    let first_wec_reconciliation = reconcile_wallet(&store, &admin, Chain::Wcash)
        .await
        .expect("first WEC wallet state reconciles");
    let key = Uuid::new_v4();
    let wec_batch = store
        .create_payout_batch(Chain::Wcash, key, first_wec_reconciliation.id)
        .await
        .expect("WEC batch builds");
    assert_eq!(wec_batch.outputs.len(), 1, "batch policy caps output count");
    assert_eq!(wec_batch.miner_total_zat, 200, "ZEC never enters WEC batch");
    assert_eq!(wec_batch.maximum_network_fee_zat, 20);
    assert_eq!(wec_batch.payout_total_zat, 180);
    assert_eq!(wec_batch.outputs[0].liability_amount_zat, 200);
    assert_eq!(wec_batch.outputs[0].amount_zat, 180);
    assert_eq!(wec_batch.reconciliation_id, first_wec_reconciliation.id);
    assert_eq!(
        store
            .create_payout_batch(Chain::Wcash, key, first_wec_reconciliation.id)
            .await
            .expect("exact payout creation replay is idempotent"),
        wec_batch
    );
    assert!(
        sqlx::query("UPDATE payout_batches SET ledger_root=$3 WHERE deployment_id=$1 AND id=$2",)
            .bind(store.deployment_id())
            .bind(wec_batch.id)
            .bind([0xee; 32].as_slice())
            .execute(&admin)
            .await
            .is_err(),
        "database trigger seals the signer ledger root"
    );
    assert!(
        sqlx::query(
            "UPDATE payout_items SET amount_zat=amount_zat+1 \
             WHERE deployment_id=$1 AND batch_id=$2",
        )
        .bind(store.deployment_id())
        .bind(wec_batch.id)
        .execute(&admin)
        .await
        .is_err(),
        "database trigger seals payout outputs"
    );
    assert!(
        sqlx::query(
            "INSERT INTO payout_items \
             (deployment_id,batch_id,account_id,destination_id,amount_zat,allocation_id) \
             SELECT $1,$2,$3,d.id,1,$4 FROM payout_destinations d \
              WHERE d.deployment_id=$1 AND d.account_id=$3 AND d.chain='wcash' AND d.state='active'",
        )
        .bind(store.deployment_id())
        .bind(wec_batch.id)
        .bind(account_id)
        .bind(Uuid::new_v4())
        .execute(&admin)
        .await
        .is_err(),
        "database trigger rejects outputs appended after the batch seal"
    );
    assert!(
        sqlx::query(
            "UPDATE payout_destinations SET address='tampered-address' \
             WHERE deployment_id=$1 AND id=$2",
        )
        .bind(store.deployment_id())
        .bind(wec_batch.outputs[0].destination_id)
        .execute(&admin)
        .await
        .is_err(),
        "database trigger seals validated destination facts"
    );
    let second_wec_reconciliation = reconcile_wallet(&store, &admin, Chain::Wcash)
        .await
        .expect("post-reservation WEC wallet state reconciles");
    assert!(matches!(
        store
            .create_payout_batch(Chain::Wcash, key, second_wec_reconciliation.id)
            .await,
        Err(StoreError::PayoutIdempotencyConflict)
    ));
    let second_wec_batch = store
        .create_payout_batch(Chain::Wcash, Uuid::new_v4(), second_wec_reconciliation.id)
        .await
        .expect("deterministic pagination leaves the next WEC account payable");
    assert_eq!(second_wec_batch.outputs.len(), 1);
    assert_eq!(second_wec_batch.miner_total_zat, 100);
    assert_eq!(second_wec_batch.maximum_network_fee_zat, 10);
    assert_eq!(second_wec_batch.payout_total_zat, 90);
    let signer_request = store
        .authorize_payout_signing(wec_batch.id)
        .await
        .expect("signer request is authorized from immutable reconciliation facts");
    assert_eq!(
        signer_request.reconciliation_id,
        first_wec_reconciliation.id
    );
    assert_eq!(signer_request.ledger_root, wec_batch.ledger_root);
    assert_eq!(
        signer_request.maximum_network_fee_zat, 20,
        "relative fee policy is bound before signing"
    );
    assert_eq!(signer_request.outputs.len(), 1);
    assert_eq!(
        signer_request.outputs[0].allocation_id,
        wec_batch.outputs[0].allocation_id
    );
    let replayed_signer_request = store
        .authorize_payout_signing(wec_batch.id)
        .await
        .expect("historic signer root re-derives after later ledger appends");
    assert_eq!(replayed_signer_request.ledger_root, wec_batch.ledger_root);
    assert_eq!(
        store
            .list_resumable_payout_batches(Chain::Wcash, 10)
            .await
            .expect("restart can enumerate incomplete WEC batches")
            .len(),
        2
    );
    let zec_reconciliation = reconcile_wallet(&store, &admin, Chain::Zcash)
        .await
        .expect("ZEC wallet state reconciles independently");
    assert!(matches!(
        store
            .create_payout_batch(Chain::Zcash, key, zec_reconciliation.id)
            .await,
        Err(StoreError::PayoutIdempotencyConflict)
    ));
    let zec_batch = store
        .create_payout_batch(Chain::Zcash, Uuid::new_v4(), zec_reconciliation.id)
        .await
        .expect("ZEC batch builds");
    assert_eq!(zec_batch.miner_total_zat, 300, "WEC never enters ZEC batch");
    assert_eq!(zec_batch.maximum_network_fee_zat, 30);
    assert_eq!(zec_batch.payout_total_zat, 270);
    let zec_signer_request = store
        .authorize_payout_signing(zec_batch.id)
        .await
        .expect("ZEC signer effect is durably authorized before its boundary");
    assert_eq!(zec_signer_request.maximum_network_fee_zat, 30);

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
        reconcile_wallet(&store, &admin, Chain::Wcash).await,
        Err(StoreError::WalletReconciliationBlocked)
    ));
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

    store
        .authorize_payout_signing(second_wec_batch.id)
        .await
        .expect("second batch signing is authorized before the wallet boundary");
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
    let authorized_artifact = store
        .authorize_payout_broadcast(wec_batch.id)
        .await
        .expect("signed batch receives a durable broadcast fence");
    assert_eq!(authorized_artifact.state, PayoutBatchState::Broadcasting);
    assert_eq!(authorized_artifact.signed_transaction, signed_transaction);
    store
        .mark_payout_broadcast(wec_batch.id)
        .await
        .expect("signed batch becomes broadcast");
    store
        .mark_payout_broadcast(wec_batch.id)
        .await
        .expect("broadcast replay is idempotent");
    let pending_disclosure = PortalRepository::payout_history(
        &store,
        wec_batch.outputs[0].account_id,
        PageRequest {
            before: None,
            limit: 10,
        },
    )
    .await
    .expect("broadcast payout disclosure loads")
    .items
    .into_iter()
    .find(|payout| payout.batch_id == wec_batch.id)
    .expect("broadcast payout disclosure is present");
    assert_eq!(pending_disclosure.gross_amount_zat, 200);
    assert_eq!(pending_disclosure.reserved_network_fee_zat, Some(20));
    assert_eq!(pending_disclosure.actual_network_fee_zat, None);
    assert_eq!(pending_disclosure.refunded_network_fee_zat, None);
    assert_eq!(pending_disclosure.amount_zat, 180);
    let broadcast_watches = store
        .list_payout_watches(Chain::Wcash, 10)
        .await
        .expect("broadcast payout is visible to the validator observer");
    assert_eq!(broadcast_watches.watches.len(), 1);
    assert_eq!(broadcast_watches.watches[0].batch_id, wec_batch.id);
    assert_eq!(broadcast_watches.watches[0].chain, Chain::Wcash);
    assert_eq!(
        broadcast_watches.watches[0].state,
        PayoutBatchState::Broadcast
    );
    assert_eq!(broadcast_watches.watches[0].transaction_id, transaction_id);
    assert_eq!(broadcast_watches.watches[0].prior_confirmation, None);
    let payout_confirmation = PayoutConfirmation {
        block_hash: [0xf1; 32],
        block_height: 50_000,
        confirmations: 3,
    };
    let shallow_confirmation = PayoutConfirmation {
        confirmations: 2,
        ..payout_confirmation.clone()
    };
    assert!(matches!(
        store
            .confirm_payout(wec_batch.id, &shallow_confirmation)
            .await,
        Err(StoreError::PrematurePayoutConfirmation {
            required: 3,
            actual: 2
        })
    ));
    credit_immature(&store, &admin, account_id, Chain::Wcash, 1_000)
        .await
        .expect("immature collector fixture commits");
    store
        .confirm_payout(wec_batch.id, &payout_confirmation)
        .await
        .expect("miner fee reserve permits confirmation without operator capital");
    let post_payout_balances = sqlx::query(
        "SELECT ledger_account,SUM(amount_zat)::BIGINT AS balance \
         FROM ledger_entries e JOIN ledger_transactions t \
           ON (t.deployment_id,t.id)=(e.deployment_id,e.transaction_id) \
         WHERE e.deployment_id=$1 AND t.chain='wcash' \
           AND e.ledger_account IN ('collector_spendable_asset','miner_payable', \
                                    'payout_pending','network_fee_expense', \
                                    'miner_network_fee_contribution') \
           AND (e.ledger_account NOT IN ('network_fee_expense', \
                                         'miner_network_fee_contribution') \
                OR (t.kind='payout_confirmed' AND t.reference=$2)) \
         GROUP BY ledger_account",
    )
    .bind(store.deployment_id())
    .bind(wec_batch.id.to_string())
    .fetch_all(&admin)
    .await
    .expect("post-payout conserving balances read");
    let balance = |account: &str| {
        post_payout_balances
            .iter()
            .find(|row| row.get::<String, _>("ledger_account") == account)
            .map_or(0, |row| row.get::<i64, _>("balance"))
    };
    assert_eq!(balance("collector_spendable_asset"), 115);
    assert_eq!(balance("miner_payable"), -15);
    assert_eq!(balance("payout_pending"), -100);
    assert_eq!(balance("network_fee_expense"), 5);
    assert_eq!(balance("miner_network_fee_contribution"), -5);
    store
        .confirm_payout(wec_batch.id, &payout_confirmation)
        .await
        .expect("confirmation replay is idempotent");
    let confirmed_watches = store
        .list_payout_watches(Chain::Wcash, 10)
        .await
        .expect("confirmed payout remains watched for reorganization");
    assert_eq!(confirmed_watches.watches.len(), 1);
    assert_eq!(
        confirmed_watches.watches[0].state,
        PayoutBatchState::Confirmed
    );
    assert_eq!(
        confirmed_watches.watches[0].prior_confirmation.as_ref(),
        Some(&payout_confirmation)
    );
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
    assert!(store
        .list_payout_watches(Chain::Wcash, 10)
        .await
        .expect("reorged payout is removed from normal observation")
        .watches
        .is_empty());
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
    let delayed_projector = projector.clone();
    let delayed_authority = authority.clone();
    let delayed_event = zcash_deep_reorg.clone();
    let projection = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        delayed_projector
            .project_event(&delayed_authority, &delayed_event)
            .await
    });
    assert_eq!(
        store
            .project_event(&authority, &zcash_deep_reorg)
            .await
            .expect("public consumer waits only until the exact event is durable"),
        ProjectionResult::Replayed
    );
    assert_eq!(
        projection
            .await
            .expect("delayed projector task joins")
            .expect("deep reorg is always journaled and reversed"),
        ProjectionResult::Applied
    );
    let unprojected = BackendEvent::GenerationClosed {
        event_seq: 9,
        job_id: descriptor.job_id.clone(),
    };
    let lag_wait_started = tokio::time::Instant::now();
    assert!(matches!(
        store.project_event(&authority, &unprojected).await,
        Err(StoreError::EventProjectionLag {
            projected: 8,
            required: 9
        })
    ));
    assert!(
        lag_wait_started.elapsed() < Duration::from_secs(6),
        "public event verification has a hard bounded-lag deadline"
    );
    store
        .mark_payout_signed(zec_batch.id, &[0xe1; 32], &[0xe2; 32], &[0xe3, 0xe4], 1)
        .await
        .expect("an authorized signer result remains recordable after a later freeze");
    assert!(matches!(
        store.authorize_payout_broadcast(zec_batch.id).await,
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
    assert!(matches!(
        store.cancel_payout_draft(zec_batch.id).await,
        Err(StoreError::InvalidPayoutTransition)
    ));
    assert!(matches!(
        store.cancel_payout_draft(second_wec_batch.id).await,
        Err(StoreError::InvalidPayoutTransition)
    ));
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
        row.get::<Uuid, _>("id") == zec_batch.id && row.get::<String, _>("state") == "signed"
    }));
    assert!(payout_states.iter().any(|row| {
        row.get::<Uuid, _>("id") == second_wec_batch.id
            && row.get::<String, _>("state") == "signing"
    }));

    assert!(store
        .revoke_worker(account_id, worker_id)
        .await
        .expect("worker revokes"));
    assert!(matches!(
        auth.authenticate_credentials("alice.z15", rotated_token.expose_secret())
            .await,
        Err(AuthenticationError::Denied)
    ));

    // The portal adapter uses this exact PostgreSQL identity and token truth;
    // there is no secondary SQLite worker or payout database.
    PortalRepository::readiness(&store)
        .await
        .expect("deployment and zero-fee policies are portal-ready");
    let portal_account = Uuid::new_v4();
    let password_token = generate_mining_token().expect("test password material exists");
    let password_hash = hash_mining_token(&password_token).expect("password PHC is canonical");
    PortalRepository::create_account(&store, portal_account, "bob", &password_hash, 1_725_000_100)
        .await
        .expect("portal account persists");
    sqlx::query(
        "INSERT INTO portal_sessions \
         (deployment_id,token_digest,csrf_digest,account_id,security_version,authenticated_at, \
          expires_at,idle_expires_at) \
         SELECT $1,decode(lpad(to_hex(series),64,'0'),'hex'), \
                decode(lpad(to_hex(series+100),64,'0'),'hex'),$2,1, \
                clock_timestamp()-INTERVAL '1000 seconds', \
                clock_timestamp()-INTERVAL '500 seconds', \
                clock_timestamp()-INTERVAL '501 seconds' \
         FROM generate_series(1,5) AS series",
    )
    .bind(store.deployment_id())
    .bind(portal_account)
    .execute(&admin)
    .await
    .expect("expired session fixtures seed");
    sqlx::query(
        "INSERT INTO portal_sessions \
         (deployment_id,token_digest,csrf_digest,account_id,security_version,authenticated_at, \
          expires_at,idle_expires_at) VALUES \
         ($1,decode(lpad(to_hex(99),64,'0'),'hex'), \
          decode(lpad(to_hex(199),64,'0'),'hex'),$2,1,clock_timestamp(), \
          clock_timestamp()+INTERVAL '1000 seconds',clock_timestamp()+INTERVAL '500 seconds')",
    )
    .bind(store.deployment_id())
    .bind(portal_account)
    .execute(&admin)
    .await
    .expect("live session fixture seeds");
    assert!(matches!(
        store.cleanup_expired_portal_sessions(0).await,
        Err(StoreError::InvalidSessionCleanupLimit)
    ));
    assert!(matches!(
        store.cleanup_expired_portal_sessions(1_025).await,
        Err(StoreError::InvalidSessionCleanupLimit)
    ));
    assert_eq!(
        store
            .cleanup_expired_portal_sessions(2)
            .await
            .expect("bounded cleanup succeeds"),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM portal_sessions WHERE deployment_id=$1 \
             AND (expires_at <= clock_timestamp() OR idle_expires_at <= clock_timestamp())",
        )
        .bind(store.deployment_id())
        .fetch_one(&admin)
        .await
        .expect("remaining expired sessions count"),
        3,
        "one cleanup call cannot exceed its explicit bound"
    );
    assert_eq!(
        store
            .cleanup_expired_portal_sessions(1_024)
            .await
            .expect("remaining expired sessions clean up"),
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM portal_sessions WHERE deployment_id=$1",
        )
        .bind(store.deployment_id())
        .fetch_one(&admin)
        .await
        .expect("live session remains"),
        1
    );
    let credential = PortalRepository::account_by_username(&store, "bob")
        .await
        .expect("portal lookup succeeds")
        .expect("portal account exists");
    assert_eq!(credential.id, portal_account);
    let worker_argon2_permit = Arc::new(Semaphore::new(1))
        .try_acquire_owned()
        .expect("worker Argon2 permit");
    let portal_worker = PortalRepository::provision_worker(
        &store,
        portal_account,
        "bob",
        "rig1",
        1_725_000_101,
        worker_argon2_permit,
    )
    .await
    .expect("portal worker persists through shared store");
    assert!(portal_worker.token.starts_with("zw1."));
    assert!(auth
        .authenticate_credentials("bob.rig1", &portal_worker.token)
        .await
        .is_ok());
    let listed = PortalRepository::list_workers(&store, portal_account, "bob")
        .await
        .expect("workers list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].revoked_at, None);
    assert!(PortalRepository::revoke_worker(
        &store,
        portal_account,
        portal_worker.worker_id,
        1_725_000_102,
    )
    .await
    .expect("portal worker revocation commits"));
    let listed = PortalRepository::list_workers(&store, portal_account, "bob")
        .await
        .expect("revoked worker remains auditable");
    assert_eq!(listed[0].revoked_at, Some(1_725_000_102));
    assert!(matches!(
        auth.authenticate_credentials("bob.rig1", &portal_worker.token)
            .await,
        Err(AuthenticationError::Denied)
    ));

    let first_destination = ValidatedDestination::from_authoritative_validation(
        Asset::Wec,
        ChainNetwork::Testnet,
        "wtestsapling1portalintegrationdestination0001".to_owned(),
        PortalReceiverKind::Ironwood,
    )
    .expect("authoritative fixture");
    let first_requested_not_before =
        sqlx::query_scalar::<_, i64>("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
            .fetch_one(&admin)
            .await
            .expect("database clock lower fence reads");
    let first_setting = PortalRepository::configure_payout(
        &store,
        PayoutPreferenceChange {
            account_id: portal_account,
            destination: &first_destination,
            threshold_zat: 100,
            automatic: true,
            changed_at: 1_725_000_110,
            replacement_hold_secs: 48 * 60 * 60,
            address_digest: &[0x31; 32],
        },
    )
    .await
    .expect("initial payout enters the mandatory hold");
    let first_requested_not_after =
        sqlx::query_scalar::<_, i64>("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
            .fetch_one(&admin)
            .await
            .expect("database clock upper fence reads");
    assert_eq!(first_setting.active_destination, None);
    assert!(first_setting.pending_destination.is_some());
    assert_eq!(first_setting.threshold_zat, 0);
    assert!(!first_setting.automatic);
    assert_eq!(first_setting.revision, 0);
    assert_eq!(first_setting.pending_threshold_zat, Some(100));
    assert_eq!(first_setting.pending_automatic, Some(true));
    assert_eq!(first_setting.pending_revision, Some(1));
    let first_hold = sqlx::query(
        "SELECT FLOOR(EXTRACT(EPOCH FROM requested_at))::BIGINT AS requested_at, \
                FLOOR(EXTRACT(EPOCH FROM active_after))::BIGINT AS active_after \
         FROM payout_change_events \
         WHERE deployment_id=$1 AND account_id=$2 AND chain='wcash' AND revision=1",
    )
    .bind(store.deployment_id())
    .bind(portal_account)
    .fetch_one(&admin)
    .await
    .expect("initial hold audit event reads");
    let first_requested_at = first_hold.get::<i64, _>("requested_at");
    let first_active_after = first_hold.get::<i64, _>("active_after");
    assert!(
        (first_requested_not_before..=first_requested_not_after).contains(&first_requested_at),
        "initial request time comes from the database clock"
    );
    assert_eq!(first_active_after - first_requested_at, 48 * 60 * 60);
    assert_eq!(
        first_setting.pending_effective_at,
        Some(u64::try_from(first_active_after).expect("database timestamp is positive"))
    );
    let replacement = ValidatedDestination::from_authoritative_validation(
        Asset::Wec,
        ChainNetwork::Testnet,
        first_destination.canonical_address().to_owned(),
        PortalReceiverKind::Ironwood,
    )
    .expect("same-address policy replacement fixture");
    let replacement_requested_not_before =
        sqlx::query_scalar::<_, i64>("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
            .fetch_one(&admin)
            .await
            .expect("database clock lower fence reads");
    let replacement_setting = PortalRepository::configure_payout(
        &store,
        PayoutPreferenceChange {
            account_id: portal_account,
            destination: &replacement,
            threshold_zat: 200,
            automatic: false,
            changed_at: 1_725_000_120,
            replacement_hold_secs: 48 * 60 * 60,
            address_digest: &[0x31; 32],
        },
    )
    .await
    .expect("replacement is held");
    let replacement_requested_not_after =
        sqlx::query_scalar::<_, i64>("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
            .fetch_one(&admin)
            .await
            .expect("database clock upper fence reads");
    assert_eq!(replacement_setting.active_destination, None);
    assert!(replacement_setting.pending_destination.is_some());
    assert_eq!(replacement_setting.threshold_zat, 0);
    assert!(!replacement_setting.automatic);
    assert_eq!(replacement_setting.revision, 0);
    assert_eq!(replacement_setting.pending_threshold_zat, Some(200));
    assert_eq!(replacement_setting.pending_automatic, Some(false));
    assert_eq!(replacement_setting.pending_revision, Some(2));
    let persisted_hold = sqlx::query(
        "SELECT FLOOR(EXTRACT(EPOCH FROM requested_at))::BIGINT AS requested_at, \
                FLOOR(EXTRACT(EPOCH FROM active_after))::BIGINT AS active_after \
         FROM payout_change_events \
         WHERE deployment_id=$1 AND account_id=$2 AND chain='wcash' AND revision=2",
    )
    .bind(store.deployment_id())
    .bind(portal_account)
    .fetch_one(&admin)
    .await
    .expect("replacement hold audit event reads");
    let persisted_requested_at = persisted_hold.get::<i64, _>("requested_at");
    let persisted_active_after = persisted_hold.get::<i64, _>("active_after");
    assert!(
        (replacement_requested_not_before..=replacement_requested_not_after)
            .contains(&persisted_requested_at),
        "request time comes from the fenced database clock"
    );
    assert_eq!(
        persisted_active_after - persisted_requested_at,
        48 * 60 * 60,
        "database timestamps retain the exact configured hold"
    );
    assert_eq!(
        replacement_setting.pending_effective_at,
        Some(u64::try_from(persisted_active_after).expect("database timestamp is positive"))
    );
    let settings = PortalRepository::payout_settings(
        &store,
        portal_account,
        ChainNetwork::Testnet,
        1_725_000_121,
    )
    .await
    .expect("masked settings load");
    assert_eq!(settings.len(), 1);
    let active = PortalRepository::active_payout_destination(
        &store,
        portal_account,
        Asset::Wec,
        ChainNetwork::Testnet,
        1_725_000_121,
    )
    .await
    .expect("active destination lookup succeeds");
    assert_eq!(
        active, None,
        "any pending replacement immediately excludes the account from payout use"
    );
    assert!(PortalRepository::payout_settings(
        &store,
        portal_account,
        ChainNetwork::Mainnet,
        1_725_000_121,
    )
    .await
    .is_err());

    // A blocking advisory-lock transaction commits a replacement while batch
    // creation is queued behind it. READ COMMITTED must observe that pending
    // row after acquiring the lock and must not reserve the old destination.
    let payout_safety_identity = identity(74);
    let payout_safety_store =
        PostgresStore::connect(&database_url, 4, payout_safety_identity.clone())
            .await
            .expect("isolated payout-safety deployment connects");
    payout_safety_store
        .bind_deployment()
        .await
        .expect("isolated payout-safety deployment binds");
    payout_safety_store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("isolated payout-safety policies bind");
    let held_account = Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'held_account')")
        .bind(payout_safety_store.deployment_id())
        .bind(held_account)
        .execute(&admin)
        .await
        .expect("held account seeds");
    insert_destination(&payout_safety_store, &admin, held_account, Chain::Wcash)
        .await
        .expect("held account active destination seeds");
    credit_payable(&payout_safety_store, &admin, held_account, Chain::Wcash, 10)
        .await
        .expect("held account payable credit commits");
    let held_reconciliation = reconcile_wallet(&payout_safety_store, &admin, Chain::Wcash)
        .await
        .expect("held account wallet reconciles");
    let observer = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("advisory-lock observer connects");
    let mut blocker = admin.begin().await.expect("advisory blocker begins");
    let payout_lock_key = format!(
        "zecwec:{}:{}",
        payout_safety_store.deployment_id(),
        Chain::Wcash.as_str()
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&payout_lock_key)
        .execute(&mut *blocker)
        .await
        .expect("blocker owns payout-chain advisory lock");
    let waiting_store = payout_safety_store.clone();
    let waiting_batch_key = Uuid::new_v4();
    let waiting_batch = tokio::spawn(async move {
        waiting_store
            .create_payout_batch(Chain::Wcash, waiting_batch_key, held_reconciliation.id)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let has_waiter = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM pg_locks \
                 WHERE locktype='advisory' AND NOT granted)",
            )
            .fetch_one(&observer)
            .await
            .expect("advisory waiter state reads");
            if has_waiter {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("batch reaches the held advisory lock");
    let held_pending_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by,validated_at, \
          active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
         VALUES ($1,$2,$3,'wcash','testnet','integration-wcash-address','transparent', \
                 'integration-authority-v1',clock_timestamp(), \
                 clock_timestamp()+INTERVAL '48 hours',$4,2,false,'pending',2)",
    )
    .bind(payout_safety_store.deployment_id())
    .bind(held_pending_id)
    .bind(held_account)
    .bind([0x44_u8; 32].as_slice())
    .execute(&mut *blocker)
    .await
    .expect("replacement commits in the lock-owning transaction");
    blocker
        .commit()
        .await
        .expect("replacement releases advisory lock");
    assert!(matches!(
        waiting_batch.await.expect("waiting batch task completes"),
        Err(StoreError::NoPayableBalances)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM payout_items WHERE deployment_id=$1 AND account_id=$2",
        )
        .bind(payout_safety_store.deployment_id())
        .bind(held_account)
        .fetch_one(&observer)
        .await
        .expect("held account payout item count reads"),
        0,
        "a committed pending replacement immediately excludes the account"
    );
    assert!(PortalRepository::active_payout_destination(
        &payout_safety_store,
        held_account,
        Asset::Wec,
        ChainNetwork::Testnet,
        1,
    )
    .await
    .expect("held account active lookup succeeds")
    .is_none());

    // A separate due replacement is promoted inside the same locked batch
    // transaction, and a reconnected process observes the promoted address.
    let due_account = Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'due_account')")
        .bind(payout_safety_store.deployment_id())
        .bind(due_account)
        .execute(&admin)
        .await
        .expect("due account seeds");
    insert_destination(&payout_safety_store, &admin, due_account, Chain::Wcash)
        .await
        .expect("due account active destination seeds");
    let due_destination_id = Uuid::new_v4();
    let due_address = "integration-promoted-address";
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by,validated_at, \
          active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
         VALUES ($1,$2,$3,'wcash','testnet',$4,'transparent','integration-authority-v1', \
                 clock_timestamp()-INTERVAL '2 seconds',clock_timestamp()-INTERVAL '1 second', \
                 $5,1,true,'pending',2)",
    )
    .bind(payout_safety_store.deployment_id())
    .bind(due_destination_id)
    .bind(due_account)
    .bind(due_address)
    .bind([0x76_u8; 32].as_slice())
    .execute(&admin)
    .await
    .expect("due pending destination seeds");
    credit_payable(&payout_safety_store, &admin, due_account, Chain::Wcash, 11)
        .await
        .expect("due account payable credit commits");
    let due_reconciliation = reconcile_wallet(&payout_safety_store, &admin, Chain::Wcash)
        .await
        .expect("due account wallet reconciles");
    let promoted_batch = payout_safety_store
        .create_payout_batch(Chain::Wcash, Uuid::new_v4(), due_reconciliation.id)
        .await
        .expect("batch atomically promotes the due replacement");
    assert_eq!(promoted_batch.outputs.len(), 1);
    assert_eq!(promoted_batch.outputs[0].account_id, due_account);
    assert_eq!(promoted_batch.outputs[0].destination_id, due_destination_id);
    assert_eq!(promoted_batch.outputs[0].address, due_address);
    let payout_safety_restart =
        PostgresStore::connect(&database_url, 1, payout_safety_identity.clone())
            .await
            .expect("payout-safety store reconnects");
    payout_safety_restart
        .verify_deployment()
        .await
        .expect("restarted payout process verifies deployment");
    let restarted_destination = PortalRepository::active_payout_destination(
        &payout_safety_restart,
        due_account,
        Asset::Wec,
        ChainNetwork::Testnet,
        1,
    )
    .await
    .expect("restarted process reads promoted destination")
    .expect("due destination is active after batch commit");
    assert_eq!(restarted_destination.canonical_address(), due_address);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM payout_destinations \
             WHERE deployment_id=$1 AND account_id=$2 AND chain='wcash' AND state='disabled'",
        )
        .bind(payout_safety_store.deployment_id())
        .bind(due_account)
        .fetch_one(&admin)
        .await
        .expect("superseded destination state reads"),
        1
    );

    let historic_account = event_worker.account_id.get();
    let balances = PortalRepository::balances(&store, historic_account)
        .await
        .expect("post-reorg private balances load");
    assert_eq!(balances.len(), 2);
    let wec_balance = balances
        .iter()
        .find(|balance| balance.asset == Asset::Wec)
        .expect("WEC balance exists");
    assert_eq!(wec_balance.total_zat, 0);
    let zec_balance = balances
        .iter()
        .find(|balance| balance.asset == Asset::Zec)
        .expect("ZEC balance exists");
    assert_eq!(zec_balance.immature_zat, 0);
    assert_eq!(zec_balance.payable_zat, 0);
    assert_eq!(zec_balance.pending_zat, 0);
    assert_eq!(zec_balance.total_zat, 0);
    let rewards = PortalRepository::reward_history(
        &store,
        historic_account,
        PageRequest {
            before: None,
            limit: 1,
        },
    )
    .await
    .expect("private rewards page");
    assert_eq!(rewards.items.len(), 1);
    assert!(rewards.next_before.is_some());
    let blocks = PortalRepository::found_blocks(
        &store,
        historic_account,
        PageRequest {
            before: None,
            limit: 10,
        },
    )
    .await
    .expect("private found-block page");
    assert_eq!(blocks.items.len(), 2);
    let payouts = PortalRepository::payout_history(
        &store,
        wec_batch.outputs[0].account_id,
        PageRequest {
            before: None,
            limit: 10,
        },
    )
    .await
    .expect("private payout page");
    assert!(!payouts.items.is_empty());
    assert!(payouts
        .items
        .iter()
        .any(|payout| payout.transaction_id.is_some()));
    let disclosed_payout = payouts
        .items
        .iter()
        .find(|payout| payout.batch_id == wec_batch.id)
        .expect("confirmed payout disclosure is present");
    assert_eq!(disclosed_payout.gross_amount_zat, 200);
    assert_eq!(disclosed_payout.reserved_network_fee_zat, Some(20));
    assert_eq!(disclosed_payout.actual_network_fee_zat, Some(5));
    assert_eq!(disclosed_payout.refunded_network_fee_zat, Some(15));
    assert_eq!(disclosed_payout.amount_zat, 180);

    let overview = PostgresPoolDataSource::new(store.clone());
    assert!(!overview.overview().available);
    overview
        .refresh()
        .await
        .expect("overview projection refreshes");
    let snapshot = overview.overview();
    assert!(snapshot.available);
    assert_eq!(snapshot.wec_fee_bps, Some(0));
    assert_eq!(snapshot.zec_fee_bps, Some(0));
    assert_eq!(snapshot.wec_maximum_network_fee_zat, Some(1_000_000));
    assert_eq!(snapshot.wec_maximum_network_fee_bps, Some(1_000));
    assert_eq!(snapshot.zec_maximum_network_fee_zat, Some(1_000_000));
    assert_eq!(snapshot.zec_maximum_network_fee_bps, Some(1_000));
    assert_eq!(snapshot.fee_policy_revision, Some(1));
    assert_eq!(
        snapshot.wcash_height,
        Some(u64::from(descriptor.wcash_height - 1))
    );
    assert_eq!(
        snapshot.zcash_height,
        Some(u64::from(descriptor.zcash_height - 1))
    );

    let stale_store = PostgresStore::connect(&database_url, 2, identity(73))
        .await
        .expect("isolated reconciliation deployment connects");
    stale_store
        .bind_deployment()
        .await
        .expect("isolated reconciliation deployment binds");
    stale_store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("isolated reconciliation policies bind");
    let stale_account = Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'stale_account')")
        .bind(stale_store.deployment_id())
        .bind(stale_account)
        .execute(&admin)
        .await
        .expect("isolated reconciliation account seeds");
    insert_destination(&stale_store, &admin, stale_account, Chain::Wcash)
        .await
        .expect("isolated reconciliation destination seeds");
    credit_payable(&stale_store, &admin, stale_account, Chain::Wcash, 10)
        .await
        .expect("isolated reconciliation payable credit commits");
    let stale_checkpoint = reconcile_wallet(&stale_store, &admin, Chain::Wcash)
        .await
        .expect("initial isolated wallet state reconciles");
    credit_payable(&stale_store, &admin, stale_account, Chain::Wcash, 1)
        .await
        .expect("later ledger fact commits");
    assert!(matches!(
        stale_store
            .create_payout_batch(Chain::Wcash, Uuid::new_v4(), stale_checkpoint.id)
            .await,
        Err(StoreError::WalletReconciliationStale)
    ));
    let database_now = u64::try_from(
        sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT")
            .fetch_one(&admin)
            .await
            .expect("database clock reads"),
    )
    .expect("database clock is positive");
    assert!(matches!(
        stale_store
            .record_wallet_reconciliation(&WalletObservation {
                chain: Chain::Wcash,
                wallet_state_digest: [0xc1; 32],
                wallet_spendable_zat: 12,
                best_tip_hash: [0xc2; 32],
                best_tip_height: 60_000,
                observed_at: database_now,
                valid_until: database_now + 240,
            })
            .await,
        Err(StoreError::CollectorReconciliationFailed)
    ));
    let mismatch_state = sqlx::query(
        "SELECT s.payouts_frozen,s.freeze_reason, \
                (SELECT COUNT(*) FROM wallet_reconciliations r \
                  WHERE r.deployment_id=s.deployment_id AND r.chain=s.chain \
                    AND r.status='mismatch') AS mismatch_count \
         FROM chain_safety_state s WHERE s.deployment_id=$1 AND s.chain='wcash'",
    )
    .bind(stale_store.deployment_id())
    .fetch_one(&admin)
    .await
    .expect("wallet mismatch audit state reads");
    assert!(mismatch_state.get::<bool, _>("payouts_frozen"));
    assert_eq!(
        mismatch_state.get::<Option<String>, _>("freeze_reason"),
        Some("wallet_reconciliation_mismatch".to_owned())
    );
    assert_eq!(mismatch_state.get::<i64, _>("mismatch_count"), 1);

    let counts = sqlx::query(
        "SELECT \
           (SELECT COUNT(*) FROM nonce_global_range_reservations \
             WHERE backend_instance=$2 AND journal_stream=$3 \
               AND profile=4 AND namespace=7) AS ranges, \
           (SELECT COUNT(*) FROM nonce_namespace_claim_events \
             WHERE backend_instance=$2 AND journal_stream=$3 \
               AND profile=4 AND namespace=7) AS claim_events, \
           (SELECT COUNT(*) FROM payout_batches WHERE deployment_id=$1) AS batches",
    )
    .bind(store.deployment_id())
    .bind(store_identity.backend_instance)
    .bind(store_identity.journal_stream)
    .fetch_one(&admin)
    .await
    .expect("audit counts load");
    assert_eq!(counts.get::<i64, _>("ranges"), 11);
    assert_eq!(counts.get::<i64, _>("claim_events"), 5);
    assert_eq!(counts.get::<i64, _>("batches"), 3);
}

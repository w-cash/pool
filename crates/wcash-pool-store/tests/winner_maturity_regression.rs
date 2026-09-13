//! Focused real-PostgreSQL coverage for winner maturity upgrade and payout
//! serialization. Set `WCASH_POOL_TEST_DATABASE_URL` to an isolated disposable
//! database; this test recreates its public schema.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use num_bigint::BigUint;
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;
use wcash_pool_store::{
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PayoutConfirmation, PostgresStore,
    WalletObservation,
};

const PRE_REGRESSION_MIGRATIONS: [&str; 7] = [
    include_str!("../migrations/0001_runtime_accounting.sql"),
    include_str!("../migrations/0002_portal_read_models.sql"),
    include_str!("../migrations/0003_global_nonce_fencing.sql"),
    include_str!("../migrations/0004_portal_miner_views.sql"),
    include_str!("../migrations/0005_security_hardening.sql"),
    include_str!("../migrations/0006_public_runtime_boundaries.sql"),
    include_str!("../migrations/0007_payout_watch_rotation.sql"),
];
const REGRESSION_MIGRATION: &str =
    include_str!("../migrations/0008_winner_maturity_regression.sql");

fn assert_check_violation(error: sqlx::Error, expected_message: &str) {
    let sqlx::Error::Database(database) = error else {
        panic!("expected PostgreSQL database error, got {error:?}");
    };
    assert_eq!(database.code().as_deref(), Some("23514"));
    assert!(
        database.message().contains(expected_message),
        "unexpected migration error: {}",
        database.message()
    );
}

async fn assert_regression_upgrade_is_atomic(pool: &sqlx::PgPool) {
    let mut fixture = pool.begin().await.expect("migration fixture begins");
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&mut *fixture)
        .await
        .expect("migration fixture schema resets");
    for migration in PRE_REGRESSION_MIGRATIONS {
        sqlx::raw_sql(migration)
            .execute(&mut *fixture)
            .await
            .expect("pre-regression migration applies");
    }

    sqlx::raw_sql(
        "INSERT INTO deployments \
           (id,network,wcash_genesis,zcash_genesis,chain_id,wcash_payout_commitment, \
            zcash_payout_commitment,backend_instance,journal_stream) VALUES \
           ('00000000-0000-0000-0000-000000000101','testnet', \
            decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),1, \
            decode(repeat('33',32),'hex'),decode(repeat('44',32),'hex'), \
            '00000000-0000-0000-0000-000000000102', \
            '00000000-0000-0000-0000-000000000103'); \
         INSERT INTO backend_events \
           (deployment_id,event_seq,event_kind,payload,payload_sha256) VALUES \
           ('00000000-0000-0000-0000-000000000101',1,'job_activated','{}', \
            decode(repeat('55',32),'hex')), \
           ('00000000-0000-0000-0000-000000000101',2,'share_committed','{}', \
            decode(repeat('56',32),'hex')); \
         INSERT INTO chain_policies \
           (deployment_id,chain,pplns_window_work,fee_bps,payout_threshold_zat, \
            required_confirmations,maximum_payout_outputs,maximum_network_fee_zat, \
            maximum_network_fee_bps,policy_version) VALUES \
           ('00000000-0000-0000-0000-000000000101','wcash',1,0,1,100,1,1000,100,1), \
           ('00000000-0000-0000-0000-000000000101','zcash',1,0,1,100,1,1000,100,1); \
         INSERT INTO accounts (deployment_id,id,login) VALUES \
           ('00000000-0000-0000-0000-000000000101', \
            '00000000-0000-0000-0000-000000000104','audit'); \
         INSERT INTO workers (deployment_id,id,account_id,label,canonical_login) VALUES \
           ('00000000-0000-0000-0000-000000000101', \
            '00000000-0000-0000-0000-000000000105', \
            '00000000-0000-0000-0000-000000000104','worker','audit.worker'); \
         INSERT INTO jobs (deployment_id,job_id,activation_event_seq,descriptor) VALUES \
           ('00000000-0000-0000-0000-000000000101',decode(repeat('66',32),'hex'),1, \
            '{\"wcash_maturity_confirmations\":100,\"zcash_maturity_confirmations\":100}'); \
         INSERT INTO shares \
           (deployment_id,share_id,event_seq,job_id,account_id,worker_id,target_le,work, \
            parent_hash_le) VALUES \
           ('00000000-0000-0000-0000-000000000101',decode(repeat('77',32),'hex'),2, \
            decode(repeat('66',32),'hex'),'00000000-0000-0000-0000-000000000104', \
            '00000000-0000-0000-0000-000000000105',decode(repeat('7f',32),'hex'),1, \
            decode(repeat('88',32),'hex')); \
         INSERT INTO winners \
           (deployment_id,chain,block_hash_le,share_id,job_id,height,coinbase_txid_le, \
            reward_zat,maturity_confirmations,state) VALUES \
           ('00000000-0000-0000-0000-000000000101','wcash', \
            decode(repeat('99',32),'hex'),decode(repeat('77',32),'hex'), \
            decode(repeat('66',32),'hex'),11,decode(repeat('aa',32),'hex'),1000,100, \
            'submitted')",
    )
    .execute(&mut *fixture)
    .await
    .expect("fully related legacy fixtures seed");

    sqlx::raw_sql("SAVEPOINT job_policy_mismatch")
        .execute(&mut *fixture)
        .await
        .expect("job mismatch savepoint begins");
    sqlx::query(
        "UPDATE jobs SET descriptor=jsonb_set( \
             descriptor,'{wcash_maturity_confirmations}','99'::jsonb,FALSE) \
         WHERE deployment_id='00000000-0000-0000-0000-000000000101'",
    )
    .execute(&mut *fixture)
    .await
    .expect("legacy job mismatch injects");
    let error = sqlx::raw_sql(REGRESSION_MIGRATION)
        .execute(&mut *fixture)
        .await
        .expect_err("retained job mismatch must abort migration");
    assert_check_violation(error, "retained job maturity requirements");
    sqlx::raw_sql(
        "ROLLBACK TO SAVEPOINT job_policy_mismatch; RELEASE SAVEPOINT job_policy_mismatch",
    )
    .execute(&mut *fixture)
    .await
    .expect("failed job upgrade rolls back to savepoint");

    let pre_upgrade_constraint = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid='public.ledger_transactions'::regclass \
           AND conname='ledger_transactions_kind_check'",
    )
    .fetch_one(&mut *fixture)
    .await
    .expect("pre-upgrade ledger constraint reads");
    assert!(!pre_upgrade_constraint.contains("winner_dematured"));
    let pre_upgrade_function = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_functiondef( \
             'public.freeze_chain_payouts_v1(uuid,text,bigint,text)'::regprocedure)",
    )
    .fetch_one(&mut *fixture)
    .await
    .expect("pre-upgrade freeze function reads");
    assert!(!pre_upgrade_function.contains("matured_winner_depth_regression"));

    sqlx::raw_sql("SAVEPOINT winner_policy_mismatch")
        .execute(&mut *fixture)
        .await
        .expect("winner mismatch savepoint begins");
    sqlx::query(
        "UPDATE winners SET maturity_confirmations=101 \
         WHERE deployment_id='00000000-0000-0000-0000-000000000101'",
    )
    .execute(&mut *fixture)
    .await
    .expect("legacy winner mismatch injects");
    let error = sqlx::raw_sql(REGRESSION_MIGRATION)
        .execute(&mut *fixture)
        .await
        .expect_err("retained winner mismatch must abort migration");
    assert_check_violation(error, "retained winner maturity requirements");
    sqlx::raw_sql(
        "ROLLBACK TO SAVEPOINT winner_policy_mismatch; RELEASE SAVEPOINT winner_policy_mismatch",
    )
    .execute(&mut *fixture)
    .await
    .expect("failed winner upgrade rolls back to savepoint");

    sqlx::raw_sql(REGRESSION_MIGRATION)
        .execute(&mut *fixture)
        .await
        .expect("matching retained facts upgrade successfully");
    let upgraded_constraint = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid='public.ledger_transactions'::regclass \
           AND conname='ledger_transactions_kind_check'",
    )
    .fetch_one(&mut *fixture)
    .await
    .expect("upgraded ledger constraint reads");
    assert!(upgraded_constraint.contains("winner_dematured"));
    let upgraded_function = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_functiondef( \
             'public.freeze_chain_payouts_v1(uuid,text,bigint,text)'::regprocedure)",
    )
    .fetch_one(&mut *fixture)
    .await
    .expect("upgraded freeze function reads");
    assert!(upgraded_function.contains("matured_winner_depth_regression"));

    fixture
        .rollback()
        .await
        .expect("migration fixture rolls back cleanly");
}

fn identity() -> DeploymentIdentity {
    DeploymentIdentity {
        id: Uuid::new_v4(),
        network: DeploymentNetwork::Testnet,
        wcash_genesis: [0x11; 32],
        zcash_genesis: [0x22; 32],
        chain_id: 91,
        wcash_payout_commitment: [0x33; 32],
        zcash_payout_commitment: [0x44; 32],
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
        maximum_payout_outputs: 1,
        maximum_network_fee_zat: 1_000_000,
        maximum_network_fee_bps: 1_000,
        policy_version: 1,
    }
}

async fn seed_payable(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    account_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'lock_audit')")
        .bind(store.deployment_id())
        .bind(account_id)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by, \
          validated_at,active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
         VALUES ($1,$2,$3,'wcash','testnet','integration-wcash-lock-address','transparent', \
                 'integration-authority-v1',clock_timestamp(),clock_timestamp(),$4,1,true, \
                 'active',1)",
    )
    .bind(store.deployment_id())
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind([0x55_u8; 32].as_slice())
    .execute(pool)
    .await?;

    let transaction_id = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference) VALUES ($1,$2,'wcash','winner_matured',$3)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
    .bind(format!("lock-audit-credit-{transaction_id}"))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO ledger_entries \
         (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES \
         ($1,$2,1,NULL,'collector_spendable_asset',100), \
         ($1,$2,2,$3,'miner_payable',-100)",
    )
    .bind(store.deployment_id())
    .bind(transaction_id)
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

async fn assert_confirmation_waits_for_safety_lock(pool: &sqlx::PgPool, database_url: &str) {
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(pool)
        .await
        .expect("confirmation fixture schema resets");
    let store = PostgresStore::connect(database_url, 4, identity())
        .await
        .expect("confirmation store connects");
    store.migrate().await.expect("current schema migrates");
    store.bind_deployment().await.expect("deployment binds");
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("launch policies bind");

    let account_id = Uuid::new_v4();
    seed_payable(&store, pool, account_id)
        .await
        .expect("payable fixture seeds");
    let now = sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT")
        .fetch_one(pool)
        .await
        .expect("database clock reads");
    let reconciliation = store
        .record_wallet_reconciliation(&WalletObservation {
            chain: Chain::Wcash,
            wallet_state_digest: [0x66; 32],
            wallet_spendable_zat: 100,
            best_tip_hash: [0x77; 32],
            best_tip_height: 50_000,
            observed_at: u64::try_from(now).expect("database time is positive"),
            valid_until: u64::try_from(now).expect("database time is positive") + 240,
        })
        .await
        .expect("wallet reconciles");
    let batch = store
        .create_payout_batch(Chain::Wcash, Uuid::new_v4(), reconciliation.id)
        .await
        .expect("payout batch creates");
    assert_eq!(batch.miner_total_zat, 100);
    assert_eq!(batch.payout_total_zat, 90);
    assert_eq!(batch.maximum_network_fee_zat, 10);
    store
        .authorize_payout_signing(batch.id)
        .await
        .expect("signing authorization commits");
    store
        .mark_payout_signed(batch.id, &[0x81; 32], &[0x82; 32], &[0x83, 0x84], 1)
        .await
        .expect("signed facts persist");
    store
        .authorize_payout_broadcast(batch.id)
        .await
        .expect("broadcast authorization commits");
    store
        .mark_payout_broadcast(batch.id)
        .await
        .expect("broadcast completion persists");

    let mut blocker = pool.begin().await.expect("safety lock blocker begins");
    sqlx::query(
        "SELECT payouts_frozen FROM chain_safety_state \
         WHERE deployment_id=$1 AND chain='wcash' FOR UPDATE",
    )
    .bind(store.deployment_id())
    .fetch_one(&mut *blocker)
    .await
    .expect("blocker owns the chain safety row");

    let confirmation = PayoutConfirmation {
        block_hash: [0x91; 32],
        block_height: 50_001,
        confirmations: 100,
    };
    let waiting_store = store.clone();
    let waiting_confirmation = confirmation.clone();
    let waiting = tokio::spawn(async move {
        waiting_store
            .confirm_payout(batch.id, &waiting_confirmation)
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let is_waiting = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS( \
                   SELECT 1 FROM pg_stat_activity \
                   WHERE datname=current_database() AND pid<>pg_backend_pid() \
                     AND state='active' AND wait_event_type='Lock' \
                     AND query LIKE '%lock_chain_safety_v1%')",
            )
            .fetch_one(pool)
            .await
            .expect("lock waiter state reads");
            if is_waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("confirmation reaches the held safety lock");
    assert!(
        !waiting.is_finished(),
        "confirmation cannot pass the held lock"
    );

    blocker.commit().await.expect("safety lock releases");
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("confirmation finishes after lock release")
        .expect("confirmation task joins")
        .expect("confirmation commits");
    let row = sqlx::query(
        "SELECT state,confirmation_block_hash FROM payout_batches \
         WHERE deployment_id=$1 AND id=$2",
    )
    .bind(store.deployment_id())
    .bind(batch.id)
    .fetch_one(pool)
    .await
    .expect("confirmed batch reads");
    assert_eq!(row.get::<String, _>("state"), "confirmed");
    assert_eq!(
        row.get::<Vec<u8>, _>("confirmation_block_hash"),
        confirmation.block_hash
    );
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL service in required CI"]
async fn winner_maturity_upgrade_and_confirmation_lock_are_deterministic() {
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL")
        .expect("ignored PostgreSQL integration test requires WCASH_POOL_TEST_DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("isolated PostgreSQL is available");

    assert_regression_upgrade_is_atomic(&pool).await;
    assert_confirmation_waits_for_safety_lock(&pool, &database_url).await;
}

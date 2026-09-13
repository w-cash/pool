//! Focused real-PostgreSQL coverage for the payout external-effect fence
//! upgrade. Set `WCASH_POOL_TEST_DATABASE_URL` to an isolated disposable
//! database; this test recreates its public schema.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::time::Duration;

use sqlx::{postgres::PgPoolOptions, Row};
use tokio::sync::oneshot;

const PRE_EFFECT_FENCE_MIGRATIONS: [&str; 8] = [
    include_str!("../migrations/0001_runtime_accounting.sql"),
    include_str!("../migrations/0002_portal_read_models.sql"),
    include_str!("../migrations/0003_global_nonce_fencing.sql"),
    include_str!("../migrations/0004_portal_miner_views.sql"),
    include_str!("../migrations/0005_security_hardening.sql"),
    include_str!("../migrations/0006_public_runtime_boundaries.sql"),
    include_str!("../migrations/0007_payout_watch_rotation.sql"),
    include_str!("../migrations/0008_winner_maturity_regression.sql"),
];
const EFFECT_FENCE_MIGRATION: &str =
    include_str!("../migrations/0009_payout_external_effect_fences.sql");

const DEPLOYMENT_ID: &str = "00000000-0000-0000-0000-000000000901";
const ACCOUNT_ID: &str = "00000000-0000-0000-0000-000000000902";
const DESTINATION_ID: &str = "00000000-0000-0000-0000-000000000903";
const RECONCILIATION_ID: &str = "00000000-0000-0000-0000-000000000904";
const RESERVATION_ID: &str = "00000000-0000-0000-0000-000000000905";
const BATCH_ID: &str = "00000000-0000-0000-0000-000000000906";

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

async fn payout_constraint_snapshot(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT conname,pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid='public.payout_batches'::regclass \
         ORDER BY conname",
    )
    .fetch_all(pool)
    .await
    .expect("payout constraint snapshot reads")
}

async fn payout_trigger_function(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT pg_get_functiondef( \
             'public.permit_only_payout_batch_seal()'::regprocedure)",
    )
    .fetch_one(pool)
    .await
    .expect("payout lifecycle function reads")
}

async fn install_old_schema(pool: &sqlx::PgPool) {
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(pool)
        .await
        .expect("migration fixture schema resets");
    for migration in PRE_EFFECT_FENCE_MIGRATIONS {
        sqlx::raw_sql(migration)
            .execute(pool)
            .await
            .expect("pre-effect-fence migration applies");
    }
}

async fn seed_old_writer_prerequisites(pool: &sqlx::PgPool) -> i64 {
    let mut fixture = pool.begin().await.expect("old-writer fixture begins");
    sqlx::raw_sql(
        "INSERT INTO deployments \
           (id,network,wcash_genesis,zcash_genesis,chain_id,wcash_payout_commitment, \
            zcash_payout_commitment,backend_instance,journal_stream) VALUES \
           ('00000000-0000-0000-0000-000000000901','testnet', \
            decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),1, \
            decode(repeat('33',32),'hex'),decode(repeat('44',32),'hex'), \
            '00000000-0000-0000-0000-000000000907', \
            '00000000-0000-0000-0000-000000000908'); \
         INSERT INTO chain_policies \
           (deployment_id,chain,pplns_window_work,fee_bps,payout_threshold_zat, \
            required_confirmations,maximum_payout_outputs,maximum_network_fee_zat, \
            maximum_network_fee_bps,policy_version) VALUES \
           ('00000000-0000-0000-0000-000000000901','wcash',1,0,1,100,1,1000,100,1); \
         INSERT INTO accounts (deployment_id,id,login) VALUES \
           ('00000000-0000-0000-0000-000000000901', \
            '00000000-0000-0000-0000-000000000902','effect_fence_audit'); \
         INSERT INTO payout_destinations \
           (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by, \
            validated_at,active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
           VALUES \
           ('00000000-0000-0000-0000-000000000901', \
            '00000000-0000-0000-0000-000000000903', \
            '00000000-0000-0000-0000-000000000902','wcash','testnet', \
            'effect-fence-test-address','transparent','integration-authority-v1', \
            clock_timestamp(),clock_timestamp(),decode(repeat('55',32),'hex'),1,true, \
            'active',1); \
         INSERT INTO wallet_reconciliations \
           (deployment_id,id,chain,ledger_root,ledger_transaction_count,wallet_state_digest, \
            wallet_spendable_zat,ledger_spendable_zat,best_tip_hash,best_tip_height, \
            observed_at,valid_until,status) VALUES \
           ('00000000-0000-0000-0000-000000000901', \
            '00000000-0000-0000-0000-000000000904','wcash', \
            decode(repeat('66',32),'hex'),1,decode(repeat('67',32),'hex'),100,100, \
            decode(repeat('68',32),'hex'),1000,clock_timestamp(), \
            clock_timestamp() + INTERVAL '4 minutes','matched')",
    )
    .execute(&mut *fixture)
    .await
    .expect("old-writer prerequisites seed");

    let reservation_sequence = sqlx::query_scalar::<_, i64>(
        "INSERT INTO ledger_transactions \
           (deployment_id,id,chain,kind,reference) \
         VALUES ($1::uuid,$2::uuid,'wcash','payout_reserved',$3::uuid::text) \
         RETURNING ledger_sequence",
    )
    .bind(DEPLOYMENT_ID)
    .bind(RESERVATION_ID)
    .bind(BATCH_ID)
    .fetch_one(&mut *fixture)
    .await
    .expect("reservation transaction seeds");
    sqlx::query(
        "INSERT INTO ledger_entries \
           (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES \
           ($1::uuid,$2::uuid,1,NULL,'collector_spendable_asset',-100), \
           ($1::uuid,$2::uuid,2,$3::uuid,'payout_pending',100)",
    )
    .bind(DEPLOYMENT_ID)
    .bind(RESERVATION_ID)
    .bind(ACCOUNT_ID)
    .execute(&mut *fixture)
    .await
    .expect("balanced reservation entries seed");
    sqlx::query(
        "UPDATE ledger_transactions \
         SET sealed_at=clock_timestamp(),sealed_entry_count=2 \
         WHERE deployment_id=$1::uuid AND id=$2::uuid",
    )
    .bind(DEPLOYMENT_ID)
    .bind(RESERVATION_ID)
    .execute(&mut *fixture)
    .await
    .expect("reservation transaction seals");
    fixture
        .commit()
        .await
        .expect("old-writer prerequisites commit");
    reservation_sequence
}

async fn wait_for_payout_table_lock(pool: &sqlx::PgPool, migration_pid: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let is_waiting = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS( \
                   SELECT 1 FROM pg_locks \
                   WHERE pid=$1 \
                     AND relation='public.payout_batches'::regclass \
                     AND mode='AccessExclusiveLock' \
                     AND NOT granted)",
            )
            .bind(migration_pid)
            .fetch_one(pool)
            .await
            .expect("migration lock waiter state reads");
            if is_waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("migration waits for the old writer's payout table lock");
}

async fn apply_effect_fence_concurrently(
    pool: sqlx::PgPool,
    pid_sender: oneshot::Sender<i32>,
) -> Result<(), sqlx::Error> {
    // PostgreSQL executes every statement in one simple-query message as one
    // implicit transaction. Keeping the LOCK and guard in this same raw SQL
    // batch is part of what this regression exercises.
    let mut connection = pool.acquire().await?;
    let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await?;
    let _ = pid_sender.send(pid);
    sqlx::raw_sql(EFFECT_FENCE_MIGRATION)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL service in required CI"]
async fn payout_effect_fence_upgrade_waits_for_old_writer_and_is_atomic() {
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL")
        .expect("ignored PostgreSQL integration test requires WCASH_POOL_TEST_DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&database_url)
        .await
        .expect("isolated PostgreSQL is available");

    install_old_schema(&pool).await;
    let reservation_sequence = seed_old_writer_prerequisites(&pool).await;
    let old_constraints = payout_constraint_snapshot(&pool).await;
    let old_function = payout_trigger_function(&pool).await;
    assert!(!old_function.contains("NEW.state = 'signing'"));

    // This transaction represents the last old binary racing deployment. Its
    // RowExclusiveLock must make migration 0009 wait before taking the guard's
    // snapshot, not merely before the later ALTER TABLE statements.
    let mut old_writer = pool.begin().await.expect("old writer begins");
    sqlx::query(
        "INSERT INTO payout_batches \
           (deployment_id,id,chain,policy_version,idempotency_key,state) \
         VALUES ($1::uuid,$2::uuid,'wcash',1, \
                 '00000000-0000-0000-0000-000000000909'::uuid,'draft')",
    )
    .bind(DEPLOYMENT_ID)
    .bind(BATCH_ID)
    .execute(&mut *old_writer)
    .await
    .expect("old writer opens draft batch");
    sqlx::query(
        "INSERT INTO payout_items \
           (deployment_id,batch_id,account_id,destination_id,amount_zat,allocation_id) \
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,100, \
                 '00000000-0000-0000-0000-000000000910'::uuid)",
    )
    .bind(DEPLOYMENT_ID)
    .bind(BATCH_ID)
    .bind(ACCOUNT_ID)
    .bind(DESTINATION_ID)
    .execute(&mut *old_writer)
    .await
    .expect("old writer appends payout item");
    sqlx::query(
        "UPDATE payout_batches \
         SET reconciliation_id=$3::uuid,ledger_root=decode(repeat('66',32),'hex'), \
             ledger_sequence_cutoff=$4,updated_at=clock_timestamp() \
         WHERE deployment_id=$1::uuid AND id=$2::uuid",
    )
    .bind(DEPLOYMENT_ID)
    .bind(BATCH_ID)
    .bind(RECONCILIATION_ID)
    .bind(reservation_sequence)
    .execute(&mut *old_writer)
    .await
    .expect("old writer seals draft batch");

    let migration_pool = pool.clone();
    let (pid_sender, pid_receiver) = oneshot::channel();
    let coordinate_writer = async {
        let migration_pid = pid_receiver.await.expect("migration reports backend pid");
        wait_for_payout_table_lock(&pool, migration_pid).await;
        old_writer.commit().await.expect("old writer commits draft");
    };
    let (migration_result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            apply_effect_fence_concurrently(migration_pool, pid_sender),
            coordinate_writer
        )
    })
    .await
    .expect("migration and old writer complete without deadlock");
    let error =
        migration_result.expect_err("migration must reject the newly committed legacy draft");
    assert_check_violation(
        error,
        "cannot install payout effect fences with legacy draft or signed batches",
    );

    let committed_state = sqlx::query("SELECT state FROM payout_batches WHERE id=$1::uuid")
        .bind(BATCH_ID)
        .fetch_one(&pool)
        .await
        .expect("old writer's batch remains visible")
        .get::<String, _>("state");
    assert_eq!(committed_state, "draft");
    assert_eq!(payout_constraint_snapshot(&pool).await, old_constraints);
    assert_eq!(payout_trigger_function(&pool).await, old_function);

    // Once the old release drains the ambiguous row, the exact same migration
    // must install successfully and expose the new durable authorization states.
    sqlx::query(
        "UPDATE payout_batches SET state='cancelled',updated_at=clock_timestamp() \
         WHERE deployment_id=$1::uuid AND id=$2::uuid",
    )
    .bind(DEPLOYMENT_ID)
    .bind(BATCH_ID)
    .execute(&pool)
    .await
    .expect("old release drains the draft batch");
    let mut upgrade = pool.begin().await.expect("drained upgrade begins");
    sqlx::raw_sql(EFFECT_FENCE_MIGRATION)
        .execute(&mut *upgrade)
        .await
        .expect("drained old schema upgrades");
    upgrade.commit().await.expect("drained upgrade commits");

    let upgraded_constraints = payout_constraint_snapshot(&pool).await;
    assert_ne!(upgraded_constraints, old_constraints);
    let upgraded_state_constraint = upgraded_constraints
        .iter()
        .find(|(name, _)| name == "payout_batches_state_check")
        .expect("upgraded state constraint exists");
    assert!(upgraded_state_constraint.1.contains("signing"));
    assert!(upgraded_state_constraint.1.contains("broadcasting"));
    let upgraded_function = payout_trigger_function(&pool).await;
    assert!(upgraded_function.contains("NEW.state = 'signing'"));
    assert!(upgraded_function.contains("NEW.state = 'broadcasting'"));
}

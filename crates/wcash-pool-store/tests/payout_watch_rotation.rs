//! Real PostgreSQL coverage for durable confirmed-payout watch rotation.
//!
//! Set `WCASH_POOL_TEST_DATABASE_URL` to an isolated disposable database. The
//! ignored test recreates its public schema.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use num_bigint::BigUint;
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;
use wcash_pool_store::{
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PayoutBatchState, PayoutReorg,
    PostgresStore,
};

fn identity() -> DeploymentIdentity {
    DeploymentIdentity {
        id: Uuid::from_u128(0x1000),
        network: DeploymentNetwork::Testnet,
        wcash_genesis: [0x11; 32],
        zcash_genesis: [0x12; 32],
        chain_id: 77,
        wcash_payout_commitment: [0x13; 32],
        zcash_payout_commitment: [0x14; 32],
        backend_instance: Uuid::from_u128(0x1001),
        journal_stream: Uuid::from_u128(0x1002),
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
        maximum_payout_zat: 1_000_000_000_000,
        maximum_network_fee_zat: 1_000_000,
        maximum_network_fee_bps: 1_000,
        policy_version: 1,
    }
}

struct PayoutFixture<'a> {
    pool: &'a sqlx::PgPool,
    deployment_id: Uuid,
    account_id: Uuid,
    destination_id: Uuid,
}

impl PayoutFixture<'_> {
    async fn seed_payout(
        &self,
        batch_id: Uuid,
        marker: u8,
        confirmed: bool,
        created_at: i64,
        confirmation_height: i64,
    ) {
        let Self {
            pool,
            deployment_id,
            account_id,
            destination_id,
        } = *self;
        let ledger_id = Uuid::from_u128(0x2000 + u128::from(marker));
        let reconciliation_id = Uuid::from_u128(0x3000 + u128::from(marker));
        let allocation_id = Uuid::from_u128(0x4000 + u128::from(marker));
        let mut transaction = pool
            .begin()
            .await
            .expect("watch fixture transaction begins");
        let ledger_sequence = sqlx::query_scalar::<_, i64>(
            "INSERT INTO ledger_transactions \
         (deployment_id,id,chain,kind,reference,created_at) \
         VALUES ($1,$2,'wcash','payout_reserved',$3,to_timestamp($4)) \
         RETURNING ledger_sequence",
        )
        .bind(deployment_id)
        .bind(ledger_id)
        .bind(batch_id.to_string())
        .bind(created_at)
        .fetch_one(&mut *transaction)
        .await
        .expect("watch fixture ledger transaction inserts");
        sqlx::query(
            "INSERT INTO ledger_entries \
         (deployment_id,transaction_id,line_no,account_id,ledger_account,amount_zat) VALUES \
         ($1,$2,1,NULL,'collector_spendable_asset',-1), \
         ($1,$2,2,$3,'payout_pending',1)",
        )
        .bind(deployment_id)
        .bind(ledger_id)
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture ledger balances");
        sqlx::query(
            "UPDATE ledger_transactions SET sealed_at=clock_timestamp(),sealed_entry_count=2 \
         WHERE deployment_id=$1 AND id=$2",
        )
        .bind(deployment_id)
        .bind(ledger_id)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture ledger seals");
        sqlx::query(
            "INSERT INTO wallet_reconciliations \
         (deployment_id,id,chain,ledger_root,ledger_transaction_count,wallet_state_digest, \
          wallet_spendable_zat,ledger_spendable_zat,best_tip_hash,best_tip_height, \
          observed_at,valid_until,status) \
         VALUES ($1,$2,'wcash',$3,1,$4,0,0,$5,1000, \
                 clock_timestamp(),clock_timestamp()+INTERVAL '4 minutes','matched')",
        )
        .bind(deployment_id)
        .bind(reconciliation_id)
        .bind([marker; 32].as_slice())
        .bind([marker.wrapping_add(1); 32].as_slice())
        .bind([marker.wrapping_add(2); 32].as_slice())
        .execute(&mut *transaction)
        .await
        .expect("watch fixture reconciliation inserts");
        sqlx::query(
            "INSERT INTO payout_batches \
         (deployment_id,id,chain,policy_version,idempotency_key,state,created_at,updated_at) \
         VALUES ($1,$2,'wcash',1,$3,'draft',to_timestamp($4),to_timestamp($4))",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .bind(Uuid::from_u128(0x5000 + u128::from(marker)))
        .bind(created_at)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture payout inserts");
        sqlx::query(
            "INSERT INTO payout_items \
         (deployment_id,batch_id,account_id,destination_id,amount_zat,allocation_id, \
          liability_amount_zat) VALUES ($1,$2,$3,$4,1,$5,1)",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .bind(account_id)
        .bind(destination_id)
        .bind(allocation_id)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture payout item inserts");
        sqlx::query(
        "UPDATE payout_batches SET reconciliation_id=$3,ledger_root=$4,ledger_sequence_cutoff=$5 \
         WHERE deployment_id=$1 AND id=$2 AND state='draft'",
    )
    .bind(deployment_id)
    .bind(batch_id)
    .bind(reconciliation_id)
    .bind([marker; 32].as_slice())
    .bind(ledger_sequence)
    .execute(&mut *transaction)
    .await
    .expect("watch fixture payout reconciliation seal commits");
        sqlx::query(
            "UPDATE payout_batches SET state='signing' \
         WHERE deployment_id=$1 AND id=$2 AND state='draft'",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture payout authorizes signing");
        sqlx::query(
            "UPDATE payout_batches SET state='signed',unsigned_digest=$3,transaction_id=$4, \
                signed_transaction=$5,network_fee_zat=0 \
         WHERE deployment_id=$1 AND id=$2 AND state='signing'",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .bind([marker.wrapping_add(3); 32].as_slice())
        .bind([marker.wrapping_add(4); 32].as_slice())
        .bind([marker, marker.wrapping_add(1)].as_slice())
        .execute(&mut *transaction)
        .await
        .expect("watch fixture payout signs");
        sqlx::query(
            "UPDATE payout_batches SET state='broadcasting' \
         WHERE deployment_id=$1 AND id=$2 AND state='signed'",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture payout authorizes broadcast");
        sqlx::query(
            "UPDATE payout_batches SET state='broadcast' \
         WHERE deployment_id=$1 AND id=$2 AND state='broadcasting'",
        )
        .bind(deployment_id)
        .bind(batch_id)
        .execute(&mut *transaction)
        .await
        .expect("watch fixture payout broadcasts");
        if confirmed {
            sqlx::query(
                "UPDATE payout_batches SET state='confirmed',confirmation_block_hash=$3, \
                    confirmation_height=$4,confirmation_count=100 \
             WHERE deployment_id=$1 AND id=$2 AND state='broadcast'",
            )
            .bind(deployment_id)
            .bind(batch_id)
            .bind([marker.wrapping_add(5); 32].as_slice())
            .bind(confirmation_height)
            .execute(&mut *transaction)
            .await
            .expect("watch fixture payout confirms");
        }
        transaction
            .commit()
            .await
            .expect("watch fixture transaction commits");
    }
}

fn confirmed_ids(page: &wcash_pool_store::PayoutWatchPage) -> Vec<Uuid> {
    page.watches
        .iter()
        .filter(|watch| watch.state == PayoutBatchState::Confirmed)
        .map(|watch| watch.batch_id)
        .collect()
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL service in required CI"]
async fn confirmed_watches_rotate_across_restart_without_broadcast_starvation() {
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL")
        .expect("ignored PostgreSQL integration test requires WCASH_POOL_TEST_DATABASE_URL");
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("isolated PostgreSQL is available");
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&admin)
        .await
        .expect("isolated schema resets");

    let identity = identity();
    let store = PostgresStore::connect(&database_url, 2, identity.clone())
        .await
        .expect("store connects");
    store.migrate().await.expect("schema migrates");
    store.bind_deployment().await.expect("deployment binds");
    store
        .bind_zero_fee_launch_policies(&policy(Chain::Wcash), &policy(Chain::Zcash))
        .await
        .expect("chain policies bind");

    let account_id = Uuid::from_u128(0x6000);
    let destination_id = Uuid::from_u128(0x6001);
    sqlx::query("INSERT INTO accounts (deployment_id,id,login) VALUES ($1,$2,'watcher')")
        .bind(identity.id)
        .bind(account_id)
        .execute(&admin)
        .await
        .expect("watch fixture account inserts");
    sqlx::query(
        "INSERT INTO payout_destinations \
         (deployment_id,id,account_id,chain,network,address,receiver_kind,validated_by, \
          validated_at,active_after,address_digest,payout_threshold_zat,automatic,state,revision) \
         VALUES ($1,$2,$3,'wcash','testnet','rotation-test-address','transparent', \
                 'rotation-test-authority',clock_timestamp(),clock_timestamp(),$4,1,true,'active',1)",
    )
    .bind(identity.id)
    .bind(destination_id)
    .bind(account_id)
    .bind([0x61_u8; 32].as_slice())
    .execute(&admin)
    .await
    .expect("watch fixture destination inserts");

    let confirmed: Vec<Uuid> = (1_u128..=9)
        .map(|suffix| Uuid::from_u128(0x7000 + suffix))
        .collect();
    let fixture = PayoutFixture {
        pool: &admin,
        deployment_id: identity.id,
        account_id,
        destination_id,
    };
    for (index, batch_id) in confirmed.iter().copied().enumerate() {
        let historic = index == 8;
        fixture
            .seed_payout(
                batch_id,
                u8::try_from(index + 1).unwrap(),
                true,
                if historic {
                    1_700_000_000
                } else {
                    1_800_000_000 + i64::try_from(index).unwrap()
                },
                if historic {
                    1_000
                } else {
                    2_000 + i64::try_from(index).unwrap()
                },
            )
            .await;
    }
    for index in 0_u8..4 {
        fixture
            .seed_payout(
                Uuid::from_u128(0x8000 + u128::from(index)),
                20 + index,
                false,
                1_900_000_000 + i64::from(index),
                3_000 + i64::from(index),
            )
            .await;
    }

    let first = store
        .list_payout_watches(Chain::Wcash, 3)
        .await
        .expect("first watch page loads");
    assert_eq!(
        first
            .watches
            .iter()
            .filter(|watch| watch.state == PayoutBatchState::Broadcast)
            .count(),
        3,
        "broadcasts have their own bound"
    );
    assert_eq!(
        confirmed_ids(&first),
        confirmed[..3],
        "broadcasts cannot consume confirmed-watch capacity"
    );

    let restarted = PostgresStore::connect(&database_url, 1, identity.clone())
        .await
        .expect("payout worker reconnects");
    restarted
        .verify_deployment()
        .await
        .expect("restarted payout worker verifies deployment");
    let repeated = restarted
        .list_payout_watches(Chain::Wcash, 3)
        .await
        .expect("unacknowledged page reloads after restart");
    assert_eq!(confirmed_ids(&repeated), confirmed[..3]);
    let first_cursor = first
        .confirmed_cursor
        .as_ref()
        .expect("first confirmed page has a cursor");
    restarted
        .advance_confirmed_payout_watch_cursor(Chain::Wcash, first_cursor)
        .await
        .expect("valid authority snapshot acknowledges first page");
    assert!(
        restarted
            .advance_confirmed_payout_watch_cursor(Chain::Wcash, first_cursor)
            .await
            .is_err(),
        "a stale page cannot advance or rewind the cursor"
    );

    let second = restarted
        .list_payout_watches(Chain::Wcash, 3)
        .await
        .expect("second confirmed page loads");
    assert_eq!(confirmed_ids(&second), confirmed[3..6]);
    restarted
        .advance_confirmed_payout_watch_cursor(
            Chain::Wcash,
            second
                .confirmed_cursor
                .as_ref()
                .expect("second confirmed page has a cursor"),
        )
        .await
        .expect("second authority snapshot advances cursor");

    let final_restart = PostgresStore::connect(&database_url, 1, identity.clone())
        .await
        .expect("second payout worker restart connects");
    let third = final_restart
        .list_payout_watches(Chain::Wcash, 3)
        .await
        .expect("third confirmed page loads after restart");
    assert_eq!(confirmed_ids(&third), confirmed[6..9]);
    let historic_id = confirmed[8];
    let historic = third
        .watches
        .iter()
        .find(|watch| watch.batch_id == historic_id)
        .expect("oldest historical confirmation is eventually observed");
    let prior = historic
        .prior_confirmation
        .clone()
        .expect("historical watch carries its exact confirmation");
    final_restart
        .mark_confirmed_payout_reorged(
            historic_id,
            &PayoutReorg {
                prior_confirmation: prior,
                replacement_tip_hash: [0xf1; 32],
                replacement_tip_height: 4_000,
                observed_at: 1_900_000_100,
            },
        )
        .await
        .expect("oldest payout reorg freezes its chain");
    let safety = sqlx::query(
        "SELECT payouts_frozen,freeze_reason FROM chain_safety_state \
         WHERE deployment_id=$1 AND chain='wcash'",
    )
    .bind(identity.id)
    .fetch_one(&admin)
    .await
    .expect("chain safety state reads");
    assert!(safety.get::<bool, _>("payouts_frozen"));
    assert_eq!(
        safety.get::<Option<String>, _>("freeze_reason"),
        Some("confirmed_payout_reorg".to_owned())
    );
    let cursor = sqlx::query(
        "SELECT generation,last_confirmed_batch_id FROM payout_watch_cursors \
         WHERE deployment_id=$1 AND chain='wcash'",
    )
    .bind(identity.id)
    .fetch_one(&admin)
    .await
    .expect("durable cursor reads");
    assert_eq!(cursor.get::<i64, _>("generation"), 2);
    assert_eq!(
        cursor.get::<Option<Uuid>, _>("last_confirmed_batch_id"),
        Some(confirmed[5]),
        "a reorg page is never acknowledged after the freeze transition"
    );
}

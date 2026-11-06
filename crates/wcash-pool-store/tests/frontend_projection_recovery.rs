//! Read-only public projection verification against an isolated disposable PostgreSQL database.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Postgres, QueryBuilder};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use uuid::Uuid;
use wcash_pool_backend_client::{BackendClient, BackendClientConfig, ExpectedBackend};
use wcash_pool_protocol::{
    decode_backend_request, encode_backend_message, BackendEvent, BackendMessage, BackendRequest,
    CanonicalUuid, Hex32, TargetBe, BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION,
    REQUIRED_BACKEND_CAPABILITIES,
};
use wcash_pool_store::{DeploymentIdentity, DeploymentNetwork, PostgresStore, StoreError};

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

fn event(sequence: u64) -> BackendEvent {
    let mut id = [0xa1; 32];
    id[..8].copy_from_slice(&sequence.to_le_bytes());
    BackendEvent::GenerationClosed {
        event_seq: sequence,
        job_id: Hex32::new(id),
    }
}

async fn seed_batch(pool: &sqlx::PgPool, deployment: Uuid, events: &[BackendEvent]) {
    let mut transaction = pool.begin().await.unwrap();
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO backend_events (deployment_id,event_seq,event_kind,payload,payload_sha256) ",
    );
    query.push_values(events, |mut row, event| {
        row.push_bind(deployment)
            .push_bind(i64::try_from(event.event_seq()).unwrap())
            .push_bind("generation_closed")
            .push_bind(serde_json::to_value(event).unwrap())
            .push_bind(Sha256::digest(serde_json::to_vec(event).unwrap()).to_vec());
    });
    query.build().execute(&mut *transaction).await.unwrap();
    sqlx::query("UPDATE backend_cursors SET last_event_seq=$2 WHERE deployment_id=$1")
        .bind(deployment)
        .bind(i64::try_from(events.last().unwrap().event_seq()).unwrap())
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated disposable PostgreSQL database"]
async fn public_projection_batch_is_readonly_exact_and_bounded() {
    let database_url = std::env::var("WCASH_POOL_TEST_DATABASE_URL").unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&admin)
        .await
        .unwrap();
    let deployment = identity(0x63);
    let writer = PostgresStore::connect(&database_url, 2, deployment.clone())
        .await
        .unwrap();
    writer.migrate().await.unwrap();
    writer.bind_deployment().await.unwrap();
    let authority = authority_for(&deployment).await;
    let role = format!("projection_reader_{}", Uuid::new_v4().simple());
    let password = "disposable_projection_reader_password";
    sqlx::raw_sql(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; \
         ALTER ROLE {role} SET default_transaction_read_only=on; \
         GRANT USAGE ON SCHEMA public TO {role}; \
         GRANT SELECT ON deployments,backend_cursors,backend_events TO {role}"
    )).execute(&admin).await.unwrap();
    let role_url = database_url_for_role(&database_url, &role, password);
    let public = PostgresStore::connect(&role_url, 2, deployment.clone())
        .await
        .unwrap();
    let reader = PgPoolOptions::new()
        .max_connections(1)
        .connect(&role_url)
        .await
        .unwrap();
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT NOT rolsuper FROM pg_roles WHERE rolname=current_user"
    )
    .fetch_one(&reader)
    .await
    .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT current_setting('transaction_read_only')")
            .fetch_one(&reader)
            .await
            .unwrap(),
        "on"
    );
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT has_table_privilege(current_user,'backend_events','INSERT')"
    )
    .fetch_one(&reader)
    .await
    .unwrap());
    public.verify_deployment().await.unwrap();

    let events: Vec<_> = (1..=1_024).map(event).collect();
    assert!(matches!(
        public
            .project_replay_page(&authority, &[event(1), event(3)])
            .await,
        Err(StoreError::EventSequenceGap {
            expected: 2,
            actual: 3
        })
    ));
    assert!(matches!(
        public
            .project_replay_page(&authority, &[event(1), event(1)])
            .await,
        Err(StoreError::EventSequenceGap {
            expected: 2,
            actual: 1
        })
    ));
    assert!(matches!(
        public
            .project_replay_page(&authority, &(1..=1_025).map(event).collect::<Vec<_>>())
            .await,
        Err(StoreError::ReplayBatchTooLarge(1_025))
    ));
    let wrong = authority_for(&identity(0x64)).await;
    assert!(matches!(
        public.project_replay_page(&wrong, &events).await,
        Err(StoreError::BackendAuthorityMismatch)
    ));

    // The real read-only role waits for one atomic projected batch, including
    // the largest supported batch, without gaining any accounting write grant.
    let delayed_admin = admin.clone();
    let delayed_events = events.clone();
    let deployment_id = deployment.id;
    let projection = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        seed_batch(&delayed_admin, deployment_id, &delayed_events).await;
    });
    public
        .project_replay_page(&authority, &events)
        .await
        .unwrap();
    projection.await.unwrap();
    assert_eq!(public.last_event_seq().await.unwrap(), 1_024);
    assert!(
        sqlx::query("UPDATE backend_cursors SET last_event_seq=0 WHERE deployment_id=$1")
            .bind(deployment.id)
            .execute(&reader)
            .await
            .is_err()
    );

    let mut conflicting = events.clone();
    conflicting[0] = BackendEvent::GenerationClosed {
        event_seq: 1,
        job_id: Hex32::new([0xff; 32]),
    };
    assert!(matches!(
        public.project_replay_page(&authority, &conflicting).await,
        Err(StoreError::EventReplayConflict(1))
    ));
    // Inject a missing covered record with the fixture administrator only.
    // Restore the append-only trigger inside the same transaction before the
    // read-only verifier sees the fault; runtime privileges stay unchanged.
    let mut corruption = admin.begin().await.unwrap();
    sqlx::query("ALTER TABLE backend_events DISABLE TRIGGER backend_events_append_only")
        .execute(&mut *corruption)
        .await
        .unwrap();
    sqlx::query("DELETE FROM backend_events WHERE deployment_id=$1 AND event_seq=512")
        .bind(deployment.id)
        .execute(&mut *corruption)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE backend_events ENABLE TRIGGER backend_events_append_only")
        .execute(&mut *corruption)
        .await
        .unwrap();
    corruption.commit().await.unwrap();
    assert!(matches!(
        public.project_replay_page(&authority, &events).await,
        Err(StoreError::EventReplayConflict(512))
    ));
    // A missing covered event is permanent even while a later batch suffix
    // remains unprojected; the verifier must not hide a replay conflict as lag.
    sqlx::query("UPDATE backend_cursors SET last_event_seq=700 WHERE deployment_id=$1")
        .bind(deployment.id)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        public.project_replay_page(&authority, &events).await,
        Err(StoreError::EventReplayConflict(512))
    ));
    let missing = event(512);
    sqlx::query("INSERT INTO backend_events (deployment_id,event_seq,event_kind,payload,payload_sha256) VALUES($1,512,'generation_closed',$2,$3)")
        .bind(deployment.id).bind(serde_json::to_value(&missing).unwrap())
        .bind(Sha256::digest(serde_json::to_vec(&missing).unwrap()).to_vec())
        .execute(&admin).await.unwrap();
    let started = tokio::time::Instant::now();
    assert!(matches!(
        public.project_replay_page(&authority, &events).await,
        Err(StoreError::EventProjectionLag {
            projected: 700,
            required: 1_024
        })
    ));
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(7));
    assert_eq!(public.last_event_seq().await.unwrap(), 700);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM backend_events WHERE deployment_id=$1")
            .bind(deployment.id)
            .fetch_one(&admin)
            .await
            .unwrap(),
        1_024
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ledger_transactions WHERE deployment_id=$1"
        )
        .bind(deployment.id)
        .fetch_one(&admin)
        .await
        .unwrap(),
        0
    );
    drop(public);
    reader.close().await;
    sqlx::raw_sql(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
        .execute(&admin)
        .await
        .unwrap();
}

//! Fail-closed database, journal replay, and live mining bootstrap.

use std::{sync::Arc, time::Duration};

use wcash_pool_backend_client::{
    BackendClient, BackendClientConfig, ClientError, ExpectedBackend, MonotonicTimeline,
};
use wcash_pool_core::{
    GenerationRegistryConfig, NonceNamespaceLease, NoncePrefixAllocator, ShareTarget,
    TargetBinding, TargetBounds,
};
use wcash_pool_edge::{
    JobRouter, JobRouterError, ShareRouter, ShareRouterConfig, ShareRouterError,
};
use wcash_pool_protocol::{CanonicalUuid, Hex32, NonceProfile, TargetBe};
use wcash_pool_store::{
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, PostgresAuthenticationProvider,
    PostgresStore, StoreError,
};

use crate::config::{ChainRuntimePolicy, ConfigError, RuntimeConfig};

const REPLAY_PAGE_ITEMS: u16 = 1_024;
const JOB_UPDATE_CAPACITY: usize = 256;
const MAXIMUM_RECENT_JOBS: usize = 16;
const MAXIMUM_GENERATIONS_PER_PROCESS: usize = 65_536;

/// Live, identity-bound mining components created before any public socket opens.
pub struct MiningBootstrap {
    /// Durable accounting and portal store.
    pub store: Arc<PostgresStore>,
    /// Current authoritative job fanout.
    pub jobs: JobRouter,
    /// Serialized Wolf submission and event-projection actor.
    pub shares: ShareRouter,
    /// Shared portal/Stratum authentication authority.
    pub authentication: Arc<PostgresAuthenticationProvider>,
    /// Transactionally reserved, process-local nonce-prefix allocator.
    pub nonces: Arc<NoncePrefixAllocator>,
    /// Monotonic epoch used by every miner actor in this process.
    pub timeline: MonotonicTimeline,
}

/// Applies append-only schema migrations without connecting to Wolf.
pub async fn migrate(config: &RuntimeConfig) -> Result<(), BootstrapError> {
    let store = connect_store(config).await?;
    store.migrate().await?;
    store.bind_deployment().await?;
    bind_policies(&store, config).await?;
    Ok(())
}

/// Replays every authoritative event, closes the subscription race, and starts
/// the one live share actor before returning public-listener dependencies.
pub async fn start(config: &RuntimeConfig) -> Result<MiningBootstrap, BootstrapError> {
    let store = Arc::new(connect_store(config).await?);
    store.bind_deployment().await?;
    bind_policies(&store, config).await?;

    let last_event_seq = store.last_event_seq().await?;
    let backend_config = backend_config(config)?;
    let mut client = BackendClient::connect(
        backend_config.clone(),
        CanonicalUuid::new(config.pool_instance),
        last_event_seq,
    )
    .await?;
    replay_to_end(&mut client, &store).await?;
    let replayed_through = client.replay_cursor();
    let timeline = MonotonicTimeline::new();
    let snapshot = client.subscribe_jobs(replayed_through).await?;

    if snapshot.event_seq() > snapshot.replayed_through_event_seq() {
        let mut gap = BackendClient::connect(
            backend_config,
            CanonicalUuid::new(config.pool_instance),
            snapshot.replayed_through_event_seq(),
        )
        .await?;
        replay_through(&mut gap, &store, snapshot.event_seq()).await?;
        gap.shutdown().await?;
    }

    let jobs = JobRouter::from_snapshot(
        &snapshot,
        GenerationRegistryConfig::new(MAXIMUM_RECENT_JOBS, MAXIMUM_GENERATIONS_PER_PROCESS)?,
        timeline,
        JOB_UPDATE_CAPACITY,
    )?;
    validate_initial_target_policy(&jobs, config)?;
    let share_config = ShareRouterConfig::new(
        config.maximum_miners.min(4_096),
        Duration::from_secs(5),
        Duration::from_secs(10),
    )?;
    let shares = ShareRouter::spawn(
        client,
        jobs.clone(),
        share_config,
        Arc::clone(&store) as Arc<dyn wcash_pool_edge::BackendEventConsumer>,
    )
    .await?;
    let authentication =
        Arc::new(store.authentication_provider(config.authentication_parallelism)?);
    let namespace = NonceNamespaceLease::new(config.nonce_namespace)?;
    let reservation = store
        .reserve_nonce_range(
            config.pool_instance,
            NonceProfile::FourByte,
            namespace,
            config.nonce_reservation,
        )
        .await?;
    let nonces = Arc::new(reservation.allocator()?);

    Ok(MiningBootstrap {
        store,
        jobs,
        shares,
        authentication,
        nonces,
        timeline,
    })
}

fn validate_initial_target_policy(
    jobs: &JobRouter,
    config: &RuntimeConfig,
) -> Result<(), BootstrapError> {
    let generation = jobs
        .current_generation()?
        .ok_or(BootstrapError::NoCurrentJob)?;
    let initial = ShareTarget::from_zip301(&TargetBe::new(config.initial_share_target_be))?;
    let easiest = ShareTarget::from_zip301(&TargetBe::new(config.easiest_share_target_be))?;
    let bounds = TargetBounds::new(
        generation.wcash_network_target(),
        generation.zcash_network_target(),
        easiest,
    )?;
    TargetBinding::new(1, initial, bounds)?;
    Ok(())
}

async fn connect_store(config: &RuntimeConfig) -> Result<PostgresStore, BootstrapError> {
    let database_url = config.database_url()?;
    PostgresStore::connect(
        &database_url,
        config.database_connections,
        deployment_identity(config),
    )
    .await
    .map_err(BootstrapError::from)
}

fn deployment_identity(config: &RuntimeConfig) -> DeploymentIdentity {
    DeploymentIdentity {
        id: config.deployment_id,
        network: DeploymentNetwork::Testnet,
        wcash_genesis: config.wcash_genesis,
        zcash_genesis: config.zcash_genesis,
        chain_id: config.chain_id,
        wcash_payout_commitment: config.wcash_payout_commitment,
        zcash_payout_commitment: config.zcash_payout_commitment,
        backend_instance: config.backend_instance,
        journal_stream: config.journal_stream,
    }
}

fn backend_config(config: &RuntimeConfig) -> Result<BackendClientConfig, BootstrapError> {
    let expected = ExpectedBackend::new(
        Hex32::new(config.wcash_genesis),
        Hex32::new(config.zcash_genesis),
        config.chain_id,
        Hex32::new(config.wcash_payout_commitment),
        Hex32::new(config.zcash_payout_commitment),
    )?
    .with_backend_instance(CanonicalUuid::new(config.backend_instance))
    .with_journal_stream(CanonicalUuid::new(config.journal_stream));
    Ok(
        BackendClientConfig::new(config.backend_socket.clone(), expected)?
            .with_timeouts(Duration::from_secs(5), Duration::from_secs(20))?
            .with_event_queue_capacity(1_024)?,
    )
}

async fn bind_policies(
    store: &PostgresStore,
    config: &RuntimeConfig,
) -> Result<(), BootstrapError> {
    let wcash = chain_policy(Chain::Wcash, &config.wcash_policy);
    let zcash = chain_policy(Chain::Zcash, &config.zcash_policy);
    store.bind_zero_fee_launch_policies(&wcash, &zcash).await?;
    Ok(())
}

fn chain_policy(chain: Chain, config: &ChainRuntimePolicy) -> ChainPolicy {
    ChainPolicy {
        chain,
        pplns_window_work: config.pplns_window_work.clone(),
        fee_bps: 0,
        payout_threshold_zat: config.payout_threshold_zat,
        required_confirmations: config.required_confirmations,
        maximum_payout_outputs: config.maximum_payout_outputs,
        maximum_network_fee_zat: config.maximum_network_fee_zat,
        maximum_network_fee_bps: config.maximum_network_fee_bps,
        policy_version: config.policy_version,
    }
}

async fn replay_to_end(
    client: &mut BackendClient,
    store: &PostgresStore,
) -> Result<(), BootstrapError> {
    loop {
        let previous = client.replay_cursor();
        let page = client.read_events(previous, REPLAY_PAGE_ITEMS).await?;
        let authority = client.authority();
        store.project_replay_page(&authority, &page.events).await?;
        if page.complete {
            return Ok(());
        }
        if page.next_event_seq <= previous {
            return Err(BootstrapError::StalledReplay);
        }
    }
}

async fn replay_through(
    client: &mut BackendClient,
    store: &PostgresStore,
    required_event_seq: u64,
) -> Result<(), BootstrapError> {
    while client.replay_cursor() < required_event_seq {
        let previous = client.replay_cursor();
        let page = client.read_events(previous, REPLAY_PAGE_ITEMS).await?;
        let authority = client.authority();
        store.project_replay_page(&authority, &page.events).await?;
        if page.next_event_seq <= previous {
            return Err(BootstrapError::StalledReplay);
        }
    }
    Ok(())
}

/// Startup failure that prevents every public listener from opening.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// Protected configuration or credential loading failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// PostgreSQL fencing, projection, or accounting failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Wolf transport or protocol validation failed.
    #[error(transparent)]
    Backend(#[from] ClientError),
    /// Backend client configuration failed.
    #[error(transparent)]
    BackendConfig(#[from] wcash_pool_backend_client::ClientConfigError),
    /// Core generation registry rejected runtime bounds or snapshot state.
    #[error(transparent)]
    JobRegistry(#[from] wcash_pool_core::JobRegistryError),
    /// Live job fanout could not be established.
    #[error(transparent)]
    JobRouter(#[from] JobRouterError),
    /// Live serialized share/event actor could not be established.
    #[error(transparent)]
    ShareRouter(#[from] ShareRouterError),
    /// Share actor policy was invalid.
    #[error(transparent)]
    ShareRouterConfig(#[from] wcash_pool_edge::ShareRouterConfigError),
    /// Nonce namespace or reserved range was invalid.
    #[error(transparent)]
    Nonce(#[from] wcash_pool_core::NoncePrefixError),
    /// Configured share-target policy cannot include every network winner.
    #[error(transparent)]
    TargetPolicy(#[from] wcash_pool_core::TargetPolicyError),
    /// Configured share target was zero or malformed.
    #[error(transparent)]
    ShareTarget(#[from] wcash_pool_core::ShareTargetError),
    /// Wolf did not provide a current proposal-validated job.
    #[error("backend snapshot has no current mineable job")]
    NoCurrentJob,
    /// An incomplete replay page did not advance its cursor.
    #[error("backend journal replay made no progress")]
    StalledReplay,
}

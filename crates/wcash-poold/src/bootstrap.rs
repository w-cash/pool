//! Fail-closed database, journal replay, and live mining bootstrap.

use std::{future::Future, sync::Arc, time::Duration};

use tokio::time;
use uuid::Uuid;
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
    Chain, ChainPolicy, DeploymentIdentity, DeploymentNetwork, NonceNamespaceClaim, NonceRange,
    PostgresAuthenticationProvider, PostgresEventProjector, PostgresStore, StoreError,
};

use crate::config::{ChainRuntimePolicy, ConfigError, RuntimeConfig};

const REPLAY_PAGE_ITEMS: u16 = 1_024;
const JOB_UPDATE_CAPACITY: usize = 256;
const MAXIMUM_RECENT_JOBS: usize = 16;
const MAXIMUM_GENERATIONS_PER_PROCESS: usize = 65_536;
// Startup may cross one normal Zcash parent-tip rollover while the template
// node and independent validator converge. Keep preflight bounded, but long
// enough to match the live share-router and projector recovery windows.
const BACKEND_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const BACKEND_READINESS_RETRY_INTERVAL: Duration = Duration::from_millis(250);
/// Database-clock lease duration renewed by the serving process.
pub const NONCE_NAMESPACE_LEASE_DURATION: Duration = Duration::from_secs(60);

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
    /// Process-unique database claim fencing the allocator's namespace.
    pub nonce_claim: NonceNamespaceClaim,
    /// Monotonic epoch used by every miner actor in this process.
    pub timeline: MonotonicTimeline,
}

/// Snapshot-bound dependencies exercised by preflight without starting a
/// live share actor or retaining a database nonce lease.
pub struct MiningPreflight {
    /// Durable accounting store after deployment and policy binding.
    pub store: Arc<PostgresStore>,
    /// Exact current backend generation used for authority-tip binding.
    pub jobs: JobRouter,
    _authentication: Arc<PostgresAuthenticationProvider>,
    _timeline: MonotonicTimeline,
}

/// Database dependency retained by the non-listening payout worker.
///
/// The worker deliberately does not retain a job snapshot across wallet sync.
/// It obtains a fresh, exact backend snapshot only after both chain authorities
/// have been observed, immediately before binding those tips.
pub struct PayoutBootstrap {
    /// Durable accounting store opened with the payout-worker database role.
    pub store: Arc<PostgresStore>,
}

/// Durable writer and live Wolf connection retained by the isolated projector.
///
/// This bootstrap deliberately contains no listener, authentication provider,
/// nonce allocator, portal authority, or payout signer.
pub struct ProjectorBootstrap {
    /// Identity-bound live journal connection.
    pub client: BackendClient,
    /// Explicit database capability for projecting accounting events.
    pub projector: PostgresEventProjector,
}

struct PreparedBootstrap {
    store: Arc<PostgresStore>,
    jobs: JobRouter,
    client: BackendClient,
    authentication: Arc<PostgresAuthenticationProvider>,
    timeline: MonotonicTimeline,
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
    let PreparedBootstrap {
        store,
        jobs,
        client,
        authentication,
        timeline,
    } = prepare(config).await?;
    let (nonce_claim, nonces) = claim_nonce_allocator(&store, config).await?;
    let share_config = ShareRouterConfig::new(
        config.maximum_miners.min(4_096),
        Duration::from_millis(50),
        Duration::from_secs(10),
    )?;
    let shares = match ShareRouter::spawn(
        client,
        jobs.clone(),
        share_config,
        Arc::clone(&store) as Arc<dyn wcash_pool_edge::BackendEventConsumer>,
    )
    .await
    {
        Ok(shares) => shares,
        Err(error) => {
            return fail_after_nonce_claim(&store, &nonce_claim, BootstrapError::from(error)).await;
        }
    };

    Ok(MiningBootstrap {
        store,
        jobs,
        shares,
        authentication,
        nonces,
        nonce_claim,
        timeline,
    })
}

/// Exercises database, replay, authenticated job snapshot, authentication,
/// and exclusive nonce-namespace ownership without spawning a live actor. The
/// backend connection and nonce claim are both closed before this function
/// returns. Preflight deliberately reserves no nonce range: no prefix is ever
/// exposed to a miner, so advancing the finite counter would only consume
/// availability on every service-manager restart.
pub async fn preflight(config: &RuntimeConfig) -> Result<MiningPreflight, BootstrapError> {
    let PreparedBootstrap {
        store,
        jobs,
        client,
        authentication,
        timeline,
    } = wait_for_ready_backend(config).await?;
    client.shutdown().await?;

    let nonce_claim = claim_nonce_namespace(&store, config).await?;
    store.release_nonce_namespace(&nonce_claim).await?;

    Ok(MiningPreflight {
        store,
        jobs,
        _authentication: authentication,
        _timeline: timeline,
    })
}

async fn wait_for_ready_backend(
    config: &RuntimeConfig,
) -> Result<PreparedBootstrap, BootstrapError> {
    wait_for_backend_readiness(
        BACKEND_READINESS_TIMEOUT,
        BACKEND_READINESS_RETRY_INTERVAL,
        || prepare_readiness_attempt(config),
    )
    .await
}

async fn prepare_readiness_attempt(
    config: &RuntimeConfig,
) -> Result<Option<PreparedBootstrap>, BootstrapError> {
    let mut prepared = match prepare(config).await {
        Ok(prepared) => prepared,
        Err(BootstrapError::NoCurrentJob) => return Ok(None),
        Err(error) => return Err(error),
    };
    let health = prepared.client.health().await?;
    let event_queue_empty = prepared.client.queued_event_count() == 0;
    if backend_snapshot_is_ready(health.healthy, event_queue_empty) {
        Ok(Some(prepared))
    } else {
        prepared.client.shutdown().await?;
        Ok(None)
    }
}

const fn backend_snapshot_is_ready(healthy: bool, event_queue_empty: bool) -> bool {
    healthy && event_queue_empty
}

async fn wait_for_backend_readiness<T, Attempt, AttemptFuture>(
    timeout: Duration,
    retry_interval: Duration,
    mut attempt: Attempt,
) -> Result<T, BootstrapError>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Option<T>, BootstrapError>>,
{
    match time::timeout(timeout, async {
        loop {
            if let Some(ready) = attempt().await? {
                return Ok(ready);
            }
            time::sleep(retry_interval).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(BootstrapError::BackendReadinessTimeout),
    }
}

/// Verifies the payout worker's database identity and policy without claiming
/// a nonce namespace, opening a listener, or retaining a backend snapshot.
pub async fn payout(config: &RuntimeConfig) -> Result<PayoutBootstrap, BootstrapError> {
    let store = Arc::new(connect_store(config).await?);
    store.verify_deployment().await?;
    verify_policies(&store, config).await?;

    Ok(PayoutBootstrap { store })
}

/// Obtains a race-free, verifier-only snapshot of the current Wolf job.
///
/// Callers must invoke this immediately before binding independently observed
/// chain tips. The payout database role verifies the projector's exact rows;
/// it never projects an event or writes mining accounting state itself.
pub async fn payout_jobs(
    config: &RuntimeConfig,
    store: &PostgresStore,
) -> Result<JobRouter, BootstrapError> {
    store.verify_deployment().await?;
    verify_policies(store, config).await?;

    let last_event_seq = store.last_event_seq().await?;
    let backend_config = backend_config(config)?;
    let mut client = BackendClient::connect(
        backend_config.clone(),
        CanonicalUuid::new(config.pool_instance),
        last_event_seq,
    )
    .await?;
    replay_to_end(&mut client, store).await?;
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
        replay_through(&mut gap, store, snapshot.event_seq()).await?;
        gap.shutdown().await?;
    }
    client.shutdown().await?;

    let jobs = JobRouter::from_snapshot(
        &snapshot,
        GenerationRegistryConfig::new(MAXIMUM_RECENT_JOBS, MAXIMUM_GENERATIONS_PER_PROCESS)?,
        timeline,
        JOB_UPDATE_CAPACITY,
    )?;
    validate_initial_target_policy(&jobs, config)?;

    Ok(jobs)
}

/// Reconciles the durable Wolf journal with PostgreSQL, closes the subscribe
/// race, and returns one live, identity-bound projector connection.
///
/// Only the explicit [`PostgresEventProjector`] capability writes accounting
/// state. The process does not construct any public or spending authority.
pub async fn projector(config: &RuntimeConfig) -> Result<ProjectorBootstrap, BootstrapError> {
    let store = connect_store(config).await?;
    store.verify_deployment().await?;
    verify_policies(&store, config).await?;

    let last_event_seq = store.last_event_seq().await?;
    let projector = store.event_projector();
    let backend_config = backend_config(config)?;
    let mut client = BackendClient::connect(
        backend_config.clone(),
        CanonicalUuid::new(config.pool_instance),
        last_event_seq,
    )
    .await?;
    projector_replay_to_end(&mut client, &projector).await?;
    let replayed_through = client.replay_cursor();
    let snapshot = client.subscribe_jobs(replayed_through).await?;

    if snapshot.event_seq() > snapshot.replayed_through_event_seq() {
        let mut gap = BackendClient::connect(
            backend_config,
            CanonicalUuid::new(config.pool_instance),
            snapshot.replayed_through_event_seq(),
        )
        .await?;
        projector_replay_through(&mut gap, &projector, snapshot.event_seq()).await?;
        gap.shutdown().await?;
    }

    Ok(ProjectorBootstrap { client, projector })
}

async fn prepare(config: &RuntimeConfig) -> Result<PreparedBootstrap, BootstrapError> {
    let store = Arc::new(connect_store(config).await?);
    store.verify_deployment().await?;
    verify_policies(&store, config).await?;

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
    let authentication = Arc::new(store.authentication_provider(
        config.authentication_parallelism,
        config.mining_authentication,
    )?);

    Ok(PreparedBootstrap {
        store,
        jobs,
        client,
        authentication,
        timeline,
    })
}

async fn claim_nonce_allocator(
    store: &Arc<PostgresStore>,
    config: &RuntimeConfig,
) -> Result<(NonceNamespaceClaim, Arc<NoncePrefixAllocator>), BootstrapError> {
    let nonce_claim = claim_nonce_namespace(store, config).await?;
    let reservation = match reserve_nonce_tail(store, &nonce_claim, config.nonce_reservation).await
    {
        Ok(reservation) => reservation,
        Err(error) => {
            let startup = BootstrapError::from(error);
            return fail_after_nonce_claim(store, &nonce_claim, startup).await;
        }
    };
    let nonces = match reservation.allocator() {
        Ok(allocator) => Arc::new(allocator),
        Err(error) => {
            let startup = BootstrapError::from(error);
            return fail_after_nonce_claim(store, &nonce_claim, startup).await;
        }
    };
    Ok((nonce_claim, nonces))
}

async fn claim_nonce_namespace(
    store: &PostgresStore,
    config: &RuntimeConfig,
) -> Result<NonceNamespaceClaim, BootstrapError> {
    let namespace = NonceNamespaceLease::new(config.nonce_namespace)?;
    store
        .claim_nonce_namespace(
            Uuid::new_v4(),
            NonceProfile::FourByte,
            namespace,
            NONCE_NAMESPACE_LEASE_DURATION,
        )
        .await
        .map_err(BootstrapError::from)
}

async fn fail_after_nonce_claim<T>(
    store: &PostgresStore,
    claim: &NonceNamespaceClaim,
    startup: BootstrapError,
) -> Result<T, BootstrapError> {
    match store.release_nonce_namespace(claim).await {
        Ok(()) => Err(startup),
        Err(cleanup) => Err(BootstrapError::NonceClaimCleanup {
            startup: Box::new(startup),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// Reserves the largest reviewed chunk obtainable near permanent namespace
/// exhaustion. Every rejected attempt is a rolled-back transaction, and only
/// `NonceNamespaceExhausted` permits a smaller retry.
pub(crate) async fn reserve_nonce_tail(
    store: &PostgresStore,
    claim: &NonceNamespaceClaim,
    requested: u64,
) -> Result<NonceRange, StoreError> {
    let mut attempt = requested;
    loop {
        match store.reserve_nonce_range(claim, attempt).await {
            Ok(range) => return Ok(range),
            Err(error @ StoreError::NonceNamespaceExhausted) => {
                let Some(smaller) = smaller_nonce_reservation(attempt) else {
                    return Err(error);
                };
                attempt = smaller;
            }
            Err(error) => return Err(error),
        }
    }
}

fn smaller_nonce_reservation(current: u64) -> Option<u64> {
    (current > 1).then(|| (current / 2).max(1))
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
        network: match config.network {
            wcash_pool_portal::ChainNetwork::Testnet => DeploymentNetwork::Testnet,
            wcash_pool_portal::ChainNetwork::Mainnet => DeploymentNetwork::Mainnet,
            #[cfg(feature = "regtest")]
            wcash_pool_portal::ChainNetwork::Regtest => DeploymentNetwork::Regtest,
        },
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
        TargetBe::new(config.easiest_share_target_be),
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

async fn verify_policies(
    store: &PostgresStore,
    config: &RuntimeConfig,
) -> Result<(), BootstrapError> {
    let wcash = chain_policy(Chain::Wcash, &config.wcash_policy);
    let zcash = chain_policy(Chain::Zcash, &config.zcash_policy);
    store
        .verify_zero_fee_launch_policies(&wcash, &zcash)
        .await?;
    Ok(())
}

fn chain_policy(chain: Chain, config: &ChainRuntimePolicy) -> ChainPolicy {
    ChainPolicy {
        chain,
        pplns_window_work: config.pplns_window_work.clone(),
        fee_bps: 0,
        payout_threshold_zat: config.payout_threshold_zat,
        required_confirmations: config.required_confirmations,
        payout_confirmations: config.payout_confirmations,
        maximum_payout_outputs: config.maximum_payout_outputs,
        minimum_payout_zat: config.minimum_payout_zat,
        maximum_payout_zat: config.maximum_payout_zat,
        payout_skip_bps: config.payout_skip_bps,
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

async fn projector_replay_to_end(
    client: &mut BackendClient,
    projector: &PostgresEventProjector,
) -> Result<(), BootstrapError> {
    loop {
        let previous = client.replay_cursor();
        let page = client.read_events(previous, REPLAY_PAGE_ITEMS).await?;
        let authority = client.authority();
        projector
            .project_replay_page(&authority, &page.events)
            .await?;
        if page.complete {
            return Ok(());
        }
        if page.next_event_seq <= previous {
            return Err(BootstrapError::StalledReplay);
        }
    }
}

async fn projector_replay_through(
    client: &mut BackendClient,
    projector: &PostgresEventProjector,
    required_event_seq: u64,
) -> Result<(), BootstrapError> {
    while client.replay_cursor() < required_event_seq {
        let previous = client.replay_cursor();
        let page = client.read_events(previous, REPLAY_PAGE_ITEMS).await?;
        let authority = client.authority();
        projector
            .project_replay_page(&authority, &page.events)
            .await?;
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
    /// Wolf did not expose one current, healthy, event-exact snapshot in time.
    #[error("backend did not become ready before the bounded preflight deadline")]
    BackendReadinessTimeout,
    /// An incomplete replay page did not advance its cursor.
    #[error("backend journal replay made no progress")]
    StalledReplay,
    /// Nonce startup failed and the acquired database lease could not be released.
    #[error("nonce startup failed ({startup}); namespace cleanup also failed ({cleanup})")]
    NonceClaimCleanup {
        /// Original reservation or allocator failure.
        startup: Box<BootstrapError>,
        /// Independent database failure while releasing the claim.
        cleanup: Box<StoreError>,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{cell::Cell, rc::Rc, time::Duration};

    use super::{
        backend_snapshot_is_ready, smaller_nonce_reservation, wait_for_backend_readiness,
        BootstrapError,
    };

    #[test]
    fn nonce_tail_backoff_terminates_at_one_without_skipping_it() {
        assert_eq!(smaller_nonce_reservation(9), Some(4));
        assert_eq!(smaller_nonce_reservation(4), Some(2));
        assert_eq!(smaller_nonce_reservation(2), Some(1));
        assert_eq!(smaller_nonce_reservation(1), None);
    }

    #[test]
    fn preflight_requires_a_healthy_event_exact_backend_snapshot() {
        assert!(backend_snapshot_is_ready(true, true));
        assert!(!backend_snapshot_is_ready(false, true));
        assert!(!backend_snapshot_is_ready(true, false));
        assert!(!backend_snapshot_is_ready(false, false));
    }

    #[tokio::test(start_paused = true)]
    async fn preflight_waits_through_transient_backend_rotation() {
        let attempts = Rc::new(Cell::new(0_u8));
        let observed = Rc::clone(&attempts);
        let ready = wait_for_backend_readiness(
            Duration::from_secs(5),
            Duration::from_millis(250),
            move || {
                let attempt = observed.get();
                observed.set(attempt + 1);
                async move { Ok::<_, BootstrapError>((attempt == 2).then_some(attempt)) }
            },
        )
        .await
        .expect("the third exact snapshot is healthy");

        assert_eq!(ready, 2);
        assert_eq!(attempts.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn preflight_backend_readiness_wait_has_a_hard_deadline() {
        let result = wait_for_backend_readiness(
            Duration::from_secs(1),
            Duration::from_millis(250),
            || async { Ok::<Option<()>, BootstrapError>(None) },
        )
        .await;

        assert!(matches!(
            result,
            Err(BootstrapError::BackendReadinessTimeout)
        ));
    }
}

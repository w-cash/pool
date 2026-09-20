//! Testnet service composition and ordered process shutdown.

use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};

#[cfg(unix)]
use std::{ffi::OsStr, os::unix::net::UnixDatagram, path::Path};

use tokio::{net::TcpListener, sync::watch, task::JoinSet, time};
use wcash_pool_address::{TestnetAddressValidator, WcashCommandValidator};
use wcash_pool_backend_client::BackendClient;
use wcash_pool_edge::{JobRouter, ShareRouterError};
use wcash_pool_portal::{
    serve_until_shutdown, AddressValidator, Asset, ChainNetwork, IsolatedPayoutSigner,
    MinerTelemetrySource, PoolDataSource, PoolOverview, PortalApp, PortalBuildError, PortalConfig,
    PortalRepository, PortalSecrets, TestnetPayoutBoundary,
};
use wcash_pool_store::{
    Chain, NonceNamespaceClaim, PostgresEventProjector, PostgresPoolDataSource, PostgresStore,
    StoreError,
};
use wcash_wec_payout_signer::{SeedSource, WalletFundSource, WecPayoutSigner, WecSignerConfig};

use crate::{
    bootstrap::{self, BootstrapError, MiningBootstrap},
    config::{
        AutomaticPayoutChain, AutomaticPayoutConfig, ConfigError, PayoutMode, RuntimeConfig,
        MAX_WCASH_WALLET_SYNC_TIMEOUT,
    },
    edge::{self, EdgeCounters, EdgeDependencies, EdgeRuntimeError},
    live_payout::{
        LivePayoutConfigError, LoopbackJsonRpc, NodePayoutAuthority, RpcExactBroadcaster,
    },
    miner_telemetry::LiveMinerTelemetry,
    payout_runtime::{
        AutomaticPayoutRuntime, ObservationFailure, PayoutConfirmationAuthority, PayoutLoopPolicy,
        PayoutRuntimeError, WalletObservationSource, WcashObservationSource,
    },
    settlement::{
        ReconciliationGate, ResumeOutcome, SettlementError, SettlementOrchestrator,
        WecExecutionSigner,
    },
    wcash_observation::WcashWalletObserver,
    wec_wallet_transport::{PinnedWolfProgram, WolfWalletTransport},
};

const ADDRESS_VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);
const PORTAL_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
// The WEC worker can enter one non-cancellable, bounded wallet sync followed by
// a crash-safe signer pass. Keep the process alive long enough for every child
// deadline to fire, be reaped, and persist its journal result before Tokio
// tasks may be aborted. The service manager must use a larger stop timeout.
const SERVICE_DRAIN_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub(crate) const REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT: Duration = Duration::from_secs(31 * 60);
const SHARE_ROUTER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const COMPONENT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const PAYOUT_POLL_INTERVAL: Duration = Duration::from_secs(15);
const PAYOUT_RETRY_INITIAL: Duration = Duration::from_secs(1);
const PAYOUT_RETRY_MAXIMUM: Duration = Duration::from_secs(60);
const PAYOUT_MAXIMUM_CONSECUTIVE_FAILURES: u32 = 20;
// Serial historical lookups have their own 15-second bounds. Capping a pass at
// eight watches keeps their worst case inside the non-cancellable drain bound;
// any backlog advances deterministically on later ticks.
const PAYOUT_MAXIMUM_CONFIRMATION_WATCHES: u32 = 8;
const PAYOUT_WORKER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const PROJECTOR_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(50);
const PREFLIGHT_PAYOUT_AUTHORITY_ATTEMPTS: u8 = 30;
const PREFLIGHT_PAYOUT_AUTHORITY_RETRY_INTERVAL: Duration = Duration::from_secs(1);
// A Zcash block can take longer than thirty seconds on the Testnet and the
// backend must briefly retry while its two pinned parents converge on the
// same tip. The backend advertises jobs for 45 seconds, so the projector must
// tolerate a bounded rotation gap without tearing down the public pool. A
// two-minute grace still fails closed well before an operator would mistake a
// stale backend for a healthy one.
const PROJECTOR_BACKEND_UNHEALTHY_GRACE: Duration = Duration::from_secs(120);
const PROJECTOR_BATCH_TIMEOUT: Duration = Duration::from_secs(20);
const PAYOUT_WORKER_LEASE_DURATION: Duration = Duration::from_secs(35 * 60);
const PAYOUT_WORKER_LEASE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
// A successor remains alive without constructing either signer while a lease
// left by SIGKILL reaches its database-clock expiry. The extra minute covers
// the final poll and ordinary scheduling delay without weakening the fence.
const PAYOUT_WORKER_LEASE_ACQUIRE_WAIT: Duration = Duration::from_secs(36 * 60);
pub(crate) const REQUIRED_PAYOUT_READINESS_TIMEOUT: Duration = Duration::from_secs(70 * 60);
const MAX_WEC_DEFAULT_SIGNER_PASS_SECS: u64 = 15 + 15 + 300 + 30 + 15;
const MAX_EMPTY_AUTHORITY_SNAPSHOT_SECS: u64 = 2 * (15 + 10 + 10);
const MAX_AUTHORITY_WATCH_SECS: u64 = 15 + 10;
const MAX_EXACT_BROADCAST_PASS_SECS: u64 = 35 + 15 + 15 + 15 + 35;
const SIGNER_READINESS_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const MAX_WEC_IN_FLIGHT_PASS_SECS: u64 = MAX_WCASH_WALLET_SYNC_TIMEOUT.as_secs()
    + 15
    + MAX_EMPTY_AUTHORITY_SNAPSHOT_SECS
    + MAX_AUTHORITY_WATCH_SECS * PAYOUT_MAXIMUM_CONFIRMATION_WATCHES as u64
    + MAX_WEC_DEFAULT_SIGNER_PASS_SECS
    + MAX_EXACT_BROADCAST_PASS_SECS;
const _: () = assert!(SERVICE_DRAIN_TIMEOUT.as_secs() > MAX_WEC_IN_FLIGHT_PASS_SECS);
const _: () =
    assert!(REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT.as_secs() > SERVICE_DRAIN_TIMEOUT.as_secs());
const _: () = assert!(
    PAYOUT_WORKER_LEASE_DURATION.as_secs() > REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT.as_secs() + 60
);
const _: () = assert!(
    PAYOUT_WORKER_LEASE_ACQUIRE_WAIT.as_secs()
        >= PAYOUT_WORKER_LEASE_DURATION.as_secs() + PAYOUT_WORKER_LEASE_RETRY_INTERVAL.as_secs()
);
const _: () = assert!(
    REQUIRED_PAYOUT_READINESS_TIMEOUT.as_secs()
        > PAYOUT_WORKER_LEASE_ACQUIRE_WAIT.as_secs() + SERVICE_DRAIN_TIMEOUT.as_secs()
);

/// Starts every Testnet dependency before opening either listener, then runs
/// until a termination signal or any authority component exits.
pub async fn run(config: RuntimeConfig) -> Result<(), ServiceError> {
    if config.payout_mode != PayoutMode::Deferred || config.automatic_payout.is_some() {
        return Err(ServiceError::PublicServiceHasPayoutAuthority);
    }
    let mut bootstrap = Some(bootstrap::start(&config).await?);
    let service_result = run_started(&config, &mut bootstrap).await;
    let Some(owned) = bootstrap.take() else {
        return service_result;
    };
    let cleanup_result = shutdown_bootstrap(owned).await;
    combine_service_and_cleanup(service_result, cleanup_result)
}

/// Runs the sole durable Wolf journal projector without opening a TCP listener.
///
/// This process receives only the projector database credential. It constructs
/// no portal authentication, nonce, node-RPC, wallet, or payout authority.
pub async fn run_projector(config: RuntimeConfig) -> Result<(), ServiceError> {
    validate_projector_authority(config.payout_mode, config.automatic_payout.is_some())?;

    let bootstrap::ProjectorBootstrap {
        mut client,
        projector,
    } = bootstrap::projector(&config).await?;
    let service_result = run_projector_loop(&mut client, &projector, shutdown_signal()).await;
    let cleanup_result = client
        .shutdown()
        .await
        .map_err(BootstrapError::from)
        .map_err(ServiceError::from);
    combine_service_and_cleanup(service_result, cleanup_result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectorBackendHealth {
    Healthy,
    TransientlyUnhealthy,
    GraceExpired,
}

#[derive(Debug, Default)]
struct ProjectorBackendHealthWindow {
    unhealthy_since: Option<time::Instant>,
}

impl ProjectorBackendHealthWindow {
    fn observe(&mut self, healthy: bool, now: time::Instant) -> ProjectorBackendHealth {
        if healthy {
            self.unhealthy_since = None;
            return ProjectorBackendHealth::Healthy;
        }

        let unhealthy_since = *self.unhealthy_since.get_or_insert(now);
        if now.duration_since(unhealthy_since) >= PROJECTOR_BACKEND_UNHEALTHY_GRACE {
            ProjectorBackendHealth::GraceExpired
        } else {
            ProjectorBackendHealth::TransientlyUnhealthy
        }
    }
}

async fn run_projector_loop<S>(
    client: &mut BackendClient,
    projector: &PostgresEventProjector,
    shutdown: S,
) -> Result<(), ServiceError>
where
    S: Future<Output = io::Result<()>>,
{
    let mut heartbeat = time::interval(PROJECTOR_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut backend_health = ProjectorBackendHealthWindow::default();
    tokio::pin!(shutdown);

    loop {
        // Backend request futures are deliberately never cancelled because a
        // partial framed response makes the connection correlation unusable.
        if !wait_for_projector_heartbeat(&mut heartbeat, shutdown.as_mut()).await? {
            return Ok(());
        }

        // Valid journal events received before a failing health response are
        // still durable facts and must be projected before the process exits.
        let health = client
            .health()
            .await
            .map_err(BootstrapError::from)
            .map_err(ServiceError::from);
        drain_projector_events(client, projector).await?;
        let health = health?;
        if backend_health.observe(health.healthy, time::Instant::now())
            == ProjectorBackendHealth::GraceExpired
        {
            return Err(ServiceError::ProjectorBackendUnhealthy);
        }
    }
}

fn validate_projector_authority(
    payout_mode: PayoutMode,
    has_automatic_payout: bool,
) -> Result<(), ServiceError> {
    if payout_mode != PayoutMode::Deferred || has_automatic_payout {
        Err(ServiceError::ProjectorHasPayoutAuthority)
    } else {
        Ok(())
    }
}

async fn wait_for_projector_heartbeat<S>(
    heartbeat: &mut time::Interval,
    shutdown: Pin<&mut S>,
) -> io::Result<bool>
where
    S: Future<Output = io::Result<()>>,
{
    tokio::select! {
        biased;
        signal = shutdown => {
            signal?;
            Ok(false)
        }
        _ = heartbeat.tick() => Ok(true),
    }
}

async fn drain_projector_events(
    client: &mut BackendClient,
    projector: &PostgresEventProjector,
) -> Result<(), ServiceError> {
    let binding = client
        .connection_binding()
        .ok_or(ServiceError::ProjectorConnectionMismatch)?;
    let mut events = Vec::with_capacity(client.queued_event_count());
    while let Some(event) = client.pop_queued_event() {
        if event.connection_binding() != &binding {
            return Err(ServiceError::ProjectorConnectionMismatch);
        }
        events.push(event.event().clone());
    }
    if events.is_empty() {
        return Ok(());
    }

    match time::timeout(
        PROJECTOR_BATCH_TIMEOUT,
        projector.project_replay_page(binding.authority(), &events),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ServiceError::ProjectorRejected(error)),
        Err(_) => Err(ServiceError::ProjectorBatchTimeout),
    }
}

/// Runs the key-bearing payout lifecycle without opening any TCP listener.
///
/// A database-clock lease prevents two workers from signing concurrently. The
/// public service can only advertise enabled payouts while this independently
/// authenticated worker continues to refresh its durable heartbeat.
pub async fn run_payout_worker(config: RuntimeConfig) -> Result<(), ServiceError> {
    if config.payout_mode != PayoutMode::Automatic || config.automatic_payout.is_none() {
        return Err(ServiceError::PayoutWorkerMissingAuthority);
    }

    let started = bootstrap::payout(&config).await?;
    let worker_instance = uuid::Uuid::new_v4();
    let acquire_store = Arc::clone(&started.store);
    let acquired = wait_for_payout_worker_lease(
        move || {
            let store = Arc::clone(&acquire_store);
            async move {
                store
                    .acquire_payout_worker(worker_instance, PAYOUT_WORKER_LEASE_DURATION)
                    .await
            }
        },
        PAYOUT_WORKER_LEASE_ACQUIRE_WAIT,
        PAYOUT_WORKER_LEASE_RETRY_INTERVAL,
        shutdown_signal(),
        time::sleep,
    )
    .await?;
    if !acquired {
        return Ok(());
    }

    let release_store = Arc::clone(&started.store);
    with_payout_worker_lease(
        async { Ok(true) },
        || run_acquired_payout_worker(&config, &started, worker_instance),
        || async move { release_store.release_payout_worker(worker_instance).await },
    )
    .await
}

/// Waits inside one service process for an orphaned lease to expire.
///
/// Acquisition is always decided by PostgreSQL's clock. While waiting, this
/// process has no signer, wallet, heartbeat, or payout authority, and a normal
/// shutdown exits without attempting to release the predecessor's lease.
async fn wait_for_payout_worker_lease<A, AF, S, W, WF>(
    mut acquire: A,
    maximum_wait: Duration,
    retry_interval: Duration,
    shutdown: S,
    mut wait: W,
) -> Result<bool, ServiceError>
where
    A: FnMut() -> AF,
    AF: Future<Output = Result<bool, StoreError>>,
    S: Future<Output = io::Result<()>>,
    W: FnMut(Duration) -> WF,
    WF: Future<Output = ()>,
{
    if maximum_wait.is_zero() || retry_interval.is_zero() {
        return Err(ServiceError::Invariant);
    }

    let mut remaining = maximum_wait;
    tokio::pin!(shutdown);
    loop {
        // Do not cancel this database request mid-flight. A successful insert
        // or takeover must be observed before any shutdown path can exit.
        if acquire().await? {
            return Ok(true);
        }
        if remaining.is_zero() {
            return Err(ServiceError::PayoutWorkerAlreadyActive);
        }

        let delay = retry_interval.min(remaining);
        let delay_elapsed = wait(delay);
        tokio::pin!(delay_elapsed);
        tokio::select! {
            biased;
            signal = &mut shutdown => {
                signal?;
                return Ok(false);
            }
            () = &mut delay_elapsed => {}
        }
        remaining = remaining.saturating_sub(delay);
    }
}

async fn with_payout_worker_lease<A, AF, R>(
    acquire: A,
    action: impl FnOnce() -> AF,
    release: impl FnOnce() -> R,
) -> Result<(), ServiceError>
where
    A: Future<Output = Result<bool, StoreError>>,
    AF: Future<Output = Result<(), ServiceError>>,
    R: Future<Output = Result<bool, StoreError>>,
{
    if !acquire.await? {
        return Err(ServiceError::PayoutWorkerAlreadyActive);
    }
    let service_result = action().await;
    if service_result
        .as_ref()
        .is_err_and(|error| !error.payout_worker_lease_can_release())
    {
        // A Tokio task that exceeded the drain deadline may still own a
        // non-cancellable blocking wallet call. Preserve the 35-minute DB
        // takeover fence and let systemd's shorter stop timeout kill the old
        // process before any successor can acquire authority.
        return service_result;
    }
    let release_result = release()
        .await
        .map_err(ServiceError::from)
        .and_then(|released| {
            if released {
                Ok(())
            } else {
                Err(ServiceError::PayoutWorkerLeaseLost)
            }
        });
    combine_service_and_cleanup(service_result, release_result)
}

async fn mark_payout_ready_or_shutdown<R, S>(
    mark_ready: R,
    shutdown: S,
) -> Result<bool, ServiceError>
where
    R: Future<Output = Result<bool, StoreError>>,
    S: Future<Output = io::Result<()>>,
{
    tokio::pin!(mark_ready);
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        signal = &mut shutdown => {
            signal?;
            Ok(false)
        }
        result = &mut mark_ready => {
            match result? {
                true => Ok(true),
                false => Err(ServiceError::PayoutWorkerLeaseLost),
            }
        }
    }
}

async fn run_acquired_payout_worker(
    config: &RuntimeConfig,
    started: &crate::bootstrap::PayoutBootstrap,
    worker_instance: uuid::Uuid,
) -> Result<(), ServiceError> {
    // Heartbeat begins before any signer is constructed or any journal,
    // reconciliation, or external recovery transition can occur. Losing the
    // lease cancels startup immediately.
    let (heartbeat_shutdown_tx, heartbeat_shutdown_rx) = watch::channel(false);
    let mut heartbeat_tasks = JoinSet::new();
    let heartbeat_store = Arc::clone(&started.store);
    let mut heartbeat_shutdown = heartbeat_shutdown_rx;
    heartbeat_tasks.spawn(async move {
        ServiceTask::PayoutHeartbeat(
            maintain_payout_worker_heartbeat(
                heartbeat_store,
                worker_instance,
                &mut heartbeat_shutdown,
            )
            .await,
        )
    });
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let startup_config = config.clone();
    let startup_store = Arc::clone(&started.store);
    let mut startup_tasks = JoinSet::new();
    startup_tasks.spawn(async move { build_payout_services(&startup_config, startup_store).await });
    let startup_result = tokio::select! {
        biased;
        signal = &mut shutdown => {
            signal?;
            Ok(None)
        }
        result = heartbeat_tasks.join_next() => {
            Err(classify_task_exit(result).err().unwrap_or(ServiceError::Invariant))
        }
        result = startup_tasks.join_next() => {
            classify_payout_startup_exit(result).map(Some)
        }
    };
    let payout_services = match startup_result {
        Ok(Some(services)) => services,
        Ok(None) => {
            let startup_cleanup = drain_payout_startup(&mut startup_tasks).await;
            let _ = heartbeat_shutdown_tx.send(true);
            let heartbeat_cleanup = drain_service_tasks(&mut heartbeat_tasks).await;
            return combine_service_and_cleanup(startup_cleanup, heartbeat_cleanup);
        }
        Err(error) => {
            let startup_cleanup = drain_payout_startup(&mut startup_tasks).await;
            let _ = heartbeat_shutdown_tx.send(true);
            let heartbeat_cleanup = drain_service_tasks(&mut heartbeat_tasks).await;
            let cleanup = combine_service_and_cleanup(startup_cleanup, heartbeat_cleanup);
            return combine_service_and_cleanup(Err(error), cleanup);
        }
    };

    let (payout_shutdown_tx, payout_shutdown_rx) = watch::channel(false);
    let mut payout_tasks = JoinSet::new();
    let wec = Arc::clone(&payout_services.wec);
    let wec_shutdown = payout_shutdown_rx;
    payout_tasks.spawn(async move { ServiceTask::WecPayout(wec.run(wec_shutdown).await) });

    // A worker becomes externally ready only after its enabled runtime exists
    // and signer recovery/reconciliation performed by construction succeeds.
    let ready_result = {
        let ready_store = Arc::clone(&started.store);
        let mark_ready = async {
            let marked = mark_payout_ready_or_shutdown(
                ready_store.mark_payout_worker_ready(worker_instance),
                &mut shutdown,
            )
            .await?;
            if !marked {
                return Ok(false);
            }
            if let Err(notification_error) = notify_service_manager_ready() {
                let withdrawal = ready_store
                    .mark_payout_worker_not_ready(worker_instance)
                    .await
                    .map_err(ServiceError::from)
                    .and_then(|updated| {
                        if updated {
                            Ok(())
                        } else {
                            Err(ServiceError::PayoutWorkerLeaseLost)
                        }
                    });
                return match combine_service_and_cleanup(Err(notification_error), withdrawal) {
                    Err(error) => Err(error),
                    Ok(()) => Err(ServiceError::Invariant),
                };
            }
            Ok(true)
        };
        tokio::pin!(mark_ready);
        tokio::select! {
            result = &mut mark_ready => result,
            result = heartbeat_tasks.join_next() => {
                classify_task_exit(result).map(|()| false)
            }
            result = payout_tasks.join_next() => {
                classify_task_exit(result).map(|()| false)
            }
        }
    };
    match ready_result {
        Ok(true) => {}
        Ok(false) => {
            let _ = payout_shutdown_tx.send(true);
            let payout_cleanup = drain_service_tasks(&mut payout_tasks).await;
            let _ = heartbeat_shutdown_tx.send(true);
            let heartbeat_cleanup = drain_service_tasks(&mut heartbeat_tasks).await;
            return combine_service_and_cleanup(payout_cleanup, heartbeat_cleanup);
        }
        Err(error) => {
            let _ = payout_shutdown_tx.send(true);
            let payout_cleanup = drain_service_tasks(&mut payout_tasks).await;
            let _ = heartbeat_shutdown_tx.send(true);
            let heartbeat_cleanup = drain_service_tasks(&mut heartbeat_tasks).await;
            let cleanup = combine_service_and_cleanup(payout_cleanup, heartbeat_cleanup);
            return combine_service_and_cleanup(Err(error), cleanup);
        }
    }

    let first_exit = tokio::select! {
        signal = &mut shutdown => {
            signal?;
            None
        }
        result = payout_tasks.join_next() => Some(classify_task_exit(result)),
        result = heartbeat_tasks.join_next() => Some(classify_task_exit(result)),
    };

    // Stop advertising execution before asking either potentially
    // non-cancellable signer pass to drain. The ownership heartbeat continues
    // until those passes are gone, so no successor can race their external
    // effects.
    let not_ready = started
        .store
        .mark_payout_worker_not_ready(worker_instance)
        .await
        .map_err(ServiceError::from)
        .and_then(|updated| {
            if updated {
                Ok(())
            } else {
                Err(ServiceError::PayoutWorkerLeaseLost)
            }
        });
    let _ = payout_shutdown_tx.send(true);
    let payout_drained = drain_service_tasks(&mut payout_tasks).await;
    let _ = heartbeat_shutdown_tx.send(true);
    let heartbeat_drained = drain_service_tasks(&mut heartbeat_tasks).await;

    let mut result = None;
    retain_first_error(&mut result, first_exit.transpose().map(|_| ()));
    retain_first_error(&mut result, not_ready);
    retain_first_error(&mut result, payout_drained);
    retain_first_error(&mut result, heartbeat_drained);
    result.map_or(Ok(()), Err)
}

/// Publishes readiness from the exact long-running payout process. Combined
/// with `Type=notify`, this keeps the target's start job pending until signer
/// construction and durable database readiness both belong to this process.
fn notify_service_manager_ready() -> Result<(), ServiceError> {
    let socket = std::env::var_os("NOTIFY_SOCKET").ok_or_else(|| {
        ServiceError::ServiceManagerNotification(io::Error::new(
            io::ErrorKind::NotFound,
            "NOTIFY_SOCKET is unavailable",
        ))
    })?;
    send_service_manager_ready(&socket).map_err(ServiceError::ServiceManagerNotification)
}

#[cfg(unix)]
fn send_service_manager_ready(socket_name: &OsStr) -> io::Result<()> {
    use std::os::unix::{ffi::OsStrExt, net::SocketAddr};

    const READY: &[u8] = b"READY=1";
    let name = socket_name.as_bytes();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is invalid",
        ));
    }

    let address = if name[0] == b'@' {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            SocketAddr::from_abstract_name(&name[1..])?
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract service-manager sockets require Linux",
            ));
        }
    } else {
        let path = Path::new(socket_name);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET path is not absolute",
            ));
        }
        SocketAddr::from_pathname(path)?
    };
    let socket = UnixDatagram::unbound()?;
    let sent = socket.send_to_addr(READY, &address)?;
    if sent != READY.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "service-manager readiness datagram was truncated",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_service_manager_ready(_socket_name: &std::ffi::OsStr) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "service-manager readiness requires a Unix socket",
    ))
}

async fn drain_service_tasks(tasks: &mut JoinSet<ServiceTask>) -> Result<(), ServiceError> {
    let drain = async {
        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            retain_first_error(&mut first_error, classify_drained_task(result));
        }
        first_error.map_or(Ok(()), Err)
    };
    match time::timeout(SERVICE_DRAIN_TIMEOUT, drain).await {
        Ok(result) => result,
        Err(_) => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            Err(ServiceError::DrainTimeout)
        }
    }
}

fn classify_payout_startup_exit(
    result: Option<Result<Result<PayoutServices, ServiceError>, tokio::task::JoinError>>,
) -> Result<PayoutServices, ServiceError> {
    match result {
        Some(Ok(result)) => result,
        Some(Err(_)) | None => Err(ServiceError::TaskFailed),
    }
}

async fn drain_payout_startup(
    tasks: &mut JoinSet<Result<PayoutServices, ServiceError>>,
) -> Result<(), ServiceError> {
    let drain = async {
        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            let result = classify_payout_startup_exit(Some(result)).map(drop);
            retain_first_error(&mut first_error, result);
        }
        first_error.map_or(Ok(()), Err)
    };
    match time::timeout(SERVICE_DRAIN_TIMEOUT, drain).await {
        Ok(result) => result,
        Err(_) => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            Err(ServiceError::DrainTimeout)
        }
    }
}

async fn maintain_payout_worker_heartbeat(
    store: Arc<PostgresStore>,
    worker_instance: uuid::Uuid,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), StoreError> {
    let mut interval = time::interval(PAYOUT_WORKER_HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {
                if !store.heartbeat_payout_worker(worker_instance).await? {
                    return Err(StoreError::PayoutWorkerLeaseLost);
                }
            }
        }
    }
}

/// Exercises the non-listening, probe-only service dependency graph once.
///
/// Unlike [`run`], this path starts no share, payout, portal, refresh, nonce,
/// or socket task. It never constructs signer journals or payout runtimes and
/// never creates, recovers, signs, observes, synchronizes, or broadcasts a
/// transaction. Durable payout recovery remains exclusive to
/// [`run_payout_worker`] after this service-manager probe succeeds. Every
/// resource is dropped before return.
pub async fn preflight(config: &RuntimeConfig) -> Result<(), ServiceError> {
    for attempt in 0..PREFLIGHT_PAYOUT_AUTHORITY_ATTEMPTS {
        let started = bootstrap::preflight(config).await?;
        let mut probe = LivePreflightProbe {
            config,
            started,
            validator: None,
            payout_boundary: None,
        };
        match exercise_preflight(&mut probe).await {
            Err(ServiceError::PayoutAuthorityUnavailable)
                if attempt + 1 < PREFLIGHT_PAYOUT_AUTHORITY_ATTEMPTS =>
            {
                // A preflight snapshot has no live subscription. Reconnect
                // to Wolf so the next attempt starts from its current job.
                time::sleep(PREFLIGHT_PAYOUT_AUTHORITY_RETRY_INTERVAL).await;
            }
            result => return result,
        }
    }
    Err(ServiceError::PayoutAuthorityUnavailable)
}

trait PreflightProbe {
    async fn address_authority(&mut self) -> Result<(), ServiceError>;
    async fn payout_composition(&mut self) -> Result<(), ServiceError>;
    async fn portal_composition(&mut self) -> Result<(), ServiceError>;
}

async fn exercise_preflight(probe: &mut impl PreflightProbe) -> Result<(), ServiceError> {
    probe.address_authority().await?;
    probe.payout_composition().await?;
    probe.portal_composition().await
}

struct LivePreflightProbe<'a> {
    config: &'a RuntimeConfig,
    started: bootstrap::MiningPreflight,
    validator: Option<Arc<dyn AddressValidator>>,
    payout_boundary: Option<Arc<TestnetPayoutBoundary>>,
}

impl PreflightProbe for LivePreflightProbe<'_> {
    async fn address_authority(&mut self) -> Result<(), ServiceError> {
        let validator = build_address_validator(self.config)?;
        verify_address_authority(Arc::clone(&validator), self.config.network).await?;
        self.validator = Some(validator);
        Ok(())
    }

    async fn payout_composition(&mut self) -> Result<(), ServiceError> {
        self.payout_boundary =
            Some(build_probe_only_payout_boundary(self.config, &self.started.jobs).await?);
        Ok(())
    }

    async fn portal_composition(&mut self) -> Result<(), ServiceError> {
        let validator = self.validator.clone().ok_or(ServiceError::Invariant)?;
        let payout = self
            .payout_boundary
            .clone()
            .ok_or(ServiceError::Invariant)?;
        let pool_data = PostgresPoolDataSource::new(self.started.store.as_ref().clone());
        pool_data.refresh().await?;
        let portal = build_preflight_portal(
            self.config,
            Arc::clone(&self.started.store),
            validator,
            pool_data,
            self.started.jobs.clone(),
            Arc::new(LiveMinerTelemetry::default()),
            payout,
        )?;
        drop(portal);
        Ok(())
    }
}

fn combine_service_and_cleanup(
    service_result: Result<(), ServiceError>,
    cleanup_result: Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    match (service_result, cleanup_result) {
        (Err(service), Err(cleanup)) => Err(ServiceError::ServiceAndCleanupFailed {
            service: Box::new(service),
            cleanup: Box::new(cleanup),
        }),
        (Err(service), Ok(())) => Err(service),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_started(
    config: &RuntimeConfig,
    bootstrap: &mut Option<MiningBootstrap>,
) -> Result<(), ServiceError> {
    let started = bootstrap.as_ref().ok_or(ServiceError::Invariant)?;

    let validator = build_address_validator(config)?;
    verify_address_authority(Arc::clone(&validator), config.network).await?;
    let payout_boundary =
        build_probe_only_payout_boundary_with_retry(config, &started.jobs).await?;

    let pool_data = PostgresPoolDataSource::new(started.store.as_ref().clone());
    pool_data.refresh().await?;
    let miner_telemetry = Arc::new(LiveMinerTelemetry::default());
    let portal = build_portal(
        config,
        started,
        validator,
        pool_data.clone(),
        Arc::clone(&miner_telemetry),
        payout_boundary,
    )?;

    // Dependency checks can consume most of the bootstrap lease. Revalidate
    // ownership against the database clock immediately before public binding;
    // a stale process must never open a miner listener and wait for the first
    // periodic heartbeat to discover that it already lost the namespace.
    started
        .store
        .renew_nonce_namespace(
            &started.nonce_claim,
            bootstrap::NONCE_NAMESPACE_LEASE_DURATION,
        )
        .await?;

    // Binding is deliberately the final startup action. No miner can connect
    // while replay, target validation, signers, or the portal read model are
    // unavailable.
    let portal_listener = TcpListener::bind(config.portal_listen).await?;
    let stratum_listener = TcpListener::bind(config.stratum_listen).await?;

    let dependencies = EdgeDependencies::from_bootstrap(
        started,
        miner_telemetry as Arc<dyn wcash_pool_edge::MinerTelemetrySink>,
    );
    let counters = Arc::new(EdgeCounters::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    let edge_config = config.clone();
    let edge_shutdown = shutdown_rx.clone();
    let edge_counters = Arc::clone(&counters);
    tasks.spawn(async move {
        ServiceTask::Edge(
            edge::run(
                stratum_listener,
                dependencies,
                &edge_config,
                edge_shutdown,
                edge_counters,
            )
            .await,
        )
    });

    let portal_shutdown = shutdown_rx.clone();
    tasks.spawn(async move {
        ServiceTask::Portal(serve_until_shutdown(portal_listener, portal, portal_shutdown).await)
    });

    let refresh_shutdown = shutdown_rx.clone();
    tasks.spawn(
        async move { ServiceTask::Refresh(refresh_portal(pool_data, refresh_shutdown).await) },
    );

    let nonce_store = Arc::clone(&started.store);
    let nonce_allocator = Arc::clone(&started.nonces);
    let nonce_claim = started.nonce_claim.clone();
    let nonce_reservation = config.nonce_reservation;
    let nonce_shutdown = shutdown_rx.clone();
    tasks.spawn(async move {
        ServiceTask::Nonce(
            maintain_nonce_namespace(
                nonce_store,
                nonce_allocator,
                nonce_claim,
                nonce_reservation,
                nonce_shutdown,
            )
            .await,
        )
    });

    let first_exit = {
        let shares = &bootstrap.as_ref().ok_or(ServiceError::Invariant)?.shares;
        tokio::select! {
            signal = shutdown_signal() => {
                signal?;
                None
            }
            result = tasks.join_next() => Some(classify_task_exit(result)),
            reason = wait_for_share_router_exit(shares) => Some(Err(ServiceError::ShareRouterExited(reason))),
        }
    };

    let _ = shutdown_tx.send(true);
    let drain = async {
        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            retain_first_error(&mut first_error, classify_drained_task(result));
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    };
    let drained = match time::timeout(SERVICE_DRAIN_TIMEOUT, drain).await {
        Ok(result) => result,
        Err(_) => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            Err(ServiceError::DrainTimeout)
        }
    };

    // Session producers are now gone, so the single share actor can consume
    // every command already admitted before its shutdown marker.
    let owned = bootstrap.take().ok_or(ServiceError::Invariant)?;
    let authority_shutdown = shutdown_bootstrap(owned).await;

    let mut service_error = None;
    retain_first_error(&mut service_error, first_exit.transpose().map(|_| ()));
    retain_first_error(&mut service_error, drained);
    let service_result = match service_error {
        Some(error) => Err(error),
        None => Ok(()),
    };
    combine_service_and_cleanup(service_result, authority_shutdown)
}

async fn shutdown_bootstrap(owned: MiningBootstrap) -> Result<(), ServiceError> {
    let MiningBootstrap {
        store,
        jobs,
        shares,
        authentication,
        nonces,
        nonce_claim,
        timeline: _,
    } = owned;
    let share_shutdown = match time::timeout(SHARE_ROUTER_SHUTDOWN_TIMEOUT, shares.shutdown()).await
    {
        Ok(result) => result
            .map_err(BootstrapError::from)
            .map_err(ServiceError::from),
        Err(_) => Err(ServiceError::ShareRouterShutdownTimeout),
    };
    // Releasing is attempted even when the share actor failed or exceeded its
    // deadline. A timed-out shutdown future drops and aborts the owned actor
    // before this release can allow a replacement process to acquire the lease.
    let nonce_release = store
        .release_nonce_namespace(&nonce_claim)
        .await
        .map_err(ServiceError::from);
    drop((store, jobs, authentication, nonces));
    share_shutdown?;
    nonce_release?;
    Ok(())
}

fn build_address_validator(
    config: &RuntimeConfig,
) -> Result<Arc<dyn AddressValidator>, ServiceError> {
    let command = WcashCommandValidator::new(
        config.wcash_wallet_program.clone(),
        config.wcash_wallet_sha256,
        config.wcash_wallet_uid,
        ADDRESS_VALIDATION_TIMEOUT,
    )
    .map_err(|_| ServiceError::AddressAuthorityUnavailable)?;
    let validator = TestnetAddressValidator::new(command);
    let validator = if config.network == ChainNetwork::Mainnet {
        validator.with_mainnet_network()
    } else {
        validator
    };
    #[cfg(feature = "regtest")]
    let validator = if config.network == ChainNetwork::Regtest {
        validator.with_regtest_network()
    } else {
        validator
    };
    Ok(Arc::new(validator))
}

async fn verify_address_authority(
    validator: Arc<dyn AddressValidator>,
    network: ChainNetwork,
) -> Result<(), ServiceError> {
    tokio::task::spawn_blocking(move || {
        validator
            .readiness(Asset::Wec, network)
            .and_then(|()| validator.readiness(Asset::Zec, network))
    })
    .await
    .map_err(|_| ServiceError::AddressAuthorityUnavailable)?
    .map_err(|_| ServiceError::AddressAuthorityUnavailable)
}

struct PayoutServices {
    wec: Arc<AutomaticPayoutRuntime>,
}

/// Builds the payout-facing portal dependency after configuration and
/// read-only chain authority checks, without constructing any signer journal,
/// settlement orchestrator, wallet observer, or automatic payout runtime.
///
/// In particular, this path cannot create, recover, sign, rebroadcast, or
/// reconcile a payout. Those durable transitions remain exclusive to
/// [`build_payout_services`] during actual service startup.
async fn build_probe_only_payout_boundary_with_retry(
    config: &RuntimeConfig,
    jobs: &wcash_pool_edge::JobRouter,
) -> Result<Arc<TestnetPayoutBoundary>, ServiceError> {
    for attempt in 0..PREFLIGHT_PAYOUT_AUTHORITY_ATTEMPTS {
        match build_probe_only_payout_boundary(config, jobs).await {
            Err(ServiceError::PayoutAuthorityUnavailable)
                if attempt + 1 < PREFLIGHT_PAYOUT_AUTHORITY_ATTEMPTS =>
            {
                // Wolf can rotate while the two read-only node observations
                // are in flight. Discard every fact from this attempt and
                // compare a fresh snapshot instead of spending systemd's
                // restart budget on an ordinary moving-tip race.
                time::sleep(PREFLIGHT_PAYOUT_AUTHORITY_RETRY_INTERVAL).await;
            }
            result => return result,
        }
    }
    Err(ServiceError::PayoutAuthorityUnavailable)
}

async fn build_probe_only_payout_boundary(
    config: &RuntimeConfig,
    jobs: &wcash_pool_edge::JobRouter,
) -> Result<Arc<TestnetPayoutBoundary>, ServiceError> {
    validate_probe_only_payout_configuration(config)?;

    let wcash_rpc = Arc::new(
        LoopbackJsonRpc::new(config.wcash_node_rpc, config.wcash_node_cookie_file.clone())
            .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
    );
    let zcash_rpc = Arc::new(
        LoopbackJsonRpc::new(config.zcash_node_rpc, config.zcash_node_cookie_file.clone())
            .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
    );
    let wcash_authority = NodePayoutAuthority::new(Chain::Wcash, wcash_rpc, config.wcash_genesis)?;
    let zcash_authority = NodePayoutAuthority::new(Chain::Zcash, zcash_rpc, config.zcash_genesis)?;
    let (wcash_authority, zcash_authority) = if config.network == ChainNetwork::Mainnet {
        (
            wcash_authority.with_mainnet_network(),
            zcash_authority.with_mainnet_network(),
        )
    } else {
        (wcash_authority, zcash_authority)
    };
    #[cfg(feature = "regtest")]
    let (wcash_authority, zcash_authority) = if config.network == ChainNetwork::Regtest {
        (
            wcash_authority.with_regtest_network()?,
            zcash_authority.with_regtest_network()?,
        )
    } else {
        (wcash_authority, zcash_authority)
    };
    let (wcash_tip, zcash_tip) = tokio::join!(
        wcash_authority.preflight_probe(),
        zcash_authority.preflight_probe()
    );
    let wcash_tip = wcash_tip.map_err(map_authority_failure)?;
    let zcash_tip = zcash_tip.map_err(map_authority_failure)?;
    verify_backend_authority(
        jobs,
        AuthorityTip {
            hash: wcash_tip.hash,
            height: wcash_tip.height,
        },
        AuthorityTip {
            hash: zcash_tip.hash,
            height: zcash_tip.height,
        },
    )?;

    // Preflight composes the portal without giving it an execution-capable
    // signer. No listener is opened, and the boundary is dropped on return.
    let boundary = TestnetPayoutBoundary::deferred();
    let boundary = if config.network == ChainNetwork::Mainnet {
        boundary.with_mainnet_network()
    } else {
        boundary
    };
    #[cfg(feature = "regtest")]
    let boundary = if config.network == ChainNetwork::Regtest {
        boundary.with_regtest_network()
    } else {
        boundary
    };
    Ok(Arc::new(boundary))
}

fn validate_probe_only_payout_configuration(config: &RuntimeConfig) -> Result<(), ServiceError> {
    if config.payout_mode == PayoutMode::Deferred {
        if config.automatic_payout.is_some() {
            return Err(ServiceError::SignerConfiguration);
        }
        return Ok(());
    }
    let payout = automatic_payout(config)?;
    if payout.chains.as_slice() != [AutomaticPayoutChain::Wcash] {
        return Err(ServiceError::SignerConfiguration);
    }
    let pinned = PinnedWolfProgram::verify(
        config.wcash_wallet_program.clone(),
        config.wcash_wallet_sha256,
        config.wcash_wallet_uid,
    )
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wallet = WolfWalletTransport::new(
        pinned,
        payout.wcash_wallet_database.clone(),
        payout.wcash_lightwalletd_endpoint.clone(),
    )
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wallet = if config.network == ChainNetwork::Mainnet {
        wallet.with_mainnet_network()
    } else {
        wallet
    };
    #[cfg(feature = "regtest")]
    let wallet = if config.network == ChainNetwork::Regtest {
        wallet.with_regtest_network()
    } else {
        wallet
    };
    wallet
        .probe_readonly_boundary()
        .map_err(|_| ServiceError::SignerConfiguration)?;

    let seed =
        SeedSource::protected_file(payout.wcash_wallet_seed_file.clone(), payout.wcash_seed_uid);
    seed.validate_protected_metadata()
        .map_err(|_| ServiceError::SignerConfiguration)?;
    let _wec = WecSignerConfig::new(
        payout.wcash_signer_journal_directory.clone(),
        payout.wcash_signer_account,
        config.wcash_payout_commitment,
        seed,
    )
    .and_then(|configured| {
        if config.network == ChainNetwork::Mainnet {
            return configured.with_mainnet_network();
        }
        #[cfg(feature = "regtest")]
        if config.network == ChainNetwork::Regtest {
            return configured.with_regtest_network();
        }
        Ok(configured)
    })
    .and_then(|configured| {
        configured.with_confirmations(config.wcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.wcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.wcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;

    Ok(())
}

fn automatic_payout(config: &RuntimeConfig) -> Result<&AutomaticPayoutConfig, ServiceError> {
    if config.payout_mode != PayoutMode::Automatic {
        return Err(ServiceError::SignerConfiguration);
    }
    config
        .automatic_payout
        .as_ref()
        .ok_or(ServiceError::SignerConfiguration)
}

async fn build_payout_services(
    config: &RuntimeConfig,
    store: Arc<PostgresStore>,
) -> Result<PayoutServices, ServiceError> {
    let payout = automatic_payout(config)?;
    if payout.chains.as_slice() != [AutomaticPayoutChain::Wcash] {
        return Err(ServiceError::SignerConfiguration);
    }
    let pinned = PinnedWolfProgram::verify(
        config.wcash_wallet_program.clone(),
        config.wcash_wallet_sha256,
        config.wcash_wallet_uid,
    )
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wallet = Arc::new(
        WolfWalletTransport::new(
            pinned,
            payout.wcash_wallet_database.clone(),
            payout.wcash_lightwalletd_endpoint.clone(),
        )
        .map(|wallet| {
            if config.network == ChainNetwork::Mainnet {
                return wallet.with_mainnet_network();
            }
            #[cfg(feature = "regtest")]
            if config.network == ChainNetwork::Regtest {
                return wallet.with_regtest_network();
            }
            wallet
        })
        .map_err(|_| ServiceError::SignerConfiguration)?,
    );
    let wec_config = WecSignerConfig::new(
        payout.wcash_signer_journal_directory.clone(),
        payout.wcash_signer_account,
        config.wcash_payout_commitment,
        SeedSource::protected_file(payout.wcash_wallet_seed_file.clone(), payout.wcash_seed_uid),
    )
    .and_then(|configured| {
        if config.network == ChainNetwork::Mainnet {
            return configured.with_mainnet_network();
        }
        #[cfg(feature = "regtest")]
        if config.network == ChainNetwork::Regtest {
            return configured.with_regtest_network();
        }
        Ok(configured)
    })
    .and_then(|configured| {
        configured.with_confirmations(config.wcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.wcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.wcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wec = Arc::new(
        WecPayoutSigner::new(wec_config, wallet.clone())
            .map_err(|_| ServiceError::SignerConfiguration)?,
    );
    let signer: Arc<dyn IsolatedPayoutSigner> = Arc::clone(&wec) as Arc<dyn IsolatedPayoutSigner>;

    let wcash_rpc = Arc::new(
        LoopbackJsonRpc::new(config.wcash_node_rpc, config.wcash_node_cookie_file.clone())
            .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
    );
    let wcash_wallet = Arc::new(
        WcashObservationSource::new(
            WcashWalletObserver::new(
                wallet.as_ref().clone(),
                config.wallet_network(),
                config.wcash_genesis,
                config.wcash_branch_id(),
                payout.wcash_signer_account,
                WalletFundSource::Ironwood,
                config.wcash_payout_commitment,
                payout.wcash_wallet_sync_timeout,
                payout.wcash_wallet_sync_batch_size,
            )
            .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
            Duration::from_secs(15),
            1024 * 1024,
        )
        .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
    );
    let wcash_authority = NodePayoutAuthority::new(Chain::Wcash, wcash_rpc, config.wcash_genesis)?;
    let wcash_authority = if config.network == ChainNetwork::Mainnet {
        wcash_authority.with_mainnet_network()
    } else {
        wcash_authority
    };
    #[cfg(feature = "regtest")]
    let wcash_authority = if config.network == ChainNetwork::Regtest {
        wcash_authority.with_regtest_network()?
    } else {
        wcash_authority
    };
    let wcash_authority = Arc::new(wcash_authority);

    wcash_authority
        .startup_probe()
        .await
        .map_err(map_authority_failure)?;

    let snapshot_store = Arc::clone(&store);
    let wcash_verified = verify_observer_authority(
        wcash_wallet.as_ref(),
        wcash_authority.as_ref(),
        Chain::Wcash,
    )
    .await?;
    // Wcash wallet sync may consume its full bound. Obtain a verifier-only,
    // race-free Wolf snapshot at the last possible moment.
    let jobs = bootstrap::payout_jobs(config, &snapshot_store).await?;
    verify_wcash_backend_authority(&jobs, wcash_verified.tip)?;

    // The observation above performs the required seedless sync under the same
    // transport lock. Check the spend-capable identity before journal recovery.
    verify_startup_signer_readiness(signer, SIGNER_READINESS_TIMEOUT).await?;

    let settlement = Arc::new(SettlementOrchestrator::new_wec_only(
        Arc::clone(&store) as Arc<dyn crate::settlement::SettlementStore>,
        Arc::new(WecExecutionSigner::new(
            Arc::clone(&wec),
            payout.wcash_signer_account,
        )),
        Arc::new(RpcExactBroadcaster::new(Arc::clone(&wcash_authority))),
    )?);

    // SQL authorizes the signer boundary first. Recover durable Signing rows
    // before comparing wallet balances: an exact journal artifact is copied to
    // Signed, while an empty journal completes only that already-authorized
    // idempotent request. Migration 0009 rejects ambiguous legacy Draft/Signed
    // rows, so startup never guesses whether an older release crossed a fence.
    let wec_gate = settlement
        .recover_before_wallet_reconciliation(Chain::Wcash)
        .await?;

    // With no in-flight external effect, a collector can join this accounting
    // namespace only when its spendable balance is represented by the sealed
    // ledger. Signing/Signed/Broadcasting/Broadcast batches deliberately skip
    // this snapshot: SQL classifies their wallet balance as externally
    // ambiguous until confirmation.
    if wec_gate == ReconciliationGate::Safe {
        store
            .record_opening_pool_equity(
                Chain::Wcash,
                wcash_verified.observation.wallet_spendable_zat,
                payout.wcash_opening_pool_equity_zat,
            )
            .await?;
        record_startup_reconciliation(&store, &wcash_verified.observation).await?;
    }

    // Only after a safe wallet/ledger snapshot may Draft authorize signing.
    // Existing effect-fenced states remain resumable without changing their
    // exact request or transaction bytes.
    if wec_gate == ReconciliationGate::Safe {
        require_nonterminal_startup_outcome(settlement.resume_next(Chain::Wcash).await?)?;
    }

    let policy = PayoutLoopPolicy {
        poll_interval: PAYOUT_POLL_INTERVAL,
        retry_initial: PAYOUT_RETRY_INITIAL,
        retry_maximum: PAYOUT_RETRY_MAXIMUM,
        maximum_consecutive_failures: PAYOUT_MAXIMUM_CONSECUTIVE_FAILURES,
        maximum_confirmation_watches: PAYOUT_MAXIMUM_CONFIRMATION_WATCHES,
    };
    let lifecycle_store: Arc<dyn crate::payout_runtime::PayoutLifecycleStore> = store;
    let settlement_driver: Arc<dyn crate::payout_runtime::SettlementDriver> = settlement;
    let wec = Arc::new(AutomaticPayoutRuntime::new(
        Chain::Wcash,
        config.deployment_id,
        policy,
        Arc::clone(&lifecycle_store),
        wcash_wallet,
        wcash_authority,
        Arc::clone(&settlement_driver),
    )?);
    Ok(PayoutServices { wec })
}

/// Runs the full, potentially multi-RPC signer startup probe outside Tokio's
/// async workers. Portal HTTP readiness intentionally has a separate five
/// second budget; startup recovery must not inherit that request-time cap.
async fn verify_startup_signer_readiness(
    signer: Arc<dyn IsolatedPayoutSigner>,
    timeout: Duration,
) -> Result<(), ServiceError> {
    if timeout.is_zero() || timeout > SIGNER_READINESS_TIMEOUT {
        return Err(ServiceError::SignerUnavailable);
    }
    let readiness = tokio::task::spawn_blocking(move || signer.readiness());
    time::timeout(timeout, readiness)
        .await
        .map_err(|_| ServiceError::SignerUnavailable)?
        .map_err(|_| ServiceError::SignerUnavailable)?
        .map_err(|_| ServiceError::SignerUnavailable)
}

fn require_nonterminal_startup_outcome(outcome: ResumeOutcome) -> Result<(), ServiceError> {
    match outcome {
        ResumeOutcome::Idle
        | ResumeOutcome::Broadcast { .. }
        | ResumeOutcome::AwaitingConfirmation { .. } => Ok(()),
        ResumeOutcome::FrozenAfterReorg { .. } | ResumeOutcome::Terminal { .. } => {
            Err(ServiceError::PayoutAuthorityUnavailable)
        }
    }
}

async fn verify_observer_authority(
    wallet: &dyn WalletObservationSource,
    authority: &dyn PayoutConfirmationAuthority,
    chain: Chain,
) -> Result<VerifiedWalletAuthority, ServiceError> {
    if wallet.chain() != chain || authority.chain() != chain {
        return Err(ServiceError::PayoutAuthorityConfiguration);
    }
    let (observation, snapshot) = tokio::join!(wallet.observe(), authority.snapshot(&[]));
    let observation = observation.map_err(map_authority_failure)?;
    let snapshot = snapshot.map_err(map_authority_failure)?;
    if observation.chain != chain
        || snapshot.chain != chain
        || observation.best_tip_hash != snapshot.best_tip_hash
        || observation.best_tip_height != snapshot.best_tip_height
        || observation.wallet_state_digest == [0; 32]
        || observation.observed_at == 0
        || observation.valid_until <= observation.observed_at
        || snapshot.observed_at == 0
        || !snapshot.payouts.is_empty()
    {
        return Err(ServiceError::PayoutAuthorityUnavailable);
    }
    Ok(VerifiedWalletAuthority {
        tip: AuthorityTip {
            hash: snapshot.best_tip_hash,
            height: snapshot.best_tip_height,
        },
        observation,
    })
}

struct VerifiedWalletAuthority {
    tip: AuthorityTip,
    observation: wcash_pool_store::WalletObservation,
}

#[cfg(test)]
async fn observe_then_verify_current_backend<W, Z, V, VF>(
    wcash_observation: W,
    zcash_observation: Z,
    verify_fresh_backend: V,
) -> Result<(VerifiedWalletAuthority, VerifiedWalletAuthority), ServiceError>
where
    W: Future<Output = Result<VerifiedWalletAuthority, ServiceError>>,
    Z: Future<Output = Result<VerifiedWalletAuthority, ServiceError>>,
    V: FnOnce(AuthorityTip, AuthorityTip) -> VF,
    VF: Future<Output = Result<(), ServiceError>>,
{
    let wcash = wcash_observation.await?;
    let zcash = zcash_observation.await?;
    verify_fresh_backend(wcash.tip, zcash.tip).await?;
    Ok((wcash, zcash))
}

async fn record_startup_reconciliation(
    store: &PostgresStore,
    observation: &wcash_pool_store::WalletObservation,
) -> Result<(), ServiceError> {
    let recorded = store.record_wallet_reconciliation(observation).await?;
    if recorded.chain != observation.chain
        || recorded.wallet_spendable_zat != observation.wallet_spendable_zat
        || recorded.best_tip_hash != observation.best_tip_hash
        || recorded.best_tip_height != observation.best_tip_height
        || recorded.observed_at != observation.observed_at
        || recorded.valid_until != observation.valid_until
    {
        return Err(ServiceError::PayoutAuthorityUnavailable);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityTip {
    hash: [u8; 32],
    height: u32,
}

fn verify_backend_authority(
    jobs: &wcash_pool_edge::JobRouter,
    wcash: AuthorityTip,
    zcash: AuthorityTip,
) -> Result<(), ServiceError> {
    let generation = jobs
        .current_generation()
        .map_err(BootstrapError::from)?
        .ok_or(ServiceError::PayoutAuthorityUnavailable)?;
    let descriptor = generation.descriptor();
    let tips = generation.tips();
    if !backend_tip_facts_match(
        tips.wcash_previous_hash_le(),
        descriptor.wcash_height,
        wcash,
        tips.zcash_previous_hash_le(),
        descriptor.zcash_height,
        zcash,
    ) {
        return Err(ServiceError::PayoutAuthorityUnavailable);
    }
    Ok(())
}

fn verify_wcash_backend_authority(
    jobs: &wcash_pool_edge::JobRouter,
    wcash: AuthorityTip,
) -> Result<(), ServiceError> {
    let generation = jobs
        .current_generation()
        .map_err(BootstrapError::from)?
        .ok_or(ServiceError::PayoutAuthorityUnavailable)?;
    let descriptor = generation.descriptor();
    let tips = generation.tips();
    if tips.wcash_previous_hash_le() != wcash.hash
        || descriptor.wcash_height.checked_sub(1) != Some(wcash.height)
    {
        return Err(ServiceError::PayoutAuthorityUnavailable);
    }
    Ok(())
}

fn backend_tip_facts_match(
    wcash_previous_hash: [u8; 32],
    wcash_candidate_height: u32,
    wcash: AuthorityTip,
    zcash_previous_hash: [u8; 32],
    zcash_candidate_height: u32,
    zcash: AuthorityTip,
) -> bool {
    wcash_previous_hash == wcash.hash
        && zcash_previous_hash == zcash.hash
        && wcash_candidate_height.checked_sub(1) == Some(wcash.height)
        && zcash_candidate_height.checked_sub(1) == Some(zcash.height)
}

fn map_authority_failure(failure: ObservationFailure) -> ServiceError {
    match failure {
        ObservationFailure::Unavailable => ServiceError::PayoutAuthorityUnavailable,
        ObservationFailure::Invariant => ServiceError::PayoutAuthorityConfiguration,
    }
}

fn build_portal(
    config: &RuntimeConfig,
    bootstrap: &MiningBootstrap,
    validator: Arc<dyn AddressValidator>,
    pool_data: PostgresPoolDataSource,
    miner_telemetry: Arc<LiveMinerTelemetry>,
    payout: Arc<TestnetPayoutBoundary>,
) -> Result<PortalApp, ServiceError> {
    build_preflight_portal(
        config,
        Arc::clone(&bootstrap.store),
        validator,
        pool_data,
        bootstrap.jobs.clone(),
        miner_telemetry,
        payout,
    )
}

fn build_preflight_portal(
    config: &RuntimeConfig,
    store: Arc<PostgresStore>,
    validator: Arc<dyn AddressValidator>,
    pool_data: PostgresPoolDataSource,
    jobs: JobRouter,
    miner_telemetry: Arc<dyn MinerTelemetrySource>,
    payout: Arc<TestnetPayoutBoundary>,
) -> Result<PortalApp, ServiceError> {
    let mut portal_config = PortalConfig::testnet();
    portal_config.network = config.network;
    if config.network == ChainNetwork::Mainnet {
        // Mainnet registration remains closed until the operator explicitly
        // opens the isolated, accounting-backed deployment.
        portal_config.allow_registration = config.registration_open;
    }
    portal_config.payout_change_hold_secs = config.payout_change_hold_secs;
    portal_config.mining_password_ignored = matches!(
        config.mining_authentication,
        wcash_pool_store::MiningAuthenticationMode::UsernameOnly
    );
    portal_config
        .canonical_origin
        .clone_from(&config.portal_origin);
    let token = RuntimeConfig::portal_secret(&config.portal_token_pepper_file)?;
    let totp = RuntimeConfig::portal_secret(&config.portal_totp_key_file)?;
    let secrets = PortalSecrets::new(*token, *totp);
    let repository: Arc<dyn PortalRepository> = store;
    let data: Arc<dyn PoolDataSource> = Arc::new(LivePoolDataSource {
        projection: pool_data,
        jobs,
    });
    PortalApp::new_with_telemetry(
        portal_config,
        secrets,
        repository,
        validator,
        data,
        miner_telemetry,
        payout,
    )
    .map_err(ServiceError::from)
}

/// Combines durable history with the current mining authority's admission gate.
struct LivePoolDataSource {
    projection: PostgresPoolDataSource,
    jobs: JobRouter,
}

impl PoolDataSource for LivePoolDataSource {
    fn overview(&self) -> PoolOverview {
        self.projection.overview()
    }

    fn mining_ready(&self) -> bool {
        self.jobs
            .current_generation()
            .is_ok_and(|generation| generation.is_some())
    }
}

async fn refresh_portal(
    source: PostgresPoolDataSource,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), StoreError> {
    let mut interval = time::interval(PORTAL_REFRESH_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    // The mandatory initial refresh occurred before either listener was bound.
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => source.refresh().await?,
        }
    }
}

fn retain_first_error(slot: &mut Option<ServiceError>, result: Result<(), ServiceError>) {
    if let Err(error) = result {
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}

async fn maintain_nonce_namespace(
    store: Arc<PostgresStore>,
    allocator: Arc<wcash_pool_core::NoncePrefixAllocator>,
    claim: NonceNamespaceClaim,
    reservation_count: u64,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), StoreError> {
    let mut interval = time::interval(bootstrap::NONCE_NAMESPACE_LEASE_DURATION / 4);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {
                store
                    .renew_nonce_namespace(
                        &claim,
                        bootstrap::NONCE_NAMESPACE_LEASE_DURATION,
                    )
                    .await?;
                let remaining = allocator.remaining()?;
                let replenishment_threshold = (reservation_count / 4).max(1);
                if remaining <= replenishment_threshold {
                    let range =
                        bootstrap::reserve_nonce_tail(&store, &claim, reservation_count).await?;
                    allocator.extend_reserved(range.start(), range.end())?;
                }
            }
        }
    }
}

async fn wait_for_share_router_exit(shares: &wcash_pool_edge::ShareRouter) -> ShareRouterError {
    let mut interval = time::interval(COMPONENT_POLL_INTERVAL);
    loop {
        interval.tick().await;
        if shares.is_finished() {
            return shares
                .terminal_error()
                .unwrap_or(ShareRouterError::TaskFailed);
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

enum ServiceTask {
    Edge(Result<(), EdgeRuntimeError>),
    Portal(io::Result<()>),
    Refresh(Result<(), StoreError>),
    Nonce(Result<(), StoreError>),
    WecPayout(Result<(), PayoutRuntimeError>),
    PayoutHeartbeat(Result<(), StoreError>),
}

fn classify_task_exit(
    result: Option<Result<ServiceTask, tokio::task::JoinError>>,
) -> Result<(), ServiceError> {
    match result {
        Some(Ok(ServiceTask::Edge(Ok(())))) => Err(ServiceError::UnexpectedComponentExit("edge")),
        Some(Ok(ServiceTask::Edge(Err(error)))) => Err(ServiceError::Edge(error)),
        Some(Ok(ServiceTask::Portal(Ok(())))) => {
            Err(ServiceError::UnexpectedComponentExit("portal"))
        }
        Some(Ok(ServiceTask::Portal(Err(error)))) => Err(ServiceError::Listener(error)),
        Some(Ok(ServiceTask::Refresh(Ok(())))) => {
            Err(ServiceError::UnexpectedComponentExit("portal_refresh"))
        }
        Some(Ok(ServiceTask::Refresh(Err(error)))) => Err(ServiceError::Store(error)),
        Some(Ok(ServiceTask::Nonce(Ok(())))) => {
            Err(ServiceError::UnexpectedComponentExit("nonce_lease"))
        }
        Some(Ok(ServiceTask::Nonce(Err(error)))) => Err(ServiceError::Store(error)),
        Some(Ok(ServiceTask::WecPayout(Ok(())))) => {
            Err(ServiceError::UnexpectedComponentExit("wec_payout"))
        }
        Some(Ok(ServiceTask::WecPayout(Err(error)))) => Err(ServiceError::PayoutRuntime(error)),
        Some(Ok(ServiceTask::PayoutHeartbeat(Ok(())))) => {
            Err(ServiceError::UnexpectedComponentExit("payout_heartbeat"))
        }
        Some(Ok(ServiceTask::PayoutHeartbeat(Err(error)))) => Err(ServiceError::Store(error)),
        Some(Err(_)) => Err(ServiceError::TaskFailed),
        None => Err(ServiceError::TaskFailed),
    }
}

fn classify_drained_task(
    result: Result<ServiceTask, tokio::task::JoinError>,
) -> Result<(), ServiceError> {
    match result {
        Ok(ServiceTask::Edge(result)) => result.map_err(ServiceError::from),
        Ok(ServiceTask::Portal(result)) => result.map_err(ServiceError::Listener),
        Ok(ServiceTask::Refresh(result)) => result.map_err(ServiceError::from),
        Ok(ServiceTask::Nonce(result)) => result.map_err(ServiceError::from),
        Ok(ServiceTask::WecPayout(result)) => result.map_err(ServiceError::from),
        Ok(ServiceTask::PayoutHeartbeat(result)) => result.map_err(ServiceError::from),
        Err(_) => Err(ServiceError::TaskFailed),
    }
}

/// Service startup, authority, or ordered-shutdown failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Mining bootstrap or owned share-actor shutdown failed.
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    /// Protected runtime input was rejected.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Durable read-model refresh failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Portal policy could not be constructed.
    #[error(transparent)]
    Portal(#[from] PortalBuildError),
    /// An expected listener could not be opened or served.
    #[error("service listener is unavailable")]
    Listener(#[from] io::Error),
    /// The exact payout worker could not publish readiness to its service manager.
    #[error("service-manager payout readiness notification failed")]
    ServiceManagerNotification(#[source] io::Error),
    /// Wolf's authoritative address command was not usable.
    #[error("Wcash address authority is unavailable")]
    AddressAuthorityUnavailable,
    /// A chain-separated signer had invalid static configuration.
    #[error("payout signer configuration is invalid")]
    SignerConfiguration,
    /// A configured signer failed its live readiness check.
    #[error("payout signer is unavailable")]
    SignerUnavailable,
    /// Local wallet or validator configuration violated a payout boundary.
    #[error(transparent)]
    LivePayoutConfiguration(#[from] LivePayoutConfigError),
    /// Exact settlement composition was internally inconsistent.
    #[error(transparent)]
    Settlement(#[from] SettlementError),
    /// An automatic payout worker stopped on a durable or authority failure.
    #[error(transparent)]
    PayoutRuntime(#[from] PayoutRuntimeError),
    /// The Internet-facing service was given spending-authority configuration.
    #[error("public service refuses payout spending authority")]
    PublicServiceHasPayoutAuthority,
    /// The accounting projector was given spending-authority configuration.
    #[error("accounting projector refuses payout spending authority")]
    ProjectorHasPayoutAuthority,
    /// The projector's backend stream was not the connection that produced its snapshot.
    #[error("accounting projector backend connection binding changed")]
    ProjectorConnectionMismatch,
    /// A typed accounting rejection must remain visible in private service logs.
    #[error("accounting projector rejected a backend event: {0}")]
    ProjectorRejected(#[source] StoreError),
    /// A bounded journal batch exceeded its execution deadline.
    #[error("accounting projector exceeded its 20-second batch deadline")]
    ProjectorBatchTimeout,
    /// Wolf reported that accepting or projecting current work is unsafe.
    #[error("accounting projector stopped because the backend is unhealthy")]
    ProjectorBackendUnhealthy,
    /// The isolated worker was started without its complete spending authority.
    #[error("payout worker requires automatic payout authority")]
    PayoutWorkerMissingAuthority,
    /// A fresh worker already owns this deployment's payout lease.
    #[error("another payout worker is already active")]
    PayoutWorkerAlreadyActive,
    /// This process no longer owns the durable database-clock payout lease.
    #[error("payout worker lease was lost")]
    PayoutWorkerLeaseLost,
    /// Wallet and validator authorities could not be bound to one exact tip.
    #[error("payout authority configuration is invalid")]
    PayoutAuthorityConfiguration,
    /// A required wallet or validator authority was unavailable at startup.
    #[error("payout authority is unavailable")]
    PayoutAuthorityUnavailable,
    /// Public miner edge failed.
    #[error(transparent)]
    Edge(#[from] EdgeRuntimeError),
    /// The authoritative share router stopped while listeners were live.
    #[error("authoritative share router exited: {0}")]
    ShareRouterExited(#[source] ShareRouterError),
    /// A serving component stopped without a process shutdown request.
    #[error("serving component exited unexpectedly: {0}")]
    UnexpectedComponentExit(&'static str),
    /// A spawned service task panicked or was cancelled.
    #[error("serving component task failed")]
    TaskFailed,
    /// Public sessions or HTTP requests did not drain within policy.
    #[error("service shutdown exceeded its bounded drain interval")]
    DrainTimeout,
    /// The owned share actor did not drain within its independent deadline.
    #[error("authoritative share router shutdown exceeded its bounded interval")]
    ShareRouterShutdownTimeout,
    /// Startup or service execution failed and its mandatory cleanup also failed.
    #[error("service failed ({service}); mandatory cleanup also failed ({cleanup})")]
    ServiceAndCleanupFailed {
        /// Original service or startup error.
        service: Box<ServiceError>,
        /// Independent authority shutdown or namespace-release error.
        cleanup: Box<ServiceError>,
    },
    /// An owned component was absent from an impossible internal state.
    #[error("service ownership invariant failed")]
    Invariant,
}

impl ServiceError {
    fn payout_worker_lease_can_release(&self) -> bool {
        match self {
            Self::DrainTimeout | Self::TaskFailed => false,
            Self::ServiceAndCleanupFailed { service, cleanup } => {
                service.payout_worker_lease_can_release()
                    && cleanup.payout_worker_lease_can_release()
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use std::{io, sync::Arc, time::Duration};

    #[cfg(unix)]
    use std::{
        fs,
        net::SocketAddr,
        os::unix::{fs::PermissionsExt, net::UnixDatagram},
        path::{Path, PathBuf},
        str::FromStr,
    };

    #[cfg(unix)]
    use num_bigint::BigUint;
    #[cfg(unix)]
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use tempfile::TempDir;
    #[cfg(unix)]
    use uuid::Uuid;
    use wcash_pool_store::StoreError;

    #[cfg(unix)]
    use super::send_service_manager_ready;
    use super::{
        backend_tip_facts_match, combine_service_and_cleanup, drain_payout_startup,
        exercise_preflight, mark_payout_ready_or_shutdown, observe_then_verify_current_backend,
        retain_first_error, validate_probe_only_payout_configuration, validate_projector_authority,
        verify_startup_signer_readiness, wait_for_payout_worker_lease,
        wait_for_projector_heartbeat, with_payout_worker_lease, AuthorityTip, PreflightProbe,
        ProjectorBackendHealth, ProjectorBackendHealthWindow, ServiceError,
        VerifiedWalletAuthority, MAX_WEC_IN_FLIGHT_PASS_SECS, PAYOUT_MAXIMUM_CONFIRMATION_WATCHES,
        PAYOUT_WORKER_LEASE_ACQUIRE_WAIT, PAYOUT_WORKER_LEASE_DURATION,
        PAYOUT_WORKER_LEASE_RETRY_INTERVAL, PROJECTOR_BACKEND_UNHEALTHY_GRACE,
        REQUIRED_PAYOUT_READINESS_TIMEOUT, REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT,
        SERVICE_DRAIN_TIMEOUT, SIGNER_READINESS_TIMEOUT,
    };
    use crate::config::PayoutMode;
    #[cfg(unix)]
    use crate::config::{
        AutomaticPayoutChain, AutomaticPayoutConfig, ChainRuntimePolicy, RuntimeConfig,
    };

    #[derive(Clone, Copy)]
    enum BrokenPreflightGate {
        None,
        Program,
        Signer,
        Authority,
    }

    #[test]
    fn share_router_exit_retains_the_sanitized_terminal_reason() {
        let error = ServiceError::ShareRouterExited(
            wcash_pool_edge::ShareRouterError::BackendHealthDeadline,
        );
        assert_eq!(
            error.to_string(),
            "authoritative share router exited: backend remained unhealthy beyond the two-minute job-rollover deadline"
        );
        assert!(std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<wcash_pool_edge::ShareRouterError>())
            .is_some_and(
                |source| *source == wcash_pool_edge::ShareRouterError::BackendHealthDeadline
            ));
    }

    #[cfg(unix)]
    #[test]
    fn service_manager_readiness_uses_one_exact_absolute_datagram() {
        let temporary = TempDir::new().expect("notification fixture directory");
        let socket_path = temporary.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind notification fixture");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bound notification timeout");

        send_service_manager_ready(socket_path.as_os_str()).expect("send exact readiness");
        let mut payload = [0_u8; 32];
        let received = receiver
            .recv(&mut payload)
            .expect("receive exact readiness");
        assert_eq!(&payload[..received], b"READY=1");

        let relative = std::ffi::OsStr::new("notify.sock");
        assert_eq!(
            send_service_manager_ready(relative)
                .expect_err("relative notification socket is rejected")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn projector_configuration_cannot_contain_spending_authority() {
        validate_projector_authority(PayoutMode::Deferred, false)
            .expect("deferred projector is accepted");
        for (mode, configured) in [
            (PayoutMode::Automatic, true),
            (PayoutMode::Automatic, false),
            (PayoutMode::Deferred, true),
        ] {
            assert!(matches!(
                validate_projector_authority(mode, configured),
                Err(ServiceError::ProjectorHasPayoutAuthority)
            ));
        }
    }

    #[tokio::test]
    async fn projector_shutdown_preempts_an_immediately_ready_heartbeat() {
        let mut heartbeat = tokio::time::interval(Duration::from_secs(60));
        let mut shutdown = Box::pin(async { Ok(()) });
        assert!(
            !wait_for_projector_heartbeat(&mut heartbeat, shutdown.as_mut())
                .await
                .expect("shutdown signal succeeds")
        );
    }

    #[tokio::test]
    async fn projector_starts_with_an_immediate_health_cycle() {
        let mut heartbeat = tokio::time::interval(Duration::from_secs(60));
        let mut shutdown = Box::pin(std::future::pending::<io::Result<()>>());
        assert!(
            wait_for_projector_heartbeat(&mut heartbeat, shutdown.as_mut())
                .await
                .expect("initial heartbeat succeeds")
        );
    }

    #[test]
    fn projector_tolerates_bounded_startup_and_rotation_health_gaps() {
        let start = tokio::time::Instant::now();
        let mut window = ProjectorBackendHealthWindow::default();

        assert_eq!(
            window.observe(false, start),
            ProjectorBackendHealth::TransientlyUnhealthy
        );
        assert_eq!(
            window.observe(
                false,
                start + PROJECTOR_BACKEND_UNHEALTHY_GRACE - Duration::from_nanos(1)
            ),
            ProjectorBackendHealth::TransientlyUnhealthy
        );
        assert_eq!(
            window.observe(true, start + PROJECTOR_BACKEND_UNHEALTHY_GRACE),
            ProjectorBackendHealth::Healthy
        );

        let rotation = start + PROJECTOR_BACKEND_UNHEALTHY_GRACE + Duration::from_secs(1);
        assert_eq!(
            window.observe(false, rotation),
            ProjectorBackendHealth::TransientlyUnhealthy
        );
        assert_eq!(
            window.observe(false, rotation + PROJECTOR_BACKEND_UNHEALTHY_GRACE),
            ProjectorBackendHealth::GraceExpired
        );
    }

    #[tokio::test]
    async fn payout_lease_precedes_authority_and_releases_after_failure() {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let acquire_events = std::sync::Arc::clone(&events);
        let action_events = std::sync::Arc::clone(&events);
        let release_events = std::sync::Arc::clone(&events);
        let result = with_payout_worker_lease(
            async move {
                acquire_events.lock().expect("events").push("acquire");
                Ok::<_, StoreError>(true)
            },
            || async move {
                action_events.lock().expect("events").push("authority");
                Err(ServiceError::SignerUnavailable)
            },
            || async move {
                release_events.lock().expect("events").push("release");
                Ok::<_, StoreError>(true)
            },
        )
        .await;

        assert!(matches!(result, Err(ServiceError::SignerUnavailable)));
        assert_eq!(
            *events.lock().expect("events"),
            ["acquire", "authority", "release"]
        );
    }

    #[tokio::test]
    async fn rejected_payout_lease_constructs_no_authority_and_does_not_release() {
        let action_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let action_probe = std::sync::Arc::clone(&action_called);
        let release_probe = std::sync::Arc::clone(&release_called);
        let result = with_payout_worker_lease(
            async { Ok::<_, StoreError>(false) },
            || async move {
                action_probe.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            || async move {
                release_probe.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, StoreError>(true)
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(ServiceError::PayoutWorkerAlreadyActive)
        ));
        assert!(!action_called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!release_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn sigkill_takeover_waits_for_database_clock_expiry_without_overlap() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let database_now = Arc::new(AtomicU64::new(0));
        let attempts = Arc::new(AtomicU64::new(0));
        let acquire_clock = Arc::clone(&database_now);
        let acquire_attempts = Arc::clone(&attempts);
        let wait_clock = Arc::clone(&database_now);
        let previous_owner_expires_at = PAYOUT_WORKER_LEASE_DURATION.as_secs();

        let acquired = wait_for_payout_worker_lease(
            move || {
                let now = acquire_clock.load(Ordering::SeqCst);
                acquire_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok::<_, StoreError>(now >= previous_owner_expires_at) }
            },
            PAYOUT_WORKER_LEASE_ACQUIRE_WAIT,
            PAYOUT_WORKER_LEASE_RETRY_INTERVAL,
            std::future::pending::<io::Result<()>>(),
            move |delay| {
                wait_clock.fetch_add(delay.as_secs(), Ordering::SeqCst);
                std::future::ready(())
            },
        )
        .await
        .expect("successor reaches the database-clock takeover boundary");

        assert!(acquired);
        assert_eq!(
            database_now.load(Ordering::SeqCst),
            previous_owner_expires_at
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            previous_owner_expires_at / PAYOUT_WORKER_LEASE_RETRY_INTERVAL.as_secs() + 1
        );
    }

    #[tokio::test]
    async fn payout_lease_standby_is_interruptible_without_claim_or_release() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let attempts = Arc::new(AtomicU64::new(0));
        let acquire_attempts = Arc::clone(&attempts);
        let acquired = wait_for_payout_worker_lease(
            move || {
                acquire_attempts.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, StoreError>(false) }
            },
            PAYOUT_WORKER_LEASE_ACQUIRE_WAIT,
            PAYOUT_WORKER_LEASE_RETRY_INTERVAL,
            async { Ok(()) },
            |_| std::future::pending::<()>(),
        )
        .await
        .expect("standby shutdown succeeds");

        assert!(!acquired);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn payout_lease_standby_has_a_hard_retry_budget() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let waited = Arc::new(AtomicU64::new(0));
        let wait_clock = Arc::clone(&waited);
        let result = wait_for_payout_worker_lease(
            || async { Ok::<_, StoreError>(false) },
            PAYOUT_WORKER_LEASE_ACQUIRE_WAIT,
            PAYOUT_WORKER_LEASE_RETRY_INTERVAL,
            std::future::pending::<io::Result<()>>(),
            move |delay| {
                wait_clock.fetch_add(delay.as_secs(), Ordering::SeqCst);
                std::future::ready(())
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(ServiceError::PayoutWorkerAlreadyActive)
        ));
        assert_eq!(
            waited.load(Ordering::SeqCst),
            PAYOUT_WORKER_LEASE_ACQUIRE_WAIT.as_secs()
        );
    }

    #[tokio::test]
    async fn shutdown_before_readiness_never_marks_worker_ready() {
        use std::{
            pin::Pin,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            task::{Context, Poll},
        };

        struct MarkReadyProbe(Arc<AtomicBool>);

        impl std::future::Future for MarkReadyProbe {
            type Output = Result<bool, StoreError>;

            fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
                self.0.store(true, Ordering::SeqCst);
                Poll::Pending
            }
        }

        let readiness_polled = Arc::new(AtomicBool::new(false));
        let outcome =
            mark_payout_ready_or_shutdown(MarkReadyProbe(Arc::clone(&readiness_polled)), async {
                Ok(())
            })
            .await
            .expect("clean pre-ready shutdown succeeds");

        assert!(!outcome);
        assert!(!readiness_polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn pre_ready_shutdown_drains_startup_before_lease_release() {
        use std::sync::Mutex;

        use tokio::{sync::Notify, task::JoinSet};

        let events = Arc::new(Mutex::new(Vec::new()));
        let startup_gate = Arc::new(Notify::new());
        let acquire_events = Arc::clone(&events);
        let action_events = Arc::clone(&events);
        let action_gate = Arc::clone(&startup_gate);
        let release_events = Arc::clone(&events);

        let worker = tokio::spawn(async move {
            with_payout_worker_lease(
                async move {
                    acquire_events.lock().expect("events").push("acquire");
                    Ok::<_, StoreError>(true)
                },
                || async move {
                    let mut startup_tasks = JoinSet::new();
                    startup_tasks.spawn(async move {
                        action_gate.notified().await;
                        action_events
                            .lock()
                            .expect("events")
                            .push("startup_finished");
                        Err(ServiceError::SignerUnavailable)
                    });
                    // This is the production pre-ready signal path: it must
                    // join the non-cancellable startup task before returning.
                    drain_payout_startup(&mut startup_tasks).await
                },
                || async move {
                    release_events.lock().expect("events").push("release");
                    Ok::<_, StoreError>(true)
                },
            )
            .await
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(*events.lock().expect("events"), ["acquire"]);

        startup_gate.notify_one();
        let result = worker.await.expect("worker task joins");
        assert!(matches!(result, Err(ServiceError::SignerUnavailable)));
        assert_eq!(
            *events.lock().expect("events"),
            ["acquire", "startup_finished", "release"]
        );
    }

    #[test]
    fn unsafe_task_drain_never_releases_the_takeover_fence() {
        assert!(!ServiceError::DrainTimeout.payout_worker_lease_can_release());
        assert!(!ServiceError::TaskFailed.payout_worker_lease_can_release());
    }

    struct StartupReadySigner;

    impl wcash_pool_portal::IsolatedPayoutSigner for StartupReadySigner {
        fn readiness(&self) -> Result<(), wcash_pool_portal::SignerError> {
            Ok(())
        }

        fn sign_and_broadcast(
            &self,
            _request: &wcash_pool_portal::PayoutBatchRequest,
        ) -> Result<wcash_pool_portal::BroadcastReceipt, wcash_pool_portal::SignerError> {
            Err(wcash_pool_portal::SignerError::NotConfigured)
        }
    }

    #[tokio::test]
    async fn startup_signer_probe_uses_its_dedicated_long_budget() {
        assert!(SIGNER_READINESS_TIMEOUT > Duration::from_secs(5));
        verify_startup_signer_readiness(Arc::new(StartupReadySigner), SIGNER_READINESS_TIMEOUT)
            .await
            .expect("startup probe accepts the reviewed long timeout");

        let error = verify_startup_signer_readiness(
            Arc::new(StartupReadySigner),
            SIGNER_READINESS_TIMEOUT + Duration::from_secs(1),
        )
        .await
        .expect_err("unreviewed startup timeouts fail closed");
        assert!(matches!(error, ServiceError::SignerUnavailable));
    }

    struct FakePreflightProbe {
        broken: BrokenPreflightGate,
        calls: Vec<&'static str>,
    }

    impl PreflightProbe for FakePreflightProbe {
        async fn address_authority(&mut self) -> Result<(), ServiceError> {
            self.calls.push("address");
            if matches!(self.broken, BrokenPreflightGate::Program) {
                Err(ServiceError::AddressAuthorityUnavailable)
            } else {
                Ok(())
            }
        }

        async fn payout_composition(&mut self) -> Result<(), ServiceError> {
            self.calls.push("payout");
            match self.broken {
                BrokenPreflightGate::Signer => Err(ServiceError::SignerUnavailable),
                BrokenPreflightGate::Authority => Err(ServiceError::PayoutAuthorityUnavailable),
                BrokenPreflightGate::None | BrokenPreflightGate::Program => Ok(()),
            }
        }

        async fn portal_composition(&mut self) -> Result<(), ServiceError> {
            self.calls.push("portal");
            Ok(())
        }
    }

    #[test]
    fn simultaneous_startup_and_cleanup_failures_remain_visible() {
        let error = combine_service_and_cleanup(
            Err(ServiceError::SignerUnavailable),
            Err(ServiceError::ShareRouterShutdownTimeout),
        )
        .expect_err("combined failure must remain fatal");
        let ServiceError::ServiceAndCleanupFailed { service, cleanup } = error else {
            panic!("both errors must be retained");
        };
        assert!(matches!(*service, ServiceError::SignerUnavailable));
        assert!(matches!(*cleanup, ServiceError::ShareRouterShutdownTimeout));
    }

    #[test]
    fn drain_retains_first_failure_while_accepting_later_results() {
        let mut first = None;
        retain_first_error(&mut first, Err(ServiceError::SignerUnavailable));
        retain_first_error(&mut first, Ok(()));
        retain_first_error(&mut first, Err(ServiceError::TaskFailed));
        assert!(matches!(first, Some(ServiceError::SignerUnavailable)));
    }

    #[tokio::test]
    async fn preflight_fails_closed_on_broken_program_signer_or_authority() {
        for (broken, expected_calls) in [
            (BrokenPreflightGate::Program, vec!["address"]),
            (BrokenPreflightGate::Signer, vec!["address", "payout"]),
            (BrokenPreflightGate::Authority, vec!["address", "payout"]),
        ] {
            let mut probe = FakePreflightProbe {
                broken,
                calls: Vec::new(),
            };
            assert!(exercise_preflight(&mut probe).await.is_err());
            assert_eq!(probe.calls, expected_calls);
        }

        let mut healthy = FakePreflightProbe {
            broken: BrokenPreflightGate::None,
            calls: Vec::new(),
        };
        exercise_preflight(&mut healthy)
            .await
            .expect("every required dependency is healthy");
        assert_eq!(healthy.calls, ["address", "payout", "portal"]);
    }

    #[cfg(unix)]
    #[test]
    fn payout_preflight_cannot_invoke_wallet_effects_or_create_runtime_state() {
        let root = TempDir::new().expect("temporary preflight root");
        let root = fs::canonicalize(root.path()).expect("canonical preflight root");
        let marker = root.join("wallet-was-invoked");
        let program_bytes = format!(
            "#!/bin/sh\nprintf invoked > '{}'\nexit 97\n",
            marker.display()
        )
        .into_bytes();
        let program = write_probe_file(&root, "wcash-wallet", &program_bytes, 0o700);
        let wallet_database = write_probe_file(&root, "wallet.sqlite", b"probe-only", 0o600);
        let seed_bytes = format!("{}\n", "42".repeat(32)).into_bytes();
        let seed = write_probe_file(&root, "wcash-seed", &seed_bytes, 0o600);
        let zcash_cookie = write_probe_file(&root, "zcash.cookie", b"user:password", 0o600);
        let wcash_cookie = write_probe_file(&root, "wcash.cookie", b"user:password", 0o600);
        let database_url =
            write_probe_file(&root, "database-url", b"postgresql://pool@/zecwec", 0o600);
        let pepper = write_probe_file(&root, "pepper", &[0x81; 32], 0o600);
        let totp = write_probe_file(&root, "totp", &[0x82; 32], 0o600);
        let wec_journal = root.join("wec-journal");
        let wallet_digest: [u8; 32] = Sha256::digest(&program_bytes).into();
        let before = directory_names(&root);

        let policy = ChainRuntimePolicy {
            pplns_window_work: BigUint::from(1_u8),
            payout_threshold_zat: 100_000_000,
            required_confirmations: 100,
            maximum_payout_outputs: 50,
            maximum_payout_zat: 100_000_000,
            maximum_network_fee_zat: 1_000_000,
            maximum_network_fee_bps: 100,
            policy_version: 1,
        };
        let config = RuntimeConfig {
            network: wcash_pool_portal::ChainNetwork::Testnet,
            deployment_id: Uuid::from_u128(1),
            pool_instance: Uuid::from_u128(2),
            backend_instance: Uuid::from_u128(3),
            journal_stream: Uuid::from_u128(4),
            chain_id: 1_991_772_603,
            wcash_genesis: [1; 32],
            zcash_genesis: [2; 32],
            wcash_payout_commitment: [3; 32],
            zcash_payout_commitment: [4; 32],
            backend_socket: root.join("backend.sock"),
            database_url_file: database_url,
            stratum_listen: SocketAddr::from_str("0.0.0.0:28237").expect("stratum address"),
            portal_listen: SocketAddr::from_str("127.0.0.1:8080").expect("portal address"),
            portal_origin: "https://testnet.zecwec.com".to_owned(),
            registration_open: true,
            payout_change_hold_secs: 172800,
            nonce_namespace: 1,
            nonce_reservation: 1_000_000,
            database_connections: 8,
            maximum_miners: 1_024,
            maximum_miners_per_ip: 8,
            authentication_parallelism: 4,
            mining_authentication: wcash_pool_store::MiningAuthenticationMode::Token,
            wcash_wallet_program: program,
            wcash_wallet_sha256: wallet_digest,
            wcash_wallet_uid: rustix::process::geteuid().as_raw(),
            payout_mode: PayoutMode::Automatic,
            automatic_payout: Some(AutomaticPayoutConfig {
                chains: vec![AutomaticPayoutChain::Wcash],
                wcash_wallet_database: wallet_database.clone(),
                wcash_lightwalletd_endpoint: "http://127.0.0.1:38234".to_owned(),
                wcash_wallet_sync_batch_size: 16,
                wcash_wallet_sync_timeout: Duration::from_secs(300),
                wcash_wallet_seed_file: seed.clone(),
                wcash_seed_uid: rustix::process::geteuid().as_raw(),
                wcash_signer_journal_directory: wec_journal.clone(),
                wcash_signer_account: Uuid::from_u128(5),
                wcash_opening_pool_equity_zat: 0,
            }),
            wcash_node_rpc: SocketAddr::from_str("127.0.0.1:38232").expect("Wcash RPC address"),
            wcash_node_cookie_file: wcash_cookie,
            zcash_node_rpc: SocketAddr::from_str("127.0.0.1:18242").expect("Zcash RPC address"),
            zcash_node_cookie_file: zcash_cookie,
            portal_token_pepper_file: pepper,
            portal_totp_key_file: totp,
            wcash_policy: policy.clone(),
            zcash_policy: policy,
            initial_share_target_be: [6; 32],
            easiest_share_target_be: [7; 32],
        };

        validate_probe_only_payout_configuration(&config)
            .expect("probe-only payout configuration is valid");

        let mut deferred = config.clone();
        deferred.payout_mode = PayoutMode::Deferred;
        deferred.automatic_payout = None;
        validate_probe_only_payout_configuration(&deferred)
            .expect("deferred mining does not require payout authority");

        assert_eq!(directory_names(&root), before);
        assert!(!marker.exists(), "the wallet executable must not run");
        assert!(
            !wec_journal.exists(),
            "WEC signer journal must not be created"
        );
        assert!(!root.join("wallet.sqlite-wal").exists());
        assert!(!root.join("wallet.sqlite-shm").exists());
        assert_eq!(
            fs::read(wallet_database).expect("wallet database"),
            b"probe-only"
        );
        assert_eq!(fs::read(seed).expect("seed credential"), seed_bytes);
    }

    #[cfg(unix)]
    fn write_probe_file(root: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, bytes).expect("write probe fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set probe fixture permissions");
        path
    }

    #[cfg(unix)]
    fn directory_names(root: &Path) -> Vec<PathBuf> {
        let mut names = fs::read_dir(root)
            .expect("read probe directory")
            .map(|entry| entry.expect("probe directory entry").path())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn shutdown_bounds_cover_the_longest_serialized_wcash_pass() {
        assert!(SERVICE_DRAIN_TIMEOUT.as_secs() > MAX_WEC_IN_FLIGHT_PASS_SECS);
        assert!(REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT > SERVICE_DRAIN_TIMEOUT);
        assert!(
            PAYOUT_WORKER_LEASE_DURATION
                > REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT + Duration::from_secs(60)
        );
        assert!(
            PAYOUT_WORKER_LEASE_ACQUIRE_WAIT
                >= PAYOUT_WORKER_LEASE_DURATION + PAYOUT_WORKER_LEASE_RETRY_INTERVAL
        );
        assert!(
            REQUIRED_PAYOUT_READINESS_TIMEOUT
                > PAYOUT_WORKER_LEASE_ACQUIRE_WAIT + SERVICE_DRAIN_TIMEOUT
        );
        assert_eq!(PAYOUT_MAXIMUM_CONFIRMATION_WATCHES, 8);
    }

    #[test]
    fn backend_generation_must_bind_both_exact_authority_predecessors() {
        let wcash_hash = std::array::from_fn(|index| index as u8);
        let zcash_hash = std::array::from_fn(|index| 0x80_u8.wrapping_add(index as u8));
        let wcash = AuthorityTip {
            hash: wcash_hash,
            height: 40,
        };
        let zcash = AuthorityTip {
            hash: zcash_hash,
            height: 90,
        };
        assert!(backend_tip_facts_match(
            wcash_hash, 41, wcash, zcash_hash, 91, zcash,
        ));

        let mut displayed_wcash = wcash_hash;
        displayed_wcash.reverse();
        assert!(!backend_tip_facts_match(
            displayed_wcash,
            41,
            wcash,
            zcash_hash,
            91,
            zcash,
        ));
        assert!(!backend_tip_facts_match(
            wcash_hash, 42, wcash, zcash_hash, 91, zcash,
        ));
        assert!(!backend_tip_facts_match(
            wcash_hash, 41, wcash, zcash_hash, 90, zcash,
        ));
    }

    #[tokio::test]
    async fn payout_backend_snapshot_is_loaded_after_both_live_observations() {
        use std::sync::Mutex;

        fn verified(chain: wcash_pool_store::Chain, tip: AuthorityTip) -> VerifiedWalletAuthority {
            VerifiedWalletAuthority {
                tip,
                observation: wcash_pool_store::WalletObservation {
                    chain,
                    wallet_state_digest: [9; 32],
                    wallet_spendable_zat: 0,
                    best_tip_hash: tip.hash,
                    best_tip_height: tip.height,
                    observed_at: 1,
                    valid_until: 2,
                },
            }
        }

        let order = Arc::new(Mutex::new(Vec::new()));
        let wcash_order = Arc::clone(&order);
        let zcash_order = Arc::clone(&order);
        let backend_order = Arc::clone(&order);
        let wcash_tip = AuthorityTip {
            hash: [1; 32],
            height: 10,
        };
        let zcash_tip = AuthorityTip {
            hash: [2; 32],
            height: 20,
        };

        let result = observe_then_verify_current_backend(
            async move {
                wcash_order.lock().expect("order").push("wcash");
                Ok(verified(wcash_pool_store::Chain::Wcash, wcash_tip))
            },
            async move {
                zcash_order.lock().expect("order").push("zcash");
                Ok(verified(wcash_pool_store::Chain::Zcash, zcash_tip))
            },
            move |wcash, zcash| {
                backend_order.lock().expect("order").push("backend");
                async move {
                    assert_eq!(wcash, wcash_tip);
                    assert_eq!(zcash, zcash_tip);
                    Ok(())
                }
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(*order.lock().expect("order"), ["wcash", "zcash", "backend"]);
    }
}

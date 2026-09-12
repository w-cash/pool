//! Testnet service composition and ordered process shutdown.

use std::{io, sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::watch, task::JoinSet, time};
use wcash_pool_address::{TestnetAddressValidator, WcashCommandValidator};
use wcash_pool_portal::{
    serve_until_shutdown, AddressValidator, IsolatedPayoutSigner, PoolDataSource, PortalApp,
    PortalBuildError, PortalConfig, PortalRepository, PortalSecrets, TestnetPayoutBoundary,
};
use wcash_pool_store::{NonceNamespaceClaim, PostgresPoolDataSource, PostgresStore, StoreError};
use wcash_wec_payout_signer::{SeedSource, WecPayoutSigner, WecSignerConfig};
use wcash_zec_payout_signer::{LoopbackHttpTransport, ZecPcztSigner, ZecSignerConfig};

use crate::{
    bootstrap::{self, BootstrapError, MiningBootstrap},
    config::{ConfigError, RuntimeConfig},
    edge::{self, EdgeCounters, EdgeDependencies, EdgeRuntimeError},
    payout::DualPayoutSigner,
    wec_wallet_transport::{PinnedWolfProgram, WolfWalletTransport},
};

const ADDRESS_VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);
const PORTAL_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const SERVICE_DRAIN_TIMEOUT: Duration = Duration::from_secs(45);
const SHARE_ROUTER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const COMPONENT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Starts every Testnet dependency before opening either listener, then runs
/// until a termination signal or any authority component exits.
pub async fn run(config: RuntimeConfig) -> Result<(), ServiceError> {
    let mut bootstrap = Some(bootstrap::start(&config).await?);
    let service_result = run_started(&config, &mut bootstrap).await;
    let Some(owned) = bootstrap.take() else {
        return service_result;
    };
    let cleanup_result = shutdown_bootstrap(owned).await;
    combine_service_and_cleanup(service_result, cleanup_result)
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
    let payout = build_payout_boundary(config)?;
    payout
        .readiness_bounded(Duration::from_secs(5))
        .await
        .map_err(|_| ServiceError::SignerUnavailable)?;

    let pool_data = PostgresPoolDataSource::new(started.store.as_ref().clone());
    pool_data.refresh().await?;
    let portal = build_portal(config, started, validator, pool_data.clone(), payout)?;

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

    let dependencies = EdgeDependencies::from_bootstrap(started);
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
            () = wait_for_share_router_exit(shares) => Some(Err(ServiceError::ShareRouterExited)),
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
    Ok(Arc::new(TestnetAddressValidator::new(command)))
}

fn build_payout_boundary(
    config: &RuntimeConfig,
) -> Result<Arc<TestnetPayoutBoundary>, ServiceError> {
    let pinned = PinnedWolfProgram::verify(
        config.wcash_wallet_program.clone(),
        config.wcash_wallet_sha256,
        config.wcash_wallet_uid,
    )
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wallet = Arc::new(
        WolfWalletTransport::new(
            pinned,
            config.wcash_wallet_database.clone(),
            config.wcash_lightwalletd_endpoint.clone(),
        )
        .map_err(|_| ServiceError::SignerConfiguration)?,
    );
    let wec_config = WecSignerConfig::new(
        config.wcash_signer_journal_directory.clone(),
        config.wcash_signer_account,
        SeedSource::protected_file(config.wcash_wallet_seed_file.clone(), config.wcash_seed_uid),
    )
    .and_then(|configured| {
        configured.with_confirmations(config.wcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.wcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.wcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wec: Arc<dyn IsolatedPayoutSigner> = Arc::new(
        WecPayoutSigner::new(wec_config, wallet).map_err(|_| ServiceError::SignerConfiguration)?,
    );

    let zallet = Arc::new(
        LoopbackHttpTransport::new(config.zallet_rpc, config.zallet_cookie_file.clone())
            .map_err(|_| ServiceError::SignerConfiguration)?,
    );
    let zebra = Arc::new(
        LoopbackHttpTransport::new(config.zcash_node_rpc, config.zcash_node_cookie_file.clone())
            .map_err(|_| ServiceError::SignerConfiguration)?,
    );
    let zec_config = ZecSignerConfig::new(
        config.zcash_signer_journal_directory.clone(),
        config.zallet_configuration.clone(),
        config.zcash_signer_account,
    )
    .and_then(|configured| {
        configured.with_min_confirmations(config.zcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.zcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.zcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let zec: Arc<dyn IsolatedPayoutSigner> = Arc::new(
        ZecPcztSigner::new(zec_config, zallet, zebra)
            .map_err(|_| ServiceError::SignerConfiguration)?,
    );

    Ok(Arc::new(TestnetPayoutBoundary::new(Arc::new(
        DualPayoutSigner::new(wec, zec),
    ))))
}

fn build_portal(
    config: &RuntimeConfig,
    bootstrap: &MiningBootstrap,
    validator: Arc<dyn AddressValidator>,
    pool_data: PostgresPoolDataSource,
    payout: Arc<TestnetPayoutBoundary>,
) -> Result<PortalApp, ServiceError> {
    let mut portal_config = PortalConfig::testnet();
    portal_config
        .canonical_origin
        .clone_from(&config.portal_origin);
    let token = RuntimeConfig::portal_secret(&config.portal_token_pepper_file)?;
    let totp = RuntimeConfig::portal_secret(&config.portal_totp_key_file)?;
    let secrets = PortalSecrets::new(*token, *totp);
    let repository: Arc<dyn PortalRepository> = bootstrap.store.clone();
    let data: Arc<dyn PoolDataSource> = Arc::new(pool_data);
    PortalApp::new(portal_config, secrets, repository, validator, data, payout)
        .map_err(ServiceError::from)
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

async fn wait_for_share_router_exit(shares: &wcash_pool_edge::ShareRouter) {
    let mut interval = time::interval(COMPONENT_POLL_INTERVAL);
    loop {
        interval.tick().await;
        if shares.is_finished() {
            return;
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
    /// Wolf's authoritative address command was not usable.
    #[error("Wcash address authority is unavailable")]
    AddressAuthorityUnavailable,
    /// A chain-separated signer had invalid static configuration.
    #[error("payout signer configuration is invalid")]
    SignerConfiguration,
    /// A configured signer failed its live readiness check.
    #[error("payout signer is unavailable")]
    SignerUnavailable,
    /// Public miner edge failed.
    #[error(transparent)]
    Edge(#[from] EdgeRuntimeError),
    /// The authoritative share router stopped while listeners were live.
    #[error("authoritative share router exited")]
    ShareRouterExited,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::{combine_service_and_cleanup, retain_first_error, ServiceError};

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
}

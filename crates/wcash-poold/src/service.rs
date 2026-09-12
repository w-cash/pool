//! Testnet service composition and ordered process shutdown.

use std::{io, sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::watch, task::JoinSet, time};
use wcash_pool_address::{TestnetAddressValidator, WcashCommandValidator};
use wcash_pool_portal::{
    serve_until_shutdown, AddressValidator, Asset, ChainNetwork, DisabledPayoutSigner,
    IsolatedPayoutSigner, MinerTelemetrySource, PoolDataSource, PortalApp, PortalBuildError,
    PortalConfig, PortalRepository, PortalSecrets, TestnetPayoutBoundary,
};
use wcash_pool_store::{
    Chain, NonceNamespaceClaim, PostgresPoolDataSource, PostgresStore, StoreError,
};
use wcash_wec_payout_signer::{
    SeedSource, WalletFundSource, WalletNetwork, WecPayoutSigner, WecSignerConfig,
    WCASH_TESTNET_BRANCH_ID,
};
use wcash_zec_payout_signer::{
    validate_zallet_configuration, LoopbackHttpTransport, ZecPcztSigner, ZecSignerConfig,
};

use crate::{
    bootstrap::{self, BootstrapError, MiningBootstrap},
    config::{ConfigError, RuntimeConfig, MAX_WCASH_WALLET_SYNC_TIMEOUT},
    edge::{self, EdgeCounters, EdgeDependencies, EdgeRuntimeError},
    live_payout::{
        LivePayoutConfigError, LoopbackJsonRpc, NodePayoutAuthority, RpcExactBroadcaster,
        ZalletObservationSource,
    },
    miner_telemetry::LiveMinerTelemetry,
    payout::DualPayoutSigner,
    payout_runtime::{
        AutomaticPayoutRuntime, ObservationFailure, PayoutConfirmationAuthority, PayoutLoopPolicy,
        PayoutRuntimeError, WalletObservationSource, WcashObservationSource,
    },
    settlement::{
        ReconciliationGate, ResumeOutcome, SettlementError, SettlementOrchestrator,
        WecExecutionSigner, ZecExecutionSigner,
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

/// Exercises the non-listening, probe-only service dependency graph once.
///
/// Unlike [`run`], this path starts no share, payout, portal, refresh, nonce,
/// or socket task. It never constructs signer journals or payout runtimes and
/// never creates, recovers, signs, observes, synchronizes, or broadcasts a
/// transaction. Durable payout recovery remains part of [`run`] after this
/// service-manager probe succeeds. Every resource is dropped before return.
pub async fn preflight(config: &RuntimeConfig) -> Result<(), ServiceError> {
    let started = bootstrap::preflight(config).await?;
    let mut probe = LivePreflightProbe {
        config,
        started,
        validator: None,
        payout_boundary: None,
    };
    exercise_preflight(&mut probe).await
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
        verify_address_authority(Arc::clone(&validator)).await?;
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
    verify_address_authority(Arc::clone(&validator)).await?;
    let payout_services =
        build_payout_services(config, Arc::clone(&started.store), &started.jobs).await?;

    let pool_data = PostgresPoolDataSource::new(started.store.as_ref().clone());
    pool_data.refresh().await?;
    let miner_telemetry = Arc::new(LiveMinerTelemetry::default());
    let portal = build_portal(
        config,
        started,
        validator,
        pool_data.clone(),
        Arc::clone(&miner_telemetry),
        Arc::clone(&payout_services.portal),
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

    let wec_payout_shutdown = shutdown_rx.clone();
    let wec_payout = Arc::clone(&payout_services.wec);
    tasks.spawn(async move { ServiceTask::WecPayout(wec_payout.run(wec_payout_shutdown).await) });

    let zec_payout_shutdown = shutdown_rx.clone();
    let zec_payout = Arc::clone(&payout_services.zec);
    tasks.spawn(async move { ServiceTask::ZecPayout(zec_payout.run(zec_payout_shutdown).await) });

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

async fn verify_address_authority(
    validator: Arc<dyn AddressValidator>,
) -> Result<(), ServiceError> {
    tokio::task::spawn_blocking(move || {
        validator
            .readiness(Asset::Wec, ChainNetwork::Testnet)
            .and_then(|()| validator.readiness(Asset::Zec, ChainNetwork::Testnet))
    })
    .await
    .map_err(|_| ServiceError::AddressAuthorityUnavailable)?
    .map_err(|_| ServiceError::AddressAuthorityUnavailable)
}

struct PayoutServices {
    portal: Arc<TestnetPayoutBoundary>,
    wec: Arc<AutomaticPayoutRuntime>,
    zec: Arc<AutomaticPayoutRuntime>,
}

/// Builds the payout-facing portal dependency after configuration and
/// read-only chain authority checks, without constructing any signer journal,
/// settlement orchestrator, wallet observer, or automatic payout runtime.
///
/// In particular, this path cannot create, recover, sign, rebroadcast, or
/// reconcile a payout. Those durable transitions remain exclusive to
/// [`build_payout_services`] during actual service startup.
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
    Ok(Arc::new(TestnetPayoutBoundary::new(Arc::new(
        DisabledPayoutSigner,
    ))))
}

fn validate_probe_only_payout_configuration(config: &RuntimeConfig) -> Result<(), ServiceError> {
    let pinned = PinnedWolfProgram::verify(
        config.wcash_wallet_program.clone(),
        config.wcash_wallet_sha256,
        config.wcash_wallet_uid,
    )
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let wallet = WolfWalletTransport::new(
        pinned,
        config.wcash_wallet_database.clone(),
        config.wcash_lightwalletd_endpoint.clone(),
    )
    .map_err(|_| ServiceError::SignerConfiguration)?;
    wallet
        .probe_readonly_boundary()
        .map_err(|_| ServiceError::SignerConfiguration)?;

    let seed =
        SeedSource::protected_file(config.wcash_wallet_seed_file.clone(), config.wcash_seed_uid);
    seed.validate_protected_metadata()
        .map_err(|_| ServiceError::SignerConfiguration)?;
    let _wec = WecSignerConfig::new(
        config.wcash_signer_journal_directory.clone(),
        config.wcash_signer_account,
        config.wcash_payout_commitment,
        seed,
    )
    .and_then(|configured| {
        configured.with_confirmations(config.wcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.wcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.wcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;

    validate_zallet_configuration(&config.zallet_configuration)
        .map_err(|_| ServiceError::SignerConfiguration)?;
    let _zallet = LoopbackHttpTransport::new(config.zallet_rpc, config.zallet_cookie_file.clone())
        .map_err(|_| ServiceError::SignerConfiguration)?;
    let _zebra =
        LoopbackHttpTransport::new(config.zcash_node_rpc, config.zcash_node_cookie_file.clone())
            .map_err(|_| ServiceError::SignerConfiguration)?;
    let _zec = ZecSignerConfig::new(
        config.zcash_signer_journal_directory.clone(),
        config.zallet_configuration.clone(),
        config.zcash_signer_account,
        config.zcash_payout_commitment,
    )
    .and_then(|configured| {
        configured.with_min_confirmations(config.zcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.zcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.zcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;

    Ok(())
}

async fn build_payout_services(
    config: &RuntimeConfig,
    store: Arc<PostgresStore>,
    jobs: &wcash_pool_edge::JobRouter,
) -> Result<PayoutServices, ServiceError> {
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
        config.wcash_payout_commitment,
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
    let wec = Arc::new(
        WecPayoutSigner::new(wec_config, wallet.clone())
            .map_err(|_| ServiceError::SignerConfiguration)?,
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
        config.zcash_payout_commitment,
    )
    .and_then(|configured| {
        configured.with_min_confirmations(config.zcash_policy.required_confirmations)
    })
    .and_then(|configured| {
        configured.with_max_outputs(config.zcash_policy.maximum_payout_outputs as usize)
    })
    .and_then(|configured| configured.with_max_fee_zat(config.zcash_policy.maximum_network_fee_zat))
    .map_err(|_| ServiceError::SignerConfiguration)?;
    let zec = Arc::new(
        ZecPcztSigner::new(zec_config, zallet, zebra)
            .map_err(|_| ServiceError::SignerConfiguration)?,
    );

    let portal = Arc::new(TestnetPayoutBoundary::new(Arc::new(DualPayoutSigner::new(
        Arc::clone(&wec) as Arc<dyn IsolatedPayoutSigner>,
        Arc::clone(&zec) as Arc<dyn IsolatedPayoutSigner>,
    ))));

    let wcash_rpc = Arc::new(
        LoopbackJsonRpc::new(config.wcash_node_rpc, config.wcash_node_cookie_file.clone())
            .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
    );
    let zcash_rpc = Arc::new(LoopbackJsonRpc::new(
        config.zcash_node_rpc,
        config.zcash_node_cookie_file.clone(),
    )?);
    let zallet_rpc = Arc::new(LoopbackJsonRpc::new(
        config.zallet_rpc,
        config.zallet_cookie_file.clone(),
    )?);

    let wcash_wallet = Arc::new(
        WcashObservationSource::new(
            WcashWalletObserver::new(
                wallet.as_ref().clone(),
                WalletNetwork::Testnet,
                config.wcash_genesis,
                WCASH_TESTNET_BRANCH_ID,
                config.wcash_signer_account,
                WalletFundSource::Ironwood,
                config.wcash_payout_commitment,
                config.wcash_wallet_sync_timeout,
                config.wcash_wallet_sync_batch_size,
            )
            .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
            Duration::from_secs(15),
            1024 * 1024,
        )
        .map_err(|_| ServiceError::PayoutAuthorityConfiguration)?,
    );
    let zcash_wallet = Arc::new(ZalletObservationSource::new(
        zallet_rpc,
        config.zcash_signer_account,
        config.zcash_signer_account_index,
        config.zcash_policy.required_confirmations,
        config.zcash_payout_commitment,
    )?);
    let wcash_authority = Arc::new(NodePayoutAuthority::new(
        Chain::Wcash,
        wcash_rpc,
        config.wcash_genesis,
    )?);
    let zcash_authority = Arc::new(NodePayoutAuthority::new(
        Chain::Zcash,
        zcash_rpc,
        config.zcash_genesis,
    )?);

    let (wcash_capabilities, zcash_capabilities) = tokio::join!(
        wcash_authority.startup_probe(),
        zcash_authority.startup_probe()
    );
    wcash_capabilities.map_err(map_authority_failure)?;
    zcash_capabilities.map_err(map_authority_failure)?;

    let wcash_verified = verify_observer_authority(
        wcash_wallet.as_ref(),
        wcash_authority.as_ref(),
        Chain::Wcash,
    )
    .await?;
    let zcash_verified = verify_observer_authority(
        zcash_wallet.as_ref(),
        zcash_authority.as_ref(),
        Chain::Zcash,
    )
    .await?;
    verify_backend_authority(jobs, wcash_verified.tip, zcash_verified.tip)?;

    // The Wcash observation above performs the required seedless sync under
    // the same transport lock. Check both spend-capable signer identities
    // before asking either journal to recover an unfinished payout.
    portal
        .readiness_bounded(SIGNER_READINESS_TIMEOUT)
        .await
        .map_err(|_| ServiceError::SignerUnavailable)?;

    let settlement = Arc::new(SettlementOrchestrator::new(
        Arc::clone(&store) as Arc<dyn crate::settlement::SettlementStore>,
        Arc::new(WecExecutionSigner::new(
            Arc::clone(&wec),
            config.wcash_signer_account,
        )),
        Arc::new(RpcExactBroadcaster::new(Arc::clone(&wcash_authority))),
        Arc::new(ZecExecutionSigner::new(
            Arc::clone(&zec),
            config.zcash_signer_account,
        )),
        Arc::new(RpcExactBroadcaster::new(Arc::clone(&zcash_authority))),
    )?);

    // Signer journals are an earlier durable boundary than PostgreSQL. Recover
    // them before comparing wallet balances: a crash can leave SQL Draft while
    // the wallet already holds exact signed bytes (or an older release already
    // broadcast them). Recovery first copies those bytes into SQL Signed and
    // uses the authoritative node broadcaster; it never signs a replacement.
    let wec_gate = settlement
        .recover_before_wallet_reconciliation(Chain::Wcash)
        .await?;
    let zec_gate = settlement
        .recover_before_wallet_reconciliation(Chain::Zcash)
        .await?;

    // With no in-flight external effect, a collector can join this accounting
    // namespace only when its spendable balance is represented by the sealed
    // ledger. Signed/Broadcast batches deliberately skip this snapshot: SQL
    // already classifies their wallet balance as ambiguous until confirmation.
    if wec_gate == ReconciliationGate::Safe {
        record_startup_reconciliation(&store, &wcash_verified.observation).await?;
    }
    if zec_gate == ReconciliationGate::Safe {
        record_startup_reconciliation(&store, &zcash_verified.observation).await?;
    }

    // Only after a safe wallet/ledger snapshot may an ordinary Draft create or
    // sign new bytes. Ambiguous legacy and existing SQL states were already
    // resolved above and remain under authoritative confirmation monitoring.
    if wec_gate == ReconciliationGate::Safe {
        require_nonterminal_startup_outcome(settlement.resume_next(Chain::Wcash).await?)?;
    }
    if zec_gate == ReconciliationGate::Safe {
        require_nonterminal_startup_outcome(settlement.resume_next(Chain::Zcash).await?)?;
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
    let zec = Arc::new(AutomaticPayoutRuntime::new(
        Chain::Zcash,
        config.deployment_id,
        policy,
        lifecycle_store,
        zcash_wallet,
        zcash_authority,
        settlement_driver,
    )?);
    Ok(PayoutServices { portal, wec, zec })
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
        miner_telemetry,
        payout,
    )
}

fn build_preflight_portal(
    config: &RuntimeConfig,
    store: Arc<PostgresStore>,
    validator: Arc<dyn AddressValidator>,
    pool_data: PostgresPoolDataSource,
    miner_telemetry: Arc<dyn MinerTelemetrySource>,
    payout: Arc<TestnetPayoutBoundary>,
) -> Result<PortalApp, ServiceError> {
    let mut portal_config = PortalConfig::testnet();
    portal_config
        .canonical_origin
        .clone_from(&config.portal_origin);
    let token = RuntimeConfig::portal_secret(&config.portal_token_pepper_file)?;
    let totp = RuntimeConfig::portal_secret(&config.portal_totp_key_file)?;
    let secrets = PortalSecrets::new(*token, *totp);
    let repository: Arc<dyn PortalRepository> = store;
    let data: Arc<dyn PoolDataSource> = Arc::new(pool_data);
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
    WecPayout(Result<(), PayoutRuntimeError>),
    ZecPayout(Result<(), PayoutRuntimeError>),
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
        Some(Ok(ServiceTask::ZecPayout(Ok(())))) => {
            Err(ServiceError::UnexpectedComponentExit("zec_payout"))
        }
        Some(Ok(ServiceTask::ZecPayout(Err(error)))) => Err(ServiceError::PayoutRuntime(error)),
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
        Ok(ServiceTask::WecPayout(result) | ServiceTask::ZecPayout(result)) => {
            result.map_err(ServiceError::from)
        }
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
    /// Local wallet or validator configuration violated a payout boundary.
    #[error(transparent)]
    LivePayoutConfiguration(#[from] LivePayoutConfigError),
    /// Exact settlement composition was internally inconsistent.
    #[error(transparent)]
    Settlement(#[from] SettlementError),
    /// An automatic payout worker stopped on a durable or authority failure.
    #[error(transparent)]
    PayoutRuntime(#[from] PayoutRuntimeError),
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

    #[cfg(unix)]
    use std::{
        fs,
        net::SocketAddr,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        str::FromStr,
        time::Duration,
    };

    #[cfg(unix)]
    use num_bigint::BigUint;
    #[cfg(unix)]
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use tempfile::TempDir;
    #[cfg(unix)]
    use uuid::Uuid;
    #[cfg(unix)]
    use wcash_zec_payout_signer::ZALLET_API_VERSION;

    use super::{
        backend_tip_facts_match, combine_service_and_cleanup, exercise_preflight,
        retain_first_error, validate_probe_only_payout_configuration, AuthorityTip, PreflightProbe,
        ServiceError, MAX_WEC_IN_FLIGHT_PASS_SECS, PAYOUT_MAXIMUM_CONFIRMATION_WATCHES,
        REQUIRED_SERVICE_MANAGER_STOP_TIMEOUT, SERVICE_DRAIN_TIMEOUT,
    };
    #[cfg(unix)]
    use crate::config::{ChainRuntimePolicy, RuntimeConfig};

    #[derive(Clone, Copy)]
    enum BrokenPreflightGate {
        None,
        Program,
        Signer,
        Authority,
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
        let zallet = write_probe_file(
            &root,
            "zallet.toml",
            format!(
                "[consensus]\nnetwork = \"test\"\n[external]\nbroadcast = false\n[features]\nas_of_version = \"{ZALLET_API_VERSION}\"\n[rpc]\nbind = [\"127.0.0.1:28232\"]\n"
            )
            .as_bytes(),
            0o600,
        );
        let zallet_cookie = write_probe_file(&root, "zallet.cookie", b"user:password", 0o600);
        let zcash_cookie = write_probe_file(&root, "zcash.cookie", b"user:password", 0o600);
        let wcash_cookie = write_probe_file(&root, "wcash.cookie", b"user:password", 0o600);
        let database_url =
            write_probe_file(&root, "database-url", b"postgresql://pool@/zecwec", 0o600);
        let pepper = write_probe_file(&root, "pepper", &[0x81; 32], 0o600);
        let totp = write_probe_file(&root, "totp", &[0x82; 32], 0o600);
        let wec_journal = root.join("wec-journal");
        let zec_journal = root.join("zec-journal");
        let wallet_digest: [u8; 32] = Sha256::digest(&program_bytes).into();
        let before = directory_names(&root);

        let policy = ChainRuntimePolicy {
            pplns_window_work: BigUint::from(1_u8),
            payout_threshold_zat: 100_000_000,
            required_confirmations: 100,
            maximum_payout_outputs: 50,
            maximum_network_fee_zat: 1_000_000,
            maximum_network_fee_bps: 100,
            policy_version: 1,
        };
        let config = RuntimeConfig {
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
            nonce_namespace: 1,
            nonce_reservation: 1_000_000,
            database_connections: 8,
            maximum_miners: 1_024,
            maximum_miners_per_ip: 8,
            authentication_parallelism: 4,
            wcash_wallet_program: program,
            wcash_wallet_sha256: wallet_digest,
            wcash_wallet_uid: rustix::process::geteuid().as_raw(),
            wcash_wallet_database: wallet_database.clone(),
            wcash_lightwalletd_endpoint: "http://127.0.0.1:38234".to_owned(),
            wcash_wallet_sync_batch_size: 16,
            wcash_wallet_sync_timeout: Duration::from_secs(300),
            wcash_node_rpc: SocketAddr::from_str("127.0.0.1:38232").expect("Wcash RPC address"),
            wcash_node_cookie_file: wcash_cookie,
            wcash_wallet_seed_file: seed.clone(),
            wcash_seed_uid: rustix::process::geteuid().as_raw(),
            wcash_signer_journal_directory: wec_journal.clone(),
            wcash_signer_account: Uuid::from_u128(5),
            zallet_configuration: zallet,
            zallet_rpc: SocketAddr::from_str("127.0.0.1:28232").expect("Zallet RPC address"),
            zallet_cookie_file: zallet_cookie,
            zcash_node_rpc: SocketAddr::from_str("127.0.0.1:18242").expect("Zcash RPC address"),
            zcash_node_cookie_file: zcash_cookie,
            zcash_signer_journal_directory: zec_journal.clone(),
            zcash_signer_account: Uuid::from_u128(6),
            zcash_signer_account_index: 0,
            portal_token_pepper_file: pepper,
            portal_totp_key_file: totp,
            wcash_policy: policy.clone(),
            zcash_policy: policy,
            initial_share_target_be: [6; 32],
            easiest_share_target_be: [7; 32],
        };

        validate_probe_only_payout_configuration(&config)
            .expect("probe-only payout configuration is valid");

        assert_eq!(directory_names(&root), before);
        assert!(!marker.exists(), "the wallet executable must not run");
        assert!(
            !wec_journal.exists(),
            "WEC signer journal must not be created"
        );
        assert!(
            !zec_journal.exists(),
            "ZEC signer journal must not be created"
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
}

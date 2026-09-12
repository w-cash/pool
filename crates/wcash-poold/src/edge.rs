//! Public miner listener composition with process and source admission bounds.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinSet,
    time::{timeout, Instant},
};
use uuid::Uuid;
use wcash_pool_backend_client::MonotonicTimeline;
use wcash_pool_core::{NoncePrefixAllocator, ShareTarget, VardiffConfig};
use wcash_pool_edge::{
    AuthenticationProvider, ConnectionActor, ConnectionCapacity, ConnectionLimits, EdgeConfig,
    JobRouter, MiningPolicy, PublicStreamDriver, RateLimit, ShareSubmissionProvider,
};
use wcash_pool_protocol::TargetBe;

use crate::{bootstrap::MiningBootstrap, config::RuntimeConfig};

const OUTBOUND_QUEUE: usize = 32;
const MAXIMUM_ANNOUNCED_JOBS: usize = 16;
const REQUESTS_PER_SECOND: u32 = 64;
const GRACEFUL_DRAIN: Duration = Duration::from_secs(30);

/// Non-sensitive live edge counters exposed to the local readiness service.
#[derive(Debug, Default)]
pub struct EdgeCounters {
    accepted_connections: AtomicU64,
    active_connections: AtomicU64,
    completed_connections: AtomicU64,
    rejected_connections: AtomicU64,
    failed_connections: AtomicU64,
}

/// Clone-only dependencies retained by miner sessions while the owned share
/// router remains available to the service shutdown coordinator.
pub struct EdgeDependencies {
    authentication: Arc<dyn AuthenticationProvider>,
    submissions: Arc<dyn ShareSubmissionProvider>,
    nonces: Arc<NoncePrefixAllocator>,
    jobs: JobRouter,
    timeline: MonotonicTimeline,
}

impl EdgeDependencies {
    /// Borrows no owned actor from the bootstrap, so the caller can explicitly
    /// drain `ShareRouter` only after every public session has stopped.
    pub fn from_bootstrap(bootstrap: &MiningBootstrap) -> Self {
        Self {
            authentication: bootstrap.authentication.clone(),
            submissions: Arc::new(bootstrap.shares.handle()),
            nonces: Arc::clone(&bootstrap.nonces),
            jobs: bootstrap.jobs.clone(),
            timeline: bootstrap.timeline,
        }
    }
}

/// Drives the public listener until shutdown, then drains bounded sessions.
pub async fn run(
    listener: TcpListener,
    dependencies: EdgeDependencies,
    config: &RuntimeConfig,
    mut shutdown: watch::Receiver<bool>,
    counters: Arc<EdgeCounters>,
) -> Result<(), EdgeRuntimeError> {
    let edge_config = edge_config(config)?;
    let policy = mining_policy(config)?;
    let global = ConnectionCapacity::new(config.maximum_miners)?;
    let sources = Arc::new(SourceCapacity::new(config.maximum_miners_per_ip)?);
    let mut sessions = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            completed = sessions.join_next(), if !sessions.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    counters.failed_connections.fetch_add(1, Ordering::Relaxed);
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(EdgeRuntimeError::Accept)?;
                let Ok(global_permit) = global.try_acquire() else {
                    counters.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let Ok(source_permit) = sources.try_acquire(peer.ip()) else {
                    counters.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let now_ms = dependencies.timeline.now_ms()?;
                let actor = match ConnectionActor::new(
                    Uuid::new_v4(),
                    edge_config,
                    policy,
                    Arc::clone(&dependencies.nonces),
                    dependencies.jobs.clone(),
                    now_ms,
                ) {
                    Ok(actor) => actor,
                    Err(_) => {
                        counters.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let driver = match PublicStreamDriver::new(
                    stream,
                    actor,
                    Arc::clone(&dependencies.authentication),
                    Arc::clone(&dependencies.submissions),
                    global_permit,
                    now_ms,
                ) {
                    Ok(driver) => driver,
                    Err(_) => {
                        counters.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                counters.accepted_connections.fetch_add(1, Ordering::Relaxed);
                counters.active_connections.fetch_add(1, Ordering::Relaxed);
                let counters = Arc::clone(&counters);
                let mut session_shutdown = shutdown.clone();
                sessions.spawn(async move {
                    let _source_permit = source_permit;
                    let (stop, stopped) = oneshot::channel();
                    let running = driver.run(stopped);
                    tokio::pin!(running);
                    let result = if *session_shutdown.borrow() {
                        let _ = stop.send(());
                        running.await
                    } else {
                        tokio::select! {
                            result = &mut running => result,
                            _ = session_shutdown.changed() => {
                                let _ = stop.send(());
                                running.await
                            }
                        }
                    };
                    counters.active_connections.fetch_sub(1, Ordering::Relaxed);
                    match result {
                        Ok(_) => {
                            counters.completed_connections.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            counters.failed_connections.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
    }

    drop(listener);
    let deadline = Instant::now() + GRACEFUL_DRAIN;
    while !sessions.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || timeout(remaining, sessions.join_next()).await.is_err() {
            sessions.abort_all();
            while sessions.join_next().await.is_some() {}
            return Err(EdgeRuntimeError::DrainTimeout);
        }
    }
    Ok(())
}

fn edge_config(config: &RuntimeConfig) -> Result<EdgeConfig, EdgeRuntimeError> {
    let limits = ConnectionLimits::new(
        config.maximum_miners,
        OUTBOUND_QUEUE,
        config.maximum_miners.min(4_096),
        MAXIMUM_ANNOUNCED_JOBS,
    )?;
    Ok(EdgeConfig::new(
        limits,
        RateLimit::new(REQUESTS_PER_SECOND, Duration::from_secs(1))?,
        Duration::from_secs(120),
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(15),
        Duration::from_secs(30),
    )?)
}

fn mining_policy(config: &RuntimeConfig) -> Result<MiningPolicy, EdgeRuntimeError> {
    let initial = ShareTarget::from_zip301(&TargetBe::new(config.initial_share_target_be))?;
    let easiest = ShareTarget::from_zip301(&TargetBe::new(config.easiest_share_target_be))?;
    let vardiff = VardiffConfig::new(10_000, 12, 2_500, 4, easiest)?;
    Ok(MiningPolicy::new(vardiff, initial))
}

struct SourceCapacity {
    maximum: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl SourceCapacity {
    fn new(maximum: usize) -> Result<Self, EdgeRuntimeError> {
        if maximum == 0 {
            return Err(EdgeRuntimeError::InvalidSourceCapacity);
        }
        Ok(Self {
            maximum,
            counts: Mutex::new(HashMap::new()),
        })
    }

    fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Result<SourcePermit, EdgeRuntimeError> {
        let mut counts = self
            .counts
            .lock()
            .map_err(|_| EdgeRuntimeError::SourceCapacityUnavailable)?;
        let count = counts.entry(source).or_default();
        if *count >= self.maximum {
            return Err(EdgeRuntimeError::SourceCapacityExhausted);
        }
        *count += 1;
        Ok(SourcePermit {
            owner: Arc::clone(self),
            source,
        })
    }

    fn release(&self, source: IpAddr) {
        let Ok(mut counts) = self.counts.lock() else {
            return;
        };
        if let Some(count) = counts.get_mut(&source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&source);
            }
        }
    }
}

struct SourcePermit {
    owner: Arc<SourceCapacity>,
    source: IpAddr,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        self.owner.release(self.source);
    }
}

/// Public edge startup, admission, or bounded shutdown failure.
#[derive(Debug, thiserror::Error)]
pub enum EdgeRuntimeError {
    /// Accepting a public stream failed.
    #[error("public miner listener failed")]
    Accept(#[source] io::Error),
    /// Runtime connection policy was invalid.
    #[error(transparent)]
    EdgeConfig(#[from] wcash_pool_edge::EdgeConfigError),
    /// Connection capacity was invalid.
    #[error(transparent)]
    Capacity(#[from] wcash_pool_edge::RateLimitError),
    /// Share target was invalid.
    #[error(transparent)]
    Target(#[from] wcash_pool_core::ShareTargetError),
    /// Vardiff policy was invalid.
    #[error(transparent)]
    Vardiff(#[from] wcash_pool_core::VardiffError),
    /// Monotonic service time could not be represented.
    #[error(transparent)]
    Timeline(#[from] wcash_pool_backend_client::TimelineError),
    /// Per-source capacity was zero.
    #[error("per-source miner capacity is invalid")]
    InvalidSourceCapacity,
    /// Per-source accounting mutex was poisoned.
    #[error("per-source miner capacity is unavailable")]
    SourceCapacityUnavailable,
    /// One source reached its live-session ceiling.
    #[error("per-source miner capacity is exhausted")]
    SourceCapacityExhausted,
    /// Miner sessions did not leave within the bounded drain window.
    #[error("miner sessions exceeded the graceful shutdown deadline")]
    DrainTimeout,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn source_permits_are_bounded_and_released() {
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let capacity = Arc::new(SourceCapacity::new(2).expect("capacity"));
        let first = capacity.try_acquire(source).expect("first");
        let second = capacity.try_acquire(source).expect("second");
        assert!(matches!(
            capacity.try_acquire(source),
            Err(EdgeRuntimeError::SourceCapacityExhausted)
        ));
        drop(first);
        let third = capacity.try_acquire(source).expect("released");
        drop((second, third));
        assert!(capacity.counts.lock().expect("counts").is_empty());
    }
}

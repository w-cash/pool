//! One shared, fail-closed generation authority for all miner sessions.

use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::sync::broadcast;
use wcash_pool_backend_client::{
    BackendAuthority, BackendClient, BackendConnectionBinding, DeliveredBackendEvent, JobSnapshot,
    JobStateIntegrationError, MonotonicTimeline, TimelineError,
};
use wcash_pool_core::{
    BackendGeneration, GenerationRegistry, GenerationRegistryConfig, JobId, JobRegistryError,
    MiningSession, SessionError, SubmissionContext,
};
use wcash_pool_protocol::{BackendEvent, Hex1344, Hex4, JobInvalidationReason, NonceSuffix};

const MAXIMUM_EVENT_CAPACITY: usize = 4_096;

/// A lifecycle change which every connected miner actor must observe in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobUpdate {
    /// A new exact Wolf generation may be advertised.
    Activated {
        /// Immutable proposal-validated generation.
        generation: Box<BackendGeneration>,
        /// Whether ZIP-301 miners must abandon all older work.
        clean_jobs: bool,
    },
    /// This generation is no longer locally admissible and should be forgotten.
    Retired {
        /// Exact backend generation identifier.
        job_id: JobId,
    },
    /// Global generation admission is unsafe; every miner actor must close.
    Suspended,
}

#[derive(Debug)]
struct RouterState {
    registry: GenerationRegistry,
    force_clean_jobs: bool,
    backend_authority: Option<BackendAuthority>,
    connection_binding: Option<BackendConnectionBinding>,
}

impl RouterState {
    fn update_for(
        &mut self,
        event: &BackendEvent,
        now_ms: u64,
    ) -> Result<Option<JobUpdate>, JobRouterError> {
        Ok(match event {
            BackendEvent::JobActivated { job, .. } => {
                let id = JobId::new(*job.job_id.as_bytes())?;
                let generation = self
                    .registry
                    .generation(id)
                    .ok_or(JobRouterError::MissingActivatedGeneration(id))?
                    .clone();
                let admissible = self.registry.admissible_job_ids(now_ms)?;
                if admissible.current() != Some(id) {
                    // The event was valid and remains part of the contiguous
                    // journal, but its receipt-anchored lifetime elapsed while it
                    // waited in the bounded transport queue. Never advertise it.
                    return Ok(None);
                }
                let preserves_prior_work = admissible.recent().iter().any(|prior_id| {
                    self.registry
                        .generation(*prior_id)
                        .is_some_and(|prior| prior.tips() == generation.tips())
                });
                let clean_jobs = self.force_clean_jobs || !preserves_prior_work;
                self.force_clean_jobs = false;
                Some(JobUpdate::Activated {
                    generation: Box::new(generation),
                    clean_jobs,
                })
            }
            BackendEvent::JobInvalidated {
                job_id,
                reason,
                accept_for_ms,
                ..
            } => {
                let id = JobId::new(*job_id.as_bytes())?;
                let hard_retirement =
                    !matches!(reason, JobInvalidationReason::Superseded) || *accept_for_ms == 0;
                if hard_retirement {
                    self.force_clean_jobs = true;
                }
                hard_retirement.then_some(JobUpdate::Retired { job_id: id })
            }
            BackendEvent::GenerationClosed { job_id, .. } => {
                self.force_clean_jobs = true;
                Some(JobUpdate::Retired {
                    job_id: JobId::new(*job_id.as_bytes())?,
                })
            }
            BackendEvent::ShareCommitted { .. }
            | BackendEvent::WinnerObserved { .. }
            | BackendEvent::WinnerOrphaned { .. }
            | BackendEvent::WinnerMatured { .. } => None,
        })
    }
}

/// Cloneable handle to the process-global generation registry and event fanout.
///
/// A deployment must create exactly one router for one backend journal stream.
/// Its mutex is held only for synchronous policy transitions; no network I/O or
/// Equihash validation occurs while it is locked.
#[derive(Clone, Debug)]
pub struct JobRouter {
    state: Arc<Mutex<RouterState>>,
    timeline: MonotonicTimeline,
    updates: broadcast::Sender<JobUpdate>,
}

impl JobRouter {
    /// Initializes the global authority from one backend-branded atomic snapshot.
    pub fn from_snapshot(
        snapshot: &JobSnapshot,
        registry_config: GenerationRegistryConfig,
        timeline: MonotonicTimeline,
        event_capacity: usize,
    ) -> Result<Self, JobRouterError> {
        validate_event_capacity(event_capacity)?;
        let mut registry = GenerationRegistry::new(registry_config);
        snapshot.apply_to_registry(&mut registry, timeline)?;
        let (updates, _) = broadcast::channel(event_capacity);
        Ok(Self {
            state: Arc::new(Mutex::new(RouterState {
                registry,
                force_clean_jobs: false,
                backend_authority: Some(snapshot.authority().clone()),
                connection_binding: Some(snapshot.connection_binding()),
            })),
            timeline,
            updates,
        })
    }

    /// Opens a bounded ordered lifecycle stream for one connection actor.
    ///
    /// Subscribe before querying [`Self::current_generation`] so an activation
    /// cannot be lost between snapshot and live consumption. A duplicated current
    /// activation is harmless because generation IDs and assignments are immutable.
    pub fn subscribe(&self) -> JobSubscription {
        let receiver = self.updates.subscribe();
        // Subscribe before inspecting state so a concurrent suspension is either
        // observed here or retained in the broadcast receiver (a duplicate is safe).
        let suspension_pending = self
            .state
            .lock()
            .map_or(true, |state| !state.registry.is_synchronized());
        JobSubscription {
            receiver,
            suspension_pending,
        }
    }

    /// Globally suspends generation admission and tells every miner actor to close.
    ///
    /// The registry transition is idempotent, but every invocation broadcasts a
    /// suspension so existing subscribers cannot miss a terminal backend failure.
    /// Subscribers created after the transition receive a synthetic suspension
    /// from [`Self::subscribe`].
    pub fn suspend(&self) -> Result<(), JobRouterError> {
        match self.state.lock() {
            Ok(mut state) => {
                state.registry.suspend();
                state.force_clean_jobs = true;
                // Publish while the transition lock is held so a concurrently
                // completed activation cannot be observed after this suspension.
                let _ = self.updates.send(JobUpdate::Suspended);
                Ok(())
            }
            Err(_) => {
                // Broadcast even if the mutex is poisoned: established sessions
                // must close, and future subscribers fail closed on state inspection.
                let _ = self.updates.send(JobUpdate::Suspended);
                Err(JobRouterError::Poisoned)
            }
        }
    }

    /// Suspends admission only while `binding` still owns the active router epoch.
    ///
    /// A submission actor from an older connection can finish or drop after a new
    /// snapshot recovers the router. Returning `false` prevents that stale actor
    /// from suspending work owned by the replacement connection.
    pub(crate) fn suspend_if_bound(
        &self,
        binding: &BackendConnectionBinding,
    ) -> Result<bool, JobRouterError> {
        match self.state.lock() {
            Ok(mut state) => {
                if state.connection_binding.as_ref() != Some(binding) {
                    return Ok(false);
                }
                state.registry.suspend();
                state.force_clean_jobs = true;
                let _ = self.updates.send(JobUpdate::Suspended);
                Ok(true)
            }
            Err(_) => {
                let _ = self.updates.send(JobUpdate::Suspended);
                Err(JobRouterError::Poisoned)
            }
        }
    }

    /// Applies one contiguous transport-branded live event and fans out job state.
    ///
    /// Any registry or timeline failure suspends core admission. The caller must
    /// stop the failed backend stream and call [`Self::recover_from_snapshot`] with
    /// a newly authenticated snapshot from the same expected journal.
    pub fn apply_event(
        &self,
        client: &BackendClient,
        delivered: &DeliveredBackendEvent,
    ) -> Result<(), JobRouterError> {
        let binding = client
            .connection_binding()
            .ok_or(JobRouterError::BackendConnectionMismatch)?;
        self.apply_event_inner(&binding, delivered)
    }

    fn apply_event_inner(
        &self,
        required_binding: &BackendConnectionBinding,
        delivered: &DeliveredBackendEvent,
    ) -> Result<(), JobRouterError> {
        let event = delivered.event().clone();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let _ = self.updates.send(JobUpdate::Suspended);
                return Err(JobRouterError::Poisoned);
            }
        };
        if delivered.connection_binding() != required_binding
            || state.connection_binding.as_ref() != Some(required_binding)
        {
            return Err(JobRouterError::BackendConnectionMismatch);
        }
        // Sample policy time only after acquiring the transition lock. Otherwise
        // concurrent callers can sample t1 < t2, acquire in reverse order, and
        // make the older sample look like a clock rollback.
        let now_ms = match self.timeline.now_ms() {
            Ok(now_ms) => now_ms,
            Err(error) => {
                state.registry.suspend();
                state.force_clean_jobs = true;
                let _ = self.updates.send(JobUpdate::Suspended);
                return Err(error.into());
            }
        };
        if let Err(error) =
            delivered.apply_to_registry_at(&mut state.registry, self.timeline, now_ms)
        {
            drop(state);
            let _ = self.suspend();
            return Err(error.into());
        }

        let update = match state.update_for(&event, now_ms) {
            Ok(update) => update,
            Err(error) => {
                drop(state);
                let _ = self.suspend();
                return Err(error);
            }
        };
        if let Some(update) = update {
            // No receivers is valid while the edge has no authenticated miners.
            // Publish under the transition lock to preserve ordering with suspend().
            let _ = self.updates.send(update);
        }
        drop(state);
        Ok(())
    }

    /// Restores a suspended router from a newly authenticated backend snapshot.
    ///
    /// Recovery deliberately reuses the existing [`GenerationRegistry`], preserving
    /// immutable descriptors, tombstones, local deadlines, and the last journal
    /// watermark. Replacing the router would discard that safety history and could
    /// give an old generation a fresh lease. The failed stream must be fully stopped
    /// before this method is called; the snapshot's client must enforce the same
    /// configured backend and journal identities.
    ///
    /// Existing miner subscriptions remain suspended and must close. New sessions
    /// subscribe after recovery and obtain the current generation through
    /// [`Self::current_generation`].
    pub fn recover_from_snapshot(&self, snapshot: &JobSnapshot) -> Result<(), JobRouterError> {
        let authority = snapshot.authority().clone();
        let binding = snapshot.connection_binding();
        self.recover_with(Some((authority, binding)), |registry| {
            snapshot
                .apply_to_registry(registry, self.timeline)
                .map_err(JobRouterError::from)
        })
    }

    /// Checks that a live client is the exact connection that produced this router's snapshot.
    pub(crate) fn client_binding_matches(
        &self,
        client: &BackendClient,
    ) -> Result<bool, JobRouterError> {
        let state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        Ok(state
            .connection_binding
            .as_ref()
            .is_some_and(|binding| client.is_bound_to(binding)))
    }

    /// Checks that all client events through its live cursor reached the registry.
    pub(crate) fn client_cursor_matches(
        &self,
        client: &BackendClient,
    ) -> Result<bool, JobRouterError> {
        let state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        Ok(state.registry.last_event_seq() == client.live_event_cursor())
    }

    /// Returns the current admissible generation at this process's monotonic time.
    pub fn current_generation(&self) -> Result<Option<BackendGeneration>, JobRouterError> {
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        let now_ms = self.timeline.now_ms()?;
        Ok(state.registry.current_generation(now_ms)?.cloned())
    }

    /// Returns every generation that may still begin a submission.
    pub fn admissible_job_ids(&self) -> Result<Vec<JobId>, JobRouterError> {
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        let now_ms = self.timeline.now_ms()?;
        let admissible = state.registry.admissible_job_ids(now_ms)?;
        let mut ids = Vec::with_capacity(1 + admissible.recent().len());
        if let Some(current) = admissible.current() {
            ids.push(current);
        }
        ids.extend_from_slice(admissible.recent());
        Ok(ids)
    }

    /// Validates miner-controlled submission fields and retains an admission fence.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_submission(
        &self,
        session: &MiningSession,
        claimed_login: &str,
        job_id: JobId,
        submitted_time: Hex4,
        nonce_suffix: NonceSuffix,
        solution: Box<Hex1344>,
    ) -> Result<SubmissionContext, JobRouterError> {
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        let now_ms = self.timeline.now_ms()?;
        Ok(session.prepare_submission(
            claimed_login,
            job_id,
            submitted_time,
            nonce_suffix,
            solution,
            &mut state.registry,
            now_ms,
        )?)
    }

    #[cfg(test)]
    pub(crate) fn from_acceptable_for_test(
        event_seq: u64,
        current: Option<&wcash_pool_protocol::AcceptableJob>,
        recent: &[wcash_pool_protocol::AcceptableJob],
        registry_config: GenerationRegistryConfig,
        event_capacity: usize,
    ) -> Result<Self, JobRouterError> {
        validate_event_capacity(event_capacity)?;
        let timeline = MonotonicTimeline::new();
        let mut registry = GenerationRegistry::new(registry_config);
        registry.apply_snapshot(event_seq, current, recent, 0)?;
        let (updates, _) = broadcast::channel(event_capacity);
        Ok(Self {
            state: Arc::new(Mutex::new(RouterState {
                registry,
                force_clean_jobs: false,
                backend_authority: None,
                connection_binding: None,
            })),
            timeline,
            updates,
        })
    }

    #[cfg(test)]
    pub(crate) fn apply_event_for_test(
        &self,
        event: &BackendEvent,
        anchor_ms: u64,
    ) -> Result<(), JobRouterError> {
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        state.registry.apply_event(event, anchor_ms)?;
        let update = state.update_for(event, anchor_ms)?;
        drop(state);
        if let Some(update) = update {
            let _ = self.updates.send(update);
        }
        Ok(())
    }

    #[cfg(test)]
    fn recover_for_test(
        &self,
        event_seq: u64,
        current: Option<&wcash_pool_protocol::AcceptableJob>,
        recent: &[wcash_pool_protocol::AcceptableJob],
        request_started_ms: u64,
    ) -> Result<(), JobRouterError> {
        self.recover_with(None, |registry| {
            registry
                .apply_snapshot(event_seq, current, recent, request_started_ms)
                .map_err(JobRouterError::from)
        })
    }

    fn recover_with(
        &self,
        replacement_binding: Option<(BackendAuthority, BackendConnectionBinding)>,
        apply: impl FnOnce(&mut GenerationRegistry) -> Result<(), JobRouterError>,
    ) -> Result<(), JobRouterError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let _ = self.updates.send(JobUpdate::Suspended);
                return Err(JobRouterError::Poisoned);
            }
        };
        if state.registry.is_synchronized() {
            return Err(JobRouterError::RecoveryWhileSynchronized);
        }

        if let Some((authority, _)) = replacement_binding.as_ref() {
            if state.backend_authority.as_ref() != Some(authority) {
                let _ = self.updates.send(JobUpdate::Suspended);
                return Err(JobRouterError::BackendAuthorityMismatch);
            }
        }

        state.force_clean_jobs = true;
        match apply(&mut state.registry) {
            Ok(()) => {
                if let Some((authority, binding)) = replacement_binding {
                    state.backend_authority = Some(authority);
                    state.connection_binding = Some(binding);
                }
                Ok(())
            }
            Err(error) => {
                state.registry.suspend();
                drop(state);
                let _ = self.updates.send(JobUpdate::Suspended);
                Err(error)
            }
        }
    }
}

/// One miner actor's ordered view of global lifecycle changes.
#[derive(Debug)]
pub struct JobSubscription {
    receiver: broadcast::Receiver<JobUpdate>,
    suspension_pending: bool,
}

impl JobSubscription {
    /// Waits for the next update and fails closed if this consumer lagged.
    pub async fn receive(&mut self) -> Result<JobUpdate, JobRouterError> {
        if std::mem::take(&mut self.suspension_pending) {
            return Ok(JobUpdate::Suspended);
        }
        self.receiver.recv().await.map_err(|error| match error {
            broadcast::error::RecvError::Closed => JobRouterError::UpdateStreamClosed,
            broadcast::error::RecvError::Lagged(skipped) => {
                JobRouterError::UpdateStreamLagged { skipped }
            }
        })
    }
}

/// Global routing, lifecycle, or synchronization failure.
#[derive(Debug, Error)]
pub enum JobRouterError {
    /// The bounded update ring size was invalid.
    #[error("job update capacity {actual} is outside 1..={maximum}")]
    InvalidEventCapacity {
        /// Supplied capacity.
        actual: usize,
        /// Fixed maximum.
        maximum: usize,
    },
    /// Shared state was poisoned by a panic in another task.
    #[error("global job router state is poisoned")]
    Poisoned,
    /// Recovery is only valid after global admission has been suspended.
    #[error("job router recovery requires a suspended registry")]
    RecoveryWhileSynchronized,
    /// A recovery snapshot belongs to another persistent backend or journal authority.
    #[error("job router recovery changed backend or journal authority")]
    BackendAuthorityMismatch,
    /// A stale backend connection attempted to mutate another snapshot epoch.
    #[error("backend connection does not own the active job router epoch")]
    BackendConnectionMismatch,
    /// An activation was accepted but its immutable generation was unavailable.
    #[error("activated generation {0:?} is missing from the registry")]
    MissingActivatedGeneration(JobId),
    /// This connection failed to consume the bounded event ring in time.
    #[error("job update subscriber lagged by {skipped} events")]
    UpdateStreamLagged {
        /// Number of dropped updates reported by Tokio.
        skipped: u64,
    },
    /// The global sender was dropped.
    #[error("job update stream closed")]
    UpdateStreamClosed,
    /// Backend delivery time could not be mapped safely.
    #[error(transparent)]
    Timeline(#[from] TimelineError),
    /// The branded snapshot or event violated lifecycle rules.
    #[error(transparent)]
    Integration(#[from] JobStateIntegrationError),
    /// Core generation policy rejected the operation.
    #[error(transparent)]
    Registry(#[from] JobRegistryError),
    /// Core per-session policy rejected the submission.
    #[error(transparent)]
    Session(#[from] SessionError),
}

fn validate_event_capacity(actual: usize) -> Result<(), JobRouterError> {
    if !(1..=MAXIMUM_EVENT_CAPACITY).contains(&actual) {
        return Err(JobRouterError::InvalidEventCapacity {
            actual,
            maximum: MAXIMUM_EVENT_CAPACITY,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use wcash_pool_protocol::{AcceptableJob, Hex108, Hex32, JobDescriptor, TargetLe};

    fn descriptor(id: u8, wcash_tip: u8, zcash_tip: u8) -> JobDescriptor {
        let mut header = [id; 108];
        header[..4].copy_from_slice(&[4, 0, 0, 0]);
        header[4..36].copy_from_slice(&[zcash_tip; 32]);
        header[100..104].copy_from_slice(&[1, 2, 3, id]);
        JobDescriptor {
            job_id: Hex32::new([id; 32]),
            wcash_candidate_hash_le: Hex32::new([5; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([wcash_tip; 32]),
            zcash_previous_hash_le: Hex32::new([zcash_tip; 32]),
            wcash_coinbase_txid_le: Hex32::new([6; 32]),
            zcash_coinbase_txid_le: Hex32::new([7; 32]),
            wcash_target_le: TargetLe::new([3; 32]),
            zcash_target_le: TargetLe::new([4; 32]),
            wcash_height: 10,
            zcash_height: 20,
            wcash_reward_zat: 625_000_000,
            zcash_reward_zat: 312_500_000,
            wcash_maturity_confirmations: 100,
            zcash_maturity_confirmations: 100,
            max_age_ms: 60_000,
        }
    }

    fn acceptable(id: u8) -> AcceptableJob {
        AcceptableJob {
            job: descriptor(id, id.wrapping_add(1), id.wrapping_add(2)),
            accept_for_ms: 30_000,
        }
    }

    fn router(capacity: usize) -> JobRouter {
        JobRouter::from_acceptable_for_test(
            1,
            Some(&acceptable(1)),
            &[],
            GenerationRegistryConfig::new(2, 8).expect("registry limits are valid"),
            capacity,
        )
        .expect("router is valid")
    }

    #[test]
    fn current_snapshot_is_available_without_inventing_a_lifetime() {
        let router = router(4);
        let current = router
            .current_generation()
            .expect("query succeeds")
            .expect("current generation exists");
        assert_eq!(current.id().into_bytes(), [1; 32]);
        assert_eq!(
            router.admissible_job_ids().expect("query succeeds").len(),
            1
        );
    }

    #[tokio::test]
    async fn bounded_subscriber_lag_fails_closed() {
        let router = router(1);
        let mut subscription = router.subscribe();
        router
            .updates
            .send(JobUpdate::Retired {
                job_id: JobId::new([1; 32]).expect("job id is valid"),
            })
            .expect("subscriber exists");
        router
            .updates
            .send(JobUpdate::Retired {
                job_id: JobId::new([2; 32]).expect("job id is valid"),
            })
            .expect("subscriber exists");
        assert!(matches!(
            subscription.receive().await,
            Err(JobRouterError::UpdateStreamLagged { skipped: 1 })
        ));
    }

    #[tokio::test]
    async fn suspension_reaches_existing_and_future_subscribers_and_rejects_admission() {
        let router = router(8);
        let mut first = router.subscribe();
        let mut second = router.subscribe();

        router.suspend().expect("first suspension succeeds");
        assert!(matches!(first.receive().await, Ok(JobUpdate::Suspended)));
        assert!(matches!(second.receive().await, Ok(JobUpdate::Suspended)));
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(JobRegistryError::NotSynchronized))
        ));

        router.suspend().expect("repeated suspension is idempotent");
        assert!(matches!(first.receive().await, Ok(JobUpdate::Suspended)));
        assert!(matches!(second.receive().await, Ok(JobUpdate::Suspended)));

        let mut future = router.subscribe();
        assert!(matches!(future.receive().await, Ok(JobUpdate::Suspended)));
    }

    #[test]
    fn recovery_requires_suspension_without_mutating_live_state() {
        let router = router(8);
        assert!(matches!(
            router.recover_for_test(2, Some(&acceptable(1)), &[], 1),
            Err(JobRouterError::RecoveryWhileSynchronized)
        ));
        assert_eq!(
            router
                .current_generation()
                .expect("live state remains usable")
                .expect("current generation remains installed")
                .id()
                .into_bytes(),
            [1; 32]
        );
    }

    #[tokio::test]
    async fn recovery_reuses_tombstones_and_never_renews_a_generation_deadline() {
        let router = router(8);
        let mut established = router.subscribe();
        router.suspend().expect("suspension succeeds");
        assert!(matches!(
            established.receive().await,
            Ok(JobUpdate::Suspended)
        ));

        router
            .recover_for_test(2, Some(&acceptable(1)), &[], 20_000)
            .expect("an exact later snapshot restores the suspended router");
        let post_recovery = router.subscribe();
        assert!(!post_recovery.suspension_pending);

        let id = JobId::new([1; 32]).expect("job id is valid");
        {
            let mut state = router.state.lock().expect("router state is available");
            let admission = state
                .registry
                .begin_admission(id, 29_999)
                .expect("the original deadline remains live");
            drop(admission);
            assert!(matches!(
                state.registry.begin_admission(id, 30_000),
                Err(JobRegistryError::StaleJob(job_id)) if job_id == id
            ));
        }

        router.suspend().expect("expired state can be suspended");
        assert!(matches!(
            router.recover_for_test(3, Some(&acceptable(1)), &[], 30_000),
            Err(JobRouterError::Registry(JobRegistryError::ResurrectedJob(job_id)))
                if job_id == id
        ));
        let mut after_failed_recovery = router.subscribe();
        assert!(matches!(
            after_failed_recovery.receive().await,
            Ok(JobUpdate::Suspended)
        ));
    }

    #[tokio::test]
    async fn same_tip_supersession_preserves_non_clean_activation() {
        let router = router(4);
        let mut subscription = router.subscribe();
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: Hex32::new([1; 32]),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 1_000,
                },
                1,
            )
            .expect("supersession is valid");
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(2, 2, 3),
                },
                2,
            )
            .expect("same-tip activation is valid");
        let update = subscription
            .receive()
            .await
            .expect("activation is delivered");
        assert!(matches!(
            update,
            JobUpdate::Activated {
                clean_jobs: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn expired_same_tip_supersession_forces_clean_activation() {
        let router = router(4);
        let mut subscription = router.subscribe();
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: Hex32::new([1; 32]),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 1_000,
                },
                30_001,
            )
            .expect("expired supersession is a restrictive no-op");
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(2, 2, 3),
                },
                30_002,
            )
            .expect("same-tip replacement is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Activated {
                clean_jobs: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn tip_change_forces_clean_activation() {
        let router = router(4);
        let mut subscription = router.subscribe();
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: Hex32::new([1; 32]),
                    reason: JobInvalidationReason::WcashTipChanged,
                    accept_for_ms: 0,
                },
                1,
            )
            .expect("tip invalidation is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Retired { .. })
        ));
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(2, 9, 3),
                },
                2,
            )
            .expect("changed-tip activation is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Activated {
                clean_jobs: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn age_retirement_forces_same_tip_clean_activation() {
        let router = router(4);
        let mut subscription = router.subscribe();
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: Hex32::new([1; 32]),
                    reason: JobInvalidationReason::Age,
                    accept_for_ms: 0,
                },
                1,
            )
            .expect("age retirement is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Retired { .. })
        ));
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(2, 2, 3),
                },
                2,
            )
            .expect("same-tip replacement is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Activated {
                clean_jobs: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn generation_close_forces_same_tip_clean_activation() {
        let router = router(4);
        let mut subscription = router.subscribe();
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: Hex32::new([1; 32]),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 1_000,
                },
                1,
            )
            .expect("supersession grace is valid");
        router
            .apply_event_for_test(
                &BackendEvent::GenerationClosed {
                    event_seq: 3,
                    job_id: Hex32::new([1; 32]),
                },
                2,
            )
            .expect("generation close is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Retired { .. })
        ));
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 4,
                    job: descriptor(2, 2, 3),
                },
                3,
            )
            .expect("same-tip replacement is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Activated {
                clean_jobs: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn closing_older_cached_job_forces_next_notification_clean() {
        let router = router(8);
        let mut subscription = router.subscribe();
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: Hex32::new([1; 32]),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 10_000,
                },
                1,
            )
            .expect("first generation enters grace");
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(2, 2, 3),
                },
                2,
            )
            .expect("second generation is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Activated {
                clean_jobs: false,
                ..
            })
        ));

        router
            .apply_event_for_test(
                &BackendEvent::GenerationClosed {
                    event_seq: 4,
                    job_id: Hex32::new([1; 32]),
                },
                3,
            )
            .expect("older cached generation closes");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Retired { job_id }) if job_id.into_bytes() == [1; 32]
        ));
        router
            .apply_event_for_test(
                &BackendEvent::JobInvalidated {
                    event_seq: 5,
                    job_id: Hex32::new([2; 32]),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 1_000,
                },
                4,
            )
            .expect("second generation enters grace");
        router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 6,
                    job: descriptor(3, 2, 3),
                },
                5,
            )
            .expect("third generation is valid");
        assert!(matches!(
            subscription.receive().await,
            Ok(JobUpdate::Activated {
                clean_jobs: true,
                ..
            })
        ));
    }
}

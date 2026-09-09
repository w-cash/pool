//! One shared, fail-closed generation authority for all miner sessions.

use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::sync::broadcast;
use wcash_pool_backend_client::{
    DeliveredBackendEvent, JobSnapshot, JobStateIntegrationError, MonotonicTimeline, TimelineError,
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
        JobSubscription {
            receiver: self.updates.subscribe(),
        }
    }

    /// Applies one contiguous transport-branded live event and fans out job state.
    ///
    /// Any registry or timeline failure suspends core admission. The caller must
    /// stop issuing work and rebuild from a newly authenticated backend snapshot.
    pub fn apply_event(&self, delivered: &DeliveredBackendEvent) -> Result<(), JobRouterError> {
        let event = delivered.event().clone();
        let now_ms = self.timeline.now_ms()?;
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        if let Err(error) = delivered.apply_to_registry(&mut state.registry, self.timeline) {
            drop(state);
            let _ = self.updates.send(JobUpdate::Suspended);
            return Err(error.into());
        }

        let update = state.update_for(&event, now_ms)?;
        drop(state);
        if let Some(update) = update {
            // No receivers is valid while the edge has no authenticated miners.
            let _ = self.updates.send(update);
        }
        Ok(())
    }

    /// Returns the current admissible generation at this process's monotonic time.
    pub fn current_generation(&self) -> Result<Option<BackendGeneration>, JobRouterError> {
        let now_ms = self.timeline.now_ms()?;
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
        Ok(state.registry.current_generation(now_ms)?.cloned())
    }

    /// Returns every generation that may still begin a submission.
    pub fn admissible_job_ids(&self) -> Result<Vec<JobId>, JobRouterError> {
        let now_ms = self.timeline.now_ms()?;
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
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
        let now_ms = self.timeline.now_ms()?;
        let mut state = self.state.lock().map_err(|_| JobRouterError::Poisoned)?;
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
            })),
            timeline,
            updates,
        })
    }

    #[cfg(test)]
    fn apply_event_for_test(
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
}

/// One miner actor's ordered view of global lifecycle changes.
#[derive(Debug)]
pub struct JobSubscription {
    receiver: broadcast::Receiver<JobUpdate>,
}

impl JobSubscription {
    /// Waits for the next update and fails closed if this consumer lagged.
    pub async fn receive(&mut self) -> Result<JobUpdate, JobRouterError> {
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
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([wcash_tip; 32]),
            zcash_previous_hash_le: Hex32::new([zcash_tip; 32]),
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

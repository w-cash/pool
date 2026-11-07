//! Non-consensus live miner telemetry boundary.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;
use wcash_pool_core::AuthenticatedWorker;

/// Stable categories shown to an authenticated miner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareOutcome {
    /// A new share was durably committed by the backend.
    Accepted,
    /// The submitted job was unknown or no longer admissible.
    Stale,
    /// The proof, target, or request failed share validation.
    Invalid,
    /// The proof was an idempotent replay or attribution conflict.
    Duplicate,
}

/// Synchronous, best-effort observer for operational miner telemetry.
///
/// Implementations must return promptly and must never affect consensus,
/// accounting, or the miner response. Production uses a bounded in-process
/// counter map; durable share accounting remains the PostgreSQL journal.
pub trait MinerTelemetrySink: Send + Sync {
    /// Records an authorized worker connection.
    fn worker_connected(&self, worker: &AuthenticatedWorker);

    /// Records closure of a previously authorized worker connection.
    fn worker_disconnected(&self, worker: &AuthenticatedWorker);

    /// Records one classified share outcome.
    fn share_outcome(&self, worker: &AuthenticatedWorker, outcome: ShareOutcome);

    /// Records a fixed operational category, optionally scoped to an authenticated worker.
    /// The default keeps existing library observers source-compatible. No diagnostic
    /// is authority to accept, retry, acknowledge, or account for a proof.
    fn diagnostic(&self, _worker: Option<&AuthenticatedWorker>, _diagnostic: Diagnostic) {}
}

/// Observer used by library callers that do not compose portal telemetry.
#[derive(Debug, Default)]
pub struct NoopMinerTelemetry;

impl MinerTelemetrySink for NoopMinerTelemetry {
    fn worker_connected(&self, _worker: &AuthenticatedWorker) {}

    fn worker_disconnected(&self, _worker: &AuthenticatedWorker) {}

    fn share_outcome(&self, _worker: &AuthenticatedWorker, _outcome: ShareOutcome) {}
}

macro_rules! diagnostics {
    ($(($variant:ident, $label:literal, $description:literal)),+ $(,)?) => {
        /// Fixed, non-sensitive operational categories. Counts are process-lifetime
        /// observations, not monetary records or proof-loss estimates.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(usize)]
        pub enum Diagnostic {
            $(#[doc = $description] $variant,)+
        }
        impl Diagnostic {
            /// Complete finite diagnostic vocabulary; no miner-controlled labels.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];
            /// Stable serialized counter name.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label,)+ }
            }
            /// Whether this category may be shown for its own authenticated worker.
            pub const fn account_scoped(self) -> bool {
                (self as usize) < Self::AccountObservationSkipped as usize
                    || (self as usize) >= Self::DriverPeerClosed as usize
            }
        }
    };
}

diagnostics! {
    (SubmitObserved, "submit_observed", "A decoded submit reached the connection actor."),
    (AdmissionPendingLimit, "admission_pending_limit", "The connection pending-share ceiling rejected admission."),
    (AdmissionInvalidJob, "admission_invalid_job", "The submitted job identifier was invalid."),
    (AdmissionSessionRejected, "admission_session_rejected", "Another fixed core session policy rejected admission."),
    (AdmissionRateLimited, "admission_rate_limited", "The decoded submit exceeded the unchanged request rate limit."),
    (AdmissionUnauthorized, "admission_unauthorized", "Submission arrived outside authorized session state."),
    (AdmissionLoginMismatch, "admission_login_mismatch", "The claimed login differed from the authenticated worker."),
    (AdmissionJobNotAnnounced, "admission_job_not_announced", "The job was not advertised to this session."),
    (AdmissionHeaderTimeMismatch, "admission_header_time_mismatch", "Submission changed the immutable header time."),
    (AdmissionNonceMismatch, "admission_nonce_mismatch", "The nonce suffix did not match the negotiated profile."),
    (AdmissionStale, "admission_stale", "The generation or existing recovery filter was no longer admissible."),
    (AdmissionRegistryUnavailable, "admission_registry_unavailable", "The trusted generation registry was unsynchronized or failed an invariant."),
    (AdmissionRouterFailed, "admission_router_failed", "Trusted job routing failed before backend forwarding."),
    (PreparedOrdinary, "prepared_ordinary", "Ordinary core-bound work was prepared for forwarding."),
    (RawZcashRecoveryCandidate, "raw_zcash_recovery_candidate", "The existing cheap Zcash target filter qualified recovery forwarding; Equihash is not yet validated."),
    (SubmissionAccepted, "submission_accepted", "A new verified commit passed the mandatory projection barrier."),
    (SubmissionReplay, "submission_replay", "A verified idempotent replay completed."),
    (SubmissionStale, "submission_stale", "The final typed stale-job outcome may include a local queued authority recheck."),
    (SubmissionInvalid, "submission_invalid", "The backend rejected request, proof, difficulty, or target validation."),
    (SubmissionAttributionConflict, "submission_attribution_conflict", "The backend rejected a conflicting attribution."),
    (SubmissionBackendBusy, "submission_backend_busy", "The backend reported capacity pressure."),
    (SubmissionBackendUnhealthy, "submission_backend_unhealthy", "The backend reported unhealthy authority."),
    (SubmissionRecoveryDeferred, "submission_recovery_deferred", "The final recovery outcome remained deferred."),
    (SubmissionQueueFull, "submission_queue_full", "The frontend submission queue rejected this request."),
    (SubmissionUnavailable, "submission_unavailable", "No trusted completion was returned; durable outcome may be unknown."),
    (SubmissionProjectionPending, "submission_projection_pending", "An old replay still requires durable projection confirmation."),
    (SubmissionProjectionUnavailable, "submission_projection_unavailable", "The mandatory event projection path did not complete."),
    (SubmissionJobStreamUnavailable, "submission_job_stream_unavailable", "The trusted job stream failed."),
    (SubmissionHealthDeadline, "submission_health_deadline", "The existing backend health grace expired."),
    (SubmissionAuthorityMismatch, "submission_authority_mismatch", "The live backend connection binding did not match."),
    (SubmissionTaskFailed, "submission_task_failed", "The owned submission task failed."),
    (SubmissionBackendNotLive, "submission_backend_not_live", "The backend was not in live phase."),
    (AccountObservationSkipped, "account_observation_skipped", "A process observation could not be attributed in best-effort worker telemetry without waiting or creating an entry."),
    (QueueEnqueued, "queue_enqueued", "A sealed context entered the bounded submission queue."),
    (QueueFull, "queue_full", "The process submission queue was full."),
    (QueueClosed, "queue_closed", "The process submission queue was closed."),
    (QueueWaitCancelled, "queue_wait_cancelled", "The caller cancelled after enqueue; backend processing may still complete."),
    (QueueResponseLost, "queue_response_lost", "A queued request lost its response channel; durable outcome may be unknown."),
    (BackendAttemptOrdinary, "backend_attempt_ordinary", "An ordinary backend request was attempted."),
    (BackendAttemptRecovery, "backend_attempt_recovery", "A filtered recovery backend request was attempted."),
    (BackendReceiptNew, "backend_receipt_new", "The authenticated backend returned an exactly bound new durable receipt before projection verification."),
    (BackendReceiptReplay, "backend_receipt_replay", "The authenticated backend returned an exactly bound replay receipt."),
    (BackendWecWinnerReceipt, "backend_wec_winner_receipt", "A new verified backend receipt declared a Wcash winner; this is not independent node acceptance."),
    (BackendZecWinnerReceipt, "backend_zec_winner_receipt", "A new verified backend receipt declared a Zcash winner; this is not independent node acceptance."),
    (BackendRequestTimeout, "backend_request_timeout", "The backend exchange timed out; durable outcome may be unknown."),
    (BackendTransportFailure, "backend_transport_failure", "The backend transport failed; durable outcome may be unknown."),
    (BackendValidationFailure, "backend_validation_failure", "Backend protocol, authority, or receipt validation failed."),
    (BackendRejected, "backend_rejected", "The backend returned a typed rejection."),
    (BackendRecoveryDeferred, "backend_recovery_deferred", "A backend attempt returned typed recovery deferral."),
    (ProjectionBatchVerified, "projection_batch_verified", "An exact event batch passed durable projection verification."),
    (ProjectionLag, "projection_lag", "The exact batch cursor was not yet durably projected."),
    (ProjectionStorageUnavailable, "projection_storage_unavailable", "A narrowly classified transient projection store error occurred."),
    (ProjectionAttemptTimeout, "projection_attempt_timeout", "One bounded projection attempt timed out."),
    (ProjectionAuthorityMismatch, "projection_authority_mismatch", "Projection authority did not match."),
    (ProjectionInvalidBatch, "projection_invalid_batch", "The mandatory projection batch was malformed."),
    (ProjectionEventConflict, "projection_event_conflict", "Durable projection bytes conflicted with the exact batch."),
    (ProjectionStorageRejected, "projection_storage_rejected", "An unclassified projection storage failure occurred."),
    (ProjectionRetry, "projection_retry", "A retryable projection verification attempt failed."),
    (ProjectionPaused, "projection_paused", "A projection batch entered bounded admission-pause recovery."),
    (ProjectionRecovered, "projection_recovered", "A previously paused projection batch was verified."),
    (ProjectionDeadline, "projection_deadline", "The fixed projection recovery deadline expired."),
    (ProjectionRejected, "projection_rejected", "A non-retryable projection verification failed."),
    (RecoveryRetryScheduled, "recovery_retry_scheduled", "An existing filtered candidate was scheduled for bounded retry."),
    (RecoveryRetryExpired, "recovery_retry_expired", "The original candidate attempt deadline expired."),
    (RecoveryQueueFull, "recovery_queue_full", "The bounded deferred-candidate set was full."),
    (RecoveryRequalificationStale, "recovery_requalification_stale", "A queued candidate failed the unchanged authority or lifetime recheck."),
    (HealthUnhealthy, "health_unhealthy", "An authenticated health sample reported unhealthy state."),
    (HealthResumed, "health_resumed", "The actor resumed after a fresh healthy barrier."),
    (DriverPeerClosed, "driver_peer_closed", "The peer closed the connection normally."),
    (DriverLocalShutdown, "driver_local_shutdown", "The owner requested local shutdown."),
    (DriverActorClosed, "driver_actor_closed", "The actor completed a policy-directed closure."),
    (DriverIdleTimeout, "driver_idle_timeout", "The absolute idle deadline elapsed."),
    (DriverFrameTimeout, "driver_frame_timeout", "The partial-frame deadline elapsed."),
    (DriverWriteTimeout, "driver_write_timeout", "The write deadline elapsed."),
    (DriverAuthorizationTimeout, "driver_authorization_timeout", "The authorization deadline elapsed."),
    (DriverRevalidationTimeout, "driver_revalidation_timeout", "The revalidation deadline elapsed."),
    (DriverRevalidationUnavailable, "driver_revalidation_unavailable", "The authorization revalidation service was unavailable."),
    (DriverSubmissionTimeout, "driver_submission_timeout", "An admitted submission exceeded the driver deadline; durable outcome may be unknown."),
    (DriverReadFailure, "driver_read_failure", "Socket reading failed."),
    (DriverWriteFailure, "driver_write_failure", "Socket writing failed."),
    (DriverProtocolFailure, "driver_protocol_failure", "Strict framing or protocol validation failed."),
    (DriverActorFailure, "driver_actor_failure", "The actor failed closed."),
    (DriverJobStreamFailure, "driver_job_stream_failure", "The connection job subscription failed or lagged."),
    (DriverOtherFailure, "driver_other_failure", "Another fixed driver invariant failed."),
}

/// Shared fixed-size counters. They never retain proof bytes, credentials,
/// user identifiers, IP addresses, error strings, or dynamically named labels.
#[derive(Debug)]
pub struct OperationalCounters {
    values: [AtomicU64; Diagnostic::ALL.len()],
    instance_id: Uuid,
    started_at_unix: Option<u64>,
    started: Instant,
}

impl Default for OperationalCounters {
    fn default() -> Self {
        Self {
            values: std::array::from_fn(|_| AtomicU64::new(0)),
            instance_id: Uuid::new_v4(),
            started_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            started: Instant::now(),
        }
    }
}

impl OperationalCounters {
    /// Adds one observation without overflow, allocation, locks, or an await.
    pub fn record(&self, diagnostic: Diagnostic) {
        let _ = self.values[diagnostic as usize].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(1)),
        );
    }

    /// Reads one category; concurrent snapshots are best effort, not transactional.
    pub fn count(&self, diagnostic: Diagnostic) -> u64 {
        self.values[diagnostic as usize].load(Ordering::Relaxed)
    }

    /// Returns the finite, stable counter vocabulary and cumulative values.
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        Diagnostic::ALL
            .iter()
            .map(|&d| (d.as_str(), self.count(d)))
            .collect()
    }

    /// Distinguishes process-counter resets without identifying a miner.
    pub const fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    /// Best-effort wall time of this process-counter instance's creation.
    pub const fn started_at_unix(&self) -> Option<u64> {
        self.started_at_unix
    }

    /// Monotonic age of the process-counter instance in seconds.
    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn diagnostic_vocabulary_is_fixed_unique_and_saturating() {
        let counters = OperationalCounters::default();
        let mut labels = std::collections::HashSet::new();
        for &diagnostic in Diagnostic::ALL {
            assert!(labels.insert(diagnostic.as_str()));
            counters.record(diagnostic);
            assert_eq!(counters.count(diagnostic), 1);
        }
        counters.values[Diagnostic::SubmissionUnavailable as usize]
            .store(u64::MAX, Ordering::Relaxed);
        counters.record(Diagnostic::SubmissionUnavailable);
        assert_eq!(counters.count(Diagnostic::SubmissionUnavailable), u64::MAX);
        assert_eq!(counters.snapshot().len(), Diagnostic::ALL.len());
        assert!(!Diagnostic::BackendReceiptNew.account_scoped());
        assert!(Diagnostic::SubmissionUnavailable.account_scoped());
        assert!(Diagnostic::DriverReadFailure.account_scoped());
    }
}

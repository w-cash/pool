//! Miner-session authorization, job assignment, and submission preparation.
//!
//! Initial Z15 support deliberately implements one authenticated worker per
//! connection. A second worker identity requires a second connection.

use std::{collections::VecDeque, fmt};

use thiserror::Error;
use uuid::Uuid;
use wcash_pool_protocol::{
    join_nonce, CanonicalUuid, Hex1344, Hex32, Hex4, NoncePrefix, NonceSuffix, TargetLe,
    WorkerIdentity,
};

use crate::{
    GenerationAdmission, GenerationRegistry, JobAssignment, JobAssignmentError, JobId,
    JobRegistryError, NoncePrefixAllocator, NoncePrefixError,
};

/// Stable account and worker identity returned by trusted authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedWorker {
    account_id: Uuid,
    worker_id: Uuid,
    canonical_login: String,
}

impl fmt::Debug for AuthenticatedWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedWorker")
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedWorker {
    /// Creates one canonical identity which cannot be switched within a session.
    pub fn new(
        account_id: Uuid,
        worker_id: Uuid,
        canonical_login: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let canonical_login = canonical_login.into();
        if account_id.is_nil() || worker_id.is_nil() {
            return Err(SessionError::NilIdentity);
        }
        if canonical_login.is_empty()
            || canonical_login.len() > 128
            || !canonical_login.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(SessionError::InvalidCanonicalLogin);
        }
        Ok(Self {
            account_id,
            worker_id,
            canonical_login,
        })
    }

    /// Returns the stable pool account identifier.
    pub const fn account_id(&self) -> Uuid {
        self.account_id
    }

    /// Returns the stable worker identifier.
    pub const fn worker_id(&self) -> Uuid {
        self.worker_id
    }

    /// Returns the exact canonical login miners must repeat on submissions.
    pub fn canonical_login(&self) -> &str {
        &self.canonical_login
    }

    fn backend_identity(&self) -> WorkerIdentity {
        WorkerIdentity {
            account_id: CanonicalUuid::new(self.account_id),
            worker_id: CanonicalUuid::new(self.worker_id),
            label: self.canonical_login.clone(),
        }
    }
}

/// Externally observable session phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Transport is connected but has not negotiated a nonce profile.
    Connected,
    /// Subscription succeeded; authorization is the only valid next step.
    Subscribed,
    /// Stable account and worker identity is bound to the session.
    Authorized,
    /// Terminal state; no request may reactivate this session.
    Closed,
}

/// One ordered miner session.
pub struct MiningSession {
    id: Uuid,
    state: SessionState,
    nonce_prefix: Option<NoncePrefix>,
    worker: Option<AuthenticatedWorker>,
    announced_jobs: VecDeque<JobAssignment>,
    maximum_announced_jobs: usize,
}

impl fmt::Debug for MiningSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiningSession")
            .field("id", &self.id)
            .field("state", &self.state)
            .field(
                "nonce_profile",
                &self.nonce_prefix.as_ref().map(NoncePrefix::profile),
            )
            .field("worker", &self.worker.as_ref().map(|_| "[REDACTED]"))
            .field("announced_jobs", &self.announced_jobs.len())
            .field("maximum_announced_jobs", &self.maximum_announced_jobs)
            .finish()
    }
}

impl MiningSession {
    /// Creates a connected session with bounded advertised-job history.
    pub fn new(id: Uuid, maximum_announced_jobs: usize) -> Result<Self, SessionError> {
        if id.is_nil() {
            return Err(SessionError::NilSessionId);
        }
        if maximum_announced_jobs == 0 {
            return Err(SessionError::InvalidAnnouncedJobLimit);
        }
        Ok(Self {
            id,
            state: SessionState::Connected,
            nonce_prefix: None,
            worker: None,
            announced_jobs: VecDeque::with_capacity(maximum_announced_jobs),
            maximum_announced_jobs,
        })
    }

    /// Returns the stable transport-session identifier.
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the current ordering state.
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Allocates the session's unique nonce prefix.
    pub fn subscribe(
        &mut self,
        allocator: &NoncePrefixAllocator,
    ) -> Result<NoncePrefix, SessionError> {
        self.require(SessionState::Connected)?;
        let prefix = allocator.allocate()?;
        self.nonce_prefix = Some(prefix.clone());
        self.state = SessionState::Subscribed;
        Ok(prefix)
    }

    /// Binds a successful authorization result to this session.
    ///
    /// An exact retry is idempotent. Replacing the account or worker fails closed.
    pub fn complete_authorization(
        &mut self,
        worker: AuthenticatedWorker,
    ) -> Result<(), SessionError> {
        match self.state {
            SessionState::Subscribed => {
                self.worker = Some(worker);
                self.state = SessionState::Authorized;
                Ok(())
            }
            SessionState::Authorized if self.worker.as_ref() == Some(&worker) => Ok(()),
            SessionState::Authorized => Err(SessionError::IdentitySwitch),
            actual => Err(SessionError::UnexpectedState {
                required: SessionState::Subscribed,
                actual,
            }),
        }
    }

    /// Terminates a failed authorization so a connection cannot change identity.
    pub fn reject_authorization(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Subscribed)?;
        self.close();
        Ok(())
    }

    /// Records an exact assignment immediately before writing its notification.
    ///
    /// At capacity this fails without evicting still-valid work. The runtime must
    /// remove only assignments made non-admitting by authoritative backend state.
    pub fn announce_job(&mut self, assignment: JobAssignment) -> Result<(), SessionError> {
        self.require(SessionState::Authorized)?;
        if let Some(existing) = self
            .announced_jobs
            .iter()
            .find(|existing| existing.generation_id() == assignment.generation_id())
        {
            return if existing == &assignment {
                Ok(())
            } else {
                Err(SessionError::AnnouncedJobConflict(
                    assignment.generation_id(),
                ))
            };
        }
        if self.announced_jobs.len() == self.maximum_announced_jobs {
            return Err(SessionError::AnnouncedJobCapacity {
                maximum: self.maximum_announced_jobs,
            });
        }
        self.announced_jobs.push_front(assignment);
        Ok(())
    }

    /// Removes one assignment after backend invalidation or closure.
    pub fn remove_announced_job(&mut self, id: JobId) -> bool {
        let original = self.announced_jobs.len();
        self.announced_jobs
            .retain(|assignment| assignment.generation_id() != id);
        self.announced_jobs.len() != original
    }

    /// Closes a session after a prepared notification could not be written.
    pub fn notification_write_failed(&mut self) {
        self.close();
    }

    /// Validates miner-controlled fields and retains a backend admission fence.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_submission(
        &self,
        claimed_login: &str,
        job_id: JobId,
        submitted_time: Hex4,
        nonce_suffix: NonceSuffix,
        solution: Box<Hex1344>,
        registry: &mut GenerationRegistry,
        now_ms: u64,
    ) -> Result<SubmissionContext, SessionError> {
        self.require(SessionState::Authorized)?;
        let worker = self.worker.as_ref().ok_or(SessionError::MissingIdentity)?;
        let prefix = self
            .nonce_prefix
            .as_ref()
            .ok_or(SessionError::MissingNoncePrefix)?;
        if claimed_login != worker.canonical_login() {
            return Err(SessionError::LoginMismatch);
        }
        let assignment = self
            .announced_jobs
            .iter()
            .find(|assignment| assignment.generation_id() == job_id)
            .ok_or(SessionError::JobNotAnnounced(job_id))?;

        let admission = registry.begin_admission(job_id, now_ms)?;
        JobAssignment::new(admission.generation(), assignment.target_binding())
            .map_err(|_| SessionError::RegistryAssignmentMismatch(job_id))?;
        if admission.generation().header_time() != submitted_time {
            return Err(SessionError::HeaderTimeMismatch(job_id));
        }
        let nonce =
            join_nonce(prefix, &nonce_suffix).map_err(|_| SessionError::NonceProfileMismatch)?;

        Ok(SubmissionContext {
            session_id: self.id,
            identity: worker.backend_identity(),
            target_le: assignment.target_binding().target().to_backend(),
            time: submitted_time,
            nonce,
            solution,
            admission,
        })
    }

    /// Closes the session and clears all authorization and job reachability.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        self.worker = None;
        self.nonce_prefix = None;
        self.announced_jobs.clear();
    }

    fn require(&self, required: SessionState) -> Result<(), SessionError> {
        if self.state == required {
            Ok(())
        } else {
            Err(SessionError::UnexpectedState {
                required,
                actual: self.state,
            })
        }
    }
}

/// Validated immutable fields retained for one backend submission.
///
/// This value is deliberately non-cloneable. Keep it alive until the backend
/// resolves the submission so its generation admission guard cannot retire.
pub struct SubmissionContext {
    session_id: Uuid,
    identity: WorkerIdentity,
    target_le: TargetLe,
    time: Hex4,
    nonce: Hex32,
    solution: Box<Hex1344>,
    admission: GenerationAdmission,
}

impl fmt::Debug for SubmissionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmissionContext")
            .field("session_id", &self.session_id)
            .field("job_id", &self.admission.job_id())
            .field("identity", &"[REDACTED]")
            .field("target_le", &self.target_le)
            .field("time", &self.time)
            .field("nonce", &"[REDACTED]")
            .field("solution", &"[REDACTED 1344 bytes]")
            .finish()
    }
}

impl SubmissionContext {
    /// Returns the source transport session.
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Returns the exact retained backend generation.
    pub fn generation(&self) -> &crate::BackendGeneration {
        self.admission.generation()
    }

    /// Returns the exact backend job identifier.
    pub fn job_id(&self) -> Hex32 {
        self.admission.job_id().to_protocol()
    }

    /// Returns trusted attribution resolved during authorization.
    pub const fn identity(&self) -> &WorkerIdentity {
        &self.identity
    }

    /// Returns the exact session target in backend little-endian order.
    pub const fn target_le(&self) -> &TargetLe {
        &self.target_le
    }

    /// Returns the exact raw header time verified against the generation.
    pub const fn time(&self) -> &Hex4 {
        &self.time
    }

    /// Returns the full reconstructed 32-byte header nonce.
    pub const fn nonce(&self) -> &Hex32 {
        &self.nonce
    }

    /// Returns the raw 1,344-byte Equihash solution.
    pub const fn solution(&self) -> &Hex1344 {
        &self.solution
    }
}

/// Miner-session policy failure.
#[derive(Debug, Error, PartialEq)]
pub enum SessionError {
    /// Session ID must be stable and non-zero.
    #[error("session identifier must be non-nil")]
    NilSessionId,
    /// Account and worker identifiers must both be stable and non-zero.
    #[error("account and worker identifiers must be non-nil")]
    NilIdentity,
    /// Login is empty, too long, or contains unsupported bytes.
    #[error("canonical login must be 1..=128 safe ASCII bytes")]
    InvalidCanonicalLogin,
    /// At least one announced job must be retained.
    #[error("announced-job history limit must be non-zero")]
    InvalidAnnouncedJobLimit,
    /// A request arrived outside its permitted ordering phase.
    #[error("request requires {required:?} state, found {actual:?}")]
    UnexpectedState {
        /// Required state.
        required: SessionState,
        /// Actual state.
        actual: SessionState,
    },
    /// An authorized session attempted to change account or worker identity.
    #[error("authenticated identity cannot change within a session")]
    IdentitySwitch,
    /// Internal session invariant lacks an authenticated identity.
    #[error("authorized session is missing its identity")]
    MissingIdentity,
    /// Internal session invariant lacks an allocated nonce prefix.
    #[error("subscribed session is missing its nonce prefix")]
    MissingNoncePrefix,
    /// Submission login does not exactly match trusted authorization.
    #[error("submission login does not match the authenticated identity")]
    LoginMismatch,
    /// Miner submitted work for a job never sent on this session.
    #[error("job {0:?} was not announced on this session")]
    JobNotAnnounced(JobId),
    /// The same opaque job ID was advertised with conflicting session policy.
    #[error("announced job {0:?} conflicts with its previous assignment")]
    AnnouncedJobConflict(JobId),
    /// The bounded session cannot forget a still-valid advertised assignment.
    #[error("announced-job capacity {maximum} was reached")]
    AnnouncedJobCapacity {
        /// Configured maximum.
        maximum: usize,
    },
    /// Session assignment does not match the admitted backend generation.
    #[error("session assignment for {0:?} does not match the backend generation")]
    RegistryAssignmentMismatch(JobId),
    /// Miner changed the immutable raw header time.
    #[error("submitted header time does not match generation {0:?}")]
    HeaderTimeMismatch(JobId),
    /// Miner suffix and server prefix use different negotiated widths.
    #[error("submitted nonce suffix does not match the session nonce profile")]
    NonceProfileMismatch,
    /// Nonce namespace allocation failed.
    #[error(transparent)]
    Nonce(#[from] NoncePrefixError),
    /// Global generation admission failed.
    #[error(transparent)]
    Registry(#[from] JobRegistryError),
    /// Session target cannot be bound to the backend generation.
    #[error(transparent)]
    Assignment(#[from] JobAssignmentError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        BackendGeneration, GenerationRegistryConfig, NonceNamespaceLease, NonceProfile,
        ShareTarget, TargetBinding, TargetBounds,
    };
    use wcash_pool_protocol::{AcceptableJob, Hex108, Hex28, TargetLe};

    fn descriptor(id: u8) -> wcash_pool_protocol::JobDescriptor {
        let mut header = [id; 108];
        header[..4].copy_from_slice(&[4, 0, 0, 0]);
        header[4..36].copy_from_slice(&[id.wrapping_add(1); 32]);
        header[100..104].copy_from_slice(&[1, 2, 3, id]);
        wcash_pool_protocol::JobDescriptor {
            job_id: Hex32::new([id; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([id.wrapping_add(2); 32]),
            zcash_previous_hash_le: Hex32::new([id.wrapping_add(1); 32]),
            wcash_target_le: TargetLe::new([id.wrapping_add(3); 32]),
            zcash_target_le: TargetLe::new([id.wrapping_add(4); 32]),
            wcash_height: u32::from(id) + 1,
            zcash_height: u32::from(id) + 2,
            max_age_ms: 10_000,
        }
    }

    fn worker(id: u128, login: &str) -> AuthenticatedWorker {
        AuthenticatedWorker::new(Uuid::from_u128(id), Uuid::from_u128(id + 100), login)
            .expect("fixture identity is valid")
    }

    fn allocator(profile: NonceProfile, namespace: u8) -> NoncePrefixAllocator {
        let lease = NonceNamespaceLease::new(namespace).expect("fixture lease is valid");
        NoncePrefixAllocator::new(profile, lease)
    }

    fn generation(id: u8) -> BackendGeneration {
        BackendGeneration::from_descriptor(descriptor(id)).expect("fixture descriptor is valid")
    }

    fn assignment(generation: &BackendGeneration, revision: u64, easiest: bool) -> JobAssignment {
        let bounds = TargetBounds::new(
            generation.wcash_network_target(),
            generation.zcash_network_target(),
            ShareTarget::MAX,
        )
        .expect("operator limit includes network targets");
        let target = if easiest {
            ShareTarget::MAX
        } else {
            bounds.hardest_allowed()
        };
        JobAssignment::new(
            generation,
            TargetBinding::new(revision, target, bounds).expect("target is bounded"),
        )
        .expect("assignment matches generation")
    }

    fn live_registry(id: u8) -> GenerationRegistry {
        let mut registry = GenerationRegistry::new(
            GenerationRegistryConfig::new(2, 8).expect("fixture limits are valid"),
        );
        registry
            .apply_snapshot(
                1,
                Some(&AcceptableJob {
                    job: descriptor(id),
                    accept_for_ms: 9_000,
                }),
                &[],
                0,
            )
            .expect("fixture snapshot is valid");
        registry
    }

    fn authorized_session(
        id: u128,
        profile: NonceProfile,
        namespace: u8,
        login: &str,
        capacity: usize,
    ) -> MiningSession {
        let mut session =
            MiningSession::new(Uuid::from_u128(id), capacity).expect("session is valid");
        session
            .subscribe(&allocator(profile, namespace))
            .expect("prefix allocation succeeds");
        session
            .complete_authorization(worker(id + 10, login))
            .expect("authorization succeeds");
        session
    }

    #[test]
    fn ordering_and_identity_binding_fail_closed() {
        let mut session = MiningSession::new(Uuid::from_u128(1), 2).expect("session is valid");
        let generation = generation(1);
        assert!(matches!(
            session.announce_job(assignment(&generation, 1, false)),
            Err(SessionError::UnexpectedState {
                required: SessionState::Authorized,
                actual: SessionState::Connected
            })
        ));
        session
            .subscribe(&allocator(NonceProfile::FourByte, 1))
            .expect("subscription succeeds");
        let original = worker(2, "account.worker");
        session
            .complete_authorization(original.clone())
            .expect("authorization succeeds");
        session
            .complete_authorization(original)
            .expect("exact retry is idempotent");
        assert_eq!(
            session.complete_authorization(worker(3, "other.worker")),
            Err(SessionError::IdentitySwitch)
        );
    }

    #[test]
    fn announcement_capacity_never_evicts_valid_work() {
        let mut session = authorized_session(1, NonceProfile::FourByte, 1, "account.worker", 1);
        let first = generation(1);
        let second = generation(2);
        session
            .announce_job(assignment(&first, 1, false))
            .expect("first assignment fits");
        assert_eq!(
            session.announce_job(assignment(&second, 1, false)),
            Err(SessionError::AnnouncedJobCapacity { maximum: 1 })
        );
        assert!(!session.remove_announced_job(second.id()));
        assert!(session.remove_announced_job(first.id()));
        session
            .announce_job(assignment(&second, 1, false))
            .expect("explicit retirement frees capacity");
    }

    #[test]
    fn canonical_submission_binds_time_nonce_identity_target_and_guard() {
        let generation = generation(1);
        let assigned = assignment(&generation, 7, false);
        let expected_target = assigned.target_binding().target().to_backend();
        let mut session = authorized_session(1, NonceProfile::FourByte, 7, "account.worker", 2);
        session
            .announce_job(assigned)
            .expect("assignment is announced");
        let mut registry = live_registry(1);
        let context = session
            .prepare_submission(
                "account.worker",
                generation.id(),
                generation.header_time(),
                NonceSuffix::TwentyEight(Hex28::new([0xa5; 28])),
                Box::new(Hex1344::new([0x5a; 1_344])),
                &mut registry,
                1,
            )
            .expect("valid submission is prepared");

        assert_eq!(context.job_id(), generation.id().to_protocol());
        assert_eq!(context.identity().label, "account.worker");
        assert_eq!(context.target_le(), &expected_target);
        assert_eq!(context.time(), &generation.header_time());
        assert_eq!(&context.nonce().as_bytes()[..4], &[7, 0, 0, 0]);
        assert_eq!(&context.nonce().as_bytes()[4..], &[0xa5; 28]);
        assert_eq!(context.solution().as_bytes(), &[0x5a; 1_344]);
        assert_eq!(registry.in_flight(generation.id()), Some(1));
        drop(context);
        assert_eq!(registry.in_flight(generation.id()), Some(0));
    }

    #[test]
    fn wrong_time_profile_and_login_are_rejected_without_leaking_a_guard() {
        let generation = generation(1);
        let mut session = authorized_session(1, NonceProfile::FourByte, 1, "account.worker", 2);
        session
            .announce_job(assignment(&generation, 1, false))
            .expect("assignment is announced");
        let mut registry = live_registry(1);

        let result = session.prepare_submission(
            "account.worker",
            generation.id(),
            Hex4::new([9; 4]),
            NonceSuffix::TwentyEight(Hex28::new([0; 28])),
            Box::new(Hex1344::new([0; 1_344])),
            &mut registry,
            1,
        );
        assert!(matches!(result, Err(SessionError::HeaderTimeMismatch(_))));
        assert_eq!(registry.in_flight(generation.id()), Some(0));

        let result = session.prepare_submission(
            "account.worker",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyFour(wcash_pool_protocol::Hex24::new([0; 24])),
            Box::new(Hex1344::new([0; 1_344])),
            &mut registry,
            2,
        );
        assert!(matches!(result, Err(SessionError::NonceProfileMismatch)));
        assert_eq!(registry.in_flight(generation.id()), Some(0));

        let result = session.prepare_submission(
            "attacker.worker",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([0; 28])),
            Box::new(Hex1344::new([0; 1_344])),
            &mut registry,
            3,
        );
        assert!(matches!(result, Err(SessionError::LoginMismatch)));
        assert_eq!(registry.in_flight(generation.id()), Some(0));
    }

    #[test]
    fn two_workers_bind_different_targets_to_one_backend_generation() {
        let generation = generation(1);
        let first_assignment = assignment(&generation, 1, false);
        let second_assignment = assignment(&generation, 2, true);
        let mut first = authorized_session(1, NonceProfile::FourByte, 1, "first.rig", 2);
        let mut second = authorized_session(2, NonceProfile::FourByte, 2, "second.rig", 2);
        first
            .announce_job(first_assignment.clone())
            .expect("first assignment is announced");
        second
            .announce_job(second_assignment.clone())
            .expect("second assignment is announced");
        assert_ne!(
            first_assignment.target_binding(),
            second_assignment.target_binding()
        );
        assert_eq!(
            first_assignment.generation_id(),
            second_assignment.generation_id()
        );
    }

    #[test]
    fn close_is_terminal_and_clears_job_reachability() {
        let mut session = authorized_session(1, NonceProfile::EightByte, 1, "account.worker", 2);
        let generation = generation(1);
        session
            .announce_job(assignment(&generation, 1, false))
            .expect("assignment is announced");
        session.close();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(matches!(
            session.subscribe(&allocator(NonceProfile::EightByte, 2)),
            Err(SessionError::UnexpectedState {
                required: SessionState::Connected,
                actual: SessionState::Closed
            })
        ));
    }
}

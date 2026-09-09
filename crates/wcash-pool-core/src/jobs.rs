//! Backend-authored generations, conservative lifetimes, and admission fences.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use thiserror::Error;
use wcash_pool_protocol::{
    AcceptableJob, BackendEvent, Hex32, Hex4, JobDescriptor, JobInvalidationReason,
};

use crate::{ShareTarget, TargetBinding};

/// Opaque non-zero generation identifier assigned by Wolf.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId([u8; 32]);

impl JobId {
    /// Validates an opaque generation identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, JobRegistryError> {
        if bytes == [0; 32] {
            return Err(JobRegistryError::ZeroJobId);
        }
        Ok(Self(bytes))
    }

    /// Returns the identifier as a protocol value.
    pub const fn to_protocol(self) -> Hex32 {
        Hex32::new(self.0)
    }

    /// Returns the identifier bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Exact child and parent predecessors used by a merged-mining generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TipIdentity {
    wcash_previous_hash_le: [u8; 32],
    zcash_previous_hash_le: [u8; 32],
}

impl TipIdentity {
    /// Creates an identity from consensus/raw little-endian predecessor hashes.
    pub const fn new(wcash_previous_hash_le: [u8; 32], zcash_previous_hash_le: [u8; 32]) -> Self {
        Self {
            wcash_previous_hash_le,
            zcash_previous_hash_le,
        }
    }

    /// Returns the Wcash predecessor in consensus/raw little-endian order.
    pub const fn wcash_previous_hash_le(self) -> [u8; 32] {
        self.wcash_previous_hash_le
    }

    /// Returns the Zcash predecessor in consensus/raw little-endian order.
    pub const fn zcash_previous_hash_le(self) -> [u8; 32] {
        self.zcash_previous_hash_le
    }
}

/// One exact Wolf-authored generation, independent of miner share difficulty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendGeneration {
    descriptor: JobDescriptor,
    id: JobId,
    tips: TipIdentity,
    wcash_network_target: ShareTarget,
    zcash_network_target: ShareTarget,
}

impl BackendGeneration {
    /// Validates and imports a descriptor without changing consensus byte order.
    pub fn from_descriptor(descriptor: JobDescriptor) -> Result<Self, JobRegistryError> {
        descriptor
            .validate()
            .map_err(|_| JobRegistryError::InvalidDescriptor)?;
        let id = JobId::new(*descriptor.job_id.as_bytes())?;
        let tips = TipIdentity::new(
            *descriptor.wcash_previous_hash_le.as_bytes(),
            *descriptor.zcash_previous_hash_le.as_bytes(),
        );
        let wcash_network_target = ShareTarget::from_backend(&descriptor.wcash_target_le)
            .map_err(|_| JobRegistryError::InvalidDescriptor)?;
        let zcash_network_target = ShareTarget::from_backend(&descriptor.zcash_target_le)
            .map_err(|_| JobRegistryError::InvalidDescriptor)?;
        Ok(Self {
            descriptor,
            id,
            tips,
            wcash_network_target,
            zcash_network_target,
        })
    }

    /// Returns the backend generation identifier.
    pub const fn id(&self) -> JobId {
        self.id
    }

    /// Returns the exact predecessor identity.
    pub const fn tips(&self) -> TipIdentity {
        self.tips
    }

    /// Returns the validated descriptor, including header input and heights.
    pub const fn descriptor(&self) -> &JobDescriptor {
        &self.descriptor
    }

    /// Returns the exact raw four-byte header time sent to miners.
    pub fn header_time(&self) -> Hex4 {
        let mut time = [0; 4];
        time.copy_from_slice(&self.descriptor.header_input.as_bytes()[100..104]);
        Hex4::new(time)
    }

    /// Returns the Wcash network target in canonical numeric order.
    pub const fn wcash_network_target(&self) -> ShareTarget {
        self.wcash_network_target
    }

    /// Returns the Zcash network target in canonical numeric order.
    pub const fn zcash_network_target(&self) -> ShareTarget {
        self.zcash_network_target
    }

    /// Returns Wolf's maximum generation lifetime.
    pub const fn maximum_age_ms(&self) -> u32 {
        self.descriptor.max_age_ms
    }
}

impl TryFrom<JobDescriptor> for BackendGeneration {
    type Error = JobRegistryError;

    fn try_from(value: JobDescriptor) -> Result<Self, Self::Error> {
        Self::from_descriptor(value)
    }
}

impl TryFrom<&JobDescriptor> for BackendGeneration {
    type Error = JobRegistryError;

    fn try_from(value: &JobDescriptor) -> Result<Self, Self::Error> {
        Self::from_descriptor(value.clone())
    }
}

/// Per-session target assignment for one backend generation.
///
/// Different sessions may bind different vardiff targets to the same generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobAssignment {
    generation_id: JobId,
    target: TargetBinding,
}

impl JobAssignment {
    /// Binds a target after checking its network limits match the generation.
    pub fn new(
        generation: &BackendGeneration,
        target: TargetBinding,
    ) -> Result<Self, JobAssignmentError> {
        let bounds = target.bounds();
        if bounds.wcash_network() != generation.wcash_network_target()
            || bounds.zcash_network() != generation.zcash_network_target()
        {
            return Err(JobAssignmentError::NetworkTargetMismatch(generation.id()));
        }
        Ok(Self {
            generation_id: generation.id(),
            target,
        })
    }

    /// Returns the referenced backend generation.
    pub const fn generation_id(&self) -> JobId {
        self.generation_id
    }

    /// Returns the exact target and vardiff revision sent to this session.
    pub const fn target_binding(&self) -> TargetBinding {
        self.target
    }
}

/// Invalid relationship between a generation and a session target.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobAssignmentError {
    /// The binding was built from different Wcash or Zcash network targets.
    #[error("target binding does not match backend generation {0:?}")]
    NetworkTargetMismatch(JobId),
}

/// Exact current/recent generation roles which may still admit new shares.
///
/// The current job is listed separately; recent IDs preserve Wolf's authoritative
/// ordering. A runtime can reconcile each session's announced assignments against
/// this snapshot without guessing which bounded history entries remain valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissibleJobIds {
    current: Option<JobId>,
    recent: Vec<JobId>,
}

impl AdmissibleJobIds {
    /// Returns the current generation, if mining is active.
    pub const fn current(&self) -> Option<JobId> {
        self.current
    }

    /// Returns still-admissible prior generations in authoritative order.
    pub fn recent(&self) -> &[JobId] {
        &self.recent
    }
}

/// Bounded authoritative generation-registry configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationRegistryConfig {
    maximum_recent: usize,
    maximum_generations: usize,
}

impl GenerationRegistryConfig {
    /// Creates resource limits. All job lifetimes still come from Wolf.
    pub fn new(
        maximum_recent: usize,
        maximum_generations: usize,
    ) -> Result<Self, JobRegistryError> {
        if maximum_recent == 0 || maximum_generations <= maximum_recent {
            return Err(JobRegistryError::InvalidLimits);
        }
        Ok(Self {
            maximum_recent,
            maximum_generations,
        })
    }

    /// Returns the maximum simultaneous grace-period jobs.
    pub const fn maximum_recent(self) -> usize {
        self.maximum_recent
    }

    /// Returns the maximum retained generation records.
    ///
    /// This bound includes lightweight terminal tombstones. Exhaustion fails closed
    /// rather than forgetting a previously used backend generation identifier.
    pub const fn maximum_generations(self) -> usize {
        self.maximum_generations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionState {
    Accepting,
    Suspended,
    Invalidated,
    Closed,
}

#[derive(Debug)]
struct GenerationResource {
    generation: BackendGeneration,
    in_flight: AtomicUsize,
}

impl GenerationResource {
    fn new(generation: BackendGeneration) -> Self {
        Self {
            generation,
            in_flight: AtomicUsize::new(0),
        }
    }
}

#[derive(Clone, Debug)]
enum GenerationStorage {
    Live(Arc<GenerationResource>),
    Tombstone(Box<BackendGeneration>),
}

impl GenerationStorage {
    fn generation(&self) -> &BackendGeneration {
        match self {
            Self::Live(resource) => &resource.generation,
            Self::Tombstone(generation) => generation,
        }
    }

    fn live_resource(&self) -> Option<&Arc<GenerationResource>> {
        match self {
            Self::Live(resource) => Some(resource),
            Self::Tombstone(_) => None,
        }
    }

    fn in_flight(&self) -> usize {
        self.live_resource()
            .map_or(0, |resource| resource.in_flight.load(Ordering::Acquire))
    }
}

#[derive(Clone, Debug)]
struct RegistryEntry {
    storage: GenerationStorage,
    accept_until_ms: u64,
    state: AdmissionState,
}

struct PreparedSnapshot {
    entries: HashMap<JobId, RegistryEntry>,
    current: Option<JobId>,
    recent: VecDeque<JobId>,
}

impl RegistryEntry {
    fn accepting(&self, now_ms: u64) -> bool {
        self.state == AdmissionState::Accepting
            && self.storage.live_resource().is_some()
            && now_ms < self.accept_until_ms
    }
}

/// Current generation plus the exact bounded set Wolf still accepts.
///
/// Relative lifetimes must be anchored to a monotonic timestamp captured before
/// the backend operation which delivered them. Re-observing a job can shorten,
/// but can never extend, its previously established local deadline.
/// `maximum_generations` also bounds immutable retired-ID tombstones; once that
/// safety history is full, a new distinct generation suspends admission.
#[derive(Debug)]
pub struct GenerationRegistry {
    config: GenerationRegistryConfig,
    entries: HashMap<JobId, RegistryEntry>,
    current: Option<JobId>,
    recent: VecDeque<JobId>,
    watermark_current: Option<JobId>,
    watermark_recent: VecDeque<JobId>,
    last_event_seq: Option<u64>,
    last_monotonic_ms: Option<u64>,
    synchronized: bool,
}

impl GenerationRegistry {
    /// Creates an empty registry which cannot admit work before a snapshot.
    pub fn new(config: GenerationRegistryConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            current: None,
            recent: VecDeque::with_capacity(config.maximum_recent),
            watermark_current: None,
            watermark_recent: VecDeque::with_capacity(config.maximum_recent),
            last_event_seq: None,
            last_monotonic_ms: None,
            synchronized: false,
        }
    }

    /// Returns whether a valid snapshot and contiguous event stream are active.
    pub const fn is_synchronized(&self) -> bool {
        self.synchronized
    }

    /// Returns the last authoritative event watermark.
    pub const fn last_event_seq(&self) -> Option<u64> {
        self.last_event_seq
    }

    /// Returns the current generation ID without extending its lifetime.
    pub const fn current_job_id(&self) -> Option<JobId> {
        self.current
    }

    /// Returns exact admissible current/recent roles at `now_ms`.
    ///
    /// This call applies local expiry first and fails while the registry is not
    /// synchronized, so callers cannot retain session assignments from stale state.
    pub fn admissible_job_ids(
        &mut self,
        now_ms: u64,
    ) -> Result<AdmissibleJobIds, JobRegistryError> {
        self.advance_clock(now_ms)?;
        if !self.synchronized {
            return Err(JobRegistryError::NotSynchronized);
        }
        Ok(AdmissibleJobIds {
            current: self.current,
            recent: self.recent.iter().copied().collect(),
        })
    }

    /// Returns an immutable retained generation, regardless of admission state.
    pub fn generation(&self, id: JobId) -> Option<&BackendGeneration> {
        self.entries
            .get(&id)
            .map(|entry| entry.storage.generation())
    }

    /// Returns the current generation only while it remains locally admissible.
    pub fn current_generation(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<&BackendGeneration>, JobRegistryError> {
        self.advance_clock(now_ms)?;
        let Some(id) = self.current else {
            return Ok(None);
        };
        Ok(self
            .entries
            .get(&id)
            .filter(|entry| self.synchronized && entry.accepting(now_ms))
            .map(|entry| entry.storage.generation()))
    }

    /// Atomically replaces live work from an authoritative Wolf snapshot.
    ///
    /// request_started_ms must be captured before sending SubscribeJobs.
    /// Validation failure suspends all live admissions until another snapshot
    /// succeeds.
    pub fn apply_snapshot(
        &mut self,
        event_seq: u64,
        current: Option<&AcceptableJob>,
        recent: &[AcceptableJob],
        request_started_ms: u64,
    ) -> Result<(), JobRegistryError> {
        let result = self.prepare_snapshot(event_seq, current, recent, request_started_ms);
        match result {
            Ok(prepared) => {
                self.entries = prepared.entries;
                self.current = prepared.current;
                self.recent = prepared.recent;
                self.watermark_current = self.current;
                self.watermark_recent = self.recent.clone();
                self.last_event_seq = Some(event_seq);
                self.last_monotonic_ms = Some(request_started_ms);
                self.synchronized = true;
                Ok(())
            }
            Err(error) => {
                self.suspend_live_work();
                Err(error)
            }
        }
    }

    /// Applies exactly one next authoritative journal event.
    ///
    /// delivery_anchor_ms must be attached by the transport when it received or
    /// began reading the event, not when a buffered event is later processed.
    pub fn apply_event(
        &mut self,
        event: &BackendEvent,
        delivery_anchor_ms: u64,
    ) -> Result<(), JobRegistryError> {
        let result = self.try_apply_event(event, delivery_anchor_ms);
        if result.is_err() {
            self.suspend_live_work();
        }
        result
    }

    /// Begins one admission and retains its exact generation until the guard drops.
    pub fn begin_admission(
        &mut self,
        id: JobId,
        now_ms: u64,
    ) -> Result<GenerationAdmission, JobRegistryError> {
        self.advance_clock(now_ms)?;
        if !self.synchronized {
            return Err(JobRegistryError::NotSynchronized);
        }
        let entry = self
            .entries
            .get(&id)
            .ok_or(JobRegistryError::UnknownJob(id))?;
        if !entry.accepting(now_ms) {
            return Err(JobRegistryError::StaleJob(id));
        }
        let resource = entry
            .storage
            .live_resource()
            .ok_or(JobRegistryError::StaleJob(id))?;
        resource
            .in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| JobRegistryError::AdmissionCounterExhausted(id))?;
        Ok(GenerationAdmission {
            resource: Arc::clone(resource),
        })
    }

    /// Releases heavy non-admitting resources after their final guard drops.
    ///
    /// The immutable generation identity, descriptor, original deadline, and terminal
    /// state remain as a bounded tombstone. This method reports each conversion once;
    /// it never forgets an ID in order to reclaim capacity.
    pub fn collect_retired(&mut self, now_ms: u64) -> Result<Vec<JobId>, JobRegistryError> {
        self.advance_clock(now_ms)?;
        let current = self.current;
        let recent = &self.recent;
        let mut retired = Vec::new();
        for (id, entry) in &mut self.entries {
            let retained_role = current == Some(*id) || recent.contains(id);
            if retained_role
                || !matches!(
                    entry.state,
                    AdmissionState::Invalidated | AdmissionState::Closed
                )
                || entry.storage.in_flight() != 0
            {
                continue;
            }
            let generation = match &entry.storage {
                GenerationStorage::Live(resource) => Some(resource.generation.clone()),
                GenerationStorage::Tombstone(_) => None,
            };
            if let Some(generation) = generation {
                entry.storage = GenerationStorage::Tombstone(Box::new(generation));
                retired.push(*id);
            }
        }
        retired.sort_unstable();
        Ok(retired)
    }

    /// Returns the number of live admission guards for diagnostics and tests.
    pub fn in_flight(&self, id: JobId) -> Option<usize> {
        self.entries.get(&id).map(|entry| entry.storage.in_flight())
    }

    fn prepare_snapshot(
        &self,
        event_seq: u64,
        current: Option<&AcceptableJob>,
        recent: &[AcceptableJob],
        anchor_ms: u64,
    ) -> Result<PreparedSnapshot, JobRegistryError> {
        self.check_clock(anchor_ms)?;
        if let Some(previous) = self.last_event_seq {
            if event_seq < previous {
                return Err(JobRegistryError::SnapshotSequenceRollback {
                    previous,
                    received: event_seq,
                });
            }
        }
        if recent.len() > self.config.maximum_recent {
            return Err(JobRegistryError::RecentCapacityExceeded {
                maximum: self.config.maximum_recent,
            });
        }

        let capacity = recent.len() + usize::from(current.is_some());
        let mut seen = HashSet::with_capacity(capacity);
        let mut prepared = Vec::with_capacity(capacity);
        let mut current_id = None;

        if let Some(job) = current {
            let (id, entry) = self.prepare_acceptable(job, anchor_ms)?;
            if !seen.insert(id) {
                return Err(JobRegistryError::DuplicateSnapshotJob(id));
            }
            current_id = Some(id);
            prepared.push((id, entry));
        }

        let mut recent_ids = VecDeque::with_capacity(recent.len());
        for job in recent {
            let (id, entry) = self.prepare_acceptable(job, anchor_ms)?;
            if !seen.insert(id) {
                return Err(JobRegistryError::DuplicateSnapshotJob(id));
            }
            recent_ids.push_back(id);
            prepared.push((id, entry));
        }

        if self.last_event_seq == Some(event_seq)
            && (current_id != self.watermark_current || recent_ids != self.watermark_recent)
        {
            return Err(JobRegistryError::SnapshotStateConflict { event_seq });
        }

        // Keep every previously observed ID. Omitted work becomes terminal, but its
        // immutable identity and original deadline must survive resource retirement.
        let mut entries = self.entries.clone();
        for (id, entry) in prepared {
            entries.insert(id, entry);
        }

        for (id, entry) in &mut entries {
            if !seen.contains(id) {
                entry.state = match entry.state {
                    AdmissionState::Closed => AdmissionState::Closed,
                    _ => AdmissionState::Invalidated,
                };
            }
        }

        if entries.len() > self.config.maximum_generations {
            return Err(JobRegistryError::GenerationCapacityExceeded {
                maximum: self.config.maximum_generations,
            });
        }
        Ok(PreparedSnapshot {
            entries,
            current: current_id,
            recent: recent_ids,
        })
    }

    fn prepare_acceptable(
        &self,
        acceptable: &AcceptableJob,
        anchor_ms: u64,
    ) -> Result<(JobId, RegistryEntry), JobRegistryError> {
        let generation = BackendGeneration::from_descriptor(acceptable.job.clone())?;
        if acceptable.accept_for_ms == 0 || acceptable.accept_for_ms > generation.maximum_age_ms() {
            return Err(JobRegistryError::InvalidRemainingLifetime(generation.id()));
        }
        let proposed_deadline = deadline(anchor_ms, acceptable.accept_for_ms)?;
        let id = generation.id();
        if let Some(old) = self.entries.get(&id) {
            if old.storage.generation() != &generation {
                return Err(JobRegistryError::ConflictingJobId(id));
            }
            if matches!(
                old.state,
                AdmissionState::Invalidated | AdmissionState::Closed
            ) || matches!(old.storage, GenerationStorage::Tombstone(_))
            {
                return Err(JobRegistryError::ResurrectedJob(id));
            }
            let accept_until_ms = old.accept_until_ms.min(proposed_deadline);
            if accept_until_ms <= anchor_ms {
                return Err(JobRegistryError::ResurrectedJob(id));
            }
            return Ok((
                id,
                RegistryEntry {
                    storage: old.storage.clone(),
                    accept_until_ms,
                    state: AdmissionState::Accepting,
                },
            ));
        }
        Ok((
            id,
            RegistryEntry {
                storage: GenerationStorage::Live(Arc::new(GenerationResource::new(generation))),
                accept_until_ms: proposed_deadline,
                state: AdmissionState::Accepting,
            },
        ))
    }

    fn try_apply_event(
        &mut self,
        event: &BackendEvent,
        anchor_ms: u64,
    ) -> Result<(), JobRegistryError> {
        if !self.synchronized {
            return Err(JobRegistryError::NotSynchronized);
        }
        self.check_clock(anchor_ms)?;
        event
            .validate()
            .map_err(|_| JobRegistryError::InvalidBackendEvent)?;
        let previous = self
            .last_event_seq
            .ok_or(JobRegistryError::NotSynchronized)?;
        let expected = previous
            .checked_add(1)
            .ok_or(JobRegistryError::EventSequenceExhausted)?;
        if event.event_seq() != expected {
            return Err(JobRegistryError::EventSequenceGap {
                expected,
                received: event.event_seq(),
            });
        }

        self.expire_at(anchor_ms);
        match event {
            BackendEvent::JobActivated { job, .. } => {
                self.activate(job, anchor_ms)?;
            }
            BackendEvent::JobInvalidated {
                job_id,
                reason,
                accept_for_ms,
                ..
            } => {
                let id = JobId::new(*job_id.as_bytes())?;
                self.invalidate_job(id, *reason, *accept_for_ms, anchor_ms)?;
            }
            BackendEvent::GenerationClosed { job_id, .. } => {
                let id = JobId::new(*job_id.as_bytes())?;
                if let Some(entry) = self.entries.get_mut(&id) {
                    entry.state = AdmissionState::Closed;
                    if self.current == Some(id) {
                        self.current = None;
                    }
                    self.recent.retain(|recent| *recent != id);
                }
            }
            BackendEvent::ShareCommitted { .. } => {}
        }
        self.last_event_seq = Some(event.event_seq());
        self.watermark_current = self.current;
        self.watermark_recent = self.recent.clone();
        self.last_monotonic_ms = Some(anchor_ms);
        Ok(())
    }

    fn activate(
        &mut self,
        descriptor: &JobDescriptor,
        anchor_ms: u64,
    ) -> Result<(), JobRegistryError> {
        let generation = BackendGeneration::from_descriptor(descriptor.clone())?;
        let id = generation.id();
        if self.entries.contains_key(&id) {
            return Err(JobRegistryError::ReusedJobId(id));
        }
        let prior_current = self.current.filter(|prior| {
            self.entries
                .get(prior)
                .is_some_and(|entry| entry.accepting(anchor_ms))
        });
        if prior_current.is_some() && self.recent.len() == self.config.maximum_recent {
            return Err(JobRegistryError::RecentCapacityExceeded {
                maximum: self.config.maximum_recent,
            });
        }
        if self.entries.len() == self.config.maximum_generations {
            return Err(JobRegistryError::GenerationCapacityExceeded {
                maximum: self.config.maximum_generations,
            });
        }
        let accept_until_ms = deadline(anchor_ms, generation.maximum_age_ms())?;
        if let Some(prior) = prior_current {
            self.recent.push_front(prior);
        }
        self.entries.insert(
            id,
            RegistryEntry {
                storage: GenerationStorage::Live(Arc::new(GenerationResource::new(generation))),
                accept_until_ms,
                state: AdmissionState::Accepting,
            },
        );
        self.current = Some(id);
        Ok(())
    }

    fn invalidate_job(
        &mut self,
        id: JobId,
        reason: JobInvalidationReason,
        accept_for_ms: u32,
        anchor_ms: u64,
    ) -> Result<(), JobRegistryError> {
        if !self.entries.contains_key(&id) {
            return Ok(());
        }

        // A later event may further describe work that is already terminal. It
        // cannot reopen that work and must not consume grace-list capacity merely
        // to remain a harmless, restrictive no-op.
        if !self
            .entries
            .get(&id)
            .is_some_and(|entry| entry.state == AdmissionState::Accepting)
        {
            if self.current == Some(id) {
                self.current = None;
            }
            self.recent.retain(|recent| *recent != id);
            return Ok(());
        }

        if reason == JobInvalidationReason::Superseded && accept_for_ms != 0 {
            let proposed = deadline(anchor_ms, accept_for_ms)?;
            let already_recent = self.recent.contains(&id);
            if !already_recent && self.recent.len() == self.config.maximum_recent {
                return Err(JobRegistryError::RecentCapacityExceeded {
                    maximum: self.config.maximum_recent,
                });
            }
            let entry = self
                .entries
                .get_mut(&id)
                .ok_or(JobRegistryError::UnknownJob(id))?;
            if entry.state == AdmissionState::Accepting {
                entry.accept_until_ms = entry.accept_until_ms.min(proposed);
                entry.state = if entry.accept_until_ms > anchor_ms {
                    AdmissionState::Accepting
                } else {
                    AdmissionState::Invalidated
                };
            }
            if entry.state == AdmissionState::Accepting && !already_recent {
                self.recent.push_front(id);
            }
        } else {
            let entry = self
                .entries
                .get_mut(&id)
                .ok_or(JobRegistryError::UnknownJob(id))?;
            if entry.state != AdmissionState::Closed {
                entry.state = AdmissionState::Invalidated;
            }
        }

        if self.current == Some(id) {
            self.current = None;
        }
        if !self
            .entries
            .get(&id)
            .is_some_and(|entry| entry.accepting(anchor_ms))
        {
            self.recent.retain(|recent| *recent != id);
        }
        Ok(())
    }

    fn check_clock(&self, now_ms: u64) -> Result<(), JobRegistryError> {
        if self
            .last_monotonic_ms
            .is_some_and(|previous| now_ms < previous)
        {
            return Err(JobRegistryError::ClockMovedBackwards);
        }
        Ok(())
    }

    fn advance_clock(&mut self, now_ms: u64) -> Result<(), JobRegistryError> {
        if let Err(error) = self.check_clock(now_ms) {
            self.suspend_live_work();
            return Err(error);
        }
        self.expire_at(now_ms);
        self.last_monotonic_ms = Some(now_ms);
        Ok(())
    }

    fn expire_at(&mut self, now_ms: u64) {
        for entry in self.entries.values_mut() {
            if matches!(
                entry.state,
                AdmissionState::Accepting | AdmissionState::Suspended
            ) && now_ms >= entry.accept_until_ms
            {
                entry.state = AdmissionState::Invalidated;
            }
        }
        self.current = self.current.filter(|id| {
            self.entries
                .get(id)
                .is_some_and(|entry| entry.accepting(now_ms))
        });
        self.recent.retain(|id| {
            self.entries
                .get(id)
                .is_some_and(|entry| entry.accepting(now_ms))
        });
        self.watermark_current = self.watermark_current.filter(|id| {
            self.entries
                .get(id)
                .is_some_and(|entry| entry.accepting(now_ms))
        });
        self.watermark_recent.retain(|id| {
            self.entries
                .get(id)
                .is_some_and(|entry| entry.accepting(now_ms))
        });
    }

    fn suspend_live_work(&mut self) {
        for entry in self.entries.values_mut() {
            if entry.state == AdmissionState::Accepting {
                entry.state = AdmissionState::Suspended;
            }
        }
        self.current = None;
        self.recent.clear();
        self.synchronized = false;
    }
}

/// Non-cloneable RAII proof that one submission began while its job was valid.
#[derive(Debug)]
pub struct GenerationAdmission {
    resource: Arc<GenerationResource>,
}

impl GenerationAdmission {
    /// Returns the exact immutable backend generation retained by this guard.
    pub fn generation(&self) -> &BackendGeneration {
        &self.resource.generation
    }

    /// Returns the admitted generation identifier.
    pub fn job_id(&self) -> JobId {
        self.resource.generation.id()
    }
}

impl Drop for GenerationAdmission {
    fn drop(&mut self) {
        let previous = self.resource.in_flight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "generation admission counter underflow");
    }
}

/// Generation registry or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobRegistryError {
    /// Job IDs are opaque but may not be all zeroes.
    #[error("job identifier must be non-zero")]
    ZeroJobId,
    /// Registry capacities cannot safely retain current and recent jobs.
    #[error("generation registry limits are invalid")]
    InvalidLimits,
    /// Wolf supplied a descriptor that failed strict validation.
    #[error("backend job descriptor is invalid")]
    InvalidDescriptor,
    /// Snapshot remaining lifetime was zero or exceeded the descriptor maximum.
    #[error("snapshot remaining lifetime for {0:?} is invalid")]
    InvalidRemainingLifetime(JobId),
    /// A relative deadline overflowed the monotonic time domain.
    #[error("generation deadline overflowed")]
    DeadlineOverflow,
    /// A caller supplied a decreasing monotonic timestamp.
    #[error("generation-registry monotonic time moved backwards")]
    ClockMovedBackwards,
    /// A snapshot attempted to move behind an observed journal watermark.
    #[error("snapshot journal sequence rolled back from {previous} to {received}")]
    SnapshotSequenceRollback {
        /// Previously observed watermark.
        previous: u64,
        /// Regressing snapshot watermark.
        received: u64,
    },
    /// The same journal watermark described a different generation set.
    #[error("snapshot state changed without advancing event sequence {event_seq}")]
    SnapshotStateConflict {
        /// Reused snapshot watermark.
        event_seq: u64,
    },
    /// One snapshot contained the same generation in multiple roles.
    #[error("snapshot contains duplicate generation {0:?}")]
    DuplicateSnapshotJob(JobId),
    /// One opaque ID was bound to different immutable descriptor bytes.
    #[error("generation {0:?} conflicts with its prior descriptor")]
    ConflictingJobId(JobId),
    /// A terminal generation was reintroduced as acceptable.
    #[error("terminal generation {0:?} was resurrected")]
    ResurrectedJob(JobId),
    /// A new activation reused a previously retained identifier.
    #[error("job activation reused generation {0:?}")]
    ReusedJobId(JobId),
    /// More grace-period jobs were supplied than configured.
    #[error("recent-job capacity {maximum} was exceeded")]
    RecentCapacityExceeded {
        /// Configured maximum.
        maximum: usize,
    },
    /// More records were simultaneously needed than configured.
    #[error("generation capacity {maximum} was exceeded")]
    GenerationCapacityExceeded {
        /// Configured maximum.
        maximum: usize,
    },
    /// Admission is disabled until a valid snapshot succeeds.
    #[error("generation registry is not synchronized")]
    NotSynchronized,
    /// The journal sequence did not advance by exactly one.
    #[error("event sequence gap: expected {expected}, received {received}")]
    EventSequenceGap {
        /// Required sequence.
        expected: u64,
        /// Received sequence.
        received: u64,
    },
    /// No next event sequence can be represented.
    #[error("event sequence is exhausted")]
    EventSequenceExhausted,
    /// A backend event failed strict protocol validation.
    #[error("backend event is invalid")]
    InvalidBackendEvent,
    /// The requested generation is not retained.
    #[error("unknown generation {0:?}")]
    UnknownJob(JobId),
    /// The requested generation no longer accepts new work.
    #[error("stale generation {0:?}")]
    StaleJob(JobId),
    /// In-flight accounting cannot represent another submission.
    #[error("admission counter for {0:?} is exhausted")]
    AdmissionCounterExhausted(JobId),
}

fn deadline(anchor_ms: u64, duration_ms: u32) -> Result<u64, JobRegistryError> {
    anchor_ms
        .checked_add(u64::from(duration_ms))
        .ok_or(JobRegistryError::DeadlineOverflow)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{TargetBinding, TargetBounds};
    use wcash_pool_protocol::{Hex108, TargetLe};

    fn descriptor(id: u8, max_age_ms: u32) -> JobDescriptor {
        let mut header = [id; 108];
        header[..4].copy_from_slice(&[4, 0, 0, 0]);
        header[4..36].copy_from_slice(&[id.wrapping_add(1); 32]);
        header[100..104].copy_from_slice(&[1, 2, 3, id]);
        JobDescriptor {
            job_id: Hex32::new([id; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([id.wrapping_add(2); 32]),
            zcash_previous_hash_le: Hex32::new([id.wrapping_add(1); 32]),
            wcash_target_le: TargetLe::new([id.wrapping_add(3); 32]),
            zcash_target_le: TargetLe::new([id.wrapping_add(4); 32]),
            wcash_height: u32::from(id) + 1,
            zcash_height: u32::from(id) + 2,
            max_age_ms,
        }
    }

    fn acceptable(id: u8, max_age_ms: u32, accept_for_ms: u32) -> AcceptableJob {
        AcceptableJob {
            job: descriptor(id, max_age_ms),
            accept_for_ms,
        }
    }

    fn registry() -> GenerationRegistry {
        GenerationRegistry::new(
            GenerationRegistryConfig::new(2, 8).expect("fixture limits are valid"),
        )
    }

    fn id(value: u8) -> JobId {
        JobId::new([value; 32]).expect("fixture ID is non-zero")
    }

    #[test]
    fn descriptor_import_preserves_time_tips_and_endian_targets() {
        let raw = descriptor(3, 1_000);
        let generation =
            BackendGeneration::from_descriptor(raw.clone()).expect("valid descriptor imports");
        assert_eq!(generation.id(), id(3));
        assert_eq!(generation.tips().wcash_previous_hash_le(), [5; 32]);
        assert_eq!(generation.tips().zcash_previous_hash_le(), [4; 32]);
        assert_eq!(generation.header_time(), Hex4::new([1, 2, 3, 3]));
        assert_eq!(
            generation.wcash_network_target().to_backend(),
            raw.wcash_target_le
        );
        assert_eq!(
            generation.zcash_network_target().to_backend(),
            raw.zcash_target_le
        );
    }

    #[test]
    fn snapshot_anchor_and_reobservation_never_extend_lifetime() {
        let mut registry = registry();
        let job = acceptable(1, 1_000, 100);
        registry
            .apply_snapshot(4, Some(&job), &[], 1_000)
            .expect("initial snapshot is valid");
        registry
            .apply_snapshot(4, Some(&job), &[], 1_050)
            .expect("reobservation may retain only the earlier deadline");
        assert!(registry.begin_admission(id(1), 1_099).is_ok());
        assert!(matches!(
            registry.begin_admission(id(1), 1_100),
            Err(JobRegistryError::StaleJob(_))
        ));
    }

    #[test]
    fn malformed_snapshot_suspends_prior_work_atomically() {
        let mut registry = registry();
        let current = acceptable(1, 1_000, 500);
        registry
            .apply_snapshot(8, Some(&current), &[], 10)
            .expect("snapshot is valid");
        assert!(matches!(
            registry.apply_snapshot(9, Some(&current), std::slice::from_ref(&current), 11),
            Err(JobRegistryError::DuplicateSnapshotJob(_))
        ));
        assert!(!registry.is_synchronized());
        assert!(matches!(
            registry.begin_admission(id(1), 12),
            Err(JobRegistryError::NotSynchronized)
        ));
    }

    #[test]
    fn same_watermark_cannot_introduce_different_work() {
        let mut registry = registry();
        registry
            .apply_snapshot(8, Some(&acceptable(1, 1_000, 500)), &[], 10)
            .expect("snapshot is valid");
        assert!(matches!(
            registry.apply_snapshot(8, Some(&acceptable(2, 1_000, 500)), &[], 11),
            Err(JobRegistryError::SnapshotStateConflict { event_seq: 8 })
        ));
        assert!(!registry.is_synchronized());
    }

    #[test]
    fn same_watermark_preserves_exact_roles_across_suspension() {
        let mut registry = registry();
        let current = acceptable(1, 1_000, 500);
        let recent = [acceptable(2, 1_000, 400), acceptable(3, 1_000, 300)];
        registry
            .apply_snapshot(8, Some(&current), &recent, 10)
            .expect("snapshot is valid");

        assert_eq!(
            registry.apply_snapshot(8, Some(&current), &[], 11),
            Err(JobRegistryError::SnapshotStateConflict { event_seq: 8 })
        );
        assert!(!registry.is_synchronized());

        registry
            .apply_snapshot(8, Some(&current), &recent, 12)
            .expect("exact same-watermark roles restore suspended work");
        let reversed = [recent[1].clone(), recent[0].clone()];
        assert_eq!(
            registry.apply_snapshot(8, Some(&current), &reversed, 13),
            Err(JobRegistryError::SnapshotStateConflict { event_seq: 8 })
        );
        registry
            .apply_snapshot(8, Some(&current), &recent, 14)
            .expect("ordered roles remain recoverable after rejection");
        assert_eq!(
            registry
                .admissible_job_ids(15)
                .expect("restored registry is synchronized"),
            AdmissibleJobIds {
                current: Some(id(1)),
                recent: vec![id(2), id(3)],
            }
        );
    }

    #[test]
    fn omitted_and_retired_generation_cannot_reset_its_lifetime() {
        let mut registry = registry();
        let job = acceptable(1, 100, 100);
        registry
            .apply_snapshot(1, Some(&job), &[], 0)
            .expect("initial snapshot is valid");
        registry
            .apply_snapshot(2, None, &[], 10)
            .expect("authoritative omission is valid");
        assert_eq!(
            registry.collect_retired(10).expect("clock is monotonic"),
            vec![id(1)]
        );
        assert_eq!(registry.entries[&id(1)].accept_until_ms, 100);
        assert!(matches!(
            registry.apply_snapshot(3, Some(&job), &[], 20),
            Err(JobRegistryError::ResurrectedJob(job_id)) if job_id == id(1)
        ));
        assert_eq!(registry.entries[&id(1)].accept_until_ms, 100);
    }

    #[test]
    fn retired_generation_id_cannot_be_activated_again() {
        let mut registry = registry();
        registry
            .apply_snapshot(1, Some(&acceptable(1, 100, 100)), &[], 0)
            .expect("initial snapshot is valid");
        registry
            .apply_snapshot(2, None, &[], 1)
            .expect("authoritative omission is valid");
        assert_eq!(
            registry.collect_retired(1).expect("clock is monotonic"),
            vec![id(1)]
        );
        assert!(matches!(
            registry.apply_event(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(1, 100),
                },
                2,
            ),
            Err(JobRegistryError::ReusedJobId(job_id)) if job_id == id(1)
        ));
        assert!(!registry.is_synchronized());
    }

    #[test]
    fn retired_generation_id_remembers_its_exact_descriptor() {
        let mut registry = registry();
        registry
            .apply_snapshot(1, Some(&acceptable(1, 100, 100)), &[], 0)
            .expect("initial snapshot is valid");
        registry
            .apply_snapshot(2, None, &[], 1)
            .expect("authoritative omission is valid");
        assert_eq!(
            registry.collect_retired(1).expect("clock is monotonic"),
            vec![id(1)]
        );

        let mut conflicting = acceptable(2, 100, 100);
        conflicting.job.job_id = id(1).to_protocol();
        assert!(matches!(
            registry.apply_snapshot(3, Some(&conflicting), &[], 2),
            Err(JobRegistryError::ConflictingJobId(job_id)) if job_id == id(1)
        ));
    }

    #[test]
    fn tombstone_bound_fails_closed_after_distinct_rotations() {
        let mut registry = GenerationRegistry::new(
            GenerationRegistryConfig::new(1, 3).expect("fixture limits are valid"),
        );
        registry
            .apply_snapshot(1, Some(&acceptable(1, 100, 100)), &[], 0)
            .expect("first generation fits");
        registry
            .apply_snapshot(2, Some(&acceptable(2, 100, 100)), &[], 1)
            .expect("second generation fits");
        assert_eq!(
            registry.collect_retired(1).expect("clock is monotonic"),
            vec![id(1)]
        );
        registry
            .apply_snapshot(3, Some(&acceptable(3, 100, 100)), &[], 2)
            .expect("third generation fits");
        assert_eq!(
            registry.collect_retired(2).expect("clock is monotonic"),
            vec![id(2)]
        );

        assert_eq!(
            registry.apply_snapshot(4, Some(&acceptable(4, 100, 100)), &[], 3),
            Err(JobRegistryError::GenerationCapacityExceeded { maximum: 3 })
        );
        assert!(!registry.is_synchronized());
        assert_eq!(registry.entries.len(), 3);
        assert!(registry.entries.contains_key(&id(1)));
        assert!(registry.entries.contains_key(&id(2)));
        assert!(registry.entries.contains_key(&id(3)));
    }

    #[test]
    fn activation_and_reason_specific_invalidation_are_exact() {
        let mut registry = registry();
        registry
            .apply_snapshot(1, Some(&acceptable(1, 1_000, 900)), &[], 0)
            .expect("snapshot is valid");
        registry
            .apply_event(
                &BackendEvent::JobActivated {
                    event_seq: 2,
                    job: descriptor(2, 1_000),
                },
                10,
            )
            .expect("activation is contiguous");
        assert_eq!(registry.current_job_id(), Some(id(2)));

        registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 3,
                    job_id: id(1).to_protocol(),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 20,
                },
                20,
            )
            .expect("soft invalidation is contiguous");
        assert!(registry.begin_admission(id(1), 39).is_ok());
        assert!(matches!(
            registry.begin_admission(id(1), 40),
            Err(JobRegistryError::StaleJob(_))
        ));

        registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 4,
                    job_id: id(2).to_protocol(),
                    reason: JobInvalidationReason::ZcashTipChanged,
                    accept_for_ms: 0,
                },
                41,
            )
            .expect("tip change is hard stale");
        assert!(matches!(
            registry.begin_admission(id(2), 41),
            Err(JobRegistryError::StaleJob(_))
        ));
    }

    #[test]
    fn closure_blocks_new_work_but_guard_fences_resource_retirement() {
        let mut registry = registry();
        registry
            .apply_snapshot(1, Some(&acceptable(1, 1_000, 900)), &[], 0)
            .expect("snapshot is valid");
        let guard = registry.begin_admission(id(1), 1).expect("job is live");
        assert_eq!(registry.in_flight(id(1)), Some(1));
        registry
            .apply_event(
                &BackendEvent::GenerationClosed {
                    event_seq: 2,
                    job_id: id(1).to_protocol(),
                },
                2,
            )
            .expect("closure is contiguous");
        assert!(matches!(
            registry.begin_admission(id(1), 2),
            Err(JobRegistryError::StaleJob(_))
        ));
        assert!(registry
            .collect_retired(2)
            .expect("clock is monotonic")
            .is_empty());
        assert_eq!(guard.generation().id(), id(1));
        drop(guard);
        assert_eq!(
            registry.collect_retired(2).expect("clock is monotonic"),
            vec![id(1)]
        );
        assert!(registry
            .collect_retired(2)
            .expect("a tombstone is reported only once")
            .is_empty());
        assert_eq!(
            registry.generation(id(1)).map(BackendGeneration::id),
            Some(id(1))
        );
    }

    #[test]
    fn suspension_retains_deadline_and_hard_stale_cannot_be_soft_resurrected() {
        let mut first_registry = registry();
        first_registry
            .apply_snapshot(1, Some(&acceptable(1, 100, 100)), &[], 0)
            .expect("snapshot is valid");
        assert!(matches!(
            first_registry.apply_event(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: descriptor(2, 100)
                },
                10
            ),
            Err(JobRegistryError::EventSequenceGap { .. })
        ));
        assert!(first_registry
            .collect_retired(20)
            .expect("suspended deadline remains live")
            .is_empty());
        assert!(matches!(
            first_registry.apply_snapshot(2, Some(&acceptable(1, 100, 100)), &[], 100),
            Err(JobRegistryError::ResurrectedJob(_))
        ));

        let mut second_registry = registry();
        second_registry
            .apply_snapshot(1, Some(&acceptable(1, 1_000, 900)), &[], 0)
            .expect("snapshot is valid");
        second_registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: id(1).to_protocol(),
                    reason: JobInvalidationReason::Age,
                    accept_for_ms: 0,
                },
                10,
            )
            .expect("hard invalidation is valid");
        second_registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 3,
                    job_id: id(1).to_protocol(),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 20,
                },
                11,
            )
            .expect("later restriction is harmless");
        assert!(matches!(
            second_registry.begin_admission(id(1), 12),
            Err(JobRegistryError::StaleJob(_))
        ));
    }

    #[test]
    fn terminal_superseded_event_is_harmless_when_recent_is_full() {
        let mut registry = registry();
        registry
            .apply_snapshot(
                1,
                Some(&acceptable(1, 1_000, 900)),
                &[acceptable(2, 1_000, 800), acceptable(3, 1_000, 700)],
                0,
            )
            .expect("full recent snapshot is valid");
        registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: id(1).to_protocol(),
                    reason: JobInvalidationReason::Age,
                    accept_for_ms: 0,
                },
                1,
            )
            .expect("hard invalidation is valid");
        registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 3,
                    job_id: id(1).to_protocol(),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 20,
                },
                2,
            )
            .expect("later terminal description cannot consume recent capacity");
        assert!(registry.is_synchronized());
        assert_eq!(registry.last_event_seq(), Some(3));
        assert!(matches!(
            registry.begin_admission(id(1), 2),
            Err(JobRegistryError::StaleJob(_))
        ));
    }
    #[test]
    fn event_gap_and_clock_rollback_fail_closed() {
        let mut registry = registry();
        registry
            .apply_snapshot(5, Some(&acceptable(1, 1_000, 900)), &[], 100)
            .expect("snapshot is valid");
        assert!(matches!(
            registry.apply_event(
                &BackendEvent::JobActivated {
                    event_seq: 7,
                    job: descriptor(2, 1_000)
                },
                101
            ),
            Err(JobRegistryError::EventSequenceGap {
                expected: 6,
                received: 7
            })
        ));
        registry
            .apply_snapshot(6, Some(&acceptable(1, 1_000, 800)), &[], 102)
            .expect("fresh snapshot restores suspended exact work");
        assert!(matches!(
            registry.begin_admission(id(1), 99),
            Err(JobRegistryError::ClockMovedBackwards)
        ));
        assert!(!registry.is_synchronized());
    }

    #[test]
    fn assignments_are_per_session_and_require_exact_network_bounds() {
        let generation =
            BackendGeneration::from_descriptor(descriptor(1, 1_000)).expect("valid descriptor");
        let bounds = TargetBounds::new(
            generation.wcash_network_target(),
            generation.zcash_network_target(),
            ShareTarget::MAX,
        )
        .expect("operator limit includes both network targets");
        let first = JobAssignment::new(
            &generation,
            TargetBinding::new(1, bounds.hardest_allowed(), bounds).expect("bounded target"),
        )
        .expect("assignment matches");
        let second = JobAssignment::new(
            &generation,
            TargetBinding::new(2, ShareTarget::MAX, bounds).expect("bounded target"),
        )
        .expect("assignment matches");
        assert_ne!(first.target_binding(), second.target_binding());

        let other =
            BackendGeneration::from_descriptor(descriptor(2, 1_000)).expect("valid descriptor");
        assert!(matches!(
            JobAssignment::new(&other, first.target_binding()),
            Err(JobAssignmentError::NetworkTargetMismatch(_))
        ));
    }
}

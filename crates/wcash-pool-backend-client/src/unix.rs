use std::{
    collections::VecDeque,
    fmt, io,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use wcash_pool_core::{GenerationRegistry, JobRegistryError, SubmissionContext};
use wcash_pool_protocol::{
    canonical_attribution_id, canonical_parent_header_hash_le, canonical_share_id,
    decode_backend_message, encode_backend_request, AcceptableJob, BackendCapability,
    BackendErrorCode, BackendEvent, BackendMessage, BackendRequest, CanonicalUuid, Hex1344, Hex32,
    Hex4, JobDescriptor, ProtocolError, ShareReceipt, TargetLe, WorkerIdentity,
    BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, MAX_BACKEND_PAYLOAD_BYTES,
    MAX_EVENT_PAGE_ITEMS,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_EVENT_QUEUE_CAPACITY: usize = 1_024;
const MAX_EVENT_QUEUE_CAPACITY: usize = 4_096;

// This deliberately stays below the smallest common pathname-based sockaddr_un
// capacity. The terminator and platform-specific structure details then remain the
// operating system's responsibility.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// Expected immutable network and optional persistent backend identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedBackend {
    wcash_genesis: Hex32,
    zcash_genesis: Hex32,
    chain_id: u32,
    backend_instance: Option<CanonicalUuid>,
    journal_stream: Option<CanonicalUuid>,
}

impl ExpectedBackend {
    /// Creates mandatory Wcash and Zcash network expectations.
    pub fn new(
        wcash_genesis: Hex32,
        zcash_genesis: Hex32,
        chain_id: u32,
    ) -> Result<Self, ClientConfigError> {
        if wcash_genesis.is_zero() {
            return Err(ClientConfigError::ZeroNetworkIdentity {
                field: "wcash_genesis",
            });
        }
        if zcash_genesis.is_zero() {
            return Err(ClientConfigError::ZeroNetworkIdentity {
                field: "zcash_genesis",
            });
        }
        if chain_id == 0 {
            return Err(ClientConfigError::ZeroNetworkIdentity { field: "chain_id" });
        }
        Ok(Self {
            wcash_genesis,
            zcash_genesis,
            chain_id,
            backend_instance: None,
            journal_stream: None,
        })
    }

    /// Requires a previously persisted backend installation identity.
    pub fn with_backend_instance(mut self, backend_instance: CanonicalUuid) -> Self {
        self.backend_instance = Some(backend_instance);
        self
    }

    /// Requires a previously persisted backend journal namespace.
    pub fn with_journal_stream(mut self, journal_stream: CanonicalUuid) -> Self {
        self.journal_stream = Some(journal_stream);
        self
    }
}

/// Validated connection and resource bounds for one backend client.
#[derive(Clone, Debug)]
pub struct BackendClientConfig {
    socket_path: PathBuf,
    expected: ExpectedBackend,
    connect_timeout: Duration,
    request_timeout: Duration,
    event_queue_capacity: usize,
}

impl BackendClientConfig {
    /// Creates a configuration with conservative finite deadlines and queue bounds.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        expected: ExpectedBackend,
    ) -> Result<Self, ClientConfigError> {
        let config = Self {
            socket_path: socket_path.into(),
            expected,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            event_queue_capacity: DEFAULT_EVENT_QUEUE_CAPACITY,
        };
        config.validate()?;
        Ok(config)
    }

    /// Overrides the connection and complete request/response deadlines.
    pub fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ClientConfigError> {
        self.connect_timeout = connect_timeout;
        self.request_timeout = request_timeout;
        self.validate()?;
        Ok(self)
    }

    /// Overrides the number of unsolicited durable events retained in memory.
    pub fn with_event_queue_capacity(
        mut self,
        event_queue_capacity: usize,
    ) -> Result<Self, ClientConfigError> {
        self.event_queue_capacity = event_queue_capacity;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), ClientConfigError> {
        validate_socket_path(&self.socket_path)?;
        validate_timeout("connect_timeout", self.connect_timeout)?;
        validate_timeout("request_timeout", self.request_timeout)?;
        if !(1..=MAX_EVENT_QUEUE_CAPACITY).contains(&self.event_queue_capacity) {
            return Err(ClientConfigError::InvalidEventQueueCapacity {
                actual: self.event_queue_capacity,
                maximum: MAX_EVENT_QUEUE_CAPACITY,
            });
        }
        if self.expected.backend_instance.is_some()
            && self.expected.backend_instance == self.expected.journal_stream
        {
            return Err(ClientConfigError::DuplicatePersistentIdentity);
        }
        Ok(())
    }
}

/// A configuration error detected before opening a socket.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ClientConfigError {
    /// The socket path was empty.
    #[error("backend socket path must not be empty")]
    EmptySocketPath,
    /// Only absolute filesystem socket paths are accepted.
    #[error("backend socket path must be absolute")]
    RelativeSocketPath,
    /// Dot and parent traversal components make review and policy ambiguous.
    #[error("backend socket path must not contain '.' or '..' components")]
    NonCanonicalSocketPath,
    /// Unix pathname sockets cannot contain an interior NUL.
    #[error("backend socket path contains a NUL byte")]
    SocketPathContainsNul,
    /// The configured pathname is not portable across supported Unix targets.
    #[error("backend socket path is {actual} bytes; maximum is {maximum}")]
    SocketPathTooLong {
        /// Encoded pathname length.
        actual: usize,
        /// Conservative portable bound.
        maximum: usize,
    },
    /// A finite nonzero deadline was not configured.
    #[error("{field} must be greater than zero and at most 300 seconds")]
    InvalidTimeout {
        /// Configuration field with the invalid duration.
        field: &'static str,
    },
    /// The in-memory event buffer was zero or unreasonably large.
    #[error("event queue capacity is {actual}; expected 1..={maximum}")]
    InvalidEventQueueCapacity {
        /// Configured capacity.
        actual: usize,
        /// Hard safety bound.
        maximum: usize,
    },
    /// An expected network identifier used an invalid all-zero value.
    #[error("expected {field} must be nonzero")]
    ZeroNetworkIdentity {
        /// Invalid expected field.
        field: &'static str,
    },
    /// Backend and journal identities identify different namespaces.
    #[error("expected backend instance and journal stream identities must be distinct")]
    DuplicatePersistentIdentity,
}

/// Identity negotiated with a protocol-v1 backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendIdentity {
    /// Unique identity of this socket session.
    pub backend_session: CanonicalUuid,
    /// Stable backend installation identity.
    pub backend_instance: CanonicalUuid,
    /// Stable journal sequence namespace.
    pub journal_stream: CanonicalUuid,
    /// Explicit protocol capabilities validated during hello.
    pub capabilities: Vec<BackendCapability>,
    /// Latest durable journal event visible during hello.
    pub current_event_seq: u64,
}

/// Persistent chain and journal authority negotiated for one backend connection.
///
/// Fields are private so edge orchestration can compare authorities without
/// manufacturing an identity that bypasses the validated hello exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendAuthority {
    wcash_genesis: Hex32,
    zcash_genesis: Hex32,
    chain_id: u32,
    backend_instance: CanonicalUuid,
    journal_stream: CanonicalUuid,
}

impl BackendAuthority {
    /// Returns the authenticated Wcash genesis hash.
    pub const fn wcash_genesis(&self) -> &Hex32 {
        &self.wcash_genesis
    }

    /// Returns the authenticated Zcash genesis hash.
    pub const fn zcash_genesis(&self) -> &Hex32 {
        &self.zcash_genesis
    }

    /// Returns the authenticated Wcash chain identifier.
    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Returns the stable backend installation identity.
    pub const fn backend_instance(&self) -> &CanonicalUuid {
        &self.backend_instance
    }

    /// Returns the stable journal namespace used to key durable event cursors.
    pub const fn journal_stream(&self) -> &CanonicalUuid {
        &self.journal_stream
    }
}

/// Opaque binding between one snapshot and the exact live client that produced it.
///
/// Persistent authority equality alone is insufficient: two connections can have
/// different snapshot cursors and queued events. Pointer identity on the private
/// connection token prevents orchestration from cross-wiring those streams.
#[derive(Clone)]
pub struct BackendConnectionBinding {
    authority: BackendAuthority,
    connection_token: Arc<()>,
    snapshot_event_seq: u64,
}

impl fmt::Debug for BackendConnectionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendConnectionBinding")
            .field("authority", &self.authority)
            .field("snapshot_event_seq", &self.snapshot_event_seq)
            .finish_non_exhaustive()
    }
}

impl PartialEq for BackendConnectionBinding {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.snapshot_event_seq == other.snapshot_event_seq
            && Arc::ptr_eq(&self.connection_token, &other.connection_token)
    }
}

impl Eq for BackendConnectionBinding {}

impl BackendConnectionBinding {
    /// Returns the persistent authority authenticated for this connection.
    pub const fn authority(&self) -> &BackendAuthority {
        &self.authority
    }

    /// Returns the exact snapshot watermark that established live mode.
    pub const fn snapshot_event_seq(&self) -> u64 {
        self.snapshot_event_seq
    }
}

/// A client-captured monotonic instant that predates one backend I/O exchange.
///
/// The constructor is intentionally private. Code applying backend-relative job
/// lifetimes can use this value, but cannot manufacture a later anchor and thereby
/// extend a lease. An anchor is meaningful only within this process lifetime and
/// must never be persisted or compared across processes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicAnchor(Instant);

impl MonotonicAnchor {
    /// Adds a backend-authenticated relative lifetime without overflowing.
    pub fn checked_deadline(self, lifetime: Duration) -> Option<Instant> {
        self.0.checked_add(lifetime)
    }

    /// Returns how long ago this exchange began, saturating at zero.
    pub fn elapsed_at(self, now: Instant) -> Duration {
        now.saturating_duration_since(self.0)
    }
}

/// Process-local monotonic time domain shared by backend delivery and pool policy.
///
/// Construct this before opening the backend connection. Anchors captured before
/// the timeline are rejected, rather than rounded forward and given a longer job
/// lifetime. Values in this time domain must never be persisted across processes.
#[derive(Clone, Copy, Debug)]
pub struct MonotonicTimeline {
    origin: Instant,
}

impl MonotonicTimeline {
    /// Starts a new process-local time domain at the current monotonic instant.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    /// Returns the current millisecond position in this process-local time domain.
    pub fn now_ms(self) -> Result<u64, TimelineError> {
        self.instant_ms(Instant::now())
    }

    /// Converts a transport-authenticated pre-I/O anchor into this time domain.
    pub fn anchor_ms(self, anchor: MonotonicAnchor) -> Result<u64, TimelineError> {
        if anchor.0 < self.origin {
            return Err(TimelineError::AnchorPredatesTimeline);
        }
        self.instant_ms(anchor.0)
    }

    fn instant_ms(self, instant: Instant) -> Result<u64, TimelineError> {
        let elapsed = instant
            .checked_duration_since(self.origin)
            .ok_or(TimelineError::ClockMovedBackwards)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| TimelineError::MillisecondRangeExceeded)
    }
}

impl Default for MonotonicTimeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure to map a backend I/O anchor into the pool's monotonic time domain.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TimelineError {
    /// The timeline was created after the backend exchange had already started.
    #[error("backend delivery anchor predates the pool monotonic timeline")]
    AnchorPredatesTimeline,
    /// The platform monotonic clock returned an instant before the timeline origin.
    #[error("pool monotonic clock moved backwards")]
    ClockMovedBackwards,
    /// The process lifetime cannot be represented in the registry millisecond domain.
    #[error("pool monotonic time exceeded its millisecond representation")]
    MillisecondRangeExceeded,
}

/// Failure while applying a branded backend snapshot or event to job policy.
#[derive(Debug, Error, PartialEq)]
pub enum JobStateIntegrationError {
    /// The backend delivery anchor was outside the process-local time policy.
    #[error(transparent)]
    Timeline(#[from] TimelineError),
    /// The authoritative generation state failed core lifecycle validation.
    #[error(transparent)]
    Registry(#[from] JobRegistryError),
}

/// One unsolicited backend event tied to the I/O exchange that delivered it.
///
/// Fields are private so downstream code cannot pair an old activation with a
/// freshly invented timestamp. Consumers should pass this value intact into their
/// job-lifecycle adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredBackendEvent {
    event: BackendEvent,
    anchor: MonotonicAnchor,
    connection_binding: BackendConnectionBinding,
}

impl DeliveredBackendEvent {
    /// Returns the exact protocol event.
    pub const fn event(&self) -> &BackendEvent {
        &self.event
    }

    /// Returns the event's authoritative journal sequence.
    pub fn event_seq(&self) -> u64 {
        self.event.event_seq()
    }

    /// Returns the monotonic instant captured before the delivering I/O exchange.
    pub const fn anchor(&self) -> MonotonicAnchor {
        self.anchor
    }

    /// Returns the opaque live connection that delivered this event.
    pub const fn connection_binding(&self) -> &BackendConnectionBinding {
        &self.connection_binding
    }

    /// Applies this exact event using its transport-captured pre-I/O anchor.
    pub fn apply_to_registry(
        &self,
        registry: &mut GenerationRegistry,
        timeline: MonotonicTimeline,
    ) -> Result<(), JobStateIntegrationError> {
        let anchor_ms = timeline.anchor_ms(self.anchor)?;
        registry.apply_event(&self.event, anchor_ms)?;
        Ok(())
    }

    /// Applies this event using its transport anchor and a later serialized policy time.
    pub fn apply_to_registry_at(
        &self,
        registry: &mut GenerationRegistry,
        timeline: MonotonicTimeline,
        policy_now_ms: u64,
    ) -> Result<(), JobStateIntegrationError> {
        let anchor_ms = timeline.anchor_ms(self.anchor)?;
        registry.apply_event_at(&self.event, anchor_ms, policy_now_ms)?;
        Ok(())
    }
}

/// One-way stream state for a backend connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStreamPhase {
    /// Historical pages may be read; unsolicited events are forbidden.
    Replay,
    /// A job snapshot was accepted; only the live unsolicited stream may advance.
    Live,
}

/// One share submitted with immutable pool-side attribution.
#[derive(Clone, Eq, PartialEq)]
pub struct ShareSubmission {
    /// Exact backend job generation.
    pub job_id: Hex32,
    /// Account and worker resolved by the authenticated miner session.
    pub identity: WorkerIdentity,
    /// Exact target assigned to the worker for this generation.
    pub target_le: TargetLe,
    /// Exact four raw header-time bytes issued in the frozen job.
    pub time: Hex4,
    /// Reconstructed 32-byte header nonce.
    pub nonce: Hex32,
    /// Raw Equihash `(200, 9)` solution.
    pub solution: Hex1344,
}

impl fmt::Debug for ShareSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareSubmission")
            .field("job_id", &self.job_id)
            .field("identity", &"<worker identity>")
            .field("target_le", &self.target_le)
            .field("time", &self.time)
            .field("nonce", &"<32-byte header nonce>")
            .field("solution", &"<1344-byte Equihash solution>")
            .finish()
    }
}

/// Correlated but job-unbound response from the lower-level share API.
///
/// This value proves strict framing, protocol semantics, network identity, and
/// request correlation. Its winner facts have not been checked against a retained
/// pool generation, so it must not authorize credit or payout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedShareCommit {
    receipt: ShareReceipt,
    replayed: bool,
}

impl UnverifiedShareCommit {
    /// Returns the backend's structurally valid receipt.
    pub const fn receipt(&self) -> &ShareReceipt {
        &self.receipt
    }

    /// Returns whether this response referred to an already-durable commit.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Job-bound share commit returned over this client's identity-checked session.
///
/// The fields are intentionally private: freely constructible protocol wire values are
/// untrusted claims. This brand proves that this client validated framing, protocol
/// semantics, network identity, request correlation, and every exact winner against
/// the retained generation used for submission. It does not cryptographically authenticate
/// the process controlling the Unix socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedShareCommit {
    receipt: ShareReceipt,
    replayed: bool,
}

impl VerifiedShareCommit {
    /// Returns the backend's immutable durable receipt.
    pub const fn receipt(&self) -> &ShareReceipt {
        &self.receipt
    }

    /// Returns whether this response referred to an already-durable identical commit.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Atomic current/recent job snapshot returned before streamed events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobSnapshot {
    /// Snapshot journal watermark.
    event_seq: u64,
    /// Current job, if the backend is safely issuing work.
    current: Option<AcceptableJob>,
    /// Explicitly bounded prior jobs still in ingress grace.
    recent: Vec<AcceptableJob>,
    /// Journal cursor replayed on this connection before subscription.
    ///
    /// When this is smaller than `event_seq`, accounting must replay the missing
    /// range on a separate replay connection before credit or payout resumes. The
    /// job state in this snapshot is nevertheless authoritative at `event_seq`.
    replayed_through_event_seq: u64,
    anchor: MonotonicAnchor,
    connection_binding: BackendConnectionBinding,
}

impl JobSnapshot {
    /// Returns the snapshot's exact journal watermark.
    pub const fn event_seq(&self) -> u64 {
        self.event_seq
    }

    /// Returns the current exact job, if mining was active in this snapshot.
    pub const fn current(&self) -> Option<&AcceptableJob> {
        self.current.as_ref()
    }

    /// Returns the ordered prior jobs still in backend-authenticated ingress grace.
    pub fn recent(&self) -> &[AcceptableJob] {
        &self.recent
    }

    /// Returns the journal cursor replayed before this connection subscribed.
    pub const fn replayed_through_event_seq(&self) -> u64 {
        self.replayed_through_event_seq
    }

    /// Returns the monotonic instant captured before `SubscribeJobs` I/O began.
    pub const fn anchor(&self) -> MonotonicAnchor {
        self.anchor
    }

    /// Returns the persistent authority authenticated by the hello exchange.
    pub const fn authority(&self) -> &BackendAuthority {
        self.connection_binding.authority()
    }

    /// Returns an opaque binding to the exact live connection and snapshot cursor.
    pub fn connection_binding(&self) -> BackendConnectionBinding {
        self.connection_binding.clone()
    }

    /// Initializes generation policy using the exact pre-subscription I/O anchor.
    pub fn apply_to_registry(
        &self,
        registry: &mut GenerationRegistry,
        timeline: MonotonicTimeline,
    ) -> Result<(), JobStateIntegrationError> {
        let anchor_ms = timeline.anchor_ms(self.anchor)?;
        registry.apply_snapshot(
            self.event_seq,
            self.current.as_ref(),
            &self.recent,
            anchor_ms,
        )?;
        Ok(())
    }
}

/// One bounded replay page from the authoritative backend journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    /// Exclusive cursor supplied by the caller.
    pub after_event_seq: u64,
    /// Cursor for the next page.
    pub next_event_seq: u64,
    /// Whether this page reached the durable journal end.
    pub complete: bool,
    /// Strictly ordered durable events for journal/accounting reconciliation.
    ///
    /// Replayed job events are historical facts, not fresh leases. Live job state
    /// must be initialized from the later [`JobSnapshot`] and then advanced only by
    /// [`DeliveredBackendEvent`] values.
    pub events: Vec<BackendEvent>,
}

/// Backend health and pending winner pressure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    /// Latest durable event sequence.
    pub event_seq: u64,
    /// Whether the backend reports that share acceptance is safe.
    pub healthy: bool,
    /// Pending Wcash winner submissions.
    pub pending_wcash: u32,
    /// Wcash winners held due to a conflicting AuxPoW witness.
    pub quarantined_wcash: u32,
    /// Pending Zcash winner submissions.
    pub pending_zcash: u32,
}

/// A connection, framing, correlation, identity, or backend response failure.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Configuration was invalid.
    #[error(transparent)]
    Config(#[from] ClientConfigError),
    /// Opening the local socket failed.
    #[error("failed to connect to backend Unix socket: {0}")]
    Connect(#[source] io::Error),
    /// A complete operation exceeded its deadline.
    #[error("backend {operation} exceeded its configured deadline")]
    Timeout {
        /// Operation that timed out.
        operation: &'static str,
    },
    /// Socket I/O failed.
    #[error("backend {operation} failed: {source}")]
    Io {
        /// I/O phase.
        operation: &'static str,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
    /// The peer closed cleanly between frames.
    #[error("backend closed the socket before replying")]
    CleanEof,
    /// The peer closed part-way through a length prefix or payload.
    #[error("backend frame ended during {section}: received {actual} of {expected} bytes")]
    TruncatedFrame {
        /// Frame section being read.
        section: &'static str,
        /// Required bytes.
        expected: usize,
        /// Bytes received before EOF.
        actual: usize,
    },
    /// A declared payload length exceeded the allocation limit.
    #[error("backend declared {actual} payload bytes; maximum is {maximum}")]
    FrameTooLarge {
        /// Declared payload bytes.
        actual: usize,
        /// Fixed protocol maximum.
        maximum: usize,
    },
    /// The strict protocol codec rejected a frame.
    #[error("invalid backend protocol message: {0}")]
    Protocol(#[from] ProtocolError),
    /// The peer declared a different protocol version.
    #[error("backend protocol version is {actual}; expected {expected}")]
    VersionMismatch {
        /// Required client version.
        expected: u16,
        /// Version found in the envelope.
        actual: u64,
    },
    /// A response did not correlate with the outstanding request.
    #[error("backend response ID is {actual}; expected {expected}")]
    WrongResponseId {
        /// Outstanding request ID.
        expected: u64,
        /// Received response ID.
        actual: u64,
    },
    /// A correlated response had the wrong semantic kind.
    #[error("backend returned {actual} while waiting for {expected}")]
    UnexpectedResponse {
        /// Required response kind.
        expected: &'static str,
        /// Received response kind.
        actual: &'static str,
    },
    /// Hello returned a network or persistent identity different from policy.
    #[error("backend hello did not match expected {field}")]
    IdentityMismatch {
        /// Mismatched identity field.
        field: &'static str,
    },
    /// The requested replay cursor cannot exist in this journal snapshot.
    #[error("pool event cursor {requested} is ahead of backend cursor {backend}")]
    EventCursorAhead {
        /// Cursor persisted by the pool.
        requested: u64,
        /// Cursor returned by hello.
        backend: u64,
    },
    /// A job snapshot predates the cursor supplied by the caller.
    #[error("backend job snapshot cursor {snapshot} is behind requested cursor {requested}")]
    SnapshotCursorBehind {
        /// Cursor supplied to `subscribe_jobs`.
        requested: u64,
        /// Snapshot watermark returned by the backend.
        snapshot: u64,
    },
    /// Replaying a nonzero cursor without its journal namespace could skip events.
    #[error("a nonzero event cursor requires an expected journal stream identity")]
    MissingJournalIdentity,
    /// An event page did not echo the requested exclusive cursor.
    #[error("backend event page cursor is {actual}; expected {expected}")]
    EventPageCursorMismatch {
        /// Cursor sent by the client.
        expected: u64,
        /// Cursor returned by the backend.
        actual: u64,
    },
    /// An event page exceeded the explicit request limit.
    #[error("backend event page contains {actual} events; requested at most {requested}")]
    EventPageLimitExceeded {
        /// Maximum events requested by the caller.
        requested: u16,
        /// Events returned by the backend.
        actual: usize,
    },
    /// An operation was attempted in the wrong replay/live phase.
    #[error("backend {operation} is not allowed during {actual:?}; required {required:?}")]
    InvalidStreamPhase {
        /// Operation rejected before any bytes were written.
        operation: &'static str,
        /// Required connection phase.
        required: BackendStreamPhase,
        /// Current connection phase.
        actual: BackendStreamPhase,
    },
    /// A caller attempted to skip or repeat part of this connection's replay.
    #[error("backend replay cursor is {actual}; expected {expected}")]
    ReplayCursorMismatch {
        /// Cursor tracked by the client.
        expected: u64,
        /// Cursor supplied by the caller.
        actual: u64,
    },
    /// Subscription was attempted before replay reached a durable journal end.
    #[error("backend replay is incomplete at event {cursor}; read pages before subscribing")]
    ReplayIncomplete {
        /// Last event replayed on this connection.
        cursor: u64,
    },
    /// A monotonic backend journal watermark moved backwards.
    #[error("backend {operation} event watermark regressed from {previous} to {received}")]
    EventWatermarkRollback {
        /// Response or operation whose watermark regressed.
        operation: &'static str,
        /// Greatest durable watermark previously observed.
        previous: u64,
        /// Regressing watermark.
        received: u64,
    },
    /// An unsolicited live event duplicated or skipped a journal sequence.
    #[error("backend live event sequence is {actual}; expected {expected}")]
    LiveEventSequenceMismatch {
        /// Next sequence after the accepted snapshot or prior live event.
        expected: u64,
        /// Sequence received from the backend.
        actual: u64,
    },
    /// A live response claimed a journal state whose events were not delivered first.
    #[error(
        "backend {operation} response requires live events through {required}; delivered through {delivered}"
    )]
    LiveEventFlushIncomplete {
        /// Response whose watermark was not flushed.
        operation: &'static str,
        /// Journal sequence the response depends on.
        required: u64,
        /// Greatest contiguous event delivered on this live connection.
        delivered: u64,
    },
    /// A share acknowledgement was not paired with its exact durable event.
    #[error(
        "backend share commit event {event_seq} did not exactly match the submitted share receipt"
    )]
    ShareCommitEventMismatch {
        /// Sequence claimed by the share receipt.
        event_seq: u64,
    },
    /// One canonical proof identity was associated with conflicting receipts.
    #[error(
        "backend share identity was already bound to event {recorded_event_seq}, not claimed event {claimed_event_seq}"
    )]
    ShareCommitHistoryConflict {
        /// Retained journal sequence carrying the same canonical share identity.
        recorded_event_seq: u64,
        /// Sequence claimed by the correlated response.
        claimed_event_seq: u64,
    },
    /// An old idempotent replay needs confirmation from the durable projector.
    #[error("historical share replay requires projected-receipt confirmation")]
    HistoricalReplayRequiresProjection {
        /// Exact response which the projector must match byte-for-byte.
        receipt: Box<ShareReceipt>,
    },
    /// A response labelled as a fresh commit reused an already observed sequence.
    #[error(
        "backend fresh share commit sequence {event_seq} did not advance past {previous_event_seq}"
    )]
    FreshShareCommitDidNotAdvance {
        /// Sequence claimed by the fresh receipt.
        event_seq: u64,
        /// Live event cursor before the submission began.
        previous_event_seq: u64,
    },
    /// The journal committed this exact share but its correlated response rejected it.
    #[error(
        "backend durably committed share event {event_seq} but returned a contradictory error"
    )]
    ContradictoryShareOutcome {
        /// Exact matching commit event observed before the error response.
        event_seq: u64,
    },
    /// The bounded unsolicited-event queue filled while awaiting a response.
    #[error("backend event queue reached its capacity of {capacity}")]
    EventQueueFull {
        /// Configured event capacity.
        capacity: usize,
    },
    /// The backend rejected a correctly correlated request.
    #[error("backend rejected request with {code:?}: {message}")]
    BackendRejected {
        /// Stable backend error category.
        code: BackendErrorCode,
        /// Bounded, protocol-validated operator detail.
        message: String,
    },
    /// A prior stream error left framing or correlation uncertain.
    #[error("backend connection is no longer usable; reconnect and reconcile events")]
    ConnectionUnusable,
    /// The connection-local request identifier space was exhausted.
    #[error("backend request identifier space exhausted")]
    RequestIdExhausted,
}

/// One timeout-bounded protocol-v1 connection to a local Unix socket.
pub struct BackendClient {
    stream: UnixStream,
    config: BackendClientConfig,
    identity: BackendIdentity,
    connection_token: Arc<()>,
    next_request_id: u64,
    queued_events: VecDeque<DeliveredBackendEvent>,
    observed_events: VecDeque<BackendEvent>,
    historical_events: VecDeque<BackendEvent>,
    phase: BackendStreamPhase,
    replay_cursor: u64,
    replay_complete: bool,
    observed_event_high_watermark: u64,
    live_event_cursor: Option<u64>,
    subscribed_snapshot_event_seq: Option<u64>,
    live_event_anchor_floor: Option<MonotonicAnchor>,
    usable: bool,
}

impl fmt::Debug for BackendClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendClient")
            .field("socket_path", &self.config.socket_path)
            .field("identity", &self.identity)
            .field("next_request_id", &self.next_request_id)
            .field("queued_events", &self.queued_events.len())
            .field("observed_events", &self.observed_events.len())
            .field("historical_events", &self.historical_events.len())
            .field("phase", &self.phase)
            .field("replay_cursor", &self.replay_cursor)
            .field("replay_complete", &self.replay_complete)
            .field(
                "observed_event_high_watermark",
                &self.observed_event_high_watermark,
            )
            .field("live_event_cursor", &self.live_event_cursor)
            .field(
                "subscribed_snapshot_event_seq",
                &self.subscribed_snapshot_event_seq,
            )
            .field("live_event_anchor_floor", &self.live_event_anchor_floor)
            .field("usable", &self.usable)
            .finish_non_exhaustive()
    }
}

impl BackendClient {
    /// Connects and completes the mandatory version and network hello.
    ///
    /// This verifies protocol identifiers supplied by the listener. It does not
    /// cryptographically authenticate the process behind the socket path.
    pub async fn connect(
        config: BackendClientConfig,
        pool_instance: CanonicalUuid,
        last_event_seq: u64,
    ) -> Result<Self, ClientError> {
        config.validate()?;
        if last_event_seq != 0 && config.expected.journal_stream.is_none() {
            return Err(ClientError::MissingJournalIdentity);
        }
        let stream = timeout(
            config.connect_timeout,
            UnixStream::connect(&config.socket_path),
        )
        .await
        .map_err(|_| ClientError::Timeout {
            operation: "connect",
        })?
        .map_err(ClientError::Connect)?;

        // The placeholder is replaced only after a validated hello. Keeping the
        // unverified values private prevents callers observing them on failure.
        let placeholder = BackendIdentity {
            backend_session: pool_instance,
            backend_instance: pool_instance,
            journal_stream: pool_instance,
            capabilities: Vec::new(),
            current_event_seq: 0,
        };
        let mut client = Self {
            stream,
            config,
            identity: placeholder,
            connection_token: Arc::new(()),
            next_request_id: 1,
            queued_events: VecDeque::new(),
            observed_events: VecDeque::new(),
            historical_events: VecDeque::new(),
            phase: BackendStreamPhase::Replay,
            replay_cursor: last_event_seq,
            replay_complete: false,
            observed_event_high_watermark: 0,
            live_event_cursor: None,
            subscribed_snapshot_event_seq: None,
            live_event_anchor_floor: None,
            usable: true,
        };
        let request_id = client.allocate_request_id()?;
        let (response, _) = client
            .exchange(
                BackendRequest::Hello {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: request_id,
                    pool_instance,
                    last_event_seq,
                },
                "hello",
                false,
            )
            .await?;

        match response {
            BackendMessage::HelloOk {
                backend_session,
                backend_instance,
                journal_stream,
                capabilities,
                wcash_genesis,
                zcash_genesis,
                chain_id,
                current_event_seq,
                ..
            } => {
                client.verify_hello(
                    &backend_instance,
                    &journal_stream,
                    &wcash_genesis,
                    &zcash_genesis,
                    chain_id,
                    last_event_seq,
                    current_event_seq,
                )?;
                client.identity = BackendIdentity {
                    backend_session,
                    backend_instance,
                    journal_stream,
                    capabilities,
                    current_event_seq,
                };
                client.observed_event_high_watermark = current_event_seq;
                client.replay_complete = last_event_seq == current_event_seq;
                Ok(client)
            }
            BackendMessage::Error { code, message, .. } => {
                Err(ClientError::BackendRejected { code, message })
            }
            other => Err(client.invalidate(ClientError::UnexpectedResponse {
                expected: "hello_ok",
                actual: message_kind(&other),
            })),
        }
    }

    /// Returns the validated backend and journal identity for persistence.
    pub fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    /// Returns whether this connection is replaying history or consuming live events.
    pub const fn stream_phase(&self) -> BackendStreamPhase {
        self.phase
    }

    /// Returns whether framing and request correlation remain trustworthy.
    pub const fn is_usable(&self) -> bool {
        self.usable
    }

    /// Returns whether this is the exact live connection that produced `binding`.
    pub fn is_bound_to(&self, binding: &BackendConnectionBinding) -> bool {
        self.phase == BackendStreamPhase::Live
            && self.authority() == binding.authority
            && self.subscribed_snapshot_event_seq == Some(binding.snapshot_event_seq)
            && Arc::ptr_eq(&self.connection_token, &binding.connection_token)
    }

    /// Returns the opaque binding for this client's established live snapshot.
    pub fn connection_binding(&self) -> Option<BackendConnectionBinding> {
        let snapshot_event_seq = self.subscribed_snapshot_event_seq?;
        (self.phase == BackendStreamPhase::Live).then(|| BackendConnectionBinding {
            authority: self.authority(),
            connection_token: Arc::clone(&self.connection_token),
            snapshot_event_seq,
        })
    }

    /// Returns the contiguous live journal cursor observed on this connection.
    pub const fn live_event_cursor(&self) -> Option<u64> {
        self.live_event_cursor
    }

    /// Returns the last journal sequence replayed on this connection.
    pub const fn replay_cursor(&self) -> u64 {
        self.replay_cursor
    }

    /// Returns the number of unsolicited events waiting in memory.
    pub fn queued_event_count(&self) -> usize {
        self.queued_events.len()
    }

    /// Removes the oldest unsolicited durable event without performing I/O.
    ///
    /// Protocol v1 reads only inside bounded request exchanges. Once subscribed,
    /// callers must issue periodic `health` requests as their heartbeat; events
    /// received before that correlated response are queued here. This avoids
    /// cancelling a partially read frame merely because a healthy chain is quiet.
    pub fn pop_queued_event(&mut self) -> Option<DeliveredBackendEvent> {
        let delivered = self.queued_events.pop_front()?;
        if self.observed_events.len() == self.config.event_queue_capacity {
            self.observed_events.pop_front();
        }
        self.observed_events.push_back(delivered.event().clone());
        Some(delivered)
    }

    /// Requests an atomic current/recent job snapshot, then irreversibly enters live mode.
    ///
    /// Replay must first reach a page marked complete, and `after_event_seq` must be
    /// the client's exact replay cursor. Unsolicited events before the correlated
    /// snapshot are a protocol violation.
    pub async fn subscribe_jobs(
        &mut self,
        after_event_seq: u64,
    ) -> Result<JobSnapshot, ClientError> {
        self.ensure_phase("subscribe_jobs", BackendStreamPhase::Replay)?;
        if after_event_seq != self.replay_cursor {
            return Err(ClientError::ReplayCursorMismatch {
                expected: self.replay_cursor,
                actual: after_event_seq,
            });
        }
        if !self.replay_complete {
            return Err(ClientError::ReplayIncomplete {
                cursor: self.replay_cursor,
            });
        }
        let request_id = self.allocate_request_id()?;
        let (response, anchor) = self
            .exchange(
                BackendRequest::SubscribeJobs {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: request_id,
                    after_event_seq,
                },
                "subscribe_jobs",
                false,
            )
            .await?;
        match response {
            BackendMessage::JobSnapshot {
                event_seq,
                current,
                recent,
                ..
            } => {
                if event_seq < after_event_seq {
                    return Err(self.invalidate(ClientError::SnapshotCursorBehind {
                        requested: after_event_seq,
                        snapshot: event_seq,
                    }));
                }
                self.observe_watermark("job snapshot", event_seq)?;
                self.live_event_cursor = Some(event_seq);
                self.subscribed_snapshot_event_seq = Some(event_seq);
                // A later live event might already be waiting in the socket before
                // the next request begins. This pre-subscription request anchor is
                // therefore the conservative lower bound for that event's lease.
                self.live_event_anchor_floor = Some(anchor);
                self.phase = BackendStreamPhase::Live;
                let connection_binding = BackendConnectionBinding {
                    authority: self.authority(),
                    connection_token: Arc::clone(&self.connection_token),
                    snapshot_event_seq: event_seq,
                };
                Ok(JobSnapshot {
                    event_seq,
                    current,
                    recent,
                    replayed_through_event_seq: after_event_seq,
                    anchor,
                    connection_binding,
                })
            }
            BackendMessage::Error { code, message, .. } => {
                Err(ClientError::BackendRejected { code, message })
            }
            other => Err(self.invalidate(ClientError::UnexpectedResponse {
                expected: "job_snapshot",
                actual: message_kind(&other),
            })),
        }
    }

    /// Exchanges one freely constructed share with the backend.
    ///
    /// Its response is deliberately unverified because no retained generation is
    /// available to authenticate winner reward facts. Production orchestration
    /// must call [`Self::submit_prepared_share`] so those facts are job-bound and
    /// the core generation-admission fence remains alive for the complete exchange.
    pub async fn submit_share(
        &mut self,
        submission: ShareSubmission,
    ) -> Result<UnverifiedShareCommit, ClientError> {
        self.ensure_phase("submit_share", BackendStreamPhase::Live)?;
        let live_cursor_before = match self.live_event_cursor {
            Some(cursor) => cursor,
            None => {
                return Err(self.invalidate(ClientError::UnexpectedResponse {
                    expected: "job_snapshot",
                    actual: "live share submission",
                }));
            }
        };
        let submitted_job_id = submission.job_id.clone();
        let submitted_identity = submission.identity.clone();
        let submitted_target_le = submission.target_le.clone();
        let expected_attribution_id =
            canonical_attribution_id(&submission.identity, &submission.target_le)?;
        let expected_share_id = canonical_share_id(
            &submission.job_id,
            &submission.time,
            &submission.nonce,
            &submission.solution,
        );
        let request_id = self.allocate_request_id()?;
        let (response, _) = self
            .exchange(
                BackendRequest::SubmitShare {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: request_id,
                    job_id: submission.job_id,
                    identity: submission.identity,
                    target_le: submission.target_le,
                    time: submission.time,
                    nonce: submission.nonce,
                    solution: Box::new(submission.solution),
                },
                "submit_share",
                true,
            )
            .await?;
        match response {
            BackendMessage::ShareCommitted {
                receipt, replayed, ..
            } => {
                if receipt.job_id != submitted_job_id {
                    return Err(self.invalidate(ClientError::Protocol(
                        ProtocolError::InvalidField {
                            field: "share_receipt.job_id",
                            reason: "must match the submitted backend generation".to_owned(),
                        },
                    )));
                }
                if receipt.share_id != expected_share_id {
                    return Err(self.invalidate(ClientError::Protocol(
                        ProtocolError::InvalidField {
                            field: "share_receipt.share_id",
                            reason: "must match the canonical submitted proof identity".to_owned(),
                        },
                    )));
                }
                if receipt.attribution_id != expected_attribution_id {
                    return Err(self.invalidate(ClientError::Protocol(
                        ProtocolError::InvalidField {
                            field: "share_receipt.attribution_id",
                            reason: "must match the submitted worker identity and target"
                                .to_owned(),
                        },
                    )));
                }
                if !replayed && receipt.event_seq <= live_cursor_before {
                    return Err(self.invalidate(ClientError::FreshShareCommitDidNotAdvance {
                        event_seq: receipt.event_seq,
                        previous_event_seq: live_cursor_before,
                    }));
                }
                self.require_live_events_through("share commit", receipt.event_seq)?;
                self.require_consistent_share_history(
                    &receipt,
                    &submitted_identity,
                    &submitted_target_le,
                )?;
                self.require_matching_share_event(
                    &receipt,
                    &submitted_identity,
                    &submitted_target_le,
                    live_cursor_before,
                    replayed,
                )?;
                Ok(UnverifiedShareCommit { receipt, replayed })
            }
            BackendMessage::Error { code, message, .. } => {
                if let Some(event_seq) = self.matching_share_event_seq(
                    &submitted_job_id,
                    &expected_share_id,
                    &expected_attribution_id,
                    &submitted_identity,
                    &submitted_target_le,
                ) {
                    return Err(
                        self.invalidate(ClientError::ContradictoryShareOutcome { event_seq })
                    );
                }
                Err(ClientError::BackendRejected { code, message })
            }
            other => Err(self.invalidate(ClientError::UnexpectedResponse {
                expected: "share_committed",
                actual: message_kind(&other),
            })),
        }
    }

    /// Submits a core-validated share while retaining its generation fence.
    ///
    /// Ownership of `context` is held until the response, rejection, timeout, or
    /// cancellation resolves. This prevents local generation resources from being
    /// retired between field extraction and the backend I/O boundary.
    pub async fn submit_prepared_share(
        &mut self,
        context: SubmissionContext,
    ) -> Result<VerifiedShareCommit, ClientError> {
        let descriptor = context.generation().descriptor().clone();
        let expected_parent_hash_le = canonical_parent_header_hash_le(
            &descriptor.header_input,
            context.nonce(),
            context.solution(),
        );
        let submission = ShareSubmission {
            job_id: context.job_id(),
            identity: context.identity().clone(),
            target_le: context.target_le().clone(),
            time: context.time().clone(),
            nonce: context.nonce().clone(),
            solution: context.solution().clone(),
        };
        let result = match self.submit_share(submission).await {
            Ok(commit) => {
                self.validate_receipt_for_job(
                    commit.receipt(),
                    &descriptor,
                    &expected_parent_hash_le,
                )?;
                Ok(VerifiedShareCommit {
                    receipt: commit.receipt,
                    replayed: commit.replayed,
                })
            }
            Err(ClientError::HistoricalReplayRequiresProjection { receipt }) => {
                self.validate_receipt_for_job(&receipt, &descriptor, &expected_parent_hash_le)?;
                Err(ClientError::HistoricalReplayRequiresProjection { receipt })
            }
            Err(error) => Err(error),
        };
        drop(context);
        result
    }

    /// Reads one bounded, authoritative journal page before live subscription.
    ///
    /// Pages must be consumed contiguously from [`Self::replay_cursor`]. This method
    /// is rejected after [`Self::subscribe_jobs`] succeeds, preventing one journal
    /// event from arriving through both paginated and unsolicited paths.
    pub async fn read_events(
        &mut self,
        after_event_seq: u64,
        limit: u16,
    ) -> Result<EventPage, ClientError> {
        self.ensure_phase("read_events", BackendStreamPhase::Replay)?;
        if !(1..=MAX_EVENT_PAGE_ITEMS).contains(&limit) {
            return Err(ClientError::Protocol(ProtocolError::InvalidField {
                field: "read_events.limit",
                reason: format!("must be in 1..={MAX_EVENT_PAGE_ITEMS}"),
            }));
        }
        if after_event_seq != self.replay_cursor {
            return Err(ClientError::ReplayCursorMismatch {
                expected: self.replay_cursor,
                actual: after_event_seq,
            });
        }
        let request_id = self.allocate_request_id()?;
        let (response, _) = self
            .exchange(
                BackendRequest::ReadEvents {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: request_id,
                    after_event_seq,
                    limit,
                },
                "read_events",
                false,
            )
            .await?;
        match response {
            BackendMessage::EventsPage {
                after_event_seq: response_cursor,
                next_event_seq,
                complete,
                events,
                ..
            } => {
                if response_cursor != after_event_seq {
                    return Err(self.invalidate(ClientError::EventPageCursorMismatch {
                        expected: after_event_seq,
                        actual: response_cursor,
                    }));
                }
                if events.len() > usize::from(limit) {
                    return Err(self.invalidate(ClientError::EventPageLimitExceeded {
                        requested: limit,
                        actual: events.len(),
                    }));
                }
                if complete {
                    self.observe_watermark("completed event replay", next_event_seq)?;
                } else {
                    self.observed_event_high_watermark =
                        self.observed_event_high_watermark.max(next_event_seq);
                }
                self.replay_cursor = next_event_seq;
                self.replay_complete = complete;
                self.remember_historical_events(&events);
                Ok(EventPage {
                    after_event_seq: response_cursor,
                    next_event_seq,
                    complete,
                    events,
                })
            }
            BackendMessage::Error { code, message, .. } => {
                Err(ClientError::BackendRejected { code, message })
            }
            other => Err(self.invalidate(ClientError::UnexpectedResponse {
                expected: "events_page",
                actual: message_kind(&other),
            })),
        }
    }

    /// Reads backend health; callers must stop share intake when `healthy` is false.
    pub async fn health(&mut self) -> Result<HealthSnapshot, ClientError> {
        let request_id = self.allocate_request_id()?;
        let allow_events = self.phase == BackendStreamPhase::Live;
        let (response, _) = self
            .exchange(
                BackendRequest::Health {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: request_id,
                },
                "health",
                allow_events,
            )
            .await?;
        match response {
            BackendMessage::HealthStatus {
                event_seq,
                healthy,
                pending_wcash,
                quarantined_wcash,
                pending_zcash,
                ..
            } => {
                self.observe_watermark("health", event_seq)?;
                self.require_live_events_through("health", event_seq)?;
                Ok(HealthSnapshot {
                    event_seq,
                    healthy,
                    pending_wcash,
                    quarantined_wcash,
                    pending_zcash,
                })
            }
            BackendMessage::Error { code, message, .. } => {
                Err(ClientError::BackendRejected { code, message })
            }
            other => Err(self.invalidate(ClientError::UnexpectedResponse {
                expected: "health_status",
                actual: message_kind(&other),
            })),
        }
    }

    /// Shuts down the write half within the configured deadline.
    pub async fn shutdown(mut self) -> Result<(), ClientError> {
        self.ensure_usable()?;
        timeout(self.config.request_timeout, self.stream.shutdown())
            .await
            .map_err(|_| ClientError::Timeout {
                operation: "shutdown",
            })?
            .map_err(|source| ClientError::Io {
                operation: "shutdown",
                source,
            })
    }

    async fn exchange(
        &mut self,
        request: BackendRequest,
        operation: &'static str,
        allow_events: bool,
    ) -> Result<(BackendMessage, MonotonicAnchor), ClientError> {
        self.ensure_usable()?;
        let request_id = request.id();
        let frame = encode_backend_request(&request)?;
        let deadline = self.config.request_timeout;
        let capacity = self.config.event_queue_capacity;
        let anchor = MonotonicAnchor(Instant::now());
        let (event_anchor, event_binding) = if allow_events {
            match (self.live_event_anchor_floor, self.connection_binding()) {
                (Some(anchor), Some(binding)) => (anchor, Some(binding)),
                _ => {
                    return Err(self.invalidate(ClientError::UnexpectedResponse {
                        expected: "job_snapshot",
                        actual: "live event exchange",
                    }));
                }
            }
        } else {
            (anchor, None)
        };

        // From the first I/O poll until a correlated response is decoded, dropping
        // this future must poison the connection. Rust futures are cancellation-safe
        // only where explicitly designed: a cancelled write may have sent a prefix,
        // and a cancelled read may have consumed part of a response frame.
        self.usable = false;
        let result = timeout(deadline, async {
            self.stream
                .write_all(&frame)
                .await
                .map_err(|source| ClientError::Io {
                    operation: "write request",
                    source,
                })?;
            loop {
                let message = read_backend_message(&mut self.stream).await?;
                if let BackendMessage::Event { event, .. } = message {
                    if !allow_events {
                        return Err(ClientError::UnexpectedResponse {
                            expected: expected_response_kind(operation),
                            actual: "event",
                        });
                    }
                    let actual = event.event_seq();
                    let previous =
                        self.live_event_cursor
                            .ok_or(ClientError::UnexpectedResponse {
                                expected: "job_snapshot",
                                actual: "event",
                            })?;
                    let expected = previous.checked_add(1).ok_or_else(|| {
                        ClientError::Protocol(ProtocolError::InvalidField {
                            field: "event.event_seq",
                            reason: "journal sequence exhausted".to_owned(),
                        })
                    })?;
                    if actual != expected {
                        return Err(ClientError::LiveEventSequenceMismatch { expected, actual });
                    }
                    if self.queued_events.len() == capacity {
                        return Err(ClientError::EventQueueFull { capacity });
                    }
                    self.live_event_cursor = Some(actual);
                    self.observed_event_high_watermark =
                        self.observed_event_high_watermark.max(actual);
                    let connection_binding =
                        event_binding
                            .clone()
                            .ok_or(ClientError::UnexpectedResponse {
                                expected: "job_snapshot",
                                actual: "unbound live event",
                            })?;
                    self.queued_events.push_back(DeliveredBackendEvent {
                        event,
                        anchor: event_anchor,
                        connection_binding,
                    });
                    continue;
                }
                let response_id =
                    message
                        .correlation_id()
                        .ok_or(ClientError::UnexpectedResponse {
                            expected: "correlated response",
                            actual: message_kind(&message),
                        })?;
                if response_id != request_id {
                    return Err(ClientError::WrongResponseId {
                        expected: request_id,
                        actual: response_id,
                    });
                }
                return Ok(message);
            }
        })
        .await;

        match result {
            Ok(Ok(message)) => {
                if allow_events {
                    // Any event left for a later exchange cannot predate this
                    // request. Advancing only after a correlated response ensures
                    // time spent idle in the socket can shorten, never extend, a
                    // backend-authenticated generation lifetime.
                    self.live_event_anchor_floor = Some(anchor);
                }
                self.usable = true;
                Ok((message, anchor))
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(ClientError::Timeout { operation }),
        }
    }

    fn allocate_request_id(&mut self) -> Result<u64, ClientError> {
        self.ensure_usable()?;
        let current = self.next_request_id;
        self.next_request_id = current
            .checked_add(1)
            .ok_or_else(|| self.invalidate(ClientError::RequestIdExhausted))?;
        Ok(current)
    }

    fn validate_receipt_for_job(
        &mut self,
        receipt: &ShareReceipt,
        descriptor: &JobDescriptor,
        expected_parent_hash_le: &Hex32,
    ) -> Result<(), ClientError> {
        if let Err(error) = receipt.validate_for_job(descriptor) {
            return Err(self.invalidate(ClientError::Protocol(error)));
        }
        if &receipt.parent_hash_le != expected_parent_hash_le {
            return Err(
                self.invalidate(ClientError::Protocol(ProtocolError::InvalidField {
                    field: "share_receipt.parent_hash_le",
                    reason: "must match the exact submitted parent header".to_owned(),
                })),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_hello(
        &mut self,
        backend_instance: &CanonicalUuid,
        journal_stream: &CanonicalUuid,
        wcash_genesis: &Hex32,
        zcash_genesis: &Hex32,
        chain_id: u32,
        last_event_seq: u64,
        current_event_seq: u64,
    ) -> Result<(), ClientError> {
        if wcash_genesis != &self.config.expected.wcash_genesis {
            return Err(self.invalidate(ClientError::IdentityMismatch {
                field: "Wcash genesis",
            }));
        }
        if zcash_genesis != &self.config.expected.zcash_genesis {
            return Err(self.invalidate(ClientError::IdentityMismatch {
                field: "Zcash genesis",
            }));
        }
        if chain_id != self.config.expected.chain_id {
            return Err(self.invalidate(ClientError::IdentityMismatch {
                field: "Wcash chain ID",
            }));
        }
        if self
            .config
            .expected
            .backend_instance
            .as_ref()
            .is_some_and(|expected| expected != backend_instance)
        {
            return Err(self.invalidate(ClientError::IdentityMismatch {
                field: "backend instance",
            }));
        }
        if self
            .config
            .expected
            .journal_stream
            .as_ref()
            .is_some_and(|expected| expected != journal_stream)
        {
            return Err(self.invalidate(ClientError::IdentityMismatch {
                field: "journal stream",
            }));
        }
        if last_event_seq > current_event_seq {
            return Err(self.invalidate(ClientError::EventCursorAhead {
                requested: last_event_seq,
                backend: current_event_seq,
            }));
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), ClientError> {
        if self.usable {
            Ok(())
        } else {
            Err(ClientError::ConnectionUnusable)
        }
    }

    fn authority(&self) -> BackendAuthority {
        BackendAuthority {
            wcash_genesis: self.config.expected.wcash_genesis.clone(),
            zcash_genesis: self.config.expected.zcash_genesis.clone(),
            chain_id: self.config.expected.chain_id,
            backend_instance: self.identity.backend_instance,
            journal_stream: self.identity.journal_stream,
        }
    }

    fn ensure_phase(
        &self,
        operation: &'static str,
        required: BackendStreamPhase,
    ) -> Result<(), ClientError> {
        self.ensure_usable()?;
        if self.phase == required {
            Ok(())
        } else {
            Err(ClientError::InvalidStreamPhase {
                operation,
                required,
                actual: self.phase,
            })
        }
    }

    fn observe_watermark(
        &mut self,
        operation: &'static str,
        received: u64,
    ) -> Result<(), ClientError> {
        if received < self.observed_event_high_watermark {
            let error = ClientError::EventWatermarkRollback {
                operation,
                previous: self.observed_event_high_watermark,
                received,
            };
            return Err(self.invalidate(error));
        }
        self.observed_event_high_watermark = received;
        if self.phase == BackendStreamPhase::Replay && received > self.replay_cursor {
            self.replay_complete = false;
        }
        Ok(())
    }

    /// Requires a live response to follow every event through its journal watermark.
    ///
    /// A replay-phase health request has no live stream and is checked by normal
    /// replay/snapshot reconciliation instead. Once subscribed, accepting a response
    /// ahead of the contiguous live cursor could expose stale generations or return a
    /// share acknowledgement before its durable accounting event is observable.
    fn require_live_events_through(
        &mut self,
        operation: &'static str,
        required: u64,
    ) -> Result<(), ClientError> {
        if self.phase != BackendStreamPhase::Live {
            return Ok(());
        }
        let delivered = self.live_event_cursor.ok_or_else(|| {
            self.invalidate(ClientError::UnexpectedResponse {
                expected: "job_snapshot",
                actual: "live response",
            })
        })?;
        if delivered < required {
            return Err(self.invalidate(ClientError::LiveEventFlushIncomplete {
                operation,
                required,
                delivered,
            }));
        }
        Ok(())
    }

    /// Binds a share response to the exact journal event delivered on this stream.
    ///
    /// A fresh commit must always advance the pre-request live cursor. An idempotent
    /// replay can be certified here only while its exact event remains in the live
    /// cache. Once that event is evicted, a durable projector must confirm the
    /// complete receipt before any miner success or accounting credit is authorized.
    fn require_matching_share_event(
        &mut self,
        receipt: &ShareReceipt,
        identity: &WorkerIdentity,
        target_le: &TargetLe,
        live_cursor_before: u64,
        replayed: bool,
    ) -> Result<(), ClientError> {
        let live_match = self
            .queued_events
            .iter()
            .map(DeliveredBackendEvent::event)
            .chain(self.observed_events.iter())
            .any(|event| {
                event.event_seq() == receipt.event_seq
                    && share_event_matches(event, receipt, identity, target_le)
            });
        match live_match {
            true => Ok(()),
            false if replayed && receipt.event_seq <= live_cursor_before => {
                Err(ClientError::HistoricalReplayRequiresProjection {
                    receipt: Box::new(receipt.clone()),
                })
            }
            false => Err(self.invalidate(ClientError::ShareCommitEventMismatch {
                event_seq: receipt.event_seq,
            })),
        }
    }

    /// Rejects sequence reuse and share re-journaling while evidence is retained.
    ///
    /// A canonical share ID is the idempotency key. It may name exactly one byte-
    /// identical durable receipt at exactly one sequence. Retaining every event kind
    /// also prevents a response from claiming a sequence already occupied by a job
    /// or winner event. Evicted history is delegated to the durable projector, which
    /// must gate accounting and payout in a production deployment.
    fn require_consistent_share_history(
        &mut self,
        receipt: &ShareReceipt,
        identity: &WorkerIdentity,
        target_le: &TargetLe,
    ) -> Result<(), ClientError> {
        let mut sequence_conflict = false;
        let mut share_conflict = None;
        for event in self
            .queued_events
            .iter()
            .map(DeliveredBackendEvent::event)
            .chain(self.observed_events.iter())
            .chain(self.historical_events.iter())
        {
            let exact_match = share_event_matches(event, receipt, identity, target_le);
            if event.event_seq() == receipt.event_seq && !exact_match {
                sequence_conflict = true;
                break;
            }
            if let BackendEvent::ShareCommitted {
                receipt: recorded_receipt,
                ..
            } = event
            {
                if recorded_receipt.share_id == receipt.share_id && !exact_match {
                    share_conflict = Some(recorded_receipt.event_seq);
                    break;
                }
            }
        }

        if sequence_conflict {
            return Err(self.invalidate(ClientError::ShareCommitEventMismatch {
                event_seq: receipt.event_seq,
            }));
        }
        if let Some(recorded_event_seq) = share_conflict {
            return Err(self.invalidate(ClientError::ShareCommitHistoryConflict {
                recorded_event_seq,
                claimed_event_seq: receipt.event_seq,
            }));
        }
        Ok(())
    }

    fn matching_share_event_seq(
        &self,
        job_id: &Hex32,
        share_id: &Hex32,
        attribution_id: &Hex32,
        identity: &WorkerIdentity,
        target_le: &TargetLe,
    ) -> Option<u64> {
        self.queued_events
            .iter()
            .map(DeliveredBackendEvent::event)
            .chain(self.observed_events.iter())
            // Replay evidence can prove that a later rejection contradicts the
            // journal, but it must never authorize a replayed miner success. The
            // latter requires the live cache or durable projector confirmation in
            // `require_matching_share_event`.
            .chain(self.historical_events.iter())
            .find_map(|event| match event {
                BackendEvent::ShareCommitted {
                    receipt,
                    job_id: event_job_id,
                    identity: event_identity,
                    target_le: event_target_le,
                } if event_job_id == job_id
                    && &receipt.job_id == job_id
                    && &receipt.share_id == share_id
                    && &receipt.attribution_id == attribution_id
                    && event_identity == identity
                    && event_target_le == target_le =>
                {
                    Some(receipt.event_seq)
                }
                _ => None,
            })
    }

    fn remember_historical_events(&mut self, events: &[BackendEvent]) {
        for event in events {
            if self.historical_events.len() == self.config.event_queue_capacity {
                self.historical_events.pop_front();
            }
            self.historical_events.push_back(event.clone());
        }
    }

    fn invalidate(&mut self, error: ClientError) -> ClientError {
        self.usable = false;
        error
    }
}

fn share_event_matches(
    event: &BackendEvent,
    receipt: &ShareReceipt,
    identity: &WorkerIdentity,
    target_le: &TargetLe,
) -> bool {
    matches!(
        event,
        BackendEvent::ShareCommitted {
            receipt: event_receipt,
            job_id,
            identity: event_identity,
            target_le: event_target_le,
        } if event_receipt == receipt
            && job_id == &receipt.job_id
            && event_identity == identity
            && event_target_le == target_le
    )
}

fn validate_socket_path(path: &Path) -> Result<(), ClientConfigError> {
    let encoded = path.as_os_str().as_bytes();
    if encoded.is_empty() {
        return Err(ClientConfigError::EmptySocketPath);
    }
    if !path.is_absolute() {
        return Err(ClientConfigError::RelativeSocketPath);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ClientConfigError::NonCanonicalSocketPath);
    }
    if encoded.contains(&0) {
        return Err(ClientConfigError::SocketPathContainsNul);
    }
    if encoded.len() > MAX_SOCKET_PATH_BYTES {
        return Err(ClientConfigError::SocketPathTooLong {
            actual: encoded.len(),
            maximum: MAX_SOCKET_PATH_BYTES,
        });
    }
    Ok(())
}

fn validate_timeout(field: &'static str, duration: Duration) -> Result<(), ClientConfigError> {
    if duration.is_zero() || duration > MAX_TIMEOUT {
        Err(ClientConfigError::InvalidTimeout { field })
    } else {
        Ok(())
    }
}

async fn read_backend_message(stream: &mut UnixStream) -> Result<BackendMessage, ClientError> {
    let mut prefix = [0_u8; BACKEND_LENGTH_PREFIX_BYTES];
    read_exact_section(stream, &mut prefix, "length prefix", true).await?;
    let payload_length = u32::from_be_bytes(prefix) as usize;
    if payload_length == 0 {
        return Err(ClientError::Protocol(ProtocolError::EmptyFrame {
            protocol: "backend",
        }));
    }
    if payload_length > MAX_BACKEND_PAYLOAD_BYTES {
        return Err(ClientError::FrameTooLarge {
            actual: payload_length,
            maximum: MAX_BACKEND_PAYLOAD_BYTES,
        });
    }
    let mut payload = vec![0_u8; payload_length];
    read_exact_section(stream, &mut payload, "payload", false).await?;

    let value: Value =
        serde_json::from_slice(&payload).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if let Some(actual) = value.get("v").and_then(Value::as_u64) {
        if actual != u64::from(BACKEND_PROTOCOL_VERSION) {
            return Err(ClientError::VersionMismatch {
                expected: BACKEND_PROTOCOL_VERSION,
                actual,
            });
        }
    }

    let mut frame = Vec::with_capacity(BACKEND_LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&payload);
    decode_backend_message(&frame).map_err(ClientError::from)
}

async fn read_exact_section(
    stream: &mut UnixStream,
    destination: &mut [u8],
    section: &'static str,
    clean_eof_allowed: bool,
) -> Result<(), ClientError> {
    let mut offset = 0;
    while offset < destination.len() {
        match stream.read(&mut destination[offset..]).await {
            Ok(0) if clean_eof_allowed && offset == 0 => return Err(ClientError::CleanEof),
            Ok(0) => {
                return Err(ClientError::TruncatedFrame {
                    section,
                    expected: destination.len(),
                    actual: offset,
                })
            }
            Ok(read) => offset += read,
            Err(source) => {
                return Err(ClientError::Io {
                    operation: "read response",
                    source,
                })
            }
        }
    }
    Ok(())
}

fn message_kind(message: &BackendMessage) -> &'static str {
    match message {
        BackendMessage::HelloOk { .. } => "hello_ok",
        BackendMessage::JobSnapshot { .. } => "job_snapshot",
        BackendMessage::ShareCommitted { .. } => "share_committed",
        BackendMessage::EventsPage { .. } => "events_page",
        BackendMessage::HealthStatus { .. } => "health_status",
        BackendMessage::Error { .. } => "error",
        BackendMessage::Event { .. } => "event",
    }
}

fn expected_response_kind(operation: &'static str) -> &'static str {
    match operation {
        "hello" => "hello_ok",
        "subscribe_jobs" => "job_snapshot",
        "submit_share" => "share_committed",
        "read_events" => "events_page",
        "health" => "health_status",
        _ => "correlated response",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        ffi::OsStr,
        fs,
        future::pending,
        os::unix::ffi::OsStrExt,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::oneshot,
    };
    use wcash_pool_core::{
        AuthenticatedWorker, GenerationRegistry, GenerationRegistryConfig, JobAssignment,
        NonceNamespaceLease, NoncePrefixAllocator, ShareTarget, TargetBinding, TargetBounds,
    };
    use wcash_pool_protocol::{
        canonical_attribution_id, canonical_parent_header_hash_le, canonical_share_id,
        decode_backend_request, encode_backend_message, AcceptableJob, BackendCapability,
        BackendErrorCode, BackendEvent, BackendMessage, BackendRequest, CanonicalUuid, Hex108,
        Hex1344, Hex28, Hex32, Hex4, JobDescriptor, MergedChain, NonceProfile, NonceSuffix,
        ProtocolError, ShareReceipt, TargetLe, WinnerDescriptor, WorkerIdentity,
        BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, MAX_BACKEND_PAYLOAD_BYTES,
    };

    use super::{
        BackendClient, BackendClientConfig, BackendStreamPhase, ClientConfigError, ClientError,
        ExpectedBackend, MonotonicTimeline, ShareSubmission,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    static SOCKET_ID: AtomicU64 = AtomicU64::new(1);

    struct TestSocket {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestSocket {
        fn new() -> TestResult<Self> {
            let id = SOCKET_ID.fetch_add(1, Ordering::Relaxed);
            let directory = PathBuf::from("/tmp").join(format!("wcp-{}-{id}", std::process::id()));
            fs::create_dir(&directory)?;
            let path = directory.join("backend.sock");
            Ok(Self { directory, path })
        }
    }

    impl Drop for TestSocket {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[allow(clippy::expect_used)]
    fn uuid(byte: u8) -> CanonicalUuid {
        let hex = format!("{byte:02x}").repeat(16);
        let encoded = format!(
            "\"{}-{}-{}-{}-{}\"",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        );
        serde_json::from_str(&encoded).expect("test UUID is canonical")
    }

    fn required_capabilities() -> Vec<BackendCapability> {
        vec![
            BackendCapability::JobStreamV1,
            BackendCapability::DurableShareReceiptsV1,
            BackendCapability::EventReplayV1,
            BackendCapability::DualTargetV1,
            BackendCapability::WinnerLifecycleV1,
        ]
    }

    fn expected_backend() -> TestResult<ExpectedBackend> {
        Ok(
            ExpectedBackend::new(Hex32::new([0x11; 32]), Hex32::new([0x22; 32]), 0x5743_4153)?
                .with_backend_instance(uuid(2))
                .with_journal_stream(uuid(3)),
        )
    }

    fn config(path: &Path) -> TestResult<BackendClientConfig> {
        Ok(BackendClientConfig::new(path, expected_backend()?)?
            .with_timeouts(Duration::from_secs(1), Duration::from_secs(1))?)
    }

    fn hello_ok(id: u64) -> BackendMessage {
        BackendMessage::HelloOk {
            version: BACKEND_PROTOCOL_VERSION,
            id,
            backend_session: uuid(1),
            backend_instance: uuid(2),
            journal_stream: uuid(3),
            capabilities: required_capabilities(),
            wcash_genesis: Hex32::new([0x11; 32]),
            zcash_genesis: Hex32::new([0x22; 32]),
            chain_id: 0x5743_4153,
            current_event_seq: 10,
        }
    }

    async fn read_request(stream: &mut UnixStream) -> TestResult<BackendRequest> {
        let mut prefix = [0_u8; BACKEND_LENGTH_PREFIX_BYTES];
        stream.read_exact(&mut prefix).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await?;
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&payload);
        Ok(decode_backend_request(&frame)?)
    }

    async fn write_message(stream: &mut UnixStream, message: &BackendMessage) -> TestResult {
        stream.write_all(&encode_backend_message(message)?).await?;
        Ok(())
    }

    /// Writes the durable event before its correlated acknowledgement, matching
    /// the backend-v1 live-stream flush contract. Exact replays reuse the original
    /// receipt and therefore do not append or redeliver another event.
    async fn write_share_commit(
        stream: &mut UnixStream,
        id: u64,
        receipt: ShareReceipt,
        replayed: bool,
        identity: WorkerIdentity,
        target_le: TargetLe,
    ) -> TestResult {
        if !replayed {
            write_message(
                stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::ShareCommitted {
                        job_id: receipt.job_id.clone(),
                        receipt: receipt.clone(),
                        identity,
                        target_le,
                    },
                },
            )
            .await?;
        }
        write_message(
            stream,
            &BackendMessage::ShareCommitted {
                version: BACKEND_PROTOCOL_VERSION,
                id,
                receipt,
                replayed,
            },
        )
        .await
    }

    async fn accept_hello(listener: &UnixListener) -> TestResult<(UnixStream, u64)> {
        let (mut stream, _) = listener.accept().await?;
        let request = read_request(&mut stream).await?;
        let BackendRequest::Hello { id, .. } = request else {
            return Err("first request was not hello".into());
        };
        write_message(&mut stream, &hello_ok(id)).await?;
        Ok((stream, id))
    }

    async fn connect_client(socket: &TestSocket) -> TestResult<BackendClient> {
        connect_client_at(socket, 0).await
    }

    async fn connect_client_at(
        socket: &TestSocket,
        last_event_seq: u64,
    ) -> TestResult<BackendClient> {
        Ok(BackendClient::connect(config(&socket.path)?, uuid(9), last_event_seq).await?)
    }

    fn job(byte: u8) -> JobDescriptor {
        let mut header = [byte; 108];
        header[..4].copy_from_slice(&4_u32.to_le_bytes());
        header[100..104].copy_from_slice(&1_725_000_000_u32.to_le_bytes());
        JobDescriptor {
            job_id: Hex32::new([byte; 32]),
            wcash_candidate_hash_le: Hex32::new([0x73; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([byte.wrapping_add(1); 32]),
            zcash_previous_hash_le: Hex32::new([byte; 32]),
            wcash_coinbase_txid_le: Hex32::new([0x74; 32]),
            zcash_coinbase_txid_le: Hex32::new([0x73; 32]),
            wcash_target_le: TargetLe::new([0x7f; 32]),
            zcash_target_le: TargetLe::new([0x3f; 32]),
            wcash_height: 11,
            zcash_height: 22,
            wcash_reward_zat: 625_000_000,
            zcash_reward_zat: 312_500_000,
            wcash_maturity_confirmations: 100,
            zcash_maturity_confirmations: 100,
            max_age_ms: 45_000,
        }
    }

    fn winner(chain: MergedChain, block_hash: u8) -> WinnerDescriptor {
        WinnerDescriptor {
            chain,
            block_hash_le: Hex32::new([block_hash; 32]),
            height: match chain {
                MergedChain::Wcash => 11,
                MergedChain::Zcash => 22,
            },
            coinbase_txid_le: Hex32::new([block_hash.wrapping_add(1); 32]),
            reward_zat: match chain {
                MergedChain::Wcash => 625_000_000,
                MergedChain::Zcash => 312_500_000,
            },
            maturity_confirmations: 100,
        }
    }

    fn share_submission() -> ShareSubmission {
        ShareSubmission {
            job_id: Hex32::new([0x31; 32]),
            identity: WorkerIdentity {
                account_id: uuid(7),
                worker_id: uuid(8),
                label: "account.worker".to_owned(),
            },
            target_le: TargetLe::new([0xff; 32]),
            time: Hex4::new([0x78, 0x56, 0x34, 0x12]),
            nonce: Hex32::new([0x41; 32]),
            solution: Hex1344::new([0x51; 1344]),
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum PreparedReceiptMismatch {
        JobId,
        ShareId,
        ParentHash,
        HistoricalParentHash,
        CrossedNonce,
        CrossedSolution,
        WcashBlockHash,
        WcashCoinbase,
        ZcashCoinbase,
        Height,
        Reward,
        Maturity,
    }

    impl PreparedReceiptMismatch {
        const fn field(self) -> &'static str {
            match self {
                Self::JobId => "share_receipt.job_id",
                Self::ShareId => "share_receipt.share_id",
                Self::ParentHash
                | Self::HistoricalParentHash
                | Self::CrossedNonce
                | Self::CrossedSolution => "share_receipt.parent_hash_le",
                Self::WcashBlockHash => "winner.block_hash_le",
                Self::WcashCoinbase | Self::ZcashCoinbase => "winner.coinbase_txid_le",
                Self::Height => "winner.height",
                Self::Reward => "winner.reward_zat",
                Self::Maturity => "winner.maturity_confirmations",
            }
        }
    }

    async fn assert_prepared_receipt_mismatch_rejected(
        mismatch: PreparedReceiptMismatch,
    ) -> TestResult {
        let historical_replay = matches!(mismatch, PreparedReceiptMismatch::HistoricalParentHash);
        let timeline = MonotonicTimeline::new();
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let descriptor = job(0x31);
        let server_descriptor = descriptor.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: if historical_replay { 11 } else { 10 },
                    current: Some(AcceptableJob {
                        job: server_descriptor.clone(),
                        accept_for_ms: 40_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = request
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            assert_eq!(job_id, server_descriptor.job_id);
            let parent_hash_le =
                canonical_parent_header_hash_le(&server_descriptor.header_input, &nonce, &solution);
            let mut zcash_winner = winner(MergedChain::Zcash, 0x72);
            zcash_winner.block_hash_le = parent_hash_le.clone();
            zcash_winner.coinbase_txid_le = server_descriptor.zcash_coinbase_txid_le.clone();
            let winners = vec![winner(MergedChain::Wcash, 0x73), zcash_winner];
            let mut receipt = ShareReceipt {
                event_seq: 11,
                job_id: job_id.clone(),
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                parent_hash_le,
                winners,
            };
            match mismatch {
                PreparedReceiptMismatch::JobId => receipt.job_id = Hex32::new([0x44; 32]),
                PreparedReceiptMismatch::ShareId => {
                    receipt.share_id = Hex32::new([0x45; 32]);
                }
                PreparedReceiptMismatch::ParentHash
                | PreparedReceiptMismatch::HistoricalParentHash => {
                    receipt.parent_hash_le = Hex32::new([0x46; 32]);
                    receipt.winners[1].block_hash_le = receipt.parent_hash_le.clone();
                }
                PreparedReceiptMismatch::CrossedNonce => {
                    receipt.parent_hash_le = canonical_parent_header_hash_le(
                        &server_descriptor.header_input,
                        &Hex32::new([0xa5; 32]),
                        &solution,
                    );
                    receipt.winners[1].block_hash_le = receipt.parent_hash_le.clone();
                }
                PreparedReceiptMismatch::CrossedSolution => {
                    receipt.parent_hash_le = canonical_parent_header_hash_le(
                        &server_descriptor.header_input,
                        &nonce,
                        &Hex1344::new([0xa6; 1_344]),
                    );
                    receipt.winners[1].block_hash_le = receipt.parent_hash_le.clone();
                }
                PreparedReceiptMismatch::WcashBlockHash => {
                    receipt.winners[0].block_hash_le = Hex32::new([0x47; 32]);
                }
                PreparedReceiptMismatch::WcashCoinbase => {
                    receipt.winners[0].coinbase_txid_le = Hex32::new([0x48; 32]);
                }
                PreparedReceiptMismatch::ZcashCoinbase => {
                    receipt.winners[1].coinbase_txid_le = Hex32::new([0x49; 32]);
                }
                PreparedReceiptMismatch::Height => receipt.winners[0].height += 1,
                PreparedReceiptMismatch::Reward => receipt.winners[1].reward_zat += 1,
                PreparedReceiptMismatch::Maturity => {
                    receipt.winners[0].maturity_confirmations += 1;
                }
            }
            // The peer's response is valid in isolation; only binding it to the
            // exact submitted generation reveals the accounting conflict.
            receipt.validate()?;
            write_share_commit(
                &mut stream,
                id,
                receipt,
                historical_replay,
                identity,
                target_le,
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let mut registry = GenerationRegistry::new(GenerationRegistryConfig::new(2, 8)?);
        snapshot.apply_to_registry(&mut registry, timeline)?;
        let generation = registry
            .current_generation(timeline.now_ms()?)?
            .ok_or("snapshot did not install its current generation")?
            .clone();
        let generation_id = generation.id();
        let bounds = TargetBounds::new(
            generation.wcash_network_target(),
            generation.zcash_network_target(),
            ShareTarget::MAX,
        )?;
        let assignment = JobAssignment::new(
            &generation,
            TargetBinding::new(1, ShareTarget::MAX, bounds)?,
        )?;
        let allocator =
            NoncePrefixAllocator::new(NonceProfile::FourByte, NonceNamespaceLease::new(1)?);
        let mut session = wcash_pool_core::MiningSession::new(uuid(4).get(), 2)?;
        let _ = session.subscribe(&allocator)?;
        session.complete_authorization(AuthenticatedWorker::new(
            uuid(7).get(),
            uuid(8).get(),
            "account.worker",
        )?)?;
        session.announce_job(assignment)?;
        let context = session.prepare_submission(
            "account.worker",
            generation_id,
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([0x41; 28])),
            Box::new(Hex1344::new([0x51; 1_344])),
            &mut registry,
            timeline.now_ms()?,
        )?;

        match client.submit_prepared_share(context).await {
            Err(ClientError::Protocol(ProtocolError::InvalidField { field, .. })) => {
                assert_eq!(field, mismatch.field());
            }
            other => {
                return Err(format!(
                    "{mismatch:?} mismatch produced an unexpected branded result: {other:?}"
                )
                .into());
            }
        }
        assert_eq!(registry.in_flight(generation_id), Some(0));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[test]
    fn configuration_rejects_ambiguous_paths_and_unbounded_values() -> TestResult {
        let expected = expected_backend()?;
        assert!(matches!(
            BackendClientConfig::new("relative.sock", expected.clone()),
            Err(ClientConfigError::RelativeSocketPath)
        ));
        assert!(matches!(
            BackendClientConfig::new("/tmp/../backend.sock", expected.clone()),
            Err(ClientConfigError::NonCanonicalSocketPath)
        ));
        assert!(matches!(
            BackendClientConfig::new("/tmp/backend.sock", expected.clone())?
                .with_timeouts(Duration::ZERO, Duration::from_secs(1)),
            Err(ClientConfigError::InvalidTimeout { .. })
        ));
        assert!(matches!(
            BackendClientConfig::new("/tmp/backend.sock", expected)?.with_event_queue_capacity(0),
            Err(ClientConfigError::InvalidEventQueueCapacity { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn hello_verifies_network_and_persistent_identity() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (stream, _) = accept_hello(&listener).await?;
            drop(stream);
            TestResult::Ok(())
        });

        let client = connect_client(&socket).await?;
        assert_eq!(client.identity().backend_instance, uuid(2));
        assert_eq!(client.identity().journal_stream, uuid(3));
        assert_eq!(client.identity().current_event_seq, 10);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn wrong_network_fails_closed() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::Hello { id, .. } = request else {
                return TestResult::Err("first request was not hello".into());
            };
            let mut response = hello_ok(id);
            if let BackendMessage::HelloOk { wcash_genesis, .. } = &mut response {
                *wcash_genesis = Hex32::new([0x99; 32]);
            }
            write_message(&mut stream, &response).await?;
            TestResult::Ok(())
        });

        let result = BackendClient::connect(config(&socket.path)?, uuid(9), 0).await;
        assert!(matches!(
            result,
            Err(ClientError::IdentityMismatch {
                field: "Wcash genesis"
            })
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn nonzero_replay_cursor_requires_a_journal_identity() -> TestResult {
        let expected =
            ExpectedBackend::new(Hex32::new([0x11; 32]), Hex32::new([0x22; 32]), 0x5743_4153)?;
        let config = BackendClientConfig::new("/tmp/unused-wcash-backend.sock", expected)?;
        assert!(matches!(
            BackendClient::connect(config, uuid(9), 1).await,
            Err(ClientError::MissingJournalIdentity)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn event_before_hello_identity_is_rejected() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _ = read_request(&mut stream).await?;
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::GenerationClosed {
                        event_seq: 1,
                        job_id: Hex32::new([0x23; 32]),
                    },
                },
            )
            .await?;
            TestResult::Ok(())
        });

        assert!(matches!(
            BackendClient::connect(config(&socket.path)?, uuid(9), 0).await,
            Err(ClientError::UnexpectedResponse {
                expected: "hello_ok",
                actual: "event"
            })
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn queued_activation_retains_the_pre_io_anchor_while_response_is_delayed() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let (event_sent_tx, event_sent_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs {
                id,
                after_event_seq,
                ..
            } = request
            else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            assert_eq!(after_event_seq, 10);
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = request
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            assert_eq!(time, Hex4::new([0x78, 0x56, 0x34, 0x12]));
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::JobActivated {
                        event_seq: 11,
                        job: job(0x61),
                    },
                },
            )
            .await?;
            event_sent_tx
                .send(())
                .map_err(|_| "client stopped before the event was observed")?;
            release_rx
                .await
                .map_err(|_| "test did not release the delayed response")?;
            let receipt = ShareReceipt {
                event_seq: 12,
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                job_id,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: vec![winner(MergedChain::Wcash, 0x73)],
            };
            write_share_commit(&mut stream, id, receipt, false, identity, target_le).await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        assert_eq!(snapshot.replayed_through_event_seq(), 10);

        let mut in_flight = Box::pin(client.submit_share(share_submission()));
        tokio::select! {
            result = &mut in_flight => {
                return Err(format!("submit completed before the response gate: {result:?}").into());
            }
            signal = event_sent_rx => signal?,
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        let release_boundary = Instant::now();
        release_tx
            .send(())
            .map_err(|_| "backend stopped before response release")?;
        let commit = in_flight.await?;
        assert_eq!(commit.receipt().event_seq, 12);
        assert!(!commit.replayed());
        assert_eq!(client.queued_event_count(), 2);
        let delivery = client
            .pop_queued_event()
            .ok_or("expected queued job activation")?;
        assert!(
            delivery.anchor().elapsed_at(release_boundary) >= Duration::from_millis(20),
            "the delivery anchor must predate the deliberately delayed response"
        );
        assert!(matches!(
            delivery.event(),
            BackendEvent::JobActivated { event_seq: 11, .. }
        ));
        assert!(matches!(
            client
                .pop_queued_event()
                .ok_or("expected queued share commit")?
                .event(),
            BackendEvent::ShareCommitted { receipt, .. } if receipt.event_seq == 12
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn activation_prequeued_during_idle_uses_the_prior_exchange_anchor() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let (event_sent_tx, event_sent_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let mut activation = job(0x62);
            activation.max_age_ms = 10;
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::JobActivated {
                        event_seq: 11,
                        job: activation,
                    },
                },
            )
            .await?;
            event_sent_tx
                .send(())
                .map_err(|_| "client stopped before the idle event was queued")?;

            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("third request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 11,
                    healthy: true,
                    pending_wcash: 1,
                    quarantined_wcash: 1,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let timeline = MonotonicTimeline::new();
        let mut client = connect_client_at(&socket, 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let mut registry = GenerationRegistry::new(GenerationRegistryConfig::new(2, 8)?);
        snapshot.apply_to_registry(&mut registry, timeline)?;
        event_sent_rx.await?;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let after_idle = Instant::now();

        let health = client.health().await?;
        assert_eq!(health.event_seq, 11);
        assert_eq!(health.pending_wcash, 1);
        assert_eq!(health.quarantined_wcash, 1);
        let delivery = client.pop_queued_event().ok_or("missing idle activation")?;
        assert!(
            delivery.anchor().elapsed_at(after_idle) >= Duration::from_millis(20),
            "an event queued while idle must inherit the prior stream-boundary anchor"
        );
        delivery.apply_to_registry_at(&mut registry, timeline, timeline.now_ms()?)?;
        assert!(
            registry.current_generation(timeline.now_ms()?)?.is_none(),
            "socket residency must not extend the ten-millisecond generation lease"
        );
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn identical_share_retry_preserves_receipt_and_rejects_rejournaling() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let expected_submission = share_submission();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs {
                id,
                after_event_seq,
                ..
            } = request
            else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            assert_eq!(after_event_seq, 10);
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let receipt = ShareReceipt {
                event_seq: 11,
                job_id: expected_submission.job_id.clone(),
                share_id: canonical_share_id(
                    &expected_submission.job_id,
                    &expected_submission.time,
                    &expected_submission.nonce,
                    &expected_submission.solution,
                ),
                attribution_id: canonical_attribution_id(
                    &expected_submission.identity,
                    &expected_submission.target_le,
                )?,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: vec![winner(MergedChain::Wcash, 0x73)],
            };

            for replayed in [false, true] {
                let request = read_request(&mut stream).await?;
                let BackendRequest::SubmitShare {
                    id,
                    job_id,
                    identity,
                    target_le,
                    time,
                    nonce,
                    solution,
                    ..
                } = request
                else {
                    return TestResult::Err("request was not submit_share".into());
                };
                assert_eq!(job_id, expected_submission.job_id);
                assert_eq!(identity, expected_submission.identity);
                assert_eq!(target_le, expected_submission.target_le);
                assert_eq!(time, expected_submission.time);
                assert_eq!(nonce, expected_submission.nonce);
                assert_eq!(*solution, expected_submission.solution);

                write_share_commit(
                    &mut stream,
                    id,
                    receipt.clone(),
                    replayed,
                    identity,
                    target_le,
                )
                .await?;
            }

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = request
            else {
                return TestResult::Err("request was not submit_share".into());
            };
            assert_eq!(job_id, expected_submission.job_id);
            assert_eq!(time, expected_submission.time);
            assert_eq!(nonce, expected_submission.nonce);
            assert_eq!(*solution, expected_submission.solution);
            let mut rejournaled_receipt = receipt;
            rejournaled_receipt.event_seq = 12;
            write_share_commit(
                &mut stream,
                id,
                rejournaled_receipt,
                false,
                identity,
                target_le,
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        let first = client.submit_share(share_submission()).await?;
        let replay = client.submit_share(share_submission()).await?;
        assert_eq!(first.receipt(), replay.receipt());
        assert!(!first.replayed());
        assert!(replay.replayed());
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::ShareCommitHistoryConflict {
                recorded_event_seq: 11,
                claimed_event_seq: 12,
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn drained_observed_replay_stays_exact_and_keeps_attribution_bound() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let expected_submission = share_submission();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let first = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = first
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let receipt = ShareReceipt {
                event_seq: 11,
                job_id: job_id.clone(),
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            write_share_commit(&mut stream, id, receipt.clone(), false, identity, target_le)
                .await?;

            for _ in 0..2 {
                let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await?
                else {
                    return TestResult::Err("retry request was not submit_share".into());
                };
                write_message(
                    &mut stream,
                    &BackendMessage::ShareCommitted {
                        version: BACKEND_PROTOCOL_VERSION,
                        id,
                        receipt: receipt.clone(),
                        replayed: true,
                    },
                )
                .await?;
            }
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        let first = client.submit_share(expected_submission.clone()).await?;
        assert!(!first.replayed());
        assert!(matches!(
            client
                .pop_queued_event()
                .ok_or("fresh commit event was not queued")?
                .event(),
            BackendEvent::ShareCommitted { receipt, .. } if receipt.event_seq == 11
        ));

        let replay = client.submit_share(expected_submission.clone()).await?;
        assert!(replay.replayed());
        assert_eq!(replay.receipt(), first.receipt());

        let mut crossed = expected_submission;
        crossed.identity.label = "another.worker".to_owned();
        assert!(matches!(
            client.submit_share(crossed).await,
            Err(ClientError::Protocol(ProtocolError::InvalidField {
                field: "share_receipt.attribution_id",
                ..
            }))
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn historical_replay_after_reconnect_requires_projected_receipt_confirmation(
    ) -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let BackendRequest::Hello {
                id, last_event_seq, ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("first request was not hello".into());
            };
            assert_eq!(last_event_seq, 11);
            let mut hello = hello_ok(id);
            let BackendMessage::HelloOk {
                current_event_seq, ..
            } = &mut hello
            else {
                unreachable!("hello fixture has the expected variant")
            };
            *current_event_seq = 11;
            write_message(&mut stream, &hello).await?;

            let BackendRequest::SubscribeJobs {
                id,
                after_event_seq,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            assert_eq!(after_event_seq, 11);
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 11,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let receipt = ShareReceipt {
                event_seq: 11,
                job_id: job_id.clone(),
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            write_message(
                &mut stream,
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt,
                    replayed: true,
                },
            )
            .await?;

            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("fourth request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 11,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 11).await?;
        let _ = client.subscribe_jobs(11).await?;
        let receipt = match client.submit_share(share_submission()).await {
            Err(ClientError::HistoricalReplayRequiresProjection { receipt }) => receipt,
            other => return Err(format!("unexpected historical replay result: {other:?}").into()),
        };
        assert_eq!(receipt.event_seq, 11);
        assert_eq!(receipt.job_id, share_submission().job_id);
        assert!(client.health().await?.healthy);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn share_submission_requires_a_live_job_snapshot_without_writing() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::Health { id, .. } = request else {
                return TestResult::Err("pre-live share attempt wrote to the backend".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client(&socket).await?;
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::InvalidStreamPhase {
                operation: "submit_share",
                required: BackendStreamPhase::Live,
                actual: BackendStreamPhase::Replay,
            })
        ));
        assert!(client.health().await?.healthy);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn prepared_submission_holds_generation_fence_through_backend_io() -> TestResult {
        let timeline = MonotonicTimeline::new();
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let descriptor = job(0x31);
        let server_descriptor = descriptor.clone();
        let (share_seen_tx, share_seen_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: Some(AcceptableJob {
                        job: server_descriptor.clone(),
                        accept_for_ms: 40_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = request
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            share_seen_tx
                .send(())
                .map_err(|_| "client stopped before the share was observed")?;
            release_rx
                .await
                .map_err(|_| "test did not release the share response")?;
            let receipt = ShareReceipt {
                event_seq: 11,
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                job_id,
                parent_hash_le: canonical_parent_header_hash_le(
                    &server_descriptor.header_input,
                    &nonce,
                    &solution,
                ),
                winners: Vec::new(),
            };
            write_share_commit(&mut stream, id, receipt, false, identity, target_le).await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let mut registry = GenerationRegistry::new(GenerationRegistryConfig::new(2, 8)?);
        snapshot.apply_to_registry(&mut registry, timeline)?;
        let now_ms = timeline.now_ms()?;
        let generation = registry
            .current_generation(now_ms)?
            .ok_or("snapshot did not install its current generation")?
            .clone();
        assert_eq!(generation.descriptor(), &descriptor);

        let bounds = TargetBounds::new(
            generation.wcash_network_target(),
            generation.zcash_network_target(),
            ShareTarget::MAX,
        )?;
        let assignment = JobAssignment::new(
            &generation,
            TargetBinding::new(1, ShareTarget::MAX, bounds)?,
        )?;
        let allocator =
            NoncePrefixAllocator::new(NonceProfile::FourByte, NonceNamespaceLease::new(1)?);
        let mut session = wcash_pool_core::MiningSession::new(uuid(4).get(), 2)?;
        let _ = session.subscribe(&allocator)?;
        session.complete_authorization(AuthenticatedWorker::new(
            uuid(7).get(),
            uuid(8).get(),
            "account.worker",
        )?)?;
        session.announce_job(assignment)?;
        let context = session.prepare_submission(
            "account.worker",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([0x41; 28])),
            Box::new(Hex1344::new([0x51; 1_344])),
            &mut registry,
            timeline.now_ms()?,
        )?;
        assert_eq!(registry.in_flight(generation.id()), Some(1));

        let mut in_flight = Box::pin(client.submit_prepared_share(context));
        tokio::select! {
            result = &mut in_flight => {
                return Err(format!("submit completed before the response gate: {result:?}").into());
            }
            signal = share_seen_rx => signal?,
        }
        assert_eq!(registry.in_flight(generation.id()), Some(1));
        release_tx
            .send(())
            .map_err(|_| "backend stopped before response release")?;
        let commit = in_flight.await?;
        assert_eq!(commit.receipt().event_seq, 11);
        assert_eq!(registry.in_flight(generation.id()), Some(0));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn prepared_submission_rejects_crossed_proof_and_generation_bindings() -> TestResult {
        for mismatch in [
            PreparedReceiptMismatch::JobId,
            PreparedReceiptMismatch::ShareId,
            PreparedReceiptMismatch::ParentHash,
            PreparedReceiptMismatch::HistoricalParentHash,
            PreparedReceiptMismatch::CrossedNonce,
            PreparedReceiptMismatch::CrossedSolution,
            PreparedReceiptMismatch::WcashBlockHash,
            PreparedReceiptMismatch::WcashCoinbase,
            PreparedReceiptMismatch::ZcashCoinbase,
            PreparedReceiptMismatch::Height,
            PreparedReceiptMismatch::Reward,
            PreparedReceiptMismatch::Maturity,
        ] {
            assert_prepared_receipt_mismatch_rejected(mismatch).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn reads_a_correlated_event_page() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::ReadEvents {
                id,
                after_event_seq,
                limit,
                ..
            } = request
            else {
                return TestResult::Err("second request was not read_events".into());
            };
            assert_eq!(after_event_seq, 10);
            assert_eq!(limit, 16);
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq,
                    next_event_seq: 11,
                    complete: true,
                    events: vec![BackendEvent::GenerationClosed {
                        event_seq: 11,
                        job_id: Hex32::new([0x81; 32]),
                    }],
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let page = client.read_events(10, 16).await?;
        assert_eq!(page.after_event_seq, 10);
        assert_eq!(page.next_event_seq, 11);
        assert!(page.complete);
        assert_eq!(page.events.len(), 1);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn replay_must_complete_before_the_one_way_live_transition() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::ReadEvents {
                id,
                after_event_seq,
                ..
            } = request
            else {
                return TestResult::Err("second request was not read_events".into());
            };
            assert_eq!(after_event_seq, 9);
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq,
                    next_event_seq: 10,
                    complete: true,
                    events: vec![BackendEvent::GenerationClosed {
                        event_seq: 10,
                        job_id: Hex32::new([0x81; 32]),
                    }],
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs {
                id,
                after_event_seq,
                ..
            } = request
            else {
                return TestResult::Err("third request was not subscribe_jobs".into());
            };
            assert_eq!(after_event_seq, 10);
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            // Neither invalid replay call below may consume a request ID or write.
            let request = read_request(&mut stream).await?;
            let BackendRequest::Health { id, .. } = request else {
                return TestResult::Err("fourth request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 9).await?;
        assert_eq!(client.stream_phase(), BackendStreamPhase::Replay);
        assert!(matches!(
            client.subscribe_jobs(9).await,
            Err(ClientError::ReplayIncomplete { cursor: 9 })
        ));
        assert!(matches!(
            client.read_events(8, 16).await,
            Err(ClientError::ReplayCursorMismatch {
                expected: 9,
                actual: 8
            })
        ));

        let page = client.read_events(9, 16).await?;
        assert!(page.complete);
        assert_eq!(client.replay_cursor(), 10);
        let snapshot = client.subscribe_jobs(10).await?;
        assert_eq!(snapshot.replayed_through_event_seq(), 10);
        assert_eq!(client.stream_phase(), BackendStreamPhase::Live);

        assert!(matches!(
            client.read_events(10, 16).await,
            Err(ClientError::InvalidStreamPhase {
                operation: "read_events",
                required: BackendStreamPhase::Replay,
                actual: BackendStreamPhase::Live,
            })
        ));
        assert!(matches!(
            client.subscribe_jobs(10).await,
            Err(ClientError::InvalidStreamPhase {
                operation: "subscribe_jobs",
                required: BackendStreamPhase::Replay,
                actual: BackendStreamPhase::Live,
            })
        ));
        assert!(client.health().await?.healthy);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn replayed_event_cannot_be_delivered_again_on_the_live_stream() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let duplicate = BackendEvent::GenerationClosed {
            event_seq: 10,
            job_id: Hex32::new([0xa1; 32]),
        };
        let server_duplicate = duplicate.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::ReadEvents {
                id,
                after_event_seq,
                ..
            } = request
            else {
                return TestResult::Err("second request was not read_events".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq,
                    next_event_seq: 10,
                    complete: true,
                    events: vec![server_duplicate.clone()],
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("third request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            if !matches!(request, BackendRequest::Health { .. }) {
                return TestResult::Err("fourth request was not health".into());
            }
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: server_duplicate,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 9).await?;
        assert_eq!(client.read_events(9, 16).await?.events, vec![duplicate]);
        client.subscribe_jobs(10).await?;
        assert!(matches!(
            client.health().await,
            Err(ClientError::LiveEventSequenceMismatch {
                expected: 11,
                actual: 10
            })
        ));
        assert_eq!(client.queued_event_count(), 0);
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_must_not_regress_behind_requested_cursor() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 9,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        assert!(matches!(
            client.subscribe_jobs(10).await,
            Err(ClientError::SnapshotCursorBehind {
                requested: 10,
                snapshot: 9
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_exposes_any_replay_to_live_watermark_gap() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 12,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        assert_eq!(snapshot.event_seq(), 12);
        assert_eq!(snapshot.replayed_through_event_seq(), 10);
        assert!(snapshot
            .anchor()
            .checked_deadline(Duration::from_millis(1))
            .is_some());
        assert_eq!(client.stream_phase(), BackendStreamPhase::Live);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn live_health_response_rejects_an_unflushed_event_watermark() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::Health { id, .. } = request else {
                return TestResult::Err("third request was not health".into());
            };
            // Deliberately omit event 11. A watermark alone is not proof that
            // the pool received the state it is about to rely on.
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 11,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        assert!(matches!(
            client.health().await,
            Err(ClientError::LiveEventFlushIncomplete {
                operation: "health",
                required: 11,
                delivered: 10,
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn share_response_rejects_an_unflushed_commit_event() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::SubscribeJobs { id, .. } = request else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = request
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let share_id = canonical_share_id(&job_id, &time, &nonce, &solution);
            let receipt = ShareReceipt {
                event_seq: 11,
                job_id,
                share_id,
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            // Deliberately send the correlated response without its durable event.
            write_message(
                &mut stream,
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt,
                    replayed: false,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::LiveEventFlushIncomplete {
                operation: "share commit",
                required: 11,
                delivered: 10,
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn fresh_share_response_must_advance_the_live_cursor() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let receipt = ShareReceipt {
                event_seq: 10,
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                job_id,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            write_message(
                &mut stream,
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt,
                    replayed: false,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::FreshShareCommitDidNotAdvance {
                event_seq: 10,
                previous_event_seq: 10,
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn concurrently_committed_replay_accepts_its_exact_future_event() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let receipt = ShareReceipt {
                event_seq: 11,
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                job_id,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::ShareCommitted {
                        job_id: receipt.job_id.clone(),
                        receipt: receipt.clone(),
                        identity,
                        target_le,
                    },
                },
            )
            .await?;
            write_message(
                &mut stream,
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt,
                    replayed: true,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        let commit = client.submit_share(share_submission()).await?;
        assert!(commit.replayed());
        assert_eq!(commit.receipt().event_seq, 11);
        assert!(client.is_usable());
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn share_response_rejects_nonmatching_flushed_commit_events() -> TestResult {
        #[derive(Clone, Copy)]
        enum EventMismatch {
            OtherEventKind,
            CrossedIdentity,
            CrossedTarget,
        }

        for mismatch in [
            EventMismatch::OtherEventKind,
            EventMismatch::CrossedIdentity,
            EventMismatch::CrossedTarget,
        ] {
            let socket = TestSocket::new()?;
            let listener = UnixListener::bind(&socket.path)?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = accept_hello(&listener).await?;
                let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await?
                else {
                    return TestResult::Err("second request was not subscribe_jobs".into());
                };
                write_message(
                    &mut stream,
                    &BackendMessage::JobSnapshot {
                        version: BACKEND_PROTOCOL_VERSION,
                        id,
                        event_seq: 10,
                        current: None,
                        recent: Vec::new(),
                    },
                )
                .await?;

                let BackendRequest::SubmitShare {
                    id,
                    job_id,
                    identity,
                    target_le,
                    time,
                    nonce,
                    solution,
                    ..
                } = read_request(&mut stream).await?
                else {
                    return TestResult::Err("third request was not submit_share".into());
                };
                let receipt = ShareReceipt {
                    event_seq: 11,
                    share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                    attribution_id: canonical_attribution_id(&identity, &target_le)?,
                    job_id: job_id.clone(),
                    parent_hash_le: Hex32::new([0x72; 32]),
                    winners: Vec::new(),
                };
                let event = match mismatch {
                    EventMismatch::OtherEventKind => BackendEvent::JobActivated {
                        event_seq: 11,
                        job: job(0x61),
                    },
                    EventMismatch::CrossedIdentity => {
                        let crossed_identity = WorkerIdentity {
                            account_id: uuid(17),
                            worker_id: uuid(18),
                            label: "crossed.worker".to_owned(),
                        };
                        let mut crossed_receipt = receipt.clone();
                        crossed_receipt.attribution_id =
                            canonical_attribution_id(&crossed_identity, &target_le)?;
                        BackendEvent::ShareCommitted {
                            receipt: crossed_receipt,
                            job_id: job_id.clone(),
                            identity: crossed_identity,
                            target_le: target_le.clone(),
                        }
                    }
                    EventMismatch::CrossedTarget => {
                        let crossed_target = TargetLe::new([0x55; 32]);
                        let mut crossed_receipt = receipt.clone();
                        crossed_receipt.attribution_id =
                            canonical_attribution_id(&identity, &crossed_target)?;
                        BackendEvent::ShareCommitted {
                            receipt: crossed_receipt,
                            job_id: job_id.clone(),
                            identity,
                            target_le: crossed_target,
                        }
                    }
                };
                write_message(
                    &mut stream,
                    &BackendMessage::Event {
                        version: BACKEND_PROTOCOL_VERSION,
                        event,
                    },
                )
                .await?;
                write_message(
                    &mut stream,
                    &BackendMessage::ShareCommitted {
                        version: BACKEND_PROTOCOL_VERSION,
                        id,
                        receipt,
                        replayed: false,
                    },
                )
                .await?;
                TestResult::Ok(())
            });

            let mut client = connect_client_at(&socket, 10).await?;
            let _ = client.subscribe_jobs(10).await?;
            assert!(matches!(
                client.submit_share(share_submission()).await,
                Err(ClientError::ShareCommitEventMismatch { event_seq: 11 })
            ));
            assert!(matches!(
                client.health().await,
                Err(ClientError::ConnectionUnusable)
            ));
            server.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn commit_event_followed_by_correlated_error_is_terminally_contradictory() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let receipt = ShareReceipt {
                event_seq: 11,
                job_id: job_id.clone(),
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::ShareCommitted {
                        receipt,
                        job_id,
                        identity,
                        target_le,
                    },
                },
            )
            .await?;
            write_message(
                &mut stream,
                &BackendMessage::Error {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    code: BackendErrorCode::LowDifficulty,
                    message: "contradictory rejection".to_owned(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::ContradictoryShareOutcome { event_seq: 11 })
        ));
        assert!(matches!(
            client
                .pop_queued_event()
                .ok_or("durable commit event must remain observable")?
                .event(),
            BackendEvent::ShareCommitted { receipt, .. } if receipt.event_seq == 11
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn replay_evidence_requires_projection_and_detects_a_later_retry_error() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let expected = share_submission();
        let receipt = ShareReceipt {
            event_seq: 11,
            job_id: expected.job_id.clone(),
            share_id: canonical_share_id(
                &expected.job_id,
                &expected.time,
                &expected.nonce,
                &expected.solution,
            ),
            attribution_id: canonical_attribution_id(&expected.identity, &expected.target_le)?,
            parent_hash_le: Hex32::new([0x72; 32]),
            winners: Vec::new(),
        };
        let replay_event = BackendEvent::ShareCommitted {
            receipt: receipt.clone(),
            job_id: expected.job_id.clone(),
            identity: expected.identity.clone(),
            target_le: expected.target_le.clone(),
        };
        let server_replay_event = replay_event.clone();
        let server_receipt = receipt.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let BackendRequest::Hello {
                id, last_event_seq, ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("first request was not hello".into());
            };
            assert_eq!(last_event_seq, 10);
            let mut hello = hello_ok(id);
            let BackendMessage::HelloOk {
                current_event_seq, ..
            } = &mut hello
            else {
                unreachable!("hello fixture has the expected variant")
            };
            *current_event_seq = 11;
            write_message(&mut stream, &hello).await?;

            let BackendRequest::ReadEvents {
                id,
                after_event_seq,
                limit,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("second request was not read_events".into());
            };
            assert_eq!(after_event_seq, 10);
            assert_eq!(limit, 1);
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq,
                    next_event_seq: 11,
                    complete: true,
                    events: vec![server_replay_event],
                },
            )
            .await?;

            let BackendRequest::SubscribeJobs {
                id,
                after_event_seq,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("third request was not subscribe_jobs".into());
            };
            assert_eq!(after_event_seq, 11);
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 11,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("fourth request was not submit_share".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt: server_receipt,
                    replayed: true,
                },
            )
            .await?;

            let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("fifth request was not submit_share".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::Error {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    code: BackendErrorCode::LowDifficulty,
                    message: "contradictory rejection".to_owned(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let page = client.read_events(10, 1).await?;
        assert_eq!(page.events, vec![replay_event]);
        let _ = client.subscribe_jobs(11).await?;
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::HistoricalReplayRequiresProjection { receipt })
                if receipt.event_seq == 11
        ));
        assert!(client.is_usable());
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::ContradictoryShareOutcome { event_seq: 11 })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn historical_non_share_event_cannot_be_relabelled_as_a_share_commit() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let expected = share_submission();
        let receipt = ShareReceipt {
            event_seq: 11,
            job_id: expected.job_id.clone(),
            share_id: canonical_share_id(
                &expected.job_id,
                &expected.time,
                &expected.nonce,
                &expected.solution,
            ),
            attribution_id: canonical_attribution_id(&expected.identity, &expected.target_le)?,
            parent_hash_le: Hex32::new([0x72; 32]),
            winners: Vec::new(),
        };
        let occupied_event = BackendEvent::GenerationClosed {
            event_seq: 11,
            job_id: expected.job_id.clone(),
        };
        let server_event = occupied_event.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let BackendRequest::Hello {
                id, last_event_seq, ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("first request was not hello".into());
            };
            assert_eq!(last_event_seq, 10);
            let mut hello = hello_ok(id);
            let BackendMessage::HelloOk {
                current_event_seq, ..
            } = &mut hello
            else {
                unreachable!("hello fixture has the expected variant")
            };
            *current_event_seq = 11;
            write_message(&mut stream, &hello).await?;

            let BackendRequest::ReadEvents {
                id,
                after_event_seq,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("second request was not read_events".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq,
                    next_event_seq: 11,
                    complete: true,
                    events: vec![server_event],
                },
            )
            .await?;

            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("third request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 11,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("fourth request was not submit_share".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt,
                    replayed: true,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let page = client.read_events(10, 1).await?;
        assert_eq!(page.events, vec![occupied_event]);
        let _ = client.subscribe_jobs(11).await?;
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::ShareCommitEventMismatch { event_seq: 11 })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn observed_commit_followed_by_retry_error_is_terminally_contradictory() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: None,
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare {
                id,
                job_id,
                identity,
                target_le,
                time,
                nonce,
                solution,
                ..
            } = read_request(&mut stream).await?
            else {
                return TestResult::Err("third request was not submit_share".into());
            };
            let receipt = ShareReceipt {
                event_seq: 11,
                job_id: job_id.clone(),
                share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
                attribution_id: canonical_attribution_id(&identity, &target_le)?,
                parent_hash_le: Hex32::new([0x72; 32]),
                winners: Vec::new(),
            };
            write_share_commit(&mut stream, id, receipt, false, identity, target_le).await?;

            let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("retry request was not submit_share".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::Error {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    code: BackendErrorCode::LowDifficulty,
                    message: "contradictory retry rejection".to_owned(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        let _ = client.subscribe_jobs(10).await?;
        let _ = client.submit_share(share_submission()).await?;
        let committed = client
            .pop_queued_event()
            .ok_or("fresh commit event must be observable")?;
        assert!(matches!(
            committed.event(),
            BackendEvent::ShareCommitted { receipt, .. } if receipt.event_seq == 11
        ));
        assert!(matches!(
            client.submit_share(share_submission()).await,
            Err(ClientError::ContradictoryShareOutcome { event_seq: 11 })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn health_watermark_rollback_poisons_the_connection() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::Health { id, .. } = request else {
                return TestResult::Err("second request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 9,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        assert!(matches!(
            client.health().await,
            Err(ClientError::EventWatermarkRollback {
                operation: "health",
                previous: 10,
                received: 9,
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn event_page_must_respect_the_requested_limit() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::ReadEvents {
                id,
                after_event_seq,
                ..
            } = request
            else {
                return TestResult::Err("second request was not read_events".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq,
                    next_event_seq: after_event_seq + 2,
                    complete: true,
                    events: vec![
                        BackendEvent::GenerationClosed {
                            event_seq: after_event_seq + 1,
                            job_id: Hex32::new([0x91; 32]),
                        },
                        BackendEvent::GenerationClosed {
                            event_seq: after_event_seq + 2,
                            job_id: Hex32::new([0x92; 32]),
                        },
                    ],
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        assert!(matches!(
            client.read_events(10, 1).await,
            Err(ClientError::EventPageLimitExceeded {
                requested: 1,
                actual: 2
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn event_page_must_echo_the_requested_cursor() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::ReadEvents { id, .. } = request else {
                return TestResult::Err("second request was not read_events".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::EventsPage {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    after_event_seq: 9,
                    next_event_seq: 9,
                    complete: true,
                    events: Vec::new(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client_at(&socket, 10).await?;
        assert!(matches!(
            client.read_events(10, 16).await,
            Err(ClientError::EventPageCursorMismatch {
                expected: 10,
                actual: 9
            })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn wrong_response_id_poisoned_the_connection() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::Health { id, .. } = request else {
                return TestResult::Err("second request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: id + 1,
                    event_seq: 10,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client(&socket).await?;
        assert!(matches!(
            client.health().await,
            Err(ClientError::WrongResponseId { .. })
        ));
        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn correlated_backend_rejection_does_not_desynchronize_retries() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let first = read_request(&mut stream).await?;
            let BackendRequest::Health { id: first_id, .. } = first else {
                return TestResult::Err("second request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::Error {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: first_id,
                    code: BackendErrorCode::Overloaded,
                    message: "retry later".to_owned(),
                },
            )
            .await?;

            let second = read_request(&mut stream).await?;
            let BackendRequest::Health { id: second_id, .. } = second else {
                return TestResult::Err("third request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HealthStatus {
                    version: BACKEND_PROTOCOL_VERSION,
                    id: second_id,
                    event_seq: 10,
                    healthy: true,
                    pending_wcash: 0,
                    quarantined_wcash: 0,
                    pending_zcash: 0,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let mut client = connect_client(&socket).await?;
        assert!(matches!(
            client.health().await,
            Err(ClientError::BackendRejected {
                code: BackendErrorCode::Overloaded,
                ..
            })
        ));
        assert!(client.health().await?.healthy);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_an_in_flight_exchange_permanently_poisons_connection() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let (request_seen_tx, request_seen_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_hello(&listener).await?;
            let request = read_request(&mut stream).await?;
            if !matches!(request, BackendRequest::Health { .. }) {
                return TestResult::Err("second request was not health".into());
            }
            request_seen_tx
                .send(())
                .map_err(|_| "client stopped before observing the in-flight request")?;

            // The client must close without placing another request on a stream whose
            // response correlation is now unknowable.
            let mut next_byte = [0_u8; 1];
            let read = stream.read(&mut next_byte).await?;
            if read != 0 {
                return TestResult::Err("client unsafely reused a cancelled exchange".into());
            }
            TestResult::Ok(())
        });

        let mut client = connect_client(&socket).await?;
        let mut in_flight = Box::pin(client.health());
        tokio::select! {
            result = &mut in_flight => {
                return Err(format!("health completed before cancellation: {result:?}").into());
            }
            signal = request_seen_rx => signal?,
        }
        drop(in_flight);

        assert!(matches!(
            client.health().await,
            Err(ClientError::ConnectionUnusable)
        ));
        drop(client);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn wrong_version_is_reported_before_protocol_decode() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::Hello { id, .. } = request else {
                return TestResult::Err("first request was not hello".into());
            };
            let payload = serde_json::to_vec(&serde_json::json!({
                "type": "hello_ok",
                "v": 2,
                "id": id
            }))?;
            let length = u32::try_from(payload.len())?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(&payload).await?;
            TestResult::Ok(())
        });

        let result = BackendClient::connect(config(&socket.path)?, uuid(9), 0).await;
        assert!(matches!(
            result,
            Err(ClientError::VersionMismatch {
                expected: BACKEND_PROTOCOL_VERSION,
                actual: 2
            })
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn clean_eof_and_oversize_are_distinct_failures() -> TestResult {
        let eof_socket = TestSocket::new()?;
        let eof_listener = UnixListener::bind(&eof_socket.path)?;
        let eof_server = tokio::spawn(async move {
            let (mut stream, _) = eof_listener.accept().await?;
            let _ = read_request(&mut stream).await?;
            drop(stream);
            TestResult::Ok(())
        });
        assert!(matches!(
            BackendClient::connect(config(&eof_socket.path)?, uuid(9), 0).await,
            Err(ClientError::CleanEof)
        ));
        eof_server.await??;

        let oversize_socket = TestSocket::new()?;
        let oversize_listener = UnixListener::bind(&oversize_socket.path)?;
        let oversize_server = tokio::spawn(async move {
            let (mut stream, _) = oversize_listener.accept().await?;
            let _ = read_request(&mut stream).await?;
            let declared = u32::try_from(MAX_BACKEND_PAYLOAD_BYTES + 1)?;
            stream.write_all(&declared.to_be_bytes()).await?;
            TestResult::Ok(())
        });
        assert!(matches!(
            BackendClient::connect(config(&oversize_socket.path)?, uuid(9), 0).await,
            Err(ClientError::FrameTooLarge { .. })
        ));
        oversize_server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn complete_operation_timeout_is_fatal() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _ = read_request(&mut stream).await?;
            pending::<()>().await;
            #[allow(unreachable_code)]
            TestResult::Ok(())
        });
        let fast = BackendClientConfig::new(&socket.path, expected_backend()?)?
            .with_timeouts(Duration::from_secs(1), Duration::from_millis(25))?;
        let result = BackendClient::connect(fast, uuid(9), 0).await;
        assert!(matches!(
            result,
            Err(ClientError::Timeout { operation: "hello" })
        ));
        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[test]
    fn submission_debug_redacts_identity_nonce_and_solution() {
        let debug = format!("{:?}", share_submission());
        assert!(debug.contains("78563412"));
        assert!(debug.contains("<worker identity>"));
        assert!(debug.contains("<32-byte header nonce>"));
        assert!(debug.contains("<1344-byte Equihash solution>"));
        assert!(!debug.contains("account.worker"));
        assert!(!debug.contains(&"41".repeat(32)));
        assert!(!debug.contains(&"51".repeat(1_344)));
    }

    #[test]
    fn nul_socket_path_is_rejected() -> TestResult {
        let path = PathBuf::from(OsStr::from_bytes(b"/tmp/backend\0.sock"));
        assert!(matches!(
            BackendClientConfig::new(path, expected_backend()?),
            Err(ClientConfigError::SocketPathContainsNul)
        ));
        Ok(())
    }
}

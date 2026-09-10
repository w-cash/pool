//! Bounded serialization of shares and live events through one Wolf client.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{interval_at, timeout, Instant, MissedTickBehavior},
};
use wcash_pool_backend_client::{
    BackendAuthority, BackendClient, BackendConnectionBinding, BackendStreamPhase, ClientError,
    DeliveredBackendEvent, VerifiedShareCommit,
};
use wcash_pool_core::SubmissionContext;
use wcash_pool_protocol::{BackendErrorCode, ShareReceipt};

use crate::JobRouter;

const MAXIMUM_QUEUE_CAPACITY: usize = 4_096;
const MAXIMUM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const MAXIMUM_EVENT_CONSUMER_TIMEOUT: Duration = Duration::from_secs(60);

/// Finite queue and time policy for the one live Wolf actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareRouterConfig {
    queue_capacity: usize,
    heartbeat_interval: Duration,
    event_consumer_timeout: Duration,
}

impl ShareRouterConfig {
    /// Validates the submission queue, idle heartbeat, and event-consumer deadline.
    pub fn new(
        queue_capacity: usize,
        heartbeat_interval: Duration,
        event_consumer_timeout: Duration,
    ) -> Result<Self, ShareRouterConfigError> {
        if !(1..=MAXIMUM_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(ShareRouterConfigError::InvalidQueueCapacity {
                actual: queue_capacity,
                maximum: MAXIMUM_QUEUE_CAPACITY,
            });
        }
        validate_duration(
            "heartbeat_interval",
            heartbeat_interval,
            MAXIMUM_HEARTBEAT_INTERVAL,
        )?;
        validate_duration(
            "event_consumer_timeout",
            event_consumer_timeout,
            MAXIMUM_EVENT_CONSUMER_TIMEOUT,
        )?;
        Ok(Self {
            queue_capacity,
            heartbeat_interval,
            event_consumer_timeout,
        })
    }

    /// Returns the global number of pending backend submissions.
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    /// Returns the maximum idle period before the actor probes Wolf and drains events.
    pub const fn heartbeat_interval(self) -> Duration {
        self.heartbeat_interval
    }

    /// Returns the deadline for acknowledging one bounded batch of live events.
    pub const fn event_consumer_timeout(self) -> Duration {
        self.event_consumer_timeout
    }
}

fn validate_duration(
    field: &'static str,
    actual: Duration,
    maximum: Duration,
) -> Result<(), ShareRouterConfigError> {
    if actual.is_zero() || actual > maximum {
        return Err(ShareRouterConfigError::InvalidDuration {
            field,
            maximum_seconds: maximum.as_secs(),
        });
    }
    Ok(())
}

/// Invalid live-backend actor configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShareRouterConfigError {
    /// The pending submission queue was empty or excessive.
    #[error("backend queue capacity {actual} is outside 1..={maximum}")]
    InvalidQueueCapacity {
        /// Supplied queue capacity.
        actual: usize,
        /// Fixed capacity ceiling.
        maximum: usize,
    },
    /// A duration was zero or exceeded its fixed ceiling.
    #[error("{field} must be greater than zero and at most {maximum_seconds} seconds")]
    InvalidDuration {
        /// Invalid configuration field.
        field: &'static str,
        /// Fixed whole-second ceiling.
        maximum_seconds: u64,
    },
}

/// Stable failure returned by the deployment-owned live-event consumer.
///
/// The consumer should record its detailed cause through private operational
/// telemetry. The miner-facing edge deliberately treats every such failure as
/// an unavailable trusted event path without exposing storage detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("backend event consumer could not acknowledge journal progress")]
pub struct BackendEventConsumerError;

/// Acknowledges every ordered live journal batch before pool policy observes it.
///
/// Batches are non-empty, bounded by [`BackendClient`]'s event queue, and tied to
/// `authority` by an identity-checked connection. A deployment implementation
/// must return success only after the complete batch and its cursor are durable
/// and must accept byte-identical retries idempotently. This repository currently
/// supplies no durable implementation; in-memory consumers are suitable only for
/// deterministic tests.
pub trait BackendEventConsumer: Send + Sync + 'static {
    /// Consumes one non-empty, contiguous batch under a finite actor deadline.
    fn consume<'a>(
        &'a self,
        authority: &'a BackendAuthority,
        events: &'a [DeliveredBackendEvent],
    ) -> Pin<Box<dyn Future<Output = Result<(), BackendEventConsumerError>> + Send + 'a>>;
}

enum SubmitCommand {
    Share {
        context: SubmissionContext,
        response: oneshot::Sender<Result<VerifiedShareCommit, ShareRouterError>>,
    },
    Shutdown {
        complete: oneshot::Sender<()>,
    },
}

enum ActorWork {
    Heartbeat,
    Command(Option<SubmitCommand>),
}

/// Cloneable producer for the one bounded Wolf submission actor.
///
/// The only accepted input is a non-cloneable core [`SubmissionContext`]. The
/// successful output is branded by [`BackendClient`], so a normal-build caller
/// cannot manufacture share acceptance without completing the Wolf exchange.
#[derive(Clone, Debug)]
pub struct ShareRouterHandle {
    sender: mpsc::Sender<SubmitCommand>,
}

impl ShareRouterHandle {
    /// Attempts to enqueue one prepared share without waiting for queue space.
    ///
    /// Once admitted, the method waits for Wolf's bounded request exchange. The
    /// generation guard remains owned by the actor until that result resolves.
    pub async fn submit(
        &self,
        context: SubmissionContext,
    ) -> Result<VerifiedShareCommit, ShareRouterError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(SubmitCommand::Share { context, response })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ShareRouterError::Overloaded,
                mpsc::error::TrySendError::Closed(_) => ShareRouterError::Unavailable,
            })?;
        receiver.await.map_err(|_| ShareRouterError::Unavailable)?
    }
}

/// Owned Wolf submission actor and its cloneable producer.
#[derive(Debug)]
pub struct ShareRouter {
    handle: ShareRouterHandle,
    task: JoinHandle<()>,
}

impl ShareRouter {
    /// Starts the single-owner queue and idle event pump for a live backend connection.
    ///
    /// Any events already queued on `client` are acknowledged by `event_consumer`
    /// and applied to `job_router` before this method returns a producer handle.
    /// Cancelling startup after the live binding is checked suspends the router.
    pub async fn spawn(
        mut client: BackendClient,
        job_router: JobRouter,
        config: ShareRouterConfig,
        event_consumer: Arc<dyn BackendEventConsumer>,
    ) -> Result<Self, ShareRouterError> {
        if client.stream_phase() != BackendStreamPhase::Live {
            let _ = job_router.suspend();
            return Err(ShareRouterError::BackendNotLive);
        }
        if !client.is_usable() {
            let _ = job_router.suspend();
            return Err(ShareRouterError::Unavailable);
        }
        let Some(connection_binding) = client.connection_binding() else {
            let _ = job_router.suspend();
            return Err(ShareRouterError::BackendConnectionMismatch);
        };
        if !job_router.client_binding_matches(&client).unwrap_or(false) {
            let _ = job_router.suspend();
            return Err(ShareRouterError::BackendConnectionMismatch);
        }
        let suspension = SuspendOnDrop::new(job_router.clone(), Some(connection_binding));
        drain_backend_events(
            &mut client,
            &job_router,
            event_consumer.as_ref(),
            config.event_consumer_timeout(),
        )
        .await?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity());
        let handle = ShareRouterHandle { sender };
        let first_heartbeat_deadline = Instant::now() + config.heartbeat_interval();
        let task = tokio::spawn(run_submission_actor(
            client,
            job_router,
            receiver,
            suspension,
            config,
            event_consumer,
            first_heartbeat_deadline,
        ));
        Ok(Self { handle, task })
    }

    /// Returns a producer for connection actors.
    pub fn handle(&self) -> ShareRouterHandle {
        self.handle.clone()
    }

    /// Stops accepting work after draining commands queued before shutdown.
    ///
    /// The currently executing bounded backend exchange and shares ahead of the
    /// shutdown marker complete normally. When the marker is observed, the actor
    /// closes the receiver and fails any racing commands behind it. Surviving
    /// cloned handles therefore cannot keep shutdown alive indefinitely.
    pub async fn shutdown(mut self) -> Result<(), ShareRouterError> {
        let (complete, acknowledged) = oneshot::channel();
        self.handle
            .sender
            .send(SubmitCommand::Shutdown { complete })
            .await
            .map_err(|_| ShareRouterError::Unavailable)?;
        acknowledged
            .await
            .map_err(|_| ShareRouterError::TaskFailed)?;
        (&mut self.task)
            .await
            .map_err(|_| ShareRouterError::TaskFailed)
    }
}

impl Drop for ShareRouter {
    fn drop(&mut self) {
        // Dropping a Tokio JoinHandle normally detaches its task. Abort instead so
        // cancelling the owned shutdown future also drops the sole receiver and
        // closes every surviving producer handle.
        self.task.abort();
    }
}

async fn run_submission_actor(
    mut client: BackendClient,
    job_router: JobRouter,
    mut receiver: mpsc::Receiver<SubmitCommand>,
    mut suspension: SuspendOnDrop,
    config: ShareRouterConfig,
    event_consumer: Arc<dyn BackendEventConsumer>,
    first_heartbeat_deadline: Instant,
) {
    let mut heartbeat = interval_at(first_heartbeat_deadline, config.heartbeat_interval());
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        let work = tokio::select! {
            // Once due, one health exchange wins over an already-ready submission.
            // This bounds event lag while the submission queue remains non-empty.
            biased;
            _ = heartbeat.tick() => ActorWork::Heartbeat,
            command = receiver.recv() => ActorWork::Command(command),
        };
        match work {
            ActorWork::Heartbeat => {
                if pump_health(
                    &mut client,
                    &job_router,
                    event_consumer.as_ref(),
                    config.event_consumer_timeout(),
                )
                .await
                .is_err()
                {
                    suspension.suspend();
                    receiver.close();
                    fail_pending(&mut receiver).await;
                    break;
                }
            }
            ActorWork::Command(Some(SubmitCommand::Share { context, response })) => {
                // This guard is declared after `response`, so unwinding or task
                // cancellation suspends admission before dropping the response
                // sender and waking its caller with an unavailable result.
                let mut response_suspension = ResponseSuspension::new(&mut suspension);
                let mut result = client
                    .submit_prepared_share(context)
                    .await
                    .map_err(ShareRouterError::from_client);
                if let Err(error) = drain_backend_events(
                    &mut client,
                    &job_router,
                    event_consumer.as_ref(),
                    config.event_consumer_timeout(),
                )
                .await
                {
                    result = Err(error);
                }
                let terminal = result
                    .as_ref()
                    .err()
                    .is_some_and(ShareRouterError::is_terminal);
                if terminal {
                    // Stop every current and future miner session before exposing
                    // the terminal share outcome to its caller.
                    response_suspension.suspend();
                } else {
                    response_suspension.disarm();
                }
                drop(response_suspension);
                let _ = response.send(result);
                if terminal {
                    receiver.close();
                    fail_pending(&mut receiver).await;
                    break;
                }
            }
            ActorWork::Command(Some(SubmitCommand::Shutdown { complete })) => {
                suspension.suspend();
                receiver.close();
                fail_pending(&mut receiver).await;
                let _ = complete.send(());
                break;
            }
            ActorWork::Command(None) => break,
        }
    }
}

/// Ensures cancellation, panic, or loss of every producer cannot leave stale work live.
struct SuspendOnDrop {
    job_router: JobRouter,
    connection_binding: Option<BackendConnectionBinding>,
    armed: bool,
}

impl SuspendOnDrop {
    fn new(job_router: JobRouter, connection_binding: Option<BackendConnectionBinding>) -> Self {
        Self {
            job_router,
            connection_binding,
            armed: true,
        }
    }

    fn suspend(&mut self) {
        if self.armed {
            match self.connection_binding.as_ref() {
                Some(binding) => {
                    let _ = self.job_router.suspend_if_bound(binding);
                }
                None => {
                    let _ = self.job_router.suspend();
                }
            }
            self.armed = false;
        }
    }
}

impl Drop for SuspendOnDrop {
    fn drop(&mut self) {
        self.suspend();
    }
}

struct ResponseSuspension<'a> {
    suspension: &'a mut SuspendOnDrop,
    armed: bool,
}

impl<'a> ResponseSuspension<'a> {
    fn new(suspension: &'a mut SuspendOnDrop) -> Self {
        Self {
            suspension,
            armed: true,
        }
    }

    fn suspend(&mut self) {
        if self.armed {
            self.suspension.suspend();
            self.armed = false;
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ResponseSuspension<'_> {
    fn drop(&mut self) {
        self.suspend();
    }
}

async fn pump_health(
    client: &mut BackendClient,
    job_router: &JobRouter,
    event_consumer: &dyn BackendEventConsumer,
    event_consumer_timeout: Duration,
) -> Result<(), ShareRouterError> {
    // Drain any valid events received before a failing response as well. Their
    // durable journal facts remain authoritative even when this stream is terminal.
    let health = client.health().await.map_err(ShareRouterError::from_client);
    drain_backend_events(client, job_router, event_consumer, event_consumer_timeout).await?;
    let health = health?;
    if !health.healthy {
        return Err(ShareRouterError::Rejected(
            BackendErrorCode::BackendUnhealthy,
        ));
    }
    Ok(())
}

async fn drain_backend_events(
    client: &mut BackendClient,
    job_router: &JobRouter,
    event_consumer: &dyn BackendEventConsumer,
    event_consumer_timeout: Duration,
) -> Result<(), ShareRouterError> {
    if !job_router
        .client_binding_matches(client)
        .map_err(|_| ShareRouterError::JobStreamUnusable)?
    {
        return Err(ShareRouterError::BackendConnectionMismatch);
    }
    let binding = client
        .connection_binding()
        .ok_or(ShareRouterError::BackendConnectionMismatch)?;
    let mut events = Vec::with_capacity(client.queued_event_count());
    while let Some(event) = client.pop_queued_event() {
        if event.connection_binding() != &binding {
            return Err(ShareRouterError::BackendConnectionMismatch);
        }
        events.push(event);
    }
    if !events.is_empty() {
        match timeout(
            event_consumer_timeout,
            event_consumer.consume(binding.authority(), &events),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Err(ShareRouterError::EventConsumerUnusable),
        }
        for event in &events {
            job_router
                .apply_event(client, event)
                .map_err(|_| ShareRouterError::JobStreamUnusable)?;
        }
    }
    if !job_router
        .client_binding_matches(client)
        .map_err(|_| ShareRouterError::JobStreamUnusable)?
    {
        return Err(ShareRouterError::BackendConnectionMismatch);
    }
    if !job_router
        .client_cursor_matches(client)
        .map_err(|_| ShareRouterError::JobStreamUnusable)?
    {
        return Err(ShareRouterError::JobStreamUnusable);
    }
    Ok(())
}

async fn fail_pending(receiver: &mut mpsc::Receiver<SubmitCommand>) {
    while let Some(pending) = receiver.recv().await {
        match pending {
            SubmitCommand::Share { response, .. } => {
                let _ = response.send(Err(ShareRouterError::Unavailable));
            }
            SubmitCommand::Shutdown { complete } => {
                let _ = complete.send(());
            }
        }
    }
}

/// Submission queue or trusted backend failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ShareRouterError {
    /// The backend must finish replay and subscribe before accepting miners.
    #[error("backend connection is not in live job-stream phase")]
    BackendNotLive,
    /// The client did not produce the snapshot that initialized this job router.
    #[error("backend client does not match the job router snapshot connection")]
    BackendConnectionMismatch,
    /// The bounded submission queue is full.
    #[error("backend submission queue is full")]
    Overloaded,
    /// An old replay awaits confirmation from the durable accounting projector.
    #[error("historical share replay requires projected-receipt confirmation")]
    ReplayRequiresProjection {
        /// Exact backend receipt which durable accounting must confirm.
        receipt: Box<ShareReceipt>,
    },
    /// The Wolf connection is closed or no longer trustworthy.
    #[error("backend submission service is unavailable")]
    Unavailable,
    /// A queued durable event could not advance the one global job stream.
    #[error("backend job stream is no longer trustworthy")]
    JobStreamUnusable,
    /// The mandatory event consumer rejected or timed out on a live journal batch.
    #[error("backend event consumer is unavailable")]
    EventConsumerUnusable,
    /// Wolf rejected the exact share with a stable protocol category.
    #[error("backend rejected share with {0:?}")]
    Rejected(BackendErrorCode),
    /// The submission task panicked or was cancelled.
    #[error("backend submission task failed")]
    TaskFailed,
}

impl ShareRouterError {
    fn from_client(error: ClientError) -> Self {
        match error {
            ClientError::BackendRejected { code, .. } => Self::Rejected(code),
            ClientError::HistoricalReplayRequiresProjection { receipt } => {
                Self::ReplayRequiresProjection { receipt }
            }
            _ => Self::Unavailable,
        }
    }

    const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Unavailable
                | Self::JobStreamUnusable
                | Self::EventConsumerUnusable
                | Self::TaskFailed
                | Self::BackendConnectionMismatch
        ) || matches!(self, Self::Rejected(BackendErrorCode::BackendUnhealthy))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{
        error::Error,
        fs, future,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };
    use uuid::Uuid;
    use wcash_pool_backend_client::{BackendClientConfig, ExpectedBackend, MonotonicTimeline};
    use wcash_pool_core::{
        AuthenticatedWorker, GenerationRegistryConfig, JobAssignment, NonceNamespaceLease,
        NoncePrefixAllocator, ShareTarget, TargetBinding, TargetBounds,
    };
    use wcash_pool_protocol::{
        canonical_parent_header_hash_le, canonical_share_id, decode_backend_request,
        encode_backend_message, AcceptableJob, BackendEvent, BackendMessage, BackendRequest,
        CanonicalUuid, Hex108, Hex1344, Hex28, Hex32, JobDescriptor, NonceProfile, NonceSuffix,
        ShareReceipt, TargetLe, BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION,
        REQUIRED_BACKEND_CAPABILITIES,
    };

    use super::*;
    use crate::{JobRouterError, JobUpdate};

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    static SOCKET_ID: AtomicU64 = AtomicU64::new(1);

    struct TestSocket {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestSocket {
        fn new() -> TestResult<Self> {
            let id = SOCKET_ID.fetch_add(1, Ordering::Relaxed);
            let directory =
                PathBuf::from("/tmp").join(format!("wcash-edge-{}-{id}", std::process::id()));
            fs::create_dir(&directory)?;
            Ok(Self {
                path: directory.join("backend.sock"),
                directory,
            })
        }
    }

    impl Drop for TestSocket {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    fn uuid(value: u128) -> CanonicalUuid {
        CanonicalUuid::new(Uuid::from_u128(value))
    }

    fn descriptor(id: u8) -> JobDescriptor {
        let mut header = [id; 108];
        header[..4].copy_from_slice(&4_u32.to_le_bytes());
        header[4..36].copy_from_slice(&[id; 32]);
        header[100..104].copy_from_slice(&1_725_000_000_u32.to_le_bytes());
        JobDescriptor {
            job_id: Hex32::new([id; 32]),
            wcash_candidate_hash_le: Hex32::new([0x73; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([id.wrapping_add(1); 32]),
            zcash_previous_hash_le: Hex32::new([id; 32]),
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

    fn client_config(path: &Path) -> TestResult<BackendClientConfig> {
        let expected =
            ExpectedBackend::new(Hex32::new([0x11; 32]), Hex32::new([0x22; 32]), 0x5743_4153)?
                .with_backend_instance(uuid(2))
                .with_journal_stream(uuid(3));
        Ok(BackendClientConfig::new(path, expected)?
            .with_timeouts(Duration::from_secs(1), Duration::from_secs(1))?)
    }

    async fn read_request(stream: &mut UnixStream) -> TestResult<BackendRequest> {
        let mut prefix = [0; BACKEND_LENGTH_PREFIX_BYTES];
        stream.read_exact(&mut prefix).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&payload);
        Ok(decode_backend_request(&frame)?)
    }

    async fn write_message(stream: &mut UnixStream, message: &BackendMessage) -> TestResult {
        stream.write_all(&encode_backend_message(message)?).await?;
        Ok(())
    }

    async fn establish_live_stream(stream: &mut UnixStream, current: JobDescriptor) -> TestResult {
        let BackendRequest::Hello { id, .. } = read_request(stream).await? else {
            return TestResult::Err("first request was not hello".into());
        };
        write_message(
            stream,
            &BackendMessage::HelloOk {
                version: BACKEND_PROTOCOL_VERSION,
                id,
                backend_session: uuid(1),
                backend_instance: uuid(2),
                journal_stream: uuid(3),
                capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                wcash_genesis: Hex32::new([0x11; 32]),
                zcash_genesis: Hex32::new([0x22; 32]),
                chain_id: 0x5743_4153,
                current_event_seq: 10,
            },
        )
        .await?;
        let BackendRequest::SubscribeJobs { id, .. } = read_request(stream).await? else {
            return TestResult::Err("second request was not subscribe_jobs".into());
        };
        write_message(
            stream,
            &BackendMessage::JobSnapshot {
                version: BACKEND_PROTOCOL_VERSION,
                id,
                event_seq: 10,
                current: Some(AcceptableJob {
                    job: current,
                    accept_for_ms: 30_000,
                }),
                recent: Vec::new(),
            },
        )
        .await
    }

    async fn commit_share(
        stream: &mut UnixStream,
        request: BackendRequest,
        job: &JobDescriptor,
        event_seq: u64,
    ) -> TestResult {
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
            return TestResult::Err(format!("request was not submit_share: {request:?}").into());
        };
        let receipt = ShareReceipt {
            event_seq,
            job_id: job_id.clone(),
            share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
            attribution_id: wcash_pool_protocol::canonical_attribution_id(&identity, &target_le)?,
            parent_hash_le: canonical_parent_header_hash_le(&job.header_input, &nonce, &solution),
            winners: Vec::new(),
        };
        write_message(
            stream,
            &BackendMessage::Event {
                version: BACKEND_PROTOCOL_VERSION,
                event: BackendEvent::ShareCommitted {
                    receipt: receipt.clone(),
                    job_id,
                    identity,
                    target_le,
                },
            },
        )
        .await?;
        write_message(
            stream,
            &BackendMessage::ShareCommitted {
                version: BACKEND_PROTOCOL_VERSION,
                id,
                receipt,
                replayed: false,
            },
        )
        .await
    }

    #[derive(Debug, Default)]
    struct RecordingEventConsumer {
        events: Mutex<Vec<BackendEvent>>,
    }

    impl RecordingEventConsumer {
        fn events(&self) -> TestResult<Vec<BackendEvent>> {
            Ok(self
                .events
                .lock()
                .map_err(|_| "recording event consumer mutex was poisoned")?
                .clone())
        }
    }

    impl BackendEventConsumer for RecordingEventConsumer {
        fn consume<'a>(
            &'a self,
            _authority: &'a BackendAuthority,
            events: &'a [DeliveredBackendEvent],
        ) -> Pin<Box<dyn Future<Output = Result<(), BackendEventConsumerError>> + Send + 'a>>
        {
            let result = self
                .events
                .lock()
                .map_err(|_| BackendEventConsumerError)
                .map(|mut consumed| {
                    consumed.extend(events.iter().map(|event| event.event().clone()));
                });
            Box::pin(future::ready(result))
        }
    }

    #[derive(Debug)]
    struct PendingEventConsumer;

    impl BackendEventConsumer for PendingEventConsumer {
        fn consume<'a>(
            &'a self,
            _authority: &'a BackendAuthority,
            _events: &'a [DeliveredBackendEvent],
        ) -> Pin<Box<dyn Future<Output = Result<(), BackendEventConsumerError>> + Send + 'a>>
        {
            Box::pin(future::pending())
        }
    }

    fn router_config() -> Result<ShareRouterConfig, ShareRouterConfigError> {
        ShareRouterConfig::new(2, Duration::from_secs(30), Duration::from_secs(1))
    }

    fn prepared_context(router: &JobRouter, nonce_byte: u8) -> TestResult<SubmissionContext> {
        let generation = router.current_generation()?.ok_or("missing current job")?;
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
        let mut session = wcash_pool_core::MiningSession::new(Uuid::from_u128(4), 2)?;
        let _ = session.subscribe(&allocator)?;
        session.complete_authorization(AuthenticatedWorker::new(
            Uuid::from_u128(7),
            Uuid::from_u128(8),
            "account.worker",
        )?)?;
        session.announce_job(assignment)?;
        Ok(router.prepare_submission(
            &session,
            "account.worker",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([nonce_byte; 28])),
            Box::new(Hex1344::new([0x61; 1_344])),
        )?)
    }

    #[test]
    fn backend_pump_configuration_is_finite() {
        let config = ShareRouterConfig::new(
            MAXIMUM_QUEUE_CAPACITY,
            MAXIMUM_HEARTBEAT_INTERVAL,
            MAXIMUM_EVENT_CONSUMER_TIMEOUT,
        )
        .expect("finite boundary configuration is valid");
        assert_eq!(config.queue_capacity(), MAXIMUM_QUEUE_CAPACITY);
        assert_eq!(config.heartbeat_interval(), MAXIMUM_HEARTBEAT_INTERVAL);
        assert_eq!(
            config.event_consumer_timeout(),
            MAXIMUM_EVENT_CONSUMER_TIMEOUT
        );
        assert!(matches!(
            ShareRouterConfig::new(0, Duration::from_secs(1), Duration::from_secs(1)),
            Err(ShareRouterConfigError::InvalidQueueCapacity { .. })
        ));
        for (heartbeat, consumer) in [
            (Duration::ZERO, Duration::from_secs(1)),
            (Duration::from_secs(61), Duration::from_secs(1)),
            (Duration::from_secs(1), Duration::ZERO),
            (Duration::from_secs(1), Duration::from_secs(61)),
        ] {
            assert!(matches!(
                ShareRouterConfig::new(1, heartbeat, consumer),
                Err(ShareRouterConfigError::InvalidDuration { .. })
            ));
        }
    }

    #[test]
    fn only_backend_rejections_preserve_a_public_category() {
        let mapped = ShareRouterError::from_client(ClientError::BackendRejected {
            code: BackendErrorCode::LowDifficulty,
            message: "sensitive backend detail".to_owned(),
        });
        assert_eq!(
            mapped,
            ShareRouterError::Rejected(BackendErrorCode::LowDifficulty)
        );
        assert!(!mapped.is_terminal());
        assert!(ShareRouterError::Rejected(BackendErrorCode::BackendUnhealthy).is_terminal());
    }

    #[tokio::test]
    async fn cancelling_owned_shutdown_aborts_actor_and_closes_surviving_handles() -> TestResult {
        let current = AcceptableJob {
            job: descriptor(0x21),
            accept_for_ms: 30_000,
        };
        let router = JobRouter::from_acceptable_for_test(
            1,
            Some(&current),
            &[],
            GenerationRegistryConfig::new(2, 8)?,
            4,
        )?;
        let mut updates = router.subscribe();
        let (sender, receiver) = mpsc::channel(1);
        let handle = ShareRouterHandle { sender };
        let surviving_handle = handle.clone();
        let (started, actor_started) = oneshot::channel();
        let actor_router = router.clone();
        let task = tokio::spawn(async move {
            let _suspension = SuspendOnDrop::new(actor_router, None);
            let _receiver = receiver;
            let _ = started.send(());
            future::pending::<()>().await;
        });
        let service = ShareRouter { handle, task };
        actor_started.await?;

        let shutdown = tokio::spawn(service.shutdown());
        tokio::time::timeout(Duration::from_secs(1), async {
            while surviving_handle.sender.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(!shutdown.is_finished());

        shutdown.abort();
        assert!(shutdown
            .await
            .expect_err("shutdown task is cancelled")
            .is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), surviving_handle.sender.closed()).await?;
        assert!(surviving_handle.sender.is_closed());
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), updates.receive()).await??,
            JobUpdate::Suspended
        ));
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(
                wcash_pool_core::JobRegistryError::NotSynchronized
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn spawn_drains_queued_job_state_before_accepting_submissions() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let first = descriptor(0x21);
        let second = descriptor(0x22);
        let server_first = first.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let BackendRequest::Hello { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("first request was not hello".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HelloOk {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    backend_session: uuid(1),
                    backend_instance: uuid(2),
                    journal_stream: uuid(3),
                    capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                    wcash_genesis: Hex32::new([0x11; 32]),
                    zcash_genesis: Hex32::new([0x22; 32]),
                    chain_id: 0x5743_4153,
                    current_event_seq: 10,
                },
            )
            .await?;

            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: Some(AcceptableJob {
                        job: server_first,
                        accept_for_ms: 30_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("third request was not health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::JobActivated {
                        event_seq: 11,
                        job: second,
                    },
                },
            )
            .await?;
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

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let health = client.health().await?;
        assert_eq!(health.event_seq, 11);
        assert_eq!(client.queued_event_count(), 1);

        let consumer = Arc::new(RecordingEventConsumer::default());
        let service =
            ShareRouter::spawn(client, router.clone(), router_config()?, consumer.clone()).await?;
        assert_eq!(
            consumer
                .events()?
                .iter()
                .map(BackendEvent::event_seq)
                .collect::<Vec<_>>(),
            vec![11]
        );
        assert_eq!(
            router
                .current_generation()?
                .ok_or("queued activation was not installed")?
                .id()
                .into_bytes(),
            [0x22; 32]
        );
        service.shutdown().await?;
        server.await??;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_heartbeat_consumes_and_applies_prequeued_live_events() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let first = descriptor(0x23);
        let second = descriptor(0x24);
        let server_first = first.clone();
        let (event_queued, queued) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            establish_live_stream(&mut stream, server_first).await?;
            // This event waits in the socket while no miner submits work. The next
            // heartbeat must read it with the prior exchange's conservative anchor.
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::JobActivated {
                        event_seq: 11,
                        job: second,
                    },
                },
            )
            .await?;
            let _ = event_queued.send(());

            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("idle pump did not issue health".into());
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

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let mut updates = router.subscribe();
        queued.await?;
        let consumer = Arc::new(RecordingEventConsumer::default());
        let service = ShareRouter::spawn(
            client,
            router.clone(),
            ShareRouterConfig::new(2, Duration::from_secs(10), Duration::from_secs(1))?,
            consumer.clone(),
        )
        .await?;

        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert!(consumer.events()?.is_empty());
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..32 {
            if !consumer.events()?.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            consumer
                .events()?
                .iter()
                .map(BackendEvent::event_seq)
                .collect::<Vec<_>>(),
            vec![11]
        );
        let update = updates.receive().await?;
        assert!(matches!(
            update,
            JobUpdate::Activated { generation, .. }
                if generation.id().into_bytes() == [0x24; 32]
        ));
        assert_eq!(
            router
                .current_generation()?
                .ok_or("idle activation was not installed")?
                .id()
                .into_bytes(),
            [0x24; 32]
        );

        service.shutdown().await?;
        server.await??;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn unflushed_idle_health_watermark_suspends_the_job_stream() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let current = descriptor(0x26);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            establish_live_stream(&mut stream, current).await?;
            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("idle pump did not issue health".into());
            };
            // Advertising sequence 11 without first flushing event 11 is a
            // protocol violation, regardless of the nominal healthy flag.
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

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let mut updates = router.subscribe();
        let consumer = Arc::new(RecordingEventConsumer::default());
        let service = ShareRouter::spawn(
            client,
            router.clone(),
            ShareRouterConfig::new(2, Duration::from_secs(10), Duration::from_secs(1))?,
            consumer.clone(),
        )
        .await?;
        let handle = service.handle();

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(matches!(updates.receive().await?, JobUpdate::Suspended));
        handle.sender.closed().await;
        assert!(consumer.events()?.is_empty());
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(
                wcash_pool_core::JobRegistryError::NotSynchronized
            ))
        ));

        drop(service);
        server.await??;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn event_consumer_timeout_suspends_before_policy_observes_the_batch() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let current = descriptor(0x25);
        let closed_job_id = current.job_id.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            establish_live_stream(&mut stream, current).await?;
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::GenerationClosed {
                        event_seq: 11,
                        job_id: closed_job_id,
                    },
                },
            )
            .await?;
            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("idle pump did not issue health".into());
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

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let mut updates = router.subscribe();
        let service = ShareRouter::spawn(
            client,
            router.clone(),
            ShareRouterConfig::new(2, Duration::from_secs(10), Duration::from_secs(1))?,
            Arc::new(PendingEventConsumer),
        )
        .await?;
        let handle = service.handle();

        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(updates.receive().await?, JobUpdate::Suspended));
        handle.sender.closed().await;
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(
                wcash_pool_core::JobRegistryError::NotSynchronized
            ))
        ));

        drop(service);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn spawn_rejects_an_unusable_live_client_and_suspends_jobs() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let current = descriptor(0x21);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let BackendRequest::Hello { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("first request was not hello".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HelloOk {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    backend_session: uuid(1),
                    backend_instance: uuid(2),
                    journal_stream: uuid(3),
                    capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                    wcash_genesis: Hex32::new([0x11; 32]),
                    zcash_genesis: Hex32::new([0x22; 32]),
                    chain_id: 0x5743_4153,
                    current_event_seq: 10,
                },
            )
            .await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: Some(AcceptableJob {
                        job: current,
                        accept_for_ms: 30_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;
            let BackendRequest::Health { .. } = read_request(&mut stream).await? else {
                return TestResult::Err("third request was not health".into());
            };
            // Clean EOF leaves the already-live stream permanently unusable.
            TestResult::Ok(())
        });

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        assert!(matches!(client.health().await, Err(ClientError::CleanEof)));
        assert!(!client.is_usable());
        let result = ShareRouter::spawn(
            client,
            router.clone(),
            router_config()?,
            Arc::new(RecordingEventConsumer::default()),
        )
        .await;
        assert!(matches!(result, Err(ShareRouterError::Unavailable)));
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(
                wcash_pool_core::JobRegistryError::NotSynchronized
            ))
        ));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn router_rejects_crossed_events_and_clients_with_the_same_authority() -> TestResult {
        let first_socket = TestSocket::new()?;
        let second_socket = TestSocket::new()?;
        let first_listener = UnixListener::bind(&first_socket.path)?;
        let second_listener = UnixListener::bind(&second_socket.path)?;
        let first_job = descriptor(0x21);
        let first_job_id = first_job.job_id.clone();
        let second_job = first_job.clone();

        let first_server = tokio::spawn(async move {
            let (mut stream, _) = first_listener.accept().await?;
            let BackendRequest::Hello { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("first connection did not begin with hello".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HelloOk {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    backend_session: uuid(1),
                    backend_instance: uuid(2),
                    journal_stream: uuid(3),
                    capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                    wcash_genesis: Hex32::new([0x11; 32]),
                    zcash_genesis: Hex32::new([0x22; 32]),
                    chain_id: 0x5743_4153,
                    current_event_seq: 10,
                },
            )
            .await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("first connection did not subscribe".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: Some(AcceptableJob {
                        job: first_job,
                        accept_for_ms: 30_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;
            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("first connection did not request health".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::GenerationClosed {
                        event_seq: 11,
                        job_id: first_job_id,
                    },
                },
            )
            .await?;
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
        let second_server = tokio::spawn(async move {
            let (mut stream, _) = second_listener.accept().await?;
            let BackendRequest::Hello { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second connection did not begin with hello".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HelloOk {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    backend_session: uuid(4),
                    backend_instance: uuid(2),
                    journal_stream: uuid(3),
                    capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                    wcash_genesis: Hex32::new([0x11; 32]),
                    zcash_genesis: Hex32::new([0x22; 32]),
                    chain_id: 0x5743_4153,
                    current_event_seq: 10,
                },
            )
            .await?;
            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second connection did not subscribe".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: Some(AcceptableJob {
                        job: second_job,
                        accept_for_ms: 30_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let timeline = MonotonicTimeline::new();
        let mut first_client =
            BackendClient::connect(client_config(&first_socket.path)?, uuid(9), 10).await?;
        let first_snapshot = first_client.subscribe_jobs(10).await?;
        let router = JobRouter::from_snapshot(
            &first_snapshot,
            GenerationRegistryConfig::new(2, 8)?,
            timeline,
            8,
        )?;
        let health = first_client.health().await?;
        assert_eq!(health.event_seq, 11);
        let first_event = first_client
            .pop_queued_event()
            .ok_or("first client did not retain its event")?;
        let mut second_client =
            BackendClient::connect(client_config(&second_socket.path)?, uuid(9), 10).await?;
        let _second_snapshot = second_client.subscribe_jobs(10).await?;
        let foreign_binding = second_client
            .connection_binding()
            .ok_or("second client lacks a live binding")?;
        assert!(!router.suspend_if_bound(&foreign_binding)?);
        assert!(router.current_generation()?.is_some());
        assert!(matches!(
            router.apply_event(&second_client, &first_event),
            Err(JobRouterError::BackendConnectionMismatch)
        ));
        assert!(router.current_generation()?.is_some());

        let result = ShareRouter::spawn(
            second_client,
            router.clone(),
            router_config()?,
            Arc::new(RecordingEventConsumer::default()),
        )
        .await;
        assert!(matches!(
            result,
            Err(ShareRouterError::BackendConnectionMismatch)
        ));
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(
                wcash_pool_core::JobRegistryError::NotSynchronized
            ))
        ));
        drop(first_client);
        first_server.await??;
        second_server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn interleaved_job_event_is_applied_before_share_success_returns() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let first = descriptor(0x31);
        let second = descriptor(0x32);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_request(&mut stream).await?;
            let BackendRequest::Hello { id, .. } = request else {
                return TestResult::Err("first request was not hello".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HelloOk {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    backend_session: uuid(1),
                    backend_instance: uuid(2),
                    journal_stream: uuid(3),
                    capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                    wcash_genesis: Hex32::new([0x11; 32]),
                    zcash_genesis: Hex32::new([0x22; 32]),
                    chain_id: 0x5743_4153,
                    current_event_seq: 10,
                },
            )
            .await?;

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
                        job: first.clone(),
                        accept_for_ms: 30_000,
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
            assert_eq!(time.as_bytes(), &1_725_000_000_u32.to_le_bytes());
            let parent_hash_le =
                canonical_parent_header_hash_le(&first.header_input, &nonce, &solution);
            let share_id = canonical_share_id(&job_id, &time, &nonce, &solution);
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::JobActivated {
                        event_seq: 11,
                        job: second,
                    },
                },
            )
            .await?;
            let receipt = ShareReceipt {
                event_seq: 12,
                job_id: job_id.clone(),
                share_id,
                attribution_id: wcash_pool_protocol::canonical_attribution_id(
                    &identity, &target_le,
                )?,
                parent_hash_le,
                winners: Vec::new(),
            };
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event: BackendEvent::ShareCommitted {
                        receipt: receipt.clone(),
                        job_id,
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
                    replayed: false,
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let mut updates = router.subscribe();
        let generation = router.current_generation()?.ok_or("missing current job")?;
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
        let mut session = wcash_pool_core::MiningSession::new(Uuid::from_u128(4), 2)?;
        let _ = session.subscribe(&allocator)?;
        session.complete_authorization(AuthenticatedWorker::new(
            Uuid::from_u128(7),
            Uuid::from_u128(8),
            "account.worker",
        )?)?;
        session.announce_job(assignment)?;
        let context = router.prepare_submission(
            &session,
            "account.worker",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([0x51; 28])),
            Box::new(Hex1344::new([0x61; 1_344])),
        )?;

        let consumer = Arc::new(RecordingEventConsumer::default());
        let service =
            ShareRouter::spawn(client, router.clone(), router_config()?, consumer.clone()).await?;
        let handle = service.handle();
        let commit = handle.submit(context).await?;
        assert_eq!(commit.receipt().event_seq, 12);
        assert_eq!(
            consumer
                .events()?
                .iter()
                .map(BackendEvent::event_seq)
                .collect::<Vec<_>>(),
            vec![11, 12]
        );
        let update = tokio::time::timeout(Duration::from_secs(1), updates.receive()).await??;
        assert!(matches!(
            update,
            crate::JobUpdate::Activated { generation, .. }
                if generation.id().into_bytes() == [0x32; 32]
        ));
        assert_eq!(
            router
                .current_generation()?
                .ok_or("missing activated job")?
                .id()
                .into_bytes(),
            [0x32; 32]
        );

        // A cloned producer deliberately remains alive; shutdown must still finish.
        tokio::time::timeout(Duration::from_secs(1), service.shutdown()).await??;
        drop(handle);
        server.await??;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn overdue_heartbeat_wins_over_a_ready_submission() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let job = descriptor(0x35);
        let server_job = job.clone();
        let (first_received, first_started) = oneshot::channel();
        let (release_first, first_released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            establish_live_stream(&mut stream, server_job.clone()).await?;

            let first = read_request(&mut stream).await?;
            if !matches!(first, BackendRequest::SubmitShare { .. }) {
                return TestResult::Err("third request was not submit_share".into());
            }
            let _ = first_received.send(());
            first_released.await?;
            commit_share(&mut stream, first, &server_job, 11).await?;

            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err(
                    "overdue heartbeat was starved by a queued submission".into(),
                );
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

            let second = read_request(&mut stream).await?;
            commit_share(&mut stream, second, &server_job, 12).await?;
            TestResult::Ok(())
        });

        let timeline = MonotonicTimeline::new();
        let config = client_config(&socket.path)?
            .with_timeouts(Duration::from_secs(1), Duration::from_secs(60))?;
        let mut client = BackendClient::connect(config, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let first_context = prepared_context(&router, 0x51)?;
        let second_context = prepared_context(&router, 0x52)?;
        let consumer = Arc::new(RecordingEventConsumer::default());
        let service = ShareRouter::spawn(
            client,
            router,
            ShareRouterConfig::new(2, Duration::from_secs(10), Duration::from_secs(1))?,
            consumer.clone(),
        )
        .await?;
        let handle = service.handle();
        // Real Unix I/O and Tokio's paused-clock auto-advance otherwise make the
        // virtual clock jump while the scripted peer is between socket operations.
        let (stop_clock_guard, mut clock_guard_stop) = oneshot::channel();
        let clock_guard = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut clock_guard_stop => break,
                    _ = tokio::task::yield_now() => {}
                }
            }
        });
        let first_handle = handle.clone();
        let first_submit = tokio::spawn(async move { first_handle.submit(first_context).await });
        first_started.await?;

        let (second_response, second_result) = oneshot::channel();
        handle
            .sender
            .try_send(SubmitCommand::Share {
                context: second_context,
                response: second_response,
            })
            .map_err(|_| "could not enqueue the second test submission")?;
        tokio::time::advance(Duration::from_secs(10)).await;
        let _ = release_first.send(());

        let first_result = first_submit.await?;
        let second_result = second_result.await?;
        let _ = stop_clock_guard.send(());
        clock_guard.await?;
        let server_result = server.await?;
        assert_eq!(first_result?.receipt().event_seq, 11);
        assert_eq!(second_result?.receipt().event_seq, 12);
        assert_eq!(
            consumer
                .events()?
                .iter()
                .map(BackendEvent::event_seq)
                .collect::<Vec<_>>(),
            vec![11, 12]
        );

        service.shutdown().await?;
        drop(handle);
        server_result?;
        Ok(())
    }

    #[tokio::test]
    async fn terminal_backend_rejection_suspends_all_generation_admission() -> TestResult {
        let socket = TestSocket::new()?;
        let listener = UnixListener::bind(&socket.path)?;
        let server_job = descriptor(0x41);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let BackendRequest::Hello { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("first request was not hello".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::HelloOk {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    backend_session: uuid(1),
                    backend_instance: uuid(2),
                    journal_stream: uuid(3),
                    capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                    wcash_genesis: Hex32::new([0x11; 32]),
                    zcash_genesis: Hex32::new([0x22; 32]),
                    chain_id: 0x5743_4153,
                    current_event_seq: 10,
                },
            )
            .await?;

            let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("second request was not subscribe_jobs".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::JobSnapshot {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    event_seq: 10,
                    current: Some(AcceptableJob {
                        job: server_job,
                        accept_for_ms: 30_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;

            let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("third request was not submit_share".into());
            };
            write_message(
                &mut stream,
                &BackendMessage::Error {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    code: BackendErrorCode::BackendUnhealthy,
                    message: "backend journal is unavailable".to_owned(),
                },
            )
            .await?;
            TestResult::Ok(())
        });

        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
        let snapshot = client.subscribe_jobs(10).await?;
        let router =
            JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
        let mut first_updates = router.subscribe();
        let mut second_updates = router.subscribe();
        let generation = router.current_generation()?.ok_or("missing current job")?;
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
        let mut session = wcash_pool_core::MiningSession::new(Uuid::from_u128(4), 2)?;
        let _ = session.subscribe(&allocator)?;
        session.complete_authorization(AuthenticatedWorker::new(
            Uuid::from_u128(7),
            Uuid::from_u128(8),
            "account.worker",
        )?)?;
        session.announce_job(assignment)?;
        let context = router.prepare_submission(
            &session,
            "account.worker",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([0x51; 28])),
            Box::new(Hex1344::new([0x61; 1_344])),
        )?;

        let service = ShareRouter::spawn(
            client,
            router.clone(),
            router_config()?,
            Arc::new(RecordingEventConsumer::default()),
        )
        .await?;
        let handle = service.handle();
        assert!(matches!(
            handle.submit(context).await,
            Err(ShareRouterError::Rejected(
                BackendErrorCode::BackendUnhealthy
            ))
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), first_updates.receive()).await??,
            JobUpdate::Suspended
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), second_updates.receive()).await??,
            JobUpdate::Suspended
        ));
        assert!(matches!(
            router.admissible_job_ids(),
            Err(JobRouterError::Registry(
                wcash_pool_core::JobRegistryError::NotSynchronized
            ))
        ));

        let mut future_updates = router.subscribe();
        assert!(matches!(
            future_updates.receive().await?,
            JobUpdate::Suspended
        ));
        tokio::time::timeout(Duration::from_secs(1), handle.sender.closed()).await?;

        drop(service);
        drop(handle);
        server.await??;
        Ok(())
    }
}

//! Bounded serialization of shares through one identity-checked Wolf client.

use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use wcash_pool_backend_client::{
    BackendClient, BackendConnectionBinding, BackendStreamPhase, ClientError, VerifiedShareCommit,
};
use wcash_pool_core::SubmissionContext;
use wcash_pool_protocol::{BackendErrorCode, ShareReceipt};

use crate::{JobRouter, JobRouterError};

const MAXIMUM_QUEUE_CAPACITY: usize = 4_096;

enum SubmitCommand {
    Share {
        context: SubmissionContext,
        response: oneshot::Sender<Result<VerifiedShareCommit, ShareRouterError>>,
    },
    Shutdown {
        complete: oneshot::Sender<()>,
    },
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
    /// Starts a single-consumer bounded queue around a live backend connection.
    pub fn spawn(
        mut client: BackendClient,
        job_router: JobRouter,
        queue_capacity: usize,
    ) -> Result<Self, ShareRouterError> {
        if !(1..=MAXIMUM_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(ShareRouterError::InvalidQueueCapacity {
                actual: queue_capacity,
                maximum: MAXIMUM_QUEUE_CAPACITY,
            });
        }
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
        if drain_job_events(&mut client, &job_router).is_err() {
            let _ = job_router.suspend();
            return Err(ShareRouterError::JobStreamUnusable);
        }
        if !job_router.client_cursor_matches(&client).unwrap_or(false) {
            let _ = job_router.suspend();
            return Err(ShareRouterError::JobStreamUnusable);
        }
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let handle = ShareRouterHandle { sender };
        let suspension = SuspendOnDrop::new(job_router.clone(), Some(connection_binding));
        let task = tokio::spawn(run_submission_actor(
            client, job_router, receiver, suspension,
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
) {
    while let Some(command) = receiver.recv().await {
        match command {
            SubmitCommand::Share { context, response } => {
                // This guard is declared after `response`, so unwinding or task
                // cancellation suspends admission before dropping the response
                // sender and waking its caller with an unavailable result.
                let mut response_suspension = ResponseSuspension::new(&mut suspension);
                let mut result = client
                    .submit_prepared_share(context)
                    .await
                    .map_err(ShareRouterError::from_client);
                if drain_job_events(&mut client, &job_router).is_err() {
                    result = Err(ShareRouterError::JobStreamUnusable);
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
            SubmitCommand::Shutdown { complete } => {
                suspension.suspend();
                receiver.close();
                fail_pending(&mut receiver).await;
                let _ = complete.send(());
                break;
            }
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

fn drain_job_events(
    client: &mut BackendClient,
    job_router: &JobRouter,
) -> Result<(), JobRouterError> {
    if !job_router.client_binding_matches(client)? {
        return Err(JobRouterError::BackendConnectionMismatch);
    }
    while let Some(event) = client.pop_queued_event() {
        job_router.apply_event(client, &event)?;
    }
    if !job_router.client_binding_matches(client)? {
        return Err(JobRouterError::BackendConnectionMismatch);
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
    /// Queue capacity must be finite and within the hard ceiling.
    #[error("backend queue capacity {actual} is outside 1..={maximum}")]
    InvalidQueueCapacity {
        /// Supplied capacity.
        actual: usize,
        /// Fixed maximum.
        maximum: usize,
    },
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
        sync::atomic::{AtomicU64, Ordering},
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
    use crate::JobUpdate;

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

        let service = ShareRouter::spawn(client, router.clone(), 2)?;
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
        assert!(matches!(
            ShareRouter::spawn(client, router.clone(), 2),
            Err(ShareRouterError::Unavailable)
        ));
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

        assert!(matches!(
            ShareRouter::spawn(second_client, router.clone(), 2),
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

        let service = ShareRouter::spawn(client, router.clone(), 2)?;
        let handle = service.handle();
        let commit = handle.submit(context).await?;
        assert_eq!(commit.receipt().event_seq, 12);
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

        let service = ShareRouter::spawn(client, router.clone(), 2)?;
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

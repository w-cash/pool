//! Bounded serialization of shares through one identity-checked Wolf client.

use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use wcash_pool_backend_client::{
    BackendClient, BackendStreamPhase, ClientError, VerifiedShareCommit,
};
use wcash_pool_core::SubmissionContext;
use wcash_pool_protocol::BackendErrorCode;

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
        client: BackendClient,
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
            return Err(ShareRouterError::BackendNotLive);
        }
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let handle = ShareRouterHandle { sender };
        let task = tokio::spawn(run_submission_actor(client, job_router, receiver));
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
) {
    while let Some(command) = receiver.recv().await {
        match command {
            SubmitCommand::Share { context, response } => {
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
                let _ = response.send(result);
                if terminal {
                    receiver.close();
                    fail_pending(&mut receiver).await;
                    break;
                }
            }
            SubmitCommand::Shutdown { complete } => {
                receiver.close();
                fail_pending(&mut receiver).await;
                let _ = complete.send(());
                break;
            }
        }
    }
}

fn drain_job_events(
    client: &mut BackendClient,
    job_router: &JobRouter,
) -> Result<(), JobRouterError> {
    while let Some(event) = client.pop_queued_event() {
        job_router.apply_event(&event)?;
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
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
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
    /// The bounded submission queue is full.
    #[error("backend submission queue is full")]
    Overloaded,
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
            _ => Self::Unavailable,
        }
    }

    const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::JobStreamUnusable | Self::TaskFailed
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
        decode_backend_request, encode_backend_message, AcceptableJob, BackendEvent,
        BackendMessage, BackendRequest, CanonicalUuid, Hex108, Hex1344, Hex28, Hex32,
        JobDescriptor, NonceProfile, NonceSuffix, ShareReceipt, TargetLe,
        BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, REQUIRED_BACKEND_CAPABILITIES,
    };

    use super::*;

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
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([id.wrapping_add(1); 32]),
            zcash_previous_hash_le: Hex32::new([id; 32]),
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
        let (sender, receiver) = mpsc::channel(1);
        let handle = ShareRouterHandle { sender };
        let surviving_handle = handle.clone();
        let (started, actor_started) = oneshot::channel();
        let task = tokio::spawn(async move {
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
                        job: first,
                        accept_for_ms: 30_000,
                    }),
                    recent: Vec::new(),
                },
            )
            .await?;

            let request = read_request(&mut stream).await?;
            let BackendRequest::SubmitShare { id, time, .. } = request else {
                return TestResult::Err("third request was not submit_share".into());
            };
            assert_eq!(time.as_bytes(), &1_725_000_000_u32.to_le_bytes());
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
                &BackendMessage::ShareCommitted {
                    version: BACKEND_PROTOCOL_VERSION,
                    id,
                    receipt: ShareReceipt {
                        event_seq: 12,
                        share_id: Hex32::new([0x41; 32]),
                        parent_hash_le: Hex32::new([0x42; 32]),
                        winners: Vec::new(),
                    },
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
}

//! Loopback-only TCP composition for deterministic ZIP-301 integration tests.

use std::{fmt, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
    time::{self, Instant},
};
use wcash_pool_backend_client::VerifiedShareCommit;
use wcash_pool_core::SubmissionContext;
use wcash_pool_protocol::{NonceProfile, ProtocolError, Zip301FrameCodec};

use crate::{
    AuthenticationError, AuthenticationProvider, ConnectionAction, ConnectionActor,
    ConnectionActorError, ConnectionPermit, EdgeConfig, JobRouterError, JobSubscription,
    ShareRouterError, ShareRouterHandle,
};

const READ_BUFFER_BYTES: usize = 4 * 1024;

/// Asynchronous boundary used by the stream driver for already prepared shares.
///
/// The concrete implementation delegates to the single bounded [`ShareRouterHandle`].
/// A trait boundary keeps loopback transcript tests independent from a live Wolf
/// process; it does not make a successful backend receipt constructible. The stream
/// driver bounds every returned future with [`EdgeConfig::submission_timeout`].
pub trait ShareSubmissionProvider: Send + Sync {
    /// Submits one core-validated context and returns only a backend-branded result.
    fn submit<'a>(
        &'a self,
        context: SubmissionContext,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedShareCommit, ShareRouterError>> + Send + 'a>>;
}

impl ShareSubmissionProvider for ShareRouterHandle {
    fn submit<'a>(
        &'a self,
        context: SubmissionContext,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedShareCommit, ShareRouterError>> + Send + 'a>>
    {
        Box::pin(async move { ShareRouterHandle::submit(self, context).await })
    }
}

/// Expected, non-error reason that a loopback stream stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamTermination {
    /// The miner closed its TCP stream.
    PeerClosed,
    /// The owner requested bounded local shutdown.
    LocalShutdown,
    /// Session policy emitted any final response and closed the actor.
    ActorClosed,
}

/// A single admitted loopback TCP session around [`ConnectionActor`].
///
/// This type never binds or accepts a socket. Construction rejects any stream
/// whose local or peer address is not loopback and rejects every nonce profile
/// except the standard four-byte server prefix plus 28-byte miner suffix. Holding
/// the supplied [`ConnectionPermit`] accounts for this session until `run` ends
/// or its future is cancelled.
pub struct LoopbackStreamDriver {
    stream: TcpStream,
    actor: ConnectionActor,
    job_updates: JobSubscription,
    authentication: Arc<dyn AuthenticationProvider>,
    submissions: Arc<dyn ShareSubmissionProvider>,
    _connection_permit: ConnectionPermit,
    config: EdgeConfig,
    codec: Zip301FrameCodec,
    clock_origin: Instant,
    clock_origin_ms: u64,
    frame_started_at: Option<Instant>,
    idle_deadline: Instant,
}

impl fmt::Debug for LoopbackStreamDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackStreamDriver")
            .field("actor", &self.actor)
            .field("buffered_bytes", &self.codec.buffered_bytes())
            .field("frame_in_progress", &self.frame_started_at.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for LoopbackStreamDriver {
    fn drop(&mut self) {
        // `run` can be cancelled at any await point. Keep actor teardown tied to
        // ownership so cancellation cannot leave the logical session open.
        if !self.actor.is_closed() {
            self.actor.transport_failed();
        }
    }
}

impl LoopbackStreamDriver {
    /// Composes one already accepted loopback stream with an edge actor.
    ///
    /// `clock_origin_ms` must be the same monotonic millisecond value used when
    /// constructing `actor`. The driver adds elapsed Tokio monotonic time without
    /// consulting wall-clock time.
    pub fn new(
        stream: TcpStream,
        actor: ConnectionActor,
        authentication: Arc<dyn AuthenticationProvider>,
        submissions: Arc<dyn ShareSubmissionProvider>,
        connection_permit: ConnectionPermit,
        clock_origin_ms: u64,
    ) -> Result<Self, StreamDriverError> {
        let local = stream
            .local_addr()
            .map_err(StreamDriverError::SocketIdentity)?;
        let peer = stream
            .peer_addr()
            .map_err(StreamDriverError::SocketIdentity)?;
        if !local.ip().is_loopback() || !peer.ip().is_loopback() {
            return Err(StreamDriverError::LoopbackRequired { local, peer });
        }
        if actor.nonce_profile() != NonceProfile::FourByte {
            return Err(StreamDriverError::UnsupportedNonceProfile);
        }
        let config = actor.edge_config();
        let job_updates = actor.subscribe_job_updates();
        let clock_origin = Instant::now();
        let idle_deadline = clock_origin + config.idle_timeout();
        Ok(Self {
            stream,
            actor,
            job_updates,
            authentication,
            submissions,
            _connection_permit: connection_permit,
            config,
            codec: Zip301FrameCodec::new(),
            clock_origin,
            clock_origin_ms,
            frame_started_at: None,
            idle_deadline,
        })
    }

    /// Drives strict requests, ordered job updates, and bounded external actions.
    ///
    /// Actions are deliberately awaited inline: one connection cannot create an
    /// unbounded set of authentication or backend tasks. Cancelling this future
    /// drops the owned stream and permit; explicit shutdown additionally sends a
    /// bounded TCP write-half shutdown.
    pub async fn run(
        mut self,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<StreamTermination, StreamDriverError> {
        let result = self.run_inner(&mut shutdown).await;
        self.actor.transport_failed();
        let shutdown_deadline = Instant::now() + self.config.write_timeout();
        let _ = time::timeout_at(shutdown_deadline, self.stream.shutdown()).await;
        result
    }

    async fn run_inner(
        &mut self,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<StreamTermination, StreamDriverError> {
        self.flush_outbound().await?;
        let mut read_buffer = [0u8; READ_BUFFER_BYTES];

        loop {
            if self.actor.is_closed() {
                self.flush_outbound().await?;
                return Ok(StreamTermination::ActorClosed);
            }

            let idle_sleep = time::sleep_until(self.idle_deadline);
            tokio::pin!(idle_sleep);
            let frame_deadline = self
                .frame_started_at
                .map(|started| started + self.config.frame_timeout())
                .unwrap_or(self.idle_deadline);
            let frame_sleep = time::sleep_until(frame_deadline);
            tokio::pin!(frame_sleep);

            let event = tokio::select! {
                biased;
                _ = &mut *shutdown => WaitEvent::Shutdown,
                _ = &mut frame_sleep, if self.frame_started_at.is_some() => {
                    WaitEvent::FrameTimeout
                }
                _ = &mut idle_sleep => WaitEvent::IdleTimeout,
                update = self.job_updates.receive() => WaitEvent::JobUpdate(update),
                read = self.stream.read(&mut read_buffer) => WaitEvent::Read(read),
            };

            match event {
                WaitEvent::Shutdown => return Ok(StreamTermination::LocalShutdown),
                WaitEvent::IdleTimeout => return Err(StreamDriverError::IdleTimeout),
                WaitEvent::FrameTimeout => return Err(StreamDriverError::FrameReadTimeout),
                WaitEvent::JobUpdate(update) => {
                    self.actor.apply_job_update(update?)?;
                    self.flush_outbound().await?;
                }
                WaitEvent::Read(Ok(0)) => return Ok(StreamTermination::PeerClosed),
                WaitEvent::Read(Ok(read)) => {
                    if let Some(termination) =
                        self.handle_received(&read_buffer[..read], shutdown).await?
                    {
                        return Ok(termination);
                    }
                }
                WaitEvent::Read(Err(error)) => return Err(StreamDriverError::Read(error)),
            }
        }
    }

    async fn handle_received(
        &mut self,
        bytes: &[u8],
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<Option<StreamTermination>, StreamDriverError> {
        let received_at = Instant::now();
        let mut consumed = 0usize;
        while consumed < bytes.len() {
            if self.frame_started_at.is_none() {
                self.frame_started_at = Some(received_at);
            }
            let (frame_bytes, request) = self
                .codec
                .decode_request(&bytes[consumed..], NonceProfile::FourByte)?;
            if frame_bytes == 0 {
                return Err(StreamDriverError::DecoderMadeNoProgress);
            }
            consumed = consumed
                .checked_add(frame_bytes)
                .ok_or(StreamDriverError::DecoderMadeNoProgress)?;

            let Some(request) = request else {
                continue;
            };
            self.frame_started_at = None;
            self.idle_deadline = Instant::now() + self.config.idle_timeout();
            let now_ms = self.monotonic_now_ms()?;
            let action = self.actor.handle_request(request, now_ms)?;
            self.flush_outbound().await?;
            if self.actor.is_closed() {
                return Ok(Some(StreamTermination::ActorClosed));
            }
            if let Some(action) = action {
                if let Some(termination) = self.execute_action(action, shutdown).await? {
                    return Ok(Some(termination));
                }
            }
        }
        Ok(None)
    }

    async fn execute_action(
        &mut self,
        action: ConnectionAction,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> Result<Option<StreamTermination>, StreamDriverError> {
        match action {
            ConnectionAction::Authenticate(ticket) => {
                let deadline = Instant::now() + self.config.authorization_timeout();
                let (result, timed_out) = {
                    let authentication = self.authentication.authenticate(&ticket);
                    tokio::pin!(authentication);
                    tokio::select! {
                        biased;
                        _ = &mut *shutdown => {
                            return Ok(Some(StreamTermination::LocalShutdown));
                        }
                        result = time::timeout_at(deadline, &mut authentication) => match result {
                            Ok(result) => (result, false),
                            Err(_) => (Err(AuthenticationError::Unavailable), true),
                        },
                    }
                };
                self.actor.complete_authorization(ticket, result)?;
                self.flush_outbound().await?;
                if timed_out {
                    return Err(StreamDriverError::AuthorizationTimeout);
                }
            }
            ConnectionAction::Submit(pending) => {
                let (ticket, context) = pending.into_parts();
                let deadline = Instant::now() + self.config.submission_timeout();
                let (result, timed_out) = {
                    let submission = self.submissions.submit(context);
                    tokio::pin!(submission);
                    tokio::select! {
                        biased;
                        _ = &mut *shutdown => {
                            return Ok(Some(StreamTermination::LocalShutdown));
                        }
                        result = time::timeout_at(deadline, &mut submission) => match result {
                            Ok(result) => (result, false),
                            Err(_) => (Err(ShareRouterError::Unavailable), true),
                        },
                    }
                };
                self.actor.complete_submission(ticket, result)?;
                self.flush_outbound().await?;
                if timed_out {
                    return Err(StreamDriverError::SubmissionTimeout);
                }
            }
        }
        if self.actor.is_closed() {
            Ok(Some(StreamTermination::ActorClosed))
        } else {
            Ok(None)
        }
    }

    async fn flush_outbound(&mut self) -> Result<(), StreamDriverError> {
        let deadline = Instant::now() + self.config.write_timeout();
        let mut wrote = false;
        while let Some(frame) = self.actor.pop_outbound_frame()? {
            write_all_until(&mut self.stream, &frame, deadline).await?;
            wrote = true;
        }
        if wrote {
            flush_until(&mut self.stream, deadline).await?;
        }
        Ok(())
    }

    fn monotonic_now_ms(&self) -> Result<u64, StreamDriverError> {
        let elapsed = u64::try_from(self.clock_origin.elapsed().as_millis())
            .map_err(|_| StreamDriverError::MonotonicClockOverflow)?;
        self.clock_origin_ms
            .checked_add(elapsed)
            .ok_or(StreamDriverError::MonotonicClockOverflow)
    }
}

enum WaitEvent {
    Shutdown,
    IdleTimeout,
    FrameTimeout,
    JobUpdate(Result<crate::JobUpdate, JobRouterError>),
    Read(io::Result<usize>),
}

async fn write_all_until<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), StreamDriverError> {
    time::timeout_at(deadline, writer.write_all(bytes))
        .await
        .map_err(|_| StreamDriverError::WriteTimeout)?
        .map_err(StreamDriverError::Write)
}

async fn flush_until<W: AsyncWrite + Unpin>(
    writer: &mut W,
    deadline: Instant,
) -> Result<(), StreamDriverError> {
    time::timeout_at(deadline, writer.flush())
        .await
        .map_err(|_| StreamDriverError::WriteTimeout)?
        .map_err(StreamDriverError::Write)
}

/// Loopback stream composition failure.
#[derive(Debug, Error)]
pub enum StreamDriverError {
    /// The socket identity could not be inspected before accepting bytes.
    #[error("could not inspect loopback socket identity")]
    SocketIdentity(#[source] io::Error),
    /// Either side of the supplied TCP stream was not a loopback address.
    #[error("test stream must be loopback-only (local {local}, peer {peer})")]
    LoopbackRequired {
        /// Bound local address.
        local: SocketAddr,
        /// Connected peer address.
        peer: SocketAddr,
    },
    /// Only the standard four-byte server nonce prefix is accepted by this driver.
    #[error("loopback stream driver supports only the four-byte nonce profile")]
    UnsupportedNonceProfile,
    /// No complete request arrived before the absolute idle deadline.
    #[error("ZIP-301 connection idle deadline elapsed")]
    IdleTimeout,
    /// A partial LF-delimited request exceeded its absolute assembly deadline.
    #[error("ZIP-301 frame read deadline elapsed")]
    FrameReadTimeout,
    /// One complete serialized write batch exceeded its absolute deadline.
    #[error("ZIP-301 write deadline elapsed")]
    WriteTimeout,
    /// Credential verification exceeded its absolute deadline.
    #[error("ZIP-301 authorization deadline elapsed")]
    AuthorizationTimeout,
    /// One admitted share did not receive a backend result before its deadline.
    #[error("ZIP-301 share submission deadline elapsed")]
    SubmissionTimeout,
    /// Monotonic milliseconds could not be represented for actor policy.
    #[error("ZIP-301 monotonic clock overflowed")]
    MonotonicClockOverflow,
    /// The strict decoder consumed no bytes and would otherwise spin.
    #[error("ZIP-301 decoder made no progress")]
    DecoderMadeNoProgress,
    /// Reading miner bytes failed.
    #[error("ZIP-301 stream read failed")]
    Read(#[source] io::Error),
    /// Writing miner bytes failed.
    #[error("ZIP-301 stream write failed")]
    Write(#[source] io::Error),
    /// Strict LF or JSON protocol validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Per-connection state policy failed closed.
    #[error(transparent)]
    Actor(#[from] ConnectionActorError),
    /// The global job stream failed or this consumer lagged.
    #[error(transparent)]
    JobRouter(#[from] JobRouterError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{
        future::pending,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tokio::{io::AsyncReadExt, net::TcpListener};
    use uuid::Uuid;
    use wcash_pool_core::{
        AuthenticatedWorker, BackendGeneration, GenerationRegistryConfig, NonceNamespaceLease,
        NoncePrefixAllocator, ShareTarget, TargetBounds, VardiffConfig,
    };
    use wcash_pool_protocol::{
        AcceptableJob, BackendErrorCode, Hex108, Hex32, JobDescriptor, TargetLe,
    };

    use super::*;
    use crate::{ConnectionCapacity, ConnectionLimits, MiningPolicy, RateLimit};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Debug)]
    struct AllowAuthentication;

    impl AuthenticationProvider for AllowAuthentication {
        fn authenticate<'a>(
            &'a self,
            ticket: &'a crate::AuthenticationTicket,
        ) -> Pin<
            Box<dyn Future<Output = Result<AuthenticatedWorker, AuthenticationError>> + Send + 'a>,
        > {
            Box::pin(async move {
                AuthenticatedWorker::new(Uuid::from_u128(2), Uuid::from_u128(3), ticket.worker())
                    .map_err(|_| AuthenticationError::Denied)
            })
        }
    }

    #[derive(Debug)]
    struct HangingAuthentication;

    impl AuthenticationProvider for HangingAuthentication {
        fn authenticate<'a>(
            &'a self,
            _ticket: &'a crate::AuthenticationTicket,
        ) -> Pin<
            Box<dyn Future<Output = Result<AuthenticatedWorker, AuthenticationError>> + Send + 'a>,
        > {
            Box::pin(pending())
        }
    }

    #[derive(Debug, Default)]
    struct HangingSubmissions {
        calls: AtomicUsize,
    }

    impl ShareSubmissionProvider for HangingSubmissions {
        fn submit<'a>(
            &'a self,
            _context: SubmissionContext,
        ) -> Pin<Box<dyn Future<Output = Result<VerifiedShareCommit, ShareRouterError>> + Send + 'a>>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(pending())
        }
    }

    #[derive(Debug, Default)]
    struct RejectingSubmissions {
        calls: AtomicUsize,
    }

    impl ShareSubmissionProvider for RejectingSubmissions {
        fn submit<'a>(
            &'a self,
            _context: SubmissionContext,
        ) -> Pin<Box<dyn Future<Output = Result<VerifiedShareCommit, ShareRouterError>> + Send + 'a>>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ShareRouterError::Rejected(BackendErrorCode::LowDifficulty)) })
        }
    }

    fn descriptor(id: u8) -> JobDescriptor {
        let mut header = [id; 108];
        header[..4].copy_from_slice(&[4, 0, 0, 0]);
        header[4..36].copy_from_slice(&[id.wrapping_add(1); 32]);
        header[100..104].copy_from_slice(&[1, 2, 3, id]);
        JobDescriptor {
            job_id: Hex32::new([id; 32]),
            wcash_candidate_hash_le: Hex32::new([5; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([id.wrapping_add(2); 32]),
            zcash_previous_hash_le: Hex32::new([id.wrapping_add(1); 32]),
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

    fn edge_config(
        idle: Duration,
        frame: Duration,
        write: Duration,
        authorization: Duration,
        submission: Duration,
    ) -> EdgeConfig {
        let limits = ConnectionLimits::new(2, 8, 8, 4).expect("limits are valid");
        let rate = RateLimit::new(32, Duration::from_secs(1)).expect("rate is valid");
        EdgeConfig::new(limits, rate, idle, frame, write, authorization, submission)
            .expect("edge config is valid")
    }

    fn actor(config: EdgeConfig, profile: NonceProfile) -> ConnectionActor {
        let descriptor = descriptor(1);
        let generation =
            BackendGeneration::from_descriptor(descriptor.clone()).expect("descriptor is valid");
        let bounds = TargetBounds::new(
            generation.wcash_network_target(),
            generation.zcash_network_target(),
            ShareTarget::MAX,
        )
        .expect("target bounds are valid");
        let policy = MiningPolicy::new(
            VardiffConfig::new(10_000, 8, 2_500, 4, ShareTarget::MAX).expect("vardiff is valid"),
            bounds.hardest_allowed(),
        );
        let router = crate::JobRouter::from_acceptable_for_test(
            1,
            Some(&AcceptableJob {
                job: descriptor,
                accept_for_ms: 30_000,
            }),
            &[],
            GenerationRegistryConfig::new(2, 8).expect("registry config is valid"),
            8,
        )
        .expect("router is valid");
        let allocator = Arc::new(NoncePrefixAllocator::new(
            profile,
            NonceNamespaceLease::new(7).expect("nonce lease is valid"),
        ));
        ConnectionActor::new(Uuid::from_u128(1), config, policy, allocator, router, 0)
            .expect("actor is valid")
    }

    async fn tcp_pair() -> Result<(TcpStream, TcpStream), io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        Ok((client?, accepted?.0))
    }

    async fn read_line(stream: &mut TcpStream) -> Result<Vec<u8>, io::Error> {
        let mut line = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            line.push(byte);
            if byte == b'\n' {
                return Ok(line);
            }
        }
    }

    fn standard_driver(
        stream: TcpStream,
        actor: ConnectionActor,
        authentication: Arc<dyn AuthenticationProvider>,
        submissions: Arc<dyn ShareSubmissionProvider>,
        capacity: &ConnectionCapacity,
    ) -> Result<LoopbackStreamDriver, StreamDriverError> {
        LoopbackStreamDriver::new(
            stream,
            actor,
            authentication,
            submissions,
            capacity
                .try_acquire()
                .expect("connection capacity is available"),
            0,
        )
    }

    #[tokio::test]
    async fn fragmented_and_coalesced_standard_transcript_is_byte_exact() -> TestResult {
        let (mut client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let submissions = Arc::new(RejectingSubmissions::default());
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(AllowAuthentication),
            submissions.clone(),
            &capacity,
        )?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(driver.run(stopped));

        let requests = concat!(
            "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"fixture/1\",null,\"127.0.0.1\",1]}\n",
            "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"account.rig\",\"x\"]}\n"
        )
        .as_bytes();
        for chunk in requests.chunks(7) {
            client.write_all(chunk).await?;
        }

        assert_eq!(
            read_line(&mut client).await?,
            b"{\"id\":1,\"result\":[null,\"07000000\"],\"error\":null}\n"
        );
        assert_eq!(
            read_line(&mut client).await?,
            b"{\"id\":2,\"result\":true,\"error\":null}\n"
        );
        assert_eq!(
            read_line(&mut client).await?,
            format!(
                "{{\"id\":null,\"method\":\"mining.set_target\",\"params\":[\"{}\"]}}\n",
                "04".repeat(32)
            )
            .into_bytes()
        );
        assert_eq!(
            read_line(&mut client).await?,
            format!(
                concat!(
                    "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[",
                    "\"{}\",\"04000000\",\"{}\",\"{}\",\"{}\",",
                    "\"01020301\",\"01010101\",true]}}\n"
                ),
                "01".repeat(32),
                "02".repeat(32),
                "01".repeat(32),
                "01".repeat(32),
            )
            .into_bytes()
        );

        let submit = format!(
            concat!(
                "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[",
                "\"account.rig\",\"{}\",\"01020301\",\"{}\",\"fd4005{}\"]}}\n"
            ),
            "01".repeat(32),
            "22".repeat(28),
            "00".repeat(1_344),
        );
        for chunk in submit.as_bytes().chunks(113) {
            client.write_all(chunk).await?;
        }
        assert_eq!(
            read_line(&mut client).await?,
            b"{\"id\":3,\"result\":null,\"error\":[23,\"low difficulty share\",null]}\n"
        );
        assert_eq!(submissions.calls.load(Ordering::SeqCst), 1);

        stop.send(())
            .map_err(|_| "driver stopped before shutdown")?;
        assert_eq!(task.await??, StreamTermination::LocalShutdown);
        assert_eq!(capacity.available_permits(), 1);
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn partial_frame_uses_one_absolute_read_deadline() -> TestResult {
        let (mut client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(2),
            Duration::from_millis(50),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(AllowAuthentication),
            Arc::new(RejectingSubmissions::default()),
            &capacity,
        )?;
        // Queue the fragment before the task starts so its first socket read
        // deterministically establishes the absolute frame deadline.
        client.write_all(b"{").await?;
        let (_stop, stopped) = oneshot::channel();
        let task = tokio::spawn(driver.run(stopped));
        let result = task.await?;
        assert!(
            matches!(result, Err(StreamDriverError::FrameReadTimeout)),
            "unexpected driver result: {result:?}"
        );
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn idle_deadline_closes_a_silent_connection() -> TestResult {
        let (_client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_millis(50),
            Duration::from_millis(40),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(AllowAuthentication),
            Arc::new(RejectingSubmissions::default()),
            &capacity,
        )?;
        let (_stop, stopped) = oneshot::channel();
        assert!(matches!(
            driver.run(stopped).await,
            Err(StreamDriverError::IdleTimeout)
        ));
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_line_fails_closed_without_json_recovery() -> TestResult {
        let (mut client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(1),
            Duration::from_millis(250),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(AllowAuthentication),
            Arc::new(RejectingSubmissions::default()),
            &capacity,
        )?;
        let (_stop, stopped) = oneshot::channel();
        let task = tokio::spawn(driver.run(stopped));
        client
            .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\r\n")
            .await?;
        assert!(matches!(
            task.await?,
            Err(StreamDriverError::Protocol(
                ProtocolError::InvalidLineFraming
            ))
        ));
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn authorization_deadline_is_absolute_and_terminal() -> TestResult {
        let (mut client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(50),
            Duration::from_secs(1),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(HangingAuthentication),
            Arc::new(RejectingSubmissions::default()),
            &capacity,
        )?;
        client
            .write_all(
                concat!(
                "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n",
                "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"account.rig\",\"x\"]}\n"
            )
                .as_bytes(),
            )
            .await?;
        client.shutdown().await?;
        let (_stop, stopped) = oneshot::channel();
        let task = tokio::spawn(driver.run(stopped));
        assert_eq!(
            read_line(&mut client).await?,
            b"{\"id\":1,\"result\":[null,\"07000000\"],\"error\":null}\n"
        );
        assert_eq!(
            read_line(&mut client).await?,
            b"{\"id\":2,\"result\":null,\"error\":[20,\"service unavailable\",null]}\n"
        );
        assert!(matches!(
            task.await?,
            Err(StreamDriverError::AuthorizationTimeout)
        ));
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn submission_deadline_is_absolute_and_terminal() -> TestResult {
        let (mut client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(50),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let submissions = Arc::new(HangingSubmissions::default());
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(AllowAuthentication),
            submissions.clone(),
            &capacity,
        )?;
        let submit = format!(
            concat!(
                "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[",
                "\"account.rig\",\"{}\",\"01020301\",\"{}\",\"fd4005{}\"]}}\n"
            ),
            "01".repeat(32),
            "22".repeat(28),
            "00".repeat(1_344),
        );
        let mut requests = concat!(
            "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n",
            "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"account.rig\",\"x\"]}\n"
        )
        .as_bytes()
        .to_vec();
        requests.extend_from_slice(submit.as_bytes());
        client.write_all(&requests).await?;
        client.shutdown().await?;
        let (_stop, stopped) = oneshot::channel();
        let task = tokio::spawn(driver.run(stopped));
        let subscribed = read_line(&mut client).await.map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("subscription response could not be read: {source}"),
            )
        })?;
        assert_eq!(
            subscribed,
            b"{\"id\":1,\"result\":[null,\"07000000\"],\"error\":null}\n"
        );
        let authorized = read_line(&mut client).await.map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("authorization response could not be read: {source}"),
            )
        })?;
        assert_eq!(authorized, b"{\"id\":2,\"result\":true,\"error\":null}\n");
        let _set_target = read_line(&mut client).await.map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("target notification could not be read: {source}"),
            )
        })?;
        let _notify = read_line(&mut client).await.map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("job notification could not be read: {source}"),
            )
        })?;

        let rejected = read_line(&mut client).await.map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("timeout response could not be read: {source}"),
            )
        })?;
        assert_eq!(
            rejected,
            b"{\"id\":3,\"result\":null,\"error\":[20,\"service unavailable\",null]}\n"
        );
        assert!(matches!(
            task.await?,
            Err(StreamDriverError::SubmissionTimeout)
        ));
        assert_eq!(submissions.calls.load(Ordering::SeqCst), 1);
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_drops_stream_and_connection_permit() -> TestResult {
        let (mut client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let driver = standard_driver(
            server,
            actor(config, NonceProfile::FourByte),
            Arc::new(AllowAuthentication),
            Arc::new(RejectingSubmissions::default()),
            &capacity,
        )?;
        let (_stop, stopped) = oneshot::channel();
        let task = tokio::spawn(driver.run(stopped));
        assert_eq!(capacity.available_permits(), 0);
        task.abort();
        assert!(task.await.is_err());
        assert_eq!(capacity.available_permits(), 1);
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn eight_byte_nonce_profile_is_rejected_before_reading() -> TestResult {
        let (_client, server) = tcp_pair().await?;
        let config = edge_config(
            Duration::from_secs(1),
            Duration::from_millis(250),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let capacity = ConnectionCapacity::new(1)?;
        let result = standard_driver(
            server,
            actor(config, NonceProfile::EightByte),
            Arc::new(AllowAuthentication),
            Arc::new(RejectingSubmissions::default()),
            &capacity,
        );
        assert!(matches!(
            result,
            Err(StreamDriverError::UnsupportedNonceProfile)
        ));
        assert_eq!(capacity.available_permits(), 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_writer_obeys_absolute_write_deadline() -> TestResult {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let deadline = Instant::now() + Duration::from_millis(35);
        assert!(matches!(
            write_all_until(&mut writer, &[0u8; 16], deadline).await,
            Err(StreamDriverError::WriteTimeout)
        ));
        Ok(())
    }
}

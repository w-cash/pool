use super::*;
use std::sync::atomic::{AtomicU8, AtomicUsize};
use tokio::sync::Notify;
use wcash_pool_protocol::{MergedChain, WinnerDescriptor};

#[derive(Default)]
struct GatedProjection {
    // 0 = lagging, 1 = exact durable acknowledgement, 2 = permanent conflict.
    outcome: AtomicU8,
    calls: AtomicUsize,
    acknowledged: AtomicUsize,
    attempted: Notify,
    expected: Mutex<
        Option<(
            BackendAuthority,
            BackendConnectionBinding,
            Vec<BackendEvent>,
        )>,
    >,
}

impl BackendEventConsumer for GatedProjection {
    fn consume<'a>(
        &'a self,
        authority: &'a BackendAuthority,
        events: &'a [DeliveredBackendEvent],
    ) -> Pin<Box<dyn Future<Output = Result<(), BackendEventConsumerError>> + Send + 'a>> {
        Box::pin(async move {
            let first = events
                .first()
                .ok_or(BackendEventConsumerError::InvalidBatch)?;
            let binding = first.connection_binding().clone();
            let batch: Vec<_> = events.iter().map(|event| event.event().clone()).collect();
            if events
                .iter()
                .any(|event| event.connection_binding() != &binding)
            {
                return Err(BackendEventConsumerError::AuthorityMismatch);
            }
            {
                let mut expected = self
                    .expected
                    .lock()
                    .map_err(|_| BackendEventConsumerError::StorageRejected)?;
                match expected.as_ref() {
                    Some((original_authority, original_binding, original_batch)) => {
                        assert_eq!(original_authority, authority, "retry changed authority");
                        assert_eq!(original_binding, &binding, "retry changed connection epoch");
                        assert_eq!(original_batch, &batch, "retry changed ordered event bytes");
                    }
                    None => *expected = Some((authority.clone(), binding, batch)),
                }
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.attempted.notify_one();
            match self.outcome.load(Ordering::SeqCst) {
                1 => {
                    self.acknowledged.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
                2 => Err(BackendEventConsumerError::EventConflict),
                _ => Err(BackendEventConsumerError::ProjectionLag {
                    projected: 10,
                    required: events.last().expect("nonempty batch").event().event_seq(),
                }),
            }
        })
    }
}

struct QueuedProjection {
    _socket: TestSocket,
    client: BackendClient,
    router: JobRouter,
    original_job: wcash_pool_core::JobId,
    replacement_job: wcash_pool_core::JobId,
    health_calls: Arc<AtomicUsize>,
    stop: oneshot::Sender<()>,
    peer: tokio::task::JoinHandle<TestResult>,
}

async fn healthy(stream: &mut UnixStream, id: u64, cursor: u64) -> TestResult {
    write_message(
        stream,
        &BackendMessage::HealthStatus {
            version: BACKEND_PROTOCOL_VERSION,
            id,
            event_seq: cursor,
            healthy: true,
            recovery_only: false,
            pending_wcash: 0,
            quarantined_wcash: 0,
            pending_zcash: 0,
        },
    )
    .await
}

async fn queued_projection(replacement_lifetime_ms: u32) -> TestResult<QueuedProjection> {
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let first = descriptor(0x67);
    let first_id = wcash_pool_core::JobId::new(*first.job_id.as_bytes())?;
    let mut second = descriptor(0x68);
    second.max_age_ms = replacement_lifetime_ms;
    let second_id = wcash_pool_core::JobId::new(*second.job_id.as_bytes())?;
    let first_closed = first.job_id.clone();
    let (stop, mut stopped) = oneshot::channel();
    let health_calls = Arc::new(AtomicUsize::new(0));
    let peer_calls = Arc::clone(&health_calls);
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, first).await?;
        let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
            return Err("expected initial health barrier".into());
        };
        peer_calls.fetch_add(1, Ordering::SeqCst);
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
            &BackendMessage::Event {
                version: BACKEND_PROTOCOL_VERSION,
                event: BackendEvent::GenerationClosed {
                    event_seq: 12,
                    job_id: first_closed,
                },
            },
        )
        .await?;
        healthy(&mut stream, id, 12).await?;
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return Ok(()),
                request = read_request(&mut stream) => {
                    let BackendRequest::Health { id, .. } = request? else {
                        return Err("projection recovery issued an unexpected backend request".into());
                    };
                    peer_calls.fetch_add(1, Ordering::SeqCst);
                    healthy(&mut stream, id, 12).await?;
                }
            }
        }
    });
    let timeline = MonotonicTimeline::new();
    let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    client.health().await?;
    assert_eq!(client.queued_event_count(), 2);
    Ok(QueuedProjection {
        _socket: socket,
        client,
        router,
        original_job: first_id,
        replacement_job: second_id,
        health_calls,
        stop,
        peer,
    })
}

async fn observe_pause(router: &JobRouter) -> TestResult {
    for _ in 0..128 {
        if router.current_generation()?.is_none() {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err("transient projection failure did not pause ordinary admission".into())
}

#[test]
fn projection_recovery_retry_allowlist_is_narrow() {
    for error in [
        BackendEventConsumerError::ProjectionLag {
            projected: 1,
            required: 2,
        },
        BackendEventConsumerError::StorageUnavailable,
        BackendEventConsumerError::TimedOut,
    ] {
        assert!(error.is_retryable());
    }
    for error in [
        BackendEventConsumerError::AuthorityMismatch,
        BackendEventConsumerError::InvalidBatch,
        BackendEventConsumerError::EventConflict,
        BackendEventConsumerError::StorageRejected,
    ] {
        assert!(!error.is_retryable());
    }
}

#[tokio::test(start_paused = true)]
async fn projection_recovery_keeps_exact_batch_and_requires_fresh_health() -> TestResult {
    for wait in [
        Duration::from_millis(4_900),
        Duration::from_millis(5_100),
        Duration::from_secs(15),
    ] {
        let QueuedProjection {
            _socket,
            mut client,
            router,
            original_job,
            replacement_job,
            health_calls,
            stop,
            peer,
        } = queued_projection(45_000).await?;
        let consumer = Arc::new(GatedProjection::default());
        let worker_consumer = Arc::clone(&consumer);
        let worker_router = router.clone();
        let pending = tokio::spawn(async move {
            let result = drain_backend_events(
                &mut client,
                &worker_router,
                worker_consumer.as_ref(),
                Duration::from_secs(1),
            )
            .await;
            (client, result)
        });
        consumer.attempted.notified().await;
        observe_pause(&router).await?;
        assert_eq!(router.retained_job_ids()?, vec![original_job]);
        assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 0);
        tokio::time::advance(wait).await;
        assert!(!pending.is_finished());
        assert_eq!(
            router.retained_job_ids()?,
            vec![original_job],
            "batch was partially applied before acknowledgement"
        );
        consumer.outcome.store(1, Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(100)).await;
        let (mut client, recovered) = pending.await?;
        assert!(recovered?);
        assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 1);
        assert!(consumer.calls.load(Ordering::SeqCst) >= 2);
        assert!(
            router.current_generation()?.is_none(),
            "old healthy response resumed ordinary mining"
        );
        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
        let fresh = client.health().await?;
        assert!(fresh.healthy);
        router.resume_after_health(&client)?;
        assert_eq!(
            router
                .current_generation()?
                .ok_or("fresh health did not resume mining")?
                .id(),
            replacement_job
        );
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
        let _ = stop.send(());
        peer.await??;
        drop(_socket);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn projection_recovery_permanent_conflict_after_lag_is_terminal() -> TestResult {
    let QueuedProjection {
        _socket,
        client,
        router,
        stop,
        peer,
        ..
    } = queued_projection(45_000).await?;
    let consumer = Arc::new(GatedProjection::default());
    let worker_consumer = Arc::clone(&consumer);
    let worker_router = router.clone();
    let startup = tokio::spawn(async move {
        TestResult::Ok(
            ShareRouter::spawn(client, worker_router, router_config()?, worker_consumer).await?,
        )
    });
    consumer.attempted.notified().await;
    observe_pause(&router).await?;
    consumer.outcome.store(2, Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(100)).await;
    let result: TestResult<ShareRouter> = startup.await?;
    assert!(result.is_err());
    assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 0);
    assert!(matches!(
        router.admissible_job_ids(),
        Err(JobRouterError::Registry(
            wcash_pool_core::JobRegistryError::NotSynchronized
        ))
    ));
    let _ = stop.send(());
    // The failed startup closes its socket; either bounded peer termination is valid.
    let _ = peer.await?;
    drop(_socket);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn projection_recovery_rejects_ready_success_at_total_deadline() -> TestResult {
    let QueuedProjection {
        _socket,
        client,
        router,
        stop,
        peer,
        ..
    } = queued_projection(45_000).await?;
    let consumer = Arc::new(GatedProjection::default());
    let worker_consumer = Arc::clone(&consumer);
    let worker_router = router.clone();
    let startup = tokio::spawn(async move {
        TestResult::Ok(
            ShareRouter::spawn(client, worker_router, router_config()?, worker_consumer).await?,
        )
    });
    consumer.attempted.notified().await;
    observe_pause(&router).await?;
    // Tokio may poll a ready inner future before checking an expired timeout.
    // A strict absolute budget must reject this otherwise-valid late success.
    consumer.outcome.store(1, Ordering::SeqCst);
    tokio::time::advance(EVENT_CONSUMER_RECOVERY_TIMEOUT).await;
    let result: TestResult<ShareRouter> = startup.await?;
    assert!(result.is_err());
    assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 0);
    assert!(matches!(
        router.admissible_job_ids(),
        Err(JobRouterError::Registry(
            wcash_pool_core::JobRegistryError::NotSynchronized
        ))
    ));
    let _ = stop.send(());
    let _ = peer.await?;
    drop(_socket);
    Ok(())
}

#[tokio::test]
async fn projection_recovery_never_extends_an_expired_generation() -> TestResult {
    let QueuedProjection {
        _socket,
        mut client,
        router,
        replacement_job,
        stop,
        peer,
        ..
    } = queued_projection(1_000).await?;
    let consumer = Arc::new(GatedProjection::default());
    let worker_consumer = Arc::clone(&consumer);
    let worker_router = router.clone();
    let pending = tokio::spawn(async move {
        let result = drain_backend_events(
            &mut client,
            &worker_router,
            worker_consumer.as_ref(),
            Duration::from_secs(1),
        )
        .await;
        (client, result)
    });
    consumer.attempted.notified().await;
    observe_pause(&router).await?;
    // Generation leases intentionally use std::time::Instant, independently
    // from Tokio's simulated retry clock. Exercise a real expired lease.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    consumer.outcome.store(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut client, recovered) = pending.await?;
    assert!(recovered?);
    client.health().await?;
    router.resume_after_health(&client)?;
    assert!(router.current_generation()?.is_none());
    assert!(!router.admissible_job_ids()?.contains(&replacement_job));
    let _ = stop.send(());
    peer.await??;
    drop(_socket);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancelling_projection_recovery_suspends_the_owned_connection() -> TestResult {
    let QueuedProjection {
        _socket,
        client,
        router,
        stop,
        peer,
        ..
    } = queued_projection(45_000).await?;
    let consumer = Arc::new(GatedProjection::default());
    let worker_consumer = Arc::clone(&consumer);
    let worker_router = router.clone();
    let startup = tokio::spawn(async move {
        TestResult::Ok(
            ShareRouter::spawn(client, worker_router, router_config()?, worker_consumer).await?,
        )
    });
    consumer.attempted.notified().await;
    observe_pause(&router).await?;
    startup.abort();
    assert!(startup
        .await
        .expect_err("cancelled startup unexpectedly completed")
        .is_cancelled());
    assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 0);
    assert!(matches!(
        router.admissible_job_ids(),
        Err(JobRouterError::Registry(
            wcash_pool_core::JobRegistryError::NotSynchronized
        ))
    ));
    let _ = stop.send(());
    let _ = peer.await?;
    drop(_socket);
    Ok(())
}

async fn write_zec_winning_commit(
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
        return Err("expected exactly one ordinary share submission".into());
    };
    let parent_hash_le = canonical_parent_header_hash_le(&job.header_input, &nonce, &solution);
    let receipt = ShareReceipt {
        event_seq,
        job_id: job_id.clone(),
        share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
        attribution_id: wcash_pool_protocol::canonical_attribution_id(&identity, &target_le)?,
        parent_hash_le: parent_hash_le.clone(),
        winners: vec![WinnerDescriptor {
            chain: MergedChain::Zcash,
            block_hash_le: parent_hash_le,
            height: job.zcash_height,
            coinbase_txid_le: job.zcash_coinbase_txid_le.clone(),
            reward_zat: job.zcash_reward_zat,
            maturity_confirmations: job.zcash_maturity_confirmations,
        }],
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

#[tokio::test(start_paused = true)]
async fn projection_recovery_withholds_winning_ack_without_resubmitting_solution() -> TestResult {
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x6a);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    let server_job = job.clone();
    let submissions = Arc::new(AtomicUsize::new(0));
    let peer_submissions = Arc::clone(&submissions);
    let (stop, mut stopped) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, server_job.clone()).await?;
        let request = read_request(&mut stream).await?;
        peer_submissions.fetch_add(1, Ordering::SeqCst);
        write_zec_winning_commit(&mut stream, request, &server_job, 11).await?;
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return TestResult::Ok(()),
                request = read_request(&mut stream) => {
                    match request? {
                        BackendRequest::Health { id, .. } => healthy(&mut stream, id, 11).await?,
                        BackendRequest::SubmitShare { .. } => {
                            peer_submissions.fetch_add(1, Ordering::SeqCst);
                            return Err("projection retry resubmitted an already committed winning solution".into());
                        }
                        _ => return Err("unexpected backend request".into()),
                    }
                }
            }
        }
    });
    let timeline = MonotonicTimeline::new();
    let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let context = prepared_context(&router, 0x69)?;
    let consumer = Arc::new(GatedProjection::default());
    let service =
        ShareRouter::spawn(client, router.clone(), router_config()?, consumer.clone()).await?;
    let handle = service.handle();
    let accepted = tokio::spawn(async move { handle.submit(context).await });
    consumer.attempted.notified().await;
    observe_pause(&router).await?;
    tokio::time::advance(Duration::from_millis(5_100)).await;
    assert!(
        !accepted.is_finished(),
        "winning receipt acknowledged before exact durable projection"
    );
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 0);
    consumer.outcome.store(1, Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(100)).await;
    let verified = accepted.await??;
    assert_eq!(verified.receipt().winners.len(), 1);
    assert_eq!(verified.receipt().winners[0].chain, MergedChain::Zcash);
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 1);
    service.shutdown().await?;
    let _ = stop.send(());
    let _ = peer.await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn projection_recovery_prequeued_ordinary_share_requires_fresh_health() -> TestResult {
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x6b);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    let server_job = job.clone();
    let health_barriers = Arc::new(AtomicUsize::new(0));
    let peer_barriers = Arc::clone(&health_barriers);
    let (stop, mut stopped) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, server_job.clone()).await?;
        let first = read_request(&mut stream).await?;
        write_zec_winning_commit(&mut stream, first, &server_job, 11).await?;
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return TestResult::Ok(()),
                request = read_request(&mut stream) => {
                    match request? {
                        BackendRequest::Health { id, .. } => {
                            peer_barriers.fetch_add(1, Ordering::SeqCst);
                            healthy(&mut stream, id, 11).await?;
                        }
                        BackendRequest::SubmitShare { id, .. } => {
                            assert!(peer_barriers.load(Ordering::SeqCst) > 0,
                                "ordinary queued solution escaped the projection pause before fresh health");
                            write_message(&mut stream, &BackendMessage::Error {
                                version: BACKEND_PROTOCOL_VERSION,
                                id,
                                code: BackendErrorCode::StaleJob,
                                message: "fixture rejects second solution after its fresh barrier".to_owned(),
                            }).await?;
                        }
                        _ => return Err("unexpected backend request".into()),
                    }
                }
            }
        }
    });
    let timeline = MonotonicTimeline::new();
    let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    // Both contexts were admitted under the original healthy generation. The
    // second connection can enqueue its owned context while the first waits.
    let first = prepared_context(&router, 0x6a)?;
    let second = prepared_context(&router, 0x6b)?;
    let consumer = Arc::new(GatedProjection::default());
    let service =
        ShareRouter::spawn(client, router.clone(), router_config()?, consumer.clone()).await?;
    let first_handle = service.handle();
    let first_result = tokio::spawn(async move { first_handle.submit(first).await });
    consumer.attempted.notified().await;
    observe_pause(&router).await?;
    let second_handle = service.handle();
    let second_result = tokio::spawn(async move { second_handle.submit(second).await });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(!second_result.is_finished());
    consumer.outcome.store(1, Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(100)).await;
    assert_eq!(
        first_result.await??.receipt().winners[0].chain,
        MergedChain::Zcash
    );
    // A fresh health barrier may authorize forwarding, or the paused queue may
    // reject stale ordinary work. Neither path may forward on the old barrier.
    assert_eq!(
        second_result.await?,
        Err(ShareRouterError::Rejected(BackendErrorCode::StaleJob))
    );
    service.shutdown().await?;
    let _ = stop.send(());
    let _ = peer.await?;
    Ok(())
}

#[tokio::test]
async fn projection_recovery_candidate_deadline_cannot_reuse_an_unacknowledged_stream() -> TestResult
{
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x6c);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    job.max_age_ms = 1_000;
    let server_job = job.clone();
    let submissions = Arc::new(AtomicUsize::new(0));
    let peer_submissions = Arc::clone(&submissions);
    let (stop, mut stopped) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, server_job.clone()).await?;
        let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
            return Err("expired candidate lacked its health permission barrier".into());
        };
        write_message(
            &mut stream,
            &BackendMessage::HealthStatus {
                version: BACKEND_PROTOCOL_VERSION,
                id,
                event_seq: 10,
                healthy: false,
                recovery_only: true,
                pending_wcash: 0,
                quarantined_wcash: 0,
                pending_zcash: 0,
            },
        )
        .await?;
        let request = read_request(&mut stream).await?;
        peer_submissions.fetch_add(1, Ordering::SeqCst);
        write_zec_winning_commit(&mut stream, request, &server_job, 11).await?;
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return TestResult::Ok(()),
                request = read_request(&mut stream) => {
                    match request? {
                        BackendRequest::Health { id, .. } => healthy(&mut stream, id, 11).await?,
                        _ => return Err("a cancelled winning barrier resubmitted its solution".into()),
                    }
                }
            }
        }
    });
    let timeline = MonotonicTimeline::new();
    let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let ordinary = prepared_context(&router, 0x6c)?;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // Expiry without a replacement requires explicit candidate-only permission.
    pump_health(
        &mut client,
        &router,
        &RecordingEventConsumer::default(),
        Duration::from_secs(1),
    )
    .await?;
    let candidate = router.prepare_queued_paused_candidate(ordinary, &client)?;
    assert!(candidate.is_winner_recovery());
    let consumer = GatedProjection::default();
    let (result, retained, recovered) = submit_context_and_drain(
        &mut client,
        &router,
        &consumer,
        router_config()?,
        candidate,
        Instant::now() + Duration::from_millis(500),
    )
    .await;
    assert_eq!(result, Err(ShareRouterError::EventConsumerUnusable));
    assert!(result
        .as_ref()
        .expect_err("winning acknowledgement escaped its deadline")
        .is_terminal());
    assert!(retained
        .as_ref()
        .is_some_and(SubmissionContext::is_winner_recovery));
    assert!(!recovered);
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    assert!(consumer.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(consumer.acknowledged.load(Ordering::SeqCst), 0);
    // The transport already read the committed event, but it never passed the
    // exact durable barrier. A later healthy reply cannot repair that lost Vec.
    assert!(!router.client_cursor_matches(&client)?);
    client.health().await?;
    assert!(matches!(
        router.resume_after_health(&client),
        Err(JobRouterError::BackendConnectionMismatch)
    ));
    let _ = stop.send(());
    peer.await??;
    Ok(())
}

#[derive(Default)]
struct QueuedWinnerProjection {
    lagging: bool,
    release: Notify,
    first: GatedProjection,
    later: RecordingEventConsumer,
}

impl BackendEventConsumer for QueuedWinnerProjection {
    fn consume<'a>(
        &'a self,
        authority: &'a BackendAuthority,
        events: &'a [DeliveredBackendEvent],
    ) -> Pin<Box<dyn Future<Output = Result<(), BackendEventConsumerError>> + Send + 'a>> {
        if events
            .first()
            .is_some_and(|event| event.event().event_seq() == 13)
        {
            if self.lagging {
                return self.first.consume(authority, events);
            }
            Box::pin(async move {
                self.first.attempted.notify_one();
                self.release.notified().await;
                self.first.outcome.store(1, Ordering::SeqCst);
                self.first.consume(authority, events).await
            })
        } else {
            self.later.consume(authority, events)
        }
    }
}

#[derive(Clone, Copy)]
enum QueuedWinnerAuthority {
    Preserved,
    DifferentParent,
    OriginalClosed,
    PermissionRevoked,
}

async fn queued_winner_after_projection_wait(
    authority: QueuedWinnerAuthority,
    lagging: bool,
) -> TestResult {
    // Keep simulated time under explicit control while local Unix I/O is ready.
    // Tokio otherwise auto-advances a pending request timer before the OS peer
    // task is polled, which is unrelated to the queue-budget regression.
    let clock_guard = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut original = descriptor(0x70);
    original.zcash_target_le = TargetLe::new([0xff; 32]);
    let mut current = descriptor(0x71);
    // A WEC-only refresh changes the job while preserving its exact ZEC parent.
    let mut current_header = *current.header_input.as_bytes();
    current_header[4..36].copy_from_slice(original.zcash_previous_hash_le.as_bytes());
    current.header_input = Hex108::new(current_header);
    current.zcash_previous_hash_le = original.zcash_previous_hash_le.clone();
    current.zcash_target_le = TargetLe::new([0xff; 32]);
    let peer_original = original.clone();
    let peer_current = current.clone();
    let submissions = Arc::new(AtomicUsize::new(0));
    let peer_submissions = Arc::clone(&submissions);
    let barriers = Arc::new(AtomicUsize::new(0));
    let peer_barriers = Arc::clone(&barriers);
    let (expected_tx, expected_rx) = oneshot::channel::<BackendRequest>();
    let (stop, mut stopped) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, peer_original.clone()).await?;
        let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
            return Err("expected initial replacement barrier".into());
        };
        write_message(
            &mut stream,
            &BackendMessage::Event {
                version: BACKEND_PROTOCOL_VERSION,
                event: BackendEvent::JobActivated {
                    event_seq: 11,
                    job: peer_current.clone(),
                },
            },
        )
        .await?;
        write_message(
            &mut stream,
            &BackendMessage::Event {
                version: BACKEND_PROTOCOL_VERSION,
                event: BackendEvent::JobInvalidated {
                    event_seq: 12,
                    job_id: peer_original.job_id.clone(),
                    reason: wcash_pool_protocol::JobInvalidationReason::WcashTipChanged,
                    accept_for_ms: 0,
                },
            },
        )
        .await?;
        healthy(&mut stream, id, 12).await?;
        let first = read_request(&mut stream).await?;
        let BackendRequest::SubmitShare { job_id, .. } = &first else {
            return Err("expected first ordinary submission".into());
        };
        assert_eq!(job_id, &peer_current.job_id);
        peer_submissions.fetch_add(1, Ordering::SeqCst);
        write_zec_winning_commit(&mut stream, first, &peer_current, 13).await?;
        let expected = expected_rx.await?;
        let mut cursor = 13;
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return TestResult::Ok(()),
                request = read_request(&mut stream) => match request? {
                    BackendRequest::Health { id, .. } => {
                        let first_barrier = peer_barriers.fetch_add(1, Ordering::SeqCst) == 0;
                        if first_barrier {
                            match authority {
                                QueuedWinnerAuthority::DifferentParent => {
                                    cursor += 1;
                                    let mut replacement = descriptor(0x72);
                                    replacement.zcash_target_le = TargetLe::new([0xff; 32]);
                                    write_message(&mut stream, &BackendMessage::Event {
                                        version: BACKEND_PROTOCOL_VERSION,
                                        event: BackendEvent::JobActivated {
                                            event_seq: cursor, job: replacement,
                                        },
                                    }).await?;
                                }
                                QueuedWinnerAuthority::OriginalClosed => {
                                    cursor += 1;
                                    write_message(&mut stream, &BackendMessage::Event {
                                        version: BACKEND_PROTOCOL_VERSION,
                                        event: BackendEvent::GenerationClosed {
                                            event_seq: cursor,
                                            job_id: peer_original.job_id.clone(),
                                        },
                                    }).await?;
                                }
                                _ => {}
                            }
                        }
                        if matches!(authority, QueuedWinnerAuthority::PermissionRevoked) {
                            write_message(&mut stream, &BackendMessage::HealthStatus {
                                version: BACKEND_PROTOCOL_VERSION, id, event_seq: cursor,
                                healthy: false, recovery_only: false, pending_wcash: 0,
                                quarantined_wcash: 0, pending_zcash: 0,
                            }).await?;
                        } else {
                            healthy(&mut stream, id, cursor).await?;
                        }
                    }
                    request @ BackendRequest::SubmitShare { .. } => {
                        assert!(matches!(authority, QueuedWinnerAuthority::Preserved),
                            "revoked original authority reached backend");
                        assert!(peer_barriers.load(Ordering::SeqCst) > 0,
                            "second proof used the old health sample");
                        let prior = peer_submissions.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(prior, 1, "one of the two proofs was submitted again");
                        // Normalize only the request ID; every original proof,
                        // attribution and assigned-target byte must be identical.
                        let mut normalized = request.clone();
                        if let BackendRequest::SubmitShare { id, .. } = &mut normalized { *id = 0; }
                        assert_eq!(normalized, expected);
                        cursor += 1;
                        write_zec_winning_commit(&mut stream, request, &peer_original, cursor).await?;
                    }
                    _ => return Err("unexpected queued winner request".into()),
                }
            }
        }
    });
    let timeline = MonotonicTimeline::new();
    let config = client_config(&socket.path)?
        .with_timeouts(Duration::from_secs(1), Duration::from_secs(20))?;
    let mut client = BackendClient::connect(config, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let original_context = prepared_context(&router, 0x73)?;
    let initial_health = match client.health().await {
        Ok(health) => health,
        Err(error) => {
            return Err(format!(
                "initial replacement health: {error:?}; peer: {:?}",
                peer.await
            )
            .into())
        }
    };
    assert!(initial_health.healthy);
    drain_backend_events(
        &mut client,
        &router,
        &RecordingEventConsumer::default(),
        Duration::from_secs(1),
    )
    .await?;
    router.resume_after_health(&client)?;
    let second = router.prepare_queued_paused_candidate(original_context, &client)?;
    assert!(second.is_winner_recovery());
    // The all-ff target exercises the frontend forwarding filter. Complete
    // Equihash/consensus acceptance remains the backend's responsibility.
    expected_tx
        .send(BackendRequest::SubmitShare {
            version: BACKEND_PROTOCOL_VERSION,
            id: 0,
            job_id: second.job_id(),
            identity: second.identity().clone(),
            target_le: second.target_le().clone(),
            time: second.time().clone(),
            nonce: second.nonce().clone(),
            solution: Box::new(second.solution().clone()),
        })
        .map_err(|_| "fixture proof receiver closed")?;
    let first = prepared_context(&router, 0x74)?;
    let consumer = Arc::new(QueuedWinnerProjection {
        lagging,
        ..Default::default()
    });
    let heartbeat = if lagging {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(1)
    };
    let config = ShareRouterConfig::new(2, heartbeat, Duration::from_secs(10))?;
    let service = ShareRouter::spawn(client, router.clone(), config, consumer.clone()).await?;
    let first_handle = service.handle();
    let first_result = tokio::spawn(async move { first_handle.submit(first).await });
    consumer.first.attempted.notified().await;
    if lagging {
        observe_pause(&router).await?;
    }
    let second_handle = service.handle();
    let second_result = tokio::spawn(async move { second_handle.submit(second).await });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        service.handle.sender.capacity(),
        1,
        "second proof did not enter the actor queue"
    );
    tokio::time::advance(Duration::from_millis(5_100)).await;
    assert!(
        !first_result.is_finished(),
        "first acknowledgement escaped its projection barrier"
    );
    assert!(
        !second_result.is_finished(),
        "queued proof escaped the first barrier"
    );
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    assert_eq!(consumer.first.acknowledged.load(Ordering::SeqCst), 0);
    if lagging {
        consumer.first.outcome.store(1, Ordering::SeqCst);
    } else {
        consumer.release.notify_one();
    }
    tokio::time::advance(Duration::from_millis(100)).await;
    let first_commit = first_result.await?;
    assert!(
        first_commit.is_ok(),
        "first proof failed: {first_commit:?}; actor={:?}",
        service.terminal_error()
    );
    assert_eq!(first_commit?.receipt().winners[0].chain, MergedChain::Zcash);
    assert_eq!(consumer.first.acknowledged.load(Ordering::SeqCst), 1);
    let result = second_result.await?;
    clock_guard.abort();
    match authority {
        QueuedWinnerAuthority::Preserved => {
            let committed = result?;
            assert_eq!(committed.receipt().job_id, original.job_id);
            assert_eq!(committed.receipt().winners[0].chain, MergedChain::Zcash);
            assert_eq!(submissions.load(Ordering::SeqCst), 2);
            assert_eq!(consumer.later.events()?.len(), 1);
        }
        _ => {
            assert_eq!(
                result,
                Err(ShareRouterError::Rejected(BackendErrorCode::StaleJob))
            );
            assert_eq!(submissions.load(Ordering::SeqCst), 1);
        }
    }
    assert!(barriers.load(Ordering::SeqCst) > 0);
    service.shutdown().await?;
    let _ = stop.send(());
    peer.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn recovery_queue_wait_does_not_spend_candidate_attempt_budget() -> TestResult {
    queued_winner_after_projection_wait(QueuedWinnerAuthority::Preserved, false).await
}

#[tokio::test(start_paused = true)]
async fn recovery_queue_wait_cannot_cross_a_different_zcash_parent() -> TestResult {
    queued_winner_after_projection_wait(QueuedWinnerAuthority::DifferentParent, false).await
}

#[tokio::test(start_paused = true)]
async fn recovery_queue_wait_cannot_reopen_a_closed_original_job() -> TestResult {
    queued_winner_after_projection_wait(QueuedWinnerAuthority::OriginalClosed, false).await
}

#[tokio::test(start_paused = true)]
async fn recovery_queue_wait_cannot_restore_revoked_backend_permission() -> TestResult {
    queued_winner_after_projection_wait(QueuedWinnerAuthority::PermissionRevoked, false).await
}

#[tokio::test(start_paused = true)]
async fn recovery_queue_wait_rechecks_health_after_projection_lag() -> TestResult {
    queued_winner_after_projection_wait(QueuedWinnerAuthority::Preserved, true).await
}

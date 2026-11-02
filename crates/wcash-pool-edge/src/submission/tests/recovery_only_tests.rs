use super::*;
use wcash_pool_protocol::{MergedChain, WinnerDescriptor};

fn assigned_session(
    router: &JobRouter,
) -> TestResult<(
    wcash_pool_core::MiningSession,
    wcash_pool_core::BackendGeneration,
)> {
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
    let allocator = NoncePrefixAllocator::new(NonceProfile::FourByte, NonceNamespaceLease::new(1)?);
    let mut session = wcash_pool_core::MiningSession::new(Uuid::from_u128(4), 2)?;
    let _ = session.subscribe(&allocator)?;
    session.complete_authorization(AuthenticatedWorker::new(
        Uuid::from_u128(7),
        Uuid::from_u128(8),
        "account.worker",
    )?)?;
    session.announce_job(assignment)?;
    Ok((session, generation))
}

fn assigned_context(
    router: &JobRouter,
    session: &wcash_pool_core::MiningSession,
    generation: &wcash_pool_core::BackendGeneration,
    nonce: u8,
) -> TestResult<SubmissionContext> {
    Ok(router.prepare_submission(
        session,
        "account.worker",
        generation.id(),
        generation.header_time(),
        NonceSuffix::TwentyEight(Hex28::new([nonce; 28])),
        Box::new(Hex1344::new([0x61; 1344])),
    )?)
}

async fn recovery_health(
    stream: &mut UnixStream,
    id: u64,
    event_seq: u64,
    recovery_only: bool,
) -> TestResult {
    write_message(
        stream,
        &BackendMessage::HealthStatus {
            version: BACKEND_PROTOCOL_VERSION,
            id,
            event_seq,
            healthy: false,
            recovery_only,
            pending_wcash: 0,
            quarantined_wcash: 0,
            pending_zcash: 0,
        },
    )
    .await
}

async fn zcash_commit(
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
        return Err("expected candidate".into());
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

#[tokio::test]
async fn recovery_permission_is_explicit_and_can_be_revoked_without_ordinary_authority(
) -> TestResult {
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x41);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    job.max_age_ms = 1_000;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, job).await?;
        for permission in [false, true, false] {
            let BackendRequest::Health { id, .. } = read_request(&mut stream).await? else {
                return TestResult::Err("expected health barrier".into());
            };
            recovery_health(&mut stream, id, 10, permission).await?;
        }
        TestResult::Ok(())
    });
    let timeline = MonotonicTimeline::new();
    let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let (session, generation) = assigned_session(&router)?;
    let queued = assigned_context(&router, &session, &generation, 1)?;
    let consumer = RecordingEventConsumer::default();
    pump_health(&mut client, &router, &consumer, Duration::from_secs(1)).await?;
    assert!(assigned_context(&router, &session, &generation, 2).is_err());
    assert!(router
        .prepare_queued_paused_candidate(queued, &client)
        .is_err());
    pump_health(&mut client, &router, &consumer, Duration::from_secs(1)).await?;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(router.current_generation()?.is_none());
    let candidate = assigned_context(&router, &session, &generation, 3)?;
    assert!(candidate.is_paused_zcash_candidate());
    pump_health(&mut client, &router, &consumer, Duration::from_secs(1)).await?;
    assert!(router
        .prepare_queued_paused_candidate(candidate, &client)
        .is_err());
    assert!(assigned_context(&router, &session, &generation, 4).is_err());
    server.await??;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum CandidateCase {
    RetryCommit,
    OrdinaryExpiry,
    HighHash,
    AlwaysDeferred,
    Revoke,
    OtherError,
}

async fn candidate_case(case: CandidateCase) -> TestResult {
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x42);
    job.zcash_target_le = if matches!(case, CandidateCase::HighHash) {
        TargetLe::new({
            let mut bytes = [0; 32];
            bytes[0] = 1;
            bytes
        })
    } else {
        TargetLe::new([0xff; 32])
    };
    if matches!(case, CandidateCase::OrdinaryExpiry) {
        job.max_age_ms = 1_000;
    }
    let (stop, stopped) = oneshot::channel();
    let server_job = job.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, server_job.clone()).await?;
        let mut stopped = stopped;
        let mut submissions: Vec<BackendRequest> = Vec::new();
        let mut health_count = 0;
        let mut event_seq = 10;
        loop {
            let request = tokio::select! {
                biased;
                _ = &mut stopped => break,
                request = read_request(&mut stream) => match request {
                    Ok(request) => request,
                    Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof) => break,
                    Err(error) => return Err(error),
                }
            };
            match request {
                BackendRequest::Health { id, .. } => {
                    health_count += 1;
                    recovery_health(
                        &mut stream,
                        id,
                        event_seq,
                        !matches!(case, CandidateCase::Revoke) || submissions.is_empty(),
                    )
                    .await?;
                }
                request @ BackendRequest::SubmitShare { .. } => {
                    if let Some(first) = submissions.first() {
                        let mut original = first.clone();
                        let mut repeated = request.clone();
                        if let BackendRequest::SubmitShare { id, .. } = &mut original {
                            *id = 1;
                        }
                        if let BackendRequest::SubmitShare { id, .. } = &mut repeated {
                            *id = 1;
                        }
                        assert_eq!(
                            original, repeated,
                            "retry must retain every proof and attribution byte"
                        );
                    }
                    submissions.push(request.clone());
                    if matches!(case, CandidateCase::OrdinaryExpiry) && submissions.len() == 1 {
                        tokio::time::sleep(Duration::from_millis(1_100)).await;
                    }
                    if matches!(
                        case,
                        CandidateCase::RetryCommit | CandidateCase::OrdinaryExpiry
                    ) && submissions.len() == 2
                    {
                        event_seq += 1;
                        zcash_commit(&mut stream, request, &server_job, event_seq).await?;
                    } else {
                        let BackendRequest::SubmitShare { id, .. } = request else {
                            return Err("expected share".into());
                        };
                        write_message(
                            &mut stream,
                            &BackendMessage::Error {
                                version: BACKEND_PROTOCOL_VERSION,
                                id,
                                code: if matches!(case, CandidateCase::OtherError) {
                                    BackendErrorCode::LowDifficulty
                                } else {
                                    BackendErrorCode::RecoveryDeferred
                                },
                                message: "bounded candidate response".to_owned(),
                            },
                        )
                        .await?;
                    }
                }
                _ => return Err("unexpected candidate exchange".into()),
            }
        }
        TestResult::<(usize, usize)>::Ok((submissions.len(), health_count))
    });
    let timeline = MonotonicTimeline::new();
    let config = if matches!(case, CandidateCase::OrdinaryExpiry) {
        client_config(&socket.path)?
            .with_timeouts(Duration::from_secs(1), Duration::from_secs(3))?
    } else {
        client_config(&socket.path)?
    };
    let mut client = BackendClient::connect(config, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let (session, generation) = assigned_session(&router)?;
    let consumer = Arc::new(RecordingEventConsumer::default());
    // The two ordinary cases model an already queued original assignment. Only
    // the typed backend deferral may trigger subsequent candidate qualification.
    let ordinary = matches!(
        case,
        CandidateCase::OrdinaryExpiry | CandidateCase::HighHash
    );
    if !ordinary {
        pump_health(
            &mut client,
            &router,
            consumer.as_ref(),
            Duration::from_secs(1),
        )
        .await?;
    }
    let context = assigned_context(&router, &session, &generation, 9)?;
    assert_eq!(context.is_winner_recovery(), !ordinary);
    let service = ShareRouter::spawn(
        client,
        router.clone(),
        ShareRouterConfig::new(16, Duration::from_millis(50), Duration::from_secs(1))?,
        consumer.clone(),
    )
    .await?;
    let started = Instant::now();
    let result = service.handle().submit(context).await;
    match case {
        CandidateCase::RetryCommit | CandidateCase::OrdinaryExpiry => {
            assert_eq!(result?.receipt().winners[0].chain, MergedChain::Zcash);
            assert_eq!(consumer.events()?.len(), 1);
        }
        CandidateCase::HighHash | CandidateCase::Revoke => assert_eq!(
            result,
            Err(ShareRouterError::Rejected(BackendErrorCode::StaleJob))
        ),
        CandidateCase::OtherError => assert_eq!(
            result,
            Err(ShareRouterError::Rejected(BackendErrorCode::LowDifficulty))
        ),
        CandidateCase::AlwaysDeferred => {
            assert_eq!(
                result,
                Err(ShareRouterError::Rejected(
                    BackendErrorCode::RecoveryDeferred
                ))
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "existing one-second client timeout caps retry budget"
            );
        }
    }
    service.shutdown().await?;
    let _ = stop.send(());
    let (submissions, health_count) = server.await??;
    match case {
        CandidateCase::RetryCommit | CandidateCase::OrdinaryExpiry => assert_eq!(submissions, 2),
        CandidateCase::AlwaysDeferred => assert!((2..=4).contains(&submissions)),
        _ => assert_eq!(submissions, 1),
    }
    if matches!(
        case,
        CandidateCase::RetryCommit | CandidateCase::AlwaysDeferred | CandidateCase::Revoke
    ) {
        assert!(
            health_count >= 2,
            "health must advance between deferred attempts"
        );
    }
    Ok(())
}

#[tokio::test]
async fn typed_candidate_deferral_retries_exact_proof_while_health_keeps_advancing() -> TestResult {
    candidate_case(CandidateCase::RetryCommit).await
}
#[tokio::test]
async fn queued_ordinary_crossing_expiry_is_promoted_only_after_explicit_health_barrier(
) -> TestResult {
    candidate_case(CandidateCase::OrdinaryExpiry).await
}
#[tokio::test]
async fn typed_deferral_never_retries_nonwinning_ordinary_work() -> TestResult {
    candidate_case(CandidateCase::HighHash).await
}
#[tokio::test]
async fn candidate_retry_preserves_existing_shorter_client_deadline() -> TestResult {
    candidate_case(CandidateCase::AlwaysDeferred).await
}
#[tokio::test]
async fn revoked_recovery_permission_stops_pending_candidate() -> TestResult {
    candidate_case(CandidateCase::Revoke).await
}
#[tokio::test]
async fn other_backend_rejections_are_never_retried() -> TestResult {
    candidate_case(CandidateCase::OtherError).await
}

#[tokio::test]
async fn due_retries_and_ready_commands_take_alternating_turns() -> TestResult {
    let (sender, mut receiver) = mpsc::channel(2);
    let (complete, _acknowledged) = oneshot::channel();
    sender.send(SubmitCommand::Shutdown { complete }).await?;
    let due = Some(Instant::now());
    assert!(matches!(
        next_submission_work(&mut receiver, due, false).await,
        ActorWork::CandidateRetry
    ));
    assert!(matches!(
        next_submission_work(&mut receiver, due, true).await,
        ActorWork::Command(Some(SubmitCommand::Shutdown { .. }))
    ));
    Ok(())
}

#[tokio::test]
async fn pending_candidate_does_not_block_ordinary_submission_after_health_recovers() -> TestResult
{
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x43);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    let server_job = job.clone();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, server_job.clone()).await?;
        let mut stopped = stopped;
        let mut candidate_attempts = 0;
        let mut ordinary_committed = false;
        let mut event_seq = 10;
        loop {
            let request = tokio::select! { biased; _ = &mut stopped => break, request = read_request(&mut stream) => match request { Ok(request) => request, Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof) => break, Err(error) => return Err(error) } };
            match request {
                BackendRequest::Health { id, .. } if candidate_attempts == 0 => {
                    recovery_health(&mut stream, id, event_seq, true).await?
                }
                BackendRequest::Health { id, .. } => {
                    reply_health(&mut stream, id, event_seq, true).await?
                }
                request @ BackendRequest::SubmitShare { .. } => {
                    let is_candidate = matches!(&request, BackendRequest::SubmitShare { nonce, .. } if nonce.as_bytes()[4..] == [9; 28]);
                    if is_candidate {
                        candidate_attempts += 1;
                        if ordinary_committed {
                            event_seq += 1;
                            zcash_commit(&mut stream, request, &server_job, event_seq).await?;
                        } else {
                            let BackendRequest::SubmitShare { id, .. } = request else {
                                return Err("expected first candidate".into());
                            };
                            write_message(
                                &mut stream,
                                &BackendMessage::Error {
                                    version: BACKEND_PROTOCOL_VERSION,
                                    id,
                                    code: BackendErrorCode::RecoveryDeferred,
                                    message: "awaiting current authority".to_owned(),
                                },
                            )
                            .await?;
                        }
                    } else {
                        assert!(!ordinary_committed);
                        assert!(
                            matches!(&request, BackendRequest::SubmitShare { nonce, .. } if nonce.as_bytes()[4..] == [10; 28])
                        );
                        event_seq += 1;
                        commit_share(&mut stream, request, &server_job, event_seq).await?;
                        ordinary_committed = true;
                    }
                }
                _ => return Err("unexpected command".into()),
            }
        }
        TestResult::<(usize, bool)>::Ok((candidate_attempts, ordinary_committed))
    });
    let timeline = MonotonicTimeline::new();
    let config = client_config(&socket.path)?
        .with_timeouts(Duration::from_secs(1), Duration::from_secs(3))?;
    let mut client = BackendClient::connect(config, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let (session, generation) = assigned_session(&router)?;
    pump_health(
        &mut client,
        &router,
        &RecordingEventConsumer::default(),
        Duration::from_secs(1),
    )
    .await?;
    let context = assigned_context(&router, &session, &generation, 9)?;
    let service = ShareRouter::spawn(
        client,
        router.clone(),
        ShareRouterConfig::new(16, Duration::from_millis(25), Duration::from_secs(1))?,
        Arc::new(RecordingEventConsumer::default()),
    )
    .await?;
    let handle = service.handle();
    let candidate = tokio::spawn(async move { handle.submit(context).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while router.current_generation().ok().flatten().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let ordinary = assigned_context(&router, &session, &generation, 10)?;
    assert!(!ordinary.is_winner_recovery());
    assert!(service
        .handle()
        .submit(ordinary)
        .await?
        .receipt()
        .winners
        .is_empty());
    assert_eq!(
        candidate.await??.receipt().winners[0].chain,
        MergedChain::Zcash
    );
    service.shutdown().await?;
    let _ = stop.send(());
    let (attempts, ordinary_committed) = server.await??;
    assert!(attempts >= 2);
    assert!(ordinary_committed);
    Ok(())
}

#[tokio::test]
async fn deferred_candidate_capacity_and_shutdown_release_every_waiter() -> TestResult {
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x44);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    let (stop, stopped) = oneshot::channel();
    let (eight_ready, ready) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, job).await?;
        let mut stopped = stopped;
        let mut distinct = std::collections::HashSet::new();
        let mut eight_ready = Some(eight_ready);
        loop {
            let request = tokio::select! { biased; _ = &mut stopped => break, request = read_request(&mut stream) => match request { Ok(request) => request, Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof) => break, Err(error) => return Err(error) } };
            match request {
                BackendRequest::Health { id, .. } => {
                    recovery_health(&mut stream, id, 10, true).await?
                }
                BackendRequest::SubmitShare { id, nonce, .. } => {
                    distinct.insert(*nonce.as_bytes());
                    write_message(
                        &mut stream,
                        &BackendMessage::Error {
                            version: BACKEND_PROTOCOL_VERSION,
                            id,
                            code: BackendErrorCode::RecoveryDeferred,
                            message: "awaiting authority".to_owned(),
                        },
                    )
                    .await?;
                    if distinct.len() == 8 {
                        if let Some(signal) = eight_ready.take() {
                            let _ = signal.send(());
                        }
                    }
                }
                _ => return Err("unexpected command".into()),
            }
        }
        TestResult::<usize>::Ok(distinct.len())
    });
    let timeline = MonotonicTimeline::new();
    let config = client_config(&socket.path)?
        .with_timeouts(Duration::from_secs(1), Duration::from_secs(3))?;
    let mut client = BackendClient::connect(config, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let (session, generation) = assigned_session(&router)?;
    pump_health(
        &mut client,
        &router,
        &RecordingEventConsumer::default(),
        Duration::from_secs(1),
    )
    .await?;
    let mut contexts = Vec::new();
    for nonce in 1..=9 {
        contexts.push(assigned_context(&router, &session, &generation, nonce)?);
    }
    let service = ShareRouter::spawn(
        client,
        router.clone(),
        ShareRouterConfig::new(16, Duration::from_millis(50), Duration::from_secs(1))?,
        Arc::new(RecordingEventConsumer::default()),
    )
    .await?;
    let mut tasks = tokio::task::JoinSet::new();
    let ninth = contexts.pop().ok_or("missing ninth context")?;
    for context in contexts {
        let handle = service.handle();
        tasks.spawn(async move { handle.submit(context).await });
    }
    ready.await?;
    assert_eq!(
        service.handle().submit(ninth).await,
        Err(ShareRouterError::Overloaded)
    );
    service.shutdown().await?;
    assert!(matches!(
        router.admissible_job_ids(),
        Err(JobRouterError::Registry(
            wcash_pool_core::JobRegistryError::NotSynchronized
        ))
    ));
    let mut released = 0;
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result?, Err(ShareRouterError::Unavailable));
        released += 1;
    }
    assert_eq!(released, MAX_DEFERRED_CANDIDATES);
    let _ = stop.send(());
    assert_eq!(server.await??, 9);
    Ok(())
}

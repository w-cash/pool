use super::*;

#[tokio::test]
async fn diagnostics_queue_full_cancelled_and_lost_response_are_distinct() -> TestResult {
    let current = AcceptableJob {
        job: descriptor(0x44),
        accept_for_ms: 30_000,
    };
    let router = JobRouter::from_acceptable_for_test(
        1,
        Some(&current),
        &[],
        GenerationRegistryConfig::new(2, 8)?,
        4,
    )?;
    let counters = Arc::new(OperationalCounters::default());
    let (sender, mut receiver) = mpsc::channel(1);
    let handle = ShareRouterHandle {
        sender,
        projection_winners: projection_winner::channel().0,
        diagnostics: Arc::clone(&counters),
    };
    let first = prepared_context(&router, 0x41)?;
    let second = prepared_context(&router, 0x42)?;
    let task_handle = handle.clone();
    let waiting = tokio::spawn(async move { task_handle.submit(first).await });
    for _ in 0..128 {
        if counters.count(Diagnostic::QueueEnqueued) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.count(Diagnostic::QueueEnqueued), 1);
    assert_eq!(
        handle.submit(second).await,
        Err(ShareRouterError::Overloaded)
    );
    assert_eq!(counters.count(Diagnostic::QueueFull), 1);
    assert_eq!(counters.count(Diagnostic::BackendReceiptNew), 0);
    waiting.abort();
    let _ = waiting.await;
    assert_eq!(counters.count(Diagnostic::QueueWaitCancelled), 1);
    drop(receiver.recv().await);
    let task_handle = handle.clone();
    let third = prepared_context(&router, 0x43)?;
    let waiting = tokio::spawn(async move { task_handle.submit(third).await });
    let command = receiver.recv().await.ok_or("missing admitted command")?;
    drop(command);
    assert_eq!(waiting.await?, Err(ShareRouterError::Unavailable));
    assert_eq!(counters.count(Diagnostic::QueueResponseLost), 1);
    assert_eq!(counters.count(Diagnostic::QueueWaitCancelled), 1);
    drop(receiver);
    assert_eq!(
        handle.submit(prepared_context(&router, 0x44)?).await,
        Err(ShareRouterError::Unavailable)
    );
    assert_eq!(counters.count(Diagnostic::QueueClosed), 1);
    Ok(())
}

#[test]
fn diagnostics_backend_unknown_and_rejection_do_not_claim_receipts() {
    let counters = Arc::new(OperationalCounters::default());
    let consumer = ObservedEventConsumer {
        inner: Arc::new(RecordingEventConsumer::default()),
        diagnostics: Arc::clone(&counters),
    };
    record_backend_result(
        &consumer,
        &Err(ClientError::Timeout {
            operation: "fixture",
        }),
    );
    record_backend_result(&consumer, &Err(ClientError::CleanEof));
    record_backend_result(
        &consumer,
        &Err(ClientError::BackendRejected {
            code: BackendErrorCode::InvalidEquihash,
            message: "secret fixture payload must never become a label".to_owned(),
        }),
    );
    assert_eq!(counters.count(Diagnostic::BackendRequestTimeout), 1);
    assert_eq!(counters.count(Diagnostic::BackendTransportFailure), 1);
    assert_eq!(counters.count(Diagnostic::BackendRejected), 1);
    assert_eq!(counters.count(Diagnostic::BackendReceiptNew), 0);
    assert_eq!(counters.count(Diagnostic::BackendZecWinnerReceipt), 0);
    assert!(!format!("{:?}", counters.snapshot()).contains("secret fixture"));
}

#[tokio::test]
async fn diagnostics_verified_replay_never_counts_a_second_new_winner() -> TestResult {
    use wcash_pool_protocol::{MergedChain, WinnerDescriptor};
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let mut job = descriptor(0x45);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    let server_job = job.clone();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        establish_live_stream(&mut stream, server_job.clone()).await?;
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
            return TestResult::Err("expected first proof".into());
        };
        let parent_hash_le =
            canonical_parent_header_hash_le(&server_job.header_input, &nonce, &solution);
        let receipt = ShareReceipt {
            event_seq: 11,
            job_id: job_id.clone(),
            share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
            attribution_id: wcash_pool_protocol::canonical_attribution_id(&identity, &target_le)?,
            parent_hash_le: parent_hash_le.clone(),
            winners: vec![WinnerDescriptor {
                chain: MergedChain::Zcash,
                block_hash_le: parent_hash_le,
                height: server_job.zcash_height,
                coinbase_txid_le: server_job.zcash_coinbase_txid_le.clone(),
                reward_zat: server_job.zcash_reward_zat,
                maturity_confirmations: server_job.zcash_maturity_confirmations,
            }],
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
                receipt: receipt.clone(),
                replayed: false,
            },
        )
        .await?;
        let BackendRequest::SubmitShare { id, .. } = read_request(&mut stream).await? else {
            return TestResult::Err("expected exact replay".into());
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
    let timeline = MonotonicTimeline::new();
    let mut client = BackendClient::connect(client_config(&socket.path)?, uuid(9), 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let router =
        JobRouter::from_snapshot(&snapshot, GenerationRegistryConfig::new(2, 8)?, timeline, 8)?;
    let context = prepared_context(&router, 0x45)?;
    let counters = Arc::new(OperationalCounters::default());
    let observed = ObservedEventConsumer {
        inner: Arc::new(RecordingEventConsumer::default()),
        diagnostics: Arc::clone(&counters),
    };
    let first = client.submit_prepared_share_borrowed(&context).await;
    record_backend_result(&observed, &first);
    assert!(!first?.replayed());
    drain_backend_events(&mut client, &router, &observed, Duration::from_secs(1)).await?;
    let replay = client.submit_prepared_share_borrowed(&context).await;
    record_backend_result(&observed, &replay);
    assert!(replay?.replayed());
    assert_eq!(counters.count(Diagnostic::BackendReceiptNew), 1);
    assert_eq!(counters.count(Diagnostic::BackendReceiptReplay), 1);
    assert_eq!(counters.count(Diagnostic::BackendZecWinnerReceipt), 1);
    assert_eq!(counters.count(Diagnostic::ProjectionBatchVerified), 1);
    peer.await??;
    Ok(())
}

//! Startup policy and real framed Unix-client tests, without PostgreSQL or signers.
//! Programmed snapshots are not a consensus or complete service-bootstrap emulator.

#![allow(clippy::expect_used, clippy::panic)]

use std::cell::Cell;

use super::*;

#[tokio::test(start_paused = true)]
async fn startup_readiness_waits_through_typed_transient_failures() {
    let attempts = Cell::new(0_u32);
    let began = time::Instant::now();
    let result = wait_for_backend_readiness(
        BACKEND_READINESS_TIMEOUT,
        BACKEND_READINESS_RETRY_INTERVAL,
        || {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            async move {
                match attempt {
                    0 => Err(BootstrapError::NoCurrentJob),
                    1 => Err(ClientError::BackendRejected {
                        code: BackendErrorCode::BackendUnhealthy,
                        message: "fixture unavailable".into(),
                    }
                    .into()),
                    2 => Err(ClientError::Connect(io::ErrorKind::ConnectionRefused.into()).into()),
                    3 => Err(ClientError::Timeout {
                        operation: "health",
                    }
                    .into()),
                    4 => Err(ClientError::CleanEof.into()),
                    _ => Ok(Some(42_u32)),
                }
            }
        },
    )
    .await
    .expect("fresh read-only attempts recover");
    assert_eq!(result, 42);
    assert_eq!(attempts.get(), 6);
    assert_eq!(began.elapsed(), BACKEND_READINESS_RETRY_INTERVAL * 5);
}

fn permanent_errors() -> Vec<BootstrapError> {
    let target = ShareTarget::from_zip301(&TargetBe::new([0x01; 32])).expect("fixture target");
    vec![
        ConfigError::Unavailable.into(),
        ConfigError::UnsafeFile.into(),
        ConfigError::InvalidIdentity.into(),
        ClientError::Connect(io::ErrorKind::PermissionDenied.into()).into(),
        ClientError::Connect(io::ErrorKind::InvalidInput.into()).into(),
        ClientError::Io {
            operation: "read response",
            source: io::ErrorKind::PermissionDenied.into(),
        }
        .into(),
        ClientError::Io {
            operation: "submit_share",
            source: io::ErrorKind::ConnectionReset.into(),
        }
        .into(),
        ClientError::Timeout {
            operation: "submit_share",
        }
        .into(),
        ClientError::IdentityMismatch {
            field: "journal_stream",
        }
        .into(),
        ClientError::VersionMismatch {
            expected: 1,
            actual: 2,
        }
        .into(),
        ClientError::WrongResponseId {
            expected: 1,
            actual: 2,
        }
        .into(),
        ClientError::TruncatedFrame {
            section: "payload",
            expected: 10,
            actual: 5,
        }
        .into(),
        ClientError::FrameTooLarge {
            actual: 100,
            maximum: 10,
        }
        .into(),
        ClientError::LiveEventSequenceMismatch {
            expected: 11,
            actual: 12,
        }
        .into(),
        ClientError::BackendRejected {
            code: BackendErrorCode::InvalidRequest,
            message: "fixture invalid request".into(),
        }
        .into(),
        ClientError::BackendRejected {
            code: BackendErrorCode::Overloaded,
            message: "fixture queue capacity".into(),
        }
        .into(),
        ClientError::ConnectionUnusable.into(),
        StoreError::DeploymentIdentityMismatch.into(),
        StoreError::EventReplayConflict(11).into(),
        StoreError::EventProjectionLag {
            projected: 10,
            required: 11,
        }
        .into(),
        wcash_pool_core::ShareTargetError::Zero.into(),
        wcash_pool_core::TargetPolicyError::OutsideBounds {
            target,
            hardest: target,
            easiest: target,
        }
        .into(),
        wcash_pool_core::NoncePrefixError::LeaseMismatch {
            cursor_namespace: 1,
            provided_namespace: 2,
        }
        .into(),
        JobRouterError::BackendConnectionMismatch.into(),
        BootstrapError::StalledReplay,
        BootstrapError::NonceClaimCleanup {
            startup: Box::new(BootstrapError::NoCurrentJob),
            cleanup: Box::new(StoreError::BackendAuthorityMismatch),
        },
    ]
}

#[tokio::test(start_paused = true)]
async fn startup_readiness_does_not_retry_permanent_or_accounting_errors() {
    for error in permanent_errors() {
        let expected = error.to_string();
        let attempts = Cell::new(0);
        let mut first = Some(error);
        let began = time::Instant::now();
        let result = wait_for_backend_readiness(
            BACKEND_READINESS_TIMEOUT,
            BACKEND_READINESS_RETRY_INTERVAL,
            || {
                attempts.set(attempts.get() + 1);
                let error = first.take().expect("permanent error must not retry");
                async move { Err::<Option<()>, _>(error) }
            },
        )
        .await;
        assert_eq!(
            result
                .expect_err("permanent failure remains fatal")
                .to_string(),
            expected
        );
        assert_eq!(attempts.get(), 1);
        assert_eq!(began.elapsed(), Duration::ZERO);
    }
}

#[test]
fn startup_readiness_transport_whitelist_is_operation_and_kind_specific() {
    for kind in [
        io::ErrorKind::NotFound,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::TimedOut,
    ] {
        assert!(retryable_backend_readiness(
            &ClientError::Connect(kind.into()).into()
        ));
    }
    for operation in [
        "connect",
        "hello",
        "read_events",
        "subscribe_jobs",
        "health",
        "shutdown",
    ] {
        assert!(retryable_backend_readiness(
            &ClientError::Timeout { operation }.into()
        ));
    }
    for kind in [
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
        io::ErrorKind::TimedOut,
    ] {
        for operation in ["write request", "read response", "shutdown"] {
            assert!(retryable_backend_readiness(
                &ClientError::Io {
                    operation,
                    source: kind.into(),
                }
                .into()
            ));
        }
    }
    for error in permanent_errors() {
        assert!(!retryable_backend_readiness(&error));
    }
}

#[tokio::test(start_paused = true)]
async fn startup_readiness_fixed_deadline_cannot_be_extended_by_unhealthy_attempts() {
    let attempts = Cell::new(0_u32);
    let began = time::Instant::now();
    let result = wait_for_backend_readiness(
        BACKEND_READINESS_TIMEOUT,
        BACKEND_READINESS_RETRY_INTERVAL,
        || {
            attempts.set(attempts.get() + 1);
            async { Err::<Option<()>, _>(BootstrapError::NoCurrentJob) }
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(BootstrapError::BackendReadinessTimeout)
    ));
    assert_eq!(began.elapsed(), BACKEND_READINESS_TIMEOUT);
    assert!(attempts.get() <= 481, "250ms spacing bounds attempts");
    assert!(attempts.get() >= 479);
}

#[tokio::test(start_paused = true)]
async fn startup_readiness_deadline_bounds_a_stalled_attempt() {
    let began = time::Instant::now();
    let ready = wait_for_backend_readiness(
        BACKEND_READINESS_TIMEOUT,
        BACKEND_READINESS_RETRY_INTERVAL,
        || async {
            time::sleep(BACKEND_READINESS_TIMEOUT + Duration::from_secs(1)).await;
            Ok::<_, BootstrapError>(Some(()))
        },
    )
    .await;
    assert!(matches!(
        ready,
        Err(BootstrapError::BackendReadinessTimeout)
    ));
    assert_eq!(began.elapsed(), BACKEND_READINESS_TIMEOUT);
}

#[cfg(unix)]
mod wire {
    use std::{path::Path, rc::Rc};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        task::JoinHandle,
    };
    use wcash_pool_backend_client::ExpectedBackend;
    use wcash_pool_protocol::{
        decode_backend_request, encode_backend_message, AcceptableJob, BackendEvent,
        BackendMessage, BackendRequest, Hex108, JobDescriptor, TargetLe,
        BACKEND_LENGTH_PREFIX_BYTES, BACKEND_PROTOCOL_VERSION, MAX_BACKEND_PAYLOAD_BYTES,
        REQUIRED_BACKEND_CAPABILITIES,
    };

    use super::*;

    #[derive(Clone, Copy)]
    enum Step {
        NoCurrent,
        Unhealthy,
        Ready,
        QueuedEvent,
        ExpiresDuringHealth,
        HealthRejected,
        WrongJournal,
    }

    struct OwnedPeer(JoinHandle<()>);

    impl Drop for OwnedPeer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn request(stream: &mut UnixStream) -> BackendRequest {
        let mut prefix = [0_u8; BACKEND_LENGTH_PREFIX_BYTES];
        stream
            .read_exact(&mut prefix)
            .await
            .expect("fixture request length");
        let length = u32::from_be_bytes(prefix) as usize;
        assert!((1..=MAX_BACKEND_PAYLOAD_BYTES).contains(&length));
        let mut frame = prefix.to_vec();
        frame.resize(BACKEND_LENGTH_PREFIX_BYTES + length, 0);
        stream
            .read_exact(&mut frame[BACKEND_LENGTH_PREFIX_BYTES..])
            .await
            .expect("fixture request body");
        // The production codec validates the complete frame, including its
        // big-endian prefix, exact body length and strict request fields.
        decode_backend_request(&frame).expect("valid request")
    }

    async fn reply(stream: &mut UnixStream, message: BackendMessage) {
        stream
            .write_all(&encode_backend_message(&message).expect("fixture reply encodes"))
            .await
            .expect("fixture reply writes");
    }

    fn id(value: u128) -> CanonicalUuid {
        CanonicalUuid::new(Uuid::from_u128(value))
    }

    fn descriptor() -> JobDescriptor {
        let mut header = [0x41; 108];
        header[..4].copy_from_slice(&4_u32.to_le_bytes());
        header[100..104].copy_from_slice(&1_725_000_000_u32.to_le_bytes());
        JobDescriptor {
            job_id: Hex32::new([0x41; 32]),
            wcash_candidate_hash_le: Hex32::new([0x73; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([0x42; 32]),
            zcash_previous_hash_le: Hex32::new([0x41; 32]),
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

    fn config(path: &Path) -> BackendClientConfig {
        let expected = ExpectedBackend::new(
            Hex32::new([0x11; 32]),
            Hex32::new([0x22; 32]),
            0x5743_4153,
            Hex32::new([0x33; 32]),
            Hex32::new([0x44; 32]),
            TargetBe::new([0x7f; 32]),
        )
        .expect("expected authority")
        .with_backend_instance(id(7))
        .with_journal_stream(id(8));
        BackendClientConfig::new(path, expected)
            .expect("fixture client")
            .with_timeouts(Duration::from_millis(250), Duration::from_millis(500))
            .expect("bounded calls")
    }

    async fn peer(listener: UnixListener, steps: Vec<Step>) -> OwnedPeer {
        OwnedPeer(tokio::spawn(async move {
            time::timeout(Duration::from_secs(4), async move {
                for (index, step) in steps.into_iter().enumerate() {
                    let (mut stream, _) = listener.accept().await.expect("fresh attempt connects");
                    let BackendRequest::Hello {
                        id: request_id,
                        last_event_seq,
                        ..
                    } = request(&mut stream).await
                    else {
                        panic!("Hello must be first")
                    };
                    assert_eq!(
                        last_event_seq, 10,
                        "each attempt starts from verified durable cursor"
                    );
                    reply(
                        &mut stream,
                        BackendMessage::HelloOk {
                            version: BACKEND_PROTOCOL_VERSION,
                            id: request_id,
                            backend_session: id(100 + index as u128),
                            backend_instance: id(7),
                            journal_stream: id(if matches!(step, Step::WrongJournal) {
                                99
                            } else {
                                8
                            }),
                            capabilities: REQUIRED_BACKEND_CAPABILITIES.to_vec(),
                            wcash_genesis: Hex32::new([0x11; 32]),
                            zcash_genesis: Hex32::new([0x22; 32]),
                            wcash_payout_commitment: Hex32::new([0x33; 32]),
                            zcash_payout_commitment: Hex32::new([0x44; 32]),
                            share_target_ceiling_be: TargetBe::new([0x7f; 32]),
                            chain_id: 0x5743_4153,
                            current_event_seq: 10,
                        },
                    )
                    .await;
                    if matches!(step, Step::WrongJournal) {
                        continue;
                    }
                    let BackendRequest::ReadEvents {
                        id: request_id,
                        after_event_seq,
                        ..
                    } = request(&mut stream).await
                    else {
                        panic!("every attempt replays before subscription")
                    };
                    assert_eq!(after_event_seq, 10);
                    reply(
                        &mut stream,
                        BackendMessage::EventsPage {
                            version: BACKEND_PROTOCOL_VERSION,
                            id: request_id,
                            after_event_seq: 10,
                            next_event_seq: 10,
                            complete: true,
                            events: Vec::new(),
                        },
                    )
                    .await;
                    let BackendRequest::SubscribeJobs { id: request_id, .. } =
                        request(&mut stream).await
                    else {
                        panic!("subscription follows exact replay")
                    };
                    reply(
                        &mut stream,
                        BackendMessage::JobSnapshot {
                            version: BACKEND_PROTOCOL_VERSION,
                            id: request_id,
                            event_seq: 10,
                            current: (!matches!(step, Step::NoCurrent)).then(|| AcceptableJob {
                                job: descriptor(),
                                accept_for_ms: if matches!(step, Step::ExpiresDuringHealth) {
                                    1
                                } else {
                                    45_000
                                },
                            }),
                            recent: Vec::new(),
                        },
                    )
                    .await;
                    let BackendRequest::Health { id: request_id, .. } = request(&mut stream).await
                    else {
                        panic!("no submit or public service work before readiness")
                    };
                    if matches!(step, Step::ExpiresDuringHealth) {
                        time::sleep(Duration::from_millis(10)).await;
                    }
                    if matches!(step, Step::HealthRejected) {
                        reply(
                            &mut stream,
                            BackendMessage::Error {
                                version: BACKEND_PROTOCOL_VERSION,
                                id: request_id,
                                code: BackendErrorCode::BackendUnhealthy,
                                message: "fixture temporary health refusal".into(),
                            },
                        )
                        .await;
                        continue;
                    }
                    if matches!(step, Step::QueuedEvent) {
                        reply(
                            &mut stream,
                            BackendMessage::Event {
                                version: BACKEND_PROTOCOL_VERSION,
                                event: BackendEvent::JobActivated {
                                    event_seq: 11,
                                    job: descriptor(),
                                },
                            },
                        )
                        .await;
                    }
                    reply(
                        &mut stream,
                        BackendMessage::HealthStatus {
                            version: BACKEND_PROTOCOL_VERSION,
                            id: request_id,
                            event_seq: if matches!(step, Step::QueuedEvent) {
                                11
                            } else {
                                10
                            },
                            healthy: !matches!(step, Step::Unhealthy),
                            recovery_only: matches!(step, Step::Unhealthy),
                            pending_wcash: 0,
                            quarantined_wcash: 0,
                            pending_zcash: 0,
                        },
                    )
                    .await;
                    // The failed attempt must close this stream, not issue a
                    // second subscription or submit on ambiguous framing.
                    let mut byte = [0];
                    assert_eq!(stream.read(&mut byte).await.expect("attempt closes"), 0);
                }
            })
            .await
            .expect("finite programmed peer");
        }))
    }

    async fn attempt(config: BackendClientConfig) -> Result<Option<JobRouter>, BootstrapError> {
        let timeline = MonotonicTimeline::new();
        let mut client = BackendClient::connect(config, id(9), 10).await?;
        let page = client.read_events(10, 16).await?;
        assert!(page.complete && page.events.is_empty());
        let snapshot = client.subscribe_jobs(page.next_event_seq).await?;
        let jobs = JobRouter::from_snapshot(
            &snapshot,
            GenerationRegistryConfig::new(4, 16)?,
            timeline,
            16,
        )?;
        let ready = ready_backend_snapshot(&mut client, &jobs).await?;
        client.shutdown().await?;
        Ok(ready.then_some(jobs))
    }

    #[tokio::test]
    async fn startup_readiness_real_unix_client_reconnects_until_fresh_healthy_snapshot() {
        time::timeout(Duration::from_secs(5), async {
            let directory = tempfile::Builder::new()
                .prefix("prd-")
                .tempdir_in("/tmp")
                .expect("short socket dir");
            let path = directory.path().join("b.sock");
            let listener = UnixListener::bind(&path).expect("fixture binds");
            let mut peer = peer(
                listener,
                vec![
                    Step::NoCurrent,
                    Step::Unhealthy,
                    Step::HealthRejected,
                    Step::Ready,
                ],
            )
            .await;
            let config = config(&path);
            let attempts = Rc::new(Cell::new(0));
            let seen = Rc::clone(&attempts);
            let jobs = wait_for_backend_readiness(
                Duration::from_secs(3),
                Duration::from_millis(5),
                || {
                    seen.set(seen.get() + 1);
                    attempt(config.clone())
                },
            )
            .await
            .expect("one bounded startup wait recovers");
            assert_eq!(attempts.get(), 4);
            assert_eq!(
                jobs.current_generation()
                    .expect("registry")
                    .expect("current job")
                    .descriptor()
                    .job_id,
                descriptor().job_id
            );
            (&mut peer.0).await.expect("peer joined");
        })
        .await
        .expect("bounded startup wire fixture");
    }

    #[tokio::test]
    async fn startup_readiness_real_unix_client_rejects_unverified_events_and_expired_job() {
        time::timeout(Duration::from_secs(5), async {
            for step in [Step::QueuedEvent, Step::ExpiresDuringHealth] {
                let directory = tempfile::Builder::new()
                    .prefix("prg-")
                    .tempdir_in("/tmp")
                    .expect("short socket dir");
                let path = directory.path().join("b.sock");
                let listener = UnixListener::bind(&path).expect("fixture binds");
                let mut peer = peer(listener, vec![step]).await;
                assert!(attempt(config(&path))
                    .await
                    .expect("valid read-only exchange")
                    .is_none());
                (&mut peer.0).await.expect("peer joined");
            }
        })
        .await
        .expect("bounded negative snapshot fixtures");
    }

    #[tokio::test]
    async fn startup_readiness_real_unix_client_keeps_identity_failure_fatal() {
        time::timeout(Duration::from_secs(5), async {
            let directory = tempfile::Builder::new()
                .prefix("pri-")
                .tempdir_in("/tmp")
                .expect("short socket dir");
            let path = directory.path().join("b.sock");
            let listener = UnixListener::bind(&path).expect("fixture binds");
            let mut peer = peer(listener, vec![Step::WrongJournal]).await;
            let config = config(&path);
            let attempts = Cell::new(0);
            let result = wait_for_backend_readiness(
                Duration::from_secs(3),
                Duration::from_millis(5),
                || {
                    attempts.set(attempts.get() + 1);
                    attempt(config.clone())
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(BootstrapError::Backend(
                    ClientError::IdentityMismatch { .. }
                ))
            ));
            assert_eq!(attempts.get(), 1);
            (&mut peer.0).await.expect("peer joined");
        })
        .await
        .expect("bounded identity fixture");
    }
}

use super::*;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixed<const N: usize>(byte: u8) -> FixedHex<N> {
    FixedHex::new([byte; N])
}

fn uuid(value: u128) -> CanonicalUuid {
    CanonicalUuid::new(Uuid::from_u128(value))
}

fn identity() -> WorkerIdentity {
    WorkerIdentity {
        account_id: uuid(1),
        worker_id: uuid(2),
        label: "account.rig-01".to_string(),
    }
}

fn job(byte: u8) -> JobDescriptor {
    let mut header = [byte; 108];
    header[..4].copy_from_slice(&4u32.to_le_bytes());
    header[100..104].copy_from_slice(&1_725_000_000u32.to_le_bytes());
    JobDescriptor {
        job_id: fixed(byte),
        header_input: Hex108::new(header),
        wcash_previous_hash_le: fixed(byte.wrapping_add(1)),
        zcash_previous_hash_le: fixed(byte),
        wcash_target_le: fixed(0x7f).into(),
        zcash_target_le: fixed(0x3f).into(),
        wcash_height: 11,
        zcash_height: 22,
        max_age_ms: 45_000,
    }
}

fn capabilities() -> Vec<BackendCapability> {
    REQUIRED_BACKEND_CAPABILITIES.to_vec()
}

fn raw_backend_frame(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn encoded_zip_frame(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut frame = serde_json::to_vec(value)?;
    frame.push(b'\n');
    Ok(frame)
}

#[test]
fn fixed_hex_round_trips_all_protocol_sizes() -> TestResult {
    fn round_trip<const N: usize>(value: FixedHex<N>) -> TestResult {
        let json = serde_json::to_string(&value)?;
        let decoded: FixedHex<N> = serde_json::from_str(&json)?;
        assert_eq!(decoded, value);
        assert_eq!(json.len(), N * 2 + 2);
        Ok(())
    }

    round_trip(fixed::<4>(0x04))?;
    round_trip(fixed::<24>(0x24))?;
    round_trip(fixed::<28>(0x28))?;
    round_trip(fixed::<32>(0x32))?;
    round_trip(fixed::<108>(0x10))?;
    round_trip(fixed::<1344>(0x44))?;
    Ok(())
}

#[test]
fn backend_hex_and_uuid_require_canonical_encodings() {
    assert!(Hex4::parse("01020304").is_ok());
    assert!(Hex4::parse("0102030A").is_err());
    assert!(Hex4::parse("0102030").is_err());
    assert!(Hex4::parse("0102030g").is_err());

    let uppercase = r#""00000000-0000-0000-0000-00000000000A""#;
    let compact = r#""0000000000000000000000000000000a""#;
    assert!(serde_json::from_str::<CanonicalUuid>(uppercase).is_err());
    assert!(serde_json::from_str::<CanonicalUuid>(compact).is_err());
}

#[test]
fn target_endian_markers_reverse_asymmetric_bytes_and_round_trip() -> TestResult {
    let mut little_endian_bytes = [0u8; 32];
    little_endian_bytes[0] = 0x01;
    little_endian_bytes[1] = 0x23;
    little_endian_bytes[30] = 0x45;
    little_endian_bytes[31] = 0x67;
    let little = TargetLe::new(little_endian_bytes);
    let big = TargetBe::from(&little);

    let mut expected_big_endian_bytes = little_endian_bytes;
    expected_big_endian_bytes.reverse();
    assert_eq!(big.as_bytes(), &expected_big_endian_bytes);
    assert_eq!(TargetLe::from(&big), little);
    assert_eq!(
        serde_json::to_string(&little)?,
        format!("\"{}\"", hex::encode(little_endian_bytes))
    );
    assert_eq!(
        serde_json::to_string(&big)?,
        format!("\"{}\"", hex::encode(expected_big_endian_bytes))
    );
    Ok(())
}

#[test]
fn backend_health_frame_has_exact_big_endian_golden_encoding() -> TestResult {
    let request = BackendRequest::Health { version: 1, id: 7 };
    let frame = encode_backend_request(&request)?;
    let payload = br#"{"type":"health","v":1,"id":7}"#;
    assert_eq!(frame, raw_backend_frame(payload));
    assert_eq!(decode_backend_request(&frame)?, request);
    assert_eq!(request.id(), 7);
    Ok(())
}

#[test]
fn backend_frame_rejects_missing_empty_oversize_truncated_and_trailing() {
    assert_eq!(
        decode_backend_request(&[0, 0, 0]),
        Err(ProtocolError::MissingLengthPrefix)
    );
    assert_eq!(
        decode_backend_request(&[0, 0, 0, 0]),
        Err(ProtocolError::EmptyFrame {
            protocol: "backend"
        })
    );

    let declared = u32::try_from(MAX_BACKEND_PAYLOAD_BYTES + 1).unwrap_or(u32::MAX);
    assert_eq!(
        decode_backend_request(&declared.to_be_bytes()),
        Err(ProtocolError::FrameTooLarge {
            protocol: "backend",
            maximum: MAX_BACKEND_PAYLOAD_BYTES,
            actual: MAX_BACKEND_PAYLOAD_BYTES + 1,
        })
    );

    let valid = raw_backend_frame(br#"{"type":"health","v":1,"id":7}"#);
    let mut truncated = valid.clone();
    truncated.pop();
    assert!(matches!(
        decode_backend_request(&truncated),
        Err(ProtocolError::InvalidFrameLength { .. })
    ));
    let mut trailing = valid;
    trailing.push(0);
    assert!(matches!(
        decode_backend_request(&trailing),
        Err(ProtocolError::InvalidFrameLength { .. })
    ));
}

#[test]
fn frame_codec_decodes_fragmented_and_coalesced_client_frames() -> TestResult {
    let first = BackendRequest::Health { version: 1, id: 7 };
    let second = BackendRequest::ReadEvents {
        version: 1,
        id: 8,
        after_event_seq: 12,
        limit: 10,
    };
    let first_frame = FrameCodec::encode_client(&first)?;
    let second_frame = FrameCodec::encode_client(&second)?;

    let mut fragmented = FrameCodec::new();
    let mut decoded = None;
    for byte in &first_frame {
        let (consumed, message) = fragmented.decode_client(std::slice::from_ref(byte))?;
        assert_eq!(consumed, 1);
        if message.is_some() {
            assert!(decoded.is_none());
            decoded = message;
        }
    }
    assert_eq!(decoded, Some(first.clone()));
    assert_eq!(fragmented.buffered_bytes(), 0);

    let mut combined = first_frame.clone();
    combined.extend_from_slice(&second_frame);
    let mut coalesced = FrameCodec::new();
    let (first_consumed, first_decoded) = coalesced.decode_client(&combined)?;
    assert_eq!(first_consumed, first_frame.len());
    assert_eq!(first_decoded, Some(first));
    let (second_consumed, second_decoded) = coalesced.decode_client(&combined[first_consumed..])?;
    assert_eq!(second_consumed, second_frame.len());
    assert_eq!(second_decoded, Some(second));
    Ok(())
}

#[test]
fn frame_codec_rejects_declared_limits_before_buffering_and_recovers() -> TestResult {
    let mut codec = FrameCodec::new();
    let oversized = u32::try_from(MAX_FRAME_BYTES + 1)?.to_be_bytes();
    assert_eq!(
        codec.decode_client(&oversized),
        Err(ProtocolError::FrameTooLarge {
            protocol: "backend",
            maximum: MAX_FRAME_BYTES,
            actual: MAX_FRAME_BYTES + 1,
        })
    );
    assert_eq!(codec.buffered_bytes(), 0);
    assert_eq!(
        codec.decode_client(&[0, 0, 0, 0]),
        Err(ProtocolError::EmptyFrame {
            protocol: "backend"
        })
    );
    assert_eq!(codec.buffered_bytes(), 0);

    let request = BackendRequest::Health { version: 1, id: 9 };
    let frame = FrameCodec::encode_client(&request)?;
    assert_eq!(codec.decode_client(&frame)?, (frame.len(), Some(request)));
    Ok(())
}

#[test]
fn zip301_codec_decodes_fragmented_and_coalesced_requests() -> TestResult {
    let first_frame = encoded_zip_frame(&serde_json::json!({
        "id": "authorize-secret-id",
        "method": "mining.authorize",
        "params": ["account.rig-secret", "password-secret"]
    }))?;
    let second_frame = encoded_zip_frame(&serde_json::json!({
        "id": 2,
        "method": "mining.subscribe",
        "params": []
    }))?;
    let split = first_frame.len() / 2;
    let mut codec = Zip301FrameCodec::new();

    assert_eq!(
        codec.decode_request(&first_frame[..split], NonceProfile::FourByte)?,
        (split, None)
    );
    let codec_debug = format!("{codec:?}");
    assert!(codec_debug.contains(&format!("buffered_bytes: {split}")));
    assert!(!codec_debug.contains("account.rig-secret"));
    assert!(!codec_debug.contains("password-secret"));

    let mut coalesced = first_frame[split..].to_vec();
    coalesced.extend_from_slice(&second_frame);
    let (first_consumed, first) = codec.decode_request(&coalesced, NonceProfile::FourByte)?;
    assert_eq!(first_consumed, first_frame.len() - split);
    assert!(matches!(first, Some(Zip301Request::Authorize { .. })));
    let (second_consumed, second) =
        codec.decode_request(&coalesced[first_consumed..], NonceProfile::FourByte)?;
    assert_eq!(second_consumed, second_frame.len());
    assert!(matches!(second, Some(Zip301Request::Subscribe { .. })));
    assert_eq!(codec.buffered_bytes(), 0);
    Ok(())
}

#[test]
fn zip301_codec_rejects_at_limit_plus_one_and_resets_after_errors() -> TestResult {
    let mut codec = Zip301FrameCodec::new();
    let at_limit = vec![b' '; MAX_ZIP301_PAYLOAD_BYTES];
    assert_eq!(
        codec.decode_request(&at_limit, NonceProfile::FourByte)?,
        (MAX_ZIP301_PAYLOAD_BYTES, None)
    );
    assert_eq!(codec.buffered_bytes(), MAX_ZIP301_PAYLOAD_BYTES);
    assert_eq!(
        codec.decode_request(b"x", NonceProfile::FourByte),
        Err(ProtocolError::FrameTooLarge {
            protocol: "ZIP-301",
            maximum: MAX_ZIP301_PAYLOAD_BYTES,
            actual: MAX_ZIP301_PAYLOAD_BYTES + 1,
        })
    );
    assert_eq!(codec.buffered_bytes(), 0);

    assert!(codec
        .decode_request(b"not-json\n", NonceProfile::FourByte)
        .is_err());
    assert_eq!(codec.buffered_bytes(), 0);
    let valid = encoded_zip_frame(&serde_json::json!({
        "id": 3,
        "method": "mining.subscribe",
        "params": []
    }))?;
    assert!(matches!(
        codec.decode_request(&valid, NonceProfile::FourByte)?,
        (consumed, Some(Zip301Request::Subscribe { .. })) if consumed == valid.len()
    ));
    Ok(())
}

#[test]
fn frame_codec_decodes_server_messages_and_submit_share_is_redacted() -> TestResult {
    let response = BackendMessage::HealthStatus {
        version: 1,
        id: 7,
        event_seq: 4,
        healthy: true,
        pending_wcash: 0,
        pending_zcash: 1,
    };
    let frame = FrameCodec::encode_server(&response)?;
    let mut codec = FrameCodec::new();
    assert_eq!(codec.decode_server(&frame)?, (frame.len(), Some(response)));

    let submission = SubmitShare {
        version: 1,
        id: 8,
        job_id: fixed(1),
        identity: identity(),
        target_le: fixed(2).into(),
        time: Hex4::new([0x78, 0x56, 0x34, 0x12]),
        nonce: fixed(3),
        solution: Box::new(fixed(4)),
    };
    submission.validate()?;
    let debug = format!("{submission:?}");
    assert!(debug.contains("[REDACTED 1344 bytes]"));
    assert!(!debug.contains(&"04".repeat(1_344)));
    let message: ClientMessage = submission.into();
    assert!(matches!(message, BackendRequest::SubmitShare { id: 8, .. }));
    Ok(())
}

#[test]
fn backend_request_rejects_unknown_fields_versions_ids_and_limits() {
    for payload in [
        br#"{"type":"health","v":1,"id":1,"extra":true}"#.as_slice(),
        br#"{"type":"health","v":2,"id":1}"#.as_slice(),
        br#"{"type":"health","v":1,"id":0}"#.as_slice(),
        br#"{"type":"read_events","v":1,"id":1,"after_event_seq":0,"limit":0}"#.as_slice(),
        br#"{"type":"unknown","v":1,"id":1}"#.as_slice(),
    ] {
        assert!(decode_backend_request(&raw_backend_frame(payload)).is_err());
    }
}

#[test]
fn backend_jobs_and_zip301_notifications_share_strict_v4_header_checks() -> TestResult {
    let valid = job(0x11);
    valid.validate()?;
    assert_eq!(&valid.header_input.as_bytes()[..4], &[4, 0, 0, 0]);
    assert_ne!(&valid.header_input.as_bytes()[100..104], &[0, 0, 0, 0]);

    let mut wrong_version = valid.clone();
    let mut header = *wrong_version.header_input.as_bytes();
    header[..4].copy_from_slice(&[4, 0, 0, 1]);
    wrong_version.header_input = Hex108::new(header);
    assert!(matches!(
        wrong_version.validate(),
        Err(ProtocolError::InvalidField {
            field: "job.header_input.version",
            ..
        })
    ));
    assert!(encode_backend_message(&BackendMessage::Event {
        version: BACKEND_PROTOCOL_VERSION,
        event: BackendEvent::JobActivated {
            event_seq: 1,
            job: wrong_version.clone(),
        },
    })
    .is_err());
    assert!(matches!(
        encode_zip301_message(&Zip301ServerMessage::Notify(Zip301Notify {
            job_id: wrong_version.job_id,
            header_input: wrong_version.header_input,
            clean_jobs: true,
        })),
        Err(ProtocolError::InvalidField {
            field: "mining.notify version",
            ..
        })
    ));

    let mut zero_time = valid;
    let mut header = *zero_time.header_input.as_bytes();
    header[100..104].fill(0);
    zero_time.header_input = Hex108::new(header);
    assert!(matches!(
        zero_time.validate(),
        Err(ProtocolError::InvalidField {
            field: "job.header_input.time",
            ..
        })
    ));
    assert!(matches!(
        encode_zip301_message(&Zip301ServerMessage::Notify(Zip301Notify {
            job_id: zero_time.job_id,
            header_input: zero_time.header_input,
            clean_jobs: true,
        })),
        Err(ProtocolError::InvalidField {
            field: "mining.notify time",
            ..
        })
    ));
    Ok(())
}

#[test]
fn large_submit_request_round_trips_and_debug_is_redacted() -> TestResult {
    let request = BackendRequest::SubmitShare {
        version: 1,
        id: 9,
        job_id: fixed(1),
        identity: identity(),
        target_le: fixed(2).into(),
        time: Hex4::new([0x78, 0x56, 0x34, 0x12]),
        nonce: fixed(3),
        solution: Box::new(fixed(4)),
    };
    let frame = encode_backend_request(&request)?;
    let payload: serde_json::Value = serde_json::from_slice(&frame[BACKEND_LENGTH_PREFIX_BYTES..])?;
    assert_eq!(payload["time"], "78563412");
    assert_eq!(decode_backend_request(&frame)?, request);
    let debug = format!("{request:?}");
    assert!(debug.contains("[REDACTED 1344 bytes]"));
    assert!(!debug.contains("account.rig-01"));
    assert!(!debug.contains("00000000-0000-0000-0000-000000000001"));
    assert!(!debug.contains("00000000-0000-0000-0000-000000000002"));
    assert!(!debug.contains(&"04".repeat(1_344)));
    Ok(())
}

#[test]
fn worker_identity_and_worker_bearing_backend_debug_are_redacted() {
    let worker = identity();
    assert_eq!(
        format!("{worker:?}"),
        "WorkerIdentity { account_id: \"[REDACTED]\", worker_id: \"[REDACTED]\", label: \"[REDACTED]\" }"
    );

    let event = BackendEvent::ShareCommitted {
        receipt: ShareReceipt {
            event_seq: 1,
            share_id: fixed(0x31),
            parent_hash_le: fixed(0x32),
            wcash_candidate: false,
            zcash_candidate: false,
        },
        job_id: fixed(0x33),
        identity: worker,
        target_le: fixed(0x34).into(),
    };
    let event_debug = format!("{event:?}");
    assert!(event_debug.contains("identity: \"[REDACTED]\""));
    assert!(!event_debug.contains("account.rig-01"));
    assert!(!event_debug.contains("00000000-0000-0000-0000-000000000001"));
    assert!(!event_debug.contains("00000000-0000-0000-0000-000000000002"));

    let message = BackendMessage::EventsPage {
        version: BACKEND_PROTOCOL_VERSION,
        id: 1,
        after_event_seq: 0,
        next_event_seq: 1,
        complete: true,
        events: vec![event],
    };
    let message_debug = format!("{message:?}");
    assert!(message_debug.contains("identity: \"[REDACTED]\""));
    assert!(!message_debug.contains("account.rig-01"));
    assert!(!message_debug.contains("00000000-0000-0000-0000-000000000001"));

    let error_debug = format!(
        "{:?}",
        BackendMessage::Error {
            version: BACKEND_PROTOCOL_VERSION,
            id: 1,
            code: BackendErrorCode::InvalidRequest,
            message: "account.rig-01 secret diagnostic".to_owned(),
        }
    );
    assert!(error_debug.contains("message: \"[REDACTED]\""));
    assert!(!error_debug.contains("secret diagnostic"));
}

#[test]
fn share_time_is_required_and_replay_status_is_response_only() -> TestResult {
    let zero_time = BackendRequest::SubmitShare {
        version: 1,
        id: 9,
        job_id: fixed(1),
        identity: identity(),
        target_le: fixed(2).into(),
        time: Hex4::new([0; 4]),
        nonce: fixed(3),
        solution: Box::new(fixed(4)),
    };
    assert!(zero_time.validate().is_err());

    let receipt = ShareReceipt {
        event_seq: 7,
        share_id: fixed(0x51),
        parent_hash_le: fixed(0x52),
        wcash_candidate: true,
        zcash_candidate: false,
    };
    let response = BackendMessage::ShareCommitted {
        version: 1,
        id: 10,
        receipt: receipt.clone(),
        replayed: true,
    };
    let expected = format!(
        "{{\"type\":\"share_committed\",\"v\":1,\"id\":10,\"receipt\":{{\"event_seq\":7,\"share_id\":\"{}\",\"parent_hash_le\":\"{}\",\"wcash_candidate\":true,\"zcash_candidate\":false}},\"replayed\":true}}",
        "51".repeat(32),
        "52".repeat(32),
    );
    let frame = encode_backend_message(&response)?;
    assert_eq!(frame, raw_backend_frame(expected.as_bytes()));
    assert_eq!(decode_backend_message(&frame)?, response);

    let event = BackendMessage::Event {
        version: 1,
        event: BackendEvent::ShareCommitted {
            receipt,
            job_id: fixed(0x53),
            identity: identity(),
            target_le: fixed(0x54).into(),
        },
    };
    let event_frame = encode_backend_message(&event)?;
    let event_payload: serde_json::Value =
        serde_json::from_slice(&event_frame[BACKEND_LENGTH_PREFIX_BYTES..])?;
    assert!(event_payload["event"]["receipt"].get("replayed").is_none());
    assert_eq!(decode_backend_message(&event_frame)?, event);

    let missing_time = format!(
        "{{\"type\":\"submit_share\",\"v\":1,\"id\":9,\"job_id\":\"{}\",\"identity\":{{\"account_id\":\"00000000-0000-0000-0000-000000000001\",\"worker_id\":\"00000000-0000-0000-0000-000000000002\",\"label\":\"a.rig\"}},\"target_le\":\"{}\",\"nonce\":\"{}\",\"solution\":\"{}\"}}",
        "01".repeat(32),
        "02".repeat(32),
        "03".repeat(32),
        "04".repeat(1_344),
    );
    assert!(decode_backend_request(&raw_backend_frame(missing_time.as_bytes())).is_err());

    let nested_replayed = format!(
        "{{\"type\":\"share_committed\",\"v\":1,\"id\":10,\"receipt\":{{\"event_seq\":7,\"share_id\":\"{}\",\"parent_hash_le\":\"{}\",\"wcash_candidate\":true,\"zcash_candidate\":false,\"replayed\":true}},\"replayed\":true}}",
        "51".repeat(32),
        "52".repeat(32),
    );
    assert!(decode_backend_message(&raw_backend_frame(nested_replayed.as_bytes())).is_err());
    Ok(())
}

#[test]
fn hello_requires_distinct_identities_and_complete_capabilities() -> TestResult {
    let valid = BackendMessage::HelloOk {
        version: 1,
        id: 1,
        backend_session: uuid(1),
        backend_instance: uuid(2),
        journal_stream: uuid(3),
        capabilities: capabilities(),
        wcash_genesis: fixed(1),
        zcash_genesis: fixed(2),
        chain_id: 0x5745_4301,
        current_event_seq: 0,
    };
    assert_eq!(
        decode_backend_message(&encode_backend_message(&valid)?)?,
        valid
    );

    let mut duplicate_identity = valid.clone();
    if let BackendMessage::HelloOk {
        backend_session, ..
    } = &mut duplicate_identity
    {
        *backend_session = uuid(2);
    }
    assert!(encode_backend_message(&duplicate_identity).is_err());
    let mut missing_capability = valid;
    if let BackendMessage::HelloOk { capabilities, .. } = &mut missing_capability {
        capabilities.pop();
    }
    assert!(encode_backend_message(&missing_capability).is_err());
    Ok(())
}

#[test]
fn semantic_identities_reject_nil_uuids() {
    let nil = CanonicalUuid::new(Uuid::nil());
    let mut invalid_worker = identity();
    invalid_worker.account_id = nil;
    assert!(invalid_worker.validate().is_err());

    let hello = BackendRequest::Hello {
        version: 1,
        id: 1,
        pool_instance: nil,
        last_event_seq: 0,
    };
    assert!(hello.validate().is_err());

    let hello_ok = BackendMessage::HelloOk {
        version: 1,
        id: 1,
        backend_session: nil,
        backend_instance: uuid(2),
        journal_stream: uuid(3),
        capabilities: capabilities(),
        wcash_genesis: fixed(1),
        zcash_genesis: fixed(2),
        chain_id: 1,
        current_event_seq: 0,
    };
    assert!(hello_ok.validate().is_err());
}

#[test]
fn snapshots_bind_remaining_lifetime_and_reject_duplicates() {
    let current = AcceptableJob {
        job: job(1),
        accept_for_ms: 30_000,
    };
    let valid = BackendMessage::JobSnapshot {
        version: 1,
        id: 2,
        event_seq: 8,
        current: Some(current.clone()),
        recent: vec![AcceptableJob {
            job: job(2),
            accept_for_ms: 5_000,
        }],
    };
    assert!(valid.validate().is_ok());

    let mut expired = valid.clone();
    if let BackendMessage::JobSnapshot {
        current: snapshot_current,
        recent,
        ..
    } = &mut expired
    {
        *snapshot_current = Some(AcceptableJob {
            job: current.job.clone(),
            accept_for_ms: 45_001,
        });
        recent.clear();
    }
    assert!(expired.validate().is_err());
    let mut duplicate = valid;
    if let BackendMessage::JobSnapshot {
        current: snapshot_current,
        recent,
        ..
    } = &mut duplicate
    {
        *snapshot_current = Some(current.clone());
        *recent = vec![current];
    }
    assert!(duplicate.validate().is_err());
}

#[test]
fn invalidation_grace_is_reason_specific() {
    let hard_stale = BackendEvent::JobInvalidated {
        event_seq: 1,
        job_id: fixed(1),
        reason: JobInvalidationReason::ZcashTipChanged,
        accept_for_ms: 0,
    };
    assert!(hard_stale.validate().is_ok());
    let mut invalid_grace = hard_stale.clone();
    if let BackendEvent::JobInvalidated { accept_for_ms, .. } = &mut invalid_grace {
        *accept_for_ms = 1;
    }
    assert!(invalid_grace.validate().is_err());
    let mut soft_stale = hard_stale;
    if let BackendEvent::JobInvalidated {
        reason,
        accept_for_ms,
        ..
    } = &mut soft_stale
    {
        *reason = JobInvalidationReason::Superseded;
        *accept_for_ms = 10_000;
    }
    assert!(soft_stale.validate().is_ok());
}

#[test]
fn event_pages_are_strictly_ordered_and_cursor_bound() {
    let first = BackendEvent::JobActivated {
        event_seq: 11,
        job: job(1),
    };
    let second = BackendEvent::GenerationClosed {
        event_seq: 12,
        job_id: fixed(1),
    };
    let valid = BackendMessage::EventsPage {
        version: 1,
        id: 3,
        after_event_seq: 10,
        next_event_seq: 12,
        complete: true,
        events: vec![first.clone(), second.clone()],
    };
    assert!(valid.validate().is_ok());
    assert_eq!(valid.correlation_id(), Some(3));
    let mut reversed = valid.clone();
    if let BackendMessage::EventsPage { events, .. } = &mut reversed {
        *events = vec![second, first];
    }
    assert!(reversed.validate().is_err());
    let mut wrong_cursor = valid;
    if let BackendMessage::EventsPage { next_event_seq, .. } = &mut wrong_cursor {
        *next_event_seq = 13;
    }
    assert!(wrong_cursor.validate().is_err());

    let gap = BackendMessage::EventsPage {
        version: 1,
        id: 4,
        after_event_seq: 10,
        next_event_seq: 13,
        complete: false,
        events: vec![
            BackendEvent::JobActivated {
                event_seq: 11,
                job: job(2),
            },
            BackendEvent::GenerationClosed {
                event_seq: 13,
                job_id: fixed(2),
            },
        ],
    };
    assert!(gap.validate().is_err());
}

#[test]
fn zip301_authorize_is_strict_and_password_debug_is_redacted() -> TestResult {
    let frame = encoded_zip_frame(&serde_json::json!({
        "id": 2,
        "method": "mining.authorize",
        "params": ["account.rig-01", "test-only-password"]
    }))?;
    let request = decode_zip301_request(&frame, NonceProfile::FourByte)?;
    assert_eq!(
        request,
        Zip301Request::Authorize {
            id: Zip301Id::Number(2),
            worker: "account.rig-01".to_string(),
            password: "test-only-password".to_string(),
        }
    );
    let debug = format!("{request:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("account.rig-01"));
    assert!(!debug.contains("test-only-password"));
    Ok(())
}

#[test]
fn zip301_submit_accepts_uppercase_hex_and_strips_compact_size() -> TestResult {
    let solution = format!("FD4005{}", "AB".repeat(1_344));
    let frame = encoded_zip_frame(&serde_json::json!({
        "id": "share-1",
        "method": "mining.submit",
        "params": [
            "account.rig-01",
            "11".repeat(32).to_uppercase(),
            "78563412",
            "22".repeat(28).to_uppercase(),
            solution
        ]
    }))?;
    let request = decode_zip301_request(&frame, NonceProfile::FourByte)?;
    let expected = Zip301Request::Submit {
        id: Zip301Id::String("share-1".to_string()),
        worker: "account.rig-01".to_string(),
        job_id: fixed(0x11),
        time: Hex4::new([0x78, 0x56, 0x34, 0x12]),
        nonce_2: NonceSuffix::TwentyEight(fixed(0x22)),
        solution: Box::new(fixed(0xab)),
    };
    assert_eq!(request, expected);
    let debug = format!("{request:?}");
    assert!(debug.contains("worker: \"[REDACTED]\""));
    assert!(debug.contains("nonce_2: \"[REDACTED]\""));
    assert!(debug.contains("solution: \"[REDACTED 1344 bytes]\""));
    assert!(!debug.contains("account.rig-01"));
    assert!(!debug.contains("share-1"));
    assert!(!debug.contains(&"22".repeat(28)));
    assert!(!debug.contains(&"ab".repeat(1_344)));
    Ok(())
}

#[test]
fn nonce_profiles_enforce_suffix_size_and_join_without_overlap() -> TestResult {
    let solution = format!("fd4005{}", "00".repeat(1_344));
    for (profile, nonce) in [
        (NonceProfile::FourByte, "11".repeat(28)),
        (NonceProfile::EightByte, "22".repeat(24)),
    ] {
        let frame = encoded_zip_frame(&serde_json::json!({
            "id": 4,
            "method": "mining.submit",
            "params": ["account.rig", "33".repeat(32), "01000000", nonce, solution]
        }))?;
        assert!(decode_zip301_request(&frame, profile).is_ok());
        assert!(decode_zip301_request(
            &frame,
            match profile {
                NonceProfile::FourByte => NonceProfile::EightByte,
                NonceProfile::EightByte => NonceProfile::FourByte,
            }
        )
        .is_err());
    }

    let joined = join_nonce(
        &NoncePrefix::Four(fixed(0x04)),
        &NonceSuffix::TwentyEight(fixed(0xaa)),
    )?;
    assert_eq!(&joined.as_bytes()[..4], &[0x04; 4]);
    assert!(join_nonce(
        &NoncePrefix::Four(fixed(0x04)),
        &NonceSuffix::TwentyFour(fixed(0xaa))
    )
    .is_err());
    Ok(())
}

#[test]
fn zip301_rejects_bad_solution_prefix_length_and_parameter_shapes() -> TestResult {
    let cases = [
        serde_json::json!({
            "id": 1, "method": "mining.submit",
            "params": ["account.rig", "11".repeat(32), "01000000", "22".repeat(28), format!("fc4005{}", "00".repeat(1344))]
        }),
        serde_json::json!({
            "id": 1, "method": "mining.submit",
            "params": ["account.rig", "11".repeat(32), "01000000", "22".repeat(28), "fd4005"]
        }),
        serde_json::json!({
            "id": 1, "method": "mining.submit", "params": []
        }),
        serde_json::json!({
            "id": 1, "method": "mining.authorize", "params": ["bad worker", "x"]
        }),
    ];
    for value in cases {
        assert!(
            decode_zip301_request(&encoded_zip_frame(&value)?, NonceProfile::FourByte).is_err()
        );
    }
    Ok(())
}

#[test]
fn zip301_line_framing_rejects_missing_crlf_multiple_and_trailing() {
    let payload = br#"{"id":1,"method":"mining.subscribe","params":[]}"#;
    assert_eq!(
        decode_zip301_request(payload, NonceProfile::FourByte),
        Err(ProtocolError::InvalidLineFraming)
    );
    for suffix in [b"\r\n".as_slice(), b"\n\n".as_slice(), b" \n".as_slice()] {
        let mut frame = payload.to_vec();
        frame.extend_from_slice(suffix);
        assert_eq!(
            decode_zip301_request(&frame, NonceProfile::FourByte),
            Err(ProtocolError::InvalidLineFraming)
        );
    }
}

#[test]
fn zip301_rejects_oversize_unknown_methods_fields_and_invalid_ids() -> TestResult {
    let mut oversized = vec![b' '; MAX_ZIP301_PAYLOAD_BYTES + 1];
    oversized.push(b'\n');
    assert!(matches!(
        decode_zip301_request(&oversized, NonceProfile::FourByte),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
    for value in [
        serde_json::json!({"id":1,"method":"mining.unknown","params":[]}),
        serde_json::json!({"id":1,"method":"mining.subscribe","params":[],"extra":1}),
        serde_json::json!({"id":true,"method":"mining.subscribe","params":[]}),
    ] {
        assert!(
            decode_zip301_request(&encoded_zip_frame(&value)?, NonceProfile::FourByte).is_err()
        );
    }
    Ok(())
}

#[test]
fn zip301_response_and_set_target_match_golden_frames() -> TestResult {
    let subscribed = encode_zip301_message(&Zip301ServerMessage::Subscribed {
        id: Zip301Id::Number(1),
        nonce_1: NoncePrefix::Four(Hex4::new([1, 2, 3, 4])),
    })?;
    assert_eq!(
        subscribed,
        br#"{"id":1,"result":[null,"01020304"],"error":null}
"#
    );
    let target = encode_zip301_message(&Zip301ServerMessage::SetTarget {
        target_be: fixed(0x7f).into(),
    })?;
    assert_eq!(
        target,
        format!(
            "{{\"id\":null,\"method\":\"mining.set_target\",\"params\":[\"{}\"]}}\n",
            "7f".repeat(32)
        )
        .into_bytes()
    );
    assert!(encode_zip301_message(&Zip301ServerMessage::SetTarget {
        target_be: fixed(0).into()
    })
    .is_err());
    assert!(encode_zip301_message(&Zip301ServerMessage::Boolean {
        id: Zip301Id::Number(2),
        result: false,
    })
    .is_err());
    Ok(())
}

#[test]
fn zip301_notify_has_exact_eight_field_partition() -> TestResult {
    let descriptor = job(0x11);
    let frame = encode_zip301_message(&Zip301ServerMessage::Notify(Zip301Notify {
        job_id: descriptor.job_id.clone(),
        header_input: descriptor.header_input.clone(),
        clean_jobs: true,
    }))?;
    let value: serde_json::Value = serde_json::from_slice(&frame[..frame.len() - 1])?;
    assert_eq!(value["method"], "mining.notify");
    let params = match value["params"].as_array() {
        Some(params) => params,
        None => return Err(std::io::Error::other("notify params missing").into()),
    };
    assert_eq!(params.len(), 8);
    for (index, encoded_bytes) in [(1, 4), (2, 32), (3, 32), (4, 32), (5, 4), (6, 4)] {
        let encoded = match params[index].as_str() {
            Some(encoded) => encoded,
            None => return Err(std::io::Error::other("notify field is not text").into()),
        };
        assert_eq!(encoded.len(), encoded_bytes * 2);
    }
    assert_eq!(params[7], true);

    let mut invalid_header = *descriptor.header_input.as_bytes();
    invalid_header[..4].copy_from_slice(&5u32.to_le_bytes());
    assert!(
        encode_zip301_message(&Zip301ServerMessage::Notify(Zip301Notify {
            job_id: descriptor.job_id,
            header_input: Hex108::new(invalid_header),
            clean_jobs: true,
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn zip301_subscribe_accepts_bounded_legacy_scalar_parameters() -> TestResult {
    let frame = encoded_zip_frame(&serde_json::json!({
        "id": null,
        "method": "mining.subscribe",
        "params": ["nheqminer/0.5", null, "pool.example", 3032]
    }))?;
    let request = decode_zip301_request(&frame, NonceProfile::FourByte)?;
    assert!(matches!(request, Zip301Request::Subscribe { .. }));

    let invalid = encoded_zip_frame(&serde_json::json!({
        "id": 1,
        "method": "mining.subscribe",
        "params": [{"not":"a scalar"}]
    }))?;
    assert!(decode_zip301_request(&invalid, NonceProfile::FourByte).is_err());
    Ok(())
}

#[test]
fn direct_backend_serde_unknown_nested_fields_are_rejected() {
    let payload = format!(
            "{{\"type\":\"submit_share\",\"v\":1,\"id\":1,\"job_id\":\"{}\",\"identity\":{{\"account_id\":\"00000000-0000-0000-0000-000000000001\",\"worker_id\":\"00000000-0000-0000-0000-000000000002\",\"label\":\"a.rig\",\"extra\":true}},\"target_le\":\"{}\",\"time\":\"01000000\",\"nonce\":\"{}\",\"solution\":\"{}\"}}",
            "01".repeat(32),
            "02".repeat(32),
            "03".repeat(32),
            "04".repeat(1_344),
        );
    assert!(decode_backend_request(&raw_backend_frame(payload.as_bytes())).is_err());
}

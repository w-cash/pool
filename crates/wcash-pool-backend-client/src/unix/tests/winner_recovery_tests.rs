use super::*;

async fn assert_recovered_receipt_role(mask: u8, historical_replay: bool) -> TestResult {
    let encoded = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wcash-pool-core/tests/vectors/zcash-mainnet-1687118-header.hex"
    ))
    .trim();
    let header: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16))
        .collect::<Result<_, _>>()?;
    let mut descriptor = job(0x31);
    descriptor.header_input = Hex108::new(header[..108].try_into()?);
    descriptor.zcash_previous_hash_le = Hex32::new(header[4..36].try_into()?);
    let mut target = [0; 32];
    target[25..28].copy_from_slice(&[0xf0, 0xda, 0x01]);
    descriptor.zcash_target_le = TargetLe::new(target);
    let mut current = descriptor.clone();
    current.job_id = Hex32::new([0x32; 32]);
    current.wcash_previous_hash_le = Hex32::new([0x78; 32]);
    let invalidated = BackendEvent::JobInvalidated {
        event_seq: 11,
        job_id: descriptor.job_id.clone(),
        reason: wcash_pool_protocol::JobInvalidationReason::WcashTipChanged,
        accept_for_ms: 0,
    };
    let activated = BackendEvent::JobActivated {
        event_seq: 12,
        job: current,
    };
    invalidated
        .validate()
        .map_err(|error| format!("Wcash rollover fixture invalidation: {error}"))?;
    activated
        .validate()
        .map_err(|error| format!("Wcash rollover fixture activation: {error}"))?;
    let socket = TestSocket::new()?;
    let listener = UnixListener::bind(&socket.path)?;
    let server_descriptor = descriptor.clone();
    let server_invalidated = invalidated.clone();
    let server_activated = activated.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = accept_hello(&listener).await?;
        let BackendRequest::SubscribeJobs { id, .. } = read_request(&mut stream).await? else {
            return TestResult::Err("expected subscribe jobs".into());
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
        for event in [server_invalidated, server_activated] {
            write_message(
                &mut stream,
                &BackendMessage::Event {
                    version: BACKEND_PROTOCOL_VERSION,
                    event,
                },
            )
            .await?;
        }
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
            return TestResult::Err("expected recovered submit share".into());
        };
        let parent_hash_le =
            canonical_parent_header_hash_le(&server_descriptor.header_input, &nonce, &solution);
        let mut winners = Vec::new();
        if mask & 1 != 0 {
            winners.push(winner(MergedChain::Wcash, 0x73));
        }
        if mask & 2 != 0 {
            let mut zcash = winner(MergedChain::Zcash, 0x72);
            zcash.block_hash_le = parent_hash_le.clone();
            zcash.coinbase_txid_le = server_descriptor.zcash_coinbase_txid_le.clone();
            winners.push(zcash);
        }
        let receipt = ShareReceipt {
            event_seq: if historical_replay { 10 } else { 13 },
            share_id: canonical_share_id(&job_id, &time, &nonce, &solution),
            attribution_id: canonical_attribution_id(&identity, &target_le)?,
            job_id,
            parent_hash_le,
            winners,
        };
        // Every role is protocol-valid and job-bound; only recovery context
        // distinguishes the permitted Zcash-only receipt from ordinary/mixed work.
        receipt.validate_for_job(&server_descriptor)?;
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
    let timeline = MonotonicTimeline::new();
    let mut client = connect_client_at(&socket, 10).await?;
    let snapshot = client.subscribe_jobs(10).await?;
    let mut registry = GenerationRegistry::new(GenerationRegistryConfig::new(2, 16)?);
    snapshot.apply_to_registry(&mut registry, timeline)?;
    let generation = registry
        .current_generation(timeline.now_ms()?)?
        .ok_or("missing generation")?
        .clone();
    let bounds = TargetBounds::new(
        generation.wcash_network_target(),
        generation.zcash_network_target(),
        ShareTarget::MAX,
    )?;
    let assignment = JobAssignment::new(
        &generation,
        TargetBinding::new(1, ShareTarget::MAX, bounds)?,
    )?;
    let lease = NonceNamespaceLease::new(0x30)?;
    let allocator = NoncePrefixAllocator::restore(
        wcash_pool_core::NonceCursor::new(NonceProfile::FourByte, lease, 0x00a3_ed00)?,
        lease,
    )?;
    let mut session = wcash_pool_core::MiningSession::new(uuid(4).get(), 2)?;
    let _ = session.subscribe(&allocator)?;
    session.complete_authorization(AuthenticatedWorker::new(
        uuid(7).get(),
        uuid(8).get(),
        "account.worker",
    )?)?;
    session.announce_job(assignment)?;
    let at = timeline.now_ms()?;
    registry.apply_event(&invalidated, at)?;
    registry.apply_event(&activated, at)?;
    session.retire_announced_job(generation.id());
    let context = session.prepare_submission(
        "account.worker",
        generation.id(),
        generation.header_time(),
        NonceSuffix::TwentyEight(Hex28::new(header[112..140].try_into()?)),
        Box::new(Hex1344::new(header[143..1487].try_into()?)),
        &mut registry,
        timeline.now_ms()?,
    )?;
    assert!(context.is_winner_recovery());
    // A historical acknowledgement models a receipt already committed during
    // ordinary admission whose acknowledgement was lost. It must survive the
    // late retry byte-for-byte, including any original Wcash winner.
    let mut original_winners = Vec::new();
    if mask & 1 != 0 {
        original_winners.push(winner(MergedChain::Wcash, 0x73));
    }
    let original_parent = canonical_parent_header_hash_le(
        &descriptor.header_input,
        context.nonce(),
        context.solution(),
    );
    if mask & 2 != 0 {
        let mut zcash = winner(MergedChain::Zcash, 0x72);
        zcash.block_hash_le = original_parent.clone();
        zcash.coinbase_txid_le = descriptor.zcash_coinbase_txid_le.clone();
        original_winners.push(zcash);
    }
    let original_receipt = ShareReceipt {
        event_seq: if historical_replay { 10 } else { 13 },
        job_id: context.job_id(),
        share_id: canonical_share_id(
            &context.job_id(),
            context.time(),
            context.nonce(),
            context.solution(),
        ),
        attribution_id: canonical_attribution_id(context.identity(), context.target_le())?,
        parent_hash_le: original_parent,
        winners: original_winners,
    };
    let allowed = mask == 2 || (historical_replay && mask == 3);
    match client.submit_prepared_share(context).await {
        Ok(commit) if allowed => {
            assert_eq!(commit.receipt(), &original_receipt);
            assert!(commit
                .receipt()
                .winners
                .iter()
                .any(|winner| winner.chain == MergedChain::Zcash));
        }
        Err(ClientError::HistoricalReplayRequiresProjection { receipt })
            if allowed && historical_replay =>
        {
            assert_eq!(*receipt, original_receipt);
            assert_eq!(receipt.winners.len(), if mask == 3 { 2 } else { 1 });
            assert!(receipt
                .winners
                .iter()
                .any(|winner| winner.chain == MergedChain::Zcash));
        }
        Err(ClientError::Protocol(ProtocolError::InvalidField { field, .. })) if !allowed => {
            assert_eq!(field, "share_receipt.winners");
            assert!(matches!(
                client.health().await,
                Err(ClientError::ConnectionUnusable)
            ));
        }
        other => return Err(format!("recovery role {mask} returned {other:?}").into()),
    }
    server.await??;
    Ok(())
}

#[tokio::test]
async fn recovered_context_requires_zcash_and_preserves_original_dual_chain_replay() -> TestResult {
    for historical_replay in [false, true] {
        for mask in [0, 1, 3, 2] {
            if let Err(error) = assert_recovered_receipt_role(mask, historical_replay).await {
                return Err(format!(
                    "receipt role mask={mask}, historical_replay={historical_replay}: {error}"
                )
                .into());
            }
        }
    }
    Ok(())
}

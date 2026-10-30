use super::*;
use wcash_pool_protocol::{
    decode_backend_request, encode_backend_request, BackendRequest, BACKEND_PROTOCOL_VERSION,
};

fn fixture_header() -> Vec<u8> {
    let encoded = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wcash-pool-core/tests/vectors/zcash-mainnet-1687118-header.hex"
    ))
    .trim();
    (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("fixture hex"))
        .collect()
}

fn fixture_suffix() -> NonceSuffix {
    NonceSuffix::TwentyEight(Hex28::new(
        fixture_header()[112..140]
            .try_into()
            .expect("fixture nonce suffix"),
    ))
}

fn fixture_solution() -> Hex1344 {
    Hex1344::new(
        fixture_header()[143..1487]
            .try_into()
            .expect("fixture solution"),
    )
}

fn rotated_actor() -> (ConnectionActor, BackendGeneration, TargetBinding, Hex32) {
    let mut first = descriptor(1);
    let encoded = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wcash-pool-core/tests/vectors/zcash-mainnet-1687118-header.hex"
    ))
    .trim();
    let header: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("fixture hex"))
        .collect();
    first.header_input = Hex108::new(header[..108].try_into().expect("header"));
    first.zcash_previous_hash_le = Hex32::new(header[4..36].try_into().expect("parent"));
    let mut network_target = [0_u8; 32];
    network_target[25..28].copy_from_slice(&[0xf0, 0xda, 0x01]);
    first.zcash_target_le = TargetLe::new(network_target);
    let router = JobRouter::from_acceptable_for_test(
        1,
        Some(&AcceptableJob {
            job: first.clone(),
            accept_for_ms: 30_000,
        }),
        &[],
        GenerationRegistryConfig::new(2, 64).expect("bounded registry"),
        8,
    )
    .expect("initial job snapshot");
    let mut actor = actor_with_router(16, router);
    // Restore the historical header's exact prefix: 30 00 ed a3.
    let lease = NonceNamespaceLease::new(0x30).expect("fixture namespace");
    let cursor = wcash_pool_core::NonceCursor::new(NonceProfile::FourByte, lease, 0x00a3_ed00)
        .expect("fixture cursor");
    actor.nonce_allocator =
        Arc::new(NoncePrefixAllocator::restore(cursor, lease).expect("fixture allocator"));
    authorize(&mut actor);
    while actor.pop_outbound().is_some() {}
    let old = BackendGeneration::from_descriptor(first.clone()).expect("old generation");
    let target = *actor.assignments.get(&old.id()).expect("original target");
    let original = actor
        .router
        .prepare_submission(
            &actor.session,
            "account.rig",
            old.id(),
            old.header_time(),
            fixture_suffix(),
            Box::new(fixture_solution()),
        )
        .expect("ordinary admission before rollover");
    assert!(!original.is_winner_recovery());
    let nonce = original.nonce().clone();
    drop(original);
    let at = actor.router.now_ms_for_test().expect("monotonic clock");
    actor
        .router
        .apply_event_for_test(
            &BackendEvent::JobInvalidated {
                event_seq: 2,
                job_id: first.job_id.clone(),
                reason: wcash_pool_protocol::JobInvalidationReason::Superseded,
                accept_for_ms: 1,
            },
            at,
        )
        .expect("short ordinary grace");
    let mut second = first;
    second.job_id = Hex32::new([2; 32]);
    second.wcash_previous_hash_le = Hex32::new([0x71; 32]);
    second.wcash_candidate_hash_le = Hex32::new([0x72; 32]);
    actor
        .router
        .apply_event_for_test(
            &BackendEvent::JobActivated {
                event_seq: 3,
                job: second.clone(),
            },
            at,
        )
        .expect("new Wcash job on unchanged Zcash parent");
    actor
        .apply_job_update(JobUpdate::Activated {
            generation: Box::new(
                BackendGeneration::from_descriptor(second).expect("new generation"),
            ),
            clean_jobs: true,
        })
        .expect("miner receives replacement");
    std::thread::sleep(Duration::from_millis(5));
    actor
        .reconcile_jobs()
        .expect("expired ordinary assignments reconciled");
    assert!(!actor.assignments.contains_key(&old.id()));
    (actor, old, target, nonce)
}

#[test]
fn expired_announced_winner_reaches_the_existing_backend_wire_request() {
    let (mut actor, old, target, nonce) = rotated_actor();
    let now = actor.router.now_ms_for_test().expect("clock");
    let action = actor
        .handle_request(
            Zip301Request::Submit {
                id: Zip301Id::Number(20),
                worker: "account.rig".to_owned(),
                job_id: old.id().to_protocol(),
                time: old.header_time(),
                nonce_2: fixture_suffix(),
                solution: Box::new(fixture_solution()),
            },
            now,
        )
        .expect("late submission is handled")
        .expect("backend work ticket exists");
    let pending = match action {
        ConnectionAction::Submit(pending) => Some(pending),
        _ => None,
    }
    .expect("must forward submission");
    let (ticket, context) = pending.into_parts();
    assert!(context.is_winner_recovery());
    assert_eq!(
        actor.session.announced_target_binding(old.id()),
        Some(target)
    );
    assert_eq!(actor.pending_shares[&ticket.ticket].target, target);
    assert_eq!(context.target_le(), &target.target().to_backend());
    assert_eq!(context.nonce(), &nonce);
    assert!(actor.pending_shares[&ticket.ticket].winner_recovery);
    let request = BackendRequest::SubmitShare {
        version: BACKEND_PROTOCOL_VERSION,
        id: 1,
        job_id: context.job_id(),
        identity: context.identity().clone(),
        target_le: context.target_le().clone(),
        time: context.time().clone(),
        nonce: context.nonce().clone(),
        solution: Box::new(context.solution().clone()),
    };
    assert_eq!(
        decode_backend_request(&encode_backend_request(&request).expect("existing wire encoding"))
            .expect("existing wire decoding"),
        request
    );
}

#[test]
fn final_backend_closure_and_unannounced_jobs_do_not_forward() {
    let (mut actor, old, _, _) = rotated_actor();
    let at = actor.router.now_ms_for_test().expect("clock");
    actor
        .router
        .apply_event_for_test(
            &BackendEvent::GenerationClosed {
                event_seq: 4,
                job_id: old.id().to_protocol(),
            },
            at,
        )
        .expect("final backend closure");
    actor
        .apply_job_update(JobUpdate::Retired { job_id: old.id() })
        .expect("retirement reaches miner actor");
    while actor.pop_outbound().is_some() {}
    for job_id in [old.id().to_protocol(), Hex32::new([0x99; 32])] {
        assert!(actor
            .handle_request(
                Zip301Request::Submit {
                    id: Zip301Id::Number(21),
                    worker: "account.rig".to_owned(),
                    job_id,
                    time: old.header_time(),
                    nonce_2: fixture_suffix(),
                    solution: Box::new(fixture_solution()),
                },
                at
            )
            .expect("stale response")
            .is_none());
    }
    assert!(actor.pending_shares.is_empty());
}

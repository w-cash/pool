use super::*;
use wcash_pool_protocol::{BackendEvent, JobInvalidationReason};

fn fixture() -> (
    MiningSession,
    GenerationRegistry,
    BackendGeneration,
    TargetBinding,
) {
    let mut first = descriptor(1);
    first.max_age_ms = 45_000;
    // This is a policy forwarding fixture, not an Equihash-valid block.
    first.zcash_target_le = TargetLe::new([0xff; 32]);
    let generation = BackendGeneration::from_descriptor(first.clone()).expect("old generation");
    let assigned = assignment(&generation, 7, true);
    let target = assigned.target_binding();
    let mut session = authorized_session(1, NonceProfile::FourByte, 7, "account.rig", 1);
    session.announce_job(assigned).expect("old job announced");
    let mut registry =
        GenerationRegistry::new(GenerationRegistryConfig::new(2, 64).expect("bounded registry"));
    registry
        .apply_snapshot(
            1,
            Some(&AcceptableJob {
                job: first.clone(),
                accept_for_ms: 45_000,
            }),
            &[],
            0,
        )
        .expect("initial snapshot");
    registry
        .apply_event(
            &BackendEvent::JobInvalidated {
                event_seq: 2,
                job_id: first.job_id.clone(),
                reason: JobInvalidationReason::Superseded,
                accept_for_ms: 2_000,
            },
            30_000,
        )
        .expect("ordinary grace");
    let mut second = first;
    second.job_id = Hex32::new([2; 32]);
    second.wcash_previous_hash_le = Hex32::new([0x77; 32]);
    second.wcash_candidate_hash_le = Hex32::new([0x78; 32]);
    registry
        .apply_event(
            &BackendEvent::JobActivated {
                event_seq: 3,
                job: second,
            },
            30_000,
        )
        .expect("same Zcash parent on new Wcash height");
    session.retire_announced_job(generation.id());
    let current = registry
        .current_generation(32_001)
        .expect("current query")
        .expect("current job")
        .clone();
    session
        .announce_job(assignment(&current, 8, true))
        .expect("recovery does not occupy ordinary slot");
    (session, registry, generation, target)
}

#[test]
fn retired_assignment_preserves_original_binding_and_nonce_after_45_seconds() {
    let (session, mut registry, generation, target) = fixture();
    let context = session
        .prepare_submission(
            "account.rig",
            generation.id(),
            generation.header_time(),
            NonceSuffix::TwentyEight(Hex28::new([0xa5; 28])),
            Box::new(Hex1344::new([0x5a; 1344])),
            &mut registry,
            45_001,
        )
        .expect("potential late Zcash winner is forwarded");
    assert!(context.is_winner_recovery());
    assert_eq!(
        session.announced_target_binding(generation.id()),
        Some(target)
    );
    assert_eq!(context.target_le(), &target.target().to_backend());
    assert_eq!(
        context.identity(),
        &session
            .worker
            .as_ref()
            .expect("authorized worker")
            .backend_identity()
    );
    assert_eq!(context.generation(), &generation);
    assert_eq!(
        &context.nonce().as_bytes()[..4],
        session
            .nonce_prefix
            .as_ref()
            .expect("subscribed prefix")
            .as_bytes()
    );
    assert_eq!(&context.nonce().as_bytes()[4..], &[0xa5; 28]);
}

#[test]
fn recovery_does_not_relax_login_time_profile_or_announcement_checks() {
    for variant in 0..4 {
        let (session, mut registry, generation, _) = fixture();
        let login = if variant == 0 {
            "another.rig"
        } else {
            "account.rig"
        };
        let time = if variant == 1 {
            Hex4::new([0xff; 4])
        } else {
            generation.header_time()
        };
        let suffix = if variant == 2 {
            NonceSuffix::TwentyFour(wcash_pool_protocol::Hex24::new([0xa5; 24]))
        } else {
            NonceSuffix::TwentyEight(Hex28::new([0xa5; 28]))
        };
        let job_id = if variant == 3 {
            JobId::new([0x99; 32]).expect("nonzero ID")
        } else {
            generation.id()
        };
        let result = session.prepare_submission(
            login,
            job_id,
            time,
            suffix,
            Box::new(Hex1344::new([0x5a; 1344])),
            &mut registry,
            45_001,
        );
        assert!(result.is_err(), "crossed field {variant} must fail closed");
    }
}

#[test]
fn reannouncement_cannot_change_the_retired_target_binding() {
    let (mut session, _, generation, target) = fixture();
    let same = JobAssignment::new(&generation, target).expect("same assignment");
    session
        .announce_job(same)
        .expect("exact retry is idempotent");
    let changed = JobAssignment::new(
        &generation,
        TargetBinding::new(target.revision() + 1, target.target(), target.bounds())
            .expect("another revision"),
    )
    .expect("well formed changed assignment");
    assert!(matches!(
        session.announce_job(changed),
        Err(SessionError::AnnouncedJobConflict(_))
    ));
    assert_eq!(session.announced_jobs.len(), 1);
}

#[test]
fn recovery_assignments_are_bounded_and_never_use_ordinary_capacity() {
    let mut session = authorized_session(1, NonceProfile::FourByte, 7, "account.rig", 1);
    for value in 1..=40 {
        let generation = generation(value);
        session
            .announce_job(assignment(&generation, 1, true))
            .expect("ordinary slot remains free");
        session.retire_announced_job(generation.id());
    }
    assert!(session.announced_jobs.is_empty());
    assert_eq!(
        session.winner_recovery_jobs.len(),
        MAX_ZCASH_WINNER_RECOVERY_JOBS
    );
    assert!(!session
        .winner_recovery_jobs
        .iter()
        .any(|job| job.generation_id() == generation(1).id()));
    session.retain_winner_recovery_jobs(&[]);
    assert!(session.winner_recovery_jobs.is_empty());
}

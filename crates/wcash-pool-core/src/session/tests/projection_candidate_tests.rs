use super::*;
use wcash_pool_protocol::{canonical_parent_header_hash_le, BackendEvent, JobInvalidationReason};

#[test]
fn projection_candidate_uses_either_network_target_and_keeps_ordinary_authority() {
    for (zcash_winner, wcash_winner) in [(true, false), (false, true), (false, false)] {
        let mut session = authorized_session(1, NonceProfile::FourByte, 7, "account.rig", 1);
        let suffix = NonceSuffix::TwentyEight(Hex28::new([0xa5; 28]));
        let solution = Box::new(Hex1344::new([0x5a; 1344]));
        let nonce = join_nonce(
            session.nonce_prefix.as_ref().expect("session prefix"),
            &suffix,
        )
        .expect("matching nonce widths");
        let mut job = descriptor(1);
        // A non-symmetric exact boundary exercises inclusive little-endian
        // target comparison. Wolf independently verifies actual Equihash work.
        let hash = canonical_parent_header_hash_le(&job.header_input, &nonce, &solution);
        assert_ne!(hash.as_bytes()[0], hash.as_bytes()[31]);
        let mut minimum = [0; 32];
        minimum[0] = 1;
        assert!(hash.as_bytes()[1..].iter().any(|&byte| byte != 0));
        job.zcash_target_le = TargetLe::new(if zcash_winner {
            *hash.as_bytes()
        } else {
            minimum
        });
        job.wcash_target_le = TargetLe::new(if wcash_winner {
            *hash.as_bytes()
        } else {
            minimum
        });

        let generation = BackendGeneration::from_descriptor(job.clone()).expect("valid generation");
        let announced = assignment(&generation, 7, true);
        let target = announced.target_binding();
        session.announce_job(announced).expect("job announced");
        let mut registry = registry_for(job.clone());
        let candidate = session.prepare_projection_candidate(
            "account.rig",
            generation.id(),
            generation.header_time(),
            suffix,
            solution,
            &mut registry,
            1,
            42,
        );
        if zcash_winner || wcash_winner {
            let context = candidate.expect("network candidate");
            assert!(context.is_projection_candidate());
            assert!(!context.is_winner_recovery());
            assert_eq!(context.projection_episode(), Some(42));
            assert_eq!(context.target_le(), &target.target().to_backend());
            assert_eq!(context.nonce(), &nonce);
            assert_eq!(context.generation(), &generation);
            assert!(context
                .projection_candidate_is_current(&mut registry, 8_999)
                .expect("before ordinary deadline"));
            assert!(!context
                .projection_candidate_is_current(&mut registry_for(job), 8_999)
                .expect("identical descriptor in another registry"));
            assert!(!context
                .projection_candidate_is_current(&mut registry, 9_000)
                .expect("at ordinary deadline"));
            assert!(matches!(
                context.refilter_zcash_candidate(&mut registry, 9_001, false),
                Err(SessionError::Registry(JobRegistryError::StaleJob(_)))
            ));
        } else {
            assert!(matches!(
                candidate,
                Err(SessionError::Registry(JobRegistryError::StaleJob(_)))
            ));
        }
    }
}

#[test]
fn projection_candidate_requires_authenticated_current_announcement() {
    let mut job = descriptor(1);
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    let generation = BackendGeneration::from_descriptor(job.clone()).expect("valid generation");
    let mut registry = registry_for(job.clone());
    let mut session = authorized_session(1, NonceProfile::FourByte, 7, "account.rig", 1);
    let submit = |session: &MiningSession, registry: &mut GenerationRegistry, login, time| {
        session.prepare_projection_candidate(
            login,
            generation.id(),
            time,
            NonceSuffix::TwentyEight(Hex28::new([0xa5; 28])),
            Box::new(Hex1344::new([0x5a; 1344])),
            registry,
            2,
            42,
        )
    };
    session
        .announce_job(assignment(&generation, 7, true))
        .expect("job announced");
    assert!(matches!(
        submit(
            &session,
            &mut registry,
            "other.rig",
            generation.header_time()
        ),
        Err(SessionError::LoginMismatch)
    ));
    assert!(matches!(
        submit(&session, &mut registry, "account.rig", Hex4::new([0; 4])),
        Err(SessionError::HeaderTimeMismatch(_))
    ));
    registry
        .apply_event(
            &BackendEvent::JobInvalidated {
                event_seq: 2,
                job_id: job.job_id,
                reason: JobInvalidationReason::Superseded,
                accept_for_ms: 1_000,
            },
            2,
        )
        .expect("old job keeps ordinary grace");
    assert!(registry.begin_admission(generation.id(), 2).is_ok());
    assert!(matches!(
        submit(
            &session,
            &mut registry,
            "account.rig",
            generation.header_time()
        ),
        Err(SessionError::Registry(JobRegistryError::StaleJob(_)))
    ));
    session.retire_announced_job(generation.id());
    assert!(matches!(
        submit(
            &session,
            &mut registry,
            "account.rig",
            generation.header_time()
        ),
        Err(SessionError::JobNotAnnounced(_))
    ));
}

fn registry_for(job: wcash_pool_protocol::JobDescriptor) -> GenerationRegistry {
    let mut registry = GenerationRegistry::new(
        GenerationRegistryConfig::new(2, 8).expect("fixture limits are valid"),
    );
    registry
        .apply_snapshot(
            1,
            Some(&AcceptableJob {
                job,
                accept_for_ms: 9_000,
            }),
            &[],
            0,
        )
        .expect("fixture snapshot is valid");
    registry
}

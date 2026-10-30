use super::*;

fn recovery_job(value: u8) -> JobDescriptor {
    let mut job = descriptor(value, 45_000);
    job.zcash_previous_hash_le = Hex32::new([0x42; 32]);
    let mut header = *job.header_input.as_bytes();
    header[4..36].copy_from_slice(job.zcash_previous_hash_le.as_bytes());
    job.header_input = Hex108::new(header);
    // A deliberately easy target exercises forwarding, not real network work.
    job.zcash_target_le = TargetLe::new([0xff; 32]);
    job
}

fn recovery_registry() -> GenerationRegistry {
    let mut registry =
        GenerationRegistry::new(GenerationRegistryConfig::new(2, 128).expect("bounded registry"));
    registry
        .apply_snapshot(
            1,
            Some(&AcceptableJob {
                job: recovery_job(1),
                accept_for_ms: 45_000,
            }),
            &[],
            0,
        )
        .expect("initial snapshot");
    registry
}

fn replace(registry: &mut GenerationRegistry, old: u8, new: u8, first_seq: u64, at_ms: u64) {
    registry
        .apply_event(
            &BackendEvent::JobInvalidated {
                event_seq: first_seq,
                job_id: id(old).to_protocol(),
                reason: JobInvalidationReason::Superseded,
                accept_for_ms: 2_000,
            },
            at_ms,
        )
        .expect("ordinary grace");
    registry
        .apply_event(
            &BackendEvent::JobActivated {
                event_seq: first_seq + 1,
                job: recovery_job(new),
            },
            at_ms,
        )
        .expect("new current generation");
}

fn recover(
    registry: &mut GenerationRegistry,
    value: u8,
    at_ms: u64,
) -> Result<GenerationAdmission, JobRegistryError> {
    registry.begin_zcash_winner_recovery(
        id(value),
        &Hex32::new([0xa5; 32]),
        &Hex1344::new([0x5a; 1344]),
        at_ms,
    )
}

#[test]
fn winner_after_grace_and_original_age_has_a_fixed_tail() {
    let mut registry = recovery_registry();
    replace(&mut registry, 1, 2, 2, 30_000);
    assert!(matches!(
        registry.begin_admission(id(1), 32_001),
        Err(JobRegistryError::StaleJob(_))
    ));
    assert!(recover(&mut registry, 1, 32_001)
        .expect("potential winner after grace")
        .is_winner_recovery());
    assert!(recover(&mut registry, 1, 45_001).is_ok());

    // Replacing current work does not restart the old generation's tail.
    replace(&mut registry, 2, 3, 4, 60_000);
    replace(&mut registry, 3, 4, 6, 90_000);
    assert!(recover(&mut registry, 1, 104_999).is_ok());
    assert!(matches!(
        recover(&mut registry, 1, 105_000),
        Err(JobRegistryError::StaleJob(_))
    ));
}

#[test]
fn short_snapshot_grace_does_not_reset_or_shorten_original_tail() {
    let mut registry = recovery_registry();
    replace(&mut registry, 1, 2, 2, 30_000);
    registry
        .apply_snapshot(
            3,
            Some(&AcceptableJob {
                job: recovery_job(2),
                accept_for_ms: 44_000,
            }),
            &[AcceptableJob {
                job: recovery_job(1),
                accept_for_ms: 1_000,
            }],
            31_000,
        )
        .expect("same exact jobs at a later snapshot");
    assert_eq!(registry.entries[&id(1)].winner_recovery_until_ms, 105_000);
    assert!(recover(&mut registry, 1, 70_000).is_ok());
}

#[test]
fn high_hash_ordinary_work_is_not_forwarded_after_expiry() {
    let mut registry = recovery_registry();
    let old = registry.entries.get_mut(&id(1)).expect("known job");
    let mut descriptor = old.storage.generation().descriptor().clone();
    descriptor.zcash_target_le = TargetLe::new({
        let mut target = [0; 32];
        target[0] = 1;
        target
    });
    old.storage = GenerationStorage::Live(Arc::new(GenerationResource::new(
        BackendGeneration::from_descriptor(descriptor).expect("valid hard target"),
    )));
    replace(&mut registry, 1, 2, 2, 30_000);
    assert!(matches!(
        recover(&mut registry, 1, 32_001),
        Err(JobRegistryError::StaleJob(_))
    ));
}

#[test]
fn closure_zcash_invalidation_and_suspension_revoke_recovery() {
    for close in [true, false] {
        let mut registry = recovery_registry();
        replace(&mut registry, 1, 2, 2, 30_000);
        let event = if close {
            BackendEvent::GenerationClosed {
                event_seq: 4,
                job_id: id(1).to_protocol(),
            }
        } else {
            BackendEvent::JobInvalidated {
                event_seq: 4,
                job_id: id(1).to_protocol(),
                reason: JobInvalidationReason::ZcashTipChanged,
                accept_for_ms: 0,
            }
        };
        registry.apply_event(&event, 31_000).expect("revocation");
        assert!(matches!(
            recover(&mut registry, 1, 32_001),
            Err(JobRegistryError::StaleJob(_))
        ));
    }
    let mut registry = recovery_registry();
    replace(&mut registry, 1, 2, 2, 30_000);
    registry.suspend();
    assert!(matches!(
        recover(&mut registry, 1, 32_001),
        Err(JobRegistryError::NotSynchronized)
    ));
    registry
        .apply_snapshot(
            3,
            Some(&AcceptableJob {
                job: recovery_job(2),
                accept_for_ms: 12_999,
            }),
            &[],
            32_001,
        )
        .expect("authenticated stream recovery");
    assert!(matches!(
        recover(&mut registry, 1, 32_002),
        Err(JobRegistryError::StaleJob(_))
    ));
}

#[test]
fn a_live_matching_zcash_parent_is_required() {
    let mut registry = recovery_registry();
    replace(&mut registry, 1, 2, 2, 30_000);
    let current = registry.entries.get_mut(&id(2)).expect("current entry");
    let mut changed = current.storage.generation().descriptor().clone();
    changed.zcash_previous_hash_le = Hex32::new([0x43; 32]);
    let mut header = *changed.header_input.as_bytes();
    header[4..36].copy_from_slice(changed.zcash_previous_hash_le.as_bytes());
    changed.header_input = Hex108::new(header);
    current.storage = GenerationStorage::Live(Arc::new(GenerationResource::new(
        BackendGeneration::from_descriptor(changed).expect("other parent"),
    )));
    assert!(matches!(
        recover(&mut registry, 1, 32_001),
        Err(JobRegistryError::StaleJob(_))
    ));
    registry.current = None;
    assert!(matches!(
        recover(&mut registry, 2, 32_002),
        Err(JobRegistryError::StaleJob(_))
    ));
}

#[test]
fn recovery_history_is_bounded_without_changing_ordinary_capacity() {
    let mut registry = recovery_registry();
    let mut seq = 2;
    for value in 2..=40 {
        // Zero grace retires ordinary admission immediately, while preserving
        // only the bounded winner filter on the unchanged Zcash parent.
        registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: seq,
                    job_id: id(value - 1).to_protocol(),
                    reason: JobInvalidationReason::Age,
                    accept_for_ms: 0,
                },
                u64::from(value),
            )
            .expect("ordinary job invalidates");
        registry
            .apply_event(
                &BackendEvent::JobActivated {
                    event_seq: seq + 1,
                    job: recovery_job(value),
                },
                u64::from(value),
            )
            .expect("replacement does not exhaust grace capacity");
        seq += 2;
    }
    assert_eq!(
        registry.winner_recovery.len(),
        MAX_ZCASH_WINNER_RECOVERY_JOBS
    );
    assert!(recover(&mut registry, 1, 41).is_err());
    assert!(registry.begin_admission(id(40), 41).is_ok());
}

// Historical mainnet PoW header from Wolf's zebra-test block-main-1-687-118.txt.
// This tests a real compact target and canonical hash, not Equihash consensus.
#[test]
fn historical_network_winner_uses_canonical_little_endian_inclusive_target() {
    let encoded = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/zcash-mainnet-1687118-header.hex"
    ))
    .trim();
    let header: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("fixture hex"))
        .collect();
    let nonce = Hex32::new(header[108..140].try_into().expect("nonce"));
    let solution = Hex1344::new(header[143..1487].try_into().expect("solution"));
    let mut old = recovery_job(1);
    old.header_input = Hex108::new(header[..108].try_into().expect("header input"));
    old.zcash_previous_hash_le = Hex32::new(header[4..36].try_into().expect("parent"));
    assert_eq!(&header[104..108], &[0xf0, 0xda, 0x01, 0x1c]);
    let mut target = [0_u8; 32];
    target[25..28].copy_from_slice(&[0xf0, 0xda, 0x01]);
    old.zcash_target_le = TargetLe::new(target);
    let hash = canonical_parent_header_hash_le(&old.header_input, &nonce, &solution);
    assert_eq!(
        hash.to_string(),
        "99619c6db872fbf6c8e5aafadef11f5734ec30ce8905ade50c80160100000000"
    );
    for (target, accepted) in [
        (target, true),
        (*hash.as_bytes(), true),
        (
            {
                let mut below = *hash.as_bytes();
                below[0] -= 1;
                below
            },
            false,
        ),
    ] {
        let mut registry = recovery_registry();
        let mut candidate = old.clone();
        candidate.zcash_target_le = TargetLe::new(target);
        registry.entries.get_mut(&id(1)).expect("known job").storage =
            GenerationStorage::Live(Arc::new(GenerationResource::new(
                BackendGeneration::from_descriptor(candidate.clone()).expect("fixture generation"),
            )));
        let mut current = candidate;
        current.job_id = id(2).to_protocol();
        registry
            .apply_event(
                &BackendEvent::JobInvalidated {
                    event_seq: 2,
                    job_id: id(1).to_protocol(),
                    reason: JobInvalidationReason::Superseded,
                    accept_for_ms: 2_000,
                },
                30_000,
            )
            .expect("superseded");
        registry
            .apply_event(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: current,
                },
                30_000,
            )
            .expect("same parent replacement");
        assert_eq!(
            registry
                .begin_zcash_winner_recovery(id(1), &nonce, &solution, 45_001)
                .is_ok(),
            accepted
        );
    }
}

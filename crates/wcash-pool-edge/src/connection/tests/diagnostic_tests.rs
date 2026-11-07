use super::*;

fn request(job: [u8; 32], worker: &str) -> Zip301Request {
    Zip301Request::Submit {
        id: Zip301Id::Number(100),
        worker: worker.to_owned(),
        job_id: Hex32::new(job),
        time: Hex4::new([1, 2, 3, 1]),
        nonce_2: NonceSuffix::TwentyEight(Hex28::new([0; 28])),
        solution: Box::new(Hex1344::new([0; 1344])),
    }
}

#[test]
fn diagnostics_local_rejection_never_claims_backend_validation() {
    for (job, login, category) in [
        ([0; 32], "account.rig", Diagnostic::AdmissionInvalidJob),
        ([1; 32], "other.rig", Diagnostic::AdmissionLoginMismatch),
        (
            [0x99; 32],
            "account.rig",
            Diagnostic::AdmissionJobNotAnnounced,
        ),
    ] {
        let telemetry = Arc::new(RecordingTelemetry::default());
        let mut actor = actor_with_telemetry(16, router(), telemetry.clone());
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        assert!(actor
            .handle_request(request(job, login), 2)
            .expect("actor handles local rejection")
            .is_none());
        assert_eq!(
            *telemetry.1.lock().expect("diagnostics"),
            vec![Diagnostic::SubmitObserved, category]
        );
        assert!(actor.pending_shares.is_empty());
        assert!(!telemetry
            .0
            .lock()
            .expect("outcomes")
            .contains(&TelemetryEvent::Share(ShareOutcome::Accepted)));
    }
}

#[test]
fn diagnostics_service_failures_are_terminal_observations_not_invalid_proofs() {
    use wcash_pool_protocol::BackendErrorCode as B;
    for (failure, category, closes) in [
        (
            ShareRouterError::Overloaded,
            Diagnostic::SubmissionQueueFull,
            false,
        ),
        (
            ShareRouterError::Unavailable,
            Diagnostic::SubmissionUnavailable,
            true,
        ),
        (
            ShareRouterError::EventConsumerUnusable,
            Diagnostic::SubmissionProjectionUnavailable,
            true,
        ),
        (
            ShareRouterError::Rejected(B::RecoveryDeferred),
            Diagnostic::SubmissionRecoveryDeferred,
            false,
        ),
        (
            ShareRouterError::Rejected(B::Overloaded),
            Diagnostic::SubmissionBackendBusy,
            true,
        ),
        (
            ShareRouterError::Rejected(B::BackendUnhealthy),
            Diagnostic::SubmissionBackendUnhealthy,
            true,
        ),
    ] {
        let telemetry = Arc::new(RecordingTelemetry::default());
        let mut actor = actor_with_telemetry(16, router(), telemetry.clone());
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        let response_id = actor
            .store_response_id(Zip301Id::Number(11))
            .expect("response slot");
        actor.pending_shares.insert(
            50,
            PendingShareState {
                response_id: Some(response_id),
                target: actor.binding().expect("target"),
                admitted_at_ms: 3,
                vardiff_sample: None,
                winner_recovery: false,
                expected_job_id: [1; 32],
                expected_share_id: [2; 32],
                expected_attribution_id: [3; 32],
            },
        );
        let session_id = actor.session.id();
        actor
            .complete_submission(
                ShareTicket {
                    session_id,
                    ticket: 50,
                },
                Err(failure),
            )
            .expect("response");
        assert_eq!(actor.is_closed(), closes);
        assert_eq!(*telemetry.1.lock().expect("diagnostics"), vec![category]);
        assert!(!telemetry
            .0
            .lock()
            .expect("outcomes")
            .iter()
            .any(|e| matches!(e, TelemetryEvent::Share(_))));
        // A duplicated completion fails closed and cannot inflate a diagnostic.
        assert!(actor
            .complete_submission(
                ShareTicket {
                    session_id,
                    ticket: 50
                },
                Err(ShareRouterError::Unavailable)
            )
            .is_err());
        assert_eq!(telemetry.1.lock().expect("diagnostics").len(), 1);
    }
}

#[test]
fn diagnostics_registry_unavailable_is_distinct_from_stale_filter_rejection() {
    assert_eq!(
        session_diagnostic(&SessionError::Registry(
            wcash_pool_core::JobRegistryError::NotSynchronized
        )),
        Diagnostic::AdmissionRegistryUnavailable
    );
    assert_eq!(
        session_diagnostic(&SessionError::Registry(
            wcash_pool_core::JobRegistryError::StaleJob(JobId::new([1; 32]).expect("job"))
        )),
        Diagnostic::AdmissionStale
    );
}

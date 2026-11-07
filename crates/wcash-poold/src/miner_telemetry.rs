//! Account-scoped live Stratum telemetry shared with the miner portal.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_TRACKED_WORKERS: usize = 65_536;

use uuid::Uuid;
use wcash_pool_core::AuthenticatedWorker;
use wcash_pool_edge::{Diagnostic, MinerTelemetrySink, OperationalCounters, ShareOutcome};
use wcash_pool_portal::{MinerTelemetrySource, MinerTelemetrySummary, WorkerTelemetrySummary};

#[derive(Clone, Debug, Default)]
struct WorkerCounters {
    connections: u64,
    active_logins: HashMap<String, u64>,
    accepted: u64,
    stale: u64,
    invalid: u64,
    duplicate: u64,
    last_share_at: Option<u64>,
    diagnostics: BTreeMap<&'static str, u64>,
    last_activity_sequence: u64,
}

/// Process-lifetime operational counters; monetary accounting remains durable.
#[derive(Debug, Default)]
pub struct LiveMinerTelemetry {
    workers: Mutex<HashMap<(Uuid, Uuid), WorkerCounters>>,
    activity_sequence: AtomicU64,
    diagnostics: Arc<OperationalCounters>,
}

impl LiveMinerTelemetry {
    /// Shares the submission actor's process counters without adding authority.
    pub fn new(diagnostics: Arc<OperationalCounters>) -> Self {
        Self {
            diagnostics,
            ..Self::default()
        }
    }

    fn next_activity_sequence(&self) -> u64 {
        self.activity_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(1))
            })
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }

    fn tracked_worker<'a>(
        &self,
        workers: &'a mut HashMap<(Uuid, Uuid), WorkerCounters>,
        key: (Uuid, Uuid),
    ) -> Option<&'a mut WorkerCounters> {
        self.tracked_worker_with_capacity(workers, key, MAX_TRACKED_WORKERS)
    }

    fn tracked_worker_with_capacity<'a>(
        &self,
        workers: &'a mut HashMap<(Uuid, Uuid), WorkerCounters>,
        key: (Uuid, Uuid),
        maximum: usize,
    ) -> Option<&'a mut WorkerCounters> {
        if !workers.contains_key(&key) {
            if workers.len() >= maximum {
                let eviction = workers
                    .iter()
                    .filter(|(_, counters)| counters.connections == 0)
                    .min_by_key(|(_, counters)| counters.last_activity_sequence)
                    .map(|(key, _)| *key);
                if let Some(eviction) = eviction {
                    workers.remove(&eviction);
                } else {
                    return None;
                }
            }
            workers.insert(key, WorkerCounters::default());
        }
        let sequence = self.next_activity_sequence();
        let counters = workers.get_mut(&key)?;
        counters.last_activity_sequence = sequence;
        Some(counters)
    }
}

impl MinerTelemetrySink for LiveMinerTelemetry {
    fn worker_connected(&self, worker: &AuthenticatedWorker) {
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(entry) =
                self.tracked_worker(&mut workers, (worker.account_id(), worker.worker_id()))
            {
                entry.connections = entry.connections.saturating_add(1);
                let login_count = entry
                    .active_logins
                    .entry(worker.canonical_login().to_owned())
                    .or_default();
                *login_count = login_count.saturating_add(1);
            }
        }
    }

    fn worker_disconnected(&self, worker: &AuthenticatedWorker) {
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(entry) = workers.get_mut(&(worker.account_id(), worker.worker_id())) {
                entry.connections = entry.connections.saturating_sub(1);
                if let Some(login_count) = entry.active_logins.get_mut(worker.canonical_login()) {
                    *login_count = login_count.saturating_sub(1);
                    if *login_count == 0 {
                        entry.active_logins.remove(worker.canonical_login());
                    }
                }
                entry.last_activity_sequence = self.next_activity_sequence();
            }
        }
    }

    fn diagnostic(&self, worker: Option<&AuthenticatedWorker>, diagnostic: Diagnostic) {
        self.diagnostics.record(diagnostic);
        if !diagnostic.account_scoped() {
            return;
        }
        let Some(worker) = worker else {
            return;
        };
        // New diagnostics must not wait behind a portal snapshot or alter the
        // existing worker allocation/eviction policy on the admission hot path.
        let Ok(mut workers) = self.workers.try_lock() else {
            self.diagnostics
                .record(Diagnostic::AccountObservationSkipped);
            return;
        };
        let Some(entry) = workers.get_mut(&(worker.account_id(), worker.worker_id())) else {
            self.diagnostics
                .record(Diagnostic::AccountObservationSkipped);
            return;
        };
        let value = entry.diagnostics.entry(diagnostic.as_str()).or_default();
        *value = value.saturating_add(1);
    }

    fn share_outcome(&self, worker: &AuthenticatedWorker, outcome: ShareOutcome) {
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(entry) =
                self.tracked_worker(&mut workers, (worker.account_id(), worker.worker_id()))
            {
                match outcome {
                    ShareOutcome::Accepted => entry.accepted = entry.accepted.saturating_add(1),
                    ShareOutcome::Stale => entry.stale = entry.stale.saturating_add(1),
                    ShareOutcome::Invalid => entry.invalid = entry.invalid.saturating_add(1),
                    ShareOutcome::Duplicate => entry.duplicate = entry.duplicate.saturating_add(1),
                }
                entry.last_share_at = unix_now();
            }
        }
    }
}

impl MinerTelemetrySource for LiveMinerTelemetry {
    fn account_snapshot(&self, account_id: Uuid) -> MinerTelemetrySummary {
        let Ok(workers) = self.workers.lock() else {
            return MinerTelemetrySummary::default();
        };
        let mut summaries = workers
            .iter()
            .filter(|((owner, _), _)| *owner == account_id)
            .map(|((_, worker_id), counters)| {
                let mut active_logins = counters.active_logins.keys().cloned().collect::<Vec<_>>();
                active_logins.sort();
                WorkerTelemetrySummary {
                    worker_id: *worker_id,
                    connections: counters.connections,
                    active_logins,
                    accepted: counters.accepted,
                    stale: counters.stale,
                    invalid: counters.invalid,
                    duplicate: counters.duplicate,
                    last_share_at: counters.last_share_at,
                    diagnostics: counters
                        .diagnostics
                        .iter()
                        .map(|(&key, &value)| (key.to_owned(), value))
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        summaries.sort_by_key(|summary| *summary.worker_id.as_bytes());
        MinerTelemetrySummary {
            available: true,
            updated_at: unix_now(),
            process_instance_id: Some(self.diagnostics.instance_id()),
            process_started_at: self.diagnostics.started_at_unix(),
            diagnostics: sum_diagnostics(&summaries),
            active_workers: summaries
                .iter()
                .filter(|summary| summary.connections > 0)
                .count()
                .try_into()
                .unwrap_or(u64::MAX),
            accepted: saturating_sum(&summaries, |summary| summary.accepted),
            stale: saturating_sum(&summaries, |summary| summary.stale),
            invalid: saturating_sum(&summaries, |summary| summary.invalid),
            duplicate: saturating_sum(&summaries, |summary| summary.duplicate),
            workers: summaries,
        }
    }
}

fn sum_diagnostics(summaries: &[WorkerTelemetrySummary]) -> BTreeMap<String, u64> {
    let mut total = BTreeMap::<String, u64>::new();
    for summary in summaries {
        for (label, value) in &summary.diagnostics {
            let count = total.entry(label.clone()).or_default();
            *count = count.saturating_add(*value);
        }
    }
    total
}

fn saturating_sum(
    summaries: &[WorkerTelemetrySummary],
    select: impl Fn(&WorkerTelemetrySummary) -> u64,
) -> u64 {
    summaries
        .iter()
        .fold(0u64, |total, summary| total.saturating_add(select(summary)))
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcash_pool_core::SessionError;

    #[test]
    fn snapshots_are_strictly_scoped_to_one_account() -> Result<(), SessionError> {
        let telemetry = LiveMinerTelemetry::default();
        let first = AuthenticatedWorker::new(Uuid::from_u128(1), Uuid::from_u128(11), "first.rig")?;
        let second =
            AuthenticatedWorker::new(Uuid::from_u128(2), Uuid::from_u128(22), "second.rig")?;
        telemetry.worker_connected(&first);
        telemetry.share_outcome(&first, ShareOutcome::Accepted);
        telemetry.share_outcome(&second, ShareOutcome::Invalid);

        let snapshot = telemetry.account_snapshot(first.account_id());
        assert!(snapshot.available);
        assert_eq!(snapshot.active_workers, 1);
        assert_eq!(snapshot.accepted, 1);
        assert_eq!(snapshot.invalid, 0);
        assert_eq!(snapshot.workers.len(), 1);
        assert_eq!(snapshot.workers[0].worker_id, first.worker_id());
        assert_eq!(snapshot.workers[0].active_logins, ["first.rig"]);
        Ok(())
    }

    #[test]
    fn disconnect_and_outcomes_are_saturating() -> Result<(), SessionError> {
        let telemetry = LiveMinerTelemetry::default();
        let worker =
            AuthenticatedWorker::new(Uuid::from_u128(3), Uuid::from_u128(33), "miner.rig")?;
        telemetry.worker_disconnected(&worker);
        telemetry.worker_connected(&worker);
        telemetry.worker_connected(&worker);
        telemetry.worker_disconnected(&worker);
        telemetry.share_outcome(&worker, ShareOutcome::Stale);
        telemetry.share_outcome(&worker, ShareOutcome::Duplicate);

        let snapshot = telemetry.account_snapshot(worker.account_id());
        assert_eq!(snapshot.active_workers, 1);
        assert_eq!(snapshot.stale, 1);
        assert_eq!(snapshot.duplicate, 1);
        assert!(snapshot.workers[0].last_share_at.is_some());
        assert_eq!(snapshot.workers[0].active_logins, ["miner.rig"]);
        Ok(())
    }

    #[test]
    fn active_logins_follow_each_exact_connected_alias() -> Result<(), SessionError> {
        let telemetry = LiveMinerTelemetry::default();
        let canonical =
            AuthenticatedWorker::new(Uuid::from_u128(4), Uuid::from_u128(44), "miner.rig")?;
        let alias =
            AuthenticatedWorker::new(Uuid::from_u128(4), Uuid::from_u128(44), "miner.typo")?;
        telemetry.worker_connected(&canonical);
        telemetry.worker_connected(&alias);

        let snapshot = telemetry.account_snapshot(canonical.account_id());
        assert_eq!(snapshot.workers[0].connections, 2);
        assert_eq!(
            snapshot.workers[0].active_logins,
            ["miner.rig", "miner.typo"]
        );

        telemetry.worker_disconnected(&alias);
        let snapshot = telemetry.account_snapshot(canonical.account_id());
        assert_eq!(snapshot.workers[0].connections, 1);
        assert_eq!(snapshot.workers[0].active_logins, ["miner.rig"]);
        Ok(())
    }

    #[test]
    fn registry_is_bounded_and_only_prunes_disconnected_workers() -> Result<(), &'static str> {
        let telemetry = LiveMinerTelemetry::default();
        let mut workers = HashMap::new();
        let first = (Uuid::from_u128(1), Uuid::from_u128(11));
        let second = (Uuid::from_u128(2), Uuid::from_u128(22));
        let third = (Uuid::from_u128(3), Uuid::from_u128(33));
        telemetry
            .tracked_worker_with_capacity(&mut workers, first, 2)
            .ok_or("first slot unavailable")?
            .connections = 1;
        telemetry
            .tracked_worker_with_capacity(&mut workers, second, 2)
            .ok_or("second slot unavailable")?
            .connections = 0;
        telemetry
            .tracked_worker_with_capacity(&mut workers, third, 2)
            .ok_or("disconnected worker was not pruned")?
            .connections = 1;
        assert_eq!(workers.len(), 2);
        assert!(workers.contains_key(&first));
        assert!(workers.contains_key(&third));
        assert!(!workers.contains_key(&second));

        let fourth = (Uuid::from_u128(4), Uuid::from_u128(44));
        assert!(telemetry
            .tracked_worker_with_capacity(&mut workers, fourth, 2)
            .is_none());
        assert_eq!(workers.len(), 2);
        Ok(())
    }
    #[test]
    fn diagnostic_snapshots_keep_accounts_process_totals_and_crypto_claims_separate(
    ) -> Result<(), SessionError> {
        let counters = Arc::new(OperationalCounters::default());
        let telemetry = LiveMinerTelemetry::new(Arc::clone(&counters));
        let owner = AuthenticatedWorker::new(Uuid::from_u128(1), Uuid::from_u128(11), "owner.rig")?;
        let other = AuthenticatedWorker::new(Uuid::from_u128(2), Uuid::from_u128(22), "other.rig")?;
        telemetry.worker_connected(&owner);
        telemetry.worker_connected(&other);
        telemetry.diagnostic(Some(&owner), Diagnostic::RawZcashRecoveryCandidate);
        telemetry.diagnostic(Some(&owner), Diagnostic::SubmissionInvalid);
        telemetry.diagnostic(Some(&other), Diagnostic::SubmissionUnavailable);
        telemetry.diagnostic(None, Diagnostic::DriverProtocolFailure);
        // Process-only receipt categories must never enter an account snapshot,
        // even if a library observer accidentally supplies a worker here.
        telemetry.diagnostic(Some(&owner), Diagnostic::BackendZecWinnerReceipt);
        let snapshot = telemetry.account_snapshot(owner.account_id());
        assert_eq!(
            snapshot.diagnostics.get("raw_zcash_recovery_candidate"),
            Some(&1)
        );
        assert_eq!(snapshot.diagnostics.get("submission_invalid"), Some(&1));
        assert!(!snapshot.diagnostics.contains_key("submission_unavailable"));
        assert!(!snapshot.diagnostics.contains_key("driver_protocol_failure"));
        assert!(!snapshot
            .diagnostics
            .contains_key("backend_zec_winner_receipt"));
        assert_eq!(snapshot.accepted, 0);
        assert_eq!(counters.count(Diagnostic::DriverProtocolFailure), 1);
        assert_eq!(counters.count(Diagnostic::SubmissionUnavailable), 1);
        assert_eq!(snapshot.process_instance_id, Some(counters.instance_id()));
        assert_eq!(snapshot.diagnostics, snapshot.workers[0].diagnostics);
        assert!(snapshot.diagnostics.len() <= Diagnostic::ALL.len());
        assert_eq!(
            telemetry
                .account_snapshot(other.account_id())
                .diagnostics
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn diagnostic_worker_and_account_sums_saturate() -> Result<(), SessionError> {
        let telemetry = LiveMinerTelemetry::default();
        let first = AuthenticatedWorker::new(Uuid::from_u128(1), Uuid::from_u128(11), "owner.one")?;
        let second =
            AuthenticatedWorker::new(Uuid::from_u128(1), Uuid::from_u128(12), "owner.two")?;
        telemetry.worker_connected(&first);
        telemetry.worker_connected(&second);
        telemetry.diagnostic(Some(&first), Diagnostic::SubmissionUnavailable);
        telemetry.diagnostic(Some(&second), Diagnostic::SubmissionUnavailable);
        if let Ok(mut workers) = telemetry.workers.lock() {
            if let Some(counters) = workers.get_mut(&(first.account_id(), first.worker_id())) {
                counters
                    .diagnostics
                    .insert("submission_unavailable", u64::MAX);
            }
        }
        telemetry.diagnostic(Some(&first), Diagnostic::SubmissionUnavailable);
        assert_eq!(
            telemetry
                .account_snapshot(first.account_id())
                .diagnostics
                .get("submission_unavailable"),
            Some(&u64::MAX)
        );
        Ok(())
    }
    #[test]
    fn diagnostic_busy_worker_map_never_waits_or_leaks_a_global_observation(
    ) -> Result<(), SessionError> {
        let counters = Arc::new(OperationalCounters::default());
        let telemetry = Arc::new(LiveMinerTelemetry::new(Arc::clone(&counters)));
        let owner = AuthenticatedWorker::new(Uuid::from_u128(1), Uuid::from_u128(11), "owner.rig")?;
        telemetry.worker_connected(&owner);
        let lock = telemetry.workers.lock().ok();
        assert!(lock.is_some());
        let observer = Arc::clone(&telemetry);
        let worker = owner.clone();
        let (done, completed) = std::sync::mpsc::sync_channel(1);
        let task = std::thread::spawn(move || {
            observer.diagnostic(Some(&worker), Diagnostic::SubmissionUnavailable);
            let _ = done.send(());
        });
        // A regressed blocking lock fails this assertion, but releasing the
        // held guard before joining still closes the owned test thread.
        let returned_without_lock = completed
            .recv_timeout(std::time::Duration::from_millis(250))
            .is_ok();
        drop(lock);
        assert!(task.join().is_ok());
        assert!(returned_without_lock);
        assert_eq!(counters.count(Diagnostic::SubmissionUnavailable), 1);
        assert_eq!(counters.count(Diagnostic::AccountObservationSkipped), 1);
        assert!(telemetry
            .account_snapshot(owner.account_id())
            .diagnostics
            .is_empty());
        assert!(telemetry
            .account_snapshot(Uuid::from_u128(2))
            .diagnostics
            .is_empty());
        Ok(())
    }
}

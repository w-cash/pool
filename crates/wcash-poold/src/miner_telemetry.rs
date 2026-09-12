//! Account-scoped live Stratum telemetry shared with the miner portal.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_TRACKED_WORKERS: usize = 65_536;

use uuid::Uuid;
use wcash_pool_core::AuthenticatedWorker;
use wcash_pool_edge::{MinerTelemetrySink, ShareOutcome};
use wcash_pool_portal::{MinerTelemetrySource, MinerTelemetrySummary, WorkerTelemetrySummary};

#[derive(Clone, Copy, Debug, Default)]
struct WorkerCounters {
    connections: u64,
    accepted: u64,
    stale: u64,
    invalid: u64,
    duplicate: u64,
    last_share_at: Option<u64>,
    last_activity_sequence: u64,
}

/// Process-lifetime operational counters; monetary accounting remains durable.
#[derive(Debug, Default)]
pub struct LiveMinerTelemetry {
    workers: Mutex<HashMap<(Uuid, Uuid), WorkerCounters>>,
    activity_sequence: AtomicU64,
}

impl LiveMinerTelemetry {
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
            }
        }
    }

    fn worker_disconnected(&self, worker: &AuthenticatedWorker) {
        if let Ok(mut workers) = self.workers.lock() {
            if let Some(entry) = workers.get_mut(&(worker.account_id(), worker.worker_id())) {
                entry.connections = entry.connections.saturating_sub(1);
                entry.last_activity_sequence = self.next_activity_sequence();
            }
        }
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
            .map(|((_, worker_id), counters)| WorkerTelemetrySummary {
                worker_id: *worker_id,
                connections: counters.connections,
                accepted: counters.accepted,
                stale: counters.stale,
                invalid: counters.invalid,
                duplicate: counters.duplicate,
                last_share_at: counters.last_share_at,
            })
            .collect::<Vec<_>>();
        summaries.sort_by_key(|summary| *summary.worker_id.as_bytes());
        MinerTelemetrySummary {
            available: true,
            updated_at: unix_now(),
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
}

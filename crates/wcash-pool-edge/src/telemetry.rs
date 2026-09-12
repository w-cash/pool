//! Non-consensus live miner telemetry boundary.

use wcash_pool_core::AuthenticatedWorker;

/// Stable categories shown to an authenticated miner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareOutcome {
    /// A new share was durably committed by the backend.
    Accepted,
    /// The submitted job was unknown or no longer admissible.
    Stale,
    /// The proof, target, or request failed share validation.
    Invalid,
    /// The proof was an idempotent replay or attribution conflict.
    Duplicate,
}

/// Synchronous, best-effort observer for operational miner telemetry.
///
/// Implementations must return promptly and must never affect consensus,
/// accounting, or the miner response. Production uses a bounded in-process
/// counter map; durable share accounting remains the PostgreSQL journal.
pub trait MinerTelemetrySink: Send + Sync {
    /// Records an authorized worker connection.
    fn worker_connected(&self, worker: &AuthenticatedWorker);

    /// Records closure of a previously authorized worker connection.
    fn worker_disconnected(&self, worker: &AuthenticatedWorker);

    /// Records one classified share outcome.
    fn share_outcome(&self, worker: &AuthenticatedWorker, outcome: ShareOutcome);
}

/// Observer used by library callers that do not compose portal telemetry.
#[derive(Debug, Default)]
pub struct NoopMinerTelemetry;

impl MinerTelemetrySink for NoopMinerTelemetry {
    fn worker_connected(&self, _worker: &AuthenticatedWorker) {}

    fn worker_disconnected(&self, _worker: &AuthenticatedWorker) {}

    fn share_outcome(&self, _worker: &AuthenticatedWorker, _outcome: ShareOutcome) {}
}

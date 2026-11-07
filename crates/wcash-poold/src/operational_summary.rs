//! Fixed-size, process-only summaries emitted by the existing portal refresh loop.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};
use tokio::time::Instant;
use wcash_pool_edge::OperationalCounters;

use crate::edge::EdgeCounters;

const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// A rate ceiling independent of refresh-loop frequency; missed intervals never burst.
pub(crate) struct OperationalSummary {
    diagnostics: Arc<OperationalCounters>,
    connections: Arc<EdgeCounters>,
    next: Instant,
}

impl OperationalSummary {
    pub(crate) fn new(
        diagnostics: Arc<OperationalCounters>,
        connections: Arc<EdgeCounters>,
    ) -> Self {
        Self {
            diagnostics,
            connections,
            next: Instant::now(),
        }
    }

    pub(crate) fn take_if_due(&mut self, now: Instant) -> Option<Value> {
        if now < self.next {
            return None;
        }
        self.next = now + SUMMARY_INTERVAL;
        Some(summary(&self.diagnostics, &self.connections))
    }

    pub(crate) fn emit_if_due(&mut self) {
        if let Some(value) = self.take_if_due(Instant::now()) {
            eprintln!("{value}");
        }
    }
}

pub(crate) fn emit_final(diagnostics: &OperationalCounters, connections: &EdgeCounters) {
    let mut value = summary(diagnostics, connections);
    value["final"] = Value::Bool(true);
    eprintln!("{value}");
}

fn summary(diagnostics: &OperationalCounters, connections: &EdgeCounters) -> Value {
    let counters: BTreeMap<_, _> = diagnostics.snapshot().into_iter().collect();
    let connections: BTreeMap<_, _> = connections.snapshot().into_iter().collect();
    json!({
        "event": "frontend_operational_summary",
        "schema": 1,
        "process_instance_id": diagnostics.instance_id(),
        "process_started_at_unix": diagnostics.started_at_unix(),
        "sampled_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()),
        "uptime_seconds": diagnostics.uptime_seconds(),
        "scope": "process_lifetime_best_effort_not_accounting",
        "final": false,
        "counters": counters,
        "connections": connections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcash_pool_edge::Diagnostic;

    #[test]
    fn operational_summary_is_bounded_and_never_catches_up_in_bursts() {
        let counters = Arc::new(OperationalCounters::default());
        for &d in Diagnostic::ALL {
            counters.record(d);
        }
        let mut reporter = OperationalSummary::new(counters, Arc::new(EdgeCounters::default()));
        let now = reporter.next;
        let first = reporter.take_if_due(now);
        assert!(first.is_some());
        assert!(reporter.take_if_due(now).is_none());
        assert!(reporter
            .take_if_due(now + Duration::from_secs(59))
            .is_none());
        assert!(reporter
            .take_if_due(now + Duration::from_secs(600))
            .is_some());
        assert!(reporter
            .take_if_due(now + Duration::from_secs(600))
            .is_none());
        let encoded = first
            .map(|mut value| {
                if let Some(counters) = value["counters"].as_object_mut() {
                    for counter in counters.values_mut() {
                        *counter = Value::from(u64::MAX);
                    }
                }
                value.to_string()
            })
            .unwrap_or_default();
        assert!(encoded.len() < 8_192);
        assert!(!encoded.contains("account_id"));
        assert!(!encoded.contains("worker_id"));
        assert!(!encoded.contains("solution"));
        assert!(!encoded.contains("password"));
    }
}

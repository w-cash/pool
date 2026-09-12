//! Injectable time source for expiry and safety-hold decisions.

use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic-enough wall-clock abstraction for persisted Unix timestamps.
pub trait Clock: Send + Sync {
    /// Current Unix timestamp in seconds.
    fn now(&self) -> u64;
}

/// Host system clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

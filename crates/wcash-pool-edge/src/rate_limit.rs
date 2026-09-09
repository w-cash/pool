//! Integer-only request and connection admission limits.

use std::{sync::Arc, time::Duration};

use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAXIMUM_RATE_WINDOW: Duration = Duration::from_secs(300);
const MAXIMUM_BURST: u32 = 65_535;

/// Fixed-window complete-request limit.
///
/// Bytes are still bounded by the protocol frame codec. This policy limits the
/// number of complete JSON requests that reach session or backend work. The
/// caller supplies a monotonic millisecond clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    maximum_requests: u32,
    window_ms: u64,
}

impl RateLimit {
    /// Creates a finite positive request budget.
    pub fn new(maximum_requests: u32, window: Duration) -> Result<Self, RateLimitError> {
        if maximum_requests == 0 || maximum_requests > MAXIMUM_BURST {
            return Err(RateLimitError::InvalidMaximum(maximum_requests));
        }
        if window.is_zero() || window > MAXIMUM_RATE_WINDOW {
            return Err(RateLimitError::InvalidWindow);
        }
        let window_ms =
            u64::try_from(window.as_millis()).map_err(|_| RateLimitError::InvalidWindow)?;
        if window_ms == 0 {
            return Err(RateLimitError::InvalidWindow);
        }
        Ok(Self {
            maximum_requests,
            window_ms,
        })
    }

    /// Returns the request count available in each window.
    pub const fn maximum_requests(self) -> u32 {
        self.maximum_requests
    }

    /// Returns the fixed window length in milliseconds.
    pub const fn window_ms(self) -> u64 {
        self.window_ms
    }
}

/// Per-connection deterministic fixed-window counter.
#[derive(Debug)]
pub(crate) struct RequestRateLimiter {
    policy: RateLimit,
    window_start_ms: u64,
    used: u32,
    last_now_ms: u64,
}

impl RequestRateLimiter {
    pub(crate) const fn new(policy: RateLimit, now_ms: u64) -> Self {
        Self {
            policy,
            window_start_ms: now_ms,
            used: 0,
            last_now_ms: now_ms,
        }
    }

    pub(crate) fn admit(&mut self, now_ms: u64) -> Result<(), RateLimitError> {
        if now_ms < self.last_now_ms {
            return Err(RateLimitError::ClockMovedBackwards);
        }
        self.last_now_ms = now_ms;
        let elapsed = now_ms
            .checked_sub(self.window_start_ms)
            .ok_or(RateLimitError::ClockMovedBackwards)?;
        if elapsed >= self.policy.window_ms {
            self.window_start_ms = now_ms;
            self.used = 0;
        }
        if self.used == self.policy.maximum_requests {
            return Err(RateLimitError::Exceeded);
        }
        self.used = self
            .used
            .checked_add(1)
            .ok_or(RateLimitError::CounterOverflow)?;
        Ok(())
    }
}

/// Process-wide semaphore acquired before starting a connection actor.
#[derive(Clone, Debug)]
pub struct ConnectionCapacity {
    semaphore: Arc<Semaphore>,
}

impl ConnectionCapacity {
    /// Creates a finite process-wide connection ceiling.
    pub fn new(maximum_connections: usize) -> Result<Self, RateLimitError> {
        if maximum_connections == 0 || maximum_connections > 65_535 {
            return Err(RateLimitError::InvalidConnectionCapacity(
                maximum_connections,
            ));
        }
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(maximum_connections)),
        })
    }

    /// Attempts immediate admission; callers should reject before spawning work.
    pub fn try_acquire(&self) -> Result<ConnectionPermit, RateLimitError> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map(ConnectionPermit)
            .map_err(|_| RateLimitError::ConnectionCapacityExceeded)
    }

    /// Returns permits which are not currently held by connection actors.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Owned proof that one connection was admitted under the global ceiling.
#[derive(Debug)]
pub struct ConnectionPermit(#[allow(dead_code)] OwnedSemaphorePermit);

/// Request or connection admission failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RateLimitError {
    /// Request budget must be finite and within its hard maximum.
    #[error("request maximum {0} is outside 1..=65535")]
    InvalidMaximum(u32),
    /// Window must be at least one millisecond and at most five minutes.
    #[error("request window must be 1ms..=300s")]
    InvalidWindow,
    /// Connection ceiling must be finite and within its hard maximum.
    #[error("connection capacity {0} is outside 1..=65535")]
    InvalidConnectionCapacity(usize),
    /// This connection consumed its complete-request budget.
    #[error("request rate limit exceeded")]
    Exceeded,
    /// The supplied monotonic clock regressed.
    #[error("request-rate monotonic clock moved backwards")]
    ClockMovedBackwards,
    /// The bounded request counter could not be incremented.
    #[error("request-rate counter overflowed")]
    CounterOverflow,
    /// All process-wide connection permits are held.
    #[error("connection capacity exceeded")]
    ConnectionCapacityExceeded,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn exact_boundary_resets_without_fractional_math() {
        let policy = RateLimit::new(2, Duration::from_millis(10)).expect("policy is valid");
        let mut limiter = RequestRateLimiter::new(policy, 100);
        assert_eq!(limiter.admit(100), Ok(()));
        assert_eq!(limiter.admit(109), Ok(()));
        assert_eq!(limiter.admit(109), Err(RateLimitError::Exceeded));
        assert_eq!(limiter.admit(110), Ok(()));
        assert_eq!(limiter.admit(109), Err(RateLimitError::ClockMovedBackwards));
    }

    #[test]
    fn connection_permits_fail_immediately_and_return_on_drop() {
        let capacity = ConnectionCapacity::new(1).expect("capacity is valid");
        let permit = capacity.try_acquire().expect("first connection fits");
        assert_eq!(capacity.available_permits(), 0);
        assert!(matches!(
            capacity.try_acquire(),
            Err(RateLimitError::ConnectionCapacityExceeded)
        ));
        drop(permit);
        assert_eq!(capacity.available_permits(), 1);
    }
}

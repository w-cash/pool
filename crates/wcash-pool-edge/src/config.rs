//! Validated finite resource and time limits for one miner connection.

use std::time::Duration;

use thiserror::Error;

use crate::{RateLimit, RateLimitError};

const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(300);
const MAXIMUM_CONNECTIONS: usize = 65_535;
const MAXIMUM_QUEUE_CAPACITY: usize = 4_096;
const MAXIMUM_ANNOUNCED_JOBS: usize = 16;

/// Bounded process-wide and per-connection capacities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    maximum_connections: usize,
    outbound_queue_capacity: usize,
    backend_queue_capacity: usize,
    maximum_announced_jobs: usize,
}

impl ConnectionLimits {
    /// Validates all connection and queue capacities.
    pub fn new(
        maximum_connections: usize,
        outbound_queue_capacity: usize,
        backend_queue_capacity: usize,
        maximum_announced_jobs: usize,
    ) -> Result<Self, EdgeConfigError> {
        validate_capacity(
            "maximum_connections",
            maximum_connections,
            MAXIMUM_CONNECTIONS,
        )?;
        validate_capacity(
            "outbound_queue_capacity",
            outbound_queue_capacity,
            MAXIMUM_QUEUE_CAPACITY,
        )?;
        validate_capacity(
            "backend_queue_capacity",
            backend_queue_capacity,
            MAXIMUM_QUEUE_CAPACITY,
        )?;
        validate_capacity(
            "maximum_announced_jobs",
            maximum_announced_jobs,
            MAXIMUM_ANNOUNCED_JOBS,
        )?;
        Ok(Self {
            maximum_connections,
            outbound_queue_capacity,
            backend_queue_capacity,
            maximum_announced_jobs,
        })
    }

    /// Returns the process-wide live connection ceiling.
    pub const fn maximum_connections(self) -> usize {
        self.maximum_connections
    }

    /// Returns the per-connection outbound message ceiling.
    pub const fn outbound_queue_capacity(self) -> usize {
        self.outbound_queue_capacity
    }

    /// Returns the global pending backend submission ceiling.
    pub const fn backend_queue_capacity(self) -> usize {
        self.backend_queue_capacity
    }

    /// Returns the number of exact jobs one miner session may retain.
    pub const fn maximum_announced_jobs(self) -> usize {
        self.maximum_announced_jobs
    }
}

/// Complete finite policy required by the stream-level runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeConfig {
    limits: ConnectionLimits,
    request_rate: RateLimit,
    idle_timeout: Duration,
    frame_timeout: Duration,
    write_timeout: Duration,
    authorization_timeout: Duration,
    submission_timeout: Duration,
}

impl EdgeConfig {
    /// Creates a configuration after rejecting unbounded or excessive values.
    pub fn new(
        limits: ConnectionLimits,
        request_rate: RateLimit,
        idle_timeout: Duration,
        frame_timeout: Duration,
        write_timeout: Duration,
        authorization_timeout: Duration,
        submission_timeout: Duration,
    ) -> Result<Self, EdgeConfigError> {
        validate_timeout("idle_timeout", idle_timeout)?;
        validate_timeout("frame_timeout", frame_timeout)?;
        validate_timeout("write_timeout", write_timeout)?;
        validate_timeout("authorization_timeout", authorization_timeout)?;
        validate_timeout("submission_timeout", submission_timeout)?;
        if frame_timeout > idle_timeout {
            return Err(EdgeConfigError::FrameTimeoutExceedsIdle);
        }
        Ok(Self {
            limits,
            request_rate,
            idle_timeout,
            frame_timeout,
            write_timeout,
            authorization_timeout,
            submission_timeout,
        })
    }

    /// Returns finite process and session capacities.
    pub const fn limits(self) -> ConnectionLimits {
        self.limits
    }

    /// Returns the deterministic complete-request rate policy.
    pub const fn request_rate(self) -> RateLimit {
        self.request_rate
    }

    /// Returns the maximum time without a complete request.
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    /// Returns the maximum time allowed to assemble one LF frame.
    pub const fn frame_timeout(self) -> Duration {
        self.frame_timeout
    }

    /// Returns the deadline for one complete serialized write batch.
    pub const fn write_timeout(self) -> Duration {
        self.write_timeout
    }

    /// Returns the deadline for one credential verification operation.
    pub const fn authorization_timeout(self) -> Duration {
        self.authorization_timeout
    }

    /// Returns the deadline for one admitted share submission operation.
    pub const fn submission_timeout(self) -> Duration {
        self.submission_timeout
    }
}

/// Invalid edge configuration detected before accepting miners.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EdgeConfigError {
    /// A bounded capacity was zero or exceeded its fixed ceiling.
    #[error("{field} capacity {actual} is outside 1..={maximum}")]
    InvalidCapacity {
        /// Invalid configuration field.
        field: &'static str,
        /// Supplied value.
        actual: usize,
        /// Fixed maximum.
        maximum: usize,
    },
    /// A timeout was zero or greater than five minutes.
    #[error("{field} must be greater than zero and at most 300 seconds")]
    InvalidTimeout {
        /// Invalid configuration field.
        field: &'static str,
    },
    /// A partial frame may not outlive the complete-request idle deadline.
    #[error("frame_timeout must not exceed idle_timeout")]
    FrameTimeoutExceedsIdle,
    /// The request rate policy was invalid.
    #[error(transparent)]
    RateLimit(#[from] RateLimitError),
}

fn validate_capacity(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), EdgeConfigError> {
    if !(1..=maximum).contains(&actual) {
        return Err(EdgeConfigError::InvalidCapacity {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_timeout(field: &'static str, timeout: Duration) -> Result<(), EdgeConfigError> {
    if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
        return Err(EdgeConfigError::InvalidTimeout { field });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn rate() -> RateLimit {
        RateLimit::new(8, Duration::from_secs(1)).expect("fixture rate is valid")
    }

    #[test]
    fn finite_configuration_round_trips() {
        let limits = ConnectionLimits::new(100, 8, 16, 3).expect("limits are valid");
        let config = EdgeConfig::new(
            limits,
            rate(),
            Duration::from_secs(90),
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .expect("configuration is valid");
        assert_eq!(config.limits(), limits);
        assert_eq!(config.request_rate(), rate());
        assert_eq!(config.idle_timeout(), Duration::from_secs(90));
        assert_eq!(config.frame_timeout(), Duration::from_secs(10));
        assert_eq!(config.submission_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn zero_excessive_and_inverted_limits_fail_closed() {
        assert!(matches!(
            ConnectionLimits::new(0, 1, 1, 1),
            Err(EdgeConfigError::InvalidCapacity {
                field: "maximum_connections",
                ..
            })
        ));
        assert!(matches!(
            ConnectionLimits::new(1, 4_097, 1, 1),
            Err(EdgeConfigError::InvalidCapacity {
                field: "outbound_queue_capacity",
                ..
            })
        ));
        let limits = ConnectionLimits::new(1, 1, 1, 1).expect("limits are valid");
        assert_eq!(
            EdgeConfig::new(
                limits,
                rate(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
            Err(EdgeConfigError::FrameTimeoutExceedsIdle)
        );
        assert!(matches!(
            EdgeConfig::new(
                limits,
                rate(),
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::ZERO,
            ),
            Err(EdgeConfigError::InvalidTimeout {
                field: "submission_timeout"
            })
        ));
    }
}

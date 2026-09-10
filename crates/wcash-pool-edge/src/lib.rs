//! Bounded miner-edge building blocks for ZIP-301 Equihash sessions.
//!
//! This crate does not open or drive a public listener. It provides bounded state
//! actors and a loopback-only test stream driver which compose strict framing,
//! authorization, job routing, and a local Wolf backend connection. TLS
//! termination, durable nonce leasing, accounting, and payouts remain deployment
//! responsibilities outside this crate.

#![forbid(unsafe_code)]

mod config;
mod connection;
mod error;
mod rate_limit;
mod router;
#[cfg(unix)]
mod stream;
#[cfg(unix)]
mod submission;

pub use config::{ConnectionLimits, EdgeConfig, EdgeConfigError};
pub use connection::{
    AuthenticationError, AuthenticationProvider, AuthenticationTicket, ConnectionAction,
    ConnectionActor, ConnectionActorError, MiningPolicy, PendingShare, ShareTicket,
};
pub use error::{MinerError, MinerErrorCode};
pub use rate_limit::{ConnectionCapacity, ConnectionPermit, RateLimit, RateLimitError};
pub use router::{JobRouter, JobRouterError, JobSubscription, JobUpdate};
#[cfg(unix)]
pub use stream::{
    LoopbackStreamDriver, ShareSubmissionProvider, StreamDriverError, StreamTermination,
};
#[cfg(unix)]
pub use submission::{
    BackendEventConsumer, BackendEventConsumerError, ShareRouter, ShareRouterConfig,
    ShareRouterConfigError, ShareRouterError, ShareRouterHandle,
};

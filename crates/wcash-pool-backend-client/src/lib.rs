//! Timeout-bounded local transport to the consensus-sensitive Wcash mining backend.
//!
//! The Unix socket path provides a local routing and operating-system access-control
//! boundary, but connecting to a path does not prove which process is listening. An
//! operator must protect the containing directory and socket permissions. Protocol-v1
//! network, payout-recipient commitment, backend-instance, and journal identity
//! comparisons reject accidental misrouting, reward redirection, or replacement
//! when the peer reports different identifiers. A process controlling the socket can
//! copy those public identifiers, so they are not cryptographic peer authentication.

#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::{
    BackendAuthority, BackendClient, BackendClientConfig, BackendConnectionBinding,
    BackendIdentity, BackendStreamPhase, ClientConfigError, ClientError, DeliveredBackendEvent,
    EventPage, ExpectedBackend, HealthSnapshot, JobSnapshot, JobStateIntegrationError,
    MonotonicAnchor, MonotonicTimeline, ShareSubmission, TimelineError, UnverifiedShareCommit,
    VerifiedShareCommit,
};

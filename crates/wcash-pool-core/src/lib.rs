//! Consensus-independent pool policy and state machines.
//!
//! Consensus validation remains behind the local mining backend. This crate
//! owns miner-facing state that must be bound to an exact backend job.

#![forbid(unsafe_code)]

#[cfg(test)]
mod backend;
mod jobs;
mod nonce;
mod session;
mod target;
mod vardiff;

pub use jobs::{
    AdmissibleJobIds, BackendGeneration, GenerationAdmission, GenerationRegistry,
    GenerationRegistryConfig, JobAssignment, JobAssignmentError, JobId, JobRegistryError,
    TipIdentity,
};
pub use nonce::{
    NonceCursor, NonceNamespaceLease, NoncePrefix, NoncePrefixAllocator, NoncePrefixError,
    NonceProfile,
};
pub use session::{
    AuthenticatedWorker, MiningSession, SessionError, SessionState, SubmissionContext,
};
pub use target::{ShareTarget, ShareTargetError, TargetBinding, TargetBounds, TargetPolicyError};
pub use vardiff::{VardiffConfig, VardiffController, VardiffError, VardiffUpdate};

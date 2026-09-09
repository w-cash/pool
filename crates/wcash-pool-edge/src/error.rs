//! Stable miner-facing error categories without backend detail leakage.

use wcash_pool_core::{JobRegistryError, SessionError};
use wcash_pool_protocol::{BackendErrorCode, Zip301Id, Zip301ServerMessage};

/// ZIP-301 error codes used by the edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum MinerErrorCode {
    /// Malformed, unsupported, overloaded, or otherwise invalid request.
    Other = 20,
    /// Unknown or no-longer-admissible job.
    StaleJob = 21,
    /// Duplicate share or attribution conflict.
    DuplicateShare = 22,
    /// Valid proof shape which does not meet the assigned target.
    LowDifficulty = 23,
    /// Credentials or exact authorized login did not match.
    Unauthorized = 24,
    /// A request requiring subscription arrived before subscription.
    NotSubscribed = 25,
}

impl MinerErrorCode {
    /// Returns the exact integer encoded in the Stratum error tuple.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Sanitized error returned to an untrusted miner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinerError {
    code: MinerErrorCode,
    message: &'static str,
    close_connection: bool,
}

impl MinerError {
    /// Creates a stable error with no backend or account detail.
    pub const fn new(code: MinerErrorCode, message: &'static str, close_connection: bool) -> Self {
        Self {
            code,
            message,
            close_connection,
        }
    }

    /// Returns the standard ZIP-301 category.
    pub const fn code(self) -> MinerErrorCode {
        self.code
    }

    /// Returns bounded public text which does not contain internal details.
    pub const fn message(self) -> &'static str {
        self.message
    }

    /// Returns whether protocol or backend safety requires disconnecting.
    pub const fn close_connection(self) -> bool {
        self.close_connection
    }

    /// Builds the exact miner-facing error envelope for one request.
    pub fn message_for(self, id: Zip301Id) -> Zip301ServerMessage {
        Zip301ServerMessage::Error {
            id,
            code: self.code.as_i32(),
            message: self.message.to_owned(),
        }
    }

    /// Maps core session policy without leaking internal job identities.
    pub fn from_session(error: &SessionError) -> Self {
        match error {
            SessionError::UnexpectedState { actual, .. }
                if *actual == wcash_pool_core::SessionState::Connected =>
            {
                Self::new(MinerErrorCode::NotSubscribed, "not subscribed", false)
            }
            SessionError::UnexpectedState { actual, .. }
                if *actual == wcash_pool_core::SessionState::Subscribed =>
            {
                Self::new(MinerErrorCode::Unauthorized, "unauthorized", false)
            }
            SessionError::LoginMismatch
            | SessionError::IdentitySwitch
            | SessionError::MissingIdentity => {
                Self::new(MinerErrorCode::Unauthorized, "unauthorized", false)
            }
            SessionError::JobNotAnnounced(_)
            | SessionError::HeaderTimeMismatch(_)
            | SessionError::Registry(JobRegistryError::UnknownJob(_))
            | SessionError::Registry(JobRegistryError::StaleJob(_))
            | SessionError::Registry(JobRegistryError::NotSynchronized) => {
                Self::new(MinerErrorCode::StaleJob, "stale job", false)
            }
            SessionError::Registry(_)
            | SessionError::Nonce(_)
            | SessionError::Assignment(_)
            | SessionError::RegistryAssignmentMismatch(_)
            | SessionError::AnnouncedJobConflict(_)
            | SessionError::AnnouncedJobCapacity { .. }
            | SessionError::MissingNoncePrefix
            | SessionError::NonceProfileMismatch
            | SessionError::UnexpectedState { .. }
            | SessionError::NilSessionId
            | SessionError::NilIdentity
            | SessionError::InvalidCanonicalLogin
            | SessionError::InvalidAnnouncedJobLimit => {
                Self::new(MinerErrorCode::Other, "invalid request", true)
            }
        }
    }

    /// Maps a stable Wolf rejection to its ZIP-301 category.
    pub const fn from_backend(code: BackendErrorCode) -> Self {
        match code {
            BackendErrorCode::StaleJob => Self::new(MinerErrorCode::StaleJob, "stale job", false),
            BackendErrorCode::LowDifficulty => {
                Self::new(MinerErrorCode::LowDifficulty, "low difficulty share", false)
            }
            BackendErrorCode::AttributionConflict => {
                Self::new(MinerErrorCode::DuplicateShare, "duplicate share", false)
            }
            BackendErrorCode::InvalidRequest
            | BackendErrorCode::InvalidEquihash
            | BackendErrorCode::TargetOutOfRange => {
                Self::new(MinerErrorCode::Other, "invalid share", false)
            }
            BackendErrorCode::Overloaded | BackendErrorCode::BackendUnhealthy => {
                Self::new(MinerErrorCode::Other, "service unavailable", true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_standard_codes_are_frozen() {
        assert_eq!(MinerErrorCode::Other.as_i32(), 20);
        assert_eq!(MinerErrorCode::StaleJob.as_i32(), 21);
        assert_eq!(MinerErrorCode::DuplicateShare.as_i32(), 22);
        assert_eq!(MinerErrorCode::LowDifficulty.as_i32(), 23);
        assert_eq!(MinerErrorCode::Unauthorized.as_i32(), 24);
        assert_eq!(MinerErrorCode::NotSubscribed.as_i32(), 25);
    }

    #[test]
    fn backend_detail_is_replaced_by_stable_public_text() {
        let error = MinerError::from_backend(BackendErrorCode::BackendUnhealthy);
        assert_eq!(error.code(), MinerErrorCode::Other);
        assert_eq!(error.message(), "service unavailable");
        assert!(error.close_connection());
    }

    #[test]
    fn session_ordering_maps_to_standard_subscription_and_authorization_codes() {
        let before_subscription = MinerError::from_session(&SessionError::UnexpectedState {
            required: wcash_pool_core::SessionState::Authorized,
            actual: wcash_pool_core::SessionState::Connected,
        });
        assert_eq!(before_subscription.code(), MinerErrorCode::NotSubscribed);

        let before_authorization = MinerError::from_session(&SessionError::UnexpectedState {
            required: wcash_pool_core::SessionState::Authorized,
            actual: wcash_pool_core::SessionState::Subscribed,
        });
        assert_eq!(before_authorization.code(), MinerErrorCode::Unauthorized);
    }
}

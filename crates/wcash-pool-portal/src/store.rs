//! Durable identity repository boundary shared with the Stratum edge.
//!
//! The portal intentionally has no SQLite or secondary worker database. A
//! production adapter must write the same PostgreSQL account, worker, token,
//! and payout-destination domain used by Stratum authentication.

use std::{fmt, future::Future, pin::Pin};

use uuid::Uuid;

use crate::{
    Asset, ChainNetwork, MinerBlockSummary, MinerPayoutSummary, Page, PageRequest,
    PayoutSettingSummary, RewardSummary, ValidatedDestination, WorkerSummary,
};

/// Boxed repository operation used by object-safe asynchronous adapters.
pub type RepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;

/// Durable repository failure without database or secret details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RepositoryError {
    /// Requested record does not exist or is not owned by the account.
    #[error("record was not found")]
    NotFound,
    /// Unique identity already exists.
    #[error("record already exists")]
    Conflict,
    /// Persisted data violated an invariant.
    #[error("repository state is invalid")]
    InvalidState,
    /// Durable store is unavailable.
    #[error("repository is unavailable")]
    Unavailable,
}

/// Account credential record used only by authentication handlers.
#[derive(Clone)]
pub struct AccountCredential {
    /// Opaque account identifier shared with worker attribution.
    pub id: Uuid,
    /// Canonical account login.
    pub username: String,
    /// Argon2id PHC string; never returned to a browser.
    pub password_hash: String,
    /// Encrypted confirmed TOTP secret.
    pub totp_secret: Option<Vec<u8>>,
    /// Encrypted enrollment secret waiting for confirmation.
    pub totp_pending: Option<Vec<u8>>,
    /// Enrollment expiry.
    pub totp_pending_expires_at: Option<u64>,
    /// Temporary brute-force lock expiry.
    pub locked_until: Option<u64>,
    /// Incremented whenever security configuration invalidates sessions.
    pub security_version: u64,
}

impl fmt::Debug for AccountCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCredential")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|_| "[ENCRYPTED]"),
            )
            .field(
                "totp_pending",
                &self.totp_pending.as_ref().map(|_| "[ENCRYPTED]"),
            )
            .field("totp_pending_expires_at", &self.totp_pending_expires_at)
            .field("locked_until", &self.locked_until)
            .field("security_version", &self.security_version)
            .finish()
    }
}

/// New browser session persisted as keyed digests only.
pub struct NewSession<'a> {
    /// Session-token keyed digest.
    pub token_digest: &'a [u8; 32],
    /// CSRF-token keyed digest.
    pub csrf_digest: &'a [u8; 32],
    /// Account identity.
    pub account_id: Uuid,
    /// Credential version to which the session is fenced.
    pub security_version: u64,
    /// Primary authentication time.
    pub authenticated_at: u64,
    /// TOTP authentication time, when required.
    pub second_factor_at: Option<u64>,
    /// Absolute expiry.
    pub expires_at: u64,
    /// Inactivity expiry.
    pub idle_expires_at: u64,
}

/// Valid authenticated browser session.
pub struct AuthenticatedSession {
    /// Account identity.
    pub account_id: Uuid,
    /// Canonical account login.
    pub username: String,
    /// Expected CSRF keyed digest.
    pub csrf_digest: [u8; 32],
    /// Primary authentication time.
    pub authenticated_at: u64,
}

/// Mining credential returned exactly once by worker provisioning.
pub struct ProvisionedWorker {
    /// Account identity used by share attribution.
    pub account_id: Uuid,
    /// Worker identity used by share attribution.
    pub worker_id: Uuid,
    /// Canonical `account.worker` login.
    pub canonical_login: String,
    /// Canonical `zw1.<selector>.<secret>` token.
    pub token: String,
}

impl fmt::Debug for ProvisionedWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedWorker")
            .field("account_id", &self.account_id)
            .field("worker_id", &self.worker_id)
            .field("canonical_login", &self.canonical_login)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Exact payout preference change handed to the durable store.
pub struct PayoutPreferenceChange<'a> {
    /// Account owner.
    pub account_id: Uuid,
    /// Authoritatively validated chain destination.
    pub destination: &'a ValidatedDestination,
    /// Automatic payout threshold in atomic units.
    pub threshold_zat: u64,
    /// Whether eligible funds should enter automatic batches.
    pub automatic: bool,
    /// Request time.
    pub changed_at: u64,
    /// Replacement-address safety hold; initial setup may activate directly.
    pub replacement_hold_secs: u64,
    /// Keyed audit digest of the full destination.
    pub address_digest: &'a [u8; 32],
}

/// Shared PostgreSQL identity contract required by the portal.
///
/// Implementations must scope every operation to one immutable deployment
/// identity. Worker provisioning must use the canonical token format and
/// Argon2id verifier consumed by the Stratum authentication provider.
pub trait PortalRepository: Send + Sync {
    /// Confirms access to the correctly fenced PostgreSQL deployment.
    fn readiness(&self) -> RepositoryFuture<'_, ()>;

    /// Creates one account with an Argon2id portal-password PHC verifier.
    fn create_account<'a>(
        &'a self,
        id: Uuid,
        username: &'a str,
        password_hash: &'a str,
        now: u64,
    ) -> RepositoryFuture<'a, ()>;

    /// Loads an account credential by canonical login.
    fn account_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> RepositoryFuture<'a, Option<AccountCredential>>;

    /// Records an unsuccessful known-account login and applies a bounded lock.
    fn record_failed_login(
        &self,
        account_id: Uuid,
        maximum_attempts: u32,
        locked_until: u64,
    ) -> RepositoryFuture<'_, ()>;

    /// Clears temporary login-failure state.
    fn clear_failed_login(&self, account_id: Uuid) -> RepositoryFuture<'_, ()>;

    /// Persists a keyed-digest browser session.
    fn create_session(&self, session: NewSession<'_>) -> RepositoryFuture<'_, ()>;

    /// Authenticates and refreshes one unexpired session atomically.
    fn authenticate_session<'a>(
        &'a self,
        token_digest: &'a [u8; 32],
        now: u64,
        new_idle_expiry: u64,
    ) -> RepositoryFuture<'a, Option<AuthenticatedSession>>;

    /// Revokes one exact browser session.
    fn delete_session<'a>(&'a self, token_digest: &'a [u8; 32]) -> RepositoryFuture<'a, ()>;

    /// Revokes every session after a credential/security change.
    fn delete_account_sessions(&self, account_id: Uuid) -> RepositoryFuture<'_, ()>;

    /// Stores an encrypted, expiring TOTP enrollment secret.
    fn save_pending_totp<'a>(
        &'a self,
        account_id: Uuid,
        sealed_secret: &'a [u8],
        expires_at: u64,
    ) -> RepositoryFuture<'a, ()>;

    /// Activates a non-expired enrollment and increments security version.
    fn activate_pending_totp(&self, account_id: Uuid, now: u64) -> RepositoryFuture<'_, bool>;

    /// Atomically creates the worker and canonical Argon2id mining token.
    fn provision_worker<'a>(
        &'a self,
        account_id: Uuid,
        account_login: &'a str,
        worker_label: &'a str,
        now: u64,
    ) -> RepositoryFuture<'a, ProvisionedWorker>;

    /// Returns public-safe workers; never token verifiers or plaintext tokens.
    fn list_workers<'a>(
        &'a self,
        account_id: Uuid,
        account_login: &'a str,
    ) -> RepositoryFuture<'a, Vec<WorkerSummary>>;

    /// Revokes every usable mining token for one owned worker.
    fn revoke_worker(
        &self,
        account_id: Uuid,
        worker_id: Uuid,
        now: u64,
    ) -> RepositoryFuture<'_, bool>;

    /// Records a validated payout preference and immutable audit event.
    fn configure_payout(
        &self,
        change: PayoutPreferenceChange<'_>,
    ) -> RepositoryFuture<'_, PayoutSettingSummary>;

    /// Returns both chain settings after atomically activating elapsed holds.
    fn payout_settings(
        &self,
        account_id: Uuid,
        network: ChainNetwork,
        now: u64,
    ) -> RepositoryFuture<'_, Vec<PayoutSettingSummary>>;

    /// Resolves the unmasked active destination for the isolated payout engine.
    /// This method must never be exposed through a browser handler.
    fn active_payout_destination(
        &self,
        account_id: Uuid,
        asset: Asset,
        network: ChainNetwork,
        now: u64,
    ) -> RepositoryFuture<'_, Option<ValidatedDestination>>;

    /// Returns one account's reward allocations with bounded keyset pagination.
    fn reward_history(
        &self,
        _account_id: Uuid,
        _page: PageRequest,
    ) -> RepositoryFuture<'_, Page<RewardSummary>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    /// Returns blocks found by the account's workers.
    fn found_blocks(
        &self,
        _account_id: Uuid,
        _page: PageRequest,
    ) -> RepositoryFuture<'_, Page<MinerBlockSummary>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    /// Returns the account's payout outputs without exposing destinations.
    fn payout_history(
        &self,
        _account_id: Uuid,
        _page: PageRequest,
    ) -> RepositoryFuture<'_, Page<MinerPayoutSummary>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

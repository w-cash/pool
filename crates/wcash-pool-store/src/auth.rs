//! Mining-only token creation and constant-cost verification.

use std::{future::Future, pin::Pin, sync::Arc};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand_core::{OsRng, RngCore};
use sqlx::{PgPool, Row};
use thiserror::Error;
use tokio::sync::Semaphore;
use uuid::Uuid;
use wcash_pool_core::AuthenticatedWorker;
use wcash_pool_edge::{AuthenticationError, AuthenticationProvider, AuthenticationTicket};
use zeroize::Zeroizing;

const TOKEN_PREFIX: &str = "zw1";
const TOKEN_SECRET_BYTES: usize = 32;
const ARGON_MEMORY_KIB: u32 = 19_456;
const ARGON_ITERATIONS: u32 = 2;
const ARGON_LANES: u32 = 1;
const MAX_ARGON2_PARALLELISM: usize = 32;

/// One generated mining credential. Its selector is public; the full token is
/// secret and is zeroized when dropped.
pub struct MiningToken {
    id: Uuid,
    encoded: Zeroizing<String>,
}

impl std::fmt::Debug for MiningToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MiningToken")
            .field("id", &self.id)
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

impl MiningToken {
    /// Returns the non-secret selector stored with the verifier.
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Exposes the token once to a provisioning boundary. It must never be
    /// logged or reused as a portal credential.
    pub fn expose_secret(&self) -> &str {
        self.encoded.as_str()
    }
}

/// Generates a 256-bit mining-only token using the operating-system CSPRNG.
pub fn generate_mining_token() -> Result<MiningToken, MiningTokenError> {
    let id = Uuid::new_v4();
    let mut secret = Zeroizing::new([0u8; TOKEN_SECRET_BYTES]);
    OsRng
        .try_fill_bytes(secret.as_mut())
        .map_err(|_| MiningTokenError::RandomnessUnavailable)?;
    let secret_hex = Zeroizing::new(hex::encode(*secret));
    let encoded = Zeroizing::new(format!(
        "{TOKEN_PREFIX}.{}.{}",
        id.simple(),
        secret_hex.as_str()
    ));
    Ok(MiningToken { id, encoded })
}

/// Creates an Argon2id verifier for a newly generated full token.
pub fn hash_mining_token(token: &MiningToken) -> Result<String, MiningTokenError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()?
        .hash_password(token.expose_secret().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| MiningTokenError::HashingFailed)
}

fn argon2() -> Result<Argon2<'static>, MiningTokenError> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_LANES, Some(32))
        .map_err(|_| MiningTokenError::HashingFailed)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn parse_selector(candidate: &str) -> Option<Uuid> {
    let mut fields = candidate.split('.');
    let prefix = fields.next()?;
    let id = fields.next()?;
    let secret = fields.next()?;
    if fields.next().is_some()
        || prefix != TOKEN_PREFIX
        || id.len() != 32
        || secret.len() != TOKEN_SECRET_BYTES * 2
        || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !secret.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Uuid::parse_str(id).ok()
}

fn valid_login(login: &str) -> bool {
    let Some((account, worker)) = login.split_once('.') else {
        return false;
    };
    !account.is_empty()
        && account.len() <= 64
        && !worker.is_empty()
        && worker.len() <= 63
        && !worker.contains('.')
        && account.bytes().all(valid_login_byte)
        && worker.bytes().all(valid_login_byte)
}

const fn valid_login_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
}

fn verify(candidate: &[u8], verifier: &str) -> bool {
    PasswordHash::new(verifier).ok().is_some_and(|hash| {
        argon2().is_ok_and(|instance| instance.verify_password(candidate, &hash).is_ok())
    })
}

pub(crate) fn validate_argon2id_verifier(verifier: &str) -> bool {
    if verifier.len() > 1_024 {
        return false;
    }
    PasswordHash::new(verifier).ok().is_some_and(|hash| {
        let salt_length_is_bounded = hash.salt.is_some_and(|salt| {
            let mut decoded = [0u8; 64];
            salt.decode_b64(&mut decoded)
                .is_ok_and(|bytes| (16..=32).contains(&bytes.len()))
        });
        hash.algorithm.as_str() == "argon2id"
            && hash.version == Some(19)
            && hash.params.to_string() == "m=19456,t=2,p=1"
            && salt_length_is_bounded
            && hash.hash.is_some_and(|output| output.len() == 32)
    })
}

fn dummy_verifier() -> Result<String, MiningTokenError> {
    let salt = SaltString::encode_b64(b"zecwec-auth-dummy-salt")
        .map_err(|_| MiningTokenError::HashingFailed)?;
    argon2()?
        .hash_password(b"not-a-valid-mining-token", &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| MiningTokenError::HashingFailed)
}

/// PostgreSQL-backed implementation of the miner-edge authorization boundary.
///
/// A token row grants mining only. Unknown selectors, disabled workers, expired
/// tokens, revoked tokens, and bad secrets all pay one Argon2 verification and
/// return the same public denial.
#[derive(Clone)]
pub struct PostgresAuthenticationProvider {
    pool: PgPool,
    deployment_id: Uuid,
    dummy_verifier: String,
    verification_slots: Arc<Semaphore>,
}

impl std::fmt::Debug for PostgresAuthenticationProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresAuthenticationProvider")
            .field("deployment_id", &self.deployment_id)
            .finish_non_exhaustive()
    }
}

impl PostgresAuthenticationProvider {
    /// Creates a provider for exactly one network deployment.
    pub fn new(
        pool: PgPool,
        deployment_id: Uuid,
        maximum_parallel_verifications: usize,
    ) -> Result<Self, MiningTokenError> {
        if deployment_id.is_nil() {
            return Err(MiningTokenError::NilDeployment);
        }
        if !(1..=MAX_ARGON2_PARALLELISM).contains(&maximum_parallel_verifications) {
            return Err(MiningTokenError::InvalidVerificationConcurrency);
        }
        Ok(Self {
            pool,
            deployment_id,
            dummy_verifier: dummy_verifier()?,
            verification_slots: Arc::new(Semaphore::new(maximum_parallel_verifications)),
        })
    }

    /// Authenticates one exact `account.worker` and mining-only token pair.
    /// The ZIP-301 adapter delegates to this same PostgreSQL truth.
    pub async fn authenticate_credentials(
        &self,
        login: &str,
        password: &str,
    ) -> Result<AuthenticatedWorker, AuthenticationError> {
        authenticate_credentials(self, login, password).await
    }
}

async fn authenticate_credentials(
    provider: &PostgresAuthenticationProvider,
    login: &str,
    password: &str,
) -> Result<AuthenticatedWorker, AuthenticationError> {
    // Every clone shares this semaphore. It fences Argon2's ~19 MiB working
    // set process-wide instead of permitting one allocation per open socket.
    let verification_slot = provider
        .verification_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| AuthenticationError::Unavailable)?;
    let login = login.to_owned();
    let candidate = Zeroizing::new(password.to_owned());
    let selector = parse_selector(candidate.as_str());
    let row = if valid_login(&login) {
        if let Some(selector) = selector {
            sqlx::query(
                "SELECT a.id AS account_id, w.id AS worker_id, w.canonical_login, t.verifier \
                 FROM mining_tokens t \
                 JOIN workers w ON (w.deployment_id, w.id) = (t.deployment_id, t.worker_id) \
                 JOIN accounts a ON (a.deployment_id, a.id) = (w.deployment_id, w.account_id) \
                 WHERE t.deployment_id = $1 AND t.id = $2 \
                   AND w.canonical_login = $3 AND a.enabled AND w.enabled \
                   AND t.revoked_at IS NULL \
                   AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
            )
            .bind(provider.deployment_id)
            .bind(selector)
            .bind(&login)
            .fetch_optional(&provider.pool)
            .await
            .map_err(|_| AuthenticationError::Unavailable)?
        } else {
            None
        }
    } else {
        None
    };

    let (account_id, worker_id, canonical_login, verifier) = match row {
        Some(row) => {
            let account_id = row
                .try_get::<Uuid, _>("account_id")
                .map_err(|_| AuthenticationError::Unavailable)?;
            let worker_id = row
                .try_get::<Uuid, _>("worker_id")
                .map_err(|_| AuthenticationError::Unavailable)?;
            let canonical_login = row
                .try_get::<String, _>("canonical_login")
                .map_err(|_| AuthenticationError::Unavailable)?;
            let verifier = row
                .try_get::<String, _>("verifier")
                .map_err(|_| AuthenticationError::Unavailable)?;
            (Some(account_id), Some(worker_id), canonical_login, verifier)
        }
        None => (None, None, String::new(), provider.dummy_verifier.clone()),
    };

    let verified = tokio::task::spawn_blocking(move || {
        // Keep the permit inside the blocking task: dropping an async caller
        // after a deadline must not admit replacement work before Argon2 exits.
        let _verification_slot = verification_slot;
        verify(candidate.as_bytes(), &verifier)
    })
    .await
    .map_err(|_| AuthenticationError::Unavailable)?;
    match (verified, account_id, worker_id) {
        (true, Some(account_id), Some(worker_id)) => {
            AuthenticatedWorker::new(account_id, worker_id, canonical_login)
                .map_err(|_| AuthenticationError::Unavailable)
        }
        _ => Err(AuthenticationError::Denied),
    }
}

impl AuthenticationProvider for PostgresAuthenticationProvider {
    fn authenticate<'a>(
        &'a self,
        ticket: &'a AuthenticationTicket,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedWorker, AuthenticationError>> + Send + 'a>>
    {
        Box::pin(self.authenticate_credentials(ticket.worker(), ticket.password()))
    }
}

/// Mining token creation or verifier configuration failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MiningTokenError {
    /// The operating-system CSPRNG was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// Argon2id parameters or hashing failed.
    #[error("could not create mining token verifier")]
    HashingFailed,
    /// A provider was constructed without a deployment identity.
    #[error("deployment identity must be non-nil")]
    NilDeployment,
    /// Concurrent Argon2 work was unbounded or above the reviewed process cap.
    #[error("parallel mining-token verification must be in 1..=32")]
    InvalidVerificationConcurrency,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_has_parseable_selector_and_256_bit_secret() {
        let token = generate_mining_token().expect("OS randomness is available");
        assert_eq!(parse_selector(token.expose_secret()), Some(token.id()));
        assert!(!format!("{token:?}").contains(token.expose_secret()));
    }

    #[test]
    fn argon2_verifier_accepts_only_exact_token() {
        let token = generate_mining_token().expect("OS randomness is available");
        let verifier = hash_mining_token(&token).expect("hashing succeeds");
        assert!(verify(token.expose_secret().as_bytes(), &verifier));
        assert!(!verify(
            b"zw1.00000000000000000000000000000000.bad",
            &verifier
        ));
        assert!(verifier.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    }

    #[test]
    fn parser_rejects_ambiguous_token_and_login_forms() {
        assert_eq!(parse_selector(""), None);
        assert_eq!(
            parse_selector(
                "zw1.00000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000.extra"
            ),
            None
        );
        assert!(valid_login("account.z15-01"));
        assert!(!valid_login("Account.z15-01"));
        assert!(!valid_login("account.worker.extra"));
        assert!(!valid_login("account."));
    }

    #[test]
    fn persisted_argon_verifiers_require_the_reviewed_cost_and_shape() {
        let token = generate_mining_token().expect("OS randomness is available");
        let verifier = hash_mining_token(&token).expect("hashing succeeds");
        assert!(validate_argon2id_verifier(&verifier));
        assert!(!validate_argon2id_verifier(
            "$argon2id$v=19$m=4294967295,t=99,p=32$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!validate_argon2id_verifier(
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!validate_argon2id_verifier(
            "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }
}

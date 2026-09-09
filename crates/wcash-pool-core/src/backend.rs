//! Test-only raw-proof backend used to exercise recovery contracts.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use thiserror::Error;
use wcash_pool_protocol::{
    BackendRequest, Hex1344, Hex32, Hex4, MergedChain, ShareReceipt, TargetLe, WinnerDescriptor,
    WorkerIdentity,
};

const SHARE_DOMAIN: &[u8] = b"wcash-pool/fake-share-id/v1";
const PARENT_DOMAIN: &[u8] = b"wcash-pool/fake-parent-hash/v1";
const WCASH_DOMAIN: &[u8] = b"wcash-pool/fake-wcash-hash/v1";
const COINBASE_DOMAIN: &[u8] = b"wcash-pool/fake-coinbase-hash/v1";

/// Boundary implemented by the trusted local consensus backend.
///
/// The edge submits the raw full nonce and 1,344-byte Equihash solution. It
/// never supplies a claimed parent hash, candidate classification, or receipt.
trait MiningBackend {
    /// Validates raw proof and returns the backend-authored durable receipt.
    fn submit_share(
        &mut self,
        request: BackendRequest,
    ) -> Result<FakeBackendCommit, MiningBackendError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShareFingerprint {
    job_id: Hex32,
    identity: WorkerIdentity,
    target_le: TargetLe,
    time: Hex4,
    nonce: Hex32,
    solution: Box<Hex1344>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredShare {
    fingerprint: ShareFingerprint,
    receipt: ShareReceipt,
}

/// Deterministic raw-proof backend for integration and recovery tests.
///
/// This fake does not claim to validate Equihash. It exercises only the trust
/// boundary, attribution conflicts, durable sequence, and retry semantics.
#[derive(Debug, Default)]
struct FakeMiningBackend {
    planned_outcomes: HashMap<Hex32, (bool, bool)>,
    processed: HashMap<Hex32, StoredShare>,
    next_event_seq: u64,
}

impl FakeMiningBackend {
    /// Computes the ID this fake derives from a raw `SubmitShare` request.
    fn derived_share_id(request: &BackendRequest) -> Result<Hex32, MiningBackendError> {
        request
            .validate()
            .map_err(|_| MiningBackendError::InvalidProtocolRequest)?;
        let BackendRequest::SubmitShare {
            job_id,
            time,
            nonce,
            solution,
            ..
        } = request
        else {
            return Err(MiningBackendError::NotSubmitShare);
        };
        Ok(digest(
            SHARE_DOMAIN,
            [
                job_id.as_bytes().as_slice(),
                time.as_bytes(),
                nonce.as_bytes(),
                solution.as_bytes(),
            ],
        ))
    }

    /// Plans independent child/parent candidate bits for a raw request.
    fn plan_outcome(
        &mut self,
        request: &BackendRequest,
        wcash_candidate: bool,
        zcash_candidate: bool,
    ) -> Result<(), MiningBackendError> {
        let share_id = Self::derived_share_id(request)?;
        if self.processed.contains_key(&share_id) {
            return Err(MiningBackendError::AlreadyProcessed);
        }
        self.planned_outcomes
            .insert(share_id, (wcash_candidate, zcash_candidate));
        Ok(())
    }

    /// Returns the number of unique durable share commits.
    fn processed_count(&self) -> usize {
        self.processed.len()
    }
}

impl MiningBackend for FakeMiningBackend {
    fn submit_share(
        &mut self,
        request: BackendRequest,
    ) -> Result<FakeBackendCommit, MiningBackendError> {
        request
            .validate()
            .map_err(|_| MiningBackendError::InvalidProtocolRequest)?;
        let share_id = Self::derived_share_id(&request)?;
        let BackendRequest::SubmitShare {
            job_id,
            identity,
            target_le,
            time,
            nonce,
            solution,
            ..
        } = request
        else {
            return Err(MiningBackendError::NotSubmitShare);
        };
        let fingerprint = ShareFingerprint {
            job_id: job_id.clone(),
            identity,
            target_le,
            time,
            nonce: nonce.clone(),
            solution,
        };
        if let Some(stored) = self.processed.get(&share_id) {
            if stored.fingerprint != fingerprint {
                return Err(MiningBackendError::AttributionConflict);
            }
            return Ok(FakeBackendCommit {
                receipt: stored.receipt.clone(),
                replayed: true,
            });
        }

        let event_seq = self
            .next_event_seq
            .checked_add(1)
            .ok_or(MiningBackendError::SequenceOverflow)?;
        let parent_hash_le = digest(
            PARENT_DOMAIN,
            [
                job_id.as_bytes().as_slice(),
                fingerprint.time.as_bytes(),
                fingerprint.nonce.as_bytes(),
                fingerprint.solution.as_bytes(),
            ],
        );
        let (wcash_candidate, zcash_candidate) =
            self.planned_outcomes.remove(&share_id).unwrap_or_default();
        let mut winners = Vec::with_capacity(2);
        if wcash_candidate {
            winners.push(WinnerDescriptor {
                chain: MergedChain::Wcash,
                block_hash_le: digest(WCASH_DOMAIN, [share_id.as_bytes().as_slice()]),
                height: 11,
                coinbase_txid_le: digest(
                    COINBASE_DOMAIN,
                    [share_id.as_bytes().as_slice(), b"wcash"],
                ),
                reward_zat: 625_000_000,
                maturity_confirmations: 100,
            });
        }
        if zcash_candidate {
            winners.push(WinnerDescriptor {
                chain: MergedChain::Zcash,
                block_hash_le: parent_hash_le.clone(),
                height: 22,
                coinbase_txid_le: digest(
                    COINBASE_DOMAIN,
                    [share_id.as_bytes().as_slice(), b"zcash"],
                ),
                reward_zat: 312_500_000,
                maturity_confirmations: 100,
            });
        }
        let receipt = ShareReceipt {
            event_seq,
            share_id: share_id.clone(),
            parent_hash_le,
            winners,
        };
        self.next_event_seq = event_seq;
        self.processed.insert(
            share_id,
            StoredShare {
                fingerprint,
                receipt: receipt.clone(),
            },
        );
        Ok(FakeBackendCommit {
            receipt,
            replayed: false,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FakeBackendCommit {
    receipt: ShareReceipt,
    replayed: bool,
}

fn digest<'a>(domain: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> Hex32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut bytes: [u8; 32] = hasher.finalize().into();
    if bytes == [0; 32] {
        bytes[31] = 1;
    }
    Hex32::new(bytes)
}

/// Local mining-backend contract failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum MiningBackendError {
    /// Request failed strict protocol validation.
    #[error("backend request failed protocol validation")]
    InvalidProtocolRequest,
    /// The fake/backend entry point only accepts `SubmitShare`.
    #[error("backend request is not submit_share")]
    NotSubmitShare,
    /// Same solved work was replayed with changed identity or target attribution.
    #[error("durable share attribution conflicts with its original commit")]
    AttributionConflict,
    /// Fake outcome cannot change after durable processing.
    #[error("share was already processed")]
    AlreadyProcessed,
    /// Durable event sequence cannot be advanced.
    #[error("backend event sequence is exhausted")]
    SequenceOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wcash_pool_protocol::{CanonicalUuid, Hex1344, TargetLe, BACKEND_PROTOCOL_VERSION};

    fn submission(request_id: u64, worker: u128, target: u8, solution_byte: u8) -> BackendRequest {
        submission_at(request_id, worker, target, solution_byte, [1, 2, 3, 4])
    }

    fn submission_at(
        request_id: u64,
        worker: u128,
        target: u8,
        solution_byte: u8,
        time: [u8; 4],
    ) -> BackendRequest {
        BackendRequest::SubmitShare {
            version: BACKEND_PROTOCOL_VERSION,
            id: request_id,
            job_id: Hex32::new([7; 32]),
            identity: WorkerIdentity {
                account_id: CanonicalUuid::new(Uuid::from_u128(1)),
                worker_id: CanonicalUuid::new(Uuid::from_u128(worker)),
                label: "z15-01".to_owned(),
            },
            target_le: TargetLe::new([target; 32]),
            time: Hex4::new(time),
            nonce: Hex32::new([9; 32]),
            solution: Box::new(Hex1344::new([solution_byte; 1_344])),
        }
    }

    #[test]
    fn submitted_time_is_part_of_the_raw_share_identity() -> Result<(), MiningBackendError> {
        let first = FakeMiningBackend::derived_share_id(&submission_at(1, 2, 3, 4, [1, 2, 3, 4]))?;
        let second = FakeMiningBackend::derived_share_id(&submission_at(2, 2, 3, 4, [1, 2, 3, 5]))?;
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn exact_retry_returns_same_backend_authored_receipt() -> Result<(), MiningBackendError> {
        let first_request = submission(1, 2, 3, 4);
        let retry_request = submission(99, 2, 3, 4);
        let mut backend = FakeMiningBackend::default();
        backend.plan_outcome(&first_request, true, false)?;
        let first = backend.submit_share(first_request)?;
        let retry = backend.submit_share(retry_request)?;
        assert!(!first.replayed);
        assert!(retry.replayed);
        assert_eq!(first.receipt, retry.receipt);
        assert_eq!(first.receipt.winners.len(), 1);
        assert_eq!(first.receipt.winners[0].chain, MergedChain::Wcash);
        assert_eq!(backend.processed_count(), 1);
        Ok(())
    }

    #[test]
    fn same_raw_work_with_changed_attribution_fails_closed() -> Result<(), MiningBackendError> {
        let mut backend = FakeMiningBackend::default();
        backend.submit_share(submission(1, 2, 3, 4))?;
        assert_eq!(
            backend.submit_share(submission(2, 3, 3, 4)),
            Err(MiningBackendError::AttributionConflict)
        );
        assert_eq!(
            backend.submit_share(submission(3, 2, 4, 4)),
            Err(MiningBackendError::AttributionConflict)
        );
        assert_eq!(backend.processed_count(), 1);
        Ok(())
    }

    #[test]
    fn distinct_raw_solution_gets_a_distinct_commit_sequence() -> Result<(), MiningBackendError> {
        let mut backend = FakeMiningBackend::default();
        let first = backend.submit_share(submission(1, 2, 3, 4))?;
        let second = backend.submit_share(submission(2, 2, 3, 5))?;
        assert_ne!(first.receipt.share_id, second.receipt.share_id);
        assert_ne!(first.receipt.parent_hash_le, second.receipt.parent_hash_le);
        assert_eq!(first.receipt.event_seq, 1);
        assert_eq!(second.receipt.event_seq, 2);
        Ok(())
    }

    #[test]
    fn non_submit_and_invalid_protocol_requests_are_rejected() {
        let mut backend = FakeMiningBackend::default();
        assert_eq!(
            backend.submit_share(BackendRequest::Health {
                version: BACKEND_PROTOCOL_VERSION,
                id: 1,
            }),
            Err(MiningBackendError::NotSubmitShare)
        );
        assert_eq!(
            backend.submit_share(submission(1, 2, 0, 4)),
            Err(MiningBackendError::InvalidProtocolRequest)
        );
    }
}

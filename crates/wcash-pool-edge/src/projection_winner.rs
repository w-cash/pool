//! Bounded winner forwarding on the share actor's existing live connection.

use std::collections::{HashSet, VecDeque};

use tokio::{
    sync::{mpsc, oneshot},
    time::{timeout_at, Instant},
};
use wcash_pool_backend_client::{
    BackendClient, BackendConnectionBinding, ClientError, DeliveredBackendEvent,
    VerifiedShareCommit,
};
use wcash_pool_core::SubmissionContext;
use wcash_pool_protocol::{
    canonical_share_id, BackendErrorCode, BackendEvent, Hex32, TargetLe, WorkerIdentity,
};

use crate::ShareRouterError;

const CAPACITY: usize = 8;
type Reply = oneshot::Sender<Result<VerifiedShareCommit, ShareRouterError>>;

pub(crate) fn channel() -> (ProjectionWinnerHandle, ProjectionWinnerQueue) {
    let (sender, receiver) = mpsc::channel(CAPACITY);
    (
        ProjectionWinnerHandle { sender },
        ProjectionWinnerQueue { receiver },
    )
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectionWinnerHandle {
    sender: mpsc::Sender<ProjectionWinnerRequest>,
}

impl ProjectionWinnerHandle {
    pub(crate) async fn submit(
        &self,
        context: SubmissionContext,
    ) -> Result<VerifiedShareCommit, ShareRouterError> {
        if !context.is_projection_candidate() || context.is_winner_recovery() {
            return Err(ShareRouterError::Rejected(BackendErrorCode::StaleJob));
        }
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(ProjectionWinnerRequest { context, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ShareRouterError::Overloaded,
                mpsc::error::TrySendError::Closed(_) => ShareRouterError::Unavailable,
            })?;
        receiver.await.map_err(|_| ShareRouterError::Unavailable)?
    }
}

pub(crate) struct ProjectionWinnerQueue {
    receiver: mpsc::Receiver<ProjectionWinnerRequest>,
}

impl ProjectionWinnerQueue {
    pub(crate) async fn recv(&mut self) -> Option<ProjectionWinnerRequest> {
        self.receiver.recv().await
    }

    /// Reject queued requests after revoking the corresponding admission gate.
    /// Bound the drain even if a producer concurrently held a stale context.
    pub(crate) fn reject_pending(&mut self, error: ShareRouterError) {
        for _ in 0..CAPACITY {
            let Ok(request) = self.receiver.try_recv() else {
                break;
            };
            request.reject(error.clone());
        }
    }
}

pub(crate) struct ProjectionWinnerRequest {
    context: SubmissionContext,
    reply: Reply,
}

impl ProjectionWinnerRequest {
    pub(crate) fn reject(self, error: ShareRouterError) {
        let _ = self.reply.send(Err(error));
    }
}

pub(crate) struct ProjectionWinnerAttempt(ProjectionWinnerRequest);

impl ProjectionWinnerAttempt {
    pub(crate) fn context(&self) -> &SubmissionContext {
        &self.0.context
    }

    pub(crate) fn reject(self, error: ShareRouterError) {
        self.0.reject(error);
    }
}

/// Owned by the share actor for one recovery episode, including its catch-up
/// batches. Only distinct dequeued proofs spend budget before the freshness check.
pub(crate) struct ProjectionWinnerEpisode {
    attempted_proofs: HashSet<(Option<u64>, Hex32)>,
    pending: VecDeque<PendingCommit>,
}

impl ProjectionWinnerEpisode {
    pub(crate) fn new() -> Self {
        Self {
            attempted_proofs: HashSet::new(),
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn can_attempt(&self) -> bool {
        self.attempted_proofs.len() < CAPACITY
    }

    pub(crate) fn start_attempt(
        &mut self,
        request: ProjectionWinnerRequest,
    ) -> Option<ProjectionWinnerAttempt> {
        if !self.can_attempt() {
            request.reject(ShareRouterError::Overloaded);
            return None;
        }
        let context = &request.context;
        let key = (
            context.projection_episode(),
            canonical_share_id(
                &context.job_id(),
                context.time(),
                context.nonce(),
                context.solution(),
            ),
        );
        if !self.attempted_proofs.insert(key) {
            request.reject(ShareRouterError::Overloaded);
            return None;
        }
        Some(ProjectionWinnerAttempt(request))
    }

    /// Submit once after the actor rechecks admission on its original client.
    /// An error return is terminal for that client. In particular the caller
    /// must retire the connection if the deadline cancels a framed exchange.
    pub(crate) async fn submit(
        &mut self,
        attempt: ProjectionWinnerAttempt,
        client: &mut BackendClient,
        deadline: Instant,
        observe: impl FnOnce(&Result<VerifiedShareCommit, ClientError>),
    ) -> Result<(), ShareRouterError> {
        let request = attempt.0;
        if Instant::now() >= deadline {
            request.reject(ShareRouterError::Rejected(BackendErrorCode::StaleJob));
            return Ok(());
        }
        let Some(binding) = client.connection_binding() else {
            let error = ShareRouterError::BackendConnectionMismatch;
            request.reject(error.clone());
            return Err(error);
        };
        let result = timeout_at(
            deadline,
            client.submit_prepared_share_borrowed(&request.context),
        )
        .await
        .unwrap_or(Err(ClientError::Timeout {
            operation: "projection winner submit",
        }));
        observe(&result);
        match result {
            Ok(commit) if commit.replayed() => {
                request.reject(ShareRouterError::ReplayRequiresProjection {
                    receipt: Box::new(commit.receipt().clone()),
                });
            }
            Ok(commit) => {
                // The chain can move between the frontend filter and Wolf's
                // validation. A fresh ordinary receipt is still authoritative.
                self.pending.push_back(PendingCommit {
                    binding,
                    identity: request.context.identity().clone(),
                    target: request.context.target_le().clone(),
                    commit,
                    reply: request.reply,
                });
            }
            Err(ClientError::HistoricalReplayRequiresProjection { receipt }) => {
                request.reject(ShareRouterError::ReplayRequiresProjection { receipt });
            }
            Err(ClientError::BackendRejected { code, .. }) => {
                let error = ShareRouterError::Rejected(code);
                request.reject(error.clone());
                if code == BackendErrorCode::BackendUnhealthy {
                    return Err(error);
                }
            }
            Err(_) => {
                let error = ShareRouterError::Unavailable;
                request.reject(error.clone());
                return Err(error);
            }
        }
        Ok(())
    }

    /// Release fresh receipts only for the exact batch the primary actor has
    /// verified in accounting and applied to its own ordered job stream.
    pub(crate) fn release_projected(
        &mut self,
        events: &[DeliveredBackendEvent],
    ) -> Result<(), ShareRouterError> {
        let Some(last) = events.last() else {
            return Ok(());
        };
        let projected_through = last.event().event_seq();
        let due = self
            .pending
            .iter()
            .take_while(|pending| pending.commit.receipt().event_seq <= projected_through);
        let mut count = 0;
        for pending in due {
            let index = events
                .binary_search_by_key(&pending.commit.receipt().event_seq, |event| {
                    event.event().event_seq()
                })
                .map_err(|_| ShareRouterError::JobStreamUnusable)?;
            if !pending.matches(&events[index]) {
                return Err(ShareRouterError::JobStreamUnusable);
            }
            count += 1;
        }
        for pending in self.pending.drain(..count) {
            let _ = pending.reply.send(Ok(pending.commit));
        }
        Ok(())
    }
}

struct PendingCommit {
    binding: BackendConnectionBinding,
    identity: WorkerIdentity,
    target: TargetLe,
    commit: VerifiedShareCommit,
    reply: Reply,
}

impl PendingCommit {
    fn matches(&self, event: &DeliveredBackendEvent) -> bool {
        event.connection_binding() == &self.binding
            && matches!(
                event.event(),
                BackendEvent::ShareCommitted { receipt, job_id, identity, target_le }
                    if receipt == self.commit.receipt()
                        && job_id == &receipt.job_id
                        && identity == &self.identity
                        && target_le == &self.target
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wcash_pool_core::{
        AuthenticatedWorker, BackendGeneration, GenerationRegistry, GenerationRegistryConfig,
        JobAssignment, MiningSession, NonceNamespaceLease, NoncePrefixAllocator, NonceProfile,
        ShareTarget, TargetBinding, TargetBounds,
    };
    use wcash_pool_protocol::{AcceptableJob, Hex108, Hex1344, Hex28, JobDescriptor, NonceSuffix};

    #[test]
    fn duplicate_projection_proofs_leave_dispatch_budget_for_distinct_proofs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut header = [2; 108];
        header[..4].copy_from_slice(&[4, 0, 0, 0]);
        let job = JobDescriptor {
            job_id: Hex32::new([1; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([1; 32]),
            zcash_previous_hash_le: Hex32::new([2; 32]),
            wcash_candidate_hash_le: Hex32::new([3; 32]),
            wcash_coinbase_txid_le: Hex32::new([4; 32]),
            zcash_coinbase_txid_le: Hex32::new([5; 32]),
            wcash_target_le: ShareTarget::MAX.to_backend(),
            zcash_target_le: ShareTarget::MAX.to_backend(),
            wcash_height: 1,
            zcash_height: 1,
            wcash_reward_zat: 1,
            zcash_reward_zat: 1,
            wcash_maturity_confirmations: 1,
            zcash_maturity_confirmations: 1,
            max_age_ms: 1_000,
        };
        let generation = BackendGeneration::from_descriptor(job.clone())?;
        let mut registry = GenerationRegistry::new(GenerationRegistryConfig::new(1, 8)?);
        registry.apply_snapshot(
            1,
            Some(&AcceptableJob {
                job,
                accept_for_ms: 1_000,
            }),
            &[],
            0,
        )?;
        let mut session = MiningSession::new(Uuid::from_u128(1), 1)?;
        session.subscribe(&NoncePrefixAllocator::new(
            NonceProfile::FourByte,
            NonceNamespaceLease::new(1)?,
        ))?;
        session.complete_authorization(AuthenticatedWorker::new(
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "account.worker",
        )?)?;
        let bounds = TargetBounds::new(ShareTarget::MAX, ShareTarget::MAX, ShareTarget::MAX)?;
        session.announce_job(JobAssignment::new(
            &generation,
            TargetBinding::new(1, ShareTarget::MAX, bounds)?,
        )?)?;

        let mut request = |nonce_byte, pause_episode| {
            let context = session.prepare_projection_candidate(
                "account.worker",
                generation.id(),
                generation.header_time(),
                NonceSuffix::TwentyEight(Hex28::new([nonce_byte; 28])),
                Box::new(Hex1344::new([0x5a; 1344])),
                &mut registry,
                1,
                pause_episode,
            )?;
            let (reply, response) = oneshot::channel();
            Ok::<_, wcash_pool_core::SessionError>((
                ProjectionWinnerRequest { context, reply },
                response,
            ))
        };
        let mut episode = ProjectionWinnerEpisode::new();
        assert!(episode.start_attempt(request(0, 1)?.0).is_some());
        for _ in 0..CAPACITY {
            let (duplicate, mut response) = request(0, 1)?;
            assert!(episode.start_attempt(duplicate).is_none());
            assert!(matches!(
                response.try_recv(),
                Ok(Err(ShareRouterError::Overloaded))
            ));
        }
        // The same proof from another gate cannot collide with this episode's key.
        assert!(episode.start_attempt(request(0, 2)?.0).is_some());
        for nonce_byte in 1..u8::try_from(CAPACITY - 1)? {
            assert!(episode.start_attempt(request(nonce_byte, 1)?.0).is_some());
        }
        assert!(!episode.can_attempt());
        assert!(episode.start_attempt(request(0xff, 1)?.0).is_none());
        Ok(())
    }
}

//! Bounded winner forwarding on the share actor's existing live connection.

use std::collections::VecDeque;

use tokio::{
    sync::{mpsc, oneshot},
    time::{timeout_at, Instant},
};
use wcash_pool_backend_client::{
    BackendClient, BackendConnectionBinding, ClientError, DeliveredBackendEvent,
    VerifiedShareCommit,
};
use wcash_pool_core::SubmissionContext;
use wcash_pool_protocol::{BackendErrorCode, BackendEvent, TargetLe, WorkerIdentity};

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
/// batches. Every dequeued attempt spends budget before any freshness check.
pub(crate) struct ProjectionWinnerEpisode {
    attempts: usize,
    pending: VecDeque<PendingCommit>,
}

impl ProjectionWinnerEpisode {
    pub(crate) fn new() -> Self {
        Self {
            attempts: 0,
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn can_attempt(&self) -> bool {
        self.attempts < CAPACITY
    }

    pub(crate) fn start_attempt(
        &mut self,
        request: ProjectionWinnerRequest,
    ) -> Option<ProjectionWinnerAttempt> {
        if !self.can_attempt() {
            request.reject(ShareRouterError::Overloaded);
            return None;
        }
        self.attempts += 1;
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

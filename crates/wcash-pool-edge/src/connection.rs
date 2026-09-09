//! Deterministic per-connection ZIP-301 actor.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;
use uuid::Uuid;
use wcash_pool_backend_client::VerifiedShareCommit;
use wcash_pool_core::{
    AuthenticatedWorker, BackendGeneration, JobAssignment, JobId, MiningSession,
    NoncePrefixAllocator, SessionError, ShareTarget, SubmissionContext, TargetBinding,
    VardiffConfig, VardiffController, VardiffError,
};
use wcash_pool_protocol::{
    canonical_attribution_id, canonical_share_id, encode_zip301_message, Hex1344, Hex4,
    NonceSuffix, ProtocolError, ShareReceipt, Zip301Id, Zip301Notify, Zip301Request,
    Zip301ServerMessage,
};

use crate::rate_limit::RequestRateLimiter;
use crate::{
    EdgeConfig, JobRouter, JobRouterError, JobUpdate, MinerError, MinerErrorCode, ShareRouterError,
};

/// Vardiff policy installed independently on every authorized miner connection.
#[derive(Clone, Copy, Debug)]
pub struct MiningPolicy {
    vardiff: VardiffConfig,
    initial_target: ShareTarget,
}

impl MiningPolicy {
    /// Creates a policy whose initial target will be clamped to each job's bounds.
    pub const fn new(vardiff: VardiffConfig, initial_target: ShareTarget) -> Self {
        Self {
            vardiff,
            initial_target,
        }
    }
}

/// Credentials which must be resolved by a bounded external authorization service.
pub struct AuthenticationTicket {
    session_id: Uuid,
    ticket: u64,
    worker: String,
    password: String,
}

impl fmt::Debug for AuthenticationTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationTicket")
            .field("session_id", &self.session_id)
            .field("ticket", &self.ticket)
            .field("worker", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticationTicket {
    /// Returns the miner-supplied login for the authorization provider.
    pub fn worker(&self) -> &str {
        &self.worker
    }

    /// Returns the miner-supplied password; it is never payout authorization.
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Asynchronous credential boundary implemented by the deployment.
///
/// The future must be driven under [`EdgeConfig::authorization_timeout`] by the
/// stream driver. Implementations should use a bounded blocking pool for password
/// hashing and return uniform [`AuthenticationError::Denied`] results for unknown
/// accounts and invalid credentials.
pub trait AuthenticationProvider: Send + Sync {
    /// Resolves one ticket to a stable account and worker identity.
    fn authenticate<'a>(
        &'a self,
        ticket: &'a AuthenticationTicket,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedWorker, AuthenticationError>> + Send + 'a>>;
}

/// One core-validated share ready for the bounded Wolf submission actor.
pub struct PendingShare {
    ticket: ShareTicket,
    context: SubmissionContext,
}

impl fmt::Debug for PendingShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingShare")
            .field("ticket", &self.ticket)
            .field("context", &self.context)
            .finish()
    }
}

impl PendingShare {
    /// Separates the unforgeable completion ticket from the guarded backend input.
    pub fn into_parts(self) -> (ShareTicket, SubmissionContext) {
        (self.ticket, self.context)
    }
}

/// Opaque completion token for one in-flight share.
#[derive(Debug)]
pub struct ShareTicket {
    session_id: Uuid,
    ticket: u64,
}

/// External operation requested by one synchronous actor transition.
#[derive(Debug)]
pub enum ConnectionAction {
    /// Verify credentials under the configured authorization deadline.
    Authenticate(AuthenticationTicket),
    /// Submit a fully bound share through [`crate::ShareRouterHandle`].
    Submit(PendingShare),
}

#[derive(Clone, Copy, Debug)]
struct PendingShareState {
    response_id: Option<Zip301IdIndex>,
    target: TargetBinding,
    admitted_at_ms: u64,
    vardiff_sample: Option<bool>,
    expected_job_id: [u8; 32],
    expected_share_id: [u8; 32],
    expected_attribution_id: [u8; 32],
}

impl PendingShareState {
    fn matches_receipt(&self, receipt: &ShareReceipt) -> bool {
        receipt.job_id.as_bytes() == &self.expected_job_id
            && receipt.share_id.as_bytes() == &self.expected_share_id
            && receipt.attribution_id.as_bytes() == &self.expected_attribution_id
    }
}

const fn counts_toward_vardiff(replayed: bool) -> bool {
    !replayed
}

struct SubmittedWork {
    worker: String,
    job_id: wcash_pool_protocol::Hex32,
    time: Hex4,
    nonce_2: NonceSuffix,
    solution: Box<Hex1344>,
}

// Zip301Id is not Hash and can contain a bounded string. Keep response IDs in a
// side table so in-flight tracking never clones miner-controlled strings twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Zip301IdIndex(usize);

/// One ordered, bounded miner session with no network listener of its own.
pub struct ConnectionActor {
    config: EdgeConfig,
    policy: MiningPolicy,
    router: JobRouter,
    session: MiningSession,
    nonce_allocator: Arc<NoncePrefixAllocator>,
    rate_limiter: RequestRateLimiter,
    vardiff: Option<VardiffController>,
    assignments: HashMap<JobId, TargetBinding>,
    advertised_lineage: HashSet<JobId>,
    outbound: VecDeque<Zip301ServerMessage>,
    response_ids: Vec<Option<Zip301Id>>,
    pending_authorization: Option<(u64, Zip301IdIndex)>,
    pending_shares: HashMap<u64, PendingShareState>,
    timing_order: VecDeque<u64>,
    next_ticket: u64,
    closed: bool,
}

impl fmt::Debug for ConnectionActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionActor")
            .field("session", &self.session)
            .field("assignments", &self.assignments.len())
            .field("advertised_lineage", &self.advertised_lineage.len())
            .field("outbound", &self.outbound.len())
            .field(
                "pending_authorization",
                &self.pending_authorization.is_some(),
            )
            .field("pending_shares", &self.pending_shares.len())
            .field("closed", &self.closed)
            .finish()
    }
}

impl ConnectionActor {
    /// Creates one connection actor. The supplied nonce allocator must be backed
    /// by a durable, externally fenced namespace lease before public deployment.
    /// This synchronous actor enforces count bounds; the later stream driver must
    /// enforce the finite I/O and authorization durations carried by `config`.
    pub fn new(
        session_id: Uuid,
        config: EdgeConfig,
        policy: MiningPolicy,
        nonce_allocator: Arc<NoncePrefixAllocator>,
        router: JobRouter,
        now_ms: u64,
    ) -> Result<Self, ConnectionActorError> {
        let session = MiningSession::new(session_id, config.limits().maximum_announced_jobs())?;
        Ok(Self {
            config,
            policy,
            router,
            session,
            nonce_allocator,
            rate_limiter: RequestRateLimiter::new(config.request_rate(), now_ms),
            vardiff: None,
            assignments: HashMap::new(),
            advertised_lineage: HashSet::with_capacity(config.limits().maximum_announced_jobs()),
            outbound: VecDeque::with_capacity(config.limits().outbound_queue_capacity()),
            response_ids: Vec::with_capacity(config.limits().outbound_queue_capacity()),
            pending_authorization: None,
            pending_shares: HashMap::new(),
            timing_order: VecDeque::new(),
            next_ticket: 1,
            closed: false,
        })
    }

    /// Returns whether this actor has entered its terminal state.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Applies one strictly decoded request and returns any external operation.
    pub fn handle_request(
        &mut self,
        request: Zip301Request,
        now_ms: u64,
    ) -> Result<Option<ConnectionAction>, ConnectionActorError> {
        self.require_open()?;
        if self.rate_limiter.admit(now_ms).is_err() {
            self.queue_error(
                request.id().clone(),
                MinerError::new(MinerErrorCode::Other, "rate limit exceeded", true),
            )?;
            return Ok(None);
        }
        match request {
            Zip301Request::Subscribe { id, .. } => {
                match self.session.subscribe(&self.nonce_allocator) {
                    Ok(nonce_1) => self.queue(Zip301ServerMessage::Subscribed { id, nonce_1 })?,
                    Err(error) => self.queue_session_error(id, error)?,
                }
                Ok(None)
            }
            Zip301Request::Authorize {
                id,
                worker,
                password,
            } => self.begin_authorization(id, worker, password),
            Zip301Request::SuggestTarget { id, .. } => {
                if self.session.state() != wcash_pool_core::SessionState::Authorized {
                    let error = if self.session.state() == wcash_pool_core::SessionState::Connected
                    {
                        MinerError::new(MinerErrorCode::NotSubscribed, "not subscribed", false)
                    } else {
                        MinerError::new(MinerErrorCode::Unauthorized, "unauthorized", false)
                    };
                    self.queue_error(id, error)?;
                } else {
                    // Suggestions are non-authoritative. While idle, return the
                    // configured nonzero initial target so the request is answered.
                    // A real generation always sends its network-clamped target
                    // before notify and therefore replaces this provisional value.
                    let target = self
                        .current_assigned_target()?
                        .unwrap_or(self.policy.initial_target);
                    self.queue(Zip301ServerMessage::SetTarget {
                        target_be: target.to_zip301(),
                    })?;
                }
                Ok(None)
            }
            Zip301Request::ExtranonceSubscribe { id } => {
                self.queue_error(
                    id,
                    MinerError::new(
                        MinerErrorCode::Other,
                        "extranonce subscription unsupported",
                        false,
                    ),
                )?;
                Ok(None)
            }
            Zip301Request::Submit {
                id,
                worker,
                job_id,
                time,
                nonce_2,
                solution,
            } => self.begin_submission(
                id,
                SubmittedWork {
                    worker,
                    job_id,
                    time,
                    nonce_2,
                    solution,
                },
                now_ms,
            ),
        }
    }

    /// Completes exactly the outstanding credential operation represented by `ticket`.
    pub fn complete_authorization(
        &mut self,
        ticket: AuthenticationTicket,
        result: Result<AuthenticatedWorker, AuthenticationError>,
    ) -> Result<(), ConnectionActorError> {
        self.require_open()?;
        let expected = self
            .pending_authorization
            .take()
            .ok_or(ConnectionActorError::NoPendingAuthorization)?;
        if ticket.session_id != self.session.id() || ticket.ticket != expected.0 {
            self.close();
            return Err(ConnectionActorError::CompletionTicketMismatch);
        }
        let response_id = self.take_response_id(expected.1)?;
        match result {
            Ok(worker) => {
                // ZIP-301 repeats the authorized login on every share. Until the
                // authentication interface carries an explicit alias set, accepting
                // a different canonical login here would make authorization appear
                // successful while every subsequent share fails `LoginMismatch`.
                if worker.canonical_login() == ticket.worker {
                    self.session.complete_authorization(worker)?;
                    self.queue(Zip301ServerMessage::Boolean {
                        id: response_id,
                        result: true,
                    })?;
                    self.synchronize_current_job()?;
                } else {
                    self.session.reject_authorization()?;
                    self.queue_error(
                        response_id,
                        MinerError::new(MinerErrorCode::Unauthorized, "unauthorized", true),
                    )?;
                }
            }
            Err(AuthenticationError::Denied) => {
                self.session.reject_authorization()?;
                self.queue_error(
                    response_id,
                    MinerError::new(MinerErrorCode::Unauthorized, "unauthorized", true),
                )?;
            }
            Err(AuthenticationError::Unavailable) => {
                self.queue_error(
                    response_id,
                    MinerError::new(MinerErrorCode::Other, "service unavailable", true),
                )?;
            }
        }
        Ok(())
    }

    /// Completes one share only after the concrete Wolf submission actor resolves.
    ///
    /// An idempotent replay is successful because the branded response proves the
    /// identical share was already durably committed. No accounting credit is made
    /// here; the durable journal remains authoritative.
    pub fn complete_submission(
        &mut self,
        ticket: ShareTicket,
        result: Result<VerifiedShareCommit, ShareRouterError>,
    ) -> Result<(), ConnectionActorError> {
        self.require_open()?;
        if ticket.session_id != self.session.id() {
            self.close();
            return Err(ConnectionActorError::CompletionTicketMismatch);
        }
        let completion_matches = match (self.pending_shares.get(&ticket.ticket), &result) {
            (Some(pending), Ok(commit)) if pending.vardiff_sample.is_none() => {
                pending.matches_receipt(commit.receipt())
            }
            (Some(pending), Err(_)) => pending.vardiff_sample.is_none(),
            _ => false,
        };
        if !completion_matches {
            self.close();
            return Err(ConnectionActorError::CompletionTicketMismatch);
        }
        let vardiff_sample = result
            .as_ref()
            .is_ok_and(|verified| counts_toward_vardiff(verified.replayed()));
        let response_index = match self.pending_shares.get_mut(&ticket.ticket) {
            Some(pending) if pending.vardiff_sample.is_none() => {
                pending.vardiff_sample = Some(vardiff_sample);
                pending.response_id.take()
            }
            Some(_) | None => {
                self.close();
                return Err(ConnectionActorError::CompletionTicketMismatch);
            }
        }
        .ok_or_else(|| {
            self.close();
            ConnectionActorError::CompletionTicketMismatch
        })?;
        let response_id = self.take_response_id(response_index)?;
        match result {
            Ok(_verified) => {
                self.queue(Zip301ServerMessage::Boolean {
                    id: response_id,
                    result: true,
                })?;
            }
            Err(ShareRouterError::Rejected(code)) => {
                self.queue_error(response_id, MinerError::from_backend(code))?;
            }
            Err(ShareRouterError::Overloaded) => {
                self.queue_error(
                    response_id,
                    MinerError::new(MinerErrorCode::Other, "service busy", false),
                )?;
            }
            Err(ShareRouterError::ReplayRequiresProjection { .. }) => {
                self.queue_error(
                    response_id,
                    MinerError::new(MinerErrorCode::Other, "share reconciliation pending", false),
                )?;
            }
            Err(
                ShareRouterError::Unavailable
                | ShareRouterError::JobStreamUnusable
                | ShareRouterError::EventConsumerUnusable
                | ShareRouterError::TaskFailed
                | ShareRouterError::BackendNotLive
                | ShareRouterError::BackendConnectionMismatch,
            ) => {
                self.queue_error(
                    response_id,
                    MinerError::new(MinerErrorCode::Other, "service unavailable", true),
                )?;
            }
        }
        if !self.closed {
            if let Err(error) = self.drain_completed_timing() {
                self.close();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Applies one globally ordered job update.
    pub fn apply_job_update(&mut self, update: JobUpdate) -> Result<(), ConnectionActorError> {
        self.require_open()?;
        match update {
            JobUpdate::Activated {
                generation,
                clean_jobs,
            } => {
                let current = self.router.current_generation()?;
                if current.as_ref().map(BackendGeneration::id) == Some(generation.id()) {
                    self.announce_generation(generation.as_ref(), clean_jobs)?;
                } else if clean_jobs {
                    // A slow actor can observe a clean activation only after the
                    // global router has advanced again. Preserve that discarded
                    // boundary so the next current generation cannot be announced
                    // as compatible with miner work from the old lineage.
                    self.advertised_lineage.clear();
                }
            }
            JobUpdate::Retired { job_id } => {
                self.assignments.remove(&job_id);
                self.advertised_lineage.remove(&job_id);
                self.session.remove_announced_job(job_id);
            }
            JobUpdate::Suspended => self.close(),
        }
        Ok(())
    }

    /// Removes assignments no longer admitted by Wolf's exact local lifetime.
    pub fn reconcile_jobs(&mut self) -> Result<(), ConnectionActorError> {
        self.require_open()?;
        let admissible: HashSet<_> = self.router.admissible_job_ids()?.into_iter().collect();
        self.assignments.retain(|job_id, _| {
            if admissible.contains(job_id) {
                true
            } else {
                self.session.remove_announced_job(*job_id);
                false
            }
        });
        let assignments = &self.assignments;
        self.advertised_lineage
            .retain(|job_id| assignments.contains_key(job_id));
        Ok(())
    }

    /// Removes and returns the oldest queued typed message.
    pub fn pop_outbound(&mut self) -> Option<Zip301ServerMessage> {
        self.outbound.pop_front()
    }

    /// Encodes and removes the oldest queued message.
    pub fn pop_outbound_frame(&mut self) -> Result<Option<Vec<u8>>, ConnectionActorError> {
        self.outbound
            .pop_front()
            .map(|message| encode_zip301_message(&message).map_err(ConnectionActorError::Protocol))
            .transpose()
    }

    /// Marks a failed notification or response write as terminal.
    pub fn transport_failed(&mut self) {
        self.close();
    }

    fn begin_authorization(
        &mut self,
        id: Zip301Id,
        worker: String,
        password: String,
    ) -> Result<Option<ConnectionAction>, ConnectionActorError> {
        if self.pending_authorization.is_some() {
            self.queue_error(
                id,
                MinerError::new(MinerErrorCode::Other, "authorization already pending", true),
            )?;
            return Ok(None);
        }
        if self.session.state() != wcash_pool_core::SessionState::Subscribed {
            let error = MinerError::from_session(&SessionError::UnexpectedState {
                required: wcash_pool_core::SessionState::Subscribed,
                actual: self.session.state(),
            });
            self.queue_error(id, error)?;
            return Ok(None);
        }
        let response_id = self.store_response_id(id)?;
        let ticket = self.allocate_ticket()?;
        self.pending_authorization = Some((ticket, response_id));
        Ok(Some(ConnectionAction::Authenticate(AuthenticationTicket {
            session_id: self.session.id(),
            ticket,
            worker,
            password,
        })))
    }

    fn begin_submission(
        &mut self,
        id: Zip301Id,
        submitted: SubmittedWork,
        now_ms: u64,
    ) -> Result<Option<ConnectionAction>, ConnectionActorError> {
        if self.pending_shares.len() >= self.config.limits().outbound_queue_capacity() {
            self.queue_error(
                id,
                MinerError::new(MinerErrorCode::Other, "too many pending shares", true),
            )?;
            return Ok(None);
        }
        let job_id = match JobId::new(*submitted.job_id.as_bytes()) {
            Ok(job_id) => job_id,
            Err(_) => {
                self.queue_error(
                    id,
                    MinerError::new(MinerErrorCode::StaleJob, "stale job", false),
                )?;
                return Ok(None);
            }
        };
        let target = self.assignments.get(&job_id).copied();
        let context = match self.router.prepare_submission(
            &self.session,
            &submitted.worker,
            job_id,
            submitted.time,
            submitted.nonce_2,
            submitted.solution,
        ) {
            Ok(context) => context,
            Err(JobRouterError::Session(error)) => {
                self.queue_session_error(id, error)?;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let target = target.ok_or(ConnectionActorError::MissingAssignment(job_id))?;
        let expected_job_id = *context.job_id().as_bytes();
        let expected_share_id = *canonical_share_id(
            &context.job_id(),
            context.time(),
            context.nonce(),
            context.solution(),
        )
        .as_bytes();
        let expected_attribution_id =
            *canonical_attribution_id(context.identity(), context.target_le())?.as_bytes();
        let response_id = self.store_response_id(id)?;
        let ticket = self.allocate_ticket()?;
        self.pending_shares.insert(
            ticket,
            PendingShareState {
                response_id: Some(response_id),
                target,
                admitted_at_ms: now_ms,
                vardiff_sample: None,
                expected_job_id,
                expected_share_id,
                expected_attribution_id,
            },
        );
        self.timing_order.push_back(ticket);
        Ok(Some(ConnectionAction::Submit(PendingShare {
            ticket: ShareTicket {
                session_id: self.session.id(),
                ticket,
            },
            context,
        })))
    }

    fn synchronize_current_job(&mut self) -> Result<(), ConnectionActorError> {
        if let Some(generation) = self.router.current_generation()? {
            self.announce_generation(&generation, true)?;
        }
        Ok(())
    }

    fn drain_completed_timing(&mut self) -> Result<(), ConnectionActorError> {
        loop {
            let Some(ticket) = self.timing_order.front().copied() else {
                return Ok(());
            };
            let Some(vardiff_sample) = self
                .pending_shares
                .get(&ticket)
                .and_then(|pending| pending.vardiff_sample)
            else {
                return Ok(());
            };
            let pending = self
                .pending_shares
                .remove(&ticket)
                .ok_or(ConnectionActorError::CompletionTicketMismatch)?;
            self.timing_order.pop_front();
            if vardiff_sample {
                if let Some(vardiff) = self.vardiff.as_mut() {
                    let _ = vardiff.observe_share(pending.target, pending.admitted_at_ms)?;
                }
            }
        }
    }

    fn announce_generation(
        &mut self,
        generation: &BackendGeneration,
        clean_jobs: bool,
    ) -> Result<(), ConnectionActorError> {
        if self.session.state() != wcash_pool_core::SessionState::Authorized {
            return Ok(());
        }
        self.reconcile_jobs()?;
        let clean_jobs = clean_jobs || self.advertised_lineage.is_empty();
        if clean_jobs {
            self.advertised_lineage.clear();
        } else if self.assignments.contains_key(&generation.id()) {
            return Ok(());
        }
        let binding = match self.vardiff.as_mut() {
            Some(vardiff) => vardiff.update_network_targets(
                generation.wcash_network_target(),
                generation.zcash_network_target(),
            )?,
            None => {
                let vardiff = VardiffController::new(
                    self.policy.vardiff,
                    generation.wcash_network_target(),
                    generation.zcash_network_target(),
                    self.policy.initial_target,
                    1,
                )?;
                let binding = vardiff.binding();
                self.vardiff = Some(vardiff);
                binding
            }
        };
        let send_target = self.current_assigned_target()? != Some(binding.target());
        let required = usize::from(send_target) + 1;
        self.ensure_outbound_capacity(required)?;

        // Record the exact immutable target before any caller can write notify.
        let assignment = JobAssignment::new(generation, binding)?;
        self.session.announce_job(assignment)?;
        self.assignments.insert(generation.id(), binding);
        self.advertised_lineage.insert(generation.id());
        if send_target {
            self.outbound.push_back(Zip301ServerMessage::SetTarget {
                target_be: binding.target().to_zip301(),
            });
        }
        self.outbound
            .push_back(Zip301ServerMessage::Notify(Zip301Notify {
                job_id: generation.id().to_protocol(),
                header_input: generation.descriptor().header_input.clone(),
                clean_jobs,
            }));
        Ok(())
    }

    fn current_assigned_target(&self) -> Result<Option<ShareTarget>, ConnectionActorError> {
        Ok(self
            .router
            .current_generation()?
            .and_then(|generation| self.assignments.get(&generation.id()).copied())
            .map(TargetBinding::target))
    }

    fn queue_session_error(
        &mut self,
        id: Zip301Id,
        error: SessionError,
    ) -> Result<(), ConnectionActorError> {
        self.queue_error(id, MinerError::from_session(&error))
    }

    fn queue_error(&mut self, id: Zip301Id, error: MinerError) -> Result<(), ConnectionActorError> {
        self.queue(error.message_for(id))?;
        if error.close_connection() {
            self.close();
        }
        Ok(())
    }

    fn queue(&mut self, message: Zip301ServerMessage) -> Result<(), ConnectionActorError> {
        self.ensure_outbound_capacity(1)?;
        self.outbound.push_back(message);
        Ok(())
    }

    fn ensure_outbound_capacity(&mut self, additional: usize) -> Result<(), ConnectionActorError> {
        let maximum = self.config.limits().outbound_queue_capacity();
        let required = self
            .outbound
            .len()
            .checked_add(additional)
            .ok_or(ConnectionActorError::OutboundQueueFull { maximum })?;
        if required > maximum {
            self.close();
            return Err(ConnectionActorError::OutboundQueueFull { maximum });
        }
        Ok(())
    }

    fn store_response_id(&mut self, id: Zip301Id) -> Result<Zip301IdIndex, ConnectionActorError> {
        if let Some((index, slot)) = self
            .response_ids
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(id);
            return Ok(Zip301IdIndex(index));
        }
        if self.response_ids.len() >= self.config.limits().outbound_queue_capacity() {
            self.close();
            return Err(ConnectionActorError::ResponseIdCapacity);
        }
        self.response_ids.push(Some(id));
        Ok(Zip301IdIndex(self.response_ids.len() - 1))
    }

    fn take_response_id(&mut self, index: Zip301IdIndex) -> Result<Zip301Id, ConnectionActorError> {
        self.response_ids
            .get_mut(index.0)
            .and_then(Option::take)
            .ok_or(ConnectionActorError::CompletionTicketMismatch)
    }

    fn allocate_ticket(&mut self) -> Result<u64, ConnectionActorError> {
        let ticket = self.next_ticket;
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(ConnectionActorError::TicketExhausted)?;
        Ok(ticket)
    }

    fn require_open(&self) -> Result<(), ConnectionActorError> {
        if self.closed {
            Err(ConnectionActorError::Closed)
        } else {
            Ok(())
        }
    }

    fn close(&mut self) {
        self.closed = true;
        self.session.close();
        self.assignments.clear();
        self.advertised_lineage.clear();
        self.pending_authorization = None;
        self.pending_shares.clear();
        self.timing_order.clear();
        self.response_ids.clear();
    }

    #[cfg(test)]
    fn binding(&self) -> Option<TargetBinding> {
        self.vardiff.as_ref().map(VardiffController::binding)
    }
}

/// Authorization outcome with intentionally uniform public denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationError {
    /// Credentials did not resolve to an account and worker.
    #[error("authorization denied")]
    Denied,
    /// The trusted authorization store could not answer safely.
    #[error("authorization service unavailable")]
    Unavailable,
}

/// Per-connection orchestration failure.
#[derive(Debug, Error)]
pub enum ConnectionActorError {
    /// The actor already entered its terminal state.
    #[error("connection actor is closed")]
    Closed,
    /// Bounded outbound storage filled; the connection was closed without eviction.
    #[error("outbound message capacity {maximum} was reached")]
    OutboundQueueFull {
        /// Configured message ceiling.
        maximum: usize,
    },
    /// Too many response IDs were retained for outstanding operations.
    #[error("pending response identifier capacity was reached")]
    ResponseIdCapacity,
    /// An authorization result arrived without its exact outstanding ticket.
    #[error("no authorization is pending")]
    NoPendingAuthorization,
    /// A completion token was replayed or belonged to another connection.
    #[error("completion ticket does not match an outstanding operation")]
    CompletionTicketMismatch,
    /// No further monotonic completion ticket can be represented.
    #[error("connection completion ticket space exhausted")]
    TicketExhausted,
    /// A prepared context lacked its actor-side immutable target record.
    #[error("prepared generation {0:?} lacks a connection assignment")]
    MissingAssignment(JobId),
    /// Strict wire encoding failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Core session policy failed.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// Global generation routing failed.
    #[error(transparent)]
    Router(#[from] JobRouterError),
    /// Per-session target binding failed.
    #[error(transparent)]
    Assignment(#[from] wcash_pool_core::JobAssignmentError),
    /// Vardiff policy failed.
    #[error(transparent)]
    Vardiff(#[from] VardiffError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use super::*;
    use wcash_pool_core::{
        GenerationRegistryConfig, NonceNamespaceLease, NonceProfile, TargetBounds,
    };
    use wcash_pool_protocol::{
        AcceptableJob, BackendEvent, Hex108, Hex32, JobDescriptor, TargetLe,
    };

    fn descriptor(id: u8) -> JobDescriptor {
        let mut header = [id; 108];
        header[..4].copy_from_slice(&[4, 0, 0, 0]);
        header[4..36].copy_from_slice(&[id.wrapping_add(1); 32]);
        header[100..104].copy_from_slice(&[1, 2, 3, id]);
        JobDescriptor {
            job_id: Hex32::new([id; 32]),
            wcash_candidate_hash_le: Hex32::new([5; 32]),
            header_input: Hex108::new(header),
            wcash_previous_hash_le: Hex32::new([id.wrapping_add(2); 32]),
            zcash_previous_hash_le: Hex32::new([id.wrapping_add(1); 32]),
            wcash_coinbase_txid_le: Hex32::new([6; 32]),
            zcash_coinbase_txid_le: Hex32::new([7; 32]),
            wcash_target_le: TargetLe::new([3; 32]),
            zcash_target_le: TargetLe::new([4; 32]),
            wcash_height: 10,
            zcash_height: 20,
            wcash_reward_zat: 625_000_000,
            zcash_reward_zat: 312_500_000,
            wcash_maturity_confirmations: 100,
            zcash_maturity_confirmations: 100,
            max_age_ms: 60_000,
        }
    }

    fn router() -> JobRouter {
        JobRouter::from_acceptable_for_test(
            1,
            Some(&AcceptableJob {
                job: descriptor(1),
                accept_for_ms: 30_000,
            }),
            &[],
            GenerationRegistryConfig::new(2, 8).expect("registry config is valid"),
            8,
        )
        .expect("router is valid")
    }

    fn empty_router() -> JobRouter {
        JobRouter::from_acceptable_for_test(
            1,
            None,
            &[],
            GenerationRegistryConfig::new(2, 8).expect("registry config is valid"),
            8,
        )
        .expect("router is valid")
    }

    fn router_with_recent() -> JobRouter {
        JobRouter::from_acceptable_for_test(
            1,
            Some(&AcceptableJob {
                job: descriptor(1),
                accept_for_ms: 30_000,
            }),
            &[AcceptableJob {
                job: descriptor(2),
                accept_for_ms: 30_000,
            }],
            GenerationRegistryConfig::new(2, 8).expect("registry config is valid"),
            8,
        )
        .expect("router is valid")
    }

    fn actor_with_router(outbound: usize, router: JobRouter) -> ConnectionActor {
        let limits =
            crate::ConnectionLimits::new(10, outbound, 8, 4).expect("connection limits are valid");
        let rate = crate::RateLimit::new(100, Duration::from_secs(1)).expect("rate limit is valid");
        let config = EdgeConfig::new(
            limits,
            rate,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_secs(2),
        )
        .expect("edge config is valid");
        let generation =
            BackendGeneration::from_descriptor(descriptor(1)).expect("descriptor is valid");
        let bounds = TargetBounds::new(
            generation.wcash_network_target(),
            generation.zcash_network_target(),
            ShareTarget::MAX,
        )
        .expect("bounds are valid");
        let vardiff =
            VardiffConfig::new(10_000, 8, 2_500, 4, ShareTarget::MAX).expect("vardiff is valid");
        let policy = MiningPolicy::new(vardiff, bounds.hardest_allowed());
        let lease = NonceNamespaceLease::new(7).expect("lease is valid");
        let allocator = Arc::new(NoncePrefixAllocator::new(NonceProfile::FourByte, lease));
        ConnectionActor::new(Uuid::from_u128(1), config, policy, allocator, router, 0)
            .expect("actor is valid")
    }

    fn actor(outbound: usize) -> ConnectionActor {
        actor_with_router(outbound, router())
    }

    fn authorize(actor: &mut ConnectionActor) {
        actor
            .handle_request(
                Zip301Request::Subscribe {
                    id: Zip301Id::Number(1),
                    params: Vec::new(),
                },
                0,
            )
            .expect("subscribe succeeds");
        let action = actor
            .handle_request(
                Zip301Request::Authorize {
                    id: Zip301Id::Number(2),
                    worker: "account.rig".to_owned(),
                    password: "x".to_owned(),
                },
                1,
            )
            .expect("authorization begins")
            .expect("authorization action exists");
        let ConnectionAction::Authenticate(ticket) = action else {
            unreachable!("fixture must request authorization")
        };
        actor
            .complete_authorization(
                ticket,
                Ok(
                    AuthenticatedWorker::new(Uuid::from_u128(2), Uuid::from_u128(3), "account.rig")
                        .expect("worker identity is valid"),
                ),
            )
            .expect("authorization completes");
    }

    fn pop_notify(actor: &mut ConnectionActor) -> Zip301Notify {
        loop {
            if let Zip301ServerMessage::Notify(notify) = actor
                .pop_outbound()
                .expect("expected a queued mining.notify")
            {
                return notify;
            }
        }
    }

    #[test]
    fn authorization_emits_response_target_then_notify() {
        let mut actor = actor(8);
        authorize(&mut actor);
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::Subscribed { .. })
        ));
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::Boolean { result: true, .. })
        ));
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::SetTarget { .. })
        ));
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::Notify(_))
        ));
    }

    #[test]
    fn authorization_rejects_an_unannounced_canonical_login_change() {
        let mut actor = actor(8);
        actor
            .handle_request(
                Zip301Request::Subscribe {
                    id: Zip301Id::Number(1),
                    params: Vec::new(),
                },
                0,
            )
            .expect("subscribe succeeds");
        let action = actor
            .handle_request(
                Zip301Request::Authorize {
                    id: Zip301Id::Number(2),
                    worker: "account.rig".to_owned(),
                    password: "x".to_owned(),
                },
                1,
            )
            .expect("authorization begins")
            .expect("authorization action exists");
        let ConnectionAction::Authenticate(ticket) = action else {
            unreachable!("fixture must request authorization")
        };

        actor
            .complete_authorization(
                ticket,
                Ok(AuthenticatedWorker::new(
                    Uuid::from_u128(2),
                    Uuid::from_u128(3),
                    "different.rig",
                )
                .expect("worker identity is valid")),
            )
            .expect("mismatch is returned as a uniform denial");

        assert!(actor.is_closed());
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::Subscribed { .. })
        ));
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::Error {
                code,
                message,
                ..
            }) if code == MinerErrorCode::Unauthorized.as_i32() && message == "unauthorized"
        ));
        assert!(actor.pop_outbound().is_none());
    }

    #[test]
    fn changed_vardiff_binding_is_not_retrofitted_to_same_generation() {
        let mut actor = actor(8);
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        let original = actor.binding().expect("vardiff exists");
        let vardiff = actor.vardiff.as_mut().expect("vardiff exists");
        vardiff.tick(0).expect("clock starts");
        let update = vardiff.tick(120_001).expect("inactivity update succeeds");
        assert!(matches!(
            update,
            wcash_pool_core::VardiffUpdate::Changed { .. }
        ));
        assert_ne!(actor.binding(), Some(original));
        let generation = actor
            .router
            .current_generation()
            .expect("query succeeds")
            .expect("generation exists");
        actor
            .announce_generation(&generation, false)
            .expect("duplicate activation is harmless");
        assert!(actor.pop_outbound().is_none());
        assert_eq!(actor.assignments.get(&generation.id()), Some(&original));
    }

    #[test]
    fn clean_lineage_does_not_resurrect_discarded_jobs() {
        let mut actor = actor_with_router(16, router_with_recent());
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}

        let second =
            BackendGeneration::from_descriptor(descriptor(2)).expect("descriptor is valid");
        actor
            .announce_generation(&second, false)
            .expect("same-lineage generation is announced");
        assert!(!pop_notify(&mut actor).clean_jobs);

        let third = BackendGeneration::from_descriptor(descriptor(3)).expect("descriptor is valid");
        actor
            .announce_generation(&third, true)
            .expect("clean boundary is announced");
        assert!(pop_notify(&mut actor).clean_jobs);
        assert!(actor.assignments.contains_key(&second.id()));
        assert!(!actor.advertised_lineage.contains(&second.id()));

        // The third generation is not in the authoritative router, modelling a
        // coalesced or locally expired current update while the older second
        // generation remains acceptable only for late backend submissions.
        let fourth =
            BackendGeneration::from_descriptor(descriptor(4)).expect("descriptor is valid");
        actor
            .announce_generation(&fourth, false)
            .expect("replacement generation is announced");
        assert!(pop_notify(&mut actor).clean_jobs);
        assert!(actor.assignments.contains_key(&second.id()));
        assert!(actor.assignments.contains_key(&fourth.id()));
        assert!(!actor.advertised_lineage.contains(&second.id()));
        assert!(actor.advertised_lineage.contains(&fourth.id()));
    }

    #[test]
    fn skipped_clean_activation_forces_the_next_current_notification_clean() {
        let mut actor = actor(16);
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        assert!(!actor.advertised_lineage.is_empty());

        let second_descriptor = descriptor(2);
        let second = BackendGeneration::from_descriptor(second_descriptor.clone())
            .expect("second descriptor is valid");
        actor
            .router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 2,
                    job: second_descriptor.clone(),
                },
                0,
            )
            .expect("changed-tip activation succeeds");

        let mut third_descriptor = descriptor(3);
        third_descriptor.wcash_previous_hash_le = second_descriptor.wcash_previous_hash_le.clone();
        third_descriptor.zcash_previous_hash_le = second_descriptor.zcash_previous_hash_le.clone();
        let mut third_header = *third_descriptor.header_input.as_bytes();
        third_header[4..36].copy_from_slice(second_descriptor.zcash_previous_hash_le.as_bytes());
        third_descriptor.header_input = Hex108::new(third_header);
        let third = BackendGeneration::from_descriptor(third_descriptor.clone())
            .expect("third descriptor is valid");
        actor
            .router
            .apply_event_for_test(
                &BackendEvent::JobActivated {
                    event_seq: 3,
                    job: third_descriptor,
                },
                0,
            )
            .expect("same-tip replacement succeeds");

        // The actor handles the changed-tip activation after the router already
        // moved to its same-tip successor, so the second generation is skipped.
        actor
            .apply_job_update(JobUpdate::Activated {
                generation: Box::new(second),
                clean_jobs: true,
            })
            .expect("skipped clean boundary is retained");
        assert!(actor.advertised_lineage.is_empty());

        actor
            .apply_job_update(JobUpdate::Activated {
                generation: Box::new(third),
                clean_jobs: false,
            })
            .expect("current replacement is announced");
        assert!(pop_notify(&mut actor).clean_jobs);
    }

    #[test]
    fn outbound_capacity_never_evicts_an_earlier_message() {
        let mut actor = actor(2);
        actor
            .handle_request(
                Zip301Request::Subscribe {
                    id: Zip301Id::Number(1),
                    params: Vec::new(),
                },
                0,
            )
            .expect("subscribe succeeds");
        let action = actor
            .handle_request(
                Zip301Request::Authorize {
                    id: Zip301Id::Number(2),
                    worker: "account.rig".to_owned(),
                    password: "x".to_owned(),
                },
                1,
            )
            .expect("authorization begins")
            .expect("authorization action exists");
        let ConnectionAction::Authenticate(ticket) = action else {
            unreachable!("fixture must request authorization")
        };
        let result = actor.complete_authorization(
            ticket,
            Ok(
                AuthenticatedWorker::new(Uuid::from_u128(2), Uuid::from_u128(3), "account.rig")
                    .expect("worker identity is valid"),
            ),
        );
        assert!(matches!(
            result,
            Err(ConnectionActorError::OutboundQueueFull { maximum: 2 })
        ));
        assert!(actor.is_closed());
    }

    #[test]
    fn rate_limit_queues_standard_error_and_closes() {
        let mut actor = actor(8);
        actor.rate_limiter = RequestRateLimiter::new(
            crate::RateLimit::new(1, Duration::from_secs(1)).expect("rate is valid"),
            0,
        );
        actor
            .handle_request(
                Zip301Request::Subscribe {
                    id: Zip301Id::Number(1),
                    params: Vec::new(),
                },
                0,
            )
            .expect("first request succeeds");
        actor
            .handle_request(
                Zip301Request::ExtranonceSubscribe {
                    id: Zip301Id::Number(2),
                },
                1,
            )
            .expect("limit is reported");
        assert!(actor.is_closed());
        let error = actor.outbound.back().expect("error is queued");
        assert!(matches!(error, Zip301ServerMessage::Error { code: 20, .. }));
    }

    #[test]
    fn target_endianness_is_preserved_in_encoded_transcript() {
        let mut actor = actor(8);
        authorize(&mut actor);
        let mut transcript = Vec::new();
        while let Some(frame) = actor
            .pop_outbound_frame()
            .expect("message encoding succeeds")
        {
            transcript.extend_from_slice(&frame);
        }
        let text = String::from_utf8(transcript).expect("protocol output is UTF-8 JSON");
        let target = actor
            .binding()
            .expect("binding exists")
            .target()
            .to_zip301();
        assert!(text.contains(&target.to_string()));
        assert!(text.contains("\"mining.set_target\""));
        assert!(text.contains("\"mining.notify\""));
    }

    #[test]
    fn completed_response_slots_are_reused_beyond_capacity() {
        let mut actor = actor(2);
        for request in 0..10 {
            let slot = actor
                .store_response_id(Zip301Id::Number(request))
                .expect("a completed slot is reusable");
            assert_eq!(
                actor.take_response_id(slot).expect("stored id is present"),
                Zip301Id::Number(request)
            );
        }
        assert!(!actor.is_closed());
        assert_eq!(actor.response_ids.len(), 1);
    }

    #[test]
    fn idle_suggest_target_receives_safe_provisional_target() {
        let mut actor = actor_with_router(8, empty_router());
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        actor
            .handle_request(
                Zip301Request::SuggestTarget {
                    id: Zip301Id::Number(3),
                    target_be: ShareTarget::MAX.to_zip301(),
                },
                2,
            )
            .expect("suggestion is handled");
        assert!(matches!(
            actor.pop_outbound(),
            Some(Zip301ServerMessage::SetTarget { target_be })
                if target_be == actor.policy.initial_target.to_zip301()
        ));
    }

    #[test]
    fn same_session_unknown_share_ticket_closes_fail_closed() {
        let mut actor = actor(8);
        let result = actor.complete_submission(
            ShareTicket {
                session_id: actor.session.id(),
                ticket: 999,
            },
            Err(ShareRouterError::Overloaded),
        );
        assert!(matches!(
            result,
            Err(ConnectionActorError::CompletionTicketMismatch)
        ));
        assert!(actor.is_closed());
    }

    #[test]
    fn out_of_order_backend_completions_feed_vardiff_in_arrival_order() {
        let mut actor = actor(8);
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        let target = actor.binding().expect("vardiff is active");
        actor.pending_shares.insert(
            10,
            PendingShareState {
                response_id: None,
                target,
                admitted_at_ms: 10,
                vardiff_sample: None,
                expected_job_id: [1; 32],
                expected_share_id: [2; 32],
                expected_attribution_id: [3; 32],
            },
        );
        actor.pending_shares.insert(
            11,
            PendingShareState {
                response_id: None,
                target,
                admitted_at_ms: 20,
                vardiff_sample: Some(true),
                expected_job_id: [4; 32],
                expected_share_id: [5; 32],
                expected_attribution_id: [6; 32],
            },
        );
        actor.timing_order.extend([10, 11]);

        actor
            .drain_completed_timing()
            .expect("later completion waits for the earlier arrival");
        assert_eq!(actor.pending_shares.len(), 2);
        actor
            .pending_shares
            .get_mut(&10)
            .expect("earlier share exists")
            .vardiff_sample = Some(true);
        actor
            .drain_completed_timing()
            .expect("timestamps are observed in admission order");
        assert!(actor.pending_shares.is_empty());
        assert!(actor.timing_order.is_empty());
        assert!(!actor.is_closed());
    }

    #[test]
    fn replayed_completion_is_excluded_from_vardiff_timing() {
        assert!(!counts_toward_vardiff(true));
        assert!(counts_toward_vardiff(false));

        let mut actor = actor(8);
        authorize(&mut actor);
        while actor.pop_outbound().is_some() {}
        let target = actor.binding().expect("vardiff is active");
        let mut expected = actor.vardiff.clone().expect("vardiff controller exists");
        actor.pending_shares.insert(
            10,
            PendingShareState {
                response_id: None,
                target,
                admitted_at_ms: 10,
                vardiff_sample: Some(counts_toward_vardiff(true)),
                expected_job_id: [1; 32],
                expected_share_id: [2; 32],
                expected_attribution_id: [3; 32],
            },
        );
        actor.timing_order.push_back(10);
        actor
            .drain_completed_timing()
            .expect("replay completion drains without sampling");

        let actual_update = actor
            .vardiff
            .as_mut()
            .expect("vardiff controller remains active")
            .tick(100_001)
            .expect("clock advances");
        let expected_update = expected.tick(100_001).expect("reference clock advances");
        assert_eq!(actual_update, expected_update);
        assert_eq!(
            actor.vardiff.as_ref().map(VardiffController::binding),
            Some(expected.binding())
        );
    }

    #[test]
    fn pending_ticket_requires_its_exact_backend_receipt_identity() {
        let target = actor(8).policy.initial_target;
        let bounds =
            TargetBounds::new(target, target, ShareTarget::MAX).expect("fixture bounds are valid");
        let state = PendingShareState {
            response_id: None,
            target: TargetBinding::new(1, ShareTarget::MAX, bounds)
                .expect("fixture target is valid"),
            admitted_at_ms: 0,
            vardiff_sample: None,
            expected_job_id: [1; 32],
            expected_share_id: [2; 32],
            expected_attribution_id: [3; 32],
        };
        let mut receipt = ShareReceipt {
            event_seq: 1,
            job_id: Hex32::new([1; 32]),
            share_id: Hex32::new([2; 32]),
            attribution_id: Hex32::new([3; 32]),
            parent_hash_le: Hex32::new([4; 32]),
            winners: Vec::new(),
        };
        assert!(state.matches_receipt(&receipt));
        receipt.share_id = Hex32::new([9; 32]);
        assert!(!state.matches_receipt(&receipt));
    }
}

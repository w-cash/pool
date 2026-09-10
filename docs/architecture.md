# Pool architecture

> **Status:** This repository is a non-deployable phase-0 foundation. It has no
> public miner listener, authentication provider, PostgreSQL projection, payout
> engine, wallet integration, production image, or Wcash Testnet service.
> Passing unit tests is not evidence of deployment or network readiness.

## Authority and ownership

The pool and wolf have deliberately different responsibilities.

The pool owns miner-facing ZIP-301 connection state, worker authentication and
account mapping, externally leased nonce namespaces, per-miner share targets
and vardiff, the assignments advertised to each session, bounded
current/recent generation admission, and the future accounting projection and
payout policy. These are policy and bookkeeping responsibilities, not
consensus authority.

Wolf remains the sole authority for Wcash and Zcash template construction,
Equihash verification, comparison with both network targets, exact Wcash
candidate and coinbase binding, AuxPoW construction and validation, durable
accepted-share receipts, winner outboxes, and block submission. A pool policy
may reject a share before sending it to wolf. It may never accept, credit, or
promote a share that wolf rejected or did not durably acknowledge.

The Zcash template source is not trusted to validate its own proposal. Wolf
must retain the independent Zcash proposal-validation boundary described in
the Wcash merged-mining design.

## Intended data flow

1. Wolf obtains and validates exact Wcash and Zcash work.
2. Wolf publishes an immutable job generation through the versioned local
   backend protocol.
3. The pool binds that generation and a pool share target to each authorized
   ZIP-301 session before notifying its ASIC.
4. The pool reconstructs the full nonce and submits the raw Equihash solution,
   immutable job ID, exact four submitted header-time bytes, authenticated
   worker identity, and assigned share target to wolf.
5. Wolf recomputes the canonical parent-header hash and stable share ID,
   performs authoritative validation against the share target and both network
   targets, durably journals the result and any winners, flushes every live
   event through the response watermark, and only then returns a receipt.
6. The pool projects contiguous wolf journal events into PostgreSQL. A balance
   or payout state transition may reference a wolf receipt, but cannot replace
   it as evidence of acceptance.
7. Wolf owns retry of pending Wcash and Zcash winner submissions. The pool owns
   later reward attribution, maturity, reorg reversal, and payout policy after
   those facts are projected.

This is the target flow. No executable currently composes these steps.

## Implemented component status

| Component | Implemented now | Explicitly absent |
| --- | --- | --- |
| wcash-pool-protocol | Bounded four-byte big-endian backend framing; strict backend-v1 request, response, event, target-endian and identity types; exact candidate, coinbase, parent-header and stable share-ID bindings; strict LF-delimited ZIP-301 request and response codec; 4-byte and 8-byte nonce profiles | TCP/TLS listener, connection deadlines, rate limits, worker database, ASIC interoperability certification |
| wcash-pool-core | In-memory session ordering, immutable worker binding, externally namespaced nonce-prefix allocation, backend-generation lifetime separated from per-session target assignment, authoritative current/recent lifetime, bounded non-resurrectable generation tombstones, in-flight retirement fences, target policy, and integer vardiff including inactivity easing | Durable nonce-lease orchestration, durable generation-ID history, runtime composition, database persistence, crash recovery, network I/O, consensus validation |
| wcash-pool-backend-client | Timeout-bounded Unix-socket connection, strict handshake and identity checks, request correlation, job snapshot/event replay, transport-branded lifetime anchors, exact submitted header time, canonical submitted-proof and job-bound receipt checks, live response-watermark flush enforcement, a core-validated share adapter that owns the admission fence through backend I/O, branded share commits, health checks, and bounded unsolicited-event buffering | A compatible wolf server, cryptographic remote-peer authentication, production integration |
| wcash-pool-edge | Finite connection and queue policies, deterministic request limiting, ticket-bound authorization with exact miner-login binding, immutable session assignments, target-before-notify ordering, bounded global job fanout, replay-aware vardiff sampling, cancellation-safe serialized Wolf submissions, a bounded idle health/event pump with a mandatory acknowledged consumer seam, and global suspension on terminal backend/event-stream failure | TCP/TLS stream driver, authorization implementation, durable event-consumer/projector implementation, durable nonce leasing, public listener, certified ASIC transcript |
| wcash-poold | A machine-readable readiness command that exits not-ready | Serve command, miner/admin/metrics listeners, configuration, database, wallet, payout loop, deployment |
| Accounting | Protocol receipts and event shapes only | PostgreSQL schema and projector, balances, maturity, fees, rounding, reorg reversal, payouts |
| Operations | Hermetic source checks and test scaffolding | Container image, manifests, monitoring, backups, runbooks, private soak, public endpoint |

## Exact next wolf backend and journal requirement

The pool-side wire contract is implemented in wcash-pool-protocol, but the
matching server does not yet exist in wolf. Existing wolf command interfaces
and its private JSON-lines journal are not a substitute for this contract. The
next cross-repository change must expose the following adapter around wolf's
existing consensus coordinator and durable winner state.

### Transport and handshake

- Serve backend protocol version 1 over a permission-restricted Unix socket.
  The socket directory and inode must reject unauthorized users. A future TCP
  transport would require separate mutually authenticated credentials.
- Use exactly one four-byte big-endian length followed by at most 64 KiB of
  strict JSON. Reject empty, oversized, trailing, unknown-field, unknown-type,
  and unsupported-version messages before backend work.
- Require Hello as the first request. HelloOk must return distinct non-nil
  backend_session, stable backend_instance, and stable journal_stream IDs;
  exact Wcash and Zcash genesis hashes; the non-zero Wcash chain ID;
  domain-separated 32-byte commitments to the exact Wcash child and Zcash
  parent block-reward recipients; current journal sequence; and every required
  version-1 capability exactly once.
- Configure both payout commitments independently of the socket peer and require
  exact equality during Hello. A changed template recipient must therefore stop
  mining instead of silently redirecting either chain's rewards.
- Treat those IDs as consistency and replacement detection, not as
  cryptographic authentication. A changed backend instance or journal stream
  is an operator-visible reconciliation event, never an automatic reset.

### Job stream

- SubscribeJobs must atomically return a JobSnapshot at one journal watermark,
  followed by only later events on the same connection.
- Each JobDescriptor must be created by wolf and bind the exact 108 pre-nonce
  parent header bytes, the proof-independent Wcash candidate hash, explicit
  Wcash and Zcash predecessor hashes, the Wcash candidate and Zcash parent
  coinbase transaction IDs, separate little-endian Wcash and Zcash network
  targets, both heights, each chain's exact non-negative pool-recipient reward in
  zatoshi, each chain's immutable maturity requirement, a unique job ID, and a
  bounded maximum age.
- Snapshot current and recent entries must report remaining accept_for_ms from
  wolf's monotonic lease state. Reconnect must not restart a job's lifetime.
- JobActivated, JobInvalidated, and GenerationClosed events are authoritative.
  The pool owns which jobs remain advertised to each miner, but cannot extend
  wolf's acceptance window or turn a hard invalidation into grace.

### Share acceptance and idempotency

- SubmitShare carries the exact job ID, pool-authenticated account and worker
  identity, the share target actually assigned to that session, the exact four
  header-time bytes submitted by the miner, the complete 32-byte nonce, and the
  raw 1,344-byte Equihash solution.
- Wolf must re-derive and validate all consensus-bearing data. It must reject a
  target not allowed for that job and reject submitted time that is not exactly
  the frozen header time before independently classifying the result as an
  ordinary share, Wcash candidate, Zcash candidate, or both-chain candidate.
- Wolf derives the parent hash as SHA-256d over the exact
  `header_input || nonce || fd4005 || solution` bytes, where `fd4005` is the
  canonical CompactSize encoding of the 1,344-byte solution length. It derives
  the stable share ID as SHA-256 over
  `"wcash-pool/share-id/v1" || job_id || time || nonce || solution`. Worker
  identity and assigned target are excluded from that proof identity and form
  its immutable attribution fingerprint instead. Every receipt commits an
  attribution ID computed as SHA-256 over
  `"wcash-pool/attribution-id/v1" || account_uuid || worker_uuid ||
  label_length_be_u16 || label || target_le`. An identical proof with changed
  attribution is an `AttributionConflict`, not another share.
- Exact retries must resolve to the same stable share ID and byte-identical
  immutable receipt. Conflicting data must never reuse an identity. A replayed
  boolean belongs only to the correlated response envelope and reports an
  already durable result; it is not part of the receipt or an accounting key.
- Wolf must commit the accepted-share record and any winner outbox entries to
  durable storage before returning ShareCommitted or publishing its matching
  ShareCommitted journal event. A timeout remains unknown until replay or
  reconciliation proves the outcome.
- The immutable receipt binds its exact job ID, stable share ID, and parent
  header hash, then contains zero, one, or two exact winner descriptors in
  canonical Wcash-then-Zcash order. Each descriptor binds chain, block hash,
  height, coinbase transaction ID, non-negative pool reward, and maturity
  requirement. A Wcash winner hash and both chains' coinbase transaction IDs
  must match the originating job. A Zcash winner hash must equal the validated
  parent-header hash. Boolean candidate flags are insufficient evidence.
- The lower-level client submission API returns an explicitly unverified commit.
  Only `submit_prepared_share` can produce `VerifiedShareCommit`: before creating
  that brand it recomputes SHA-256d over the exact
  `header_input || nonce || fd4005 || solution`, recomputes the stable share ID,
  and checks the receipt job, parent hash, Wcash candidate, both coinbase IDs,
  and every winner's chain-specific height, reward, and maturity against the
  generation retained by `SubmissionContext`. Any mismatch poisons the backend
  connection and releases the admission fence without exposing branded success.

These generation-binding and winner-quarantine additions change the pre-Wolf
backend-v1 wire shape. The version remains 1 only because no Wolf backend-v1
server or deployed pool consumer exists; once version 1 ships, any further
incompatible change requires a new negotiated protocol version.

### Durable replay journal

- One stable journal_stream defines one non-reusable, contiguous event_seq
  namespace. The journal must persist job activation, invalidation, closure,
  accepted-share, `winner_observed`, `winner_orphaned`, Wcash-only
  `winner_quarantined`, Wcash-only `winner_requeued`, and `winner_matured`
  events and recover them after a crash.
- ReadEvents(after_event_seq, limit) must return a bounded contiguous page
  beginning at after_event_seq plus one, or an empty **complete** page with an
  unchanged cursor. An incomplete page must advance. A gap, duplicate sequence
  with different bytes, rollback, or stream identity change makes the pool stop
  issuing work.
- The atomic snapshot watermark and event replay must eliminate the
  snapshot/subscribe race. Reconnection from the last committed pool cursor
  must neither omit nor invent an event.
- Replay and live delivery are deliberately separate connection phases. The
  pool first uses a replay connection to project contiguous accounting events,
  then opens the live subscription. If SubscribeJobs returns a snapshot whose
  event_seq is ahead of replayed_through_event_seq, the snapshot is
  authoritative for mining state at that watermark but does not account for
  the missing interval. A separate replay connection must project
  `(replayed_through_event_seq, event_seq]` before credit or payout processing
  resumes; the subscribed connection cannot issue ReadEvents after entering
  live mode.
- Replayed JobActivated records are historical facts and must not create fresh
  acceptance leases. Only the atomic snapshot and later live delivered events,
  each anchored to a conservative monotonic lower bound captured no later than
  the preceding successful request boundary, may update the generation
  registry. This prior-boundary rule covers events already waiting in the Unix
  socket before the next heartbeat begins: transport and idle residency can
  shorten a lease, but can never extend wolf's remaining acceptance interval.
- The listener-free share actor owns the client and issues bounded health
  heartbeats between serialized submissions. It passes every queued live-event
  batch through a mandatory, timeout-bounded consumer before applying the batch
  to job policy; consumer failure or timeout globally suspends admission. This
  repository does not yet supply the durable consumer implementation.
- `HealthStatus.event_seq` is a live delivery barrier. Before returning health,
  wolf must send every missing live `Event` frame, in contiguous order, through
  that watermark on the same connection.
- A fresh `ShareCommitted` response has a stronger contract: its receipt
  sequence must advance past the pre-request cursor, and wolf must first deliver
  the exact `BackendEvent::ShareCommitted` containing the same receipt, job,
  worker identity, and issued target. A different event at that sequence cannot
  satisfy the barrier. An idempotent replay can become a branded success when
  that exact event is still queued or retained in the connection's bounded
  observed-event cache. While retained, every event kind also reserves its
  sequence and one stable share ID cannot name a different receipt or sequence.
  After reconnect or cache eviction, the client returns
  the complete receipt as `HistoricalReplayRequiresProjection`; it cannot become
  `VerifiedShareCommit` until the durable projector confirms byte-identical
  history. A concurrent exact replay at a future receipt sequence still has to
  be delivered before the response. Crossed, re-journaled, or contradictory
  outcomes poison the stream.
- Candidate receipts must be durable before acknowledgement, and wolf must
  retain and retry pending block submissions independently of the pool
  connection. HealthStatus must expose pending Wcash and Zcash winner pressure
  plus the Wcash-only quarantined subset; `quarantined_wcash` must not exceed
  `pending_wcash`.
- Winner lifecycle events repeat the immutable winner facts and identify the
  originating share and job. Observation and maturity events bind an exact
  best-chain tip and a confirmation count equal to
  `tip_height - winner_height + 1`; maturity additionally meets the winner's
  advertised chain-specific threshold. An orphan event binds the replacement
  best-chain tip. A Wcash witness conflict emits `WinnerQuarantined`; reward
  progression stops until exact-witness observation or `WinnerRequeued` records
  authoritative absence and releases the exact retained bytes for backend-only
  resubmission. Both transitions bind the sampled best-chain tip and are invalid
  for Zcash. The conflicting and retained block bytes stay in wolf's private
  durable journal rather than crossing the pool protocol. `GenerationClosed`
  closes share admission only and is never block acceptance, reward maturity,
  or payout evidence.
- Crash recovery, torn-tail handling, fsync ordering, journal locking, bounded
  growth or explicit rotation, and exact-retry behavior need deterministic
  wolf tests. Cross-repository golden frames must pin the pool and wolf to the
  same protocol revision.

This server should consume a released shared schema or hand-reviewed generated
types. A floating source dependency from the Internet-facing pool into the
entire wolf tree is not an acceptable boundary.

## Authentication and request ordering

Miner bytes and miner-supplied worker names are untrusted. A future listener
must bound and rate-limit a connection before parsing expensive submissions.
Subscription allocates one immutable nonce prefix inside a non-zero namespace
leased by durable orchestration. The in-process allocator serializes only local
threads: it cannot acquire or fence that lease, and its cursor must be persisted
before an allocated prefix is exposed. Successful pool authentication then
resolves a canonical account and worker identity. Only that resolved identity,
never an ID supplied by the miner, crosses the wolf boundary. A connection may
not switch identity after authorization. Until the authentication interface
supports an explicit alias set, the resolved canonical login must equal the
ZIP-301 authorization login byte for byte; otherwise authorization is denied.
Every later share must repeat that exact login.

A job is recorded in session state before its notification is written. A
submission is accepted for backend evaluation only if its login, job ID,
submitted header time, nonce profile, assigned target, and current/recent
lifetime match that immutable session state. Authorization and cheap policy
rejection happen before wolf is asked to verify Equihash.

Each session separately tracks the jobs its miner was allowed to retain across
`clean_jobs=false` notifications. A non-clean replacement is emitted only when
that session still has advertised work which is locally admissible and the
global stream has not hard-retired any cached job. A clean notification clears
the advertised lineage, but it does not discard authoritative assignments that
remain in Wolf's bounded grace window; those assignments can still validate
shares already in flight. If an activation was skipped or old work expired
while queued, the next notification is forced clean.

The current repository implements these state machines as libraries. It does
not implement the stream driver, listener, credential store, or their
orchestration. Per-session vardiff changes are installed on the next fresh Wolf
generation; changing a target on an already advertised immutable generation
would require a separate miner-facing job identifier and is not emulated. A
byte-identical durable retry observed on the current connection still returns
miner-facing success, but a branded commit whose response envelope says
`replayed=true` is excluded from vardiff timing so one proof cannot bias
difficulty more than once. A historical retry after restart remains
reconciliation-pending until the unimplemented projector confirms its exact
receipt; it is never reported as accepted merely because wolf says it was.

Retired generation IDs remain as bounded in-memory tombstones so reconnects
cannot reintroduce an old ID with a fresh lifetime. Exhausting that bound stops
new work instead of forgetting history. A long-running service therefore needs
durable, journal-scoped generation-ID history before this in-memory policy can
be used for a public endpoint.

## PostgreSQL projection and reconciliation

PostgreSQL will be a projection of wolf's accepted-share journal plus
pool-owned financial events; it will not be a competing consensus journal.
The projector must apply each wolf event and advance its cursor in one
transaction. At minimum, uniqueness must cover journal_stream plus event_seq
and the stable wolf share ID.

Only the journal event writes accounting state. For a fresh share, wolf sends
that exact event before the correlated response on the same live stream; the
response never races ahead of, upserts, or directly credits the ledger. The
response-only replayed boolean is discarded by the projection. On restart, the
pool sends its last committed cursor in Hello, verifies the same backend and
journal identities, reads contiguous pages, closes any gap to the subscription
snapshot watermark on a separate replay connection, and only then resumes
credit or payout processing. The same process-global JobRouter must be recovered
from the new snapshot so its deadlines and generation tombstones survive the
reconnect. Conflicting bytes for an existing key, a cursor ahead of wolf, or an
unexplained identity change halts new work and requires operator reconciliation.

The projector cross-checks the receipt job ID, Wcash candidate hash, both
coinbase transaction IDs, and every winner's height, reward, and maturity
against its JobActivated descriptor. A reward becomes spendable only from a
matching WinnerMatured event, never from a candidate flag, submission RPC
response, GenerationClosed, or locally sampled tip. WinnerMatured is not
finality: a later deep reorganization can emit WinnerOrphaned and must create
reversing ledger entries. Wolf must therefore retain enough durable winner
history to observe reorgs after maturity rather than deleting all tracking at
the maturity threshold.

The current listener-free share actor sends each bounded live-event batch to a
mandatory deployment-owned consumer before applying it to the in-memory job
registry, so job sequencing cannot silently advance beyond acknowledged event
delivery. This repository does not implement that durable consumer. A future
deployment must replay and transactionally project every journal sequence,
acknowledge a live batch only after its complete cursor is durable, and never
advance a durable accounting cursor from the in-memory job registry.

Balances, fees, rounding, and payout batches belong to a separate append-only
pool ledger derived from those events. That ledger and its database schema
have not been implemented.

## Failure behavior

Unknown protocol versions, inconsistent identities, event gaps, expired
snapshots, unavailable durable storage, backend timeouts, invalid template
attestation, and ambiguous accounting transitions all fail closed. The pool
stops issuing new work and raises an operator-visible error. Serving stale or
unaccountable work is not an availability fallback.

The implemented global suspension transition marks every live generation
unsynchronized without deleting immutable tombstones or already-held admission
guards. It notifies existing miner sessions and causes subscribers created
after suspension to close as well. The serialized share router invokes this
transition before returning a terminal backend result and on backend-task
cancellation, panic, shutdown, or unusable event delivery. Recovery requires a
fresh authoritative snapshot; suspension never makes stale work acceptable.

Public connections and rate-limit buckets may be ephemeral. Nonce namespace
leases and allocation cursors, accepted receipt projection, balances, payout
batches, and recovery cursors must be durable before they influence work or
money. The current in-memory core neither acquires distributed nonce leases nor
satisfies that deployment requirement by itself.

## Deployment boundary

The eventual runtime should use a non-root, read-only container with separately
mounted credentials and dedicated durable storage. Miner traffic is the only
public listener. Backend, database, metrics, admin, node, validator, and wallet
interfaces remain isolated and are not exposed by default. Payout signing keys
should stay outside the public pool process.

No image or endpoint should be published until the compatible wolf server,
PostgreSQL projection, full miner edge, durable accounting, restart recovery,
end-to-end merged-mining tests, and the gates in
[testnet-roadmap.md](testnet-roadmap.md) are complete.

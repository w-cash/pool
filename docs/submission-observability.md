# Submission diagnostics

The miner frontend records best-effort operational counters without changing
share admission, backend validation, original job/recovery authority, queue
sizes, retry deadlines, projection requirements, miner responses, accounting,
or payouts. It adds no backend RPC, proof hashing, database query, database
schema change, credential, public endpoint, or consensus rule. The authenticated
telemetry JSON gains additive fields.

The authenticated `GET /api/v1/telemetry` response retains its existing fields
and adds `process_instance_id`, `process_started_at`, and `diagnostics`. Each
worker also has a `diagnostics` object. Objects contain only nonzero fixed
counter names for that authenticated account's tracked workers. A missing key
means zero recorded observations in that retained worker entry; it does not
establish historical absence. The process identity changes on restart. Worker
entries use the existing 65,536-entry bound and disconnected-worker eviction;
eviction can also reset a worker's retained counters. New diagnostic updates
never wait for the worker-map lock and never create or evict worker entries.
A busy, poisoned or missing worker entry skips account attribution while the
atomic process observation and `account_observation_skipped` still advance.
Thus account diagnostics can undercount even while the process source is live.
An unavailable source
continues to report `available: false` with no successful empty-source claim.

Account categories cover decoded submits, admission failures, prepared ordinary
work, filtered recovery candidates, final submission outcomes, and returned
connection-driver outcomes. Local failures distinguish invalid job IDs, login,
unannounced job, immutable time, nonce profile, stale admission, unsynchronized
registry, request-rate and pending-capacity rejection. Busy, unhealthy, recovery
deferral, unavailable completion and projection failure are separate from the
existing `invalid` proof/request/difficulty aggregate. Returned driver outcomes
distinguish peer closure, local shutdown, actor closure, deadlines, transport,
protocol, actor and job-subscription failures. Unauthenticated observations
never appear in any account's snapshot.

## Process summaries

The existing portal-refresh loop offers one fixed JSON
`event=frontend_operational_summary` at startup and at most once per 60 seconds,
plus a final shutdown snapshot. Missed intervals never cause a catch-up burst.
A slow or failed refresh loop may delay summaries. One process-lifetime logging
thread writes these records to stderr through a capacity-two queue. Producers
use nonblocking enqueue and records are capped at 8 KiB, including the newline.
A full or disconnected queue, thread-spawn failure, oversized record, or write
error drops best-effort output without failing or delaying mining. Only the
logging thread may wait for stderr; startup, serving and final-summary calls
never wait for its I/O. Shutdown neither drains nor joins that thread, so even
the final snapshot may be lost at process exit. A blocked sink may retain one
record in the writer plus two queued records; it cannot accumulate an unbounded
backlog. No additional timer, RPC, metrics listener, automation, or per-share
log stream is created.

Summaries contain schema version 1, a process-counter identity/start time,
sample time, uptime, the existing aggregate connection totals, and a fixed
vocabulary of cumulative saturating `u64` counters. The complete current JSON
shape remains below 8 KiB even at saturated values. They contain no account or
worker identifiers, IP addresses, credentials, raw errors, request IDs, proof
hashes or solution bytes. Store and backend error messages never become labels.
They are private operational logs, not new public or account-global API data.
Keep them under the deployment's existing journal access and retention policy.

Process categories distinguish queue enqueue/full/closed, cancelled waiting and
lost response channels; ordinary/recovery backend attempts; verified new versus
replay receipts; new backend-declared WEC/ZEC winner receipts; timeout,
transport, validation and typed-rejection results; exact projection batch
verification, fixed retry subreasons, pause, recovery and deadline; and bounded
candidate retry scheduling, expiry, requalification and capacity outcomes.
These bounded summary counters distinguish authority mismatch, malformed
batch, conflicting bytes, storage rejection, projection lag, transient storage
failure and attempt timeout. Existing rare projection lifecycle logs remain
immediate at first pause and terminal rejection/deadline, using only fixed
`frontend_projection_lifecycle phase=... reason=...` labels without error bodies.
This preserves specific evidence when initial startup projection verification
fails before a router handle or periodic summary can exist. It adds no
per-attempt or per-share log stream.

## What the counters establish

`raw_zcash_recovery_candidate` counts only initial frontend recovery contexts
that passed the **existing cheap target-hash filter**. It excludes ordinary
work and payloads rejected before that filter. The frontend does not validate
Equihash here, does not inspect every discarded payload for a network target,
and does not turn a target match into a valid winner.

`backend_receipt_new` records an authenticated backend receipt after the
backend client's exact job/proof/attribution/winner binding checks. It is
recorded **before** mandatory event projection verification, because a
projection failure must not conceal that receipt. Backend-declared winner
receipt counters exclude replay. They rely on Wolf's validation authority and
are not independent Equihash or node-acceptance proofs. A dual-chain receipt
counts one declaration per chain. Receipt presence does not establish canonical
acceptance, maturity, reward allocation or payment.

`projection_batch_verified` requires the existing exact durable batch barrier.
`submission_accepted` is a final actor completion after the required barrier;
it is not proof that the miner received the TCP response. A write failure may
follow a durable commit. Replay and pending historical projection remain
separate and do not create a new winner count.

Timeout, EOF, caller cancellation or a lost response can leave completion
**unknown**: the backend may already have committed, and a caller's cancelled
wait does not cancel work already admitted to the backend actor. These counts
must not be described as rejected-before-durable proofs, lost winners, or
reasons to resend an ambiguous proof. No retry policy changes here.

Counters describe observations at different stages and can overlap; they are
not an exhaustive, mutually exclusive request ledger. Concurrent snapshots are
not transactional. Crashes, cancelled driver futures, tracking eviction and
process restart can lose observations. No rejected payload history is retained.
The counters cannot reconstruct earlier gaps, establish usable historical ZEC
work, physical miner efficiency, maximal profitability, or a luck-only account
of a mining drought.

## Frontend startup readiness

Frontend startup uses the same fixed 120-second backend-readiness budget and
250-millisecond retry spacing as preflight. A missing or expired current job,
a typed unhealthy-backend refusal, or a narrowly classified temporary socket
failure keeps this startup attempt waiting. Every retry opens a fresh backend
connection, repeats durable replay verification and obtains a new snapshot.
Startup requires authenticated healthy status, no queued unverified events and
a current unexpired generation before it claims a nonce namespace or constructs
the share actor. No public listener or spending authority exists during this wait.
The additional health probes are bounded startup reads, not per-share work.

Permission, configuration, identity, protocol/framing, sequence, replay,
projection, database, target-policy and nonce-cleanup failures remain fatal;
they are not retried as availability problems. A stalled attempt or repeated
temporary refusal cannot extend the total readiness budget. Timeout still
returns a startup failure, so this reduces rapid service-manager refusal loops
without promising that an unavailable backend never causes a process exit.

The running share actor retains its existing two-minute unhealthy watchdog,
admission pause, exact recovery permission, event projection and bounded
shutdown behavior. Payout and projector runtime policies are unchanged. No
wallet, signing, payout, accounting, database-schema or consensus rule changes.

## Verification scope

Path-level tests use the real actor, queue, backend client and stream driver
with bounded disposable loopback/Unix peers. They check local/service
categories, cancellation versus response loss, exact receipt-before-projection
ordering, delayed and expired projection, idempotent replay, and driver
failures without changing existing response transcripts. An actual initial-drain
failure captures the logger's fixed terminal labels before startup returns an
error; it does not claim operating-system journal persistence. Synthetic targets and
programmed backend receipts are explicitly not a consensus emulator or an ASIC
acceptance test. Account isolation, fixed labels, counter saturation, retained
worker bounds, unavailable sources and worst-case summary size are checked
separately. Summary tests exercise the actual periodic/final enqueue paths with
healthy, broken-pipe, blocked, disconnected and spawn-failed writers. Test-owned
writer threads are released and joined; this does not establish operating-system
journal persistence. Existing MR42 queue and authority regressions remain required.

Startup tests exercise the production readiness wait, typed retry policy and
snapshot-health gate with a real framed Unix backend client, including reconnect,
unhealthy status, journal identity rejection, queued events and lease expiry
during health I/O. Their peer uses programmed snapshots and empty replay pages:
they do not exercise PostgreSQL, full listener startup, signer construction or
chain consensus. Existing live-actor tests separately retain the fixed unhealthy
deadline, admission suspension, recovery queue and projection/durable-receipt
contracts; these are not claims of uninterrupted mining during backend failure.

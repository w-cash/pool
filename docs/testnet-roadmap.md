# Testnet roadmap

> **Current state: phase-0 libraries only, not deployable.** Strict protocol,
> in-memory policy, Unix backend-client, and listener-free miner-edge actors
> exist. There is no public miner listener, compatible wolf backend-v1 server,
> service-composed accepted-share path, PostgreSQL projection, payout engine,
> production image, or Wcash/Zcash endpoint. Passing source CI does not make
> this pool Testnet- or production-ready.

| Phase | Current status |
| --- | --- |
| 0 — Repository foundation | Implementation present; clean-clone CI evidence is still required on the release commit |
| 1 — Wolf backend API | Blocked: pool-side v1 contract and client exist, matching wolf server and cross-repository vectors do not |
| 2 — Miner protocol edge | Partial: strict ZIP-301 codec and policy state machines exist; network listener, TLS, auth provider, limits, and ASIC transcripts do not |
| 3 and later | Not implemented |

Each phase has an explicit exit gate. Work may be prototyped in parallel, but a
later phase cannot be called complete until every earlier gate is evidenced on
the exact release commit.

## Phase 0 — Repository foundation

Deliverables:

- pinned Rust workspace and committed lockfile;
- formatting, lint, deterministic test, documentation, dependency, and
  workflow-security checks;
- ownership, contribution, disclosure, architecture, and threat-model policy;
- an executable that clearly refuses deployment rather than opening a miner
  port.

Exit gate: all repository checks pass from a clean clone, and documentation
contains no claim that a testnet service exists.

Current note: the workspace contains these deliverables, including a
readiness-only executable that opens no port. Phase 0 is not declared complete
until the exact committed revision passes the clean-clone checks.

## Phase 1 — Freeze the wolf backend API

This is the next cross-repository blocker. The pool-side backend-v1 wire types
and Unix client now exist, but `w-cash/wolf` does not expose their matching
server. Wolf must adapt its existing coordinator and durable journal rather
than asking this repository to duplicate consensus logic.

Required wolf gates:

- permission-restricted Unix transport using the exact bounded four-byte
  big-endian backend-v1 framing;
- Hello-first negotiation of distinct backend session, stable backend
  instance and journal stream, Wcash and Zcash genesis identities, Wcash chain
  ID, exact Wcash and Zcash payout-recipient commitments, and the complete
  capability set;
- immutable jobs binding a unique job ID, exact 108-byte parent header input,
  proof-independent Wcash candidate hash, explicit Wcash and Zcash
  predecessors, the Wcash candidate and Zcash parent coinbase transaction IDs,
  endian-typed targets, both heights, each chain's exact non-negative reward and
  maturity requirement, maximum age, and snapshot remaining lifetime;
- independently validated Zcash proposal attestation before a job is released;
- share submission bound to the exact job, pool-authenticated account and
  worker, issued target, exact submitted header time, full nonce, and raw
  Equihash solution, with Wolf requiring time equality against the frozen job;
- stable share IDs computed as SHA-256 over
  `"wcash-pool/share-id/v1" || job_id || time || nonce || solution`, plus
  exact-retry receipts; identity and target remain an immutable attribution
  fingerprint committed by the domain-separated canonical attribution ID, so
  changing either for the same proof is rejected rather than credited twice;
- canonical SHA-256d parent hashes over the exact
  `header_input || nonce || fd4005 || solution`, independently recomputed by
  the pool client before a backend response can become a branded commit;
- accepted-share attribution and both winner outboxes durable before
  acknowledgement; receipts bind the exact job and parent header hash, while
  winner descriptors bind chain, block, coinbase transaction, reward, and
  maturity back to the originating job;
- an atomic current/recent snapshot followed by authoritative job activation,
  invalidation, generation-closure, share-commit, winner-observed,
  winner-orphaned, Wcash-only winner-quarantined, Wcash-only winner-requeued,
  and winner-matured events;
- one stable, contiguous, replayable journal sequence with bounded ReadEvents
  pages and fail-closed stream identity;
- a separate replay connection that closes any accounting gap through the
  atomic subscription-snapshot watermark before credit or payout resumes;
- conservative pre-I/O monotonic anchoring for snapshot and live relative
  lifetimes, including a prior-exchange lower bound for events prequeued during
  socket idle time, with historical replay events unable to renew a job lease;
- bounded live health heartbeats (or a dedicated event reader) that continuously
  drain queued events and fail closed on a gap;
- response flushing: before `HealthStatus`, wolf sends every missing live event
  contiguously through that response's watermark; before a fresh
  `ShareCommitted`, it sends the exact matching receipt/job/identity/target
  event at a sequence newer than the pre-request cursor; the pool client rejects
  and poisons unflushed or crossed responses;
- crash recovery that preserves decoded/in-flight submissions and pending
  Wcash or Zcash winners, retains observation after maturity for deep-reorg
  reversal, reports health for both outboxes, and exposes the quarantined Wcash
  subset without silently treating it as ordinary retry pressure;
- reconnect recovery through the existing process-global JobRouter so local
  deadlines, terminal generation tombstones, and watermark history cannot be
  reset by constructing a replacement router;
- a durable projected-receipt lookup which turns a cache-miss historical replay
  into a verified result only after every receipt byte and attribution key match;
- fixed cross-repository golden frames and a compatibility document tied to an
  exact wolf commit.

Exit gate: wolf CI covers each item, including torn-tail and response-loss
recovery; the two repositories pass the same golden vectors; a tagged or
commit-pinned specification exists; and an independent reviewer confirms that
the pool cannot bypass wolf's consensus validation.

## Phase 2 — Strict miner protocol edge

Deliverables:

- bounded ZIP-301 framing and strict JSON/message validation (codec
  implemented; listener integration pending);
- TLS, subscription, authorization, worker identity, clean disconnect, and
  backpressure;
- exact login binding: until aliases are explicitly represented, authentication
  succeeds only when its canonical login byte-for-byte matches the authorized
  ZIP-301 login, which every share must repeat;
- immutable per-session job assignment and share difficulty, separated from
  the global backend-generation lifetime;
- conservative vardiff with minimum/maximum bounds and no influence on network
  targets, including a bounded inactivity tick for zero-share workers;
- replay-aware share timing so an idempotent backend receipt cannot count twice
  toward a miner's vardiff estimate;
- process-global generation suspension before terminal backend results are
  exposed, including backend/event-stream failure, unhealthy responses,
  cancellation, panic, and shutdown;
- a stream-level pause or disconnect when the last advertised job retires and
  no replacement is immediately available;
- a durable external lease authority for non-zero nonce namespaces and cursors;
- rate limits before expensive parsing, hashing, or backend work;
- deterministic protocol transcripts for supported ASIC behavior.

Exit gate: truncation, oversize, trailing-data, slow-client, flood, replay,
wrong-session, wrong-job, and disconnect races are covered without live nodes.

Current note: deterministic codec, bounded connection/session actors, global
job fanout and suspension, exact-login policy, replay-aware vardiff, request
limiting, cancellation-safe submission serialization, and a bounded idle
health/event pump with a mandatory consumer seam cover only the library layer.
There is no durable event-consumer implementation, stream driver, socket
listener, TLS termination, credential implementation, durable nonce lease, or
certified ASIC transcript yet.

## Phase 3 — End-to-end job and share lifecycle

Deliverables:

- backend handshake and fail-closed compatibility checks;
- template distribution, tip rotation, stale-work policy, late-share grace,
  duplicate suppression, and bounded retry;
- exact durable mapping from accepted backend receipt to worker attribution;
- child-only, parent-only, both-target, ordinary share, invalid proof, and
  ambiguous transport outcomes;
- cross-generation, crossed-nonce, crossed-solution, candidate-hash, coinbase,
  stable-share-ID, and parent-header-hash substitution failures;
- graceful shutdown and restart reconciliation;
- durable journal-scoped generation-ID history beyond the deliberately bounded
  in-memory tombstones, without ever reclaiming capacity by forgetting safety
  state.

Exit gate: deterministic integration tests exceed 16 unsolved or parent-only
rotations, exercise candidate retirement, inject connection loss at every
submission stage, and prove no accepted share is lost or credited twice.

## Phase 4 — Durable accounting and test payouts

Deliverables:

- append-only double-entry or equivalently conserved ledger;
- transactional uniqueness for shares and backend receipts;
- independent Wcash and Zcash reward maturity and reorg reversal;
- explicit fee, rounding, dust, minimum payout, and adjustment rules;
- idempotent payout batches with an isolated wallet/signer boundary;
- backup, restore, schema migration, reconciliation, and operator audit tools.

Exit gate: crash-after-every-write, duplicate, reorg, rounding, conservation,
backup/restore, and payout-retry tests pass. Testnet payouts use test funds only
and can be suspended without losing ledger state.

## Phase 5 — Isolated local merged-mining system

Run a pinned topology containing:

- a Wcash Testnet node;
- a modified Zcash template node;
- a separate Zcash proposal-validating node;
- the wolf mining backend;
- this pool;
- deterministic miner simulators and, separately, a supported Equihash ASIC.

The ordinary required GitHub workflow remains hermetic and does not solve
Equihash or contact public nodes. Fixed valid proofs cover CI paths; resource
intensive solving and real-process scenarios run as explicit local/release
gates with captured artifacts.

Exit gate: the exact release candidates demonstrate ordinary accepted shares,
Wcash-only and Zcash-only targets, a dual winner, block submission, maturity,
reorg reversal, payout, restart recovery, stale work, and dependency loss.

## Phase 6 — Private Testnet soak

Deliverables:

- non-root read-only image with pinned bases and a mandatory durable volume;
- isolated miner, backend, node, database, metrics, admin, and wallet networks;
- dashboards and alerts for job age, rejection reason, backend queues, winner
  outboxes, ledger conservation, payout state, and node divergence;
- encrypted backups with a completed restore drill;
- load, abuse, network-partition, node-failover, disk-full, and clock-skew tests;
- incident response, credential rotation, and rollback runbooks.

Exit gate: a sustained private soak has no unexplained accounting difference,
lost winner, duplicate payout, unbounded queue, or unresolved critical alert.

## Phase 7 — Public Wcash Testnet

Before publishing an endpoint:

- close every critical threat-model finding;
- complete independent security and accounting review;
- publish the exact compatible wolf and pool revisions;
- produce immutable images, SBOMs, provenance, signatures, and checksums;
- document supported ASIC configuration, TLS identity, test-only addresses,
  payout rules, maturity, status reporting, and support channels;
- make clear that all balances and payouts are valueless test data.

Exit gate: a signed release checklist records the evidence and named reviewers.
Only then may documentation describe the pool as Wcash Testnet-ready.

## Mainnet

Mainnet is not a phase that follows automatically from Testnet. It requires a
separate launch decision, frozen consensus and backend interfaces, a long
public soak, independent audits, operational redundancy, key-management
review, and a new release gate. Nothing in this roadmap creates or authorizes a
mainnet pool.

# Threat model

> **Status:** This document describes the security target for a non-deployable
> foundation. It is not an audit, a proof of security, or permission to use the
> current repository with miners or funds.

Implemented controls are limited to strict bounded wire codecs, redacted
secret-bearing debug output, endian-distinct target types, exact job/proof
receipt bindings, in-memory session/job/nonce/vardiff policy, global
generation suspension, finite listener-free connection actors, a
timeout-bounded Unix backend client, and a bounded idle health/event pump with
a mandatory acknowledged consumer seam, all tested with local mock peers.
There is no durable event-consumer implementation, stream driver, public
listener, authentication implementation, pool database, payout code, wallet,
deployment, or live-node test. Every operational control below remains a
release requirement unless it is explicitly identified as implemented.

## Assets

The system must protect:

- exact Wcash and Zcash job provenance;
- accepted-share attribution and worker balances;
- winning shares until both applicable chains reach a terminal result;
- payout journals, maturity state, and funds;
- node, backend, database, and monitoring credentials;
- miner credentials and privacy-sensitive operational metadata;
- service availability without weakening validation.

## Trust boundaries and adversaries

All miner connections and their bytes are hostile. A miner can open many
sessions, submit malformed or duplicated data, replay prior work, lie about
capabilities, withhold blocks, and tune timing to race job rotation.

The public network, TLS terminator, DNS, and system clock are not sources of
consensus truth. Operators can misconfigure networks, endpoints, targets,
credentials, fees, maturity, and storage. Dependencies, CI actions, container
bases, and release artifacts can be compromised.

Wolf is the sole consensus authority, after an exact version/network handshake
over a locally access-controlled transport. Backend session, instance, and
journal IDs detect configuration changes; they are not cryptographic peer
authentication. A separate Zcash validator is required to check parent
proposals, because the template source is not trusted to attest its own output.
The future pool database is trusted to persist and project bytes, not to invent
valid wolf receipts.

## Primary threats and required controls

### Malformed protocol input and resource exhaustion

The implemented codecs bound backend and ZIP-301 frames, fixed-size fields,
Equihash solutions, event pages, and relevant strings; they reject trailing,
unknown, and non-canonical backend encodings before policy use. The backend
client enforces configured connection and request deadlines.

The future public listener must additionally enforce accept, TLS,
authentication, request, write, and idle deadlines plus per-IP, per-account,
and global concurrency and byte budgets before expensive hashing or backend
calls. Those listener controls do not exist yet.

Required tests include truncation at every byte boundary, oversized lengths,
invalid UTF-8 where applicable, trailing bytes, slow reads, request floods,
and cancellation under saturated queues.

### Job substitution, target manipulation, and stale work

Only the protected and identity-checked wolf connection may originate a job.
Implemented policy keeps Wolf's immutable backend generation and lifetime
separate from each session's assigned share target. A submission is evaluated
against that exact assignment, not the miner's claimed difficulty or another
session's target.
Each generation also binds the proof-independent Wcash candidate hash and the
Wcash candidate and Zcash parent coinbase transaction IDs. A receipt must repeat
the exact job ID; a Wcash winner and either chain's winner coinbase must match
those frozen facts. Reusing an ID with changed candidate bytes is a protocol
conflict.
Per-session advertised lineage prevents a coalesced activation, local expiry,
or hard retirement from incorrectly reusing `clean_jobs=false`; grace-eligible
assignments remain available only for bounded late-share validation.
Unknown, retired, cross-session, and wrong-network identifiers must fail
closed. End-to-end enforcement still depends on the missing wolf backend-v1
server and service integration.

The authentication result is also session state, not a hint. Until an explicit
alias set exists, its canonical login must byte-for-byte equal the login in the
successful ZIP-301 authorization, and every submitted share must repeat that
exact login. A normalized or substituted login is rejected rather than silently
mapped to another account or worker.

The current core retains bounded terminal generation tombstones and rejects ID
resurrection, descriptor substitution, and same-watermark role changes. It
fails closed when that history fills. Durable journal-scoped ID history is
still required for a long-running deployment; restarting or replacing the
in-memory registry is not a safe way to reclaim this bound.

### Nonce namespace collision across replicas

An in-process monotonic counter cannot fence another pool replica or a restarted
process. Durable orchestration must exclusively lease one of the non-zero
namespaces to each active allocation stream, persist its next cursor before a
prefix is exposed, and prevent reuse until every generation containing prefixes
from the prior lease is permanently closed. The implemented allocator encodes
the profile and namespace to keep 4-byte, 8-byte, and replica streams disjoint,
but deliberately does not claim to provide that external lease authority.

### Replay and duplicate credit

Wolf must derive the stable share identity as SHA-256 over
`"wcash-pool/share-id/v1" || job_id || time || nonce || solution`, then bind it
to worker identity and assigned target in its durable journal and receipt using
the domain-separated canonical attribution ID. Identity and target are
deliberately not part of the proof ID: changing either for the same proof is an
`AttributionConflict`. Repeating the exact proof and attribution
must return the byte-identical prior receipt without creating another journal
event, credit, or block submission. Only the response envelope is marked
replayed.
Connection-local request IDs correlate responses only; neither they nor the
replay marker are durable accounting keys.
An idempotently replayed receipt remains a successful miner response, but the
implemented connection actor excludes it from vardiff timing samples. Otherwise
one proof retried many times could manipulate the worker's future share target.
That success requires the exact commit event to remain queued or in the bounded
connection-local observed-event cache. While retained, all event kinds reserve
their sequence and the same stable share ID cannot be re-journaled with changed
receipt bytes or a new sequence. After reconnect or cache eviction, the full
receipt remains reconciliation-pending until the durable projector confirms it;
the current code intentionally cannot brand or acknowledge that historical replay.

In-memory duplicate filters are an optimization only. Correctness comes from
wolf's stable durable receipt and from transactional uniqueness on
journal_stream plus event_seq and share_id in the future PostgreSQL projection.
After ambiguous delivery the pool replays wolf's journal before deciding
whether to resubmit or credit.

The live job snapshot can have a watermark ahead of the pool's last projected
accounting event. The snapshot may restore mining state, but it must never be
used as evidence that the intervening shares were credited. Before balances or
payouts resume, a separate replay connection must read and transactionally
project that complete interval; ReadEvents is intentionally unavailable after
a connection enters live subscription mode. Historical JobActivated events do
not renew acceptance leases, and every relative live or snapshot lifetime is
anchored before transport so delay cannot make work valid longer than wolf did.
For live events the client carries forward the prior successful exchange's
request-start anchor; an activation that waited in the socket during an idle
period therefore loses that idle time rather than gaining a fresh lease.

The current client queues unsolicited live events only while completing
bounded requests. Its single-owner actor sends periodic health requests and
passes each queued batch through a mandatory timeout-bounded consumer before
job policy observes it. Consumer failure or timeout fails closed; no durable
consumer implementation exists yet. Before `HealthStatus`, wolf must send every
missing live event contiguously through the response watermark on the same
connection. Before a fresh `ShareCommitted` response, it must deliver the exact
matching share event, including receipt, job, immutable worker identity, and
issued target. The client rejects an unflushed future sequence, a fresh receipt
that does not advance, or any different event at the claimed sequence. These
are accounting-omission and attribution risks, not health signals. Any such
failure globally suspends generation admission and notifies both established
and future miner sessions to close.

### Rotation races and withheld late shares

Closing a miner connection or rotating either chain tip must not silently
destroy a valid Wcash or Zcash result. Wolf publishes authoritative
invalidation and generation-closure events. The pool stops advertising that
generation and its in-memory admission lease fences already started
submissions until they finish. The implemented backend adapter owns that fence
through the complete asynchronous request, including timeout and cancellation.
Wolf retains consensus resources and pending winner outboxes independently of
the pool connection. A same-ID, different-AuxPoW Wcash witness must enter an
explicit durable quarantine, and exact-byte replay can resume only after a
`WinnerRequeued` event records authoritative best-chain absence. Backend
protocol v1 has
no pool-controlled retirement capability, so documentation and code must not
invent one.

Soak tests must exceed cache capacity with unsolved and parent-only rotations,
cover late child winners, and inject transport loss at every retirement and
submission boundary.

### False acceptance and parent-template fraud

The pool does not implement authoritative Equihash, AuxPoW, exact-witness, or
network-target validation. The backend recomputes all of them. Before work is
advertised, an independent Zcash node validates the proposed parent block;
before credit, the backend validates the returned proof against the immutable
job.

No success string, HTTP status, or template-provider response is sufficient by
itself. Structured outcomes and exact identifiers are required.
Before exposing a branded commit, the pool client independently recomputes the
stable share ID and SHA-256d parent hash over
`header_input || nonce || fd4005 || solution`, then checks receipt job identity,
Wcash candidate hash, both coinbase IDs, and reward facts against the retained
generation. A mismatch poisons the backend connection rather than degrading to
an unverified credit.

### Crash, retry, and partial-write corruption

Wolf accepted shares and winner submissions must use its transactional journal
and outboxes before acknowledgement. Future pool balance mutations, maturity
changes, and payout batches require separate transactional storage. On startup
the pool must verify backend and journal identity, replay contiguous events
from its last committed cursor, and complete or roll forward interrupted
projection transitions before issuing work. That PostgreSQL path is not
implemented.

Tests terminate processes after each durable step, corrupt or truncate copies
of state, repeat messages, and verify conservation of balances. A timeout is an
unknown result to reconcile, never evidence of failure.

The implemented share router globally suspends generation admission before it
exposes a terminal backend or event-stream result. Its cancellation and panic
guards suspend before queued callers lose their response channels, and normal
shutdown suspends before closing the queue. Suspension retains immutable job
tombstones and already-held admission guards but rejects every new share and
notifies both existing and later miner sessions to close.

### Chain reorganizations and immature rewards

Every job and winning-share receipt binds the exact generation, the
proof-independent Wcash candidate hash, the Wcash candidate and Zcash parent
coinbase transaction IDs, and independent Wcash and Zcash reward amounts and
maturity requirements. The backend journal must then emit typed observed,
orphaned, and matured transitions keyed by the exact share, job, chain, block
hash, and height. Observation and maturity bind a same-snapshot best-chain tip
and exact confirmation depth. The pool must not infer any of these monetary
facts from job closure, candidate booleans, wall-clock age, or an
unauthenticated node query.

The future accounting engine keeps blocks and credits immature until the typed
maturity event. Reorganizations produce explicit reversing entries; history is
not edited in place. Maturity is spendability policy, not proof-of-work
finality, so a deep reorganization after maturity remains a valid orphan
transition and can reverse a paid reward into debt or an operator loss.
Consequently wolf must retain durable post-maturity observation state. Parent
and child maturity are tracked independently, and payouts cannot spend
unconfirmed or unreconciled balances. No accounting or payout implementation
exists today.

### Credential and payout compromise

Implemented wire request debug output redacts passwords, nonce material,
worker attribution in share submissions, and full Equihash solutions. The
future service must also keep secrets out of command lines, logs, metrics,
panic messages, repository files, and container layers; separate node
credentials; and enforce restrictive socket and credential-file permissions.
Constant-time comparison is required where equality itself is
security-relevant.

The preferred design keeps signing keys out of the public pool process. Before
automated payouts, define withdrawal limits, an approval or isolated signer
boundary, key rotation, emergency suspension, and a complete audit trail.

### Accounting fraud and operator mistakes

The future PostgreSQL projection must make every balance change an append-only,
typed event referencing its source wolf receipt, block, adjustment, or payout.
Conservation checks must run continuously. Fees, rounding, dust handling,
maturity, and payout cadence must be explicit and versioned. Administrative
adjustments require a reason and cannot delete history.

Configuration validates network identities and rejects unsafe defaults. A
Wcash Testnet process cannot silently connect to Zcash Mainnet, and no
configuration alias can turn a test balance into a mainnet balance.

### Supply-chain and release compromise

Cargo uses a committed lockfile. Repository policy checks advisories, licenses,
sources, bans, formatting, lints, tests, documentation, and workflow security.
GitHub Actions are pinned to full revisions and workflows use minimal token
permissions. There is no container base or published image to make a container
pinning claim about yet.

Before distributing an image, releases require reproducible-build evidence,
an SBOM, provenance, vulnerability scanning, immutable tags, and independent
verification of the source revision.

### Privacy leakage

A future TLS listener can protect miner bytes in transit, but timing, IP
addresses, worker names, pool shares, and transparent payout addresses still
reveal metadata. Logs and metrics must use bounded opaque identifiers and
exclude credentials or full solutions by default. Retention and operator
access must be documented before public Testnet. No TLS listener or operational
logging policy exists in the current binary.

Shielded Wcash rewards do not make the pool's database, network telemetry, or
Zcash payout path private. Privacy claims must state these limitations.

## Explicit non-goals

This pool does not make a malicious operator trustless, replace independent
node validation, secure an already compromised host, hide public network
metadata, or guarantee mainnet readiness from testnet success. It does not
change Wcash or Zcash consensus.

## Security gate

Public Testnet requires all critical controls above to have deterministic
tests, operational monitoring, documented incident response, and review by
someone other than the author. Mainnet requires a separate decision, extended
soak testing, and an independent security and accounting audit.

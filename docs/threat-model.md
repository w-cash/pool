# Threat model

> **Status:** This document describes the security target for a non-deployable
> foundation. It is not an audit, a proof of security, or permission to use the
> current repository with miners or funds.

Implemented controls are limited to strict bounded wire codecs, redacted
secret-bearing debug output, endian-distinct target types, in-memory
session/job/nonce/vardiff policy, and a timeout-bounded Unix backend client
tested with local mock peers. There is no public listener, authentication
provider, durable pool database, payout code, wallet, deployment, or live-node
test. Every operational control below remains a release requirement unless it
is explicitly identified as implemented.

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
Unknown, retired, cross-session, and wrong-network identifiers must fail
closed. End-to-end enforcement still depends on the missing wolf backend-v1
server and service integration.

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

Wolf must derive a stable share identity from the immutable job and canonical
submission, including its exact submitted header time, and bind it to worker
attribution in its durable journal. Repeating the exact submission must return
the byte-identical prior receipt without creating another journal event, credit,
or block submission. Only the response envelope is marked replayed.
Connection-local request IDs correlate responses only; neither they nor the
replay marker are durable accounting keys.

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

The current client queues unsolicited live events only while completing
bounded requests. Until a dedicated reader exists, the runtime must send
periodic health requests and drain that queue. Failing to do so is an
accounting-omission risk and must stop new work rather than permit payout from
an incomplete projection.

### Rotation races and withheld late shares

Closing a miner connection or rotating either chain tip must not silently
destroy a valid Wcash or Zcash result. Wolf publishes authoritative
invalidation and generation-closure events. The pool stops advertising that
generation and its in-memory admission lease fences already started
submissions until they finish. The implemented backend adapter owns that fence
through the complete asynchronous request, including timeout and cancellation.
Wolf retains consensus resources and pending
winner outboxes independently of the pool connection. Backend protocol v1 has
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

### Chain reorganizations and immature rewards

The future accounting engine must keep blocks and credits immature for a
configured confirmation policy. Reorganizations must produce explicit
reversing entries; history is not edited in place. Parent and child maturity
are tracked independently, and payouts cannot spend unconfirmed or
unreconciled balances. No accounting or payout implementation exists today.

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

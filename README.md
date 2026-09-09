# Wcash Pool

This repository is the phase-0 engineering foundation for a future
Wcash/Zcash merged-mining pool. It is not a running pool and is not ready for
public miners, Wcash Testnet, or funds of value. The only executable currently
reports `ready: false`; it has no `serve` command and opens no listener.

## Responsibility boundary

The pool is intended to own long-lived ZIP-301 miner sessions, worker
authentication, externally leased nonce namespaces, per-miner share targets
and vardiff, miner-facing job assignment, and the PostgreSQL accounting
projection. None of those policy decisions can establish consensus validity.

The `wcash-merge-miner` backend in
[`w-cash/wolf`](https://github.com/w-cash/wolf) remains the sole authority
for template construction, Equihash validation, Wcash and Zcash network-target
classification, AuxPoW construction, durable accepted-share receipts, winner
outboxes, and block submission. The pool must fail closed when that authority
is unavailable or its identity is inconsistent.

## Implementation status

| Area | Current phase-0 state |
| --- | --- |
| Wire protocol | Strict, bounded backend-v1 and ZIP-301 codecs; jobs bind the Wcash candidate hash and both chains' coinbase transaction IDs; canonical parent-header and stable share-ID derivations, exact dual-chain reward facts, and reversible winner-lifecycle events have deterministic positive and negative tests |
| Pool policy | In-memory session ordering with exact authorized-login reuse, externally namespaced nonce-prefix allocation, backend-generation lifetime separated from per-session target assignment, bounded non-resurrectable generation tombstones, retirement fences, endian-typed targets, and integer vardiff that excludes idempotently replayed receipts |
| Backend client | Timeout-bounded Unix-socket client, identity/capability handshake, event replay, transport-branded lifetimes, submitted-header-time preservation, canonical proof/receipt/attribution binding, live response-watermark flush enforcement, bounded all-event sequence and share-identity evidence, and a fenced core-to-backend share path tested against local mock peers |
| Miner edge | Listener-free bounded actors for connection admission, request rate, authorization tickets, immutable per-session jobs, global job fanout, serialized Wolf share submission, and global fail-closed suspension on terminal backend-stream failure; no TCP/TLS stream driver or credential implementation |
| Service process | Readiness-only command; no miner or administrative listener |
| Persistence and money | No PostgreSQL projection, balance ledger, maturity tracking, payout engine, wallet integration, or signing |
| Wolf integration | The matching backend-v1 Unix-socket server, durable replay journal, and response-watermark event-flush contract are not implemented in wolf |
| Operations | No production container, deployment manifests, public endpoint, private soak, or release readiness |

The next blocking change is the wolf backend and journal contract described in
[the architecture](docs/architecture.md#exact-next-wolf-backend-and-journal-requirement).
The staged evidence required before any public endpoint is listed in the
[testnet roadmap](docs/testnet-roadmap.md).

See [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not deploy
this repository as a mining service.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at
your option.

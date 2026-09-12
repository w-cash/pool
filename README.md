# Wcash Pool

This repository is the Rust engineering foundation for ZecWec, a planned
account-based Equihash pool that will merge-mine Wcash and Zcash from one ASIC
connection. Miners will configure one worker and receive independently
accounted WEC and ZEC rewards at two chain-specific payout destinations.

> **Current status:** non-deployable engineering foundation. There is no public
> mining listener, composed PostgreSQL account service, monetary ledger,
> collector-wallet service, or payout signer. A tested miner-portal crate and
> embedded UI now exist, but they are not composed or deployed. The executable
> still reports `ready: false`, has no `serve` command, and opens no listener.
> Do not point miners or funds at this repository.

## Product decision

ZecWec will use the familiar `account.worker` pool model with a generated,
mining-only token. The ASIC receives one ZIP-301 job stream. Wolf classifies
each accepted Equihash proof independently as an ordinary share, a Wcash
winner, a Zcash winner, or a winner on both chains.

The private portal will hold two independent payout settings: one Wcash
destination and one Zcash destination. It will never ask miners to put two
addresses in an ASIC, derive one chain's address from the other, or provide a
seed or private key.

Planned Testnet setup:

```text
Preferred URL:     stratum+ssl://testnet-mine.zecwec.com:3443
Compatibility URL: stratum+tcp://testnet-mine.zecwec.com:3333
Worker:             <account>.<worker>
Password:           <generated mining-only token>
```

This endpoint is a design target and is **not live**. ASIC Pool 2 and Pool 3
will be independent regional failovers, not separate WEC/ZEC connections. TLS
is preferred; the compatibility port is plaintext for legacy ASICs, so its
revocable token has mining-only authority and is never a portal credential.

## Reward and privacy model

Launch settlement will use independent PPLNS windows and ledgers for WEC and
ZEC. Accepted shares create accounting evidence, not coins. A collector wallet
receives value only when this pool finds and the relevant chain accepts a
block. The resulting collector asset is matched by miner liabilities; it is
not automatically pool profit. Wcash's absence of a consensus developer tax is
separate from any disclosed pool service fee.

The target collector policy is:

- **WEC:** a pool-owned private Wcash Ironwood coinbase receiver. Wcash hides
  the recipient from Zcash's all-zero outgoing-viewing-key recovery while
  keeping scheduled issuance auditable.
- **ZEC:** a separate pool-owned Zcash Ironwood receiver. This avoids a
  transparent UTXO for later spending, but ZIP-213 deliberately makes the
  coinbase receiver and value publicly recoverable. It must not be advertised
  as a private receipt.

Wolf can construct private Wcash coinbases, but the current pool-backend path
does not yet have the read-only trial-decryption attestation required to prove
the encrypted collector recipient. It correctly refuses that mode today. The
pool must add that verification and an isolated signer before private WEC
settlement can be called ready; it must never fall back silently to a
transparent collector.

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
| Wire protocol | Strict, bounded backend-v1 and ZIP-301 codecs; jobs bind the Wcash candidate hash and both chains' coinbase transaction IDs; canonical parent-header and stable share-ID derivations, exact dual-chain reward facts, and reversible winner-lifecycle events—including Wcash witness quarantine and requeue—have deterministic positive and negative tests |
| Pool policy | In-memory session ordering with exact authorized-login reuse, externally namespaced nonce-prefix allocation, backend-generation lifetime separated from per-session target assignment, bounded non-resurrectable generation tombstones, retirement fences, endian-typed targets, and integer vardiff that excludes idempotently replayed receipts |
| Backend client | Timeout-bounded Unix-socket client, identity/capability handshake, event replay, transport-branded lifetimes, submitted-header-time preservation, canonical proof/receipt/attribution binding, live response-watermark flush enforcement, bounded all-event sequence and share-identity evidence, and a fenced core-to-backend share path tested against local mock peers |
| Miner edge | Listener-free bounded actors plus a loopback-only admitted-TCP stream driver for the standard 4+28 nonce profile, with strict framing, absolute deadlines, bounded backpressure, and deterministic synthetic transcripts; no public listener, TLS, credential implementation, durable nonce lease, or ASIC certification |
| Miner portal | Responsive six-page UI; Argon2id login, encrypted TOTP, digest-only browser sessions, CSRF/origin controls, canonical shared-store worker provisioning contract, masked dual payout settings, replacement hold, loopback server composition, and fail-closed signer boundary; PostgreSQL and wallet adapters are not yet composed |
| Service process | Readiness-only command; no composed miner or administrative listener |
| Persistence and money | No PostgreSQL projection, balance ledger, maturity tracking, payout engine, wallet integration, or signing |
| Wolf integration | Wolf now contains a pool-backend-v1 Unix listener, durable journal, native retained-job path, and matching protocol pin; service composition, end-to-end release evidence, and exact private Wcash recipient attestation remain incomplete |
| Operations | No production container, deployment manifests, public endpoint, private soak, or release readiness |

The final miner, reward, privacy, account, UI, and deployment decisions are in
the [product design](docs/product-design.md). The remaining backend integration
contract is described in [the architecture](docs/architecture.md), and the
staged evidence required before any public endpoint is listed is in the
[Testnet roadmap](docs/testnet-roadmap.md).

## Documentation

- [Product and miner experience](docs/product-design.md)
- [Miner portal and payout boundary](docs/miner-portal.md)
- [Architecture and consensus boundary](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Testnet roadmap](docs/testnet-roadmap.md)
- [Security reporting policy](SECURITY.md)

See [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not deploy
this repository as a mining service.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at
your option.

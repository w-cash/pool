# Wcash Pool

This repository is the Rust engineering foundation for ZecWec, a planned
account-based Equihash pool that will merge-mine Wcash and Zcash from one ASIC
connection. Miners will configure one worker and receive independently
accounted WEC and ZEC rewards at two chain-specific payout destinations.

> **Current status:** composed private-Testnet deployment candidate, not a
> public launch. `wcash-poold serve` combines the bounded ZIP-301 edge,
> shared PostgreSQL account/accounting truth, authoritative address adapters,
> account-isolated portal, and independently fenced WEC/ZEC payout services.
> Mainnet is rejected. Public miners and funds remain blocked until the exact
> Wolf/pool release pair passes every private ASIC, payout, restart, reorg, and
> HTTPS gate in the [Testnet deployment runbook](docs/zecwec-testnet-deployment.md).

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

The Testnet launch policy charges a 0% pool service fee. Miners fund only the
actual network transaction fee for their own payout: each batch reserves a
published policy-bounded maximum, pays a net output, and returns every unused
reserved atomic unit after confirmation. The portal publishes both fee caps
and shows each account's gross amount, reserve, actual charge, refund, and net
output without exposing another miner's settlement data.

The target collector policy is:

- **WEC:** a pool-owned private Wcash Ironwood coinbase receiver. Wcash hides
  the recipient from Zcash's all-zero outgoing-viewing-key recovery while
  keeping scheduled issuance auditable.
- **ZEC:** a separate pool-owned Zcash Ironwood receiver. This avoids a
  transparent UTXO for later spending, but ZIP-213 deliberately makes the
  coinbase receiver and value publicly recoverable. It must not be advertised
  as a private receipt.

The deployment accepts private Wcash coinbases only from a Wolf backend that
proves the encrypted collector recipient by read-only trial decryption and
binds that evidence to the configured commitment. The spending seed remains
inside the isolated signer path. Missing or crossed attestation fails closed;
there is no transparent fallback. This is source-level capability, not public
release evidence: the exact Wolf binary and pool binary still require the
runbook's private launch proof.

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

| Area | Current private-Testnet candidate state |
| --- | --- |
| Wire protocol | Strict, bounded backend-v2 and ZIP-301 codecs; jobs bind the Wcash candidate hash and both chains' coinbase transaction IDs; canonical parent-header and stable share-ID derivations, exact dual-chain reward facts, and reversible winner-lifecycle events—including Wcash witness quarantine and requeue—have deterministic positive and negative tests |
| Pool policy | In-memory session ordering with exact authorized-login reuse, externally namespaced nonce-prefix allocation, backend-generation lifetime separated from per-session target assignment, bounded non-resurrectable generation tombstones, retirement fences, endian-typed targets, and integer vardiff that excludes idempotently replayed receipts |
| Backend client | Timeout-bounded Unix-socket client, identity/capability handshake, event replay, transport-branded lifetimes, submitted-header-time preservation, canonical proof/receipt/attribution binding, live response-watermark flush enforcement, bounded all-event sequence and share-identity evidence, and a fenced core-to-backend share path tested against local mock peers |
| Miner edge | Source-restricted public TCP listener behind nginx TLS, bounded ZIP-301 actors, PostgreSQL worker authentication, durable cross-process nonce leases, strict framing/deadlines/backpressure, and account-scoped process telemetry; real ASIC certification remains a launch gate |
| Miner portal | Responsive six-page UI; bounded Argon2id work, encrypted TOTP, digest-only sessions, CSRF/origin controls, authoritative address adapters, account-isolated balances/rewards/blocks/payouts, one-time worker tokens, and separate WEC/ZEC settings |
| Service process | `config-check`, listener-free `preflight`, migration/authority commands, and composed Testnet-only `serve`; readiness fails before wallet, backend, identity, or signer authority can be proven |
| Persistence and money | Deployment-fenced PostgreSQL PPLNS/ledger projection, maturity/reorg/idempotency handling, durable payout artifacts and recovery, and exact wallet-to-ledger reconciliation for independent WEC and ZEC collectors |
| Wolf integration | Backend-v2 client/server contract, journal replay, exact authority identity, private-WEC recipient commitment/attestation boundary, and dual winner handling are composed; exact artifact pairing and live recovery evidence remain launch gates |
| Operations | Immutable release renderer, protected systemd credentials, private preflight/start/rollback paths, source-restricted Stratum, Cloudflare-AOP portal staging, and explicit publication gates; no public launch is claimed |

The PostgreSQL CI job runs an authenticated payout-lifecycle test through the
production backend authority check, share and winner projector, PPLNS ledger,
maturity, reconciliation, payout planner, WEC signer journal, settlement
fences, restart retry, confirmation, and account read model. It replaces the
backend-event source, address-validation result, native-wallet transport, and
node broadcast/confirmation with deterministic test adapters. The ZEC PCZT
signer has its own real-proof pipeline suite, but its PostgreSQL lifecycle is
not duplicated by this WEC test. Live Equihash submission, Ironwood scanning,
real transaction acceptance, and an ASIC remain separate private-Testnet
release gates.

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

See [SECURITY.md](SECURITY.md) before reporting a vulnerability. Follow the
runbook's private-Testnet gates; this repository does not authorize a public or
Mainnet deployment.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at
your option.

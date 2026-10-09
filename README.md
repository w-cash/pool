# Wcash Pool

This repository implements ZecWec, the account-based Equihash pool that
merge-mines Wcash and Zcash from one miner connection. Each account has
independent WEC and ZEC accounting and chain-specific payout destinations.

> **Current status:** ZecWec is live on Mainnet. The canonical portal and API
> are at <https://pool.zecwec.com/>. Account registration, ASIC mining on port
> `3336`, GPU/CPU mining on port `3338`, PostgreSQL accounting, PPLNS reward
> allocation, and automatic WEC payouts are active. ZEC rewards are accounted
> separately and settled manually; automatic ZEC payout execution is not
> advertised or enabled. The portal's `/readyz` response reports
> `payout_execution=deferred` because the public portal process has no spending
> authority. Automatic WEC execution belongs to a separate isolated worker.
> The observed deployment evidence is recorded in
> [`production-manifest.json`](production-manifest.json) and is exposed at
> `/api/v1/production-manifest` by releases containing that endpoint.

## Product decision

ZecWec uses the familiar `account.worker` pool model. The miner receives one
ZIP-301 job stream. Wolf classifies
each accepted Equihash proof independently as an ordinary share, a Wcash
winner, a Zcash winner, or a winner on both chains.

The portal holds two independent payout settings: one Wcash destination and
one Zcash destination. It never asks miners to put two
addresses in an ASIC, derive one chain's address from the other, or provide a
seed or private key.

## Mainnet mining routes

| Route | Purpose | Account/PPLNS ledger | Pool payouts |
| --- | --- | --- | --- |
| `stratum+tcp://mainnet.zecwec.com:3333` | Legacy direct Wolf Stratum | No | No |
| `stratum+tcp://mainnet.zecwec.com:3336` | Account pool for ASICs | Yes | Automatic WEC; manual ZEC |
| `stratum+tcp://mainnet.zecwec.com:3338` | Lower-difficulty account pool for GPU/CPU miners | Yes | Automatic WEC; manual ZEC |

Account-pool miners use `<account>.<worker>` with password `x`. Ports `3336`
and `3338` share the same deployment, worker registry, accepted-share ledger,
PPLNS accounting, and payout ledger. Port `3333` is a separate legacy Wolf
service. Its shares and collector funds are not Pool balances and must not be
imported or represented as account earnings.

All public Stratum routes are currently plaintext TCP. Never place a portal
password, wallet key, seed phrase, or payout address in the Stratum password
field.

## Reward and privacy model

Settlement uses independent PPLNS windows and ledgers for WEC and
ZEC. Accepted shares create accounting evidence, not coins. A collector wallet
receives value only when this pool finds and the relevant chain accepts a
block. The resulting collector asset is matched by miner liabilities; it is
not automatically pool profit. Wcash's absence of a consensus developer tax is
separate from any disclosed pool service fee.

The Mainnet policy charges a 0% pool service fee. Miners fund only the
actual network transaction fee for their own payout: each batch reserves a
published policy-bounded maximum, pays a net output, and returns every unused
reserved atomic unit after confirmation. The portal publishes both fee caps
and shows each account's gross amount, reserve, actual charge, refund, and net
output without exposing another miner's settlement data.

The collector policy is:

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

| Area | Current repository and Mainnet state |
| --- | --- |
| Wire protocol | Strict, bounded backend-v2 and ZIP-301 codecs; jobs bind the Wcash candidate hash and both chains' coinbase transaction IDs; canonical parent-header and stable share-ID derivations, exact dual-chain reward facts, and reversible winner-lifecycle events—including Wcash witness quarantine and requeue—have deterministic positive and negative tests |
| Pool policy | In-memory session ordering with exact authorized-login reuse, externally namespaced nonce-prefix allocation, backend-generation lifetime separated from per-session target assignment, bounded non-resurrectable generation tombstones, retirement fences, endian-typed targets, and integer vardiff that excludes idempotently replayed receipts |
| Backend client | Timeout-bounded Unix-socket client, identity/capability handshake, event replay, transport-branded lifetimes, submitted-header-time preservation, canonical proof/receipt/attribution binding, live response-watermark flush enforcement, bounded all-event sequence and share-identity evidence, and a fenced core-to-backend share path tested against local mock peers |
| Miner edge | Public Mainnet ASIC and GPU/CPU routes through bounded ZIP-301 compatibility adapters, PostgreSQL worker authentication, durable cross-process nonce leases, strict framing/deadlines/backpressure, and account-scoped process telemetry |
| Miner portal | Responsive six-page UI; bounded Argon2id work, encrypted TOTP, digest-only sessions, CSRF/origin controls, authoritative address adapters, account-isolated balances/rewards/blocks/payouts, one-time worker tokens, and separate WEC/ZEC settings |
| Service process | `config-check`, listener-free `preflight`, migration/authority commands, composed `serve`, projector, and isolated payout worker; readiness fails when required database, backend, identity, or address-validation authority is unavailable |
| Persistence and money | Deployment-fenced PostgreSQL PPLNS/ledger projection, maturity/reorg/idempotency handling, durable payout artifacts and recovery, automatic WEC execution by the isolated worker, and manual ZEC settlement |
| Wolf integration | Backend-v2 client/server contract, journal replay, exact authority identity, private-WEC recipient commitment/attestation boundary, and dual winner handling; the observed backend commit and binary are recorded in the production manifest |
| Operations | Immutable release renderer, protected systemd credentials, preflight/start/rollback paths, public Mainnet Stratum on ports 3333/3336/3338, and a public portal/API; the production manifest records the observed artifact and configuration identities plus known limitations |

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

The miner, reward, privacy, account, UI, and deployment decisions are in the
[product design](docs/product-design.md). The backend integration contract is
described in [the architecture](docs/architecture.md). Testnet acceptance work
and historical launch gates remain documented in the
[Testnet roadmap](docs/testnet-roadmap.md).

## Documentation

- [Production manifest](production-manifest.json)
- [Mainnet account portal and route boundary](docs/mainnet-account-portal.md)
- [Mainnet Pool listeners](docs/mainnet-parallel-staging.md)
- [Miner and API onboarding](docs/pool-onboarding.md)
- [Product and miner experience](docs/product-design.md)
- [Miner portal and payout boundary](docs/miner-portal.md)
- [Architecture and consensus boundary](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Testnet roadmap](docs/testnet-roadmap.md)
- [Security reporting policy](SECURITY.md)

See [SECURITY.md](SECURITY.md) before reporting a vulnerability. Production
changes still require the deployment, rollback, custody, accounting, and
chain-specific acceptance gates in the Mainnet runbooks.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at
your option.

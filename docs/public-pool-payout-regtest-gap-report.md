# Public Pool payout Regtest gap report

Baseline inspected at Pool commit
`05c71684c21faff7856bb06adad71f8e60fe877a` and Wolf
`origin/testnet-v1` commit
`3f54aafaa408934c168e68413b2f7cad4575b0bb` on 2026-09-18.

## Already working

- The PostgreSQL 16 adapter owns account, worker, session, destination,
  chain-separated PPLNS, ledger, payout-batch, confirmation, and reorganization
  state. Its ignored real-database suites pass against a new disposable
  PostgreSQL 16 instance.
- Portal HTTP tests cover registration, login, logout, absolute and idle
  expiry, CSRF and Origin checks, lockout, TOTP, worker creation and revocation,
  and account isolation. Stratum closes a live revoked-worker session.
- WEC and ZEC address authorities are injected and fail closed. Their unit
  suites cover wrong networks, wrong chains, malformed encodings, unsupported
  receivers, and unavailable authorities.
- The payout worker already has a single database-clock lease, collector
  reconciliation, immutable batches, signed-byte persistence, exact retry,
  confirmation watching, fee-reserve return, and append-only reorganization
  handling.
- Wolf already implements the native WEC `pool-payout-v2` contract: seedless
  identity and recovery, durable batch/commitment binding, ordered intent,
  fee/change inspection, exact signed-byte recovery, exact-byte broadcast, and
  conflicting-retry rejection. No Wolf source change is presently required.
- The isolated ZEC signer already implements the PCZT pipeline, including
  independent effects parsing, transparent and shielded recipient checks,
  Regtest fencing, signed-byte persistence, exact retry, and wallet/node-tip
  readiness checks.

## Missing wiring and proof

- `scripts/full-pool-regtest/run.py` writes `payout_mode = "deferred"`; it does
  not start an isolated Zallet, initialize recipient wallets, configure or
  activate payout destinations, start the payout worker, mine the post-broadcast
  confirmation window, verify recipient receipts, or emit a final acceptance
  certificate.
- The harness mines only dual-chain winners. It does not deliberately produce
  ordinary, WEC-only, ZEC-only, and dual-chain work for both accounts.
- The harness creates one worker per account, does not exercise live
  cross-account token misuse, revocation, portal logout independence, or a
  second continuing worker.
- The harness waits only for `/healthz`. Complete `/readyz` cannot succeed in
  deferred mode and without a live payout-worker lease and ready wallet
  dependencies.
- `verify.py` checks live PostgreSQL and canonical block inclusion, but its
  certificate explicitly leaves recipient-wallet receipts and restart/replay
  evidence outside the result.
- The baseline Playwright suite has one failure: the UI renders
  `Safety hold (2 days) until ...`, while the browser contract expects the
  stable phrase `Safety hold until ...`.

## Tests that use doubles

- Portal API tests use an in-process repository, address-validator, signer,
  and readiness double for HTTP behavior.
- WEC signer tests use a mock `NativeWalletTransport`; they prove the
  coordinator contract but are not real Wolf wallet acceptance evidence.
- ZEC PCZT tests use scripted wallet and node transports; they prove boundary
  validation but are not a live Zallet payment.
- Payout runtime and settlement unit tests use scripted store, observer,
  signer, and broadcaster boundaries for crash-point coverage.
- Playwright uses explicit HTTP fixtures rather than a live portal. The real
  PostgreSQL adapter and full-node harness must supply the acceptance proof.

## Baseline results

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace --all-targets --all-features`: pass; real PostgreSQL
  cases are intentionally ignored in the ordinary run.
- All five ignored `wcash-pool-store` PostgreSQL suites: pass on PostgreSQL
  16.15.
- Full-pool Python unit suite: 23 pass.
- Portal Playwright suite: 6 pass, 1 fail for the payout-hold text mismatch
  described above.

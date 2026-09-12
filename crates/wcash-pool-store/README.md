# ZecWec durable pool store

`wcash-pool-store` is the PostgreSQL authority for deployment identity,
mining credentials, nonce reservations, authoritative Wolf event projection,
PPLNS allocation, and the conserved WEC/ZEC ledger.

The store deliberately does not validate consensus or Equihash. It accepts
winner lifecycle facts only from a `BackendAuthority` whose Wcash genesis,
Zcash genesis, chain ID, collector commitments, backend instance, and journal
stream exactly match the deployment row.

## Safety boundaries

- Accounts, credentials, policies, balances, and payouts are deployment-scoped;
  Testnet and Mainnet accounting cannot cross. Nonce uniqueness is deliberately
  broader: one global cursor is keyed by the exact Wolf backend instance,
  journal stream, negotiated profile, and encoded namespace so rolling
  deployment IDs cannot allocate overlapping prefixes.
- Mining bearer tokens use a random selector and 256-bit secret, with only an
  exact Argon2id verifier stored. Tokens are revocable and mining-only.
- Wolf events are applied contiguously, with canonical-payload replay checks.
- WEC and ZEC have independent zero-fee launch policies, PPLNS windows,
  maturity, ledger accounts, payout thresholds, and batches.
- Ledger lines and policy revisions are append-only. A ledger transaction must
  be balanced and sealed in the same database transaction.
- Coinbase value remains an immature collector asset until the authoritative
  maturity event. It cannot fund payouts early.
- Payout output count and signer fee are policy-capped; transaction IDs are
  unique per chain; exact signed bytes and best-chain evidence are retained for
  crash recovery and reorg handling.
- Every new payout batch consumes a fresh, short-lived wallet reconciliation
  whose wallet balance matches the chain-specific spendable collector ledger.
  The store—not an API caller—derives the checkpoint UUID and streaming ledger
  root used by the isolated signer request. Stale roots and wallet mismatches
  fail closed; mismatches freeze that chain.
- A fresh process UUID must hold a short database-clock lease before it can
  reserve nonce ranges. Lease takeover increments a generation and resumes the
  permanent global cursor; stale holders fail closed. Reservation and cursor
  advance are one transaction, audit rows are append-only, and database
  triggers reject rewind, deletion, or an advance without an exact contiguous
  reservation. A crash may waste a range but cannot cause its reissue.

## Journal migration

An existing journal may be replayed only when it uses the current canonical
backend protocol and its persisted backend instance and journal stream match
the configured deployment. Replay starts at the stored cursor and preserves
event sequence, payload, account, worker, and winner identities exactly.

Legacy counters or JSON records must never be converted into shares, rewards,
or balances by inference. If they cannot be authenticated and parsed as the
canonical stream, operators must archive them and start an explicitly new
journal epoch with new deployment/backend identities. Historical UI totals may
be labelled as archival telemetry, but they are not accounting entries.

## Deliberate readiness gates

This crate is not a standalone public-pool launch. It supplies the concrete
PostgreSQL portal adapter and durable wallet/ledger reconciliation contract,
but payout destination writes remain disabled until the service supplies
authoritative Wolf Wcash and Zcash/Zallet address decoders. The isolated wallet
integration must also persist signed transaction bytes before broadcast; the
portal's current one-call sign-and-broadcast test boundary is not safe for that
production transition. The public ZIP-301 service, TLS/plaintext listeners,
wallet adapter, and PostgreSQL least-privilege roles are composed by
`wcash-poold`; readiness must stay false until those dependencies are present.

Run the real database suite only against a disposable PostgreSQL database:

```text
WCASH_POOL_TEST_DATABASE_URL=<disposable-url> cargo test -p wcash-pool-store --all-targets
```

The integration test drops and recreates the database's `public` schema.

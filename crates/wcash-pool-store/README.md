# ZecWec durable pool store

`wcash-pool-store` is the PostgreSQL authority for deployment identity,
mining credentials, nonce reservations, authoritative Wolf event projection,
PPLNS allocation, and the conserved WEC/ZEC ledger.

The store deliberately does not validate consensus or Equihash. It accepts
winner lifecycle facts only from a `BackendAuthority` whose Wcash genesis,
Zcash genesis, chain ID, collector commitments, backend instance, and journal
stream exactly match the deployment row.

## Safety boundaries

- Every row is deployment-scoped; Testnet and Mainnet identities cannot share
  cursors, credentials, nonce ranges, policies, balances, or payout batches.
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
- Nonce ranges are atomically reserved by profile and namespace before their
  one-shot allocator is constructed. A crash may waste a range but cannot
  cause the database to reissue it.

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

This crate is not a standalone public-pool launch. Payout destination writes
remain disabled until the service supplies authoritative Wolf Wcash and
Zcash/Zallet address decoders. Signing and broadcast also require a separately
audited, durable wallet-reconciliation checkpoint. The public ZIP-301 service,
TLS/plaintext listeners, portal adapter, signing isolation, and PostgreSQL
least-privilege roles are composed by `wcash-poold`; readiness must stay false
until those dependencies are present.

Run the real database suite only against a disposable PostgreSQL database:

```text
WCASH_POOL_TEST_DATABASE_URL=<disposable-url> cargo test -p wcash-pool-store --all-targets
```

The integration test drops and recreates the database's `public` schema.

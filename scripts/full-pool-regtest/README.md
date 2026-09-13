# Full pool Regtest integration

This harness exercises actual Wcash and Zcash nodes, the native authenticated
backend, PostgreSQL 16, `wcash-poold projector`, `wcash-poold serve`, account and
worker creation through the portal API, and real Equihash 200,9 submissions through
ZIP-301. The default 101 merged blocks preserve the production 100-confirmation
policy. Wallet payout execution is a separate final stage being integrated here.

The isolated network is opt-in at compile time:

```sh
cargo build --locked -p wcash-poold --features regtest
cargo build --locked --release -p wcash-wallet --features regtest-payout
```

Ordinary pool builds reject `network = "regtest"`. Explicit Regtest configurations
require the frozen Wcash and Zcash Regtest genesis hashes and loopback Stratum.
The database retains the 48-hour payout destination hold for Testnet; only Regtest
rows use a 1-second hold so the same activation routine can be exercised locally.
No maturity, proof, wallet identity, payout amount, or ledger effect is mocked.

Required inputs:

- A fresh owner-private runtime directory and disposable PostgreSQL 16 database.
  Supply its connection URL through a mode 0600 file, never a command-line value.
- Wcash and Zcash consensus binaries from the pinned node revision (or a documented
  source-identical cached build), the native backend/ZIP-301 miner, and the Wcash
  wallet compiled with `regtest-payout`.
- An owned Zcash Orchard collector address, stored in a private file. The wallet
  that owns it must be available to the payout stage; a public fixture is unsuitable.
- Python 3 and a PostgreSQL `psql` client. Node RPC ports 18232/18242/28232,
  compact-block ports 19067–19069, pool Stratum 18237 and portal 18080 must be free.

Example (all paths supplied by the caller):

```sh
python3 scripts/full-pool-regtest/run.py \
  --runtime "$REGTEST_RUNTIME" \
  --database-url-file "$REGTEST_DATABASE_URL_FILE" \
  --zec-collector-file "$REGTEST_ZEC_COLLECTOR_FILE" \
  --wallet "$REGTEST_WCASH_WALLET" \
  --miner "$REGTEST_MERGE_MINER" \
  --wcash-node "$REGTEST_WCASH_NODE" \
  --zcash-node "$REGTEST_ZCASH_NODE" \
  --poold "$REGTEST_POOLD" \
  --blocks 101 --keep-running
```

Use `--blocks 1` only for a mining smoke; it does not prove mature balances or
payouts. `result.json` records the mining stage and is not a final payout certificate.
All wallet output, passwords, tokens, RPC credentials, logs and intermediate
responses remain in the protected runtime directory. The stdout progress excludes
these values. Ctrl-C stops only processes launched by this harness.

Local limitations are explicit: all functional processes run as the current Unix
UID, so the submitter credential is also used for read-only backend operations;
production UID and database-role separation must additionally pass the deployment
smoke. The portal API uses its exact HTTPS origin contract over the loopback
upstream HTTP listener; nginx TLS termination is tested separately.

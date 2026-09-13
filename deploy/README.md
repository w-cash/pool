# ZecWec Testnet deployment package

This directory contains the fail-closed deployment package for one Wcash/Zcash
merged-mining **Testnet** pool. It contains no credentials, collector keys,
host addresses, or Mainnet policy.

The live deployment separates six authorities:

- `wcash-pool-backend` owns the AuxPoW node access, immutable job identity,
  share validation, and append-only backend journal;
- `wcash-pool` owns the public miner/portal process and its public PostgreSQL
  role. It has no seed, wallet encryption identity, signer journal, Zallet
  cookie, or payout-table mutation privileges;
- `wcash-pool-projector` is a listener-free process with the only runtime role
  allowed to advance Wolf event, share, winner, and ledger projection. The
  public process acknowledges an event only after verifying its exact sequence,
  authority, and payload digest in PostgreSQL;
- `wcash-payout` runs the listener-free automatic payout worker with a distinct
  PostgreSQL role, Wcash seed credential, wallet database, and signer journals;
- `zecwec-zallet` runs the Zcash collector on literal loopback only. Zallet
  constructs transactions with `broadcast = false`; the payout worker persists
  exact bytes before the independent Zebra broadcaster submits them;
- `wcash-pool-migrate` is a dedicated listener-free Unix identity holding only
  the PostgreSQL migrator credential. The migrator is the only database role
  that owns schema or binds deployment identity and launch policy; public and
  payout services verify those rows.

The public portal reports payout execution as enabled only while PostgreSQL
contains a ready, unexpired payout-worker lease with a heartbeat no older than
60 seconds. Configuration alone can never make readiness pass. A 35-minute
takeover fence is longer than the payout service's 32-minute stop deadline, so
a replacement cannot overlap a non-cancellable wallet operation. After an
unclean kill, the replacement remains alive without constructing either signer
and retries the database-clock lease for up to 36 minutes. Deployment readiness
therefore has a reviewed 70-minute bound: takeover wait plus the 30-minute
startup/drain bound and four minutes of scheduling margin.

Collector custody is hot **Testnet** custody, not an offline-payout design. The
original mnemonic and temporary recovery state are removed after independent
off-host restore evidence is verified. Root retains only the protected Wcash
seed source, protected Zallet encryption-identity credential, public authority
evidence, and recovery attestations. systemd copies credentials into private
service mounts; the Internet-facing pool UID cannot read any custody path.

## Deployment order

1. Build `wcash-poold`, `wcash-merge-miner`, and `wcash-wallet` on reviewed
   x86-64 Linux. Build pinned Zallet beta.3 with
   `scripts/build-zallet-testnet.sh`, retain its `PROVENANCE.json` and
   `ZALLET_SHA256SUM`, and create the exact six-entry `SHA256SUMS` manifest
   covering all four binaries plus both provenance artifacts.
2. Copy `config/deployment.env.example` to a root-only operator file. Replace
   every `CHANGE_ME` and review both genesis byte orders, identities, accounts,
   payout commitments, endpoints, and filesystem paths.
3. Run `scripts/deploy/provision-host.sh`; archive any incompatible legacy
   service with `disable-legacy-pool.sh`.
4. Install the immutable release with `install-release.sh`. Installation does
   not start a public listener. On an existing deployment, select the staged
   version only with `activate-release.sh` after explicitly reviewing forward
   schema compatibility; the activation remains stopped unless payout readiness
   and the full health contract pass.
5. Install a fresh dedicated Wcash Testnet seed using
   `install-protected-seed.sh`, and prepare fresh zero-balance WEC and ZEC
   collectors. Never reuse a funded collector with an empty pool ledger.
6. Upgrade the host to PostgreSQL 16 or newer, then run
   `provision-postgres.sh`. Both provisioning and preflight fail closed on an
   older or unidentifiable server. Provisioning creates separate migrator, public,
   projector, and payout roles and root-only connection credentials without
   printing them, and removes any pre-existing memberships that could permit a
   service login to escalate with `SET ROLE`.
7. Render `wallet-bootstrap`; initialize/sync Wcash, perform the reviewed Zallet
   handover, replace the exact discovery sentinels, and render `bootstrap`.
   Independently restore both collectors. Seal Wcash recovery evidence with
   `seal-wcash-custody.sh`; capture and attest Zallet recovery with
   `verify-zec-wallet-recovery.py`, importing the temporary phrase only through
   `import-zallet-mnemonic.py` and the isolated recovery unit. Seal the live
   zero-balance ZEC collector using `seal-zec-initial-zero.sh`.
8. After verified off-host backup and restore, run
   `finalize-zec-offline-custody.sh`. Despite its historical command name, this
   closes the bootstrap ceremony for hot Testnet operation: it retains a
   root-only Zallet identity credential and then performs irreversible removal
   of plaintext mnemonic staging, the original identity file, and recovery
   datadir. No mnemonic may remain on the host.
9. Initialize the backend, render `finalize`, run the migration unit, and run
   `preflight.sh`. Preflight is listener-free and keyless: it verifies custody,
   exact node/backend identity, database policy, and public composition without
   constructing a signer or invoking wallet/broadcast operations. Its reviewed
   migrations and canonical journal replay may advance durable accounting. It
   temporarily runs the backend and projector for that replay and the probes,
   then proves both fully inactive on success; failure cleanup stops both as
   well. The non-key-bearing credential path watcher remains enabled so a
   dormant deployment records node-cookie rotation; while the target and all
   runtime roles are inactive, reconciliation cannot start an authority.
10. Apply `restrict-mining-firewall.sh` with either the explicit public-Testnet
    marker or exact ASIC addresses, enable the Stratum edge, and run
    `start-testnet-pool.sh`. The script waits up
    to the reviewed startup deadline for Zallet synchronization, journal
    recovery, payout reconciliation, and the worker's ready heartbeat before
    full health can pass. Any startup or credential-refresh failure stops the
    target, health timer, projector, public service, payout worker, and payout
    Zallet. The script enables the readiness-gated
    `zecwec-testnet-pool-start.service` as the only boot entry point; the raw
    target and health timer are never enabled independently. Scheduled health
    failure closes miner intake instead of only emitting an alert. A dedicated
    first-position IPv4/IPv6 `INPUT` guard exposes the two current ports only
    under that reviewed policy and drops the legacy port before any unrelated
    host rule can accept it; UFW remains the persistent second enforcement
    layer. Activation rejects managed-port NAT translations and automatically
    restores both guards closed if public-policy application fails.

`zecwec-testnet-pool.target` supervises the projector, public service, payout
Zallet, and payout worker. The public unit requires and binds to the projector;
projector failure therefore closes miner intake instead of permitting
unprojected acknowledgements. Restart limits prevent an unavailable custody
dependency from causing an unbounded loop. Cookie refresh stops the target
before rotating snapshots so `Upholds=` cannot race a worker restart.

Deployment security epoch 2 is a hard rollback boundary. Epoch-1 packages
predate the isolated projector/migrator roles and can restore broad public
database DML, so rollback rejects them before stopping the live target or
executing any target-owned deployment code. Only an epoch-2 release that also
passes the explicit schema-compatibility review can be selected.

The HTTP origin is deployed API-only: nginx exposes `/api/v1/*`, `/readyz`, and
`/healthz`, and returns `404` for `/` and bundled static assets. A separately
reviewed frontend must use this same protected origin so the strict session,
CSRF, and origin policy remains intact. The origin must remain behind
Cloudflare Full (strict) plus Authenticated Origin Pulls. The mining hostname
is DNS-only and protected by the explicit Testnet firewall policy; generic
Cloudflare HTTP proxying does not carry ZIP-301 TCP.

See [`docs/zecwec-testnet-deployment.md`](../docs/zecwec-testnet-deployment.md)
for the detailed ceremony, launch gates, health contract, and rollback rules.

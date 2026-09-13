# ZecWec Testnet deployment runbook

## Scope and readiness claim

This runbook deploys one account-based WEC/ZEC merged-mining **Testnet** pool:

- account registration, login, TOTP, workers, revocable mining tokens;
- independent WEC and ZEC payout destinations and histories;
- accepted/stale/invalid/duplicate share counters plus block, reward, and
  payout observations; calibrated hashrate projection remains unavailable;
- one ZIP-301 work stream with independent Wcash and Zcash winner handling;
- PPLNS accounting with zero launch fee and chain-separated liabilities;
- automatic threshold payouts from isolated hot Testnet collectors, with a
  listener-free worker and chain-separated crash-safe signer journals.

It does not enable Mainnet. Installing these files is not evidence that the
pool is ASIC-ready. The private mining signal requires all source gates,
independent collector-recovery proofs, initial-zero attestations, deployment
preflight, restart/reorganization tests, automatic payout evidence, and one
real accepted ASIC share.

## Security boundaries

The services run under separate Unix identities. `wcash-pool-backend` owns the
AuxPoW authority, identity, append-only winner journal, and node credentials.
`wcash-pool` owns miner sessions and the public ledger/portal role, and has no
payout or accounting-projection authority. It can reach the backend only
through a `0660` Unix socket in a `0750` non-writable directory.
`wcash-pool-projector` is a separate no-listener user with the sole runtime
PostgreSQL capability to advance the exact Wolf event cursor and derived
share, winner, and ledger rows. The public process waits for and verifies the
same authority, sequence, and payload digest before acknowledging journal
progress; projector delay therefore backpressures or stops mining instead of
losing durable credits. `wcash-pool-migrate` is a separate no-listener user
that receives only the schema-owner database credential while migrations run;
the public UID can never inherit that credential through a shared process
identity. `wcash-payout` is a distinct no-listener user that
alone receives the Wcash seed credential, wallet database, payout journals,
and payout PostgreSQL role. `zecwec-zallet` owns the Zcash collector database
and receives its encryption identity through a private systemd credential;
its RPC binds only to literal loopback.

The public unit mounts neither collector seed, wallet database, signer journal,
Zallet configuration, Zallet cookie, nor encryption identity; systemd also
makes those paths inaccessible. The payout unit does not receive portal pepper,
TOTP state, mining-token authority, or a public listener. No spending seed or
wallet identity appears in an argument, environment variable, unit,
repository, log, or public-process filesystem view.

Zallet uses public Testnet, beta.3 RPC semantics, loopback RPC, and:

```toml
[external]
broadcast = false
```

The payout pipeline persists exact transaction bytes before the independent
Zebra RPC broadcasts them. Enabling Zallet broadcasting would violate the
crash-recovery boundary and is rejected by the signer. A deployment-scoped
PostgreSQL lease is acquired before signer construction or journal recovery.
Only an exact ready owner can heartbeat or clear readiness. The public portal
reports payout execution as enabled only while that external heartbeat is
fresh; configuration alone is never readiness evidence.

An uncleanly killed payout worker can leave its 35-minute database-clock fence
intact. Its replacement stays in a listener-free, heartbeat-free standby and
retries acquisition for up to 36 minutes; it constructs no signer or wallet
until PostgreSQL grants the lease. Start and rollback wait up to 70 minutes for
that takeover plus the bounded startup path. This keeps the service process
alive past systemd's restart burst without allowing overlapping signers.

Release directories are root-owned and non-writable. Every service is rendered
with one canonical `/opt/wcash/releases/<release-id>` path and never executes
through the mutable `current` symlink. It verifies the selected binary against
an exact six-entry `SHA256SUMS` manifest before execution. The manifest covers
all four executables plus Zallet's `PROVENANCE.json` and
`ZALLET_SHA256SUM`. Installation also snapshots the matching templates,
runbook, scripts, and exact Zallet patch set into that release and binds them
with `DEPLOYMENT-SHA256SUMS`. Rollback renders from that exact snapshot, so old
binaries can never be paired silently with new templates or provenance.
The pool additionally pins the Wcash wallet digest in its policy.

The launch accepts only direct Ironwood collector coinbase on both chains. A
fresh dedicated Wcash seed/account and a fresh dedicated Zallet account must
start with exactly zero spendable Ironwood value. Reusing an already funded
collector against a zero pool ledger is forbidden: it would make wallet value
and miner liabilities irreconcilable. Importing an opening balance is outside
this runbook and requires a separately reviewed ledger migration.

## Network layout

| Endpoint | Exposure | Purpose |
| --- | --- | --- |
| Portal backend | loopback | Registration, dashboard, payout settings |
| Apex web | Cloudflare-proxied plus origin mTLS after the launch gate | `zecwec.com`, redirects to Testnet |
| Portal HTTPS | Cloudflare-proxied plus origin mTLS after the launch gate | `testnet.zecwec.com` |
| ZIP-301 plaintext | approved source CIDRs only | Legacy ASIC compatibility |
| ZIP-301 TLS | approved source CIDRs only, nginx TLS | Preferred ASIC endpoint |
| Wcash/Zcash/PostgreSQL RPC | loopback only | Live mining authorities |
| Zallet payout RPC | loopback only | Isolated hot Testnet ZEC collector; no public listener |
| Backend Unix socket | pool/backend group only | Immutable job and share authority |
| Journal projector | no TCP listener | Exact Wolf-to-PostgreSQL monetary projection |

The portal hostname must use Cloudflare Full (strict) mode with Authenticated
Origin Pulls enabled. nginx requires Cloudflare's client certificate and
rejects an absent `CF-Connecting-IP`; only that Cloudflare-overwritten value is
forwarded to the loopback portal. Direct port 80 returns no application
response. This is mandatory because the DNS-only mining hostname reveals the
same origin IP. The mining hostname must remain DNS-only unless a paid
Cloudflare product explicitly supports generic TCP proxying. ASIC TLS needs a
publicly trusted certificate such as Let's Encrypt.

The origin applies a general request limit and a stricter credential-operation
limit keyed by Cloudflare's authenticated `CF-Connecting-IP`. The application
also uses a small process-wide, non-queueing semaphore around every portal
Argon2 password hash, token hash, or verification and returns HTTP 429 with
`Retry-After` when the memory-hard work budget is full. These independent
bounds remain required even when Cloudflare edge rate limiting is enabled.

The reviewed DNS contract is deliberately narrow: `zecwec.com` and
`testnet.zecwec.com` are proxied web records; `testnet-mine.zecwec.com` is a
DNS-only mining record for ports 3333 and 3443. `mine.zecwec.com` is reserved
and must remain absent or disabled. DNS publication and origin activation wait
for the end-to-end launch gate.

nginx enforces the real client-IP connection limit for TLS before forwarding
to the loopback pool listener. The pool sees nginx as the TLS peer, so its
process-level per-source ceiling is deliberately equal to the global ceiling;
the plaintext port remains protected by source-restricted firewall rules.

## 1. Build and stage a release

Build on a reviewed x86-64 Linux builder. Do not compile on the production
host. Build pinned Zallet beta.3 with `scripts/build-zallet-testnet.sh`; retain
its generated provenance and checksum beside the binary. The release directory
must contain these exact artifacts and an exact six-entry manifest:

```text
wcash-poold
wcash-merge-miner
wcash-wallet
zallet
PROVENANCE.json
ZALLET_SHA256SUM
SHA256SUMS
```

Required CI performs two sequential clean Zallet builds from the pinned source
and compares their exact `ZALLET_SHA256SUM` files. Before public deployment,
repeat the build on two independent reviewed hosts and require the binary
SHA-256 values to match; CI does not replace that cross-host release gate.

Generate the manifest from inside the release directory, then transfer it over
an authenticated channel. Run:

```bash
sudo scripts/deploy/provision-host.sh /path/to/reviewed/pool-source
sudo scripts/deploy/install-release.sh <release-id> /path/to/release-directory
```

`install-release.sh` stages a new version without restarting a running pool. It
selects the release only when no `/opt/wcash/current` link exists. That link is
only an operator selection marker: rendered services and policies contain the
resolved immutable version directory. An existing release is accepted only if
both its binary and deployment-package manifests verify exactly.

### First security-epoch-2 bootstrap

This bootstrap supports only a new host or a never-activated, zero-balance
prototype whose old state has been independently recovered and archived. It is
not an in-place upgrade for a finalized, funded, or running epoch-1 pool. Such a
host requires a fresh or reprovisioned epoch-2 deployment and a separately
reviewed ledger and wallet migration; this release intentionally provides no
automatic state-continuity claim.

If a non-activated prototype has a `current` selector naming an epoch-1 release,
do not switch that link by hand and do not let a preparation command resolve
the selector implicitly. Stop its services, prove independent wallet recovery
and zero balances, and move every legacy wallet database, wallet authority,
signer journal, share journal, and old rendered runtime policy into a root-only
audit backup. Do not delete it. The renderer fails before invoking Python,
installing a file, or reloading systemd while any legacy durable path remains.

Pin the newly installed immutable release for every wallet, credential,
custody, render, database, preflight, firewall, and edge-preparation command:

```bash
ZECWEC_BOOTSTRAP_RELEASE=/opt/wcash/releases/<epoch-2-release-id>
ZECWEC_BOOTSTRAP_DEPLOY="$ZECWEC_BOOTSTRAP_RELEASE/deployment/scripts/deploy"
```

Use the same `sudo env ZECWEC_RELEASE_PATH=...` prefix and the same release's
snapshotted script for all remaining preparation steps below. Verify the
literal path is one installed, root-owned, immutable release; never substitute
`/opt/wcash/current`. Creating `backend-authority-protocol-v2.json` alone is not
an activation signal. First finish the final render and preflight, install the
exact miner CIDRs and publicly trusted mining certificate, and close the
firewall as described through section 8. A clean host whose selector already
names the epoch-2 release uses `start-testnet-pool.sh` in section 9. A scoped,
never-activated prototype selector uses `activate-release.sh` once to perform
the fail-closed selector change, database migration, preflight, start, edge
enablement, and health gate.

For every later forward rollout, first install and independently review schema
compatibility, then activate the staged version explicitly:

```bash
sudo scripts/deploy/activate-release.sh \
  <release-id> \
  /etc/wcash-pool/deployment.env \
  /var/lib/wcash-pool-backend/backend-authority-protocol-v2.json \
  /etc/wcash-pool/miner-cidrs \
  --ack-forward-schema-compatible
```

Activation uses the same fail-closed transition as rollback: it verifies the
target with the currently trusted tooling before stopping the live target,
then renders the immutable target snapshot, switches the selector, migrates,
runs preflight, snapshots credentials, and reopens listeners only after payout
readiness and the complete health contract pass. It never rewinds the database.
Any failed step after shutdown leaves public and payout services stopped.

If an older deployment owns `wcash-pool.service`, archive and disable it before
rendering any new unit:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/disable-legacy-pool.sh" wcash-pool.service
```

The command preserves a root-only copy of the resolved unit and, for a local
unit with the colliding name, moves the fragment into the backup directory.
It never removes legacy data. The renderer refuses an unarchived collision.

## 2. Create the operator policy

Copy `deploy/config/deployment.env.example` to
`/etc/wcash-pool/deployment.env`, replace every `CHANGE_ME`, then set owner
`root:root` and mode `0600`. It contains no secret value. Leave the five exact
`BOOTSTRAP_DISCOVERY_REQUIRED` values in place until the fresh wallets emit
their account UUIDs, the Zallet ZIP-32 account index, and collector
commitments. That sentinel is accepted only by `wallet-bootstrap`; it can
never enter a backend, authority-check, preflight, or runtime pool policy.

Use stable UUIDs. After wallet discovery, never regenerate the deployment ID,
pool instance, signer account IDs, backend identity, backend journal, payout
commitments, or nonce namespace on restart. The renderer proves that each
display-order genesis hash is the exact reverse of the configured wire-order
value.

The supplied defaults name the deployed Testnet units
`wcash-testnet-node.service`, `wcash-peer-testnet.service`,
`zcash-template-testnet.service`, and `zcash-validator-testnet.service`, with
their cookies below `/run/*-rpc/.cookie`. If the host differs, stop and review
the exact units and cookie owners before changing policy; do not guess paths.

The initial nonce reservation is 65,536. A reservation of one million would
consume the 24-bit namespace after roughly seventeen starts and is not an
acceptable operational default.

## 3. Install the protected Wcash seed and prepare collector credentials

Prepare root-owned `0600` one-line files for a fresh Wcash spending seed, its
derived Ironwood collector address and exact 64-byte lowercase-hex incoming
viewing key, and a fresh Zcash Testnet Unified Address with an Ironwood
receiver. `WCASH_PAYOUT_MODE` must be `ironwood`; there is no transparent
fallback in this pool deployment. Do not place temporary source files in a
repository or shared directory. Install the seed first:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/install-protected-seed.sh" \
  /protected/wcash-seed \
  /etc/wcash-pool/deployment.env
```

The command refuses to replace a different existing seed. Securely erase the
temporary transfer copy after an independently verified offline backup. Keep
the public address and IVK source files protected until wallet discovery has
proved that they belong to the intended account.

## 4. Provision PostgreSQL

PostgreSQL 16 or newer is a launch prerequisite. PostgreSQL 14 is outside this
deployment's tested support window and is rejected before provisioning mutates
credentials or roles, and before preflight stops any running service. Upgrade
and validate the host database first; do not bypass the numeric
`server_version_num` gate.

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/provision-postgres.sh" \
  /etc/wcash-pool/deployment.env
```

This creates or reconciles a schema-owning migrator plus distinct public,
projector, and payout roles. No service role can create databases, roles, or
schema objects. The migration unit uses its own Unix UID, receives no portal or
custody credential, and cannot bind a socket. Provisioning also revokes legacy
migrator default table and sequence grants plus default public function
execution before installing the explicit least-authority matrix, so upgrades
cannot silently restore broad public authority. It also removes every prior
PostgreSQL role membership held by the migrator, public, projector, or payout
login; `NOINHERIT` alone would still permit an explicit `SET ROLE` escalation.
The public role has no DML on Wolf events, shares, winners,
ledger, reconciliation, payout batch, payout item, reorg, or payout-worker
lease tables. The projector alone inserts projection/accounting rows, but
cannot mutate portal credentials, payout destinations, payout batches, or
wallet state. The payout role has no mining-token, session, share, job, winner,
or backend-event mutation authority. Payout-destination creation and activation
and chain freezes cross narrow migrator-owned `SECURITY DEFINER` routines;
direct service-role table updates are revoked. Every new or replacement
destination receives an exact database-clock 48-hour pending hold and audit
entry. Only the migrator binds deployment identity and chain policy; all
runtimes verify those rows. Sequence access is granted only for each role's
actual identity inserts. The script generates strong local passwords and
protected connection URL files; it never prints them or places them in process
arguments.

## 5. Discover, review, and freeze fresh wallet authorities

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/render-deployment.sh" \
  wallet-bootstrap /etc/wcash-pool/deployment.env
```

This phase renders only the supervised Wcash wallet initializer and the
reviewed Zallet service/configuration. It cannot render a backend, listener,
preflight, or runtime pool policy. Every executable path points to the exact
version directory and every unit calls scripts from the matching deployment
snapshot.

An older transient `zcash-wallet-testnet.service` may already own the Zallet
RPC port and a funded datadir. The deployment deliberately does not stop, copy,
or migrate it. Back it up, prove the intended Testnet identity, and perform a
reviewed handover before disabling it. Restore the backed-up wallet only when
needed to derive a new dedicated account; never reuse its funded collector as
the pool collector. Under `/var/lib/zecwec-zallet`, initialize only the fresh
mnemonic/encryption state and leave the wallet at exactly zero accounts. Back
up the mnemonic and encryption identity offline and confirm the mnemonic
backup before continuing. The later `capture-original` step performs the sole
`z_getnewaccount`, captures its canonical Ironwood address and account index,
and proves its spendable Ironwood balance is exactly zero. Preflight fails if
another process still owns the RPC port.

The Wcash deployment similarly never modifies an existing wallet at another
path. Initialize or idempotently verify its dedicated database from Wcash
height one (the first valid wallet birthday, which scans all post-genesis
blocks):

```bash
sudo systemctl restart wcash-pool-wallet-init.service
```

This one-shot runs as the isolated `wcash-payout` identity, reads the seed only
from its private systemd credential mount, rejects an active public pool or
projector/payout worker, and refuses a symlinked or foreign wallet database. It
then performs one timeout-bounded serialized sync,
requires every Ironwood, legacy, transparent, pending, and spendable balance to
be exactly zero, and writes only public authority data to:

```text
/var/lib/wcash-payout/wcash-wallet-authority.json
```

Review its canonical `account_id`, `collector_payout_commitment`, genesis,
collector address, birthday, and `initial_balances_zero` result. That immutable
attestation is created only while every balance is zero. On later restarts,
earned Ironwood value is allowed but any legacy or transparent value remains a
hard failure. The initializer is idempotent: a different existing authority or
account fails closed. Subsequent
payout observations run one serialized, seedless sync immediately before
observation; no concurrent wallet-sync timer is deployed.

The successful Wcash wallet machine protocol is exactly version 2. This covers
`payout-identity`, payout request/response messages, and `payout-observe`; the
initializer and runtime reject version 1 and every unknown version before
creating authority or payout state. The authority file's `schema_version: 1`
is an independent on-disk schema, and the wallet CLI's version-1 error envelope
is an independent failure-only protocol. Neither is accepted as a successful
wallet response. Before the first mining job, restore the protected seed into
a fresh isolated wallet and prove it reproduces the frozen seed-derived payout
commitment; an IVK proves receipt capability but not spendability.

Keep the fresh isolated wallet's `init` and `payout-identity` JSON outputs in
temporary root-owned mode-`0600` files. After comparing them independently,
seal the live-host copy of the seed:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/seal-wcash-custody.sh" \
  /etc/wcash-pool/deployment.env \
  /protected/recovery-init.json \
  /protected/recovery-identity.json \
  /var/lib/wcash-payout/wcash-wallet-authority.json \
  --ack-independent-offline-backup-recovery
```

The verifier requires a newly created isolated database, a canonical and
internally consistent database-local account UUID, and exact equality of
network, genesis, branch ID, both seed-derived addresses, birthday, and payout
commitment. The UUID itself is deliberately not compared with the live wallet:
`zcash_client_sqlite` assigns a new random database-local UUID on each fresh
restore. The verifier writes only a deterministic root-only attestation and
changes the seed and its parent to `root:root` mode `0400`/`0700`. It freezes
the public wallet authority as `root:wcash-payout` mode `0440`, so the
payout-only wallet initializer can verify that exact binding after sealing.
Dropped-privilege checks prove that the public pool, projector, and backend
identities cannot traverse the authority's `wcash-payout` mode-`0700` parent or
read the source file; backend services receive only a private systemd
credential snapshot. Securely erase the temporary recovery output files after
review. Re-running host provisioning preserves this sealed state. The payout
worker receives a private systemd snapshot of the sealed seed; the public pool
and backend identities remain unable to traverse or read its source directory.

The wallet-bootstrap render also installs a disabled, manual-only recovery
configuration and unit. The recovery instance has a distinct Unix identity,
`zecwec-zallet-recovery`, its own `0700` datadir, and fixed loopback RPC
`127.0.0.1:28242`. It cannot read the original Zallet datadir or Wcash custody,
cannot broadcast, and is never wanted by the pool target.

Pin one reviewed immutable release and its matching lowercase hexadecimal
source suffix for the entire ceremony. The concrete values below are examples;
replace both assignments together before running any command and do not change
them midway through the ceremony:

```bash
ZECWEC_CEREMONY_RELEASE=/opt/wcash/releases/pool-0eb9c43
ZECWEC_CEREMONY_STAGING=/var/lib/zecwec-custody/zec-0eb9c43
```

Start only the original Zallet wallet and verify its authenticated Testnet
status:

```bash
sudo systemctl start zecwec-zallet.service
```

A start or restart can spend several minutes scanning Zcash Testnet's recent
chain window. The unit allows a bounded eighteen-minute authenticated readiness
interval and uses individually bounded `getwalletstatus` calls. It accepts only
an unlocked wallet whose node and wallet tips match, with no scan-work field
and any fully-synced height equal to that common tip. Zallet omits the
fully-synced height before an account exists; the later native gate requires it
after the collector is frozen.

Before creating the account, stop the service and use the same pinned binary,
datadir, configuration, and `zecwec-zallet` identity to run `export-mnemonic`
and `confirm-backup`; both commands require the exclusive datadir lock. Store
the age ciphertext and required identity on durable off-host media and verify
decryption yields one valid 24-word BIP39 phrase without printing it. This
prelaunch Testnet ceremony may retain one temporary root-owned `0400` plaintext
at `$ZECWEC_CEREMONY_STAGING/mnemonic.txt` alongside `mnemonic.age`. It is
forbidden after the recovery proof. Mainnet must use
offline custody from key creation and must never copy plaintext to this host.
Restart the original service and wait for its readiness gate.

Create the root-owned `0700` ceremony directory, snapshot the active cookie as
root `0400`, and let the immutable verifier capture account creation itself:

```bash
sudo install -d -o root -g root -m 0700 /var/lib/zecwec-custody
sudo install -o root -g root -m 0400 \
  /var/lib/zecwec-zallet/.cookie /var/lib/zecwec-custody/original.cookie
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/verify-zec-wallet-recovery.py" \
  capture-original /etc/wcash-pool/deployment.env 127.0.0.1:28232 \
  /var/lib/zecwec-custody/original.cookie \
  /var/lib/zecwec-custody/zec-wallet-original.rpc.json \
  "$ZECWEC_CEREMONY_RELEASE/wcash-poold"
```

The command requires a synchronized zero-account wallet, performs the single
`z_getnewaccount`, derives exactly one Orchard receiver at diversifier zero,
and records internally consistent authenticated envelopes. A create-only,
fsynced mutation intent is written immediately before the RPC and removed only
after the capture is durable. Any leftover intent is a hard taint requiring
manual review; never retry blindly or hand-author a capture.

Back up the original database and stop the service. Import the Testnet phrase
through the release-paired no-echo helper:

```bash
sudo systemctl stop zecwec-zallet.service
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/import-zallet-mnemonic.py" \
  "$ZECWEC_CEREMONY_RELEASE" \
  "$ZECWEC_CEREMONY_STAGING/mnemonic.txt" \
  --ack-testnet-fresh-recovery
sudo systemctl start zecwec-zallet-recovery.service
sudo install -o root -g root -m 0400 \
  /var/lib/zecwec-zallet-recovery/.cookie \
  /var/lib/zecwec-custody/recovery.cookie
```

The helper refuses a pre-existing recovery datadir or marker, disables core
dumps, terminal echo, and Zallet logs before sending the phrase, and never puts
it in argv, environment, stdout, stderr, or a log. Success writes a canonical
root-only completion marker bound to the exact release, staging directory, and
returned ZIP-32 seed fingerprint. Failure leaves a durable intent and tainted
datadir; recreate it only after review. After authenticated readiness, snapshot
the recovery cookie and capture the actual restore:

```bash
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/verify-zec-wallet-recovery.py" \
  capture-recovered /etc/wcash-pool/deployment.env \
  /var/lib/zecwec-custody/zec-wallet-original.rpc.json \
  127.0.0.1:28242 /var/lib/zecwec-custody/recovery.cookie \
  /var/lib/zecwec-custody/zec-wallet-recovered.rpc.json \
  "$ZECWEC_CEREMONY_RELEASE/wcash-poold" \
  --ack-fresh-isolated-mnemonic-import
```

This proves the restored wallet began with zero accounts, submits
`z_recoveraccounts` using the original RPC-derived fingerprint, index, and
birthday, derives diversifier zero again, and captures every envelope. UUIDs
are database-local and only need internal consistency; they are never compared
across databases. Stop the recovery instance and remove both cookie snapshots:

```bash
sudo systemctl stop zecwec-zallet-recovery.service
sudo unlink -- /var/lib/zecwec-custody/original.cookie
sudo unlink -- /var/lib/zecwec-custody/recovery.cookie
```

Both cookie snapshots must be absent before the final custody allowlist is
checked. Then seal the two captures:

```bash
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/verify-zec-wallet-recovery.py" \
  seal /etc/wcash-pool/deployment.env \
  /var/lib/zecwec-custody/zec-wallet-original.rpc.json \
  /var/lib/zecwec-custody/zec-wallet-recovered.rpc.json \
  /var/lib/zecwec-custody/zec-wallet-recovery.attestation.json \
  "$ZECWEC_CEREMONY_RELEASE/wcash-poold" \
  --ack-fresh-isolated-mnemonic-recovery
```

The verifier binds both root-only raw captures, recomputes the payout
commitment, and delegates Orchard receiver validation to the pinned Rust
consensus crate. The temporary cookie snapshots were removed before sealing.
Do not delete the mnemonic, identities, recovery datadir, or completion marker
by hand; the final ceremony verifies them immediately before irreversible
cleanup.

Replace all five discovery sentinels with the reviewed Wcash/Zcash account
UUIDs, commitments, and Zallet account index. Install both address credentials
and the Wcash IVK, then render the bootstrap policy:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/install-backend-credentials.sh" \
  /etc/wcash-pool/deployment.env \
  /protected/wcash-address /protected/zcash-address /protected/wcash-ivk
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/render-deployment.sh" \
  bootstrap /etc/wcash-pool/deployment.env
```

Restart the Wcash initializer, restart the original Zallet service, then run
and root-seal the live zero-balance ZEC authority before backend initialization:

```bash
sudo systemctl restart wcash-pool-wallet-init.service
sudo systemctl restart zecwec-zallet.service
sudo systemctl restart wcash-pool-zec-authority-bootstrap.service
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/seal-zec-initial-zero.sh" \
  /etc/wcash-pool/deployment.env "$ZECWEC_CEREMONY_RELEASE" \
  --ack-live-testnet-zero-gate
```

The native gate requires public Zcash Testnet NU6.3, the exact account,
commitment and index, Ironwood-only balances, stable common Zallet/Zebra tips,
and zero total value. Bootstrap writes temporary backend-owned evidence;
`seal-zec-initial-zero.sh` stops all backend-capable units, rejects rogue
backend-UID processes, revalidates it, and installs root `0400` evidence at:

```text
/var/lib/zecwec-custody/zec-collector-initial-zero.json
/var/lib/zecwec-custody/zec-collector-initial-zero.attestation
```

After the off-host ciphertext and identity restore is independently confirmed,
complete bootstrap and seal the hot Testnet payout credential:

```bash
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/finalize-zec-offline-custody.sh" \
  /etc/wcash-pool/deployment.env "$ZECWEC_CEREMONY_RELEASE" \
  "$ZECWEC_CEREMONY_STAGING" \
  --ack-testnet-off-host-backup-and-recovery
```

The finalizer requires the two captures, sealed recovery attestation,
root-sealed initial-zero pair, exact recovery-completion binding, no mutation
intent, and no unexpected custody entry. It copies the exact original Zallet
encryption identity into the configured root-owned mode-`0400` systemd
credential source, verifies any existing copy byte-for-byte, and only then
removes the original identity, plaintext/ciphertext staging, completion marker,
and isolated recovery datadir. The final gate proves the bootstrap and recovery
processes/listeners are gone, neither public mining identity can traverse the
remaining five-file evidence set or identity credential, and the Zallet user
cannot read the credential source outside its service mount.

## 6. Initialize the immutable Wolf authority

The old deployment may have created
`/var/lib/wcash-pool/share-journal-v2.jsonl` using an incompatible protocol.
Stop its owning service, review and archive that file outside the active state
path, and retain it for audit. Never delete, truncate, or feed it to this
deployment. Both backend initialization and preflight refuse to continue while
that legacy path exists. The new authority uses the explicit, separate
`/var/lib/wcash-pool-backend/*-protocol-v2*` identity and journal namespace.

Run the initializer once through systemd so node cookies and the private IVK
never enter an interactive environment:

```bash
sudo systemctl restart wcash-pool-backend-init.service
```

The backend initializer requires the native ZEC gate and the frozen Wcash
wallet authority. It cannot create backend identity from discovery sentinels,
missing initial-zero evidence, a changed ZEC authority configuration, or a
funded collector that has never passed the initial-zero gate.

The idempotent initializer writes
`/var/lib/wcash-pool-backend/backend-authority-protocol-v2.json`. It will reopen matching
identity/journal state, but it will never replace mismatched state. Back up the
backend identity and journal together. Copying one without the other is not a
valid recovery.

Finalize the policy from that authority:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/render-deployment.sh" \
  finalize \
  /etc/wcash-pool/deployment.env \
  /var/lib/wcash-pool-backend/backend-authority-protocol-v2.json
```

Finalization requires one exact authority schema and compares the Wcash and
Zcash wire-order genesis hashes, both payout commitments, chain ID, listener
count, and the conventional big-endian easiest share-target ceiling. Missing,
extra, reversed, or ambiguous fields are rejected. The pool then independently
compares the configured chain identities, payout commitments, backend
instance, wallet collector commitments, and journal stream during startup.

## 7. Migrate and preflight with no miner listener

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/preflight.sh" \
  /etc/wcash-pool/deployment.env
```

This explicitly stops the full target and every key-bearing runtime, disables
the bootstrap/recovery wallets, proves the Wcash seed and Zallet encryption
identity are root-sealed with matching off-host recovery evidence, and proves
the public mining identity cannot read either custody store. It starts the
private backend and projector only long enough to replay and validate the
frozen authorities, runs migrations, grants the public, projector, and payout
roles only their reviewed privileges, and runs a probe-only public dependency
graph without binding either the miner or portal listener. After the credential
snapshot, it stops and proves both the projector and backend fully inactive; an
error or signal also stops them. The non-key-bearing credential path watcher
remains enabled after success. Its reconciliation observes the inactive target
and runtime roles, so a dormant cookie rotation only updates the protected
digest snapshot and cannot start the backend, projector, pool, Zallet, or payout
worker. The preflight policy uses
`/run/credentials/wcash-pool-preflight.service`, never the runtime service's
credential mount. The probe binds the current read-only Wcash/Zcash chain tips
to the backend generation. It deliberately has no signer policy or wallet RPC
path and does not construct a signer journal, invoke wallet commands, call
transaction-submission RPCs, or change settlement state. The surrounding
orchestration can apply reviewed migrations and advance canonical derived
accounting while replaying the journal; those are explicit durable operations,
not capabilities of the probe-only payout composition path.

During live pool startup, the no-listener projector first replays Wolf's
journal, projects any snapshot gap, then retains its own live identity-bound
stream. It receives only its database credential and backend-socket group
membership; `SocketBindDeny=any` prevents it from opening a TCP listener. The
public mining unit requires and binds to that projector, conflicts with
bootstrap and recovery wallets, and has inaccessible-path fences over all
payout custody. After `ExecStartPre` returns,
`wcash-poold serve` validates the two node tips against Wolf's exact generation
and binds the source-restricted listener. It cannot compose automatic payout
mode or read either spending key. The separate `wcash-payout-worker.service`
has no listener and cannot read portal authentication credentials. It obtains
the payout database role, acquires its DB-clock lease, begins heartbeating,
then performs signer recovery and reconciliation. Readiness remains disabled
until both chain runtimes exist and the exact lease owner marks itself ready.

After success, a root-only path watcher fingerprints the three node cookies
without logging their contents. A rotation closes mining ingress before reading
a possibly mid-rename cookie, then stops the full target before its
`Upholds=` relationship can restart a dependent unit, refreshes only affected
node/backend authorities, proves the sources stable, restores the earlier
service state, waits for a fresh payout-owner heartbeat, restores the approved
source rules and persisted edge mode, reruns the full health contract, and only
then restarts the health timer. Any error or explicit early exit stops the target,
health timer, projector, public pool, payout worker, and payout Zallet and leaves
ingress closed after a failed or racing refresh. Check logs
without copying credential-bearing environment or configuration files:

```bash
sudo journalctl -u zecwec-zallet -u wcash-pool-backend \
  -u wcash-pool-projector \
  -u wcash-pool-migrate -u wcash-pool-preflight \
  -u zecwec-cookie-refresh --since today
```

## 8. Restrict the firewall and enable the edge

Create `/etc/wcash-pool/miner-cidrs`, root-owned mode `0600`, with one approved
ASIC public CIDR per line. World-open CIDRs are rejected. The script removes
generic rules for the current and legacy mining ports, preserves unrelated
firewall rules, and requires UFW to already be active with default-deny input.
It also owns a `ZECWEC-MINING-GUARD` chain in each filter ruleset and requires
one unconditional jump to that chain as the first `INPUT` rule. The guard
returns only exact approved IPv4 `/32` and IPv6 `/128` sources on ports 3333
and 3443 plus the exact loopback interface/source used by nginx to reach the
plaintext backend. It drops every other source plus every legacy-port attempt,
then returns unrelated traffic to the host policy. This first-position guard
makes an earlier direct `ACCEPT` or jump to another accepting chain a
verification failure instead of an allowlist bypass.

`apply` and `close` stage a closed replacement guard before changing UFW. The
open replacement is activated only after the exact persistent UFW allowlist is
installed. Guard replacement uses a new populated chain and a rule-one hook,
so it never flushes the active chain in place. `check` is read-only and proves
the exact guard order and contents in both address families as well as the UFW
rule set.

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/restrict-mining-firewall.sh" \
  close /etc/wcash-pool/deployment.env /etc/wcash-pool/miner-cidrs
```

Do not open the allowlist manually for launch. The readiness-gated start command
does that only after the payout worker proves a fresh lease.

Install the publicly trusted mining certificate and matching private key before
starting the pool, but do not publish mining DNS yet. The edge gate proves the
certificate covers `testnet-mine.zecwec.com`, has at least seven days remaining,
matches its private key, chains to the host's public trust store, and is the
certificate actually served by nginx on port 3443. A file-presence or listening-
port check alone is not accepted.

The apex and portal certificates, Cloudflare Authenticated Origin Pull CA,
proxied web DNS, Full (strict) zone setting, and Access application are not
prerequisites for this Stratum-only start. Configure them immediately before
`stage-portal`; that command requires both the apex and Testnet portal
certificate/key pairs because nginx loads both web virtual hosts. Install
Cloudflare's current official Authenticated Origin Pull CA at the exact
configured root-owned path and do not substitute an arbitrary client CA. nginx
snippets are staged in `sites-available` and `streams-available`. The start
command enables only the source-restricted TLS mining edge and deliberately
leaves the portal site disabled. An SSH tunnel may be used for service
diagnostics, but it is not browser E2E evidence: it does not exercise the
canonical HTTPS origin, `Secure`/`__Host-` cookies, or Cloudflare Authenticated
Origin Pulls.

If an older pool uses a different unit name but still occupies either mining
port, archive and disable that unit before continuing. The listener-free
preflight refuses any process that already owns the plaintext port.

## 9. Private start and ASIC gate

Only after source review, deterministic tests, final policy, miner CIDRs, and
the mining certificate gate are complete may the runtime start. On the scoped
never-activated prototype described in section 1, activate the pinned release;
this is the operation that atomically changes its stale selector and starts it:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/activate-release.sh" \
  "${ZECWEC_BOOTSTRAP_RELEASE##*/}" \
  /etc/wcash-pool/deployment.env \
  /var/lib/wcash-pool-backend/backend-authority-protocol-v2.json \
  /etc/wcash-pool/miner-cidrs \
  --ack-forward-schema-compatible
```

On a host whose selector already names this reviewed epoch-2 release, use the
normal readiness-gated start instead:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/start-testnet-pool.sh" \
  /etc/wcash-pool/deployment.env /etc/wcash-pool/miner-cidrs
```

Both paths first remove all current and legacy mining allow rules, repeat
probe-only listener-free preflight, start the full Testnet target behind the
closed firewall, and waits a bounded interval for signer recovery and a fresh
payout-worker heartbeat. Only then does it restore the exact source allowlist,
reconcile nginx to the durable portal launch mode, and run health. Health requires the public pool, backend,
payout worker, and payout Zallet to be active; Zallet must listen only on
literal loopback, `/readyz` must report `payout_execution=enabled`, and a
failure stops every public/key-bearing pool component and closes mining ingress.

The command enables `zecwec-testnet-pool-start.service` as the sole boot entry
point. The raw target and health timer are deliberately not enabled: on every
boot the one-shot is ordered after a requested nginx start, closes persisted
UFW rules even if nginx failed to start, repeats preflight,
starts the target, waits for payout readiness, restores only the previously
acknowledged edge mode, proves full health, and only then starts the minute
health timer. The root-owned portal mode is persisted before its nginx link;
missing, stale, or invalid state removes the managed link and fails closed. A
failed scheduled health check closes the target, its listeners, and the mining
firewall. The health unit retains only the additional `CAP_NET_ADMIN` capability
needed to inspect and close the raw guard, and its otherwise read-only
filesystem namespace exposes only UFW's configuration and the two existing
firewall lock files as writable. There is no boot-time window where the timer
can race a recovering payout lease.

Before the browser gate, create a Cloudflare Access application covering
`testnet.zecwec.com/*`, allow only the named Testnet operator identity, and
verify the default policy denies every other identity. Then stage the portal:

```bash
sudo env ZECWEC_RELEASE_PATH="$ZECWEC_BOOTSTRAP_RELEASE" \
  "$ZECWEC_BOOTSTRAP_DEPLOY/enable-nginx-edge.sh" \
  stage-portal \
  /etc/wcash-pool/deployment.env \
  /etc/wcash-pool/miner-cidrs \
  --ack-cloudflare-access
```

This command enables the HTTPS origin only after local health succeeds. It
proves the origin rejects a direct request without Cloudflare client
authentication and proves an anonymous request through Cloudflare receives
only a redirect, 401, or 403 from Access. Any failed probe removes the newly
enabled portal link and reloads nginx. The authorized operator can now run the
complete browser flow at the canonical HTTPS hostname with real cookie and
origin semantics while the portal remains unavailable to the public.

Before telling an operator to point an ASIC, prove all of the following:

- both Wcash nodes agree on canonical tip and genesis;
- both Zcash Testnet nodes agree on canonical tip and genesis;
- both protected backups independently reproduce their frozen collector
  account, address, and payout commitment;
- the Wcash recovery attestation matches the frozen authority and the mining
  identity cannot read or traverse either wallet custody store;
- payout Zallet is active only on its configured loopback RPC; the bootstrap
  and recovery Zallet units are inactive and the recovery port is absent;
- backend identity, journal stream, payout commitments, and chain ID match;
- the projector is active under its dedicated UID, has no TCP listener, and a
  forced projector stop also closes public miner intake;
- registration, login, TOTP, worker creation/revocation, and both payout
  destination flows work through HTTPS;
- accepted/rejected/duplicate/stale shares update the correct worker metrics;
- WEC-only, ZEC-only, and dual winner paths conserve accounting;
- restart/reorganization handling neither loses nor duplicates mining
  liabilities;
- one actual ASIC share is accepted through the source-restricted endpoint;
- payout execution reports `enabled` only from a fresh exact-owner DB heartbeat;
- a matured Testnet payout can be constructed, journaled, broadcast through
  the independent node path, confirmed, and recovered idempotently after a
  forced restart.

After every gate above has evidence recorded, remove the Cloudflare Access
application, confirm the zone still uses Full (strict) and Authenticated Origin
Pulls, then enable the public portal with an explicit operator acknowledgement:

```bash
sudo scripts/deploy/enable-nginx-edge.sh \
  publish-portal \
  /etc/wcash-pool/deployment.env \
  /etc/wcash-pool/miner-cidrs \
  --ack-e2e-gates
```

Immediately before that command, activate only the proxied apex/Testnet web
records after confirming the zone's origin-pull setting; remove them again if
the command fails. Portal publication fails closed unless an unauthenticated
direct-origin probe is rejected and the same health path succeeds through
Cloudflare. Publish the DNS-only `testnet-mine.zecwec.com` record only after
the private ASIC gate. Do not create or enable `mine.zecwec.com`.

Run the local health contract at any time:

```bash
sudo scripts/deploy/health-check.sh \
  --settings /etc/wcash-pool/deployment.env \
  --cidrs /etc/wcash-pool/miner-cidrs
```

## Release activation, rollback, and recovery

Application rollback never rewinds the database. Use only a release explicitly
reviewed as schema-compatible, from deployment security epoch 2 or newer, and
acknowledge that fact:

```bash
sudo scripts/deploy/rollback-release.sh \
  <release-id> \
  /etc/wcash-pool/deployment.env \
  /var/lib/wcash-pool-backend/backend-authority-protocol-v2.json \
  /etc/wcash-pool/miner-cidrs \
  --ack-schema-compatible
```

The script verifies the mining artifact digests and the release-paired deployment
snapshot, stops the pool authorities and credential watcher, renders from that
exact target release, atomically changes the selection link, verifies the
immutable ZEC initial-zero evidence, reruns migration, probe-only preflight,
and credential snapshotting, and then starts the full public+payout target. A
failed start, payout-readiness wait, or health check leaves the target, health
timer, public pool, payout worker, and payout Zallet stopped. Database rollback
is never automatic; the explicit schema-compatible acknowledgement is
mandatory.

Epoch 1 is intentionally not rollback-compatible. Those packages predate the
separate projector and migrator identities and can reinstall broad public
database grants. The rollback script reads the immutable epoch marker and uses
the current trusted verifier before stopping any service or executing target
deployment code; an epoch-1 target therefore fails closed with the running
epoch-2 service untouched.

Back up PostgreSQL, the two payout journals, Wcash wallet database, Wcash seed,
Zallet datadir and encryption identity, the ZEC initial-zero evidence, and the
backend identity/journal using an encrypted offline process. Test restoration
on an isolated Testnet host. Never restore only one side of an
identity/journal, initial-zero-evidence, or wallet/journal pair.

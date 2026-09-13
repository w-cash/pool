# ZecWec Testnet deployment runbook

## Scope and readiness claim

This runbook deploys one account-based WEC/ZEC merged-mining **Testnet** pool:

- account registration, login, TOTP, workers, revocable mining tokens;
- independent WEC and ZEC payout destinations and histories;
- accepted/stale/invalid/duplicate share counters plus block, reward, and
  payout observations; calibrated hashrate projection remains unavailable;
- one ZIP-301 work stream with independent Wcash and Zcash winner handling;
- PPLNS accounting with zero launch fee and chain-separated liabilities;
- deferred payout execution: collector spending keys stay offline while
  mining runs, and the portal reports that state explicitly.

It does not enable Mainnet. Installing these files is not evidence that the
pool is ASIC-ready. The private mining signal requires all source gates,
independent collector-recovery proofs, initial-zero attestations, deployment
preflight, restart/reorganization tests, and one real accepted ASIC share.
Testnet payout transactions are a later, separately authorized ceremony and
are not allowed to hold the mining work stream online.

## Security boundaries

The services run under separate Unix identities. `wcash-pool-backend` owns the
AuxPoW authority, identity, append-only winner journal, and node credentials.
`wcash-pool` owns miner sessions, the ledger, and the portal. It can reach the
backend only through a
`0660` Unix socket in a `0750` non-writable directory. `zecwec-zallet` owns its
persistent wallet database and encryption identity, but it is stopped and
disabled after the one-time collector authority is sealed.

The live mining unit mounts neither collector seed, wallet database, signer
journal, Zallet configuration, nor Zallet cookie; systemd also makes those
paths inaccessible. Node cookies, payout addresses, the read-only Wcash IVK,
database URLs, portal pepper, and TOTP key use systemd credential mounts. No
spending seed appears in an argument, environment variable, unit, repository,
log, or mining-process filesystem view.

Zallet uses public Testnet, beta.3 RPC semantics, loopback RPC, and:

```toml
[external]
broadcast = false
```

The payout pipeline persists exact transaction bytes before the independent
Zebra RPC broadcasts them. Enabling Zallet broadcasting would violate the
crash-recovery boundary and is rejected by the signer.

Release directories are root-owned and non-writable. Every service is rendered
with one canonical `/opt/wcash/releases/<release-id>` path and never executes
through the mutable `current` symlink. It verifies the selected binary against
an exact four-entry `SHA256SUMS` manifest before execution. Installation also
snapshots the matching templates, runbook, and scripts into that release and
binds them with `DEPLOYMENT-SHA256SUMS`. Rollback renders from that exact
snapshot, so old binaries can never be paired silently with new templates.
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
| Zallet RPC | offline during mining | Manual collector bootstrap and payout ceremony only |
| Backend Unix socket | pool/backend group only | Immutable job and share authority |

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
host. The release directory must contain exactly these executable files and an
exact manifest:

```text
wcash-poold
wcash-merge-miner
wcash-wallet
zallet
SHA256SUMS
```

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

If an older deployment owns `wcash-pool.service`, archive and disable it before
rendering any new unit:

```bash
sudo scripts/deploy/disable-legacy-pool.sh wcash-pool.service
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
sudo scripts/deploy/install-protected-seed.sh \
  /protected/wcash-seed \
  /etc/wcash-pool/deployment.env
```

The command refuses to replace a different existing seed. Securely erase the
temporary transfer copy after an independently verified offline backup. Keep
the public address and IVK source files protected until wallet discovery has
proved that they belong to the intended account.

## 4. Provision PostgreSQL

```bash
sudo scripts/deploy/provision-postgres.sh /etc/wcash-pool/deployment.env
```

This creates or reconciles a schema-owning migrator and a separate runtime
role. The runtime role cannot create databases, roles, or schema objects. It
receives only connect, schema usage, table DML, and sequence permissions. The
script generates strong local passwords and protected connection URL files; it
never prints them or places them in process arguments.

## 5. Discover, review, and freeze fresh wallet authorities

```bash
sudo scripts/deploy/render-deployment.sh \
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

This one-shot runs as `wcash-pool`, reads the seed only from its protected file
on standard input, rejects an active public pool, and refuses a symlinked or
foreign wallet database. It then performs one timeout-bounded serialized sync,
requires every Ironwood, legacy, transparent, pending, and spendable balance to
be exactly zero, and writes only public authority data to:

```text
/var/lib/wcash-pool/wcash-wallet-authority.json
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
sudo scripts/deploy/seal-wcash-custody.sh \
  /etc/wcash-pool/deployment.env \
  /protected/recovery-init.json \
  /protected/recovery-identity.json \
  /var/lib/wcash-pool/wcash-wallet-authority.json \
  --ack-independent-offline-backup-recovery
```

The verifier requires a newly created isolated database, a canonical and
internally consistent database-local account UUID, and exact equality of
network, genesis, branch ID, both seed-derived addresses, birthday, and payout
commitment. The UUID itself is deliberately not compared with the live wallet:
`zcash_client_sqlite` assigns a new random database-local UUID on each fresh
restore. The verifier writes only a deterministic root-only attestation,
changes the seed and its parent to `root:root` mode `0400`/`0700`, and proves
with a dropped-privilege access check that `wcash-pool` cannot read it. Securely
erase the temporary recovery output files after review. Re-running host
provisioning preserves this sealed state. Reopening custody later is a
separate, explicit payout ceremony; it must never overlap the mining service.

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
sudo scripts/deploy/install-backend-credentials.sh \
  /etc/wcash-pool/deployment.env \
  /protected/wcash-address /protected/zcash-address /protected/wcash-ivk
sudo scripts/deploy/render-deployment.sh bootstrap /etc/wcash-pool/deployment.env
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
close online Testnet custody:

```bash
sudo "$ZECWEC_CEREMONY_RELEASE/deployment/scripts/deploy/finalize-zec-offline-custody.sh" \
  /etc/wcash-pool/deployment.env "$ZECWEC_CEREMONY_RELEASE" \
  "$ZECWEC_CEREMONY_STAGING" \
  --ack-testnet-off-host-backup-and-recovery
```

The finalizer requires the two captures, sealed recovery attestation,
root-sealed initial-zero pair, exact recovery-completion binding, no mutation
intent, and no unexpected custody entry. Only then does it remove the original
on-host decryption identity, plaintext/ciphertext staging, completion marker,
and isolated recovery datadir. The final gate proves both wallet identities
have no process or listener and neither mining identity can traverse the
remaining root-only five-file evidence set. These proofs and two payout
commitments are the only collector facts the mining runtime needs.

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
sudo scripts/deploy/render-deployment.sh \
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
sudo scripts/deploy/preflight.sh /etc/wcash-pool/deployment.env
```

This explicitly stops and disables the bootstrap wallets, proves the Wcash
seed is sealed behind host DAC with a matching recovery attestation, proves
the Zallet state and configuration are unreadable by the mining identity,
starts the private backend, validates both frozen collector authorities and the
immutable ZEC initial-zero evidence, runs migrations, grants the runtime role only its
required DML, and runs a
probe-only pool dependency graph without binding either the miner or portal
listener. The preflight policy uses
`/run/credentials/wcash-pool-preflight.service`, never the runtime service's
credential mount. The probe binds the current read-only Wcash/Zcash chain tips
to the backend generation. It deliberately has no signer policy or wallet RPC
path and does not construct a signer journal, invoke wallet commands, call
transaction-submission RPCs, or change payout state.

The mining unit also declares a systemd conflict with Zallet and both bootstrap
units. Starting any custody service therefore stops mining rather than allowing
the offline-key invariant to drift silently. After `ExecStartPre` returns,
`wcash-poold serve` validates the two node tips
against Wolf's exact generation and binds the source-restricted listener. It
spawns no payout task and cannot read either spending key. Payout settings and
liabilities remain durable, while execution returns a stable unavailable
response until an audited payout ceremony is deliberately activated.

After success, a root-only path watcher fingerprints the three node cookies
without logging their contents. A rotation stops the public pool, refreshes
only the affected node/backend authorities, proves
the sources stable, and then restarts the pool only if the Testnet target was
already active. A failed or racing refresh leaves the pool stopped. Check logs
without copying credential-bearing environment or configuration files:

```bash
sudo journalctl -u zecwec-zallet -u wcash-pool-backend \
  -u wcash-pool-migrate -u wcash-pool-preflight \
  -u zecwec-cookie-refresh --since today
```

## 8. Restrict the firewall and enable the edge

Create `/etc/wcash-pool/miner-cidrs`, root-owned mode `0600`, with one approved
ASIC public CIDR per line. World-open CIDRs are rejected. The script removes
generic rules for the current and legacy mining ports, preserves unrelated
firewall rules, and requires UFW to already be active with default-deny input.

```bash
sudo scripts/deploy/restrict-mining-firewall.sh \
  apply /etc/wcash-pool/deployment.env /etc/wcash-pool/miner-cidrs
```

Install the reviewed certificates, but do not publish the web origin or mining
DNS before this firewall gate. Install Cloudflare's current official
Authenticated Origin Pull CA at the exact configured root-owned path, enable
Authenticated Origin Pulls for the `zecwec.com` zone, set SSL/TLS mode to Full
(strict), and configure the edge to redirect HTTP to HTTPS. Do not substitute
an arbitrary client CA. nginx snippets are staged in `sites-available` and
`streams-available`. Enable only the source-restricted TLS mining edge for the
private ASIC test; activation is atomic with `nginx -t`:

```bash
sudo scripts/deploy/enable-nginx-edge.sh \
  stratum-only \
  /etc/wcash-pool/deployment.env \
  /etc/wcash-pool/miner-cidrs
```

This deliberately leaves the portal nginx site disabled. An SSH tunnel may be
used for service diagnostics, but it is not browser E2E evidence: it does not
exercise the canonical HTTPS origin, `Secure`/`__Host-` cookies, or Cloudflare
Authenticated Origin Pulls.

If an older pool uses a different unit name but still occupies either mining
port, archive and disable that unit before continuing. The listener-free
preflight refuses any process that already owns the plaintext port.

## 9. Private start and ASIC gate

Only after source review and all deterministic tests pass:

```bash
sudo scripts/deploy/start-testnet-pool.sh \
  /etc/wcash-pool/deployment.env /etc/wcash-pool/miner-cidrs
```

The command applies the source allowlist first, repeats probe-only listener-free
preflight, enables only the source-restricted TLS Stratum listener, starts the
pool, and stops `wcash-pool.service` if post-start health fails. Runtime payout
execution is deferred; health requires that exact state and requires Zallet to
be inactive with no wallet RPC listener.

Before the browser gate, create a Cloudflare Access application covering
`testnet.zecwec.com/*`, allow only the named Testnet operator identity, and
verify the default policy denies every other identity. Then stage the portal:

```bash
sudo scripts/deploy/enable-nginx-edge.sh \
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
- Zallet is stopped and no wallet RPC listener is present;
- backend identity, journal stream, payout commitments, and chain ID match;
- registration, login, TOTP, worker creation/revocation, and both payout
  destination flows work through HTTPS;
- accepted/rejected/duplicate/stale shares update the correct worker metrics;
- WEC-only, ZEC-only, and dual winner paths conserve accounting;
- restart/reorganization handling neither loses nor duplicates mining
  liabilities;
- one actual ASIC share is accepted through the source-restricted endpoint;
- payout execution reports `deferred` and cannot sign or broadcast.

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

## Rollback and recovery

Application rollback never rewinds the database. Use only a release explicitly
reviewed as schema-compatible, and acknowledge that fact:

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
and credential snapshotting, and then starts the pool. It keeps both wallet
services stopped. A failed start or health check
leaves the public pool service stopped. Database rollback is never automatic;
the explicit schema-compatible acknowledgement is mandatory.

Back up PostgreSQL, the two payout journals, Wcash wallet database, Wcash seed,
Zallet datadir and encryption identity, the ZEC initial-zero evidence, and the
backend identity/journal using an encrypted offline process. Test restoration
on an isolated Testnet host. Never restore only one side of an
identity/journal, initial-zero-evidence, or wallet/journal pair.

# ZecWec Testnet deployment runbook

## Scope and readiness claim

This runbook deploys one account-based WEC/ZEC merged-mining **Testnet** pool:

- account registration, login, TOTP, workers, revocable mining tokens;
- independent WEC and ZEC payout destinations and histories;
- accepted-share, hashrate, block, reward, and payout observations;
- one ZIP-301 work stream with independent Wcash and Zcash winner handling;
- PPLNS accounting with zero launch fee and chain-separated settlement.

It does not enable Mainnet. Installing these files is not evidence that the
pool is ASIC-ready. The final signal requires all source gates, deployment
preflight, restart/reorganization tests, one real accepted ASIC share, and
verified Testnet payout transactions on both ledgers.

## Security boundaries

The services run under separate Unix identities. `wcash-pool-backend` owns the
AuxPoW authority, identity, append-only winner journal, and node credentials.
`wcash-pool` owns miner sessions, the ledger, the portal, the Wcash collector
wallet database, and payout journals. It can reach the backend only through a
`0660` Unix socket in a `0750` non-writable directory. `zecwec-zallet` owns its
persistent wallet database and encryption identity.

The Wcash seed is the deliberate exception to systemd credential transport.
The native WEC signer requires a canonical, single-link file owned by the pool
UID with mode exactly `0600`; it is stored below a root-owned `0710` directory.
Node cookies, payout addresses, the read-only Wcash IVK, database URLs, portal
pepper, TOTP key, Zallet config, and Zallet cookie use systemd credential
mounts. No spending seed appears in an argument, environment variable, unit,
repository, or log.

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
| Wcash/Zcash/Zallet/PostgreSQL RPC | loopback only | Internal authorities |
| Backend Unix socket | pool/backend group only | Immutable job and share authority |

The portal hostname must use Cloudflare Full (strict) mode with Authenticated
Origin Pulls enabled. nginx requires Cloudflare's client certificate and
rejects an absent `CF-Connecting-IP`; only that Cloudflare-overwritten value is
forwarded to the loopback portal. Direct port 80 returns no application
response. This is mandatory because the DNS-only mining hostname reveals the
same origin IP. The mining hostname must remain DNS-only unless a paid
Cloudflare product explicitly supports generic TCP proxying. ASIC TLS needs a
publicly trusted certificate such as Let's Encrypt.

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
the pool collector. Initialize the new account under `/var/lib/zecwec-zallet`,
confirm its canonical Ironwood address and account index, prove its spendable
Ironwood balance is exactly zero, and back up its mnemonic and encryption
identity offline. Preflight fails if another process still owns the RPC port.

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

Start only the persistent Zallet wallet and verify its authenticated Testnet
status:

```bash
sudo systemctl start zecwec-zallet.service
```

Zallet account creation and mnemonic backup are deliberately reviewed manual
bootstrap steps. Record the new account's canonical UUID, ZIP-32 index, and
canonical Ironwood Unified Address from Zallet without copying its seed into a
shell argument, environment variable, log, or deployment file. If a restored
Zallet has multiple accounts, select the new dedicated zero-balance account
explicitly; the deployment never guesses. Compute the parent payout
commitment as lowercase SHA-256 over the exact byte string
`Wcash/Zcash parent payout address/v1\0` followed immediately by the canonical
UA bytes. Independently compare that value with the reviewed source constant
before freezing policy.

Replace all five discovery sentinels with the reviewed canonical Wcash/Zcash
account UUIDs, both commitments, and the Zallet ZIP-32 index. Install the
canonical collector addresses and Wcash incoming viewing key, then re-render
the authority bootstrap; sentinels are now forbidden:

```bash
sudo scripts/deploy/install-backend-credentials.sh \
  /etc/wcash-pool/deployment.env \
  /protected/wcash-address \
  /protected/zcash-address \
  /protected/wcash-ivk
sudo scripts/deploy/render-deployment.sh \
  bootstrap /etc/wcash-pool/deployment.env
```

Restart the Wcash wallet initializer once against the frozen values. Then run
the native ZEC authority gate before the first backend initialization:

```bash
sudo systemctl restart wcash-pool-wallet-init.service
sudo systemctl restart wcash-pool-zec-authority-bootstrap.service
```

The installer refuses to replace different credentials. It invokes the pinned
wallet parser and rejects anything other than one canonical Wcash Testnet
Ironwood address. The native `wcash-poold zec-authority-check` command reads
both RPC cookies only through its systemd credential mount. It requires public
Zcash Testnet, NU6.3, the configured account UUID/index and domain-separated
commitment, Ironwood-only balances, a stable exact common Zallet/Zebra tip,
and zero total collector value before the backend exists. Its bounded result
contains no address, UUID, commitment, or seed fingerprint and is sealed with
the exact authority-configuration digest in:

```text
/var/lib/wcash-pool-backend/zec-collector-initial-zero.json
/var/lib/wcash-pool-backend/zec-collector-initial-zero.attestation
```

Review and back up both files with the backend authority. If the backend does
not yet exist, every retry repeats the live zero-value check. Once the backend
authority exists, service restarts and release rollback verify this immutable
initial-zero evidence instead of requiring an earned collector to become
empty again. Normal pool preflight still checks the current live identity,
tip, Ironwood-only balance, and exact database reconciliation on every start.

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

This starts the loopback wallet and private backend, idempotently verifies the
Wcash wallet, validates the immutable ZEC initial-zero evidence, runs
migrations, grants the runtime role only its required DML, and runs the
complete pool dependency graph without binding either the miner or portal
listener. The preflight policy uses
`/run/credentials/wcash-pool-preflight.service`, never the runtime service's
credential mount. On the first start, both dedicated collectors and the new
ledger are zero. On funded restarts, the runtime verifies exact wallet/backend
commitments, both node authorities, payout capabilities, current
wallet-to-ledger reconciliation, and historical transaction lookup before it
succeeds; it does not rerun a zero-balance bootstrap check.

Preflight does not create, sign, broadcast, confirm, or reorganize a real miner
payout. It proves configuration and live dependency readiness without opening
listeners; it is not payout E2E evidence. Public readiness still requires the
two real Testnet payout transactions and restart/reorganization exercises in
the ASIC gate below.

After success, a root-only path watcher fingerprints the three node cookies and
the Zallet cookie without logging their contents. A rotation stops the public
pool, refreshes only the affected supervised wallet/backend authorities, proves
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

This deliberately leaves the portal nginx site disabled. Use an SSH tunnel to
the loopback portal for pre-launch registration, payout, and dashboard tests.

If an older pool uses a different unit name but still occupies either mining
port, archive and disable that unit before continuing. The listener-free
preflight refuses any process that already owns the plaintext port.

## 9. Private start and ASIC gate

Only after source review and all deterministic tests pass:

```bash
sudo scripts/deploy/start-testnet-pool.sh \
  /etc/wcash-pool/deployment.env /etc/wcash-pool/miner-cidrs
```

The command applies the source allowlist first, repeats listener-free preflight,
enables only the source-restricted TLS Stratum listener, starts the pool, and
stops `wcash-pool.service` if post-start health fails.

Before telling an operator to point an ASIC, prove all of the following:

- both Wcash nodes agree on canonical tip and genesis;
- both Zcash Testnet nodes agree on canonical tip and genesis;
- Zallet is fully synchronized and the intended account is present;
- backend identity, journal stream, payout commitments, and chain ID match;
- registration, login, TOTP, worker creation/revocation, and both payout
  destination flows work through HTTPS;
- accepted/rejected/duplicate/stale shares update the correct worker metrics;
- WEC-only, ZEC-only, and dual winner paths conserve accounting;
- restart after each durable payout stage neither loses nor duplicates value;
- confirmation and reorganization handling freeze or reverse liabilities;
- one actual ASIC share is accepted through the source-restricted endpoint;
- a real Testnet payout for each funded asset is confirmed and visible in the
  miner's portal history.

After every gate above has evidence recorded, enable the public portal with an
explicit operator acknowledgement:

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

The script verifies all four artifact digests and the release-paired deployment
snapshot, stops the pool authorities and credential watcher, renders from that
exact target release, atomically changes the selection link, verifies the
immutable ZEC initial-zero evidence, reruns Wcash wallet verification,
migration, full live ledger preflight, and credential snapshotting, and then
starts the pool. A failed start or health check leaves the public pool service
stopped. Database rollback is never automatic; the explicit schema-compatible
acknowledgement is mandatory.

Back up PostgreSQL, the two payout journals, Wcash wallet database, Wcash seed,
Zallet datadir and encryption identity, the ZEC initial-zero evidence, and the
backend identity/journal using an encrypted offline process. Test restoration
on an isolated Testnet host. Never restore only one side of an
identity/journal, initial-zero-evidence, or wallet/journal pair.

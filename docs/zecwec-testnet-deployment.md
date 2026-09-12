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

Release directories are root-owned and non-writable. Every service verifies
the selected binary against an exact four-entry `SHA256SUMS` manifest before
execution. The pool additionally pins the Wcash wallet digest in its policy.

## Network layout

| Endpoint | Exposure | Purpose |
| --- | --- | --- |
| Portal backend | loopback | Registration, dashboard, payout settings |
| Apex web | Cloudflare-proxied after the launch gate | `zecwec.com`, redirects to Testnet |
| Portal HTTPS | Cloudflare-proxied after the launch gate | `testnet.zecwec.com` |
| ZIP-301 plaintext | approved source CIDRs only | Legacy ASIC compatibility |
| ZIP-301 TLS | approved source CIDRs only, nginx TLS | Preferred ASIC endpoint |
| Wcash/Zcash/Zallet/PostgreSQL RPC | loopback only | Internal authorities |
| Backend Unix socket | pool/backend group only | Immutable job and share authority |

The portal hostname may be Cloudflare-proxied in Full (strict) mode. The mining
hostname must remain DNS-only unless a paid Cloudflare product explicitly
supports generic TCP proxying. A Cloudflare Origin certificate is appropriate
for the proxied portal, but ASIC TLS normally needs a publicly trusted
certificate such as Let's Encrypt.

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
selects the release only when no `/opt/wcash/current` link exists.

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
`root:root` and mode `0600`. It contains no secret value.

Use stable UUIDs. Never regenerate the deployment ID, pool instance, signer
account IDs, backend identity, backend journal, payout commitments, or nonce
namespace on restart. The renderer proves that each display-order genesis hash
is the exact reverse of the configured wire-order value.

The initial nonce reservation is 65,536. A reservation of one million would
consume the 24-bit namespace after roughly seventeen starts and is not an
acceptable operational default.

## 3. Install credentials

Prepare root-owned `0600` one-line files for the Wcash collector address, the
Zcash collector address, and the Wcash spending seed. Transparent Wcash
coinbase is the integration default and must not load a private incoming
viewing key. If `WCASH_PAYOUT_MODE=ironwood`, also prepare the exact 64-byte raw
Orchard incoming viewing key for that collector. Do not place temporary source
files in a repository or shared directory.

```bash
sudo scripts/deploy/install-backend-credentials.sh \
  /etc/wcash-pool/deployment.env \
  /protected/wcash-address \
  /protected/zcash-address

sudo scripts/deploy/install-protected-seed.sh \
  /protected/wcash-seed \
  /etc/wcash-pool/deployment.env
```

For explicit private Ironwood coinbase, append `/protected/wcash-ivk` as the
fourth argument. The renderer includes the IVK systemd credential only in that
mode; supplying it in transparent mode is rejected.

Both commands refuse to replace a different existing secret. Securely erase
the temporary transfer copies after an independently verified offline backup.

## 4. Provision PostgreSQL

```bash
sudo scripts/deploy/provision-postgres.sh /etc/wcash-pool/deployment.env
```

This creates or reconciles a schema-owning migrator and a separate runtime
role. The runtime role cannot create databases, roles, or schema objects. It
receives only connect, schema usage, table DML, and sequence permissions. The
script generates strong local passwords and protected connection URL files; it
never prints them or places them in process arguments.

## 5. Render bootstrap configuration and initialize wallets

```bash
sudo scripts/deploy/render-deployment.sh \
  bootstrap /etc/wcash-pool/deployment.env
```

This installs reviewed unit/config templates but starts and enables nothing.
Initialize or restore the Zallet collector under `/var/lib/zecwec-zallet` using
its service identity. Confirm and back up its mnemonic and encryption identity
offline. Do not generate a throwaway replacement when an expected collector
wallet is unavailable.

Start only the persistent wallet and verify its authenticated Testnet status:

```bash
sudo systemctl start zecwec-zallet.service
```

## 6. Initialize the immutable Wolf authority

Run the initializer once through systemd so node cookies and the private IVK
never enter an interactive environment:

```bash
sudo systemctl restart wcash-pool-backend-init.service
```

The idempotent initializer writes
`/var/lib/wcash-pool-backend/backend-authority.json`. It will reopen matching
identity/journal state, but it will never replace mismatched state. Back up the
backend identity and journal together. Copying one without the other is not a
valid recovery.

Finalize the policy from that authority:

```bash
sudo scripts/deploy/render-deployment.sh \
  finalize \
  /etc/wcash-pool/deployment.env \
  /var/lib/wcash-pool-backend/backend-authority.json
```

The pool will independently compare the configured chain identities, payout
commitments, backend instance, and journal stream during startup.

## 7. Migrate and preflight with no miner listener

```bash
sudo scripts/deploy/preflight.sh /etc/wcash-pool/deployment.env
```

This starts the loopback wallet and private backend, runs migrations, grants
the runtime role only its required DML, and runs pool bootstrap. It refuses to
continue if the public Stratum listener is already open. Check logs without
copying credential-bearing environment or configuration files:

```bash
sudo journalctl -u zecwec-zallet -u wcash-pool-backend \
  -u wcash-pool-migrate -u wcash-pool-preflight --since today
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
DNS before this firewall gate. nginx snippets are staged in `sites-available`
and `streams-available`. Enable only the source-restricted TLS mining edge for
the private ASIC test; activation is atomic with `nginx -t`:

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

Only then activate the proxied apex/Testnet web records and the DNS-only
`testnet-mine.zecwec.com` record. Do not create or enable `mine.zecwec.com`.

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
  /var/lib/wcash-pool-backend/backend-authority.json \
  /etc/wcash-pool/miner-cidrs \
  --ack-schema-compatible
```

The script verifies all four artifact digests, stops the pool authorities,
atomically changes the release link, re-renders the wallet digest pin, reruns
migration/preflight, and starts the pool. A failed start or health check leaves
the public pool service stopped.

Back up PostgreSQL, the two payout journals, Wcash wallet database, Wcash seed,
Zallet datadir and encryption identity, and the backend identity/journal using
an encrypted offline process. Test restoration on an isolated Testnet host.
Never restore only one side of an identity/journal or wallet/journal pair.

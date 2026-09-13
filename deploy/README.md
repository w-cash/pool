# ZecWec Testnet deployment package

This directory contains a fail-closed deployment skeleton for the Wcash/Zcash
merged-mining Testnet pool. It does not contain credentials, collector keys,
host addresses, or a Mainnet configuration.

The package intentionally separates four authorities:

- `wcash-pool-backend`: talks to the Wcash and Zcash template/validator nodes
  and owns the durable AuxPoW backend journal;
- `wcash-pool`: accepts miners, maintains the PostgreSQL liability ledger, and
  serves the loopback portal without receiving either collector spending key;
- `zecwec-zallet`: is a manual bootstrap and later payout tool. It creates and
  proves the Zcash collector, then remains stopped while mining is live;
- PostgreSQL: uses a schema-owning migration role and a non-DDL runtime role.

The backend socket is `0660`, owned by the backend user and the
`wcash-pool-socket` group. The socket directory is not group-writable. The pool
service is the only expected non-backend member of that group.

## Deployment order

1. Build the four release binaries on a reviewed x86-64 builder and create an
   exact `SHA256SUMS` file: `wcash-poold`, `wcash-merge-miner`, `wcash-wallet`,
   and the Zallet beta.3 binary used by the deployment. Installation snapshots
   this deployment package beside the binaries and verifies a second manifest.
2. Copy `deploy/config/deployment.env.example` to a protected operator file,
   replace every `CHANGE_ME` value, and review the two genesis byte orders.
   Leave only the five exact wallet-discovery sentinels until the fresh wallets
   provide their public account UUIDs, Zallet account index, and payout
   commitments.
3. Run `scripts/deploy/provision-host.sh`. If an old service uses the
   `wcash-pool.service` name, archive and disable it now with
   `disable-legacy-pool.sh`; the renderer refuses to overwrite it.
4. Run `scripts/deploy/install-release.sh`. It does not start a public service.
5. Install a fresh, dedicated Wcash collector seed with
   `install-protected-seed.sh` and prepare its address/IVK plus a fresh Zcash
   Ironwood address without installing them into runtime yet.
6. Run `provision-postgres.sh`. It creates or reconciles independent database
   roles and protected connection credentials without printing passwords.
7. Run `render-deployment.sh wallet-bootstrap`, initialize and fully sync the
   Wcash wallet through its supervised one-shot unit, and review its emitted
   public authority. Perform the reviewed Zallet handover into a fresh empty
   account. Replace all discovery sentinels, install the matching collector
   credentials, then run `render-deployment.sh bootstrap`. The native ZEC
   authority gate must seal its initial-zero evidence before the backend can
   initialize. Independently restore both collectors from their protected
   backups. Verify the recovered Wcash public identity and run
   `seal-wcash-custody.sh`; this records a root-only recovery attestation and
   removes host-DAC access to the seed from the mining identity. Then stop and
   disable both wallet bootstrap services. Use
   `verify-zec-wallet-recovery.py` to make authenticated loopback RPC captures
   of the original account creation and the independent mnemonic recovery. Its
   root-only mode-`0400` attestation binds those raw envelopes, the exact ZIP-32
   account index and birthday, and the natively validated Orchard-only address
   commitment without requiring database-local account UUIDs to match. This
   attestation is a mandatory pool-start custody gate. Archive any incompatible
   legacy share journal first.
8. Run `render-deployment.sh finalize`; inspect both generated pool policies,
   run `wcash-pool-migrate.service`, and run `preflight.sh`.
9. Apply `restrict-mining-firewall.sh` with explicit ASIC source CIDRs. It
   refuses world-open CIDRs.
10. Start the private deployment and run `health-check.sh`. This enables only
    source-restricted mining; the portal site stays disabled and reports
    `payout_execution=deferred`. Mature liabilities accumulate in PostgreSQL;
    a separately reviewed, on-demand payout ceremony is required before funds
    move. The mining unit conflicts with every wallet/bootstrap unit, and
    preflight proves host DAC denies the mining identity access to both
    custody stores.

The portal origin is not directly reachable even though mining DNS reveals the
server IP. Its nginx virtual host requires Cloudflare Authenticated Origin
Pulls and forwards only Cloudflare's overwritten client-IP header. Plain HTTP
returns no application response.

See [`docs/zecwec-testnet-deployment.md`](../docs/zecwec-testnet-deployment.md)
for the exact runbook, security invariants, rollback procedure, and outstanding
release gates.

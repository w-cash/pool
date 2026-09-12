# ZecWec Testnet deployment package

This directory contains a fail-closed deployment skeleton for the Wcash/Zcash
merged-mining Testnet pool. It does not contain credentials, collector keys,
host addresses, or a Mainnet configuration.

The package intentionally separates four authorities:

- `wcash-pool-backend`: talks to the Wcash and Zcash template/validator nodes
  and owns the durable AuxPoW backend journal;
- `wcash-pool`: accepts miners, maintains the PostgreSQL ledger, serves the
  loopback portal, and invokes isolated payout signers;
- `zecwec-zallet`: owns the persistent Zcash collector wallet and exposes RPC
  on loopback with wallet broadcasting disabled;
- PostgreSQL: uses a schema-owning migration role and a non-DDL runtime role.

The backend socket is `0660`, owned by the backend user and the
`wcash-pool-socket` group. The socket directory is not group-writable. The pool
service is the only expected non-backend member of that group.

## Deployment order

1. Build the four release binaries on a reviewed x86-64 builder and create an
   exact `SHA256SUMS` file: `wcash-poold`, `wcash-merge-miner`, `wcash-wallet`,
   and the Zallet beta.3 binary used by the deployment.
2. Copy `deploy/config/deployment.env.example` to a protected operator file,
   replace every `CHANGE_ME` value, and review the two genesis byte orders.
3. Run `scripts/deploy/provision-host.sh`. If an old service uses the
   `wcash-pool.service` name, archive and disable it now with
   `disable-legacy-pool.sh`; the renderer refuses to overwrite it.
4. Run `scripts/deploy/install-release.sh`. It does not start a public service.
5. Install the Wcash seed with `install-protected-seed.sh`; install the backend
   payout credentials with `install-backend-credentials.sh`.
6. Run `provision-postgres.sh`. It creates or reconciles independent database
   roles and protected connection credentials without printing passwords.
7. Run `render-deployment.sh bootstrap`, initialize or restore Zallet, then
   start `wcash-pool-backend-init.service` exactly as described in the runbook.
8. Run `render-deployment.sh finalize`; inspect both generated pool policies,
   run `wcash-pool-migrate.service`, and run `preflight.sh`.
9. Apply `restrict-mining-firewall.sh` with explicit ASIC source CIDRs. It
   refuses world-open CIDRs.
10. Start the private deployment and run `health-check.sh`. This enables only
    source-restricted mining; the portal site stays disabled. Only after the
    end-to-end payout/restart/reorg gate passes may an operator acknowledge
    portal publication, add more source CIDRs, or publish mining DNS.

See [`docs/zecwec-testnet-deployment.md`](../docs/zecwec-testnet-deployment.md)
for the exact runbook, security invariants, rollback procedure, and outstanding
release gates.

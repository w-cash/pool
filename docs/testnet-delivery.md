# Testnet delivery

## Decision

Finish the existing Rust pool as the single deployed implementation. Reuse its
Wolf mining backend, ZIP-301 edge, account service, PostgreSQL ledger and
chain-specific signers. No S-NOMP runtime or second integration track is part
of this release.

The operator-facing result is a working miner portal at
`https://testnet.zecwec.com` and ordinary Equihash `(200,9)` mining through:

- `stratum+ssl://testnet-mine.zecwec.com:3443`;
- `stratum+tcp://testnet-mine.zecwec.com:3333`.

These are target endpoints, not a readiness assertion. Each miner uses an
account/worker identity and a separate mining-only token. The portal stores two
independent payout destinations. Zcash permits transparent or supported
shielded destinations; Wcash uses its verified shielded destination profile.
No miner wallet key is requested.

## Acceptance order

1. Integrate the startup credential correction, reviewed miner UI and Zcash
   payout compatibility. Preserve custody separation, exact backend identity,
   durable accounting and fail-closed admission.
2. Run the complete service composition against local Wcash/Zcash regtest and
   PostgreSQL 16 or newer. Use real node validation and wallet transactions.
   Check the actual account-to-worker-to-share-to-ledger path, independent
   chain winners, duplicate/restart handling and both chains' payouts.
3. Exercise the packaged nginx routes and systemd credential lifetime on
   Ubuntu 22.04. These operating-system checks supplement the real chain test.
4. Only after local acceptance, build and install the exact remote release,
   run listener-free preflight, activate and verify the public HTTPS/TCP/TLS
   paths. Cloudflare proxies the web hostname; Stratum remains DNS-only.
5. Invite the controlled ASIC team, record real hardware shares and job
   rotation, and then record discovered Testnet rewards and their eventual
   payments as separate observations.

The explorer is outside this release. Existing wallet/node state and balances
must survive ordinary deployment and restart. No new VPS or data migration is
required merely to finish the pool.

## Evidence

Record source revisions, artifact digests, scenario, environment, timestamp
and result. Never put credentials, full payout destinations or wallet material
in this file. A completed component test is not a substitute for the complete
service flow. Pending evidence must remain labeled pending.

| Gate | Status |
| --- | --- |
| Integrated Rust release checks | Component suites passed; final proof-lifecycle correction under verification |
| Miner portal on the real local services | Passed: 42 browser checks, including account, worker revocation and both Zcash destination profiles |
| Complete local regtest mining and accounting | Pending: preserved chains at height 23 exposed duplicate Wcash economic-block insertion; recovery under verification |
| Real Zcash transparent and shielded payments | Pending |
| Real Wcash payment and restart reconciliation | Pending |
| Ubuntu package and origin routing | Passed locally: actual systemd 249 credentials and nginx origin mTLS/routes on Ubuntu 22.04; deployment package checks passed |
| Remote preflight and public endpoint acceptance | Pending |
| Physical ASIC accepted work | Pending |
| Public Testnet mined-reward payment | Await block discovery and confirmation |

At pool revision `1e9650956ef1928df2dc64e6ccc5f8d9b5866523`, dependency policy
checks passed and a production-default static x86_64 Linux pool binary built
successfully with Rust 1.91 and cargo-zigbuild. That binary ran on Ubuntu 22.04;
115 cross-compiled component tests also passed there. These platform checks do
not approve that revision for deployment: the real height-23 accounting failure
requires the subsequent proof-lifecycle correction and a new exact release.

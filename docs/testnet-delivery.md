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
must survive ordinary deployment and restart. Use the existing VPS and durable
state, applying the reviewed proof-lifecycle schema migration without resetting
the database, journals, or wallets.

The deployment manages only the Testnet portal and mining host. The apex
`zecwec.com` keeps its existing website or redirect and needs no pool certificate.
When upgrading an older deployment, back up its protected settings and remove
the retired `APEX_HOST`, `APEX_TLS_CERT` and `APEX_TLS_KEY` entries before rendering.
Portal origin authentication and its exact hostname remain required.

## Evidence

Record source revisions, artifact digests, scenario, environment, timestamp
and result. Never put credentials, full payout destinations or wallet material
in this file. A completed component test is not a substitute for the complete
service flow. Pending evidence must remain labeled pending.

Record the runtime-source revision and deployment-package-source revision
separately. The validated pool binary uses runtime source
`9567b7e0597e38ef315a77df8fa0d9c4e7b3423b`. Deployment package changes include
backend connection capacity and certificate renewal routes. The native
production build follows the complete local acceptance gate, which passed at
2026-09-14 02:06 UTC.

| Gate | Status |
| --- | --- |
| Integrated Rust release checks | Passed: final `bbe4274`/`e85ea46` component suites and real PostgreSQL alias, lifecycle, migration/backfill, and side-chain regressions; `9567b7e` preference regression passed on PostgreSQL 16 with store Clippy; native `11ffc3b` passed 221 library and 17 CLI tests (two existing library tests ignored) |
| Final Linux pool artifact and component checks | Passed: production-default `9567b7e` static x86_64 musl binary ran on Ubuntu 22.04 and rejected the actual Regtest config; 203 unchanged protocol/backend/core/edge tests previously executed there |
| Miner portal on the real local services | Passed: 42 browser checks, including account, worker revocation and both Zcash destination profiles |
| Complete local regtest mining and accounting | Passed at 206: 219 shares, 214 canonical mature winners and two settled payments; original state preserved through exact-tip restarts |
| Same-session duplicate replay | Passed at 105: one accepted share, identical replay rejected as stale, unchanged share/allocation/ledger totals |
| Real Zcash transparent and shielded payments | Passed at 206: exact mixed-recipient transaction included at 106 on both independent parents, 101 confirmations, both recipient output values and account deltas match, one conserved settlement |
| Real Wcash payment and restart reconciliation | Passed at 206 with 101 confirmations; separate recipient wallet decrypted the matching non-change note; normal worker restarts preserved both payments and produced no duplicate |
| Interrupted signing recovery | Passed through broadcast: the original unsigned ZEC batch resumed after a clean worker/wallet stop; the two original batch IDs and WEC transaction were preserved |
| Due payout settings and settled restart | Passed with `9567b7e`: all three paid profiles active with automatic payouts disabled, no pending settings, fresh matched wallet/ledger reconciliations, clean worker exits and lease release, unchanged signed bytes and signer journals |
| Prompt network block submission | Passed with `11ffc3b`: three actual accepted proofs reached exact committed membership on all three nodes within 1.326, 0.306 and 0.323 seconds after client completion, with the historical backlog preserved |
| Ubuntu package and origin routing | Passed locally: actual systemd 249 credentials and nginx origin mTLS/routes on Ubuntu 22.04; deployment package checks passed |
| Remote preflight and public endpoint acceptance | Pending |
| Physical ASIC accepted work | Pending |
| Public Testnet mined-reward payment | Await block discovery and confirmation |

The final production-default static x86_64 musl pool binary at `9567b7e` has
SHA-256 `09b20c60c6a920dfe790bf9caefb18272474bc1f0bf96b5d07a02d0459a0b82d`.
Its `--help` command ran successfully on Ubuntu 22.04 AMD64, and the exact
production binary rejected the actual Regtest configuration with networking
disabled. The earlier Linux test executables passed all 203 unchanged
protocol/backend/core/edge tests (39/40/63/61), matching the macOS results.
An earlier `1e96509` run also passed 115 signer/component tests on Ubuntu;
the signer code in those checks is unchanged.

The normal payout worker created exactly two batches covering three recipient
profiles. Its first ZEC proof exceeded the unchanged 180-second deadline in an
unoptimized debug Zallet. The worker and wallet stopped gracefully. The same
pinned, patched source built with standard release optimization resumed the
original unsigned batch, reaching verified proof within 18 seconds and signed
preparation within 42 seconds of worker startup. No replacement payment was
created. Both actual signed transactions were independently matched to node
bytes, canonical block membership, immutable payout items and recipient receipts.

Automatic payouts were then disabled through the ordinary authenticated portal
API while the worker was stopped. The run mined 100 full blocks after inclusion,
then resumed the same worker. Both original payments reached Confirmed with
101 confirmations at height 206, and each settled exactly once. The independent
live verifier passed with 219 shares, 214 canonical mature winners, two confirmed
batches, three recipient profiles and a conserved ledger. No confirmation policy,
balance, journal, wallet or batch was reset.

This check exposed a preference-promotion bug: an empty eligible-payment set
rolled back an otherwise valid due setting change. Runtime `9567b7e` commits
those promotions after the existing safety and wallet reconciliation checks and
before any payment or reservation write. A real PostgreSQL regression verifies
disabling the final recipient, raising its threshold, durable settings across
repeated empty selections, unchanged financial state and rollback on invalid
reconciliation. The updated worker then promoted all three paid profiles and
completed an additional normal restart. Both starts reached ready, produced fresh
matched wallet/ledger reconciliations and exited cleanly with their leases
released. The original two confirmed payments, signed bytes and signer journals
were unchanged; each retained exactly one reservation and settlement.

The 42 real browser checks, actual duplicate replay and recipient receipts remain
separate evidence. The full local acceptance gate passed at 2026-09-14 02:06 UTC;
remote and physical ASIC checks remain separate pending gates. Prompt block submission passed after a
controlled upgrade at height 170 that preserved all three exact tips, 180 shares,
350 economic winners, 360 proofs, 494 sealed ledger transactions and both original
signed payment batches. The scheduler uses the existing worker and unchanged
journal/CAS rules; new pending winners receive a bounded first attempt before
historical status checks. All four scheduling regression tests passed.

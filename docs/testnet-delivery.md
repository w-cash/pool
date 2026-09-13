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

## Evidence

Record source revisions, artifact digests, scenario, environment, timestamp
and result. Never put credentials, full payout destinations or wallet material
in this file. A completed component test is not a substitute for the complete
service flow. Pending evidence must remain labeled pending.

Record the runtime-source revision and deployment-package-source revision
separately. The validated pool binary uses runtime source
`e85ea46cc04c7d35083a526eff28d11704254903`; a later documentation-only package
revision reuses that binary with its exact newly generated deployment-package
manifest. The native production build from selected `c0e3687` remains after
the complete local acceptance gate.

| Gate | Status |
| --- | --- |
| Integrated Rust release checks | Passed: final `bbe4274`/`e85ea46` component suites and real PostgreSQL alias, lifecycle, migration/backfill, and side-chain regressions; native `c0e3687` passed 217 tests |
| Final Linux pool artifact and component checks | Passed: production-default `e85ea46` static x86_64 musl binary ran on Ubuntu 22.04; 203 `bbe4274` protocol/backend/core/edge tests executed there |
| Miner portal on the real local services | Passed: 42 browser checks, including account, worker revocation and both Zcash destination profiles |
| Complete local regtest mining and accounting | In progress: preserved-height-23 recovery succeeded with the proof-lifecycle correction and real mining resumed; full payout, controlled restart, and replay gates remain pending |
| Real Zcash transparent and shielded payments | Pending |
| Real Wcash payment and restart reconciliation | Pending |
| Ubuntu package and origin routing | Passed locally: actual systemd 249 credentials and nginx origin mTLS/routes on Ubuntu 22.04; deployment package checks passed |
| Remote preflight and public endpoint acceptance | Pending |
| Physical ASIC accepted work | Pending |
| Public Testnet mined-reward payment | Await block discovery and confirmation |

The final production-default static x86_64 musl pool binary at `e85ea46` has
SHA-256 `4aea7f43990231743b2a911359163bead06e95980c46a54947308fafb7ead026`.
It is byte-identical to the `bbe4274` production binary and its `--help` command
ran successfully on Ubuntu 22.04 AMD64. The matching Linux test executables
passed all 203 protocol/backend/core/edge tests (39/40/63/61), matching the
macOS results. An earlier `1e96509` run also passed 115 signer/component tests
on Ubuntu; the signer code in those checks is unchanged.

The 42 real browser checks and prior real worker-token authorization/revocation
checks remain separate evidence. Component tests, successful preserved-state
recovery, and platform checks do not complete the outstanding actual payment,
recipient-receipt, controlled restart, and same-session replay acceptance gates.
Remote activation remains pending those local results.

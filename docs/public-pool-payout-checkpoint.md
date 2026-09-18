# Public pool payout checkpoint

This checkpoint defines the remaining Testnet work between the current
merge-mining service and a public account-based pool that pays miners. It does
not change the mining or payout policy by itself.

## What exists now

The pool already has a single identity path from Stratum to accounting:

1. An account owns one or more workers.
2. Each worker has the canonical mining login `account.worker` and a generated
   mining-only token.
3. Stratum authenticates that pair against PostgreSQL and binds every accepted
   share to immutable account and worker identifiers.
4. Wolf independently classifies a share as ordinary work, a Wcash winner, a
   Zcash winner, or a winner on both chains.
5. The projector records accepted work and computes a separate PPLNS allocation
   for each chain winner. WEC and ZEC therefore have independent liabilities,
   maturity, and payout state even though they originate from one ASIC stream.

Payout addresses are account settings, not part of the worker name or token.
Each account has one active WEC destination and one active ZEC destination.
Changing one destination does not change the worker login or the other asset.

The repository contains registration, login, logout, browser sessions, CSRF
protection, worker creation and revocation, payout destination management,
account-scoped balances and history, PPLNS accounting, payout batching, WEC and
ZEC signer boundaries, broadcasting, confirmation watching, and reorg
handling. Logout revokes the browser session only. An ASIC continues mining
until its worker token is revoked or the connection is stopped.

## Live deployment boundary on 2026-09-18

The current Testnet host proves mining and accounting, but it is not yet a
public payout service:

- Stratum is public on port 3333 and the portal process is bound only to
  `127.0.0.1:8080`.
- Portal liveness and the aggregate overview answer locally, but `/readyz`
  fails closed because the complete validation and payout dependencies are not
  available.
- The database contains authenticated accounts, workers, accepted shares,
  winners, and PPLNS allocations.
- There are no configured payout destinations, payout batches, or browser
  sessions.
- The runtime uses `payout_mode = "deferred"`; rewards stay as conserved pool
  liabilities and no automatic payment is created.
- The isolated payout worker and the Zcash payout wallet services are not
  installed as active units on this host.
- The configured browser origin is still `https://testnet.w.cash`, while the
  public product documentation specifies `https://testnet.zecwec.com`. One
  origin must be selected and used consistently by DNS, TLS, the reverse
  proxy, cookies, CSRF validation, and runtime configuration.

The current Testnet policy is a 0% pool fee, a 1 WEC/ZEC automatic threshold,
100 confirmations, at most 50 outputs per batch, and a bounded miner-funded
network fee reserve. The live destination-change hold is only 60 seconds for
testing. A longer public policy must be chosen and published before launch.

## Intended miner flow

1. The miner registers an account and signs in with the portal password.
2. The miner configures an Ironwood-capable Wcash Testnet Unified Address and a
   supported Zcash Testnet address.
3. The miner creates a worker and copies its one-time mining token into the
   ASIC with the generated `account.worker` login.
4. Accepted target work is recorded for that account and participates in both
   chain-specific PPLNS windows.
5. When the pool finds a block, that chain's reward is divided by selected
   work. The allocation starts as immature.
6. After canonical confirmation and the configured maturity depth, the ledger
   moves the allocation to payable.
7. The isolated payout worker selects payable accounts above their threshold,
   seals an immutable batch, asks only the matching chain signer to create the
   exact outputs, persists the transaction identity, and broadcasts it.
8. Confirmation moves the batch to paid and returns any unused fee reserve.
   Reorganizations reverse maturity or payment state through append-only
   accounting rather than deleting history.

## Required public-Testnet work

1. **Freeze the policy.** Publish the WEC and ZEC PPLNS windows, maturity
   depths, minimum thresholds, batch schedule, network-fee rules, destination
   types, destination-change hold, dormant-account policy, and testnet reset
   policy.
2. **Publish the portal.** Put the loopback portal behind HTTPS, set the exact
   production origin, load independent protected session/TOTP keys, rate-limit
   registration and login, and expose no database or wallet interface.
3. **Enable account ownership.** Exercise registration, login, logout, password
   lockout, worker creation/revocation, and recovery for existing manually
   provisioned Testnet workers. A portal password must never be accepted as an
   ASIC password.
4. **Enable destinations.** Connect authoritative Wcash and Zcash Testnet
   address validators and exercise valid, wrong-network, malformed, pending,
   held, replaced, and missing destinations.
5. **Deploy isolated custody.** Run the WEC payout wallet, Zcash payout wallet,
   single-lease payout worker, confirmation watchers, and reconciliation gates
   with separate protected credentials. Keep mining available when payouts are
   deliberately paused, while readiness reports that distinction honestly.
6. **Prove two-account conservation.** Mine with two accounts and demonstrate
   that accepted work, dual and single-chain winners, PPLNS allocations,
   immature balances, payable balances, batches, transaction outputs, fees,
   and paid balances remain account- and chain-separated.
7. **Exercise failures.** Test exact retry, process restart, ambiguous
   broadcast, expired transaction, insufficient collector balance, node
   outage, stale wallet, deep reorganization, payout pause/resume, and restored
   database/wallet backups without duplicate payment or lost liability.
8. **Operate it.** Add alerts for stale jobs, share rejection, node divergence,
   projector lag, ledger conservation, collector reconciliation, payout-worker
   lease, failed batches, and low collector balance. Complete a backup and
   restore drill before inviting public miners.

## Launch decision

The current implementation should be extended and deployed rather than
replaced. Share identity, chain-separated PPLNS accounting, portal APIs, and
payout state machines already exist and are integrated around one PostgreSQL
deployment identity. The shortest robust path is to enable and prove the
existing portal and payout components on Testnet, then close any failures found
by that end-to-end exercise. Mainnet remains a separate release and custody
review.

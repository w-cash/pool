# Mainnet account portal cutover

The current `mainnet.zecwec.com:3333` endpoint is Wolf direct Stratum. Its
worker registry is not a Pool account database. Wolf's journal records winners,
but does not provide the ordinary accepted-share history needed to calculate a
per-account PPLNS balance. Neither the current collector balance nor historical
Wolf shares may be presented as a new account's payable balance.

The account Pool is a separate deployment. Its Stratum listener is port 3334,
its HTTPS portal belongs at `pool.zecwec.com`, and its Wolf backend, PostgreSQL
database, journal, nonce namespace, and collector accounting must be isolated
from the invited-worker service. Port 3333 remains available throughout staging.

`registration_open` is false by default on Mainnet. Opening the portal does not
open registration; the operator sets `registration_open = true` only after all
of the following have been observed on the isolated deployment:

1. The backend and pool pin the actual Wcash/Zcash Mainnet genesis hashes,
   chain ID, collector commitments, and synchronized authoritative node tips.
2. A private miner on 3334 successfully authenticates, receives work, submits
   ordinary shares, and sees those exact shares attributed to its account in
   PostgreSQL and in the portal. Rejected and duplicate shares remain distinct.
3. A Wcash-only winner and a Zcash winner, or deterministic private-network
   equivalents with the same production ingestion path, produce chain-specific
   reward facts. Maturity, reorganization, and payout eligibility are reflected
   in the account view without inventing historical rewards.
4. A separately controlled collector is backed up and its opening balance is
   reconciled. If the Zcash template node's existing recipient is reused,
   perform and review an explicit opening-balance migration first. Do not
   silently treat funds earned on port 3333 as funds owed by new accounts.
5. The public portal serves over HTTPS with same-origin API, registration,
   login/logout, worker creation/revocation, separate WEC/ZEC payout settings,
   account-isolated share/reward histories, and request limits verified against
   the live staging database. The ASIC token grants mining access only.
6. Actual WEC and ZEC payout transactions reach independent recipients and
   reconcile with the ledger through maturity, restart, fee, and reorg cases
   before automatic payout execution is enabled. Mainnet currently permits
   only deferred payouts; the UI must say that execution is paused.

The public launch can be split: account registration and share accounting may
open first with an explicit deferred-payout notice and an operator commitment
to settle earned balances. Automatic payments require their own release and
on-chain receipt evidence. No staging page should advertise port 3334 before
that port accepts and records real shares.

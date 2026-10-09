# Mainnet account portal cutover

The current `mainnet.zecwec.com:3333` endpoint is Wolf direct Stratum. Its
worker registry is not a Pool account database. Wolf's journal records winners,
but does not provide the ordinary accepted-share history needed to calculate a
per-account PPLNS balance. Neither the current collector balance nor historical
Wolf shares may be presented as a new account's payable balance.

The account Pool is a separate deployment. Its HTTPS portal is
`pool.zecwec.com`. ASICs use `mainnet.zecwec.com:3336`; GPU and CPU miners use
the lower-difficulty endpoint `mainnet.zecwec.com:3338`. Both adapt short-job-ID
firmware before forwarding submissions to isolated internal listeners. Port
3334 remains an unadvertised operational fallback. All three account-pool
listeners use the same deployment, Wolf backend, PostgreSQL share ledger,
workers, and payout accounting. Exact target-derived work prevents an easier
GPU share from being over-credited. They stay isolated from the direct Wolf
service on port 3333.

`registration_open` is false by default on Mainnet. Opening the portal does not
open registration; the operator sets `registration_open = true` only after all
of the following have been observed on the isolated deployment:

1. The backend and pool pin the actual Wcash/Zcash Mainnet genesis hashes,
   chain ID, collector commitments, and synchronized authoritative node tips.
2. A private miner on 3336 successfully authenticates, receives work, submits
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
6. Actual payout transactions reach independent recipients and reconcile with
   the relevant chain ledger through maturity, restart, fee, and reorg cases
   before automatic execution is enabled for that chain. WEC automatic
   execution belongs to the isolated payout worker. ZEC remains manual until
   its independent acceptance evidence is complete.

The public launch can be split: account registration and share accounting may
open independently from chain-specific payout execution. The public portal
process always remains deferred and without spending authority, so its
`/readyz` value does not describe the isolated WEC worker. The UI and
production manifest must state each chain's payout mode separately. No page
should advertise a mining route before that route accepts and records real
shares.

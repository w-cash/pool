# ZecWec pool product design

> **Status:** This is the product and security contract for the ZecWec
> merged-mining pool. The repository now contains the Testnet miner edge,
> conserved PostgreSQL ledger, portal, chain-separated collector observers,
> crash-safe signers, and an isolated automatic payout-worker deployment. This
> is still not a public-deployment claim: do not send miners or funds until the
> host ceremony and end-to-end release gates below have recorded evidence.

## Decision summary

ZecWec will be an account-based PPLNS pool for Equihash ASICs. One ASIC
connection submits one stream of work that can earn WEC and ZEC independently.
The miner configures one worker login on the ASIC and two chain-specific payout
destinations in the private web portal.

| Decision | Launch policy |
| --- | --- |
| Miner protocol | ZIP-301-compatible Stratum; TLS on port 3443 is preferred, with a restricted plaintext port 3333 for legacy ASIC firmware |
| ASIC identity | `account.worker` plus a generated, revocable mining-only token |
| Reward method | Chain-specific PPLNS based on accepted work, not raw share count |
| WEC collector | Direct private Wcash Ironwood coinbase, gated by exact read-only recipient verification |
| ZEC collector | Direct Zcash Ironwood coinbase; receipt remains publicly recoverable under ZIP-213 |
| Miner destinations | Wcash Ironwood-capable address; Zcash transparent P2PKH/P2SH or Ironwood-capable address, chosen by the miner |
| Custody | Separate collectors, wallets, keys, ledgers, maturity rules, and payout batches for WEC and ZEC |
| Testnet/Mainnet | Separate deployments and security domains; Mainnet stays unavailable until a later audited release |
| Initial settlement | PPLNS and automatic threshold payouts; no PPS/PPS+ balance-sheet risk at launch |

There is no combined ZEC/WEC address and no reason to reuse a private key across
the chains. A worker token can mine only. It cannot sign in to the portal, read
balances, change payout settings, or request a withdrawal.

## What happens to a mining reward

One returned Equihash proof can be an ordinary pool share, a Wcash block
winner, a Zcash block winner, or a winner on both chains. The chains decide
independently because they have different targets, histories, rewards, and
confirmation state.

```text
one ASIC proof stream
        |
        v
authoritative Wolf validation
        |
        +-- accepted work --------> WEC PPLNS window
        |                           ZEC PPLNS window
        |
        +-- Wcash winner ---------> Wcash collector -> WEC ledger
        |
        +-- Zcash winner ---------> Zcash collector -> ZEC ledger
        |
        `-- dual winner ----------> both independent paths
```

Accepted shares do not create coins and do not increase a collector wallet.
The relevant collector receives value only after this pool finds a block and
the corresponding chain accepts it. A Zcash block may therefore take much
longer to fund than a Wcash block.

When a block is observed, the exact pool-recipient reward is allocated to the
eligible PPLNS work for that chain. It first appears as immature. It becomes
payable only after Wolf emits the chain-specific maturity fact and the pool has
reconciled the collector wallet. An orphan or reorganization creates an
append-only reversal; it never edits the original event away.

The pool wallet balance is an asset, not pool profit. At the same time the
collector gains a reward, the accounting system records amounts owed to
miners. For each asset and accepted block, allocation must conserve exactly:

```text
exact collector reward
    = sum of miner allocations + disclosed pool fee
```

Deterministic largest-remainder allocation assigns every atomic unit of the
post-fee reward, so “rounding” cannot become hidden operator revenue. The
collector wallet has a separate roll-forward invariant:

```text
opening reconciled balance + canonical receipts - orphan reversals
    - completed miner payout value - network fees
    = closing reconciled balance
```

Unpaid-liability and pool-equity ledgers reconcile separately to that wallet
balance after every maturity, reversal, and payout. An unexplained difference
freezes payouts. Administrative corrections never appear as an invariant
catch-all; they require typed, approved, append-only entries and reconciliation.

The allocation is performed in the chain's integer atomic unit. Rounding must
use a deterministic largest-remainder or equivalent conserving rule. Dust,
transaction fees, and administrative adjustments need published policies and
auditable ledger entries. Wcash having no consensus developer tax does not
mean that an independently operated mining pool has no service fee; any pool
fee must be displayed before mining and versioned rather than changed silently.

ZecWec launch policy has a 0% pool fee, but miners pay the actual network fee
needed to deliver their payout. Batch creation deducts the tightest of the
published absolute limit, relative limit, and nonzero-output safety bound from
the selected gross balances, split by deterministic largest-remainder
allocation. That maximum is committed
into the immutable signer request. After confirmation, the same deterministic
rule charges only the fee present in the signed transaction and returns every
unused reserved atomic unit to the affected miners' payable balances. The
collector therefore never requires hidden operator capital, and a full-balance
payout conserves exactly: gross liabilities equal miner outputs plus network
fee plus any returned reserve.

## Coinbase privacy: Wcash and Zcash are different

“Ironwood” names a shielded protocol pool. It does not mean that a mining pool
is private or permissioned.

### WEC collector

Wolf's miner configuration accepts either a Wcash transparent P2PKH/P2SH
address or a Wcash Unified Address with an Orchard receiver, which its builder
routes into Ironwood. At the consensus layer, Wcash enforces one payout mode:
it rejects mixed transparent/Ironwood coinbases, Sapling or legacy Orchard
rewards, a missing positive payout, an incorrect value, and publicly
recoverable Ironwood reward actions. ZecWec's launch policy selects private
Ironwood, with no transparent fallback.

Wcash deliberately differs from Zcash by using ordinary private note
encryption for this output. An observer can audit the scheduled issuance and
see value entering the global Ironwood pool, but cannot recover the collector
receiver, note plaintext, or memo with Zcash's public all-zero outgoing viewing
key. Later Ironwood-to-Ironwood payouts redistribute private notes; they do not
leave the global Ironwood pool except for fees or an explicit transparent
output.

Wolf constructs and validates private Wcash coinbase transactions and the
private pool backend now requires an exact private-recipient attestation before
any job reaches a miner:

1. A protected verifier receives only the Wcash collector's read-only incoming
   viewing capability, never its spending key.
2. It trial-decrypts and authorizes every Ironwood action in the candidate
   coinbase; any undecryptable or unattributed action rejects the template.
3. It verifies that all positive value belongs to the configured collector and
   that the aggregate equals the exact advertised pool reward.
4. It emits an `ExactPrivateRecipient`-class attestation bound to the immutable
   job and payout commitment.
5. Wolf's pool backend releases work only when that attestation is present and
   consistent with its configured collector commitment.

The spending key remains in a separate payout signer. A template-node claim or
a signed assertion without independent trial decryption is not an equivalent
control. The source implementation and deterministic tests are present at Wolf
commit `e457b08d8db261b226cf7fb3278493d033f458f8`; public readiness still requires
the exact paired binaries to pass the private deployment, restart, reorg,
payout, and ASIC gates. Any missing or crossed attestation fails closed rather
than silently paying a transparent receiver.

The relevant Wcash construction and privacy checks at the reviewed Wolf commit
live in
[`transaction.rs`](https://github.com/w-cash/wolf/blob/e457b08d8db261b226cf7fb3278493d033f458f8/zebra-rpc/src/methods/types/transaction.rs)
and
[`zcash_note_encryption.rs`](https://github.com/w-cash/wolf/blob/e457b08d8db261b226cf7fb3278493d033f458f8/zebra-chain/src/primitives/zcash_note_encryption.rs).

### ZEC collector

After NU6.3, a supported Zcash Unified Address can route newly mined value into
Ironwood. ZecWec should use a separate pool-owned Zcash Ironwood collector and
keep its spending key isolated from every Wcash key.

This is shielded custody but not private receipt. Zcash
[`ZIP-213`](https://zips.z.cash/zip-0213) requires shielded coinbase outputs to
decrypt with an all-zero outgoing viewing key, which reveals their receiver,
value, and note plaintext to observers. Its advantage is that later spends can
use the shielded pool without exposing a transparent UTXO link. Documentation
and UI must never describe the ZEC coinbase recipient itself as hidden.

ZIP-213 applies the inherited 100-block coinbase-maturity rule only to
transparent coinbase outputs. ZecWec will nevertheless use a conservative,
chain-specific operational confirmation policy and Wolf's authoritative
maturity events before credit becomes payable. This protects miners from
ordinary and deep reorganizations rather than treating technical spendability
as economic finality. NU6.3 and Ironwood activation are specified by
[`ZIP-258`](https://zips.z.cash/zip-0258).

## Miner experience

The familiar large-pool model is the best fit for two rewards. F2Pool, ViaBTC,
AntPool, and Luxor use account/subaccount plus worker identities, while
address-as-login pools such as 2Miners optimize for a single payout asset. In
existing merged-mining products, secondary-coin destinations are configured in
the account rather than encoded into the ASIC connection. Relevant examples
include the
[`F2Pool Zcash guide`](https://f2pool.io/mining/guides/how-to-mine-zcash/),
[`F2Pool Litecoin merged-mining guide`](https://f2pool.io/mining/guides/how-to-mine-litecoin/),
[`ViaBTC Zcash guide`](https://support.viabtc.com/hc/en-us/articles/7207399677711-ZEC-Mining),
and
[`ViaBTC merged-mining guide`](https://support.viabtc.com/hc/en-us/articles/11477430615439-LTC-Merged-Mining-Coins-DOGE-BELLS-LKY-PEP-JKC-Mining-Tutorial).

| Reference product | Pattern worth keeping | ZecWec decision |
| --- | --- | --- |
| F2Pool | Account/subaccount workers, separate payout configuration, worker states, revenue and payout history, read-only watcher links, strong payout-change controls | Keep the account and security model; display both assets independently |
| ViaBTC | `account.worker`, internal account credit before withdrawal, separate merged-asset handling, workers and earnings views | Credit WEC before its destination is configured and hold it under a published unclaimed-balance policy |
| AntPool | Subaccount workers, separate merged-coin destination, hashrate alerts, payment history and API access | Put the second destination in the portal, never in the ASIC password |
| Luxor | Account workers, detailed reporting, approval controls, payout-address safety freeze | Use the reporting and change-hold pattern without launch-time payout splitting |
| 2Miners | Very simple `address.worker` onboarding and public address dashboard | Do not copy for launch: it couples identity to one asset and exposes more miner data |

See the public
[`AntPool merged-mining flow`](https://www.antpool.com/newsDetail/527-ANTPOOL%20Launches%20Merged%20Mining%20for%20Shibacoin%28SHIC%29),
[`Luxor onboarding`](https://docs.luxor.tech/platform/mining/getting-started),
[`Luxor payment controls`](https://docs.luxor.tech/platform/mining/revenue-payments),
and [`2Miners Zcash guide`](https://zec.2miners.com/help). Fees, thresholds,
and payment methods on third-party pools can change; ZecWec treats their stable
interaction patterns, not their current commercial numbers, as the reference.

ZecWec onboarding should take three steps:

1. Create an account with a strong password and optionally enable TOTP.
2. Add one valid Wcash payout destination and one valid Zcash payout
   destination, or explicitly defer either destination and accept a payout hold.
3. Create a worker, copy its three ASIC fields, and start mining.

Planned Testnet example:

```text
Preferred URL:     stratum+ssl://testnet-mine.zecwec.com:3443
Compatibility URL: stratum+tcp://testnet-mine.zecwec.com:3333
Worker:             <account>.z15-01
Password:           <generated mining-only token>
```

The production portal must copy all three fields together and show the last
successful connection and accepted share. The password is never the portal
password. It is shown once, stored as a verifier rather than plaintext, and can
be revoked without changing the account or payout destinations.

ASIC Pool 2 and Pool 3 entries are independent regional failover endpoints.
They are not separate WEC and ZEC connections, and the UI must not advertise
duplicate names until genuinely independent edges exist.

A miner may begin accruing ledger credit before both payout destinations are
configured. A missing or invalid destination blocks payout while the balance
remains a recorded liability subject to a published dormant-account,
unclaimed-property, minimum, and dust policy. It cannot be silently forfeited
or redirected to the operator. Each destination is validated by the
authoritative chain/address library for the selected chain, network, and
receiver type. String-prefix or regular-expression checks are insufficient.

TLS is preferred wherever ASIC firmware supports it. The compatibility port is
plaintext: a LAN or ISP observer can read jobs and replay its worker token.
That token therefore has mining-only authority, is rate-limited and revocable,
and is never reused as a portal credential. The portal must state this warning
beside the plaintext copy button.

## Reward method and payouts

ZecWec will launch with PPLNS because a new pool should not promise PPS income
before it has the reserves and risk controls to absorb block variance, parent
chain reorganizations, and orphaned blocks.

- Every accepted proof contributes its assigned difficulty, not one raw share,
  so variable difficulty cannot change a miner's economic weight.
- WEC and ZEC use independent published PPLNS windows ending at their
  respective block winners.
- A proof can contribute normalized work to both windows, but a reward is
  allocated only when that chain has an accepted block.
- Exact retries and duplicates are idempotent and can be credited only once.
- The fee, window definition, minimum payout, payout-transaction fee policy,
  and change-effective height are published per chain.
- Payout batches run on a regular schedule only for mature balances above the
  configured threshold. “Daily payout processing” must never be presented as
  a promise of daily ZEC income.
- Version 1 uses automatic payouts only. Manual instant withdrawals add an
  unnecessary hot-wallet and account-takeover surface.
- Wcash miner payouts require an Ironwood-capable destination. Zcash miners
  choose a transparent P2PKH/P2SH destination or an Ironwood-capable Unified
  Address. The signer verifies the exact requested receiver and amount;
  a shielded request is never changed to a transparent output. Collector
  coinbase policy remains separate from the miner's payout address choice.

Changing a Mainnet payout destination requires strong reauthentication, sends
an immediate security notification, and places that asset's payouts on a
48-hour safety hold. Mining and accounting continue during the hold. The old
and new destinations, authorization event, and activation time remain in an
append-only audit trail. A change on one chain does not alter the other chain.

## Portal information architecture

### Public pages

Public pages show only aggregate pool information:

- current network and service status;
- one connected Equihash hashrate plus the two chain difficulties;
- estimated time to block, pool effort/luck, active workers, and recent blocks;
- WEC-only, ZEC-only, and dual block counts;
- current PPLNS, fee, confirmation, threshold, and payout policies;
- regional endpoints and a concise ASIC setup guide;
- release revision and data-freshness timestamp.

There is no public lookup by account, worker, payout address, or IP. Read-only
watcher links are revocable, scoped to one account, and opt-in.

### Private dashboard

The overview uses one hashrate chart and two clearly separated asset cards.
Each WEC and ZEC card shows:

- estimated PPLNS position, explicitly labelled as an estimate rather than a
  balance;
- immature, payable, scheduled, and lifetime-paid amounts;
- masked destination, receiver type, network, threshold, and next eligible
  batch;
- the last payout state and transaction identifier when one is public.

The complete product worker page will show live, 5-minute, 1-hour, and 24-hour
hashrate; accepted, stale, invalid, and duplicate work; assigned difficulty;
last share; firmware label; and online, offline, or dead state. The initial
Testnet portal intentionally exposes only online connections, last-share time,
and process-lifetime outcome counters until a calibrated, durable hashrate
projector is implemented. It must never relabel share counts as solutions per
second. Alerts remain a later milestone and must not expose full worker labels
in notifications.

The block page labels every result `WEC`, `ZEC`, or `DUAL` and shows observed,
immature, mature, payable, paid, orphaned, quarantined, or requeued state as
applicable. A Wcash row links its AuxPoW parent header/block identifier and the
Zcash block only when that parent proof also became a canonical Zcash block.
Using a Zcash-valid header as AuxPoW does not imply that Zcash accepted a block.

The Testnet version-1 security/settings page manages TOTP, revocable worker
tokens, two payout destinations, and the payout-change hold. Passkeys, recovery
codes, an active-session management UI, and watcher links are later milestones
and must not be advertised as available. The portal never asks for a seed
phrase, spending key, incoming viewing key, or full viewing key.

## Services and data authority

The service is split so that Internet-facing code cannot invent consensus facts
or spend collector funds:

1. **Stratum edge:** bounded ZIP-301 parsing, TLS, authentication, vardiff,
   rate limits, job delivery, and miner responses.
2. **Wolf backend:** authoritative templates, proposal validation, Equihash and
   target classification, AuxPoW, durable share receipts, winner lifecycle, and
   block submission.
3. **Journal projector:** consumes Wolf's contiguous event stream exactly once
   into PostgreSQL and stops on gaps, identity changes, or contradictions.
4. **Accounting service:** chain-specific PPLNS, conserved append-only ledgers,
   maturity, reorganization reversal, thresholds, and payout batches.
5. **Wallet observer and isolated signer:** recognize collector notes, reconcile
   funds, construct bounded payouts, and sign without exposing spending keys to
   the edge, portal, or database.
6. **Portal API and UI:** account settings and read models only; no consensus
   validation and no direct signing capability.

The concrete Testnet deployment gives the journal projector its own Unix user,
PostgreSQL role, protected database URL, and persistent Wolf connection. It
opens no TCP listener and is the only runtime allowed to insert backend events,
shares, winners, allocations, or ledger entries. The Internet-facing service
retains portal and nonce operations but has no monetary-table DML: before it
acknowledges journal progress, it waits a fixed bound for the projector and
verifies the exact backend authority, event sequence, and canonical payload
digest already stored. Lag or contradiction therefore fails closed. Payout
destination changes use a migrator-owned database routine that always imposes
an audited 48-hour database-clock hold, including the first destination; the
public role has no direct destination-table mutation grant.
Schema migration likewise runs under a dedicated no-listener Unix identity;
the Internet-facing UID never receives the migrator credential. Upgrade
reconciliation clears legacy migrator table/sequence default ACLs and default
public function execution before explicit grants are reapplied, so a later
schema object fails closed until its role matrix is reviewed.

PostgreSQL is the monetary source of truth. Redis may cache rate-limited
sessions, live hashrate, and disposable UI projections, but losing Redis must
not lose or change a share, block, balance, address change, or payout.

Only miner traffic and the web/API surface are public. Wolf, nodes, proposal
validator, PostgreSQL, Redis, metrics, administration, wallet observer, and
signer stay on private authenticated networks. The signer uses bounded batch
policies and supports an immediate payout freeze independent of mining.

## Network and deployment layout

One codebase supplies two strictly separated products:

| Purpose | Mainnet | Testnet |
| --- | --- | --- |
| Portal | `pool.zecwec.com` | `testnet.zecwec.com` |
| Preferred Stratum TLS | `mine.zecwec.com:3443` | `testnet-mine.zecwec.com:3443` |
| Legacy plaintext Stratum | `mine.zecwec.com:3333` | `testnet-mine.zecwec.com:3333` |
| Currency labels | WEC / ZEC | TWC / test ZEC |

The two deployments have independent genesis/network identities, nodes,
databases, journal streams, nonce leases, collectors, viewing capabilities,
signing keys, worker tokens, TLS identities, secrets, queues, backups, and
metrics. Startup checks the exact network tuple and refuses automatic fallback
or cross-network configuration. Testnet balances and accounts never become
Mainnet balances.

Cloudflare may proxy the HTTP dashboard and API. Normal Cloudflare proxying
does not carry an arbitrary Stratum TCP port; custom TCP/UDP Spectrum support
requires an Enterprise arrangement according to Cloudflare's
[`Spectrum plan documentation`](https://developers.cloudflare.com/spectrum/protocols-per-plan/).
Until an appropriate Layer-4 service exists, Stratum hostnames remain DNS-only
and terminate TCP/TLS on a separately hardened mining edge with an ordinary
origin certificate. The web origin and Stratum edge should not share a public
failure domain at Mainnet launch.

## Privacy and security promises

The product can promise:

- separate Wcash/Zcash address and key domains;
- private WEC collector receipt only after exact encrypted-recipient
  verification is complete;
- shielded later-spend linkage for a ZEC Ironwood collector, while disclosing
  ZIP-213's public coinbase recovery;
- encrypted storage and masked display of the miner's paired destinations;
- no public miner, address-pair, worker, IP, share, or balance index;
- no spending or viewing keys in the public edge, UI, logs, metrics, source
  repository, or container image;
- independent ledgers and continuously checked conservation for both assets.

It cannot promise anonymity from the pool operator. The service sees account
identity, connection metadata, share timing, worker names, balances, and payout
instructions. Retention limits, operator access, exports, and deletion behavior
must be published before public Testnet. Shielded rewards do not make these
off-chain records private.

## Release gates

The following evidence is required before the endpoint can be called public
Testnet. Source implementation or CI success alone does not satisfy it:

1. Produce reproducible, digest-pinned Linux release artifacts and pass the
   complete workspace, real-PostgreSQL, deployment-package, Zallet patch, and
   Wolf/AuxPoW integration suites.
2. Complete fresh zero-balance WEC and ZEC collector ceremonies, independent
   off-host restores, root-sealed recovery/initial-zero attestations, and prove
   the public UID cannot read any custody material.
3. Deploy the distinct migrator, public, projector, and payout PostgreSQL roles; prove
   denied-table mutations fail with PostgreSQL `42501`, and restore the database
   plus both signer journals on an isolated host.
4. Prove ordinary shares, WEC-only, ZEC-only, and dual winners; maturity,
   orphan/reorg reversal; successful WEC and ZEC payouts; ambiguous retry;
   restart; stale work; dependency loss; and private-recipient rejection in the
   isolated Testnet topology.
5. Complete the canonical HTTPS registration/login/TOTP/worker/token/address
   flows and one real accepted ASIC share through the source-restricted edge.
   Token/worker revocation must terminate an already-authenticated connection.
6. Complete a private Testnet soak and independent security/accounting review,
   then explicitly approve public DNS/portal publication.

Public Testnet is a further evidence gate, not permission to launch Mainnet.
Mainnet needs its own threat review, release revision, infrastructure, keys,
collector funding policy, fees, thresholds, incident runbooks, reproducible
artifacts, and explicit launch decision. The detailed engineering sequence is
maintained in the [Testnet roadmap](testnet-roadmap.md).

## Version 1 non-goals

- PPS or PPS+ financing before audited reserves and risk limits exist.
- Proxying unmodified work from another Zcash pool; it cannot safely commit the
  exact Wcash candidate or preserve authoritative share ownership.
- Two ASIC connections or two ASIC payout addresses for the two chains.
- Direct per-miner outputs in either chain's coinbase.
- A shared seed, private key, address, ledger, maturity state, or payout batch
  across Wcash and Zcash.
- Public miner/address dashboards by default.
- Manual instant withdrawals.
- Silent transparent fallback when an Ironwood collector cannot be proven.

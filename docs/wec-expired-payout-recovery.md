# Expired WEC payout recovery

An accepted transaction can leave the WEC mempool during a reorganization,
remain absent from the canonical chain, and expire while the pool retains its
signed bytes. Repeatedly submitting those bytes cannot repair an expired
transaction. Replacing it immediately could pay the same liability twice if
the original later appears on a replacement chain.

## Held reservation

The isolated automatic WEC worker inspects each active artifact through the
existing seedless native-wallet recovery and inspection boundary. The signer
journal, wallet consensus parser, exact SQL bytes, transaction ID, unsigned
digest, fee, accounting request, ordered outputs and expiry must agree.
Inspection cannot create an intent, sign, broadcast, or rewrite its journal.
No transaction-header-only fallback is used.

After a stable authenticated full-node snapshot reports absence and a tip
strictly above expiry, the batch enters `expiry_pending`. Its entire gross
liability stays in `payout_pending`; no fee or collector asset is charged and
nothing from that reservation becomes payable. All original records survive.
Normal automatic batches can use only separately payable rewards and must
still pass the unchanged exact wallet/ledger reconciliation and destination
validation. They use the account's versioned active destination.

Held artifacts have a separate observation path, so they cannot crowd active
broadcasts out of the normal bounded confirmation page. A held original that
appears canonical consumes its original reservation through normal confirmation;
insufficient confirmations defer fresh settlement. A rollback to or below its
expiry also defers settlement. Two held batches block new signing, and candidate
overflow fails closed. The worker never resubmits a held or retired artifact.

## Finalized non-inclusion

The recovery policy is pinned to Wolf's WEC state rollback window of 1,000
blocks, as implemented by WEC node revision `3e708002`. Release requires a
stable tip at least `expiry + 1001`, authoritative whole-chain indexed absence,
an agreeing explicit mempool check, and an unchanged canonical expiry checkpoint.
Wolf's lookup searches the mempool, all retained nonfinalized branches and the
finalized database; RPC failures and orphan/mempool responses cannot authorize
release. The extra block accounts for publication before the writer completes
its finalization iteration. This is the configured node's local finalization
policy, not a universal guarantee against arbitrary network history rewrites.
Reassess the recovery constant before changing that node policy or replacing
the authority with an implementation that lacks its full transaction index.

One row-locked SQL transaction appends immutable finalized evidence, seals one
balanced `payout_released` entry for every original gross liability, and marks
the batch `expired`. A unique evidence-to-release binding prevents duplicate
refunds. A conflicting replay, premature evidence, changed signed facts or an
incorrect release amount is rejected. The normal automatic batch selection can
then pay the restored balance; there is no manual replacement transaction.

## Deployment and load

Migration 0022 extends only payout state and adds an append-only evidence table
and small partial indexes. No backend capability, mining wire format, job,
share, consensus, ZEC submission or payout destination format changes. The
automatic recovery is WEC-only; it does not enable automatic ZEC payouts.

Recovery visits at most two artifacts. Wallet inspection is cached against the
immutable request and signed facts, and occupies its own worker pass. State
transitions also defer the remaining settlement pass. Ordinary held polling
uses bounded read-only RPCs, with no historical scan or repeated ledger rehash.
The service's existing shutdown/lease bound includes the extra gate. Logs are
emitted only after a durable hold, release or held confirmation, outside every
mining and ZEC submission path.

Build and test away from the mining VPS. Deploy only the payout executable and
reviewed migration/grants; retain all configurations, credentials, journals,
wallets and ledger history. Do not use the full deployment preflight or grant
reset scripts on a running pool. Only the isolated payout worker needs a restart.
Once new states exist, an old payout binary is not a safe rollback. Stop only
the payout worker if recovery fails, retain evidence, and keep mining running.

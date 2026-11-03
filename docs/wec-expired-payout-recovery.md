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
strictly above expiry, the batch enters `expiry_pending`. The same hold is
permitted when the node returns the exact inspected transaction bytes in an
orphaned block, the tip is strictly above its inspected expiry, and a separate
validated mempool query confirms the transaction is absent. A known orphan is
not evidence of whole-chain non-inclusion and can never authorize release by
itself, even after the finality depth.

The batch's entire gross liability stays in `payout_pending`; no fee or collector
asset is charged and nothing from that reservation becomes payable. All original
records survive. The first durable hold defers settlement until another poll.
Normal automatic batches can use only separately payable rewards and must
still pass the unchanged exact wallet/ledger reconciliation and destination
validation. They use the account's versioned active destination.

Held artifacts have a separate observation path, so they cannot crowd active
broadcasts out of the normal bounded confirmation page. A held original that
appears canonical consumes its original reservation through normal confirmation;
insufficient confirmations defer fresh settlement. A rollback to or below its
expiry also defers settlement. A held exact expired orphan continues to permit
only separately payable rewards while its full original reserve remains held.
Mempool presence or uncertain observations on the selected page defer fresh
settlement for that pass. Held count alone does not block new signing. Every
fresh wallet reconciliation and batch still checks all held records for complete
immutable expiry evidence and requires every held expiry below its fresh wallet
tip. Full pending reserves remain excluded from payable rewards. More than one
active artifact fails closed. The worker never resubmits a held or retired
artifact.

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

Existing migration 0022 extends only payout state and adds an append-only
evidence table and small partial indexes. Holding an expired known orphan uses
that existing state and requires no additional migration. No backend capability,
mining wire format, job, share, consensus, ZEC submission or payout destination
format changes. The automatic recovery is WEC-only; it does not enable automatic
ZEC payouts.

Recovery visits at most two artifacts per pass. At most one active artifact is
always selected first; remaining slots visit held artifacts by UUID cursor with
wraparound. Only a completed authority pass advances the cursor, so an
inspection-only pass retries its same page. Wallet inspection is cached against
the selected immutable request and signed facts, and occupies its own worker
pass. State transitions also defer the remaining settlement pass. A larger held
backlog changes the number of pages, not the per-pass artifact or shutdown
budget. Ordinary held polling uses bounded read-only RPCs, with no historical
scan or repeated ledger rehash.
The service's existing shutdown/lease bound includes the extra gate. Logs are
emitted only after a durable hold, release or held confirmation, outside every
mining and ZEC submission path.

Build and test away from the mining VPS. The held-backlog correction requires only
the payout executable where migration 0022 and its reviewed grants are already
present; retain those grants, all configurations, credentials, journals, wallets
and ledger history. Do not use the full deployment preflight or grant reset
scripts on a running pool. Only the isolated payout worker needs a restart.
The previous expiry-aware worker understands the held state, but can block
payouts again when the node retains an orphan or fail closed when more than two
recovery candidates have accumulated. Rolling back to it is a funds-safety
fallback, not a recovery of payout availability. A binary predating migration 0022 cannot safely
interpret these states. Stop only the payout worker if recovery is uncertain,
retain evidence, and keep mining running.

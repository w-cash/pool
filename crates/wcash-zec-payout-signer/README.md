# Zcash Testnet payout signer

This crate is the non-custodial-process boundary between ZecWec accounting and
an isolated Zallet `v0.1.0-beta.3` wallet. It carries no spending keys. The
wallet remains the only process that can sign.

The pipeline is deliberately narrow:

1. accept a bounded, reconciled ZEC/Testnet batch;
2. require the configured Zallet account and the isolating `orchard` fund
   source;
3. create and inspect the PCZT, matching every ordered recipient and amount;
4. prove, inspect again, sign with `strict=true`, and inspect again;
5. extract only when Zallet reports `stored=true`;
6. atomically persist the raw transaction and transaction ID before asking the
   parent Zebra node to broadcast it.

The signer verifies that the local Zallet configuration says
`consensus.network = "test"` and `external.broadcast = false`. Its journal must
be on durable local storage and is written with owner-only permissions. A retry
with the exact batch resumes from the last durable stage. Reusing a batch ID
with different facts is rejected. A timeout at broadcast is unresolved, never
reported as paid; an explicit retry can only rebroadcast the already-persisted
identical bytes.

`LoopbackHttpTransport` is the concrete node boundary. It accepts only a
nonzero loopback TCP address, reloads Basic-auth credentials from an
owner-only cookie file for every request, applies the signer's per-call I/O
deadline, requires an explicit HTTP content length, bounds both the envelope
and JSON-RPC result, and rejects crossed response IDs. Cookie material and
request bytes are cleared after transmission and are never formatted for logs.

This crate implements the ZEC half of payout execution only. It does not
authorize ledger entries, calculate rewards, operate the WEC signer, or expose
an Internet-facing RPC endpoint.

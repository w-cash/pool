# Zcash Testnet payout signer

This crate is the non-custodial-process boundary between ZecWec accounting and
an isolated Zallet `v0.1.0-beta.3` wallet. It carries no spending keys. The
wallet remains the only process that can sign.

The pipeline is deliberately narrow:

1. accept a bounded, reconciled ZEC/Testnet batch;
2. require the configured Zallet account and the isolating `orchard` fund
   source;
3. create the PCZT, parse it independently, and match every recipient, amount,
   source effect, and fee before consulting Zallet's inspection report;
4. prove, inspect again, sign with `strict=true`, and inspect again;
5. extract only when Zallet reports `stored=true`;
6. atomically persist the raw transaction and transaction ID before asking the
   parent Zebra node to broadcast it.

Zallet's `pczt_inspect` fields are creator-supplied annotations, so they are not
the authorization boundary. The signer parses the Created PCZT with `pczt`
0.9.3 itself. It requires V6/NU6.3, a bounded future expiry, finalized
nonmodifiable effects, the configured account's canonical ZIP 32 identity, no
transparent inputs, no Sapling data, and no legacy Orchard actions. Every
positive Ironwood spend must verify under the account UFVK exported by the
isolated wallet and carry the standard account derivation. Every positive
external output must contain the exact requested Testnet receiver bytes and
amount plus the canonical empty memo; at most one unlabeled positive output
may be account-owned change.
ZEC miner destinations support Testnet transparent P2PKH/P2SH addresses and
Unified Addresses containing a supported shielded receiver. The collector
remains shielded. PCZT creation requests `FullPrivacy` for shielded-only batches
or `AllowRevealedRecipients` when a batch includes transparent recipients;
transparent destinations and amounts are public on-chain. Existing mixed
batches retain independent exact-output verification for both receiver types.

Transparent outputs, when requested, must contain the exact independently
decoded P2PKH or P2SH script and amount. The fee is derived from these parsed
effects and bounded independently.

The PCZT must carry Testnet's SLIP-44 coin-type marker `1`; mainnet's marker
`133` is rejected. Pinned `pczt` 0.9.3 parses this field but does not expose a
logical getter, so the signer decodes the leading global record of the exact
PCZT v2 wire schema and fails closed on any other marker or encoding. This
separate check is necessary because coin type is wallet metadata, not a
consensus transaction effect.

Only after those checks does the signer derive the Zcash consensus
shielded-signature hash. This is the transaction-effects digest authorized by
shielded spends, not the portal's accounting-request commitment and not a hash
of mutable PCZT metadata. It is persisted with the independently derived fee
and re-derived from every proved and signed PCZT before continuing. Proof and
signature bytes may change; consensus transaction effects may not. Version 1
journals did not contain this binding and are rejected rather than upgraded by
guessing.

Before trusting `pczt_extract`, the signer also runs the pinned PCZT transaction
extractor locally. That requires and verifies the Ironwood proof and spend
authorization and derives the ZIP-244 transaction ID of the approved signed
PCZT. Zallet's returned bytes are decoded as one canonical V6/NU6.3 transaction;
its locally computed transaction ID must match both the PCZT and Zallet's
claimed display ID. Only those exact raw bytes are journaled and broadcast.

The signer verifies that the local Zallet configuration says
`consensus.network = "test"` and `external.broadcast = false`. Readiness also
requires beta.3's sync engine to report unlocked, identical nonzero node and
wallet tips, a fully-scanned height at that tip, and no remaining sync work.
Here, `getwalletstatus.locked` is specifically a chain-synchronization lock, not
the key-store lock; the subsequent viewing-key export independently fails if
the key store is locked. The configured signing account UUID, canonical seed
fingerprint, account index, owned Unified Address, and exported Testnet UFVK
must match exactly. Its journal must be on durable local storage and is written
with owner-only permissions. Because beta.3's
`orchard` fund-source selector includes both Orchard-family pools, readiness
also requires the configured account's comprehensive `z_getbalances` report to
omit the legacy Orchard pool; the parsed PCZT independently enforces Ironwood
effects only. A retry with the exact batch resumes from the last durable stage.
Reusing a batch ID with different facts is rejected. A timeout at broadcast is
unresolved, never reported as paid; an explicit retry can only rebroadcast the
already-persisted identical bytes.

`LoopbackHttpTransport` is the concrete node boundary. It accepts only a
nonzero loopback TCP address, reloads Basic-auth credentials from an
owner-only cookie file for every request, applies the signer's per-call I/O
deadline, requires an explicit HTTP content length, bounds both the envelope
and JSON-RPC result, and rejects crossed response IDs. Cookie material and
request bytes are cleared after transmission and are never formatted for logs.

This crate implements the ZEC half of payout execution only. It does not
authorize ledger entries, calculate rewards, operate the WEC signer, or expose
an Internet-facing RPC endpoint.

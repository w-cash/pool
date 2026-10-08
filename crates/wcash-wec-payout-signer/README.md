# Wcash payout signer

This crate is the crash-safe pool coordinator for the WEC half of a payout
batch. It accepts only `Asset::Wec` on the configured Wcash network, one configured
wallet account, mature Ironwood funds, and Ironwood destinations or explicitly
enabled transparent P2PKH destinations. Testnet is the default; Mainnet requires
its frozen network identity, and isolated Regtest support is compile-time opt-in.

The coordinator:

- binds every accounting field, source policy, fee cap, and Wcash chain
  identity to a stable request commitment;
- asks the native wallet to recover that commitment before it reads spending
  authority;
- reads the seed only from a canonical single-link `0600` file owned by the
  configured UID, or from non-terminal standard input;
- verifies the native wallet's independently persisted ordered intent, exact
  amounts, transaction bytes, identifier, fee, branch, genesis, account, and
  change authority;
- atomically journals the exact raw transaction and transaction identifier in
  a `0700` directory with `0600` files and file/directory `fsync` before any
  broadcast; and
- replays only those bytes after an ambiguous node result.

`wcash-wallet transfer` is not a valid transport implementation. That command
is intentionally a one-recipient, non-idempotent operation. Deployment requires
the Wolf payout commands implementing `NativeWalletTransport` semantics: an
atomic `(batch_id, request_commitment)` binding, seedless exact recovery,
independent persisted-intent inspection, and exact-byte broadcast/status
reconciliation. This crate makes no claim about the separate ZEC payout half.

## Optional Wcash P2PKH payouts

The reviewed wallet implementation for this change is Wolf commit
[`b8fc95d7a347ac1123fa3d9e1e7ebb9856a6d5f2`](https://github.com/w-cash/wolf/commit/b8fc95d7a347ac1123fa3d9e1e7ebb9856a6d5f2).
Build and integrity-pin that compatible wallet before enabling W1 payouts.

`wcash_transparent_payouts_enabled = false` is the default in pool configuration.
The policy gates three separate operations: accepting new destinations in the
portal, selecting new W1 batches in the store, and authorizing a new batch in the
signer. It does not gate recovery. Enable it only after pinning a compatible Wolf
wallet and passing preflight;
preflight requires `payout-capabilities` to advertise protocol 2 and both
`ironwood` and `transparent_p2pkh`.

Shielded Ironwood (`wu1…` on Mainnet) is recommended. Transparent W1 payments make
the destination and transferred amount public. The wallet's `validate-address`
command remains the authority: its canonical response must identify
`transparent_p2pkh` for the exact configured network. W3/P2SH, TEX, Zcash addresses
and noncanonical encodings are rejected. The server validates the submitted
address independently of the browser selector.

Example output shapes (addresses abbreviated, not executable requests):

```json
{"canonical_address":"wu1…","receiver_kind":"ironwood","amount_zat":1000000,"memo_hex":""}
{"canonical_address":"W1…","receiver_kind":"transparent_p2pkh","amount_zat":1000000,"memo_hex":""}
```

A W1 `validate-address` result has this shape:

```json
{"network":"mainnet","receiver_kind":"transparent_p2pkh","canonical":"W1…"}
```

W1 always uses an empty memo. Funding and internal change remain Ironwood. Batches
are homogeneous by receiver kind, chosen by the existing oldest-unpaid ordering.
Accounts of the other kind remain payable for a later cycle. Existing limits,
random amount/skip policy, holds, maturity and one-transaction-per-cycle behavior
remain in effect. The transport binds every returned output to its frozen request.

No database migration is required. The stored `transparent` kind denotes only
P2PKH for WEC because the authoritative validator excludes P2SH. Ledger entries
and destination history are retained. No payout/journal protocol version changes.
Never log full addresses, request bodies or seed material. Store addresses in the
pool account, not ASIC password fields.

### Later rollout and rollback

1. Stop only the WEC payout worker; keep mining and accounting running.
2. Install and pin the compatible Wolf wallet, then run wallet/payout preflight.
3. Install the pool update with public payouts disabled.
4. Restart the worker and verify existing Ironwood payouts.
5. Enable public payouts, pass capability preflight, and make one small W1 canary.
6. Verify its exact transaction, inclusion and ledger settlement before ordinary batches.

Rollback disables public payouts. Preserve the compatible wallet, signer journal
and frozen SQL allocations; the worker can recover existing batches with the flag
disabled. The signer's durable `reserved` record authorizes its exact request
commitment before signing begins, so a restart may complete that already
authorized operation. A wallet commit recovered after a crash returns its stored
bytes without signing again. Prepared, legacy signed, ambiguous and completed
stages retain their exact transaction. A rejected transaction stays rejected.

A W1 request with no signer reservation cannot gain new authorization while the
flag is disabled, even if a SQL batch was frozen earlier. Leave that unpaid batch
reserved for an explicit later re-enable; never replace it or release its funds
as though a transaction had been ruled out. `recover_prepared` remains seedless
and never signs or broadcasts. Do not roll back confirmed ledger history or
interrupt mining.

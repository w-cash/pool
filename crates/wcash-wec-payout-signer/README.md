# Wcash Testnet payout signer

This crate is the crash-safe pool coordinator for the WEC half of a payout
batch. It accepts only `Asset::Wec` on public Wcash Testnet, one configured
wallet account, mature Ironwood funds, and Ironwood destinations supported by
the current Wolf transfer builder.

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
is intentionally a one-recipient, non-idempotent operation. Deployment remains
fail-closed until Wolf provides the `NativeWalletTransport` semantics: an
atomic `(batch_id, request_commitment)` binding, seedless exact recovery,
independent persisted-intent inspection, and exact-byte broadcast/status
reconciliation. This crate contains no Mainnet mode and makes no claim about
the separate ZEC payout half.

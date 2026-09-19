# Mainnet parallel Pool staging

The live `mainnet.zecwec.com:3333` path is Wolf's direct Stratum service. It
has no per-account Pool share ledger. Never infer historical user balances from
its accepted shares or import its existing collector balance as Pool funds.

Stage the new Pool under its own database, deployment ID, Wolf backend identity,
journal stream, nonce namespace, Unix socket, service users, and TCP port 3334.
Keep the current Wolf unit, port 3333, nginx stream block, nodes, and collector
unchanged. The staging port stays firewalled and registration stays closed.
The portal belongs on a separate hostname, such as `pool.zecwec.com`, leaving
the apex website and existing mining hostname alone.

The Mainnet config pins Wcash genesis
`5bae12c8662a577b04ce1591af1a137c128f0cb51018a5f1622d861d1bb6fc48`,
Zcash genesis
`00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08`,
AuxPoW chain ID `0x57434153`, Wcash branch `d9c6a7ee`, and Zcash branch
`37a5165b`. Mainnet config accepts only `payout_mode = "deferred"`; no spending
keys enter the mining or portal process.

Before opening 3334, prove these gates in order:

1. Bind an exact Wolf backend release and initialize its new identity/journal
   without modifying the live backend. Verify both node tips and genesis hashes.
2. Use a new, empty WEC and ZEC collector or complete a reviewed opening-balance
   migration. The currently funded Wolf collector cannot silently become the
   Pool's zero-balance source. Preserve recovery material and prove that the
   configured coinbase outputs belong to the collectors.
3. Run the Pool schema and grants in a separate PostgreSQL database. Confirm
   the backend's event cursor, share accounting, winner proofs, and per-account
   balances from a private ASIC on 3334. The starting accounting height is
   recorded explicitly; old Wolf shares have no Pool payout claim.
4. Exercise actual WEC and ZEC recipient transactions with the production
   signer and wallet adapters in Regtest, including maturity, restart, exact
   transaction retry, fee accounting, and a reorg. Mocked wallet responses do
   not satisfy this gate.
5. Publish the account portal over HTTPS only after address validation,
   authentication, CSRF, rate limits, worker revocation, and payout holds pass
   against the live staging database. Enable public registration and automatic
   payouts in separate reviewed changes. Retain a rollback to 3333 throughout.

No new service may claim public payout readiness until recipient receipt and
ledger reconciliation are independently observed on both chains.

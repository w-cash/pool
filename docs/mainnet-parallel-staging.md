# Mainnet Pool listeners

The legacy `mainnet.zecwec.com:3333` path is Wolf direct Stratum. It has no
per-account Pool share ledger. Never infer Pool balances from that path or
import its collector balance as Pool funds.

The account Pool advertises one endpoint to miners:

```text
stratum+tcp://mainnet.zecwec.com:3336
```

Port 3336 accepts standard ZIP-301 clients and firmware such as GodMiner that
stores shorter job identifiers. The bounded adapter assigns an eight-character
alias to each upstream job and restores the immutable full job ID before
forwarding a share to `wcash-poold` on firewall-restricted port 3337.

Port 3334 runs the original standard listener as an unadvertised operational
fallback. It must not be presented as a second pool. Both listeners have the
same deployment ID and use the same Wolf backend, PostgreSQL share ledger,
account and worker records, winners, PPLNS history, and payout ledger. Moving a
worker between 3334 and 3336 does not reset or discard accepted work.

The Mainnet configuration pins Wcash genesis
`5bae12c8662a577b04ce1591af1a137c128f0cb51018a5f1622d861d1bb6fc48`,
Zcash genesis
`00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08`,
AuxPoW chain ID `0x57434153`, Wcash branch `d9c6a7ee`, and Zcash branch
`37a5165b`.

Operational checks must prove that 3336 returns a short job alias, submitted
shares appear under the existing canonical worker in the shared deployment,
and ports 3334 and 3336 never allocate the same nonce namespace. Port 3337 must
remain unavailable from the public Internet.

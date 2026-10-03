# Public pool API

The public API exposes aggregate Wcash mining rates without accounts, workers,
addresses, or credentials.

## Pool hashrate

`GET /api/v1/hashrate/pool`

`hashrate_sol_s` is the accepted target-derived work recorded during the
trailing `window_seconds`, divided by that window. The production window is
1,200 seconds. A quiet pool returns zero; `available: false` means the durable
projection is unavailable.

## Network hashrate

`GET /api/v1/hashrate/network`

`hashrate_sol_s` is returned by the local Wcash node's `getnetworksolps` RPC
for the reported `height` and `sample_blocks`. The production sample is 120
blocks. `available: false` means a fresh node estimate could not be obtained.

Both responses use integer solutions per second and Unix timestamps in
seconds. Clients should use the `available` field rather than interpreting a
missing value as zero.

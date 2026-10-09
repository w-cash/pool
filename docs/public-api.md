# Public pool API

The public API exposes production identity, service readiness, aggregate Wcash
mining rates, and bounded public activity without accounts, workers, addresses,
or credentials.

## Production manifest

`GET /api/v1/production-manifest`

This endpoint combines the repository-tracked production evidence in
[`production-manifest.json`](../production-manifest.json) with a `runtime`
object sampled for the request. The static evidence identifies the observed
Pool and Wolf artifacts, deployment/configuration revision, chain genesis
values, public routes, payout policy, and known limitations. `recorded_at` is
the evidence timestamp; clients must not treat `observed_deployment` or
`observed_runtime` as a live heartbeat.

`runtime.registration_open` comes from portal configuration,
`runtime.mining_ready` comes from the current pool-data authority, and
`runtime.wec.worker_live` comes from the database-clock payout-worker lease.
An unavailable worker query is returned as `null`, not as a successful
heartbeat. ZEC has a manual settlement policy and therefore has no automatic
worker state.

`manifest_server` is separate from `observed_deployment`. It remains
`not_deployed` with null build fields until release packaging and
post-deployment attestation record the exact source, build, and binary serving
the endpoint.

## Readiness

`GET /readyz`

Readiness covers the public portal's database, mining view, address validators,
and configured payout boundary. `payout_execution` is scoped to the portal
process. Mainnet returns `deferred` because that process has no spending
authority. The production manifest separates the automatic WEC policy from the
isolated worker's live lease and reports manual ZEC settlement independently.

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

## Public activity

`GET /api/v1/public/activity`

This endpoint supplies the dashboard with three bounded lists:

- `hashrate`: ten-minute samples of the accepted-work 20-minute pool estimate,
  retained for up to 24 hours by the running portal process.
- `blocks`: the latest WEC and ZEC blocks found by the pool, including chain,
  height, block hash, lifecycle state, and discovery time.
- `payouts`: the latest broadcast payout transaction IDs and lifecycle state.

The response deliberately excludes account IDs, worker names, payout
destinations, balances, and transaction amounts. Consumers must treat
`available: false` as unavailable history rather than an empty pool.

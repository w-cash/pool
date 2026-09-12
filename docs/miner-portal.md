# Miner portal and payout boundary

> **Milestone status:** the portal, shared PostgreSQL adapter, authoritative
> address adapters, account read models, and isolated Testnet payout services
> are composed in `wcash-poold`. It is not a public service until the private
> end-to-end launch and soak gates pass. Mainnet is deliberately rejected by
> this release.

## Miner experience

One private account owns any number of revocable ASIC workers and two
independent payout preferences. The responsive portal has Overview, Workers,
Rewards, Blocks, Payouts, and Settings pages. Aggregate service information is
public; account names, worker names, shares, balances, destinations, and
payouts require authentication.

The authenticated overview shows independently conserved WEC and ZEC
immature, payable, pending-payout, and total balances. Reward allocations,
found blocks, and payout batches use bounded keyset pagination. Transaction
identifiers appear only after a reconciled signer result. Live worker status
and accepted, stale, invalid, and duplicate counters are scoped to one account
and explicitly labelled as process-lifetime operational telemetry; they are
not the durable monetary accounting record.

The Workers page creates one canonical `account.worker` login and one
`zw1.<selector>.<secret>` mining token. The token is displayed once. Only its
Argon2id verifier is retained in the shared PostgreSQL identity domain. The
same worker row and verifier are consumed by the Stratum authentication
provider; the portal has no separate worker database.

WEC and ZEC destinations are entered separately. Full values are accepted only
by the mutation endpoint and handed to a chain-specific authoritative parser.
The parser must verify the complete encoding, checksum, chain, network, and
supported receiver set. A prefix or regular expression is not an acceptable
validator. Browser responses contain masked destinations. The initial valid
destination can become active immediately; a replacement remains pending for
the configured safety hold while accounting continues against the existing
destination.

## Browser security

- Portal passwords use bounded Argon2id PHC verifiers with 19 MiB memory,
  two iterations, and one lane.
- Unknown-account login still performs a dummy Argon2 verification, and known
  accounts receive a bounded temporary lock after repeated failures.
- Registration, login, worker-token creation, and payout reauthentication
  share a small non-queueing process-wide Argon2 semaphore. Saturation returns
  HTTP 429 with a bounded retry hint instead of allocating another memory-hard
  blocking task.
- Browser sessions are random 256-bit values. PostgreSQL stores only a
  domain-separated keyed digest, an absolute expiry, an idle expiry, and the
  account security version.
- The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, host-only, and
  scoped to `/`. A separate random CSRF value is bound to the session by a
  keyed digest and is required in a request header.
- Every mutation requires an exact configured HTTPS `Origin`. There is no
  cross-origin policy.
- TOTP secrets are 160 random bits and encrypted with XChaCha20-Poly1305 using
  the account identifier as associated data. Enrollment expires after ten
  minutes; activation revokes every existing browser session.
- Payout changes require the current password and the TOTP code when TOTP is
  enabled. Their failed checks use the same bounded account-lock policy.
- Responses apply a deny-by-default Content Security Policy, HSTS, no-sniff,
  no-referrer, no-store, and restrictive browser permission policy.
- Request bodies are capped at 16 KiB. Unknown JSON fields are rejected.

The portal never accepts or displays a seed phrase, spending key, viewing key,
wallet RPC credential, database credential, or pool collector secret.

## Data and payout authority

`wcash-pool-portal` exposes an object-safe asynchronous `PortalRepository`
contract. Production must implement it with the same deployment-fenced
PostgreSQL store used by Stratum authentication and monetary accounting.
SQLite is not a production or development fallback. Integration tests use a
process-local fake repository only to prove HTTP behavior.

Address validation is an injected `AddressValidator`. If either chain's
authority is missing, `/readyz` and destination changes fail closed.

The `/api/v1/balances`, `/api/v1/rewards`, `/api/v1/blocks`, and
`/api/v1/payouts` handlers are authenticated and query deployment-fenced,
account-scoped PostgreSQL projections. The found-block view starts at the
backend-validated submitted state rather than waiting for reward allocation;
its immutable cursor also keeps dual-chain winners independently pageable.
The `/api/v1/telemetry` route reads only the authenticated account's bounded
in-process counters. Empty arrays mean a proven empty account dataset;
repository failure remains an explicit unavailable response.

The `TestnetPayoutBoundary` accepts only Testnet requests. Each request binds:

- one stable batch UUID;
- one asset and network;
- the exact accounting ledger root and reconciliation checkpoint;
- an ordered, bounded output list with allocation IDs, canonical addresses,
  receiver classes, and atomic-unit amounts.

Its SHA-256 request commitment covers every field. The isolated signer must
durably store `(batch ID, request commitment, transaction ID)` before success.
An exact retry returns the stored receipt; reuse of a batch ID with different
content is an idempotency conflict and must never sign. The portal verifies the
returned commitment, asset, batch ID, output total, and transaction identifier.
The built-in disabled signer always returns `NotConfigured`; there is no fake
success or transparent-wallet fallback.

## HTTP composition

The crate exposes:

- `PortalApp::router()` for composition in `wcash-poold`;
- `serve(TcpListener, PortalApp)` for a caller-owned listener;
- `GET /healthz` for process liveness;
- `GET /readyz` for the shared PostgreSQL repository, both address authorities,
  and isolated signer readiness;
- `/api/v1/*` account, worker, security, payout-setting, and read-model routes;
- embedded static assets, so deployment does not require Node.js.

The listener must bind to loopback and sit behind the configured HTTPS reverse
proxy. Readiness is not whole-pool readiness: `wcash-poold` must additionally
gate public mining on Wolf identity/journal continuity, the durable accounting
projector, collector reconciliation, and Stratum readiness.

## Deployment secrets

The two 32-byte portal keys—token-digest pepper and TOTP encryption key—must be
independently generated per deployment. All-zero or reused keys are rejected.
Load them as binary systemd credentials or equivalently protected files. Never
place them in arguments, environment variables, unit-file text, repository
files, container images, HTTP configuration, or logs.

Testnet and Mainnet must never reuse these keys, the PostgreSQL deployment
identity, session rows, worker tokens, payout destinations, wallet keys, or
signer state.

## Evidence required before ASIC testing

1. Re-run the deployment-fenced PostgreSQL migration and portal/Stratum
   integration suite against the release artifact.
2. Exercise authoritative Wcash Testnet and Zcash Testnet address validation;
   wrong-chain, wrong-network, malformed, unsupported, and unavailable cases
   must fail closed.
3. Verify non-empty and empty balance, reward, winner, and payout projections
   through two independent accounts to prove isolation.
4. Exercise separate WEC and ZEC Testnet wallet observers plus the isolated,
   durably idempotent signer. Exercise success, rejection, timeout, ambiguous
   broadcast, exact retry, conflicting retry, restart, and reorganization.
5. Compose the portal on loopback behind HTTPS, inject secrets from protected
   credential files, back up and restore PostgreSQL, and pass a private soak.
6. Only then expose a Testnet Stratum address to an ASIC. Mainnet remains
   blocked by a separate review and release.

# ZecWec pool onboarding

This guide is the public contract for miners, frontend developers, and agents
integrating with the ZecWec Wcash/Zcash merged-mining pool.

> **Testnet only.** TWC and Testnet ZEC have no monetary value. Use the
> endpoints below only after the project announces that the Testnet pool is
> live. `zecwec.com` and `mine.zecwec.com` are reserved for a later Mainnet
> deployment.

## Miner setup

One ASIC connection submits the same Equihash work toward two independent
chains. A share can qualify for Wcash, Zcash, both chains, or neither network
target. Each chain has its own block acceptance, maturity, balance, and payout.

1. Register a pool account through the Testnet portal or its API.
2. Sign in and create a worker, for example `rig-01`.
3. Save the worker token immediately. It is shown only once and cannot be used
   to sign in to the portal.
4. Configure one Wcash Testnet payout destination and one Zcash Testnet payout
   destination. Zcash accepts a transparent address or a supported shielded
   address; Wcash requires a supported shielded address. Never provide a seed
   phrase, spending key, or private key.
5. Copy the generated mining username and token into the ASIC.

Testnet connection settings:

```text
Preferred:     stratum+ssl://testnet-mine.zecwec.com:3443
Compatibility: stratum+tcp://testnet-mine.zecwec.com:3333
Username:      <account>.<worker>
Password:      <generated worker token>
Algorithm:     Equihash 200,9
```

The compatibility endpoint is plaintext and exists for ASIC firmware that
cannot use TLS. Its worker token has mining-only authority. Never put a portal
password in an ASIC.

ASIC Pool 2 and Pool 3 are failovers, not separate Wcash and Zcash jobs. Leave
them empty until independent failover endpoints are published; do not invent
hostnames or use two pool slots for the two assets.

An accepted share is accounting evidence, not a block reward. A miner balance
increases only after this pool finds a block on the relevant chain and the
reward is allocated by that chain's PPLNS window. The balance becomes payable
after the required confirmation depth and payout threshold are both reached.
Changing a payout destination starts a 48-hour Testnet safety hold.

Both assets use eight decimal places:

```text
1 WEC or ZEC = 100,000,000 atomic units
```

The pool charges a 0% Testnet service fee. A payout may reserve a bounded
network fee; any unused reserve is returned to the miner's payable balance
after confirmation.

## Account API

The API origin is:

```text
https://testnet.zecwec.com
```

The miner UI and API are served together at this origin. The UI is embedded in
the Rust release and does not require a separate frontend service. Browser mutations require the exact
`Origin: https://testnet.zecwec.com` header, a secure host-only session cookie,
and the login response's CSRF token in `x-csrf-token`. Cross-origin browser
requests are intentionally unsupported.

The examples below use a local cookie jar. Replace the placeholder values; do
not paste real credentials into logs, issues, chat messages, or source files.

### Register and sign in

Account names are 3-32 characters, start with a lowercase letter, and contain
only lowercase letters, digits, or `_`. Input is normalized to lowercase.

```sh
origin=https://testnet.zecwec.com
curl --fail-with-body --silent --show-error \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"REPLACE_ME"}' \
  "$origin/api/v1/auth/register"

curl --fail-with-body --silent --show-error \
  -c zecwec-testnet.cookies \
  -H "Origin: $origin" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"REPLACE_ME"}' \
  "$origin/api/v1/auth/login"
```

The login response contains `csrf_token`. Keep it in memory and send it on
every authenticated `POST`, `PUT`, or `DELETE` request. Sessions expire after
12 hours or 30 minutes of inactivity. Five failed logins cause a 15-minute
temporary lock.

### Create a worker

Worker labels are 1-32 lowercase letters, digits, or `-`.

```sh
csrf='COPY_CSRF_TOKEN_FROM_LOGIN'
curl --fail-with-body --silent --show-error \
  -b zecwec-testnet.cookies \
  -H "Origin: $origin" \
  -H "x-csrf-token: $csrf" \
  -H 'Content-Type: application/json' \
  --data '{"label":"rig-01"}' \
  "$origin/api/v1/workers"
```

The response contains `mining_username` and a one-time `token`. Store the token
in the ASIC. If it is lost or exposed, revoke that worker and create a new one;
the API never returns the token again.

### Configure payouts

Wcash and Zcash destinations are configured independently. The server parses
each address using the authoritative Testnet rules and rejects wrong-chain,
wrong-network, or unsupported receiver types.

| Asset | Accepted destination |
| --- | --- |
| TWC | Wcash Testnet Unified Address with the supported Ironwood receiver |
| ZEC | Zcash Testnet transparent P2PKH/P2SH address, or a Unified Address with the supported Ironwood receiver |

The portal's transparent/shielded choice explains the Zcash address format;
the server validates the actual address. It does not select a second mining
implementation or require a second ASIC connection.

```sh
curl --fail-with-body --silent --show-error \
  -X PUT \
  -b zecwec-testnet.cookies \
  -H "Origin: $origin" \
  -H "x-csrf-token: $csrf" \
  -H 'Content-Type: application/json' \
  --data '{
    "destination":"REPLACE_WITH_WCASH_TESTNET_ADDRESS",
    "threshold_zat":100000000,
    "automatic":true,
    "password":"REPLACE_ME"
  }' \
  "$origin/api/v1/settings/payouts/wec"

curl --fail-with-body --silent --show-error \
  -X PUT \
  -b zecwec-testnet.cookies \
  -H "Origin: $origin" \
  -H "x-csrf-token: $csrf" \
  -H 'Content-Type: application/json' \
  --data '{
    "destination":"REPLACE_WITH_ZCASH_TESTNET_ADDRESS",
    "threshold_zat":100000000,
    "automatic":true,
    "password":"REPLACE_ME"
  }' \
  "$origin/api/v1/settings/payouts/zec"
```

When TOTP is enabled, add `"totp_code":"123456"` to login and sensitive
reauthentication bodies. `POST /api/v1/security/totp/begin` returns an
enrollment secret and URI after password reauthentication. Confirm it within
10 minutes using `POST /api/v1/security/totp/confirm` with `{"code":"123456"}`.
Confirmation revokes existing sessions, so sign in again afterward.

## API reference for frontends and agents

All request bodies reject unknown fields and are limited to 16 KiB. Use
`credentials: "include"` in browser `fetch` calls. Treat response schemas as a
versioned contract; do not scrape HTML or infer private state from masked
addresses.

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | Process liveness |
| `GET` | `/readyz` | none | Full advertised deployment readiness |
| `GET` | `/api/v1/overview` | none | Aggregate pool and chain status |
| `POST` | `/api/v1/auth/register` | exact Origin | Create an account |
| `POST` | `/api/v1/auth/login` | exact Origin | Create a session and return CSRF token |
| `POST` | `/api/v1/auth/logout` | session + CSRF | Revoke the current session |
| `GET` | `/api/v1/me` | session | Current account |
| `GET`/`POST` | `/api/v1/workers` | session; CSRF for POST | List or create workers |
| `DELETE` | `/api/v1/workers/{id}` | session + CSRF | Revoke one worker |
| `GET` | `/api/v1/settings/payouts` | session | Masked WEC and ZEC settings |
| `PUT` | `/api/v1/settings/payouts/{wec|zec}` | session + CSRF + reauthentication | Replace one payout policy |
| `GET` | `/api/v1/balances` | session | Per-asset immature, payable, and pending balances |
| `GET` | `/api/v1/telemetry` | session | This account's live workers and shares |
| `GET` | `/api/v1/rewards` | session | PPLNS reward history |
| `GET` | `/api/v1/blocks` | session | Blocks attributed to this account |
| `GET` | `/api/v1/payouts` | session | Payout lifecycle and fee accounting |
| `POST` | `/api/v1/security/totp/begin` | session + CSRF + reauthentication | Begin TOTP enrollment |
| `POST` | `/api/v1/security/totp/confirm` | session + CSRF | Confirm TOTP and revoke sessions |

History endpoints accept `limit=1..100` and an opaque monotonic `before`
cursor. Responses use `{ "items": [...], "next_before": ... }`.

Automation must stop on non-2xx responses, preserve cookies securely, avoid
retrying non-idempotent mutations blindly, and never log passwords, CSRF
tokens, worker tokens, TOTP secrets, or full payout destinations. Polling
`/healthz` proves only that the HTTP process is alive; use `/readyz` for the
deployment state advertised to miners.

For implementation and security boundaries, see
[Miner portal and payouts](miner-portal.md) and the
[Testnet deployment runbook](zecwec-testnet-deployment.md).

# Changelog

## Unreleased

- Wait within the existing bounded readiness budget before frontend startup
  claims a nonce namespace or starts its share actor. Retry only missing current
  jobs and typed temporary backend availability failures with a fresh connection
  and replay/snapshot verification. Preserve permanent-error refusal, running
  health/recovery deadlines, target policy, accounting and payout behavior.

- Isolate frontend operational summaries behind one bounded, best-effort logging
  thread. Broken or blocked summary output no longer fails or delays startup, serving
  tasks or shutdown; full queues and final output at process exit may be lost.
  Preserve the summary JSON schema, cadence and mining/accounting behavior.

- Add bounded frontend submission, recovery, projection and connection-driver
  diagnostics. Account and worker counters use the existing authenticated
  telemetry route; process totals use fixed, rate-limited operational summaries.
  Distinguish raw target filtering, authenticated backend receipts, exact
  projection and unknown completion without changing validation, responses,
  retry/authority fences, Stratum/backend wire formats, database schema,
  accounting or payouts. The authenticated telemetry JSON gains additive fields.

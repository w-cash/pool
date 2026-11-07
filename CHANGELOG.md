# Changelog

## Unreleased

- Add bounded frontend submission, recovery, projection and connection-driver
  diagnostics. Account and worker counters use the existing authenticated
  telemetry route; process totals use fixed, rate-limited operational summaries.
  Distinguish raw target filtering, authenticated backend receipts, exact
  projection and unknown completion without changing validation, responses,
  retry/authority fences, Stratum/backend wire formats, database schema,
  accounting or payouts. The authenticated telemetry JSON gains additive fields.

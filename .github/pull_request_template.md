## Summary

<!-- Explain the outcome and why this change is needed. -->

## Security and accounting impact

<!-- Describe changes to trust boundaries, miner input, job attribution, durable
state, balances, payouts, credentials, or denial-of-service exposure. Write
"none" only after checking each boundary. -->

## Wcash backend compatibility

<!-- Name the exact wolf commit/API version used for any backend-facing change.
The pool must fail closed on an unknown version or ambiguous result. -->

- Backend/API version changed: yes / no
- Wire format or persisted state changed: yes / no
- Migration or rollback required: yes / no

## Verification

<!-- List exact commands and deterministic scenarios exercised. Required CI must
not depend on a live network, real funds, wall-clock races, or Equihash solving. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --workspace --all-targets --all-features`
- [ ] Relevant invalid-input, duplicate, retry, restart, stale-job, and reorg cases are covered
- [ ] Documentation and the testnet roadmap match the resulting behavior

## Deployment declaration

- [ ] This change does **not** claim that the current foundation is deployable or testnet-ready
- [ ] No credential, RPC cookie, payout key, production endpoint, or real-funds configuration is included
- [ ] The PR title follows `type(scope): concise description`

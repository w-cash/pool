# Contributing

Keep changes focused and explain their security and accounting consequences.
Consensus-sensitive logic belongs in the Wcash node, not in this repository.

Every change must pass formatting, linting, tests, and documentation checks.
New protocol inputs require strict size bounds, negative tests, and stable test
vectors. Changes to share attribution, job retirement, or settlement require
explicit replay and failure-mode tests.

Use conventional commit messages. Never commit credentials, payout keys, or
production configuration.

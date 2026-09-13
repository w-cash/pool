#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

[[ $# -eq 5 && $5 == --ack-forward-schema-compatible ]] || {
    printf '%s\n' \
        'activate-release: usage: activate-release.sh <version> <settings> <authority> <miner-cidr-file> --ack-forward-schema-compatible' \
        >&2
    exit 1
}

# Forward activation and rollback have the same fail-closed state transition:
# verify the immutable target with the currently trusted tooling, stop every
# authority, render from the target snapshot, switch the selector, migrate,
# preflight, and expose listeners only after payout readiness and health pass.
# Keep one implementation so the two paths cannot silently diverge.
ZECWEC_RELEASE_TRANSITION=activation exec "$script_dir/rollback-release.sh" \
    "$1" "$2" "$3" "$4" --ack-schema-compatible

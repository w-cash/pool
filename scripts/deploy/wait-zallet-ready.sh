#!/usr/bin/env bash

set -Eeuo pipefail
set +x

readonly libexec=/usr/local/libexec/zecwec
[[ $# -eq 1 ]] || {
    printf 'wait-zallet-ready: usage: wait-zallet-ready.sh <loopback-socket>\n' >&2
    exit 1
}
: "${STATE_DIRECTORY:?systemd StateDirectory is required}"
exec python3 "$libexec/zallet_rpc_health.py" \
    --socket "$1" \
    --cookie "$STATE_DIRECTORY/.cookie" \
    --deadline 1080

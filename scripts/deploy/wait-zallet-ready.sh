#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $# -eq 1 ]] || {
    printf 'wait-zallet-ready: usage: wait-zallet-ready.sh <loopback-socket>\n' >&2
    exit 1
}
: "${STATE_DIRECTORY:?systemd StateDirectory is required}"
exec python3 "$script_dir/zallet_rpc_health.py" \
    --socket "$1" \
    --cookie "$STATE_DIRECTORY/.cookie" \
    --deadline 1080

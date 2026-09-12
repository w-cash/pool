#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command systemctl

[[ $# -eq 2 ]] || die "usage: start-testnet-pool.sh <settings> <miner-cidr-file>"
settings=$1
cidrs=$2
require_private_regular_file "$settings"
require_private_regular_file "$cidrs"

"$ZECWEC_LIBEXEC/restrict-mining-firewall.sh" apply "$settings" "$cidrs"
"$ZECWEC_LIBEXEC/preflight.sh" "$settings"
"$ZECWEC_LIBEXEC/enable-nginx-edge.sh" stratum-only "$settings" "$cidrs"

if ! systemctl start zecwec-testnet-pool.target; then
    systemctl stop zecwec-testnet-pool.target wcash-pool-health.timer wcash-pool.service \
        >/dev/null 2>&1 || true
    die "pool start failed; public pool service was stopped"
fi
if ! "$ZECWEC_LIBEXEC/health-check.sh" --settings "$settings" --cidrs "$cidrs"; then
    systemctl stop zecwec-testnet-pool.target wcash-pool-health.timer wcash-pool.service \
        >/dev/null 2>&1 || true
    die "post-start health failed; public pool service was stopped"
fi
systemctl enable wcash-pool-health.timer zecwec-testnet-pool.target

log "private Testnet pool is healthy for only the approved miner CIDRs"

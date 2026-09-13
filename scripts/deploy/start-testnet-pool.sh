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

# Keep every mining ingress closed until the isolated payout worker has proved
# a fresh lease. This also closes rules persisted by UFW across a reboot.
"$script_dir/restrict-mining-firewall.sh" close "$settings" "$cidrs"
"$script_dir/preflight.sh" "$settings"

if ! systemctl start zecwec-testnet-pool.target; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "pool start failed; public pool service was stopped"
fi
portal=$(read_setting "$settings" PORTAL_LISTEN)
if ! python3 "$script_dir/wait_payout_ready.py" "http://$portal/readyz" 4200; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "payout worker did not become ready; public and payout services were stopped"
fi
"$script_dir/restrict-mining-firewall.sh" apply "$settings" "$cidrs"
if ! "$script_dir/enable-nginx-edge.sh" reconcile "$settings" "$cidrs"; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "the persisted edge mode could not be reconciled; public and payout services were stopped"
fi
if ! "$script_dir/health-check.sh" --settings "$settings" --cidrs "$cidrs"; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "post-start health failed; public pool service was stopped"
fi
systemctl disable zecwec-testnet-pool.target wcash-pool-health.timer \
    >/dev/null 2>&1 || true
if ! systemctl enable zecwec-testnet-pool-start.service >/dev/null \
    || ! systemctl start wcash-pool-health.timer; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "could not install the readiness-gated boot and health supervision path"
fi

log "Testnet mining and the isolated payout worker are healthy for the approved miner CIDRs"

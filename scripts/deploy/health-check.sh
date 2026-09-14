#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

quiet=false
settings=/etc/wcash-pool/deployment.env
cidrs=/etc/wcash-pool/miner-cidrs
while (($#)); do
    case "$1" in
        --quiet) quiet=true; shift ;;
        --settings) [[ $# -ge 2 ]] || die "--settings needs a path"; settings=$2; shift 2 ;;
        --cidrs) [[ $# -ge 2 ]] || die "--cidrs needs a path"; cidrs=$2; shift 2 ;;
        *) die "usage: health-check.sh [--quiet] [--settings path] [--cidrs path]" ;;
    esac
done

require_root

# The scheduled probe is a safety authority, not only an alarm. Interactive
# probes remain read-only so an operator can diagnose an intentionally stopped
# deployment, but a failed timer probe closes every public and payout runtime.
health_check_exit() {
    local status=$?
    trap - EXIT
    if $quiet && ((status != 0)); then
        stop_testnet_runtime_after_failure "$settings" "$cidrs"
    fi
    exit "$status"
}
trap health_check_exit EXIT

require_command curl
require_command grep
require_command openssl
require_command python3
require_command runuser
require_command ss
require_command systemctl
require_private_regular_file "$settings"
release_policy=/etc/wcash-pool/release.env
[[ -f $release_policy && ! -L $release_policy \
    && $(stat -c '%u:%a:%h' -- "$release_policy") == 0:644:1 ]] \
    || die "rendered release policy is unavailable or unsafe"
release_root=$(resolve_release_root "$(read_setting "$release_policy" ZECWEC_RELEASE_PATH)")
[[ $(read_setting "$release_policy" ZECWEC_DEPLOYMENT_SCHEMA) == 2 ]] \
    || die "rendered deployment schema is unsupported"
for binary in wcash-poold wcash-merge-miner wcash-wallet; do
    ZECWEC_RELEASE_PATH=$release_root \
        "$release_root/deployment/scripts/deploy/verify-release.sh" "$binary"
done
ZECWEC_RELEASE_PATH=$release_root \
    "$release_root/deployment/scripts/deploy/verify-release.sh" deployment-package
for service in postgresql.service zecwec-testnet-pool.target wcash-pool-backend.service \
    wcash-pool-projector.service wcash-pool.service \
    zecwec-zallet-payout.service wcash-payout-worker.service \
    zecwec-cookie-refresh.path; do
    systemctl is-active --quiet "$service" || die "service is not active: $service"
done
for unit in zecwec-zallet.service zecwec-zallet-recovery.service; do
    require_loaded_unit_fully_inactive "$unit"
done
require_no_processes_for_user zecwec-zallet-recovery "recovery identity"
zallet_rpc=$(read_setting "$settings" ZALLET_RPC)
zallet_port=${zallet_rpc##*:}
zallet_listeners=$(ss -H -ltn "sport = :$zallet_port") \
    || die "Zallet payout RPC listener inspection failed"
[[ -n $zallet_listeners && $zallet_listeners != *"0.0.0.0:$zallet_port"* \
    && $zallet_listeners != *"[::]:$zallet_port"* ]] \
    || die "Zallet payout RPC is absent or publicly reachable"
require_tcp_listener_absent 28242 "recovery Zallet RPC"
require_hot_testnet_payout_custody "$settings" "$release_root"

socket=$(read_setting "$settings" BACKEND_SOCKET)
[[ -S $socket && ! -L $socket ]] || die "backend socket is unavailable"
[[ $(stat -c '%U:%G:%a' -- "$socket") == wcash-pool-backend:wcash-pool-socket:660 ]] \
    || die "backend socket ownership or mode is invalid"

portal=$(read_setting "$settings" PORTAL_LISTEN)
stratum=$(read_setting "$settings" STRATUM_LISTEN)
plain_port=${stratum##*:}
tls_port=$(read_setting "$settings" STRATUM_TLS_PORT)
portal_ready=false
# Keep the edge open through the same bounded parent-tip rollover window used
# by the pool and projector. A transient validator/template disagreement must
# not close every public listener before the backend can publish its next job.
for attempt in $(seq 1 30); do
    if portal_readiness=$(curl --fail --silent --show-error --max-time 5 \
        "http://$portal/readyz"); then
        if python3 -c '
import json
import sys
try:
    value = json.load(sys.stdin)
except (UnicodeError, json.JSONDecodeError):
    raise SystemExit(1) from None
expected = {
    "ready": True,
    "component": "miner-portal",
    "network": "testnet",
    "payout_execution": "enabled",
}
raise SystemExit(0 if value == expected else 1)
' <<<"$portal_readiness"; then
            portal_ready=true
            break
        fi
    fi
    if ((attempt < 30)); then
        sleep 2
    fi
done
[[ $portal_ready == true ]] || die "portal readiness failed after bounded retries"
ss -H -ltn "sport = :$plain_port" | grep -q . || die "plaintext Stratum listener is unavailable"
systemctl is-active --quiet nginx.service || die "nginx TLS edge is not active"
ss -H -ltn "sport = :$tls_port" | grep -q . || die "TLS Stratum listener is unavailable"
mining_certificate=$(read_setting "$settings" MINING_TLS_CERT)
require_trusted_etc_file "$mining_certificate" false
require_public_tls_listener \
    "$(read_setting "$settings" MINING_HOST)" "$tls_port" 127.0.0.1 \
    "$mining_certificate"

"$script_dir/restrict-mining-firewall.sh" check "$settings" "$cidrs" >/dev/null
trap - EXIT
$quiet || printf '{"healthy":true,"network":"testnet","pool":"zecwec"}\n'

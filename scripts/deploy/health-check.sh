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
require_command curl
require_command grep
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
[[ $(read_setting "$release_policy" ZECWEC_DEPLOYMENT_SCHEMA) == 1 ]] \
    || die "rendered deployment schema is unsupported"
for binary in wcash-poold wcash-merge-miner wcash-wallet; do
    ZECWEC_RELEASE_PATH=$release_root \
        "$release_root/deployment/scripts/deploy/verify-release.sh" "$binary"
done
ZECWEC_RELEASE_PATH=$release_root \
    "$release_root/deployment/scripts/deploy/verify-release.sh" deployment-package
for service in postgresql.service wcash-pool-backend.service \
    wcash-pool.service zecwec-cookie-refresh.path; do
    systemctl is-active --quiet "$service" || die "service is not active: $service"
done
systemctl is-active --quiet zecwec-zallet.service \
    && die "deferred-payout mining must not keep Zallet online"
zallet_rpc=$(read_setting "$settings" ZALLET_RPC)
zallet_port=${zallet_rpc##*:}
if ss -H -ltn "sport = :$zallet_port" | grep -q .; then
    die "deferred-payout mining exposed a Zallet RPC listener"
fi
require_offline_collector_custody "$settings"

socket=$(read_setting "$settings" BACKEND_SOCKET)
[[ -S $socket && ! -L $socket ]] || die "backend socket is unavailable"
[[ $(stat -c '%U:%G:%a' -- "$socket") == wcash-pool-backend:wcash-pool-socket:660 ]] \
    || die "backend socket ownership or mode is invalid"

portal=$(read_setting "$settings" PORTAL_LISTEN)
stratum=$(read_setting "$settings" STRATUM_LISTEN)
plain_port=${stratum##*:}
tls_port=$(read_setting "$settings" STRATUM_TLS_PORT)
portal_readiness=$(curl --fail --silent --show-error --max-time 5 "http://$portal/readyz") \
    || die "portal readiness failed"
python3 -c '
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
    "payout_execution": "deferred",
}
raise SystemExit(0 if value == expected else 1)
' <<<"$portal_readiness" || die "portal readiness policy is not deferred Testnet mining"
ss -H -ltn "sport = :$plain_port" | grep -q . || die "plaintext Stratum listener is unavailable"
if systemctl is-active --quiet nginx.service; then
    ss -H -ltn "sport = :$tls_port" | grep -q . || die "TLS Stratum listener is unavailable"
fi

"$script_dir/restrict-mining-firewall.sh" check "$settings" "$cidrs" >/dev/null
$quiet || printf '{"healthy":true,"network":"testnet","pool":"zecwec"}\n'

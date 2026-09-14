#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command systemctl
require_command ss
require_command python3
require_command runuser

[[ $# -eq 1 ]] || die "usage: preflight.sh <settings>"
settings=$1
require_private_regular_file "$settings"
require_supported_postgres_server
[[ -f /etc/wcash-pool/pool.runtime.toml ]] || die "finalized runtime policy is missing"
[[ -f /etc/wcash-pool/pool.projector.toml ]] || die "finalized projector policy is missing"
[[ -f /etc/wcash-pool/pool.migrate.toml ]] || die "finalized migration policy is missing"
[[ -f /etc/wcash-pool/pool.preflight.toml ]] || die "finalized preflight policy is missing"
[[ -f /etc/wcash-pool/pool.payout.toml ]] || die "finalized payout-worker policy is missing"
legacy_share_journal=/var/lib/wcash-pool/share-journal-v2.jsonl
[[ ! -e $legacy_share_journal && ! -L $legacy_share_journal ]] \
    || die "legacy share journal must be reviewed and archived before protocol-v2 preflight"

stop_preflight_authorities() {
    systemctl stop wcash-pool-projector.service \
        wcash-pool-backend.service >/dev/null 2>&1 || true
}

stop_failed_preflight() {
    systemctl stop zecwec-testnet-pool.target wcash-pool-custody-gate.service \
        wcash-pool-health.timer \
        wcash-payout-worker.service zecwec-zallet-payout.service \
        wcash-pool.service wcash-pool-projector.service \
        wcash-pool-backend.service >/dev/null 2>&1 || true
}

trap stop_preflight_authorities EXIT
trap stop_failed_preflight ERR
systemctl stop zecwec-testnet-pool.target wcash-pool-custody-gate.service >/dev/null 2>&1 || true
systemctl stop wcash-pool-health.timer >/dev/null 2>&1 || true
systemctl stop zecwec-cookie-refresh.path >/dev/null 2>&1 || true
systemctl stop zecwec-cookie-refresh.service >/dev/null 2>&1 || true
systemctl disable zecwec-zallet.service zecwec-zallet-recovery.service \
    >/dev/null 2>&1 || true
systemctl stop wcash-payout-worker.service zecwec-zallet-payout.service \
    zecwec-zallet.service zecwec-zallet-recovery.service \
    wcash-pool-wallet-init.service \
    wcash-pool-zec-authority-bootstrap.service >/dev/null 2>&1 || true

systemctl stop wcash-pool-projector.service >/dev/null 2>&1 || true
require_loaded_unit_fully_inactive wcash-pool-projector.service

if systemctl is-active --quiet wcash-pool.service; then
    systemctl stop wcash-pool.service
fi

stratum=$(read_setting "$settings" STRATUM_LISTEN)
port=${stratum##*:}
portal=$(read_setting "$settings" PORTAL_LISTEN)
portal_port=${portal##*:}
for listener in "$port" "$portal_port"; do
    require_tcp_listener_absent "$listener" "preflight public-service"
done

zallet_rpc=$(read_setting "$settings" ZALLET_RPC)
zallet_port=${zallet_rpc##*:}
for unit in zecwec-zallet.service zecwec-zallet-payout.service \
    zecwec-zallet-recovery.service wcash-payout-worker.service; do
    require_loaded_unit_fully_inactive "$unit"
done
require_no_processes_for_user zecwec-zallet "collector identity"
require_no_processes_for_user zecwec-zallet-recovery "recovery identity"
require_no_processes_for_user wcash-payout "payout identity"
for wallet_port in "$zallet_port" 28242; do
    require_tcp_listener_absent "$wallet_port" "preflight Zallet RPC"
done

release_policy=/etc/wcash-pool/release.env
[[ -f $release_policy && ! -L $release_policy \
    && $(stat -c '%u:%a:%h' -- "$release_policy") == 0:644:1 ]] \
    || die "rendered release policy is unavailable or unsafe"
release_root=$(resolve_release_root "$(read_setting "$release_policy" ZECWEC_RELEASE_PATH)")
require_hot_testnet_payout_custody "$settings" "$release_root"

systemctl stop wcash-pool-backend.service >/dev/null 2>&1 || true
systemctl restart wcash-pool-backend-init.service
systemctl restart wcash-pool-backend.service
systemctl restart wcash-pool-migrate.service
systemctl restart wcash-pool-projector.service
systemctl restart wcash-pool-preflight.service

for unit in zecwec-zallet.service zecwec-zallet-payout.service \
    zecwec-zallet-recovery.service wcash-payout-worker.service; do
    require_loaded_unit_fully_inactive "$unit"
done
require_no_processes_for_user zecwec-zallet "collector identity"
require_no_processes_for_user zecwec-zallet-recovery "recovery identity"
require_no_processes_for_user wcash-payout "payout identity"
systemctl is-active --quiet wcash-pool-backend.service || die "backend is not active"
systemctl is-active --quiet wcash-pool-projector.service || die "accounting projector is not active"
systemctl is-active --quiet postgresql.service || die "PostgreSQL is not active"

for listener in "$port" "$portal_port"; do
    require_tcp_listener_absent "$listener" "post-validation public-service"
done

"$script_dir/refresh-runtime-credentials.sh" snapshot "$settings"
systemctl start zecwec-cookie-refresh.path
systemctl stop wcash-pool-projector.service
require_loaded_unit_fully_inactive wcash-pool-projector.service
systemctl stop wcash-pool-backend.service
require_loaded_unit_fully_inactive wcash-pool-backend.service
trap - ERR
trap - EXIT

log "listener-free Testnet preflight passed; the pool, backend, and projector remain stopped"

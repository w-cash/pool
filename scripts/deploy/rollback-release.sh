#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command systemctl

transition=${ZECWEC_RELEASE_TRANSITION:-rollback}
[[ $transition == rollback || $transition == activation ]] \
    || die "release transition kind is invalid"

[[ $# -eq 5 && $5 == --ack-schema-compatible ]] \
    || die "usage: rollback-release.sh <version> <settings> <authority> <miner-cidr-file> --ack-schema-compatible"
version=$1
settings=$2
authority=$3
cidrs=$4
[[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "release version is unsafe"
require_private_regular_file "$settings"
require_absolute_path "$authority"
[[ -f $authority && ! -L $authority ]] || die "backend authority file is unavailable"
require_private_regular_file "$cidrs"

target="$ZECWEC_RELEASE_ROOT/$version"
[[ -d $target && ! -L $target ]] || die "rollback release is not installed"
# Security epoch 2 introduced the isolated projector/migrator identities and
# removed public monetary DML. Never execute a target-owned verifier, renderer,
# or migrator from an older epoch: that package can restore its persisted broad
# runtime grants before current code has a chance to repair them.
target_schema="$target/deployment/DEPLOYMENT-SCHEMA"
[[ -f $target_schema && ! -L $target_schema \
    && $(cat -- "$target_schema") == 2 ]] \
    || die "rollback release predates the isolated-authority security epoch"
for binary in wcash-poold wcash-merge-miner wcash-wallet; do
    ZECWEC_RELEASE_PATH=$target "$script_dir/verify-release.sh" "$binary"
done
ZECWEC_RELEASE_PATH=$target \
    "$script_dir/verify-release.sh" deployment-package

"$script_dir/restrict-mining-firewall.sh" close "$settings" "$cidrs"
transition_failed() {
    local status=$?
    trap - ERR
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    exit "$status"
}
trap transition_failed ERR

for unit in \
    zecwec-testnet-pool-start.service \
    wcash-pool-health.timer \
    zecwec-cookie-refresh.path \
    zecwec-cookie-refresh.service \
    zecwec-testnet-pool.target \
    wcash-payout-worker.service \
    wcash-pool.service \
    wcash-pool-projector.service \
    wcash-pool-backend.service \
    zecwec-zallet.service \
    zecwec-zallet-payout.service \
    zecwec-zallet-recovery.service \
    wcash-pool-wallet-init.service \
    wcash-pool-zec-authority-bootstrap.service; do
    stop_loaded_unit_strict "$unit"
done
systemctl disable zecwec-zallet.service zecwec-zallet-recovery.service \
    >/dev/null 2>&1 || true
ZECWEC_RELEASE_PATH=$target \
    "$target/deployment/scripts/deploy/render-deployment.sh" finalize "$settings" "$authority"
temporary=/opt/wcash/.current.rollback.$$
trap 'rm -f -- "$temporary"' EXIT
ln -s -- "$target" "$temporary"
mv -Tf -- "$temporary" "$ZECWEC_CURRENT_RELEASE"
trap - EXIT

systemctl restart wcash-pool-backend-init.service
systemctl restart wcash-pool-backend.service
systemctl restart wcash-pool-migrate.service
systemctl restart wcash-pool-preflight.service
"$target/deployment/scripts/deploy/refresh-runtime-credentials.sh" snapshot "$settings"
systemctl start zecwec-cookie-refresh.path
if ! systemctl start zecwec-testnet-pool.target; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "rollback target failed to start; public and payout services remain stopped"
fi
portal=$(read_setting "$settings" PORTAL_LISTEN)
if ! python3 "$target/deployment/scripts/deploy/wait_payout_ready.py" \
    "http://$portal/readyz" 4200; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "rollback payout worker did not become ready; all public and payout services remain stopped"
fi
"$target/deployment/scripts/deploy/restrict-mining-firewall.sh" apply "$settings" "$cidrs"
"$target/deployment/scripts/deploy/enable-nginx-edge.sh" reconcile "$settings" "$cidrs"
if ! "$target/deployment/scripts/deploy/health-check.sh" \
    --settings "$settings" --cidrs "$cidrs"; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "rollback target failed health checks; all public and payout services remain stopped"
fi
systemctl disable zecwec-testnet-pool.target wcash-pool-health.timer \
    >/dev/null 2>&1 || true
if ! systemctl enable zecwec-testnet-pool-start.service >/dev/null \
    || ! systemctl start wcash-pool-health.timer; then
    stop_testnet_runtime_after_failure "$settings" "$cidrs"
    die "release transition could not install readiness-gated boot supervision"
fi
trap - ERR

if [[ $transition == activation ]]; then
    log "activated verified release $version after an explicit forward schema-compatibility acknowledgement"
else
    log "rolled back to verified release $version after an explicit schema-compatibility acknowledgement"
fi

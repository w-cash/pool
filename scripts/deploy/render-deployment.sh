#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3
require_command realpath
require_command systemctl

[[ $# -eq 2 || $# -eq 3 ]] \
    || die "usage: render-deployment.sh <wallet-bootstrap|bootstrap|finalize> <settings> [backend-authority]"
phase=$1
settings=$2
authority=${3:-}
[[ $phase == wallet-bootstrap || $phase == bootstrap || $phase == finalize ]] \
    || die "phase must be wallet-bootstrap, bootstrap, or finalize"
require_private_regular_file "$settings"
if [[ $phase == finalize ]]; then
    [[ -n $authority ]] || die "finalize requires a backend authority file"
    require_absolute_path "$authority"
    [[ -f $authority && ! -L $authority ]] || die "backend authority file is unavailable"
fi

release_root=$(resolve_release_root "${ZECWEC_RELEASE_PATH:-$ZECWEC_CURRENT_RELEASE}")
ZECWEC_RELEASE_PATH=$release_root \
    "$release_root/deployment/scripts/deploy/verify-release.sh" deployment-package
for binary in wcash-poold wcash-merge-miner wcash-wallet zallet; do
    ZECWEC_RELEASE_PATH=$release_root \
        "$release_root/deployment/scripts/deploy/verify-release.sh" "$binary"
done
source_root="$release_root/deployment"
pool_uid=$(id -u wcash-pool)

if systemctl is-active --quiet wcash-pool.service; then
    die "wcash-pool.service must be stopped before rendering deployment state"
fi
if systemctl is-active --quiet wcash-pool-backend.service; then
    die "wcash-pool-backend.service must be stopped before rendering deployment state"
fi
# Cached backend/Wcash oneshots must be reconciled against every newly rendered
# exact policy. The ZEC gate itself is deliberately transient: it repeats the
# strict zero check only while no backend authority exists.
systemctl stop wcash-pool-backend-init.service wcash-pool-zec-authority-bootstrap.service \
    wcash-pool-wallet-init.service >/dev/null 2>&1 || true
if [[ $phase == wallet-bootstrap ]]; then
    for stale in \
        /etc/wcash-pool/backend.env \
        /etc/wcash-pool/pool.runtime.toml \
        /etc/wcash-pool/pool.preflight.toml \
        /etc/wcash-pool/pool.migrate.toml; do
        [[ ! -e $stale && ! -L $stale ]] \
            || die "wallet-bootstrap refuses existing authority or runtime policy: $stale"
    done
fi
managed_unit=/etc/systemd/system/wcash-pool.service
if [[ -e $managed_unit || -L $managed_unit ]]; then
    [[ -f $managed_unit && ! -L $managed_unit ]] \
        || die "refusing to replace a non-regular wcash-pool.service unit"
    grep -Fq '# Managed by the ZecWec Testnet deployment package.' "$managed_unit" \
        || die "archive the legacy wcash-pool.service with disable-legacy-pool.sh before rendering"
fi

staging=$(mktemp -d /var/tmp/zecwec-render.XXXXXX)
trap 'rm -rf -- "$staging"' EXIT
arguments=(
    "$phase"
    --settings "$settings"
    --source-root "$source_root"
    --release-root "$release_root"
    --output "$staging"
    --pool-uid "$pool_uid"
)
if [[ $phase == finalize ]]; then
    arguments+=(--authority "$authority")
fi
python3 "$source_root/scripts/deploy/render_deployment.py" "${arguments[@]}"

install -d -o root -g root -m 0755 "$ZECWEC_CONFIG_DIR"
install -o zecwec-zallet -g zecwec-zallet -m 0600 "$staging/zallet.toml" "$ZECWEC_CONFIG_DIR/zallet.toml"
install -o root -g wcash-pool -m 0640 "$staging/wcash-wallet-bootstrap.env" \
    "$ZECWEC_CONFIG_DIR/wcash-wallet-bootstrap.env"
if [[ $phase != wallet-bootstrap ]]; then
    install -o root -g wcash-pool-backend -m 0640 "$staging/backend.env" "$ZECWEC_CONFIG_DIR/backend.env"
    install -o root -g wcash-pool-backend -m 0640 "$staging/zec-authority.testnet.toml" \
        "$ZECWEC_CONFIG_DIR/zec-authority.testnet.toml"
fi

if [[ $phase == finalize ]]; then
    install -o root -g wcash-pool -m 0640 "$staging/pool.runtime.toml" "$ZECWEC_CONFIG_DIR/pool.runtime.toml"
    install -o root -g wcash-pool -m 0640 "$staging/pool.preflight.toml" "$ZECWEC_CONFIG_DIR/pool.preflight.toml"
    install -o root -g wcash-pool -m 0640 "$staging/pool.migrate.toml" "$ZECWEC_CONFIG_DIR/pool.migrate.toml"
fi
install -o root -g root -m 0644 "$staging/release.env" "$ZECWEC_CONFIG_DIR/release.env"

for unit in "$staging"/systemd/*; do
    install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename -- "$unit")"
done
if [[ $phase != wallet-bootstrap ]]; then
    install -d -o root -g root -m 0755 /etc/nginx/sites-available /etc/nginx/streams-available
    install -o root -g root -m 0644 "$staging/nginx/zecwec-testnet-portal.conf" \
        /etc/nginx/sites-available/zecwec-testnet-portal.conf
    install -o root -g root -m 0644 "$staging/nginx/zecwec-testnet-stratum.conf" \
        /etc/nginx/streams-available/zecwec-testnet-stratum.conf
fi

systemctl daemon-reload
log "rendered $phase Testnet configuration; no service or nginx endpoint was started or enabled"

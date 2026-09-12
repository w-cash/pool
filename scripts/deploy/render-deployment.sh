#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3
require_command systemctl

[[ $# -eq 2 || $# -eq 3 ]] \
    || die "usage: render-deployment.sh <bootstrap|finalize> <settings> [backend-authority]"
phase=$1
settings=$2
authority=${3:-}
[[ $phase == bootstrap || $phase == finalize ]] || die "phase must be bootstrap or finalize"
require_private_regular_file "$settings"
if [[ $phase == finalize ]]; then
    [[ -n $authority ]] || die "finalize requires a backend authority file"
    require_absolute_path "$authority"
    [[ -f $authority && ! -L $authority ]] || die "backend authority file is unavailable"
fi

source_root=${ZECWEC_DEPLOY_SOURCE_ROOT:-/usr/local/share/zecwec-deploy}
require_absolute_path "$source_root"
[[ -d $source_root/deploy && -d $source_root/scripts ]] || die "deployment source root is incomplete"
pool_uid=$(id -u wcash-pool)

if systemctl is-active --quiet wcash-pool.service; then
    die "wcash-pool.service must be stopped before rendering deployment state"
fi
if systemctl is-active --quiet wcash-pool-backend.service; then
    die "wcash-pool-backend.service must be stopped before rendering deployment state"
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
    --release-root /opt/wcash/current
    --output "$staging"
    --pool-uid "$pool_uid"
)
if [[ $phase == finalize ]]; then
    arguments+=(--authority "$authority")
fi
python3 "$source_root/scripts/deploy/render_deployment.py" "${arguments[@]}"

install -d -o root -g root -m 0755 "$ZECWEC_CONFIG_DIR"
install -o root -g wcash-pool-backend -m 0640 "$staging/backend.env" "$ZECWEC_CONFIG_DIR/backend.env"
install -o zecwec-zallet -g zecwec-zallet -m 0600 "$staging/zallet.toml" "$ZECWEC_CONFIG_DIR/zallet.toml"

if [[ $phase == finalize ]]; then
    install -o root -g wcash-pool -m 0640 "$staging/pool.runtime.toml" "$ZECWEC_CONFIG_DIR/pool.runtime.toml"
    install -o root -g wcash-pool -m 0640 "$staging/pool.migrate.toml" "$ZECWEC_CONFIG_DIR/pool.migrate.toml"
fi

for unit in "$staging"/systemd/*; do
    install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename -- "$unit")"
done
install -d -o root -g root -m 0755 /etc/nginx/sites-available /etc/nginx/streams-available
install -o root -g root -m 0644 "$staging/nginx/zecwec-testnet-portal.conf" \
    /etc/nginx/sites-available/zecwec-testnet-portal.conf
install -o root -g root -m 0644 "$staging/nginx/zecwec-testnet-stratum.conf" \
    /etc/nginx/streams-available/zecwec-testnet-stratum.conf

systemctl daemon-reload
log "rendered $phase Testnet configuration; no service or nginx endpoint was enabled"

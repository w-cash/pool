#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command systemctl

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
for binary in wcash-poold wcash-merge-miner wcash-wallet zallet; do
    ZECWEC_RELEASE_PATH=$target "$ZECWEC_LIBEXEC/verify-release.sh" "$binary"
done

systemctl stop wcash-pool.service wcash-pool-backend.service zecwec-zallet.service
temporary=/opt/wcash/.current.rollback.$$
trap 'rm -f -- "$temporary"' EXIT
ln -s -- "$target" "$temporary"
mv -Tf -- "$temporary" "$ZECWEC_CURRENT_RELEASE"
trap - EXIT

"$ZECWEC_LIBEXEC/render-deployment.sh" finalize "$settings" "$authority"
systemctl restart zecwec-zallet.service
systemctl restart wcash-pool-backend-init.service
systemctl restart wcash-pool-backend.service
systemctl restart wcash-pool-migrate.service
systemctl restart wcash-pool-preflight.service
if ! systemctl start wcash-pool.service; then
    systemctl stop wcash-pool.service >/dev/null 2>&1 || true
    die "rollback target failed to start; pool remains stopped"
fi
if ! "$ZECWEC_LIBEXEC/health-check.sh" --settings "$settings" --cidrs "$cidrs"; then
    systemctl stop wcash-pool.service >/dev/null 2>&1 || true
    die "rollback target failed health checks; pool remains stopped"
fi

log "rolled back to verified release $version after an explicit schema-compatibility acknowledgement"

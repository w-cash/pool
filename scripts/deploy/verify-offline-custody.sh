#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3
require_command pgrep
require_command runuser
require_command ss
require_command systemctl

[[ $# -eq 1 ]] || die "usage: verify-offline-custody.sh <settings>"
settings=$1
require_private_regular_file "$settings"
for unit in zecwec-zallet.service zecwec-zallet-recovery.service \
    wcash-pool-wallet-init.service \
    wcash-pool-zec-authority-bootstrap.service; do
    require_loaded_unit_fully_inactive "$unit"
done
require_no_processes_for_user wcash-pool "mining identity"
require_no_processes_for_user zecwec-zallet "collector identity"
require_no_processes_for_user zecwec-zallet-recovery "recovery identity"
zallet_rpc=$(read_setting "$settings" ZALLET_RPC)
for port in "${zallet_rpc##*:}" 28242; do
    if ! listener=$(ss -H -ltn "sport = :$port"); then
        die "collector RPC listener inspection failed"
    fi
    [[ -z $listener ]] || die "collector RPC listener remains active"
done
require_offline_collector_custody "$settings" "${ZECWEC_RELEASE_PATH:?immutable release path is required}"
log "offline collector custody gate passed without reading spending authority"

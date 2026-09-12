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
require_command systemctl

[[ $# -eq 1 ]] || die "usage: verify-offline-custody.sh <settings>"
settings=$1
require_private_regular_file "$settings"
for unit in zecwec-zallet.service wcash-pool-wallet-init.service \
    wcash-pool-zec-authority-bootstrap.service; do
    [[ $(systemctl show --property=ActiveState --value "$unit") == inactive \
        && $(systemctl show --property=SubState --value "$unit") == dead \
        && $(systemctl show --property=MainPID --value "$unit") == 0 \
        && $(systemctl show --property=ControlPID --value "$unit") == 0 ]] \
        || die "collector custody service is not fully inactive"
done
require_no_processes_for_user wcash-pool "mining identity"
require_no_processes_for_user zecwec-zallet "collector identity"
require_offline_collector_custody "$settings"
log "offline collector custody gate passed without reading spending authority"

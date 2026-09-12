#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command systemctl
require_command ss

[[ $# -eq 1 ]] || die "usage: preflight.sh <settings>"
settings=$1
require_private_regular_file "$settings"
[[ -f /etc/wcash-pool/pool.runtime.toml ]] || die "finalized runtime policy is missing"
[[ -f /etc/wcash-pool/pool.migrate.toml ]] || die "finalized migration policy is missing"

if systemctl is-active --quiet wcash-pool.service; then
    die "stop the public pool service before running the listener-free preflight"
fi

stratum=$(read_setting "$settings" STRATUM_LISTEN)
port=${stratum##*:}
if ss -H -ltn "sport = :$port" | grep -q .; then
    die "preflight found the public Stratum listener open before validation"
fi

systemctl stop wcash-pool-backend.service >/dev/null 2>&1 || true
systemctl restart zecwec-zallet.service
systemctl restart wcash-pool-backend-init.service
systemctl restart wcash-pool-backend.service
systemctl restart wcash-pool-migrate.service
systemctl restart wcash-pool-preflight.service

systemctl is-active --quiet zecwec-zallet.service || die "Zallet is not active"
systemctl is-active --quiet wcash-pool-backend.service || die "backend is not active"
systemctl is-active --quiet postgresql.service || die "PostgreSQL is not active"

if ss -H -ltn "sport = :$port" | grep -q .; then
    die "preflight unexpectedly found the public Stratum listener open"
fi

log "listener-free Testnet preflight passed; the pool remains stopped"

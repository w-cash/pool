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
[[ -f /etc/wcash-pool/pool.preflight.toml ]] || die "finalized preflight policy is missing"
legacy_share_journal=/var/lib/wcash-pool/share-journal-v2.jsonl
[[ ! -e $legacy_share_journal && ! -L $legacy_share_journal ]] \
    || die "legacy share journal must be reviewed and archived before protocol-v2 preflight"

trap 'systemctl stop wcash-pool.service >/dev/null 2>&1 || true' ERR
systemctl stop zecwec-cookie-refresh.path >/dev/null 2>&1 || true

if systemctl is-active --quiet wcash-pool.service; then
    systemctl stop wcash-pool.service
fi

stratum=$(read_setting "$settings" STRATUM_LISTEN)
port=${stratum##*:}
portal=$(read_setting "$settings" PORTAL_LISTEN)
portal_port=${portal##*:}
for listener in "$port" "$portal_port"; do
    if ss -H -ltn "sport = :$listener" | grep -q .; then
        die "preflight found a public-service listener open before validation"
    fi
done

zallet_rpc=$(read_setting "$settings" ZALLET_RPC)
zallet_port=${zallet_rpc##*:}
if ! systemctl is-active --quiet zecwec-zallet.service \
    && ss -H -ltn "sport = :$zallet_port" | grep -q .; then
    die "another wallet owns the reviewed Zallet RPC port; complete the manual wallet handover first"
fi

systemctl stop wcash-pool-backend.service >/dev/null 2>&1 || true
systemctl restart zecwec-zallet.service
systemctl restart wcash-pool-wallet-init.service
systemctl restart wcash-pool-backend-init.service
systemctl restart wcash-pool-backend.service
systemctl restart wcash-pool-migrate.service
systemctl restart wcash-pool-preflight.service

systemctl is-active --quiet zecwec-zallet.service || die "Zallet is not active"
systemctl is-active --quiet wcash-pool-backend.service || die "backend is not active"
systemctl is-active --quiet postgresql.service || die "PostgreSQL is not active"

for listener in "$port" "$portal_port"; do
    if ss -H -ltn "sport = :$listener" | grep -q .; then
        die "preflight unexpectedly opened a public-service listener"
    fi
done

"$script_dir/refresh-runtime-credentials.sh" snapshot "$settings"
systemctl start zecwec-cookie-refresh.path
trap - ERR

log "listener-free Testnet preflight passed; the pool remains stopped"

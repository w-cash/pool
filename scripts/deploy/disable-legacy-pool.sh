#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command systemctl

[[ $# -eq 1 ]] || die "usage: disable-legacy-pool.sh <legacy-systemd-unit>"
unit=$1
[[ $unit =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || die "legacy unit name is unsafe"
if ! unit_definition=$(systemctl cat "$unit" 2>/dev/null); then
    load_state=$(systemctl_value_strict "$unit" LoadState)
    if [[ $load_state == not-found ]]; then
        log "legacy unit does not exist: $unit"
        exit 0
    fi
    die "legacy unit definition cannot be inspected"
fi
[[ -n $unit_definition ]] || die "legacy unit definition is empty"
if grep -Fq '# Managed by the ZecWec Testnet deployment package.' \
    <<<"$unit_definition"; then
    die "refusing to archive the managed ZecWec Testnet pool unit"
fi

backup_dir=/var/backups/zecwec/legacy-pool
install -d -o root -g root -m 0700 "$backup_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$backup_dir/${unit}.${stamp}.unit"
umask 077
printf '%s\n' "$unit_definition" >"$backup"
chmod 0600 "$backup"
systemctl disable --now "$unit"
systemctl is-active --quiet "$unit" && die "legacy pool unit remained active"

fragment=$(systemctl show --property=FragmentPath --value "$unit")
if [[ $unit == wcash-pool.service && $fragment == /etc/systemd/system/wcash-pool.service ]]; then
    [[ -e $fragment || -L $fragment ]] || die "legacy unit fragment disappeared unexpectedly"
    mv -- "$fragment" "${backup}.fragment"
    [[ -L ${backup}.fragment ]] || chmod 0600 "${backup}.fragment"
    systemctl daemon-reload
fi

log "disabled $unit and retained a root-only unit backup; legacy data was not deleted"

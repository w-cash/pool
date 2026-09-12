#!/usr/bin/env bash
# Shared deployment helpers. This file must never be sourced with xtrace on.

set -Eeuo pipefail
set +x

# shellcheck disable=SC2034
readonly ZECWEC_CONFIG_DIR=/etc/wcash-pool
# shellcheck disable=SC2034
readonly ZECWEC_CREDENTIAL_DIR=/etc/wcash-pool/credentials
# shellcheck disable=SC2034
readonly ZECWEC_RELEASE_ROOT=/opt/wcash/releases
# shellcheck disable=SC2034
readonly ZECWEC_CURRENT_RELEASE=/opt/wcash/current
# shellcheck disable=SC2034
readonly ZECWEC_LIBEXEC=/usr/local/libexec/zecwec

log() {
    printf 'zecwec-deploy: %s\n' "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

require_root() {
    [[ ${EUID} -eq 0 ]] || die "this command must run as root"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

require_absolute_path() {
    local path=${1:?path is required}
    [[ $path == /* ]] || die "path must be absolute"
    [[ $path != *'/../'* && $path != *'/./'* && $path != */.. && $path != */. ]] \
        || die "path must be lexically normalized"
}

require_safe_name() {
    local value=${1:?value is required}
    local label=${2:-name}
    [[ $value =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,62}$ ]] \
        || die "$label has an unsafe representation"
}

require_private_regular_file() {
    local path=${1:?path is required}
    require_absolute_path "$path"
    [[ -f $path && ! -L $path ]] || die "protected input is not a regular file"
    local mode owner links
    mode=$(stat -c '%a' -- "$path")
    owner=$(stat -c '%u' -- "$path")
    links=$(stat -c '%h' -- "$path")
    [[ $owner == 0 && $mode == 600 && $links == 1 ]] \
        || die "protected input must be root-owned, mode 0600, with one link"
}

install_private_file() {
    local source=${1:?source is required}
    local destination=${2:?destination is required}
    local owner=${3:?owner is required}
    local group=${4:?group is required}
    require_private_regular_file "$source"
    require_absolute_path "$destination"
    install -d -o root -g root -m 0700 -- "$(dirname -- "$destination")"
    local temporary="${destination}.new.$$"
    if ! install -o "$owner" -g "$group" -m 0600 -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        die "failed to stage protected file"
    fi
    if ! mv -fT -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        die "failed to install protected file"
    fi
}

read_one_line_credential() {
    local path=${1:?credential path is required}
    local maximum=${2:-4096}
    [[ -f $path && ! -L $path ]] || die "credential is unavailable"
    local size
    size=$(stat -c '%s' -- "$path")
    ((size > 0 && size <= maximum)) || die "credential has an invalid size"
    local value extra
    IFS= read -r value <"$path" || [[ -n $value ]] || die "credential is empty"
    extra=$(tail -n +2 -- "$path")
    [[ -z $extra ]] || die "credential must contain exactly one line"
    [[ $value != *[$'\r\n\t']* ]] || die "credential contains control characters"
    printf '%s' "$value"
}

read_setting() {
    local path=${1:?settings path is required}
    local key=${2:?settings key is required}
    [[ $key =~ ^[A-Z][A-Z0-9_]*$ ]] || die "settings key is invalid"
    local count value
    count=$(awk -F= -v key="$key" '$1 == key { count += 1 } END { print count + 0 }' "$path")
    [[ $count == 1 ]] || die "settings key must occur exactly once: $key"
    value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path")
    [[ -n $value && $value != *[$'\r\n\t']* ]] || die "settings value is invalid: $key"
    printf '%s' "$value"
}

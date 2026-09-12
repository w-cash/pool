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

require_unreadable_by_user() {
    local path=${1:?path is required}
    local user=${2:?user is required}
    local label=${3:-protected path}
    require_command runuser
    [[ -e $path && ! -L $path ]] || die "$label is unavailable or unsafe"
    local result
    # $1 belongs to the deliberately isolated child shell.
    # shellcheck disable=SC2016
    if ! result=$(runuser --user "$user" -- /bin/sh -c \
        'if /usr/bin/test -r "$1"; then printf readable; else printf unreadable; fi' \
        sh "$path"); then
        die "$label access probe could not enter the mining identity"
    fi
    [[ $result == unreadable ]] || die "$label is readable by the mining identity"
}

require_exact_user_groups() {
    local user=${1:?user is required}
    local expected=${2:?expected groups are required}
    require_command id
    local actual
    actual=$(id -Gn "$user" | tr ' ' '\n' | LC_ALL=C sort | paste -sd, -) \
        || die "could not establish service identity groups"
    [[ $actual == "$expected" ]] || die "service identity has unexpected group membership"
}

require_no_processes_for_user() {
    local user=${1:?user is required}
    local label=${2:-service identity}
    require_command id
    require_command pgrep
    local uid pgrep_status
    uid=$(id -u "$user") || die "$label is unavailable"
    if pgrep -u "$uid" >/dev/null 2>&1; then
        die "$label has an active process outside the custody boundary"
    else
        pgrep_status=$?
    fi
    [[ $pgrep_status == 1 ]] || die "$label process inspection failed"
}

require_sealed_wcash_custody() {
    local seed=${1:?seed path is required}
    local authority=${2:?authority path is required}
    local attestation=${3:?attestation path is required}
    local parent
    parent=$(dirname -- "$seed")
    [[ -d $parent && ! -L $parent \
        && $(stat -c '%U:%G:%a' -- "$parent") == root:root:700 ]] \
        || die "sealed Wcash custody directory is unsafe"
    [[ -f $seed && ! -L $seed \
        && $(stat -c '%U:%G:%a:%h' -- "$seed") == root:root:400:1 ]] \
        || die "sealed Wcash seed is unsafe"
    [[ -f $attestation && ! -L $attestation \
        && $(stat -c '%U:%G:%a:%h' -- "$attestation") == root:root:400:1 ]] \
        || die "Wcash recovery attestation is unsafe"
    [[ -f $authority && ! -L $authority \
        && $(stat -c '%U:%G:%a:%h' -- "$authority") == root:root:400:1 ]] \
        || die "frozen Wcash authority is unsafe"
    require_unreadable_by_user "$parent" wcash-pool "sealed Wcash custody directory"
    require_unreadable_by_user "$seed" wcash-pool "sealed Wcash seed"
    require_unreadable_by_user "$authority" wcash-pool "frozen Wcash authority"
    python3 "$(dirname -- "${BASH_SOURCE[0]}")/verify-wcash-wallet-recovery.py" \
        verify "$authority" "$attestation"
}

require_offline_collector_custody() {
    local settings=${1:?settings path is required}
    local wcash_seed wcash_authority wcash_recovery_attestation
    local zallet_state zallet_config
    require_exact_user_groups wcash-pool wcash-pool,wcash-pool-socket
    require_exact_user_groups wcash-pool-backend wcash-pool-socket
    require_exact_user_groups zecwec-zallet zecwec-zallet
    wcash_seed=$(read_setting "$settings" WEC_SEED_FILE)
    wcash_authority=/var/lib/wcash-pool/wcash-wallet-authority.json
    wcash_recovery_attestation=/var/lib/wcash-pool-secrets/wcash-wallet-recovery.attestation
    require_sealed_wcash_custody \
        "$wcash_seed" "$wcash_authority" "$wcash_recovery_attestation"
    zallet_state=$(read_setting "$settings" ZALLET_STATE_DIR)
    zallet_config=$(read_setting "$settings" ZALLET_CONFIG_FILE)
    [[ $zallet_state == /var/lib/zecwec-zallet && -d $zallet_state && ! -L $zallet_state \
        && $(stat -c '%U:%G:%a' -- "$zallet_state") == zecwec-zallet:zecwec-zallet:700 ]] \
        || die "offline Zallet state directory is unsafe"
    [[ $zallet_config == /etc/wcash-pool/zallet.toml \
        && -f $zallet_config && ! -L $zallet_config \
        && $(stat -c '%U:%G:%a:%h' -- "$zallet_config") == zecwec-zallet:zecwec-zallet:600:1 ]] \
        || die "offline Zallet configuration is unsafe"
    require_unreadable_by_user "$zallet_state" wcash-pool "offline Zallet state"
    require_unreadable_by_user "$zallet_config" wcash-pool "offline Zallet configuration"
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

resolve_release_root() {
    local candidate=${1:-$ZECWEC_CURRENT_RELEASE}
    require_absolute_path "$candidate"
    [[ -e $candidate || -L $candidate ]] || die "selected release is unavailable"
    local resolved
    resolved=$(realpath -e -- "$candidate")
    [[ $resolved =~ ^/opt/wcash/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ \
        && -d $resolved && ! -L $resolved ]] \
        || die "selected release is not one canonical immutable version directory"
    printf '%s' "$resolved"
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

require_trusted_etc_file() {
    local path=${1:?path is required}
    local private=${2:-false}
    require_absolute_path "$path"
    [[ $path == /etc/* && -f $path ]] || die "trusted file must resolve below /etc"
    local resolved
    resolved=$(realpath -e -- "$path")
    [[ $resolved == /etc/* && -f $resolved && ! -L $resolved ]] \
        || die "trusted file resolves outside /etc or is not regular"
    local owner mode links forbidden
    owner=$(stat -Lc '%u' -- "$path")
    mode=$(stat -Lc '%a' -- "$path")
    links=$(stat -Lc '%h' -- "$path")
    forbidden=022
    $private && forbidden=077
    [[ $owner == 0 && $links == 1 && $mode =~ ^[0-7]{3,4}$ \
        && $((8#$mode & 8#$forbidden)) -eq 0 ]] \
        || die "trusted file ownership, mode, or link count is unsafe"
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

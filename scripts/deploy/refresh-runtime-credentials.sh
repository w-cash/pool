#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command sha256sum
require_command systemctl

[[ $# -eq 2 ]] \
    || die "usage: refresh-runtime-credentials.sh <snapshot|reconcile> <settings>"
mode=$1
settings=$2
[[ $mode == snapshot || $mode == reconcile ]] || die "credential refresh mode is invalid"
require_private_regular_file "$settings"

state_directory=/var/lib/zecwec-cookie-refresh
state_file="$state_directory/cookie-digests"
install -d -o root -g root -m 0700 -- "$state_directory"

declare -A cookie_paths=()
cookie_paths[WCASH_RPC_COOKIE]=$(read_setting "$settings" WCASH_RPC_COOKIE_SOURCE)
cookie_paths[ZCASH_TEMPLATE_COOKIE]=$(read_setting "$settings" ZCASH_TEMPLATE_COOKIE_SOURCE)
cookie_paths[ZCASH_VALIDATOR_COOKIE]=$(read_setting "$settings" ZCASH_VALIDATOR_COOKIE_SOURCE)
zallet_state=$(read_setting "$settings" ZALLET_STATE_DIR)
cookie_paths[ZALLET_COOKIE]="$zallet_state/.cookie"

cookie_names=(
    WCASH_RPC_COOKIE
    ZCASH_TEMPLATE_COOKIE
    ZCASH_VALIDATOR_COOKIE
    ZALLET_COOKIE
)

validate_cookie() {
    local path=${1:?cookie path is required}
    require_absolute_path "$path"
    [[ -f $path && ! -L $path && $(realpath -e -- "$path") == "$path" ]] \
        || return 1
    [[ $(stat -c '%a:%h' -- "$path") == 600:1 ]] || return 1
    local size cookie extra
    size=$(stat -c '%s' -- "$path")
    ((size > 2 && size <= 4096)) || return 1
    IFS= read -r cookie <"$path" || [[ -n $cookie ]] || return 1
    extra=$(tail -n +2 -- "$path")
    [[ -z $extra && $cookie == *:* && ${cookie%%:*} != '' && ${cookie#*:} != '' \
        && $cookie != *[$'\r\n\t ']* ]]
}

wait_for_cookies() {
    local attempt name valid
    for ((attempt = 0; attempt < 30; attempt += 1)); do
        valid=true
        for name in "${cookie_names[@]}"; do
            if ! validate_cookie "${cookie_paths[$name]}"; then
                valid=false
                break
            fi
        done
        $valid && return 0
        sleep 1
    done
    die "rotating RPC credentials did not become ready"
}

cookie_digest() {
    local path=${1:?cookie path is required}
    sha256sum -- "$path" | awk '{print $1}'
}

declare -A current=()
read_current() {
    local name
    wait_for_cookies
    for name in "${cookie_names[@]}"; do
        current[$name]=$(cookie_digest "${cookie_paths[$name]}")
    done
}

write_snapshot() {
    local temporary="${state_file}.new.$$" name
    trap 'rm -f -- "$temporary"' RETURN
    : >"$temporary"
    chmod 0600 -- "$temporary"
    for name in "${cookie_names[@]}"; do
        printf '%s=%s\n' "$name" "${current[$name]}" >>"$temporary"
    done
    mv -fT -- "$temporary" "$state_file"
    trap - RETURN
}

read_current
if [[ $mode == snapshot ]]; then
    write_snapshot
    log "recorded current RPC credential generations without exposing their contents"
    exit 0
fi

declare -A previous=()
if [[ -e $state_file || -L $state_file ]]; then
    require_private_regular_file "$state_file"
    for name in "${cookie_names[@]}"; do
        previous[$name]=$(read_setting "$state_file" "$name")
        [[ ${previous[$name]} =~ ^[0-9a-f]{64}$ ]] \
            || die "stored credential generation state is invalid"
    done
fi

wcash_changed=false
template_changed=false
validator_changed=false
zallet_changed=false
[[ ${previous[WCASH_RPC_COOKIE]:-} == "${current[WCASH_RPC_COOKIE]}" ]] \
    || wcash_changed=true
[[ ${previous[ZCASH_TEMPLATE_COOKIE]:-} == "${current[ZCASH_TEMPLATE_COOKIE]}" ]] \
    || template_changed=true
[[ ${previous[ZCASH_VALIDATOR_COOKIE]:-} == "${current[ZCASH_VALIDATOR_COOKIE]}" ]] \
    || validator_changed=true
[[ ${previous[ZALLET_COOKIE]:-} == "${current[ZALLET_COOKIE]}" ]] \
    || zallet_changed=true

if ! $wcash_changed && ! $template_changed && ! $validator_changed && ! $zallet_changed; then
    exit 0
fi

pool_should_run=false
if systemctl is-active --quiet zecwec-testnet-pool.target \
    || systemctl is-active --quiet wcash-pool.service; then
    pool_should_run=true
fi
systemctl stop wcash-pool.service >/dev/null 2>&1 || true

if $validator_changed && systemctl is-active --quiet zecwec-zallet.service; then
    systemctl restart zecwec-zallet.service
fi

if $wcash_changed || $template_changed || $validator_changed; then
    if systemctl is-active --quiet wcash-pool-backend.service || $pool_should_run; then
        systemctl stop wcash-pool-backend.service >/dev/null 2>&1 || true
        systemctl restart wcash-pool-backend-init.service
        systemctl start wcash-pool-backend.service
    fi
fi

# Zallet can rotate its own cookie while refreshing the validator credential.
# Prove every source is stable before a pool process snapshots it.
declare -A before_pool=()
read_current
for name in "${cookie_names[@]}"; do
    before_pool[$name]=${current[$name]}
done
sleep 1
read_current
for name in "${cookie_names[@]}"; do
    if [[ ${before_pool[$name]} != "${current[$name]}" ]]; then
        systemctl stop wcash-pool.service >/dev/null 2>&1 || true
        die "an RPC credential rotated during refresh; the public pool remains stopped"
    fi
done

if $pool_should_run; then
    systemctl start wcash-pool.service
    read_current
    for name in "${cookie_names[@]}"; do
        if [[ ${before_pool[$name]} != "${current[$name]}" ]]; then
            systemctl stop wcash-pool.service >/dev/null 2>&1 || true
            die "an RPC credential rotated during pool startup; the public pool was stopped"
        fi
    done
fi

write_snapshot
log "refreshed affected systemd credential snapshots without exposing credentials"

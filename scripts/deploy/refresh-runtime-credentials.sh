#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command python3
require_command sha256sum
require_command systemctl

[[ $# -eq 2 ]] \
    || die "usage: refresh-runtime-credentials.sh <snapshot|reconcile> <settings>"
mode=$1
settings=$2
[[ $mode == snapshot || $mode == reconcile ]] || die "credential refresh mode is invalid"
require_private_regular_file "$settings"
cidrs=/etc/wcash-pool/miner-cidrs

state_directory=/var/lib/zecwec-cookie-refresh
state_file="$state_directory/cookie-digests"
install -d -o root -g root -m 0700 -- "$state_directory"

declare -A cookie_paths=()
cookie_paths[WCASH_RPC_COOKIE]=$(read_setting "$settings" WCASH_RPC_COOKIE_SOURCE)
cookie_paths[ZCASH_TEMPLATE_COOKIE]=$(read_setting "$settings" ZCASH_TEMPLATE_COOKIE_SOURCE)
cookie_paths[ZCASH_VALIDATOR_COOKIE]=$(read_setting "$settings" ZCASH_VALIDATOR_COOKIE_SOURCE)

cookie_names=(
    WCASH_RPC_COOKIE
    ZCASH_TEMPLATE_COOKIE
    ZCASH_VALIDATOR_COOKIE
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

refresh_completed=false
target_was_active=false
refresh_failed() {
    local status=$?
    trap - ERR
    trap - EXIT
    if ! $refresh_completed; then
        stop_testnet_runtime_after_failure "$settings" "$cidrs"
    fi
    exit "$status"
}
if [[ $mode == reconcile ]]; then
    systemctl is-active --quiet zecwec-testnet-pool.target && target_was_active=true
    # A path-triggered rotation can observe a cookie between unlink and rename.
    # Close ingress before waiting or parsing any state, and make explicit exits
    # as well as command failures stop the stale-credential runtime.
    trap refresh_failed ERR
    trap refresh_failed EXIT
    "$script_dir/restrict-mining-firewall.sh" close "$settings" "$cidrs"
fi

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
[[ ${previous[WCASH_RPC_COOKIE]:-} == "${current[WCASH_RPC_COOKIE]}" ]] \
    || wcash_changed=true
[[ ${previous[ZCASH_TEMPLATE_COOKIE]:-} == "${current[ZCASH_TEMPLATE_COOKIE]}" ]] \
    || template_changed=true
[[ ${previous[ZCASH_VALIDATOR_COOKIE]:-} == "${current[ZCASH_VALIDATOR_COOKIE]}" ]] \
    || validator_changed=true

if ! $wcash_changed && ! $template_changed && ! $validator_changed; then
    if $target_was_active; then
        portal=$(read_setting "$settings" PORTAL_LISTEN)
        python3 "$script_dir/wait_payout_ready.py" "http://$portal/readyz" 4200
        "$script_dir/restrict-mining-firewall.sh" apply "$settings" "$cidrs"
        "$script_dir/enable-nginx-edge.sh" reconcile "$settings" "$cidrs"
        "$script_dir/health-check.sh" --settings "$settings" --cidrs "$cidrs"
    fi
    refresh_completed=true
    trap - ERR
    trap - EXIT
    exit 0
fi

target_should_run=false
if systemctl is-active --quiet zecwec-testnet-pool.target; then
    target_should_run=true
fi
pool_should_run=$target_should_run
if systemctl is-active --quiet wcash-pool.service; then
    pool_should_run=true
fi
projector_should_run=$target_should_run
if systemctl is-active --quiet wcash-pool-projector.service; then
    projector_should_run=true
fi
payout_should_run=$target_should_run
if systemctl is-active --quiet wcash-payout-worker.service; then
    payout_should_run=true
fi
zallet_should_run=$target_should_run
if systemctl is-active --quiet zecwec-zallet-payout.service; then
    zallet_should_run=true
fi

# An active target upholds the payout services. Stop it first so systemd does
# not race the credential refresh by immediately reviving a stopped worker.
if $target_should_run || $pool_should_run || $payout_should_run; then
    "$script_dir/restrict-mining-firewall.sh" close "$settings" "$cidrs"
fi
if $target_should_run; then
    systemctl stop wcash-pool-health.timer >/dev/null 2>&1 || true
    systemctl stop zecwec-testnet-pool.target >/dev/null 2>&1 || true
fi
systemctl stop wcash-payout-worker.service zecwec-zallet-payout.service \
    wcash-pool.service wcash-pool-projector.service >/dev/null 2>&1 || true

if $wcash_changed || $template_changed || $validator_changed; then
    if systemctl is-active --quiet wcash-pool-backend.service || $pool_should_run; then
        systemctl stop wcash-pool-backend.service >/dev/null 2>&1 || true
        systemctl restart wcash-pool-backend-init.service
        systemctl start wcash-pool-backend.service
    fi
fi

# Prove every node source is stable before a pool process snapshots it.
declare -A before_pool=()
read_current
for name in "${cookie_names[@]}"; do
    before_pool[$name]=${current[$name]}
done
sleep 1
read_current
for name in "${cookie_names[@]}"; do
    if [[ ${before_pool[$name]} != "${current[$name]}" ]]; then
        stop_testnet_runtime_after_failure "$settings" "$cidrs"
        die "an RPC credential rotated during refresh; the public pool remains stopped"
    fi
done

if $projector_should_run; then
    systemctl start wcash-pool-projector.service
fi
if $pool_should_run; then
    systemctl start wcash-pool.service
    read_current
    for name in "${cookie_names[@]}"; do
        if [[ ${before_pool[$name]} != "${current[$name]}" ]]; then
            stop_testnet_runtime_after_failure "$settings" "$cidrs"
            die "an RPC credential rotated during pool startup; the public pool was stopped"
        fi
    done
fi
if $zallet_should_run; then
    systemctl start zecwec-zallet-payout.service
fi
if $payout_should_run; then
    systemctl start wcash-payout-worker.service
fi
if $target_should_run; then
    systemctl start zecwec-testnet-pool.target
    portal=$(read_setting "$settings" PORTAL_LISTEN)
    python3 "$script_dir/wait_payout_ready.py" "http://$portal/readyz" 4200
    "$script_dir/restrict-mining-firewall.sh" apply "$settings" "$cidrs"
    "$script_dir/enable-nginx-edge.sh" reconcile "$settings" "$cidrs"
    "$script_dir/health-check.sh" --settings "$settings" \
        --cidrs "$cidrs"
fi

read_current
for name in "${cookie_names[@]}"; do
    if [[ ${before_pool[$name]} != "${current[$name]}" ]]; then
        stop_testnet_runtime_after_failure "$settings" "$cidrs"
        die "an RPC credential rotated during service startup; public and payout services were stopped"
    fi
done

write_snapshot
if $target_should_run; then
    systemctl start wcash-pool-health.timer
fi
refresh_completed=true
trap - ERR
trap - EXIT
log "refreshed affected systemd credential snapshots without exposing credentials"

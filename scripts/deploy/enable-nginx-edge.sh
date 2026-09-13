#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command nginx
require_command readlink
require_command systemctl

[[ $# -eq 3 || $# -eq 4 ]] \
    || die "usage: enable-nginx-edge.sh <stratum-only|stage-portal|publish-portal|reconcile> <settings> <miner-cidr-file> [acknowledgement]"
mode=$1
settings=$2
cidrs=$3
case "$mode" in
    stratum-only)
        [[ $# -eq 3 ]] || die "stratum-only does not accept a launch acknowledgement"
        ;;
    stage-portal)
        [[ $# -eq 4 && $4 == --ack-cloudflare-access ]] \
            || die "private portal staging requires --ack-cloudflare-access"
        ;;
    publish-portal)
        [[ $# -eq 4 && $4 == --ack-e2e-gates ]] \
            || die "portal publication requires --ack-e2e-gates"
        ;;
    reconcile)
        [[ $# -eq 3 ]] || die "edge reconciliation does not accept a launch acknowledgement"
        ;;
    *) die "edge mode must be stratum-only, stage-portal, publish-portal, or reconcile" ;;
esac
require_private_regular_file "$settings"
require_private_regular_file "$cidrs"
"$script_dir/restrict-mining-firewall.sh" check "$settings" "$cidrs"

portal_source=/etc/nginx/sites-available/zecwec-testnet-portal.conf
portal_link=/etc/nginx/sites-enabled/zecwec-testnet-portal.conf
portal_state=/etc/wcash-pool/portal-edge-mode
stream_source=/etc/nginx/streams-available/zecwec-testnet-stratum.conf
stream_link=/etc/nginx/modules-enabled/99-zecwec-testnet-stream.conf
if [[ -e $portal_state || -L $portal_state ]]; then
    require_trusted_etc_file "$portal_state" false
fi
for binding in "$portal_link:$portal_source" "$stream_link:$stream_source"; do
    link=${binding%%:*}
    source=${binding#*:}
    if [[ -e $link || -L $link ]]; then
        [[ -L $link && $(readlink -- "$link") == "$source" ]] \
            || die "refusing an unexpected nginx edge binding: $link"
    fi
done

disable_managed_portal() {
    rm -f -- "$portal_link" "$portal_state"
    if ! nginx -t >/dev/null 2>&1 \
        || ! systemctl reload nginx.service >/dev/null 2>&1; then
        systemctl stop nginx.service >/dev/null 2>&1 || true
    fi
}

persist_portal_mode() {
    local launch_mode=${1:?portal launch mode is required}
    local state_staging
    state_staging=$(mktemp /etc/wcash-pool/.portal-edge-mode.XXXXXX)
    trap 'rm -f -- "$state_staging"' RETURN
    printf '%s\n' "$launch_mode" >"$state_staging"
    chown root:root "$state_staging"
    chmod 0644 "$state_staging"
    mv -T -- "$state_staging" "$portal_state"
    trap - RETURN
}

effective_mode=$mode
if [[ $mode == reconcile ]]; then
    if [[ -e $portal_link || -L $portal_link ]]; then
        if [[ ! -e $portal_state || -L $portal_state ]]; then
            disable_managed_portal
            die "disabled an enabled Testnet portal with no durable launch mode"
        fi
        effective_mode=$(cat -- "$portal_state")
        if [[ $effective_mode != stage-portal && $effective_mode != publish-portal ]]; then
            disable_managed_portal
            die "disabled a Testnet portal with an invalid durable launch mode"
        fi
    else
        if [[ -e $portal_state || -L $portal_state ]]; then
            rm -f -- "$portal_state"
            die "removed a stale launch mode for a disabled Testnet portal"
        fi
        effective_mode=stratum-only
    fi
fi

certificate_keys=(MINING_TLS_CERT MINING_TLS_KEY)
if [[ $effective_mode != stratum-only ]]; then
    certificate_keys+=(
        APEX_TLS_CERT
        APEX_TLS_KEY
        PORTAL_TLS_CERT
        PORTAL_TLS_KEY
        CLOUDFLARE_ORIGIN_PULL_CA
    )
fi
for key in "${certificate_keys[@]}"; do
    path=$(read_setting "$settings" "$key")
    private=false
    [[ $key == *_KEY ]] && private=true
    require_trusted_etc_file "$path" "$private"
done

[[ -f $portal_source && ! -L $portal_source ]] || die "rendered portal nginx config is missing"
[[ -f $stream_source && ! -L $stream_source ]] || die "rendered Stratum nginx config is missing"
install -d -o root -g root -m 0755 /etc/nginx/sites-enabled /etc/nginx/modules-enabled
if [[ $effective_mode != stratum-only ]]; then
    require_command curl
    "$script_dir/health-check.sh" --quiet --settings "$settings" --cidrs "$cidrs"
fi

created_stream=false
if [[ $mode == stratum-only && (-e $portal_link || -L $portal_link) ]]; then
    die "the Testnet portal is already enabled; use a portal mode only after its gate"
fi
if [[ $mode == stratum-only && (-e $portal_state || -L $portal_state) ]]; then
    die "the Testnet portal launch mode exists while its site is disabled"
fi
if [[ $mode == stage-portal && (-e $portal_link || -L $portal_link) ]]; then
    die "private portal staging requires a currently disabled portal"
fi
if [[ $mode == stage-portal && (-e $portal_state || -L $portal_state) ]]; then
    die "private portal staging requires no prior launch mode"
fi
if [[ $mode == publish-portal \
    && ! -e $portal_link && ! -L $portal_link \
    && (-e $portal_state || -L $portal_state) ]]; then
    die "portal publication found a stale launch mode"
fi
if [[ $mode == stage-portal || $mode == publish-portal ]]; then
    # Persist the acknowledged intent before enabling nginx. A crash can leave
    # a harmless stale state with no link, but never a live portal with no
    # durable mode for the boot reconciler to verify.
    persist_portal_mode "$mode"
fi
if [[ $mode != stratum-only && $mode != reconcile \
    && ! -e $portal_link && ! -L $portal_link ]]; then
    ln -s -- "$portal_source" "$portal_link"
fi
if [[ ! -e $stream_link && ! -L $stream_link ]]; then
    ln -s -- "$stream_source" "$stream_link"
    created_stream=true
fi

if ! nginx -t; then
    if [[ $effective_mode != stratum-only ]]; then
        disable_managed_portal
    fi
    $created_stream && rm -f -- "$stream_link"
    die "nginx rejected the edge configuration; newly created links were removed"
fi
if ! systemctl reload nginx.service; then
    if [[ $effective_mode != stratum-only ]]; then
        disable_managed_portal
    fi
    $created_stream && rm -f -- "$stream_link"
    die "nginx reload failed; newly created links were removed"
fi
if [[ $effective_mode != stratum-only ]]; then
    portal_host=$(read_setting "$settings" PORTAL_HOST)
    if ! require_direct_origin_mtls_rejection "$portal_host" 127.0.0.1; then
        disable_managed_portal
        die "the portal origin did not prove Cloudflare client authentication"
    fi
fi
if [[ $effective_mode == stage-portal ]]; then
    # Cloudflare Access must deny an anonymous client while an operator tests
    # the real HTTPS origin, Secure cookies, and __Host cookie boundary.
    if ! access_status=$(curl --silent --show-error --max-time 15 \
        --output /dev/null --write-out '%{http_code}' \
        "https://$portal_host/healthz"); then
        disable_managed_portal
        die "the Cloudflare Access staging probe could not reach the portal hostname"
    fi
    case "$access_status" in
        301 | 302 | 303 | 307 | 308 | 401 | 403) ;;
        *)
            disable_managed_portal
            die "Cloudflare Access did not deny the anonymous staging probe"
            ;;
    esac
    log "enabled the Testnet portal behind a proven Cloudflare Access gate for private HTTPS E2E testing"
elif [[ $effective_mode == publish-portal ]]; then
    if ! public_probe=$(curl --silent --show-error --max-time 15 \
        --write-out $'\n%{http_code}' "https://$portal_host/healthz"); then
        disable_managed_portal
        die "the Cloudflare Authenticated Origin Pull path did not pass its public health probe"
    fi
    public_status=${public_probe##*$'\n'}
    public_body=${public_probe%$'\n'*}
    if [[ $public_status != 200 || $public_body != '{"status":"ok"}' ]]; then
        disable_managed_portal
        die "the public portal did not return the exact expected health response"
    fi
    log "enabled the public Testnet portal after explicit E2E acknowledgement"
else
    log "enabled only the source-restricted TLS Stratum edge; the public portal remains disabled"
fi

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
    || die "usage: enable-nginx-edge.sh <stratum-only|stage-portal|publish-portal> <settings> <miner-cidr-file> [acknowledgement]"
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
    *) die "edge mode must be stratum-only, stage-portal, or publish-portal" ;;
esac
require_private_regular_file "$settings"
require_private_regular_file "$cidrs"
"$script_dir/restrict-mining-firewall.sh" check "$settings" "$cidrs"

certificate_keys=(MINING_TLS_CERT MINING_TLS_KEY)
if [[ $mode != stratum-only ]]; then
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

portal_source=/etc/nginx/sites-available/zecwec-testnet-portal.conf
portal_link=/etc/nginx/sites-enabled/zecwec-testnet-portal.conf
stream_source=/etc/nginx/streams-available/zecwec-testnet-stratum.conf
stream_link=/etc/nginx/modules-enabled/99-zecwec-testnet-stream.conf
[[ -f $portal_source && ! -L $portal_source ]] || die "rendered portal nginx config is missing"
[[ -f $stream_source && ! -L $stream_source ]] || die "rendered Stratum nginx config is missing"
install -d -o root -g root -m 0755 /etc/nginx/sites-enabled /etc/nginx/modules-enabled

for binding in "$portal_link:$portal_source" "$stream_link:$stream_source"; do
    link=${binding%%:*}
    source=${binding#*:}
    if [[ -e $link || -L $link ]]; then
        [[ -L $link && $(readlink -- "$link") == "$source" ]] \
            || die "refusing an unexpected nginx edge binding: $link"
    fi
done
if [[ $mode != stratum-only ]]; then
    require_command curl
    "$script_dir/health-check.sh" --quiet --settings "$settings" --cidrs "$cidrs"
fi

created_portal=false
created_stream=false
if [[ $mode == stratum-only && (-e $portal_link || -L $portal_link) ]]; then
    die "the Testnet portal is already enabled; use a portal mode only after its gate"
fi
if [[ $mode == stage-portal && (-e $portal_link || -L $portal_link) ]]; then
    die "private portal staging requires a currently disabled portal"
fi
if [[ $mode != stratum-only && ! -e $portal_link && ! -L $portal_link ]]; then
    ln -s -- "$portal_source" "$portal_link"
    created_portal=true
fi
if [[ ! -e $stream_link && ! -L $stream_link ]]; then
    ln -s -- "$stream_source" "$stream_link"
    created_stream=true
fi

if ! nginx -t; then
    $created_portal && rm -f -- "$portal_link"
    $created_stream && rm -f -- "$stream_link"
    die "nginx rejected the edge configuration; newly created links were removed"
fi
if ! systemctl reload nginx.service; then
    $created_portal && rm -f -- "$portal_link"
    $created_stream && rm -f -- "$stream_link"
    die "nginx reload failed; newly created links were removed"
fi
if [[ $mode != stratum-only ]]; then
    portal_host=$(read_setting "$settings" PORTAL_HOST)
    if curl --fail --silent --show-error --max-time 10 --noproxy '*' \
        --header 'CF-Connecting-IP: 192.0.2.1' \
        --resolve "$portal_host:443:127.0.0.1" \
        "https://$portal_host/healthz" >/dev/null 2>&1; then
        rm -f -- "$portal_link"
        nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1 || true
        die "the portal origin accepted a request without Cloudflare client authentication"
    fi
fi
if [[ $mode == stage-portal ]]; then
    # Cloudflare Access must deny an anonymous client while an operator tests
    # the real HTTPS origin, Secure cookies, and __Host cookie boundary.
    if ! access_status=$(curl --silent --show-error --max-time 15 \
        --output /dev/null --write-out '%{http_code}' \
        "https://$portal_host/healthz"); then
        rm -f -- "$portal_link"
        nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1 || true
        die "the Cloudflare Access staging probe could not reach the portal hostname"
    fi
    case "$access_status" in
        301 | 302 | 303 | 307 | 308 | 401 | 403) ;;
        *)
            rm -f -- "$portal_link"
            nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1 || true
            die "Cloudflare Access did not deny the anonymous staging probe"
            ;;
    esac
    log "enabled the Testnet portal behind a proven Cloudflare Access gate for private HTTPS E2E testing"
elif [[ $mode == publish-portal ]]; then
    if ! public_probe=$(curl --silent --show-error --max-time 15 \
        --write-out $'\n%{http_code}' "https://$portal_host/healthz"); then
        rm -f -- "$portal_link"
        nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1 || true
        die "the Cloudflare Authenticated Origin Pull path did not pass its public health probe"
    fi
    public_status=${public_probe##*$'\n'}
    public_body=${public_probe%$'\n'*}
    if [[ $public_status != 200 || $public_body != '{"status":"ok"}' ]]; then
        rm -f -- "$portal_link"
        nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1 || true
        die "the public portal did not return the exact expected health response"
    fi
    log "enabled the public Testnet portal after explicit E2E acknowledgement"
else
    log "enabled only the source-restricted TLS Stratum edge; the public portal remains disabled"
fi

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
    || die "usage: enable-nginx-edge.sh <stratum-only|publish-portal> <settings> <miner-cidr-file> [--ack-e2e-gates]"
mode=$1
settings=$2
cidrs=$3
case "$mode" in
    stratum-only)
        [[ $# -eq 3 ]] || die "stratum-only does not accept a launch acknowledgement"
        ;;
    publish-portal)
        [[ $# -eq 4 && $4 == --ack-e2e-gates ]] \
            || die "portal publication requires --ack-e2e-gates"
        ;;
    *) die "edge mode must be stratum-only or publish-portal" ;;
esac
require_private_regular_file "$settings"
require_private_regular_file "$cidrs"
"$ZECWEC_LIBEXEC/restrict-mining-firewall.sh" check "$settings" "$cidrs"

certificate_keys=(MINING_TLS_CERT MINING_TLS_KEY)
if [[ $mode == publish-portal ]]; then
    certificate_keys+=(APEX_TLS_CERT APEX_TLS_KEY PORTAL_TLS_CERT PORTAL_TLS_KEY)
fi
for key in "${certificate_keys[@]}"; do
    path=$(read_setting "$settings" "$key")
    require_absolute_path "$path"
    [[ -f $path && ! -L $path ]] || die "TLS material is unavailable: $key"
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
if [[ $mode == publish-portal ]]; then
    "$ZECWEC_LIBEXEC/health-check.sh" --quiet --settings "$settings" --cidrs "$cidrs"
fi

created_portal=false
created_stream=false
if [[ $mode == stratum-only && (-e $portal_link || -L $portal_link) ]]; then
    die "public Testnet portal is already enabled; use publish-portal only after the E2E gate"
fi
if [[ $mode == publish-portal && ! -e $portal_link && ! -L $portal_link ]]; then
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
if [[ $mode == publish-portal ]]; then
    log "enabled the public Testnet portal after explicit E2E acknowledgement"
else
    log "enabled only the source-restricted TLS Stratum edge; the public portal remains disabled"
fi

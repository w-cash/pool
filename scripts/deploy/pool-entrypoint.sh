#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

[[ $# -eq 1 ]] || die "usage: pool-entrypoint.sh <preflight|serve|payout>"
mode=$1
case "$mode" in
    preflight)
        config=/etc/wcash-pool/pool.preflight.toml
        expected_credentials=/run/credentials/wcash-pool-preflight.service
        ;;
    serve)
        config=/etc/wcash-pool/pool.runtime.toml
        expected_credentials=/run/credentials/wcash-pool.service
        ;;
    payout)
        config=/etc/wcash-pool/pool.payout.toml
        expected_credentials=/run/credentials/wcash-payout-worker.service
        ;;
    *)
        die "unsupported pool entrypoint mode"
        ;;
esac

release_root=$(resolve_release_root "${ZECWEC_RELEASE_PATH:?immutable release path is required}")
credential_directory=${CREDENTIALS_DIRECTORY:-}
[[ $credential_directory == "$expected_credentials" \
    && -d $credential_directory && ! -L $credential_directory ]] \
    || die "pool credential directory is unavailable"

# Keep every credential-reading operation under one systemd main process.
# Ubuntu systemd 249 can retire the LoadCredential mount between separate
# startup commands, even though the unit is still activating.
if [[ $mode == payout ]]; then
    "$release_root/wcash-poold" payout-config-check --config "$config"
    exec "$release_root/wcash-poold" payout-worker --config "$config"
fi

"$release_root/wcash-poold" config-check --config "$config"
if [[ $mode == preflight ]]; then
    exec "$release_root/wcash-poold" preflight --config "$config"
fi

"$release_root/wcash-poold" preflight --config "$config"
exec "$release_root/wcash-poold" serve --config "$config"

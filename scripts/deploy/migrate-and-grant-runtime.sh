#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

[[ $# -eq 4 ]] \
    || die "usage: migrate-and-grant-runtime.sh <migrator-role> <public-role> <projector-role> <payout-role>"
require_command realpath

release_root=$(resolve_release_root "${ZECWEC_RELEASE_PATH:?immutable release path is required}")
credential_directory=${CREDENTIALS_DIRECTORY:-}
[[ $credential_directory == /run/credentials/wcash-pool-migrate.service \
    && -d $credential_directory && ! -L $credential_directory ]] \
    || die "migration credential directory is unavailable"
database_url=$credential_directory/database-url
[[ -f $database_url && ! -L $database_url ]] \
    || die "migrator URL is unavailable"

# Keep both operations in this main service process. systemd 249 can retire a
# LoadCredential mount before a separate post-start process is launched.
"$release_root/wcash-poold" migrate --config /etc/wcash-pool/pool.migrate.toml
"$release_root/deployment/scripts/deploy/grant-runtime.sh" \
    "$database_url" "$@"

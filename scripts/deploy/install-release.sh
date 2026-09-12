#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command sha256sum

[[ $# -eq 2 ]] || die "usage: install-release.sh <version> <release-directory>"
version=$1
source_dir=$2
[[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid release version"
require_absolute_path "$source_dir"
[[ -d $source_dir && ! -L $source_dir ]] || die "release source must be a real directory"

allowed=(wcash-poold wcash-merge-miner wcash-wallet zallet)
manifest="$source_dir/SHA256SUMS"
[[ -f $manifest && ! -L $manifest ]] || die "SHA256SUMS is required"
[[ $(wc -l <"$manifest") -eq ${#allowed[@]} ]] || die "manifest must contain exactly four entries"

for binary in "${allowed[@]}"; do
    [[ -f $source_dir/$binary && ! -L $source_dir/$binary && -x $source_dir/$binary ]] \
        || die "missing executable release artifact: $binary"
    count=$(awk -v name="$binary" '$2 == name { count += 1 } END { print count + 0 }' "$manifest")
    [[ $count == 1 ]] || die "manifest must contain exactly one entry for $binary"
done

if awk 'NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || $2 !~ /^[A-Za-z0-9._-]+$/ { exit 1 }' "$manifest"; then
    :
else
    die "manifest syntax is invalid"
fi
(
    cd -- "$source_dir"
    sha256sum --strict --check --status SHA256SUMS
) || die "release source digest check failed"

install -d -o root -g root -m 0755 /opt/wcash "$ZECWEC_RELEASE_ROOT"
destination="$ZECWEC_RELEASE_ROOT/$version"
if [[ -e $destination ]]; then
    ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" wcash-poold
    ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" wcash-merge-miner
    ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" wcash-wallet
    ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" zallet
    log "release $version is already installed and verified"
    exit 0
fi

temporary="$ZECWEC_RELEASE_ROOT/.${version}.new.$$"
trap 'rm -rf -- "$temporary"' EXIT
install -d -o root -g root -m 0755 -- "$temporary"
for binary in "${allowed[@]}"; do
    install -o root -g root -m 0555 -- "$source_dir/$binary" "$temporary/$binary"
done
install -o root -g root -m 0444 -- "$manifest" "$temporary/SHA256SUMS"
mv -- "$temporary" "$destination"
trap - EXIT

for binary in "${allowed[@]}"; do
    ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" "$binary"
done

if [[ ! -e $ZECWEC_CURRENT_RELEASE ]]; then
    ln -s -- "$destination" /opt/wcash/current.new
    mv -T -- /opt/wcash/current.new "$ZECWEC_CURRENT_RELEASE"
    log "installed and selected initial release $version; no service was started"
else
    log "installed release $version without changing the active release"
fi

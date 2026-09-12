#!/usr/bin/env bash

set -Eeuo pipefail
set +x

readonly release_root=${ZECWEC_RELEASE_PATH:-/opt/wcash/current}
readonly manifest="$release_root/SHA256SUMS"

die() {
    printf 'verify-release: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die "usage: verify-release.sh <binary-name>"
binary=$1
case "$binary" in
    wcash-poold | wcash-merge-miner | wcash-wallet | zallet) ;;
    *) die "binary is not in the release allowlist" ;;
esac

[[ -d $release_root && ! -L $release_root ]] \
    || [[ $release_root == /opt/wcash/current && -L $release_root ]] \
    || die "release root is unavailable"
[[ -f $manifest && ! -L $manifest ]] || die "release manifest is unavailable"
[[ -f $release_root/$binary && ! -L $release_root/$binary && -x $release_root/$binary ]] \
    || die "release binary is unavailable"

owner=$(stat -Lc '%u' -- "$release_root/$binary")
mode=$(stat -Lc '%a' -- "$release_root/$binary")
links=$(stat -Lc '%h' -- "$release_root/$binary")
[[ $owner == 0 && $mode == 555 && $links == 1 ]] \
    || die "release binary ownership or mode is unsafe"

match_count=$(awk -v name="$binary" '$2 == name { count += 1 } END { print count + 0 }' "$manifest")
[[ $match_count == 1 ]] || die "manifest must contain one exact binary entry"

(
    cd -- "$release_root"
    awk -v name="$binary" '$2 == name { print }' SHA256SUMS | sha256sum --strict --check --status
) || die "release digest mismatch"

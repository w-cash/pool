#!/usr/bin/env bash

set -Eeuo pipefail
set +x

readonly selected_release=${ZECWEC_RELEASE_PATH:-/opt/wcash/current}

die() {
    printf 'verify-release: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die "usage: verify-release.sh <binary-name>"
binary=$1
case "$binary" in
    wcash-poold | wcash-merge-miner | wcash-wallet | zallet | deployment-package) ;;
    *) die "binary is not in the release allowlist" ;;
esac

[[ $selected_release == /* && (-e $selected_release || -L $selected_release) ]] \
    || die "release root is unavailable"
release_root=$(realpath -e -- "$selected_release")
[[ $release_root =~ ^/opt/wcash/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ \
    && -d $release_root && ! -L $release_root ]] \
    || die "release root is not one canonical immutable version directory"

if [[ $binary == deployment-package ]]; then
    manifest="$release_root/DEPLOYMENT-SHA256SUMS"
    package="$release_root/deployment"
    [[ -d $package && ! -L $package && -f $manifest && ! -L $manifest ]] \
        || die "deployment package manifest is unavailable"
    [[ $(stat -c '%u:%a:%h' -- "$manifest") == 0:444:1 ]] \
        || die "deployment package manifest ownership or mode is unsafe"
    [[ -f $package/DEPLOYMENT-SCHEMA \
        && $(cat -- "$package/DEPLOYMENT-SCHEMA") == 1 ]] \
        || die "deployment package schema is unsupported"
    if find "$package" -type l -o ! -type d ! -type f | grep -q .; then
        die "deployment package contains an unsupported file type"
    fi
    if find "$package" \( ! -user root -o -perm /022 \) -print -quit | grep -q .; then
        die "deployment package ownership or mode is unsafe"
    fi
    if awk 'NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || $2 !~ /^deployment\/[A-Za-z0-9._\/-]+$/ || $2 ~ /(^|\/)\.\.?(\/|$)/ { exit 1 }' \
        "$manifest"; then
        :
    else
        die "deployment package manifest syntax is invalid"
    fi
    manifest_count=$(wc -l <"$manifest")
    file_count=$(find "$package" -type f | wc -l)
    [[ $manifest_count -eq $file_count ]] \
        || die "deployment package manifest does not cover every file"
    if ! (
        cd -- "$release_root"
        cmp --silent \
            <(find deployment -type f -print | LC_ALL=C sort) \
            <(awk '{print $2}' DEPLOYMENT-SHA256SUMS | LC_ALL=C sort)
    ); then
        die "deployment package manifest path set is incomplete or duplicated"
    fi
    (
        cd -- "$release_root"
        sha256sum --strict --check --status DEPLOYMENT-SHA256SUMS
    ) || die "deployment package digest mismatch"
    exit 0
fi

manifest="$release_root/SHA256SUMS"
[[ -f $manifest && ! -L $manifest ]] || die "release manifest is unavailable"
[[ $(stat -c '%u:%a:%h' -- "$manifest") == 0:444:1 ]] \
    || die "release manifest ownership or mode is unsafe"
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

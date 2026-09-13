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
        && $(cat -- "$package/DEPLOYMENT-SCHEMA") == 2 ]] \
        || die "deployment package schema is unsupported"
    audit=$(mktemp -d) || die "cannot create deployment verification workspace"
    chmod 0700 -- "$audit" || die "cannot protect deployment verification workspace"
    trap 'rm -rf -- "$audit"' EXIT
    if ! find "$package" \( -type l -o ! -type d ! -type f \) \
        -print >"$audit/unsupported"; then
        die "deployment package file types cannot be inspected"
    fi
    [[ ! -s $audit/unsupported ]] \
        || die "deployment package contains an unsupported file type"
    if ! find "$package" \( ! -user root -o -perm /022 \) \
        -print >"$audit/unsafe-metadata"; then
        die "deployment package ownership and modes cannot be inspected"
    fi
    [[ ! -s $audit/unsafe-metadata ]] \
        || die "deployment package ownership or mode is unsafe"
    if awk 'NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || $2 !~ /^deployment\/[A-Za-z0-9._\/-]+$/ || $2 ~ /(^|\/)\.\.?(\/|$)/ { exit 1 }' \
        "$manifest"; then
        :
    else
        die "deployment package manifest syntax is invalid"
    fi
    if ! (cd -- "$release_root" && find deployment -type f -print) \
        >"$audit/files.unsorted"; then
        die "deployment package file inventory cannot be inspected"
    fi
    LC_ALL=C sort -- "$audit/files.unsorted" >"$audit/files" \
        || die "deployment package file inventory cannot be sorted"
    if ! awk '{print $2}' "$manifest" >"$audit/manifest.unsorted"; then
        die "deployment package manifest paths cannot be read"
    fi
    LC_ALL=C sort -- "$audit/manifest.unsorted" >"$audit/manifest" \
        || die "deployment package manifest paths cannot be sorted"
    manifest_count=$(wc -l <"$audit/manifest")
    file_count=$(wc -l <"$audit/files")
    [[ $manifest_count -eq $file_count ]] \
        || die "deployment package manifest does not cover every file"
    if ! cmp --silent "$audit/files" "$audit/manifest"; then
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
release_artifacts=(
    wcash-poold
    wcash-merge-miner
    wcash-wallet
    zallet
    PROVENANCE.json
    ZALLET_SHA256SUM
)
[[ $(wc -l <"$manifest") -eq ${#release_artifacts[@]} ]] \
    || die "release manifest inventory is incomplete"
for artifact in "${release_artifacts[@]}"; do
    match_count=$(awk -v name="$artifact" \
        '$2 == name { count += 1 } END { print count + 0 }' "$manifest")
    [[ $match_count == 1 ]] || die "manifest must contain one exact $artifact entry"
done
[[ -f $release_root/$binary && ! -L $release_root/$binary && -x $release_root/$binary ]] \
    || die "release binary is unavailable"

owner=$(stat -Lc '%u' -- "$release_root/$binary")
mode=$(stat -Lc '%a' -- "$release_root/$binary")
links=$(stat -Lc '%h' -- "$release_root/$binary")
[[ $owner == 0 && $mode == 555 && $links == 1 ]] \
    || die "release binary ownership or mode is unsafe"

verified_artifacts=("$binary")
if [[ $binary == zallet ]]; then
    verified_artifacts+=(PROVENANCE.json ZALLET_SHA256SUM)
    for metadata in PROVENANCE.json ZALLET_SHA256SUM; do
        [[ -f $release_root/$metadata && ! -L $release_root/$metadata \
            && $(stat -c '%u:%a:%h' -- "$release_root/$metadata") == 0:444:1 ]] \
            || die "Zallet provenance artifact is unavailable or unsafe"
    done
fi
for artifact in "${verified_artifacts[@]}"; do
    (
        cd -- "$release_root"
        awk -v name="$artifact" '$2 == name { print }' SHA256SUMS \
            | sha256sum --strict --check --status
    ) || die "release digest mismatch for $artifact"
done
if [[ $binary == zallet ]]; then
    command -v python3 >/dev/null 2>&1 || die "python3 is unavailable"
    python3 "$release_root/deployment/scripts/verify-zallet-build.py" \
        "$release_root" "$release_root/deployment/patches/zallet-v0.1.0-beta.3" \
        || die "Zallet provenance verification failed"
fi

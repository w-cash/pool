#!/usr/bin/env bash

set -Eeuo pipefail
set +x

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

require_root
require_command sha256sum
require_command find
require_command sort
require_command python3

[[ $# -eq 2 ]] || die "usage: install-release.sh <version> <release-directory>"
version=$1
source_dir=$2
[[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid release version"
require_absolute_path "$source_dir"
[[ -d $source_dir && ! -L $source_dir ]] || die "release source must be a real directory"
default_deployment_source=$(realpath -m -- "$script_dir/../..")
if [[ ! -d $default_deployment_source/deploy \
    || ! -d $default_deployment_source/scripts/deploy \
    || ! -d $default_deployment_source/patches/zallet-v0.1.0-beta.3 ]]; then
    default_deployment_source=/usr/local/share/zecwec-deploy
fi
deployment_source=${ZECWEC_DEPLOY_SOURCE_ROOT:-$default_deployment_source}
require_absolute_path "$deployment_source"
[[ -d $deployment_source/deploy && -d $deployment_source/scripts/deploy \
    && -d $deployment_source/docs \
    && -d $deployment_source/patches/zallet-v0.1.0-beta.3 ]] \
    || die "deployment package source is incomplete"
require_deployment_source_tree_safe "$deployment_source"

allowed=(wcash-poold wcash-merge-miner wcash-wallet zallet)
zallet_metadata=(PROVENANCE.json ZALLET_SHA256SUM)
release_artifacts=("${allowed[@]}" "${zallet_metadata[@]}")
manifest="$source_dir/SHA256SUMS"
[[ -f $manifest && ! -L $manifest ]] || die "SHA256SUMS is required"
[[ $(wc -l <"$manifest") -eq ${#release_artifacts[@]} ]] \
    || die "manifest must contain the exact release artifact inventory"

for binary in "${allowed[@]}"; do
    [[ -f $source_dir/$binary && ! -L $source_dir/$binary && -x $source_dir/$binary ]] \
        || die "missing executable release artifact: $binary"
done
for metadata in "${zallet_metadata[@]}"; do
    [[ -f $source_dir/$metadata && ! -L $source_dir/$metadata ]] \
        || die "missing Zallet provenance artifact: $metadata"
done
for artifact in "${release_artifacts[@]}"; do
    count=$(awk -v name="$artifact" '$2 == name { count += 1 } END { print count + 0 }' \
        "$manifest")
    [[ $count == 1 ]] || die "manifest must contain exactly one entry for $artifact"
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

zallet_patch_source="$deployment_source/patches/zallet-v0.1.0-beta.3"
expected_zallet_patch_entries=$(printf '%s\n' \
    0001-reserve-wallet-database-capacity.patch \
    0002-signal-data-requests-after-chain-writes.patch \
    0003-remove-nonreproducible-shadow-paths.patch \
    0004-observe-batch-decryptor-shutdown.patch \
    README.md \
    zewif-zcashd-0.1.0-rc.5-relocatable-db-dump.patch | LC_ALL=C sort)
[[ -d $zallet_patch_source && ! -L $zallet_patch_source ]] \
    || die "pinned Zallet patch source is unavailable"
require_exact_immediate_entries \
    "$zallet_patch_source" "$expected_zallet_patch_entries" "Zallet patch source"
if ! unsupported_patch_entry=$(find "$zallet_patch_source" -mindepth 1 \
    \( -type l -o ! -type f \) -print -quit); then
    die "Zallet patch source file types cannot be inspected"
fi
[[ -z $unsupported_patch_entry ]] || die "Zallet patch source contains an unsafe file"
python3 "$deployment_source/scripts/verify-zallet-build.py" \
    "$source_dir" "$zallet_patch_source"

install -d -o root -g root -m 0755 /opt/wcash "$ZECWEC_RELEASE_ROOT"
destination="$ZECWEC_RELEASE_ROOT/$version"
if [[ -e $destination ]]; then
    ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" deployment-package
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
for metadata in "${zallet_metadata[@]}"; do
    install -o root -g root -m 0444 -- "$source_dir/$metadata" "$temporary/$metadata"
done
install -o root -g root -m 0444 -- "$manifest" "$temporary/SHA256SUMS"

install -d -o root -g root -m 0555 -- "$temporary/deployment"
cp -a -- "$deployment_source/deploy" "$temporary/deployment/deploy"
cp -a -- "$deployment_source/scripts" "$temporary/deployment/scripts"
cp -a -- "$deployment_source/docs" "$temporary/deployment/docs"
install -d -o root -g root -m 0555 -- "$temporary/deployment/patches"
cp -a -- "$zallet_patch_source" "$temporary/deployment/patches/zallet-v0.1.0-beta.3"
printf '2\n' >"$temporary/deployment/DEPLOYMENT-SCHEMA"
find "$temporary/deployment" -type d -exec chmod 0555 {} +
find "$temporary/deployment" -type f -exec chmod 0444 {} +
find "$temporary/deployment/scripts" -type f \( -name '*.sh' -o -name '*.py' \) \
    -exec chmod 0555 {} +
(
    cd -- "$temporary"
    find deployment -type f -print | LC_ALL=C sort | while IFS= read -r file; do
        sha256sum -- "$file"
    done >DEPLOYMENT-SHA256SUMS
)
chown -R root:root -- "$temporary/deployment"
chmod 0444 -- "$temporary/DEPLOYMENT-SHA256SUMS"
mv -- "$temporary" "$destination"
trap - EXIT

ZECWEC_RELEASE_PATH=$destination "$script_dir/verify-release.sh" deployment-package
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

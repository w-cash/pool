#!/usr/bin/env bash

set -Eeuo pipefail
set +x

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base_commit=987382f67e622915228686e9f956c6a9c9a7514c
upstream=https://github.com/zcash/zallet.git
patch_dir="$repo_root/patches/zallet-v0.1.0-beta.3"

command -v git >/dev/null 2>&1 || {
    printf 'zallet-patch-test: git is required\n' >&2
    exit 1
}

temporary=$(mktemp -d)
temporary=$(CDPATH='' cd -- "$temporary" && pwd -P)
trap 'rm -rf -- "$temporary"' EXIT
source_dir="$temporary/source"

git init --quiet "$source_dir"
git -C "$source_dir" remote add origin "$upstream"
git -C "$source_dir" fetch --quiet --depth 1 origin "$base_commit"
git -C "$source_dir" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
[[ $(git -C "$source_dir" rev-parse HEAD) == "$base_commit" ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]

for patch in \
    "$patch_dir/0001-reserve-wallet-database-capacity.patch" \
    "$patch_dir/0002-signal-data-requests-after-chain-writes.patch" \
    "$patch_dir/0003-remove-nonreproducible-shadow-paths.patch"; do
    git -C "$source_dir" apply --check "$patch"
    git -C "$source_dir" apply "$patch"
done
git -C "$source_dir" diff --check
grep -Fq '.runtime(deadpool::Runtime::Tokio1)' \
    "$source_dir/zallet-core/src/components/database/connection.rs"
grep -Fq 'data_request_signal.notify_one();' \
    "$source_dir/zallet-core/src/components/sync.rs"
grep -Fq 'denied_build_constants.extend([CARGO_MANIFEST_DIR, CARGO_TREE]);' \
    "$source_dir/zallet-core/build.rs"
grep -Fq '.deny_const(denied_build_constants)' \
    "$source_dir/zallet-core/build.rs"
printf 'zallet-patch-test: exact beta.3 patch set applies cleanly\n'

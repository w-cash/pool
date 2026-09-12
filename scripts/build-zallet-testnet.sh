#!/usr/bin/env bash

set -Eeuo pipefail
set +x

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base_commit=987382f67e622915228686e9f956c6a9c9a7514c
upstream=https://github.com/zcash/zallet.git
patch_dir="$repo_root/patches/zallet-v0.1.0-beta.3"
toolchain=1.95.0

[[ $# -eq 1 ]] || {
    printf 'build-zallet-testnet: usage: build-zallet-testnet.sh <output-directory>\n' >&2
    exit 1
}
output=$1
[[ $output == /* ]] || {
    printf 'build-zallet-testnet: output directory must be absolute\n' >&2
    exit 1
}

for command in cargo git install python3 rustc rustup sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'build-zallet-testnet: missing command: %s\n' "$command" >&2
        exit 1
    }
done

temporary=$(mktemp -d)
temporary=$(CDPATH='' cd -- "$temporary" && pwd -P)
trap 'rm -rf -- "$temporary"' EXIT
source_dir="$temporary/source"
target_dir="$temporary/target"
cargo_home="$temporary/cargo-home"

git init --quiet "$source_dir"
git -C "$source_dir" remote add origin "$upstream"
git -C "$source_dir" fetch --quiet --depth 1 origin "$base_commit"
git -C "$source_dir" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
[[ $(git -C "$source_dir" rev-parse HEAD) == "$base_commit" ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]

for patch in \
    "$patch_dir/0001-reserve-wallet-database-capacity.patch" \
    "$patch_dir/0002-signal-data-requests-after-chain-writes.patch"; do
    git -C "$source_dir" apply --check "$patch"
    git -C "$source_dir" apply "$patch"
done
git -C "$source_dir" diff --check

unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS RUSTDOCFLAGS
export CARGO_HOME="$cargo_home"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$target_dir"
export SOURCE_DATE_EPOCH=1787546182
export LANG=C
export LC_ALL=C
export TZ=UTC
export RUSTFLAGS="--remap-path-prefix=$temporary=/build/zecwec-zallet"
export CFLAGS="-ffile-prefix-map=$temporary=/build/zecwec-zallet -fdebug-prefix-map=$temporary=/build/zecwec-zallet"
export CXXFLAGS="-include cstdint $CFLAGS"
install -d -m 0700 "$cargo_home"
rustc "+$toolchain" -vV >"$temporary/rustc-version"
cargo "+$toolchain" -vV >"$temporary/cargo-version"
(
    cd "$source_dir"
    cargo "+$toolchain" fmt --all -- --check
    cargo "+$toolchain" test --locked --package zallet-core pool_config_tests
    cargo "+$toolchain" test --locked --package zallet-core components::sync::tests
    cargo "+$toolchain" build --locked --release \
        --manifest-path backends/zaino/Cargo.toml \
        --features rpc-cli,zcashd-import \
        --bin zallet-zaino
)

install -d -m 0755 "$output"
install -m 0555 "$target_dir/release/zallet-zaino" "$output/zallet"
(
    cd "$output"
    sha256sum zallet >ZALLET_SHA256SUM
)
python3 - \
    "$output/PROVENANCE.json" \
    "$base_commit" \
    "$patch_dir" \
    "$temporary/rustc-version" \
    "$temporary/cargo-version" \
    "$source_dir" \
    "$output/zallet" \
    "$temporary" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

output = pathlib.Path(sys.argv[1])
patches = sorted(pathlib.Path(sys.argv[3]).glob("*.patch"))
source_dir = pathlib.Path(sys.argv[6])
binary = pathlib.Path(sys.argv[7])
temporary = sys.argv[8].encode("utf-8")
binary_bytes = binary.read_bytes()
if temporary in binary_bytes:
    raise SystemExit("build-zallet-testnet: binary contains its temporary build path")
source_diff = subprocess.check_output(
    ["git", "-C", str(source_dir), "diff", "--binary", "--no-ext-diff"]
)
record = {
    "schema_version": 1,
    "upstream": "https://github.com/zcash/zallet",
    "base_commit": sys.argv[2],
    "binary": "zallet-zaino renamed to zallet",
    "features": ["rpc-cli", "zcashd-import"],
    "rustc": pathlib.Path(sys.argv[4]).read_text(encoding="utf-8").strip(),
    "cargo": pathlib.Path(sys.argv[5]).read_text(encoding="utf-8").strip(),
    "source_date_epoch": 1787546182,
    "source_patch_sha256": hashlib.sha256(source_diff).hexdigest(),
    "binary_sha256": hashlib.sha256(binary_bytes).hexdigest(),
    "patches": [
        {
            "name": patch.name,
            "sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
        }
        for patch in patches
    ],
}
output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 0444 "$output/ZALLET_SHA256SUM" "$output/PROVENANCE.json"
printf 'build-zallet-testnet: verified patched binary written to %s\n' "$output"

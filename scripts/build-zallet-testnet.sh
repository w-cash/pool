#!/usr/bin/env bash

set -Eeuo pipefail
set +x

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base_commit=987382f67e622915228686e9f956c6a9c9a7514c
upstream=https://github.com/zcash/zallet.git
patch_dir="$repo_root/patches/zallet-v0.1.0-beta.3"
toolchain=1.95.0
protoc_version=25.9
protoc_sha256=88f2d0c78a1072c4f84c59e9f9785b74849953e882a573188bc2d0518915b03e
protoc_url="https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-linux-x86_64.zip"

[[ $# -eq 1 ]] || {
    printf 'build-zallet-testnet: usage: build-zallet-testnet.sh <output-directory>\n' >&2
    exit 1
}
output=$1
[[ $output == /* ]] || {
    printf 'build-zallet-testnet: output directory must be absolute\n' >&2
    exit 1
}
[[ ! -e $output && ! -L $output ]] || {
    printf 'build-zallet-testnet: output directory already exists\n' >&2
    exit 1
}
output_parent=$(dirname -- "$output")
[[ -d $output_parent && ! -L $output_parent ]] || {
    printf 'build-zallet-testnet: output parent must be a real directory\n' >&2
    exit 1
}

for command in cargo curl git install python3 rustc rustup sha256sum timeout unzip; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'build-zallet-testnet: missing command: %s\n' "$command" >&2
        exit 1
    }
done

temporary=$(mktemp -d)
temporary=$(CDPATH='' cd -- "$temporary" && pwd -P)
staging=$(mktemp -d "$output_parent/.zallet-build.XXXXXX")
trap 'rm -rf -- "$temporary" "$staging"' EXIT
source_dir="$temporary/source"
target_dir="$temporary/target"
cargo_home="$temporary/cargo-home"
protoc_root="$temporary/protoc"
protoc_archive="$temporary/protoc.zip"

curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --location --fail --silent --show-error \
    --output "$protoc_archive" "$protoc_url"
printf '%s  %s\n' "$protoc_sha256" "$protoc_archive" | sha256sum --check --status
install -d -m 0700 "$protoc_root"
unzip -q "$protoc_archive" -d "$protoc_root"
[[ -f $protoc_root/bin/protoc && ! -L $protoc_root/bin/protoc \
    && -x $protoc_root/bin/protoc && -d $protoc_root/include ]]

git init --quiet "$source_dir"
git -C "$source_dir" remote add origin "$upstream"
git -C "$source_dir" fetch --quiet --depth 1 origin "$base_commit"
git -C "$source_dir" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
[[ $(git -C "$source_dir" rev-parse HEAD) == "$base_commit" ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]

patches=(
    "$patch_dir/0001-reserve-wallet-database-capacity.patch"
    "$patch_dir/0002-signal-data-requests-after-chain-writes.patch"
    "$patch_dir/0003-remove-nonreproducible-shadow-paths.patch"
    "$patch_dir/0004-deflake-batch-decryptor-shutdown-test.patch"
)
applied_patch_list=$temporary/applied-patches
printf '%s\n' "${patches[@]}" >"$applied_patch_list"
for patch in "${patches[@]}"; do
    git -C "$source_dir" apply --check "$patch"
    git -C "$source_dir" apply "$patch"
done
git -C "$source_dir" diff --check

unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS RUSTDOCFLAGS
export CARGO_HOME="$cargo_home"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$target_dir"
export PROTOC="$protoc_root/bin/protoc"
export PROTOC_INCLUDE="$protoc_root/include"
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
"$PROTOC" --version >"$temporary/protoc-version"
grep -Fx "libprotoc $protoc_version" "$temporary/protoc-version" >/dev/null
(
    cd "$source_dir"
    cargo "+$toolchain" fmt --all -- --check
    cargo "+$toolchain" test --locked --package zallet-core pool_config_tests
    # beta.3's original assertion raced a reload request against Tokio's
    # asynchronous task abort. The audited upstream #766 backport observes
    # eventual shutdown with its own 30-second bound; repeat it to exercise the
    # scheduling boundary before accepting the full sync suite.
    for _stress_iteration in {1..100}; do
        timeout --signal=TERM --kill-after=10s 40s \
            cargo "+$toolchain" test --locked --package zallet-core \
            components::sync::tests::wallet_sync_error_shuts_down_the_spawned_batch_decryptor \
            -- --exact --test-threads=1
    done
    # These Tokio cancellation tests share global tracing/i18n state and can
    # deadlock each other when the Rust harness runs them concurrently.  They
    # complete in seconds serially; keep an outer bound so a regression cannot
    # hold an isolated release build indefinitely.
    timeout --signal=TERM --kill-after=10s 300s \
        cargo "+$toolchain" test --locked --package zallet-core \
        components::sync::tests -- --test-threads=1
    cargo "+$toolchain" build --locked --release \
        --manifest-path backends/zaino/Cargo.toml \
        --features rpc-cli,zcashd-import \
        --bin zallet-zaino
)

python3 - "$target_dir" "$temporary" <<'PY'
import pathlib
import sys

target_dir = pathlib.Path(sys.argv[1])
temporary = sys.argv[2].encode("utf-8")
shadow_files = sorted(target_dir.glob("**/build/zallet-core-*/out/shadow.rs"))
if not shadow_files:
    raise SystemExit("build-zallet-testnet: generated shadow metadata is missing")
for shadow_file in shadow_files:
    content = shadow_file.read_bytes()
    if b"pub const CARGO_MANIFEST_DIR" in content or b"pub const CARGO_TREE" in content:
        raise SystemExit("build-zallet-testnet: non-reproducible shadow metadata was generated")
    if temporary in content:
        raise SystemExit("build-zallet-testnet: generated shadow metadata contains its build path")
PY

install -m 0555 "$target_dir/release/zallet-zaino" "$staging/zallet"
(
    cd "$staging"
    sha256sum zallet >ZALLET_SHA256SUM
)
python3 - \
    "$staging/PROVENANCE.json" \
    "$base_commit" \
    "$applied_patch_list" \
    "$temporary/rustc-version" \
    "$temporary/cargo-version" \
    "$temporary/protoc-version" \
    "$source_dir" \
    "$staging/zallet" \
    "$temporary" \
    "$protoc_version" \
    "$protoc_sha256" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

output = pathlib.Path(sys.argv[1])
patches = [
    pathlib.Path(line)
    for line in pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
]
if not patches or len(patches) != len(set(patches)):
    raise SystemExit("build-zallet-testnet: applied patch list is invalid")
source_dir = pathlib.Path(sys.argv[7])
binary = pathlib.Path(sys.argv[8])
temporary = sys.argv[9].encode("utf-8")
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
    "protoc": {
        "version": pathlib.Path(sys.argv[6]).read_text(encoding="utf-8").strip(),
        "release": sys.argv[10],
        "archive_sha256": sys.argv[11],
    },
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
chmod 0444 "$staging/ZALLET_SHA256SUM" "$staging/PROVENANCE.json"
(
    cd "$staging"
    sha256sum --strict --check --status ZALLET_SHA256SUM
)
[[ ! -e $output && ! -L $output ]] || {
    printf 'build-zallet-testnet: output directory appeared during the build\n' >&2
    exit 1
}
mv -T -- "$staging" "$output"
trap 'rm -rf -- "$temporary"' EXIT
printf 'build-zallet-testnet: verified patched binary written to %s\n' "$output"

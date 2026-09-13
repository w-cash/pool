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
zewif_zcashd_version=0.1.0-rc.5
zewif_zcashd_sha256=b67252cc55aad73afc6d608f29d14711d86e2b06bffcb76585aba31ee6310901
zewif_zcashd_url="https://static.crates.io/crates/zewif-zcashd/zewif-zcashd-${zewif_zcashd_version}.crate"
build_root=/tmp/zecwec-zallet-v0.1.0-beta.3-build
build_lock=/tmp/zecwec-zallet-v0.1.0-beta.3-build.lock.d

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

for command in cargo curl flock git id install python3 rustc rustup sha256sum stat timeout unzip; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'build-zallet-testnet: missing command: %s\n' "$command" >&2
        exit 1
    }
done

# Cargo includes canonical path-package identities in rustc crate metadata before
# rustc applies --remap-path-prefix. Therefore the source and Cargo roots must
# have the same canonical path on every builder for byte-identical output.
# Serialize access to that fixed root, reject unsafe leftovers, and clean it on
# every exit. The caller's output staging directory remains unique.
if ! mkdir -m 0700 -- "$build_lock" 2>/dev/null; then
    [[ -d $build_lock && ! -L $build_lock \
        && $(stat -c '%u' "$build_lock") == "$(id -u)" \
        && $(stat -c '%a' "$build_lock") == 700 ]] || {
        printf 'build-zallet-testnet: unsafe fixed build lock: %s\n' "$build_lock" >&2
        exit 1
    }
fi
[[ -d $build_lock && ! -L $build_lock \
    && $(stat -c '%u' "$build_lock") == "$(id -u)" \
    && $(stat -c '%a' "$build_lock") == 700 ]] || {
    printf 'build-zallet-testnet: unsafe fixed build lock: %s\n' "$build_lock" >&2
    exit 1
}
exec {build_lock_fd}<"$build_lock"
flock "$build_lock_fd"

if [[ -e $build_root || -L $build_root ]]; then
    [[ -d $build_root && ! -L $build_root \
        && $(stat -c '%u' "$build_root") == "$(id -u)" \
        && $(stat -c '%a' "$build_root") == 700 ]] || {
        printf 'build-zallet-testnet: unsafe fixed build root: %s\n' "$build_root" >&2
        exit 1
    }
    rm -rf -- "$build_root"
fi
install -d -m 0700 "$build_root"
temporary=$(CDPATH='' cd -- "$build_root" && pwd -P)
[[ $temporary == "$build_root" ]] || {
    printf 'build-zallet-testnet: fixed build root did not resolve canonically\n' >&2
    exit 1
}
staging=$(mktemp -d "$output_parent/.zallet-build.XXXXXX")
trap 'rm -rf -- "$temporary" "$staging"' EXIT
source_dir="$temporary/source"
target_dir="$temporary/target"
cargo_home="$temporary/cargo-home"
protoc_root="$temporary/protoc"
protoc_archive="$temporary/protoc.zip"
patched_dependencies="$temporary/patched-dependencies"
zewif_zcashd_archive="$temporary/zewif-zcashd-${zewif_zcashd_version}.crate"
zewif_zcashd_pristine_source="$patched_dependencies/zewif-zcashd-${zewif_zcashd_version}"

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
    "$patch_dir/0004-observe-batch-decryptor-shutdown.patch"
)
dependency_patches=(
    "$patch_dir/zewif-zcashd-0.1.0-rc.5-relocatable-db-dump.patch"
)
applied_patch_list=$temporary/applied-patches
printf '%s\n' "${patches[@]}" "${dependency_patches[@]}" >"$applied_patch_list"
for patch in "${patches[@]}"; do
    git -C "$source_dir" apply --check "$patch"
    git -C "$source_dir" apply "$patch"
done
git -C "$source_dir" diff --check

curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --location --fail --silent --show-error \
    --output "$zewif_zcashd_archive" "$zewif_zcashd_url"
printf '%s  %s\n' "$zewif_zcashd_sha256" "$zewif_zcashd_archive" \
    | sha256sum --check --status
install -d -m 0700 "$patched_dependencies"
python3 - \
    "$zewif_zcashd_archive" \
    "$patched_dependencies" \
    "zewif-zcashd-${zewif_zcashd_version}" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected_root = sys.argv[3]

with tarfile.open(archive_path, mode="r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("build-zallet-testnet: patched dependency archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute()
            or not path.parts
            or path.parts[0] != expected_root
            or any(part in ("", ".", "..") for part in path.parts)
            or not (member.isfile() or member.isdir())
        ):
            raise SystemExit(
                f"build-zallet-testnet: unsafe patched dependency member: {member.name}"
            )
    archive.extractall(destination)
PY
[[ -d $zewif_zcashd_pristine_source && ! -L $zewif_zcashd_pristine_source ]]

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
zaino_manifest="$source_dir/backends/zaino/Cargo.toml"
zaino_lock="$source_dir/backends/zaino/Cargo.lock"
zaino_lock_digest=$(sha256sum "$zaino_lock")
zaino_lock_sha256=${zaino_lock_digest%% *}

# Populate this build's private registry from the committed lock before
# modifying any dependency source. Keeping the package's registry identity is
# essential: a Cargo path override makes the crate disambiguator depend on the
# random source root, even when rustc path remapping is enabled.
cargo "+$toolchain" metadata --locked --format-version 1 \
    --manifest-path "$zaino_manifest" \
    --features rpc-cli,zcashd-import \
    >"$temporary/cargo-metadata-pristine.json"
[[ $(sha256sum "$zaino_lock") == "$zaino_lock_digest" ]] || {
    printf 'build-zallet-testnet: Cargo.lock changed during pristine resolution\n' >&2
    exit 1
}

zewif_zcashd_registry_sources=()
shopt -s nullglob
for candidate in "$cargo_home"/registry/src/*/"zewif-zcashd-${zewif_zcashd_version}"; do
    if [[ -d $candidate && ! -L $candidate ]]; then
        zewif_zcashd_registry_sources+=("$candidate")
    fi
done
shopt -u nullglob
[[ ${#zewif_zcashd_registry_sources[@]} -eq 1 ]] || {
    printf 'build-zallet-testnet: expected one private zewif-zcashd registry source, found %s\n' \
        "${#zewif_zcashd_registry_sources[@]}" >&2
    exit 1
}
zewif_zcashd_registry_source=${zewif_zcashd_registry_sources[0]}

# Cargo verifies the lockfile checksum while extracting the crate. Independently
# compare every source byte with the separately downloaded, digest-pinned
# archive before applying the recorded local patch to this private registry.
python3 - \
    "$zewif_zcashd_archive" \
    "$zewif_zcashd_registry_source" \
    "zewif-zcashd-${zewif_zcashd_version}" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
source = pathlib.Path(sys.argv[2])
expected_root = pathlib.PurePosixPath(sys.argv[3])
expected_files = {}

with tarfile.open(archive_path, mode="r:gz") as archive:
    for member in archive.getmembers():
        path = pathlib.PurePosixPath(member.name)
        try:
            relative = path.relative_to(expected_root)
        except ValueError as error:
            raise SystemExit(
                f"build-zallet-testnet: dependency escaped archive root: {member.name}"
            ) from error
        if member.isdir():
            continue
        if not member.isfile():
            raise SystemExit(
                f"build-zallet-testnet: unsupported dependency member: {member.name}"
            )
        stream = archive.extractfile(member)
        if stream is None:
            raise SystemExit(
                f"build-zallet-testnet: dependency member is unreadable: {member.name}"
            )
        expected_files[relative.as_posix()] = stream.read()

actual_files = {}
for path in source.rglob("*"):
    if path.is_symlink():
        raise SystemExit(
            f"build-zallet-testnet: private registry contains a symlink: {path}"
        )
    if path.is_dir():
        continue
    if not path.is_file():
        raise SystemExit(
            f"build-zallet-testnet: private registry contains a special file: {path}"
        )
    actual_files[path.relative_to(source).as_posix()] = path.read_bytes()

extra_files = set(actual_files) - set(expected_files)
unexpected_extra_files = extra_files - {".cargo-ok"}
if unexpected_extra_files:
    raise SystemExit(
        "build-zallet-testnet: unexpected private-registry files: "
        + ", ".join(sorted(unexpected_extra_files))
    )
missing_files = set(expected_files) - set(actual_files)
if missing_files:
    raise SystemExit(
        "build-zallet-testnet: private registry is missing files: "
        + ", ".join(sorted(missing_files))
    )
for relative, expected in expected_files.items():
    if actual_files[relative] != expected:
        raise SystemExit(
            f"build-zallet-testnet: private-registry source differs from archive: {relative}"
        )
PY

for patch in "${dependency_patches[@]}"; do
    (
        cd "$zewif_zcashd_registry_source"
        git apply --check "$patch"
        git apply "$patch"
    )
done
grep -Fq 'emit_db_dump_path(out_path, &db_dump_binary)?;' \
    "$zewif_zcashd_registry_source/build.rs"
grep -Fq 'vendored_db_dump_path(&executable, vendored_path)' \
    "$zewif_zcashd_registry_source/src/bdb_dump.rs"

# Re-resolve after patching and prove that the locked package is still the
# crates.io registry package, not a root-dependent path dependency.
cargo "+$toolchain" metadata --locked --format-version 1 \
    --manifest-path "$zaino_manifest" \
    --features rpc-cli,zcashd-import \
    >"$temporary/cargo-metadata-patched.json"
[[ $(sha256sum "$zaino_lock") == "$zaino_lock_digest" ]] || {
    printf 'build-zallet-testnet: Cargo.lock changed after dependency patching\n' >&2
    exit 1
}
python3 - \
    "$temporary/cargo-metadata-patched.json" \
    "$zewif_zcashd_registry_source" \
    "$zewif_zcashd_version" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_source = pathlib.Path(sys.argv[2]).resolve()
expected_version = sys.argv[3]
packages = [
    package
    for package in metadata["packages"]
    if package["name"] == "zewif-zcashd" and package["version"] == expected_version
]
if len(packages) != 1:
    raise SystemExit(
        f"build-zallet-testnet: expected one locked zewif-zcashd package, found {len(packages)}"
    )
package = packages[0]
if package["source"] != "registry+https://github.com/rust-lang/crates.io-index":
    raise SystemExit(
        f"build-zallet-testnet: zewif-zcashd lost registry identity: {package['source']}"
    )
manifest_source = pathlib.Path(package["manifest_path"]).resolve().parent
if manifest_source != expected_source:
    raise SystemExit(
        "build-zallet-testnet: metadata resolved an unexpected zewif-zcashd source"
    )
PY
(
    cd "$source_dir"
    cargo "+$toolchain" fmt --all -- --check
    cargo "+$toolchain" test --locked --package zallet-core pool_config_tests
    zallet_core_test_harnesses=()
    shopt -s nullglob
    for candidate in "$target_dir"/debug/deps/zallet_core-*; do
        if [[ -f $candidate && ! -L $candidate && -x $candidate ]]; then
            zallet_core_test_harnesses+=("$candidate")
        fi
    done
    shopt -u nullglob
    [[ ${#zallet_core_test_harnesses[@]} -eq 1 ]] || {
        printf 'build-zallet-testnet: expected exactly one Zallet core test harness, found %s\n' \
            "${#zallet_core_test_harnesses[@]}" >&2
        exit 1
    }
    zallet_core_test_harness=${zallet_core_test_harnesses[0]}
    # beta.3's original assertion raced a reload request against Tokio's
    # asynchronous task abort. The audited test seam observes the spawned task
    # itself with a 30-second bound; repeat it to exercise the scheduling
    # boundary before accepting the full sync suite.
    # Invoke the exact harness already built by the pool-config gate so Cargo
    # cannot rebuild or relink inside the per-execution timeout.
    (
        cd "$source_dir/zallet-core"
        for _stress_iteration in {1..200}; do
            timeout --signal=TERM --kill-after=10s 40s \
                "$zallet_core_test_harness" \
                components::sync::tests::wallet_sync_error_shuts_down_the_spawned_batch_decryptor \
                --exact --test-threads=1
        done
        # These Tokio cancellation tests share global tracing/i18n state and
        # can deadlock each other when the Rust harness runs them concurrently.
        # They complete in seconds serially; keep an outer bound so a
        # regression cannot hold an isolated release build indefinitely.
        timeout --signal=TERM --kill-after=10s 300s \
            "$zallet_core_test_harness" components::sync::tests --test-threads=1
    )
    cargo "+$toolchain" build --locked --release \
        --manifest-path backends/zaino/Cargo.toml \
        --features rpc-cli,zcashd-import \
        --bin zallet-zaino
)
[[ $(sha256sum "$zaino_lock") == "$zaino_lock_digest" ]] || {
    printf 'build-zallet-testnet: Cargo.lock changed during compilation\n' >&2
    exit 1
}

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
    "$protoc_sha256" \
    "$zewif_zcashd_version" \
    "$zewif_zcashd_url" \
    "$zewif_zcashd_sha256" \
    "$zaino_lock_sha256" <<'PY'
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
    "cargo_lock": {
        "path": "backends/zaino/Cargo.lock",
        "sha256": sys.argv[15],
    },
    "patched_dependencies": [
        {
            "name": "zewif-zcashd",
            "version": sys.argv[12],
            "archive": sys.argv[13],
            "archive_sha256": sys.argv[14],
        }
    ],
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

#!/usr/bin/env bash

set -Eeuo pipefail
set +x

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base_commit=987382f67e622915228686e9f956c6a9c9a7514c
upstream=https://github.com/zcash/zallet.git
patch_dir="$repo_root/patches/zallet-v0.1.0-beta.3"
zewif_zcashd_version=0.1.0-rc.5
zewif_zcashd_sha256=b67252cc55aad73afc6d608f29d14711d86e2b06bffcb76585aba31ee6310901
zewif_zcashd_patch_sha256=0cd00a61194c9cf1d45554d35dd5954333709355adcef1c2939c20a48a41f91e
zewif_zcashd_url="https://static.crates.io/crates/zewif-zcashd/zewif-zcashd-${zewif_zcashd_version}.crate"
zewif_zcashd_patch="$patch_dir/zewif-zcashd-${zewif_zcashd_version}-relocatable-db-dump.patch"

for command in curl git install python3 sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'zallet-patch-test: %s is required\n' "$command" >&2
        exit 1
    }
done

temporary=$(mktemp -d)
temporary=$(CDPATH='' cd -- "$temporary" && pwd -P)
trap 'rm -rf -- "$temporary"' EXIT
source_dir="$temporary/source"
zewif_zcashd_archive="$temporary/zewif-zcashd-${zewif_zcashd_version}.crate"
zewif_zcashd_extract_root="$temporary/dependency"
zewif_zcashd_source="$zewif_zcashd_extract_root/zewif-zcashd-${zewif_zcashd_version}"

git init --quiet "$source_dir"
git -C "$source_dir" remote add origin "$upstream"
git -C "$source_dir" fetch --quiet --depth 1 origin "$base_commit"
git -C "$source_dir" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
[[ $(git -C "$source_dir" rev-parse HEAD) == "$base_commit" ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]

for patch in \
    "$patch_dir/0001-reserve-wallet-database-capacity.patch" \
    "$patch_dir/0002-signal-data-requests-after-chain-writes.patch" \
    "$patch_dir/0003-remove-nonreproducible-shadow-paths.patch" \
    "$patch_dir/0004-observe-batch-decryptor-shutdown.patch"; do
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
grep -Fq 'tokio::time::timeout(Duration::from_secs(30), async {' \
    "$source_dir/zallet-core/src/components/sync.rs"
grep -Fq 'observe_batch_task(batch_decryptor_task.abort_handle());' \
    "$source_dir/zallet-core/src/components/sync.rs"
grep -Fq 'while !batch_task_abort.is_finished()' \
    "$source_dir/zallet-core/src/components/sync.rs"

# A path dependency changes Cargo's crate disambiguator with every source root.
# Keep the committed registry identity and lock checksum untouched.
if grep -Fq 'zewif-zcashd = { path' "$source_dir/backends/zaino/Cargo.toml"; then
    printf 'zallet-patch-test: zewif-zcashd became a root-dependent path override\n' >&2
    exit 1
fi
grep -Fq 'build_root=/tmp/zecwec-zallet-v0.1.0-beta.3-build' \
    "$repo_root/scripts/build-zallet-testnet.sh"
grep -Fq "flock \"\$build_lock_fd\"" \
    "$repo_root/scripts/build-zallet-testnet.sh"
python3 - "$source_dir/backends/zaino/Cargo.lock" "$zewif_zcashd_sha256" <<'PY'
import pathlib
import re
import sys

lock = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
expected_checksum = sys.argv[2]
matches = re.findall(
    r'\[\[package\]\]\nname = "zewif-zcashd"\nversion = "0\.1\.0-rc\.5"\n'
    r'source = "registry\+https://github\.com/rust-lang/crates\.io-index"\n'
    r'checksum = "([0-9a-f]{64})"',
    lock,
)
if matches != [expected_checksum]:
    raise SystemExit("zallet-patch-test: locked zewif-zcashd registry identity changed")
PY

printf '%s  %s\n' "$zewif_zcashd_patch_sha256" "$zewif_zcashd_patch" \
    | sha256sum --check --status
curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --location --fail --silent --show-error \
    --output "$zewif_zcashd_archive" "$zewif_zcashd_url"
printf '%s  %s\n' "$zewif_zcashd_sha256" "$zewif_zcashd_archive" \
    | sha256sum --check --status
install -d -m 0700 "$zewif_zcashd_extract_root"
python3 - \
    "$zewif_zcashd_archive" \
    "$zewif_zcashd_extract_root" \
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
        raise SystemExit("zallet-patch-test: dependency archive is empty")
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
                f"zallet-patch-test: unsafe dependency archive member: {member.name}"
            )
    archive.extractall(destination)
PY
[[ -d $zewif_zcashd_source && ! -L $zewif_zcashd_source ]]
(
    cd "$zewif_zcashd_source"
    git apply --check "$zewif_zcashd_patch"
    git apply "$zewif_zcashd_patch"
)
grep -Fq 'emit_db_dump_path(out_path, &db_dump_binary)?;' \
    "$zewif_zcashd_source/build.rs"
grep -Fq 'if vendored_path.is_absolute()' \
    "$zewif_zcashd_source/src/bdb_dump.rs"
grep -Fq 'vendored_db_dump_is_resolved_relative_to_the_executable' \
    "$zewif_zcashd_source/src/bdb_dump.rs"
grep -Fq 'absolute_build_host_paths_are_rejected' \
    "$zewif_zcashd_source/src/bdb_dump.rs"
printf 'zallet-patch-test: exact beta.3 patch set applies cleanly\n'

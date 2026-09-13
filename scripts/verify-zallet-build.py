#!/usr/bin/env python3

"""Verify a pinned Zallet build and its complete, reviewable provenance."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys


BASE_COMMIT = "987382f67e622915228686e9f956c6a9c9a7514c"
SOURCE_PATCH_SHA256 = "2bb4146e3c581d847ed943ac537564edf5a36eb971548a7f20ffaa838f1cdd5b"
ZAINO_LOCK_SHA256 = "3915e0b4907510b8f76b9deebba1840a7ec233c2a265bc5e0e9fe52e21b682d2"
ZEWIF_VERSION = "0.1.0-rc.5"
ZEWIF_ARCHIVE = (
    "https://static.crates.io/crates/zewif-zcashd/"
    "zewif-zcashd-0.1.0-rc.5.crate"
)
ZEWIF_ARCHIVE_SHA256 = (
    "b67252cc55aad73afc6d608f29d14711d86e2b06bffcb76585aba31ee6310901"
)
LIBRUSTZCASH_REPOSITORY = "https://github.com/zcash/librustzcash.git"
LIBRUSTZCASH_REVISION = "1f6bb2072e7fcb142b0d90ff7b267a8699a84818"
PATCH_NAMES = [
    "0001-reserve-wallet-database-capacity.patch",
    "0002-signal-data-requests-after-chain-writes.patch",
    "0003-remove-nonreproducible-shadow-paths.patch",
    "0004-observe-batch-decryptor-shutdown.patch",
    "zewif-zcashd-0.1.0-rc.5-relocatable-db-dump.patch",
    "librustzcash-1f6bb207-recovery-tip-gate.patch",
]
PATCH_DIRECTORY_ENTRIES = set(PATCH_NAMES) | {"README.md"}
RECORD_KEYS = {
    "base_commit",
    "binary",
    "binary_sha256",
    "cargo",
    "cargo_lock",
    "features",
    "patched_dependencies",
    "patches",
    "protoc",
    "rustc",
    "schema_version",
    "source_date_epoch",
    "source_patch_sha256",
    "upstream",
}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> None:
    raise SystemExit(f"verify-zallet-build: {message}")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_plain_file(path: pathlib.Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is not a plain file")


def load_record(path: pathlib.Path) -> dict[str, object]:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"provenance is unreadable: {error}")
    if not isinstance(record, dict) or set(record) != RECORD_KEYS:
        fail("provenance has an unexpected schema")
    return record


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify-zallet-build.py <artifact-directory> <patch-directory>")
    artifact_dir = pathlib.Path(sys.argv[1])
    patch_dir = pathlib.Path(sys.argv[2])
    if artifact_dir.is_symlink() or not artifact_dir.is_dir():
        fail("artifact directory is unavailable")
    if patch_dir.is_symlink() or not patch_dir.is_dir():
        fail("patch directory is unavailable")

    entries = {path.name for path in patch_dir.iterdir()}
    if entries != PATCH_DIRECTORY_ENTRIES:
        fail("patch directory inventory is not exact")
    for entry in PATCH_DIRECTORY_ENTRIES:
        require_plain_file(patch_dir / entry, f"patch-set entry {entry}")

    binary = artifact_dir / "zallet"
    checksum = artifact_dir / "ZALLET_SHA256SUM"
    provenance = artifact_dir / "PROVENANCE.json"
    require_plain_file(binary, "Zallet binary")
    require_plain_file(checksum, "Zallet checksum")
    require_plain_file(provenance, "Zallet provenance")
    binary_sha256 = sha256(binary)

    try:
        checksum_text = checksum.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail(f"checksum is unreadable: {error}")
    checksum_match = re.fullmatch(r"([0-9a-f]{64})  zallet\n", checksum_text)
    if checksum_match is None or checksum_match.group(1) != binary_sha256:
        fail("checksum does not identify the exact Zallet binary")

    record = load_record(provenance)
    expected_scalars = {
        "schema_version": 1,
        "upstream": "https://github.com/zcash/zallet",
        "base_commit": BASE_COMMIT,
        "binary": "zallet-zaino renamed to zallet",
        "features": ["rpc-cli", "zcashd-import"],
        "source_date_epoch": 1787546182,
        "source_patch_sha256": SOURCE_PATCH_SHA256,
        "binary_sha256": binary_sha256,
    }
    for key, expected in expected_scalars.items():
        if record.get(key) != expected:
            fail(f"provenance field {key} does not match the pinned build")

    rustc = record.get("rustc")
    cargo = record.get("cargo")
    if not isinstance(rustc, str) or not rustc.startswith("rustc 1.95.0 "):
        fail("provenance does not identify rustc 1.95.0")
    if not isinstance(cargo, str) or not cargo.startswith("cargo 1.95.0 "):
        fail("provenance does not identify cargo 1.95.0")

    if record.get("cargo_lock") != {
        "path": "backends/zaino/Cargo.lock",
        "sha256": ZAINO_LOCK_SHA256,
    }:
        fail("provenance does not identify the exact locked Zaino graph")
    if record.get("protoc") != {
        "archive_sha256": "88f2d0c78a1072c4f84c59e9f9785b74849953e882a573188bc2d0518915b03e",
        "release": "25.9",
        "version": "libprotoc 25.9",
    }:
        fail("provenance does not identify the pinned protoc tool")
    if record.get("patched_dependencies") != [
        {
            "archive": ZEWIF_ARCHIVE,
            "archive_sha256": ZEWIF_ARCHIVE_SHA256,
            "name": "zewif-zcashd",
            "version": ZEWIF_VERSION,
        },
        {
            "name": "librustzcash",
            "patched_package": "zcash_client_sqlite",
            "repository": LIBRUSTZCASH_REPOSITORY,
            "revision": LIBRUSTZCASH_REVISION,
        },
    ]:
        fail("provenance does not identify the pinned patched dependencies")

    patches = record.get("patches")
    if not isinstance(patches, list) or len(patches) != len(PATCH_NAMES):
        fail("provenance patch inventory is incomplete")
    expected_patches = [
        {"name": name, "sha256": sha256(patch_dir / name)} for name in PATCH_NAMES
    ]
    if patches != expected_patches:
        fail("provenance patch hashes do not match the immutable patch set")
    for patch in patches:
        if not HEX_SHA256.fullmatch(str(patch["sha256"])):
            fail("provenance contains an invalid patch digest")

    print(f"verify-zallet-build: verified {binary_sha256}")


if __name__ == "__main__":
    main()

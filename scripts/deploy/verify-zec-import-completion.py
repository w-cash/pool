#!/usr/bin/env python3
"""Verify the secret-free binding for one completed Zallet recovery import."""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import sys
from typing import NoReturn


TRUSTED_UID = 0
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"verify-zec-import-completion: {message}")


def read_private_object(path: pathlib.Path, label: str) -> tuple[bytes, object]:
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"{label} is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != TRUSTED_UID
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_EVIDENCE_BYTES
    ):
        fail(f"{label} ownership, mode, size, or link count is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"{label} cannot be opened safely")
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_uid != TRUSTED_UID
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_nlink != 1
        ):
            fail(f"{label} changed during validation")
        raw = os.read(descriptor, MAX_EVIDENCE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_EVIDENCE_BYTES:
        fail(f"{label} exceeds its size limit")
    try:
        return raw, json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        fail(f"{label} is not valid JSON")


def capture_seedfp(capture: object) -> object:
    try:
        return capture["rpc_transcript"]["account"]["response"]["result"]["seedfp"]
    except (KeyError, TypeError):
        return None


def verify(
    marker_path: pathlib.Path,
    release: pathlib.Path,
    staging: pathlib.Path,
    original_path: pathlib.Path,
    recovered_path: pathlib.Path,
) -> None:
    if (
        not release.is_absolute()
        or release.parent != pathlib.Path("/opt/wcash/releases")
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release.name) is None
    ):
        fail("release path is outside the immutable release namespace")
    if (
        not staging.is_absolute()
        or staging.parent != pathlib.Path("/var/lib/zecwec-custody")
        or re.fullmatch(r"zec-[0-9a-f]{7,40}", staging.name) is None
    ):
        fail("mnemonic staging path is outside the reviewed Testnet namespace")
    raw, marker = read_private_object(marker_path, "recovery completion marker")
    _, original = read_private_object(original_path, "original RPC capture")
    _, recovered = read_private_object(recovered_path, "recovered RPC capture")
    if not isinstance(marker, dict):
        fail("recovery completion marker has an invalid schema")
    seed_fingerprint = marker.get("seed_fingerprint")
    if (
        not isinstance(seed_fingerprint, str)
        or re.fullmatch(r"zip32seedfp1[02-9ac-hj-np-z]{58}", seed_fingerprint)
        is None
    ):
        fail("recovery completion seed fingerprint is invalid")
    expected = {
        "mnemonic_staging": str(staging),
        "network": "testnet",
        "release": str(release),
        "schema_version": 1,
        "seed_fingerprint": seed_fingerprint,
        "state": "complete",
    }
    canonical = (
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii")
        + b"\n"
    )
    if marker != expected or raw != canonical:
        fail("recovery completion marker is not canonical or exactly bound")
    if (
        capture_seedfp(original) != seed_fingerprint
        or capture_seedfp(recovered) != seed_fingerprint
    ):
        fail("recovery marker does not bind both authenticated RPC captures")


def main() -> None:
    if len(sys.argv) != 6:
        fail(
            "usage: verify-zec-import-completion.py "
            "<marker> <release> <staging> <original-capture> <recovered-capture>"
        )
    if os.geteuid() != TRUSTED_UID:
        fail("this command must run as root")
    verify(*(pathlib.Path(value) for value in sys.argv[1:]))
    print("verify-zec-import-completion: recovery import binding is valid")


if __name__ == "__main__":
    main()

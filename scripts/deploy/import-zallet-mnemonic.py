#!/usr/bin/env python3
"""Import one Testnet mnemonic through a no-echo PTY into a fresh recovery wallet."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pathlib
import pwd
import re
import resource
import stat
import subprocess
import sys
from typing import NoReturn

import pexpect


TRUSTED_UID = 0
RECOVERY_USER = "zecwec-zallet-recovery"
RECOVERY_GROUP = "zecwec-zallet-recovery"
ORIGINAL_USER = "zecwec-zallet"
POOL_USER = "wcash-pool"
BACKEND_USER = "wcash-pool-backend"
RECOVERY_STATE = pathlib.Path("/var/lib/zecwec-zallet-recovery")
RECOVERY_CONFIG = pathlib.Path("/etc/wcash-pool/zallet-recovery.toml")
CUSTODY_ROOT = pathlib.Path("/var/lib/zecwec-custody")
IMPORT_INTENT = CUSTODY_ROOT / "zec-wallet-recovery-import.intent"
IMPORT_COMPLETE = CUSTODY_ROOT / "zec-wallet-recovery-import.completed"
MAX_MNEMONIC_BYTES = 256


def fail(message: str) -> NoReturn:
    raise SystemExit(f"import-zallet-mnemonic: {message}")


def private_metadata(
    path: pathlib.Path,
    label: str,
    modes: tuple[int, ...],
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> os.stat_result:
    if owner_uid is None:
        owner_uid = TRUSTED_UID
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"{label} is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != owner_uid
        or (owner_gid is not None and metadata.st_gid != owner_gid)
        or stat.S_IMODE(metadata.st_mode) not in modes
        or metadata.st_nlink != 1
    ):
        fail(f"{label} ownership, mode, or link count is unsafe")
    return metadata


def require_private_parent(path: pathlib.Path, label: str) -> None:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError:
        fail(f"{label} parent is unavailable")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or parent.is_symlink()
        or metadata.st_uid != TRUSTED_UID
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        fail(f"{label} parent must be root-owned and private")


def read_mnemonic(path: pathlib.Path) -> str:
    if (
        not path.is_absolute()
        or path.name != "mnemonic.txt"
        or path.parent.parent != CUSTODY_ROOT
        or re.fullmatch(r"zec-[0-9a-f]{7,40}", path.parent.name) is None
    ):
        fail("mnemonic must use the reviewed Testnet custody staging path")
    require_private_parent(path, "mnemonic")
    metadata = private_metadata(path, "mnemonic", (0o400,))
    if metadata.st_size == 0 or metadata.st_size > MAX_MNEMONIC_BYTES:
        fail("mnemonic size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("mnemonic cannot be opened safely")
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_uid != TRUSTED_UID
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_nlink != 1
        ):
            fail("mnemonic changed during validation")
        raw = os.read(descriptor, MAX_MNEMONIC_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_MNEMONIC_BYTES:
        fail("mnemonic exceeds its size limit")
    try:
        phrase = raw.decode("ascii")
    except UnicodeDecodeError:
        fail("mnemonic must be ASCII")
    if phrase.endswith("\n"):
        phrase = phrase[:-1]
    if "\n" in phrase or "\r" in phrase or "\t" in phrase:
        fail("mnemonic must be exactly one line")
    words = phrase.split(" ")
    if len(words) != 24 or any(not word.isalpha() or not word.islower() for word in words):
        fail("mnemonic must contain exactly 24 canonical lowercase words")
    return phrase


def require_recovery_identity() -> tuple[int, int]:
    try:
        users = {
            name: pwd.getpwnam(name)
            for name in (POOL_USER, BACKEND_USER, ORIGINAL_USER, RECOVERY_USER)
        }
        original_group = grp.getgrnam(ORIGINAL_USER)
        recovery_group = grp.getgrnam(RECOVERY_GROUP)
    except KeyError:
        fail("dedicated custody identity is unavailable")
    uids = [user.pw_uid for user in users.values()]
    gids = [user.pw_gid for user in users.values()]
    if (
        any(type(value) is not int or value <= 0 for value in (*uids, *gids))
        or len(set(uids)) != len(uids)
        or len(set(gids)) != len(gids)
    ):
        fail("custody identities must use distinct non-root numeric IDs")
    original = users[ORIGINAL_USER]
    recovery = users[RECOVERY_USER]
    if original.pw_gid != original_group.gr_gid or recovery.pw_gid != recovery_group.gr_gid:
        fail("dedicated wallet identities have unexpected primary groups")
    for name, user in ((ORIGINAL_USER, original), (RECOVERY_USER, recovery)):
        if sorted(set(os.getgrouplist(name, user.pw_gid))) != [user.pw_gid]:
            fail("dedicated wallet identity has unexpected supplementary groups")
    return recovery.pw_uid, recovery_group.gr_gid


def require_no_processes(uid: int, label: str) -> None:
    try:
        result = subprocess.run(
            ["/usr/bin/pgrep", "--uid", str(uid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        fail(f"cannot inspect {label} processes")
    if result.returncode == 0:
        fail(f"{label} has a running process")
    if result.returncode != 1:
        fail(f"cannot prove {label} has no running process")


def require_custody_identities_quiet(recovery_uid: int) -> None:
    try:
        original_uid = pwd.getpwnam(ORIGINAL_USER).pw_uid
    except KeyError:
        fail("original Zallet identity is unavailable")
    require_no_processes(original_uid, "original Zallet identity")
    require_no_processes(recovery_uid, "recovery Zallet identity")


def systemd_value(unit: str, field: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", f"--property={field}", "--value", unit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        fail("cannot inspect custody service state")
    value = result.stdout.strip()
    if not value or "\n" in value:
        fail("custody service state is ambiguous")
    return value


def require_services_inactive() -> None:
    units = {
        "wcash-pool-projector.service": True,
        "wcash-pool.service": True,
        "zecwec-zallet.service": False,
        "zecwec-zallet-recovery.service": False,
        "wcash-pool-zec-authority-bootstrap.service": True,
    }
    for unit, may_be_absent in units.items():
        load_state = systemd_value(unit, "LoadState")
        if load_state == "not-found" and may_be_absent:
            continue
        if load_state != "loaded":
            fail("custody service load state is unsafe")
        expected = {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0"}
        for field, value in expected.items():
            if systemd_value(unit, field) != value:
                fail("custody services must be fully inactive before mnemonic import")


def require_release(release: pathlib.Path) -> pathlib.Path:
    if not release.is_absolute() or release.parent != pathlib.Path("/opt/wcash/releases"):
        fail("release must be one immutable installed release")
    try:
        resolved = release.resolve(strict=True)
    except OSError:
        fail("release is unavailable")
    if resolved != release or not release.is_dir() or release.is_symlink():
        fail("release path is not canonical")
    release_metadata = release.stat()
    if release_metadata.st_uid != TRUSTED_UID or stat.S_IMODE(release_metadata.st_mode) & 0o022:
        fail("release directory ownership or mode is unsafe")
    binary = release / "zallet"
    private_metadata(binary, "Zallet binary", (0o555,))
    try:
        subprocess.run(
            [str(release / "deployment/scripts/deploy/verify-release.sh"), "zallet"],
            env={"PATH": "/usr/bin:/bin", "ZECWEC_RELEASE_PATH": str(release)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        fail("immutable Zallet release verification failed")
    return binary


def require_config() -> None:
    try:
        expected = pwd.getpwnam(RECOVERY_USER)
        expected_group = grp.getgrnam(RECOVERY_GROUP)
    except KeyError:
        fail("dedicated recovery identity is unavailable")
    private_metadata(
        RECOVERY_CONFIG,
        "recovery configuration",
        (0o640,),
        TRUSTED_UID,
        expected_group.gr_gid,
    )


def prepare_empty_state(uid: int, gid: int) -> None:
    if RECOVERY_STATE.exists() or RECOVERY_STATE.is_symlink():
        fail("recovery datadir already exists; destroy and recreate it after review")
    os.mkdir(RECOVERY_STATE, 0o700)
    os.chown(RECOVERY_STATE, uid, gid)


def write_marker(path: pathlib.Path, payload: dict[str, object]) -> None:
    require_private_parent(path, "recovery import marker")
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o400)
    except OSError:
        fail("recovery import marker already exists or is unsafe")
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                fail("cannot write recovery import marker")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_quiet(argv: list[str], timeout: int = 120) -> None:
    try:
        subprocess.run(
            argv,
            env={
                "HOME": str(RECOVERY_STATE),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "RUST_LOG": "off",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        fail("recovery wallet initialization failed; datadir is tainted and must be destroyed")


def import_with_no_echo(binary: pathlib.Path, phrase: str) -> str:
    argv = [
        "--user",
        RECOVERY_USER,
        "--",
        str(binary),
        "--datadir",
        str(RECOVERY_STATE),
        "--config",
        str(RECOVERY_CONFIG),
        "import-mnemonic",
    ]
    child = None
    try:
        child = pexpect.spawn(
            "/usr/sbin/runuser",
            argv,
            env={
                "HOME": str(RECOVERY_STATE),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "RUST_LOG": "off",
            },
            encoding="utf-8",
            echo=False,
            timeout=30,
            logfile=None,
        )
        child.setecho(False)
        if not child.waitnoecho(timeout=5):
            fail("recovery terminal did not disable echo")
        child.expect_exact("Enter mnemonic:", timeout=30)
        if child.before != "":
            fail("mnemonic prompt had unexpected output")
        child.sendline(phrase)
        phrase = ""
        child.expect(
            re.compile(
                r"\r?\nSeed fingerprint: "
                r"(zip32seedfp1[023456789acdefghjklmnpqrstuvwxyz]{58})\r?\n"
            ),
            timeout=120,
        )
        if child.before != "":
            fail("mnemonic import returned unexpected output")
        seed_fingerprint = child.match.group(1)
        child.expect(pexpect.EOF, timeout=120)
        if child.before != "":
            fail("mnemonic import returned trailing output")
        child.close()
        if child.exitstatus != 0 or child.signalstatus is not None:
            fail("mnemonic import failed; datadir is tainted and must be destroyed")
        return seed_fingerprint
    except (pexpect.ExceptionPexpect, OSError):
        fail("mnemonic import failed; datadir is tainted and must be destroyed")
    finally:
        phrase = ""
        if child is not None and child.isalive():
            child.close(force=True)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("release", type=pathlib.Path)
    parser.add_argument("mnemonic", type=pathlib.Path)
    parser.add_argument("--ack-testnet-fresh-recovery", action="store_true")
    args = parser.parse_args()
    if not args.ack_testnet_fresh_recovery:
        fail("explicit Testnet fresh-recovery acknowledgement is required")
    if os.geteuid() != TRUSTED_UID:
        fail("this command must run as root")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require_services_inactive()
    uid, gid = require_recovery_identity()
    require_custody_identities_quiet(uid)
    binary = require_release(args.release)
    require_config()
    phrase = read_mnemonic(args.mnemonic)
    if IMPORT_INTENT.exists() or IMPORT_INTENT.is_symlink() or IMPORT_COMPLETE.exists() or IMPORT_COMPLETE.is_symlink():
        fail("recovery import was already attempted; destroy and review the recovery datadir")
    prepare_empty_state(uid, gid)
    marker_base: dict[str, object] = {
        "mnemonic_staging": str(args.mnemonic.parent),
        "network": "testnet",
        "release": str(args.release),
        "schema_version": 1,
    }
    write_marker(IMPORT_INTENT, {**marker_base, "state": "intent"})
    prefix = ["/usr/sbin/runuser", "--user", RECOVERY_USER, "--", str(binary), "--datadir", str(RECOVERY_STATE), "--config", str(RECOVERY_CONFIG)]
    run_quiet(prefix + ["generate-encryption-identity"])
    run_quiet(prefix + ["init-wallet-encryption"])
    require_custody_identities_quiet(uid)
    seed_fingerprint = import_with_no_echo(binary, phrase)
    phrase = ""
    write_marker(
        IMPORT_COMPLETE,
        {
            **marker_base,
            "seed_fingerprint": seed_fingerprint,
            "state": "complete",
        },
    )
    try:
        IMPORT_INTENT.unlink()
    except OSError:
        fail("recovery import intent could not be cleared after durable completion")
    directory = os.open(CUSTODY_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print("import-zallet-mnemonic: fresh Testnet recovery wallet initialized; mnemonic was not emitted")


if __name__ == "__main__":
    main()

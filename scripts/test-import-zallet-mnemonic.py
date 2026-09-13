#!/usr/bin/env python3
"""Secret-safe unit tests for the isolated Zallet mnemonic import helper."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import pathlib
import re
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).parent / "deploy/import-zallet-mnemonic.py"
SEEDFP = "zip32seedfp1" + "q" * 58
PHRASE = " ".join(["abandon"] * 24)


class FakePexpectError(Exception):
    pass


fake_pexpect = types.ModuleType("pexpect")
fake_pexpect.ExceptionPexpect = FakePexpectError
fake_pexpect.EOF = object()
fake_pexpect.spawn = None
sys.modules["pexpect"] = fake_pexpect
spec = importlib.util.spec_from_file_location("import_zallet_mnemonic", SCRIPT)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
MODULE.TRUSTED_UID = os.getuid()


class FakeMatch:
    def group(self, index: int) -> str:
        if index != 1:
            raise AssertionError("unexpected capture group")
        return SEEDFP


class SuccessfulChild:
    def __init__(self, command: str, argv: list[str], **kwargs: object) -> None:
        self.command = command
        self.argv = argv
        self.kwargs = kwargs
        self.before = ""
        self.match = FakeMatch()
        self.exitstatus = 0
        self.signalstatus = None
        self.sent = ""
        self.expect_count = 0

    def setecho(self, enabled: bool) -> None:
        if enabled:
            raise AssertionError("echo must stay disabled")

    def waitnoecho(self, timeout: int) -> bool:
        return timeout == 5

    def expect_exact(self, prompt: str, timeout: int) -> int:
        if prompt != "Enter mnemonic:" or timeout != 30:
            raise FakePexpectError("unexpected prompt")
        return 0

    def sendline(self, value: str) -> None:
        self.sent = value

    def expect(self, pattern: object, timeout: int) -> int:
        self.expect_count += 1
        if self.expect_count == 1:
            if not isinstance(pattern, re.Pattern) or timeout != 120:
                raise FakePexpectError("unexpected result matcher")
            transcript = f"\r\nSeed fingerprint: {SEEDFP}\r\n"
            if pattern.fullmatch(transcript) is None:
                raise FakePexpectError("result matcher is not anchored")
        elif pattern is not fake_pexpect.EOF or timeout != 120:
            raise FakePexpectError("unexpected EOF matcher")
        self.before = ""
        return 0

    def close(self, force: bool = False) -> None:
        if force:
            raise AssertionError("successful child must not be force-closed")

    def isalive(self) -> bool:
        return False


class ImportHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tempdir.name)
        os.chmod(self.root, 0o700)
        self.custody = self.root / "custody"
        self.custody.mkdir(mode=0o700)
        self.staging = self.custody / "zec-abcdef1"
        self.staging.mkdir(mode=0o700)
        self.mnemonic = self.staging / "mnemonic.txt"
        self._old_custody = MODULE.CUSTODY_ROOT
        MODULE.CUSTODY_ROOT = self.custody

    def tearDown(self) -> None:
        MODULE.CUSTODY_ROOT = self._old_custody
        self.tempdir.cleanup()

    def write_phrase(self, raw: bytes, mode: int = 0o400) -> None:
        self.mnemonic.write_bytes(raw)
        os.chmod(self.mnemonic, mode)

    def test_read_mnemonic_accepts_one_optional_lf(self) -> None:
        for suffix in (b"", b"\n"):
            with self.subTest(suffix=suffix):
                self.mnemonic.unlink(missing_ok=True)
                self.write_phrase(PHRASE.encode("ascii") + suffix)
                self.assertEqual(MODULE.read_mnemonic(self.mnemonic), PHRASE)

    def test_read_mnemonic_rejects_unsafe_shapes(self) -> None:
        bad_values = (
            PHRASE.encode("ascii") + b"\n\n",
            PHRASE.encode("ascii") + b"\r\n",
            PHRASE.replace(" ", "\t", 1).encode("ascii"),
            " ".join(["abandon"] * 25).encode("ascii"),
            ("abandon " * 24).encode("ascii") + b"x" * 100,
        )
        for raw in bad_values:
            with self.subTest(length=len(raw)):
                self.mnemonic.unlink(missing_ok=True)
                self.write_phrase(raw)
                with self.assertRaises(SystemExit):
                    MODULE.read_mnemonic(self.mnemonic)

    def test_read_mnemonic_rejects_mode_symlink_and_hardlink(self) -> None:
        self.write_phrase(PHRASE.encode("ascii"), 0o600)
        with self.assertRaises(SystemExit):
            MODULE.read_mnemonic(self.mnemonic)
        self.mnemonic.unlink()
        target = self.root / "target"
        target.write_text(PHRASE, encoding="ascii")
        os.chmod(target, 0o400)
        self.mnemonic.symlink_to(target)
        with self.assertRaises(SystemExit):
            MODULE.read_mnemonic(self.mnemonic)
        self.mnemonic.unlink()
        os.link(target, self.mnemonic)
        with self.assertRaises(SystemExit):
            MODULE.read_mnemonic(self.mnemonic)

    def test_import_uses_no_echo_minimal_environment_and_no_secret_argv(self) -> None:
        children: list[SuccessfulChild] = []

        def spawn(command: str, argv: list[str], **kwargs: object) -> SuccessfulChild:
            child = SuccessfulChild(command, argv, **kwargs)
            children.append(child)
            return child

        fake_pexpect.spawn = spawn
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = MODULE.import_with_no_echo(pathlib.Path("/release/zallet"), PHRASE)
        self.assertEqual(result, SEEDFP)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(len(children), 1)
        child = children[0]
        self.assertEqual(child.command, "/usr/sbin/runuser")
        self.assertEqual(
            child.argv,
            [
                "--user",
                "zecwec-zallet-recovery",
                "--",
                "/release/zallet",
                "--datadir",
                "/var/lib/zecwec-zallet-recovery",
                "--config",
                "/etc/wcash-pool/zallet-recovery.toml",
                "import-mnemonic",
            ],
        )
        self.assertNotIn(PHRASE, child.command)
        self.assertNotIn(PHRASE, "\0".join(child.argv))
        self.assertNotIn(PHRASE, "\0".join(f"{k}={v}" for k, v in child.kwargs["env"].items()))
        self.assertEqual(child.kwargs["env"]["RUST_LOG"], "off")
        self.assertIsNone(child.kwargs["logfile"])
        self.assertIs(child.kwargs["echo"], False)
        self.assertEqual(child.sent, PHRASE)

    def test_unexpected_child_output_fails_without_emitting_secret(self) -> None:
        class EchoingChild(SuccessfulChild):
            def expect(self, pattern: object, timeout: int) -> int:
                result = super().expect(pattern, timeout)
                if self.expect_count == 1:
                    self.before = PHRASE
                return result

        fake_pexpect.spawn = lambda command, argv, **kwargs: EchoingChild(
            command, argv, **kwargs
        )
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit):
                MODULE.import_with_no_echo(pathlib.Path("/release/zallet"), PHRASE)
        self.assertNotIn(PHRASE, output.getvalue())
        self.assertNotIn(PHRASE, errors.getvalue())

    def test_prompt_mismatch_fails_without_emitting_secret(self) -> None:
        class WrongPromptChild(SuccessfulChild):
            def expect_exact(self, prompt: str, timeout: int) -> int:
                raise FakePexpectError("prompt mismatch")

        fake_pexpect.spawn = lambda command, argv, **kwargs: WrongPromptChild(
            command, argv, **kwargs
        )
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit):
                MODULE.import_with_no_echo(pathlib.Path("/release/zallet"), PHRASE)
        self.assertNotIn(PHRASE, output.getvalue() + errors.getvalue())

    def test_trailing_output_and_nonzero_exit_fail(self) -> None:
        class TrailingChild(SuccessfulChild):
            def expect(self, pattern: object, timeout: int) -> int:
                result = super().expect(pattern, timeout)
                if self.expect_count == 2:
                    self.before = "unexpected trailing output"
                return result

        class NonzeroChild(SuccessfulChild):
            def close(self, force: bool = False) -> None:
                super().close(force)
                self.exitstatus = 1

        for child_type in (TrailingChild, NonzeroChild):
            with self.subTest(child_type=child_type.__name__):
                fake_pexpect.spawn = lambda command, argv, **kwargs: child_type(
                    command, argv, **kwargs
                )
                with self.assertRaises(SystemExit):
                    MODULE.import_with_no_echo(
                        pathlib.Path("/release/zallet"), PHRASE
                    )

    def test_marker_is_canonical_and_create_only(self) -> None:
        marker = self.custody / "marker"
        payload = {
            "mnemonic_staging": str(self.staging),
            "network": "testnet",
            "release": "/opt/wcash/releases/pool-test",
            "schema_version": 1,
            "seed_fingerprint": SEEDFP,
            "state": "complete",
        }
        MODULE.write_marker(marker, payload)
        self.assertEqual(
            marker.read_text(encoding="ascii"),
            '{"mnemonic_staging":"'
            + str(self.staging)
            + '","network":"testnet","release":"/opt/wcash/releases/pool-test",'
            '"schema_version":1,"seed_fingerprint":"'
            + SEEDFP
            + '","state":"complete"}\n',
        )
        self.assertEqual(marker.stat().st_mode & 0o777, 0o400)
        with self.assertRaises(SystemExit):
            MODULE.write_marker(marker, payload)

    def test_run_quiet_sets_no_logging_and_never_passes_phrase(self) -> None:
        with mock.patch.object(MODULE.subprocess, "run") as run:
            MODULE.run_quiet(["/release/zallet", "init-wallet-encryption"])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"]["RUST_LOG"], "off")
        self.assertNotIn(PHRASE, "\0".join(run.call_args.args[0]))
        self.assertNotIn(PHRASE, "\0".join(kwargs["env"].values()))
        self.assertIs(kwargs["stdout"], MODULE.subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], MODULE.subprocess.DEVNULL)

    def test_process_absence_probe_is_fail_closed(self) -> None:
        for returncode, should_pass in ((1, True), (0, False), (2, False), (3, False)):
            with self.subTest(returncode=returncode), mock.patch.object(
                MODULE.subprocess,
                "run",
                return_value=types.SimpleNamespace(returncode=returncode),
            ) as run:
                if should_pass:
                    MODULE.require_no_processes(12345, "test identity")
                else:
                    with self.assertRaises(SystemExit):
                        MODULE.require_no_processes(12345, "test identity")
                self.assertEqual(
                    run.call_args.args[0],
                    ["/usr/bin/pgrep", "--uid", "12345"],
                )
                self.assertFalse(run.call_args.kwargs["check"])

    def test_recovery_identity_requires_distinct_non_root_ids(self) -> None:
        user_ids = {
            "wcash-pool": (1101, 1201),
            "wcash-pool-backend": (1102, 1202),
            "zecwec-zallet": (1103, 1203),
            "zecwec-zallet-recovery": (1104, 1204),
        }

        def passwd(name: str) -> object:
            uid, gid = user_ids[name]
            return types.SimpleNamespace(pw_uid=uid, pw_gid=gid)

        def group(name: str) -> object:
            return types.SimpleNamespace(gr_gid=user_ids[name][1])

        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=passwd), mock.patch.object(
            MODULE.grp, "getgrnam", side_effect=group
        ), mock.patch.object(
            MODULE.os,
            "getgrouplist",
            side_effect=lambda name, gid: [gid],
        ):
            self.assertEqual(MODULE.require_recovery_identity(), (1104, 1204))
            for duplicate_field in ("uid", "gid"):
                with self.subTest(duplicate_field=duplicate_field):
                    original = user_ids["zecwec-zallet-recovery"]
                    source = user_ids["zecwec-zallet"]
                    user_ids["zecwec-zallet-recovery"] = (
                        source[0] if duplicate_field == "uid" else original[0],
                        source[1] if duplicate_field == "gid" else original[1],
                    )
                    with self.assertRaises(SystemExit):
                        MODULE.require_recovery_identity()
                    user_ids["zecwec-zallet-recovery"] = original


if __name__ == "__main__":
    unittest.main()

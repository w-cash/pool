#!/usr/bin/env python3
"""Focused tests for the Zallet recovery-import completion binding."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parent / "deploy/verify-zec-import-completion.py"
spec = importlib.util.spec_from_file_location("verify_zec_import_completion", SCRIPT)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
MODULE.TRUSTED_UID = os.getuid()
SEEDFP = "zip32seedfp1" + "q" * 58


class CompletionBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.marker = self.root / "marker.json"
        self.original = self.root / "original.json"
        self.recovered = self.root / "recovered.json"
        self.release = pathlib.Path("/opt/wcash/releases/pool-test")
        self.staging = pathlib.Path("/var/lib/zecwec-custody/zec-abcdef1")
        capture = {
            "rpc_transcript": {
                "account": {"response": {"result": {"seedfp": SEEDFP}}}
            }
        }
        self.write(self.original, capture)
        self.write(self.recovered, capture)
        self.write_marker()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write(path: pathlib.Path, value: object) -> None:
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        os.chmod(path, 0o400)

    def write_marker(self, **updates: object) -> None:
        value = {
            "mnemonic_staging": str(self.staging),
            "network": "testnet",
            "release": str(self.release),
            "schema_version": 1,
            "seed_fingerprint": SEEDFP,
            "state": "complete",
        }
        value.update(updates)
        self.marker.unlink(missing_ok=True)
        self.write(self.marker, value)

    def verify(self) -> None:
        MODULE.verify(
            self.marker,
            self.release,
            self.staging,
            self.original,
            self.recovered,
        )

    def test_valid_binding_passes(self) -> None:
        self.verify()

    def test_wrong_release_fails(self) -> None:
        self.write_marker(release="/opt/wcash/releases/other")
        with self.assertRaises(SystemExit):
            self.verify()

    def test_wrong_staging_fails(self) -> None:
        self.write_marker(mnemonic_staging="/var/lib/zecwec-custody/zec-fffffff")
        with self.assertRaises(SystemExit):
            self.verify()

    def test_wrong_state_or_extra_field_fails(self) -> None:
        for updates in ({"state": "intent"}, {"unexpected": True}):
            with self.subTest(updates=updates):
                self.write_marker(**updates)
                with self.assertRaises(SystemExit):
                    self.verify()

    def test_capture_fingerprint_mismatch_fails(self) -> None:
        bad = {
            "rpc_transcript": {
                "account": {
                    "response": {"result": {"seedfp": "zip32seedfp1" + "p" * 58}}
                }
            }
        }
        self.recovered.unlink()
        self.write(self.recovered, bad)
        with self.assertRaises(SystemExit):
            self.verify()

    def test_noncanonical_marker_fails(self) -> None:
        value = json.loads(self.marker.read_text(encoding="ascii"))
        self.marker.unlink()
        self.marker.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")
        os.chmod(self.marker, 0o400)
        with self.assertRaises(SystemExit):
            self.verify()

    def test_unsafe_mode_and_hardlink_fail(self) -> None:
        os.chmod(self.marker, 0o600)
        with self.assertRaises(SystemExit):
            self.verify()
        os.chmod(self.marker, 0o400)
        link = self.root / "marker-link"
        os.link(self.marker, link)
        with self.assertRaises(SystemExit):
            self.verify()


if __name__ == "__main__":
    unittest.main()

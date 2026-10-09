#!/usr/bin/env python3
"""Regression tests for the production-manifest semantic validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
VALIDATOR_PATH = ROOT / "scripts" / "validate-production-manifest.py"
SPEC = importlib.util.spec_from_file_location("production_manifest_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
BASE = json.loads((ROOT / "production-manifest.json").read_text(encoding="utf-8"))


class ProductionManifestValidationTests(unittest.TestCase):
    def assert_rejected(self, mutation) -> None:
        document = copy.deepcopy(BASE)
        mutation(document)
        self.assertTrue(VALIDATOR.validate(document))

    def test_repository_manifest_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate(BASE), [])

    def test_live_runtime_claim_cannot_be_committed(self) -> None:
        self.assert_rejected(lambda document: document.update(runtime={"mining_ready": True}))

    def test_undeployed_server_cannot_claim_a_binary(self) -> None:
        self.assert_rejected(
            lambda document: document["manifest_server"].update(binary_sha256="0" * 64)
        )

    def test_deployed_server_requires_complete_identity(self) -> None:
        self.assert_rejected(
            lambda document: document["manifest_server"].update(state="deployed")
        )

    def test_snapshot_timestamp_must_match(self) -> None:
        self.assert_rejected(
            lambda document: document["observed_runtime"].update(
                observed_at="2026-10-09T00:00:00Z"
            )
        )

    def test_zec_policy_cannot_be_advertised_as_automatic(self) -> None:
        self.assert_rejected(
            lambda document: document["payout_policy"]["zec"].update(mode="automatic")
        )

    def test_legacy_route_cannot_claim_account_payouts(self) -> None:
        self.assert_rejected(
            lambda document: document["mining_routes"]["legacy_direct_wolf"].update(
                pool_payouts=True
            )
        )


if __name__ == "__main__":
    unittest.main()

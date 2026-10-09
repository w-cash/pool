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

    def test_mainnet_service_cannot_claim_a_testnet_network(self) -> None:
        self.assert_rejected(
            lambda document: document["networks"]["wcash"].update(network="testnet")
        )

    def test_mainnet_genesis_and_branch_id_are_immutable(self) -> None:
        self.assert_rejected(
            lambda document: document["networks"]["zcash"].update(
                genesis_hash="0" * 64,
                branch_id="0x00000000",
            )
        )

    def test_wcash_auxpow_and_branch_ids_are_immutable(self) -> None:
        self.assert_rejected(
            lambda document: document["networks"]["wcash"].update(
                auxpow_chain_id="0x00000000",
                branch_id="0x00000000",
            )
        )

    def test_legacy_endpoint_must_match_port_3333(self) -> None:
        self.assert_rejected(
            lambda document: document["public_endpoints"].update(
                legacy_direct_wolf="stratum+tcp://evil.example:9999"
            )
        )

    def test_account_endpoints_must_match_ports_3336_and_3338(self) -> None:
        self.assert_rejected(
            lambda document: document["public_endpoints"].update(
                account_pool_asic="stratum+tcp://mainnet.zecwec.com:3338",
                account_pool_gpu_cpu="stratum+tcp://mainnet.zecwec.com:3336",
            )
        )

    def test_automatic_wec_policy_requires_the_isolated_worker(self) -> None:
        self.assert_rejected(
            lambda document: document["payout_policy"]["wec"].update(
                executor="manual operator"
            )
        )

    def test_manual_zec_policy_cannot_claim_a_live_worker(self) -> None:
        self.assert_rejected(
            lambda document: document["observed_runtime"]["zec"].update(
                worker_live=True
            )
        )

    def test_pool_source_tree_is_bound_to_the_observed_binary(self) -> None:
        self.assert_rejected(
            lambda document: document["observed_deployment"]["pool"].update(
                source_tree="0" * 40
            )
        )

    def test_wolf_backend_identity_is_exact_and_well_formed(self) -> None:
        self.assert_rejected(
            lambda document: document["observed_deployment"]["wolf"][
                "merged_mining_backend"
            ].update(binary_sha256="untrusted")
        )

    def test_wcash_node_tree_and_binary_are_exact(self) -> None:
        self.assert_rejected(
            lambda document: document["observed_deployment"]["wolf"][
                "wcash_node"
            ].update(source_tree="f" * 40, binary_sha256="f" * 64)
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Validate the static ZecWec production-evidence contract."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_OBSERVED_DEPLOYMENT = {
    "deployment_id": "af99f42c-f66d-4332-acd2-8eebbe154da0",
    "configuration_revision": "af99f42c-f66d-4332-acd2-8eebbe154da0",
    "configuration_revision_kind": "deployment_id",
    "pool": {
        "repository": "https://github.com/w-cash/pool",
        "source_commit": "49bcc0570a4b9eabf0134d8a3b47cfdef7edf8f8",
        "source_tree": "bed40f1e03dd19d34313db3c86366d2c7113a8ec",
        "binary_sha256": "e25ca32aa086fab945f3171e5ff5976cedf55871a7f13b0478a307464bf2dcfd",
    },
    "wolf": {
        "repository": "https://github.com/w-cash/wolf",
        "merged_mining_backend": {
            "source_commit": "1ecc5a4d611ad0cc4aa97e8cf1417345a4368e15",
            "source_tree": "7610768fc48bd2421dcd8061e7a2312d29bbc8e4",
            "binary_sha256": "7a195ff9b1262162959942869bde7410e1a5b12dab4d7d46fbd138ba220f1339",
        },
        "wcash_node": {
            "source_commit": None,
            "source_base_commit": "89ddd34cf1a4ec7b841130829c6b3b971099bb6e",
            "source_tree": "7bbf7936ae3cc32cf5a9655f578029f0efd41ba7",
            "source_tree_sha256": "615897da3027199d5b965bd951690e1f81286c7e20432c01e0c3c61a53d5d91e",
            "binary_sha256": "7aed40427d7165d3af561af5c462df41dbced0895075be3b10702c253bc17b88",
            "provenance": (
                "source copy without Git metadata; base commit and exact source-tree "
                "digests are recorded"
            ),
        },
    },
}
EXPECTED_NETWORKS = {
    "wcash": {
        "network": "mainnet",
        "genesis_hash": "5bae12c8662a577b04ce1591af1a137c128f0cb51018a5f1622d861d1bb6fc48",
        "auxpow_chain_id": "0x57434153",
        "branch_id": "0xd9c6a7ee",
    },
    "zcash": {
        "network": "mainnet",
        "genesis_hash": "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
        "branch_id": "0x37a5165b",
    },
}
EXPECTED_ENDPOINTS = {
    "portal": "https://pool.zecwec.com/",
    "readiness": "https://pool.zecwec.com/readyz",
    "production_manifest": "https://pool.zecwec.com/api/v1/production-manifest",
    "legacy_direct_wolf": "stratum+tcp://mainnet.zecwec.com:3333",
    "account_pool_asic": "stratum+tcp://mainnet.zecwec.com:3336",
    "account_pool_gpu_cpu": "stratum+tcp://mainnet.zecwec.com:3338",
}
EXPECTED_MINING_ROUTES = {
    "legacy_direct_wolf": {
        "port": 3333,
        "account_ledger": False,
        "pplns": False,
        "pool_payouts": False,
    },
    "account_pool": {
        "asic_port": 3336,
        "gpu_cpu_port": 3338,
        "account_ledger": True,
        "pplns": True,
    },
}
EXPECTED_PAYOUT_POLICY = {
    "wec": {
        "mode": "automatic",
        "executor": "isolated payout worker",
    },
    "zec": {
        "mode": "manual",
        "executor": "operator settlement after an accepted Zcash block",
    },
}


def validate(manifest: Any) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    def require_exact_object(actual: Any, expected: dict[str, Any], path: str) -> None:
        require(isinstance(actual, dict), f"{path} must be an object")
        if not isinstance(actual, dict):
            return
        require(set(actual) == set(expected), f"{path} fields changed")
        for key, expected_value in expected.items():
            actual_value = actual.get(key)
            field_path = f"{path}.{key}"
            if isinstance(expected_value, dict):
                require_exact_object(actual_value, expected_value, field_path)
            else:
                require(actual_value == expected_value, f"{field_path} changed")

    def require_hash(
        container: Any,
        field: str,
        pattern: re.Pattern[str],
        path: str,
    ) -> None:
        value = container.get(field) if isinstance(container, dict) else None
        require(
            isinstance(value, str) and pattern.fullmatch(value) is not None,
            f"{path}.{field} has an invalid hash format",
        )

    require(isinstance(manifest, dict), "manifest root must be an object")
    if not isinstance(manifest, dict):
        return errors

    require(manifest.get("schema_version") == 2, "schema_version must be 2")
    require(manifest.get("service") == "ZecWec Mainnet", "service identity changed")
    require(
        manifest.get("evidence_scope") == "observed production snapshot; not a live heartbeat",
        "evidence_scope must identify the document as a snapshot",
    )
    require("runtime" not in manifest, "live runtime state must be added by the endpoint")
    for obsolete in ("deployment", "registration", "mining", "payouts"):
        require(obsolete not in manifest, f"obsolete live-looking field is forbidden: {obsolete}")

    server = manifest.get("manifest_server")
    require(isinstance(server, dict), "manifest_server must be an object")
    if isinstance(server, dict):
        state = server.get("state")
        require(state in {"not_deployed", "deployed"}, "manifest_server.state is invalid")
        if state == "not_deployed":
            for field in ("source_commit", "build_id", "binary_sha256"):
                require(server.get(field) is None, f"not-deployed manifest_server.{field} must be null")
        elif state == "deployed":
            require(
                isinstance(server.get("source_commit"), str)
                and HEX40.fullmatch(server["source_commit"]) is not None,
                "deployed manifest_server.source_commit must be a full Git commit",
            )
            require(
                isinstance(server.get("build_id"), str) and bool(server["build_id"].strip()),
                "deployed manifest_server.build_id must be non-empty",
            )
            require(
                isinstance(server.get("binary_sha256"), str)
                and HEX64.fullmatch(server["binary_sha256"]) is not None,
                "deployed manifest_server.binary_sha256 must be a SHA-256 digest",
            )

    deployment = manifest.get("observed_deployment")
    require_exact_object(
        deployment,
        EXPECTED_OBSERVED_DEPLOYMENT,
        "observed_deployment",
    )
    if isinstance(deployment, dict):
        pool = deployment.get("pool")
        wolf = deployment.get("wolf")
        backend = wolf.get("merged_mining_backend") if isinstance(wolf, dict) else None
        wcash_node = wolf.get("wcash_node") if isinstance(wolf, dict) else None
        for field in ("source_commit", "source_tree"):
            require_hash(pool, field, HEX40, "observed_deployment.pool")
        require_hash(pool, "binary_sha256", HEX64, "observed_deployment.pool")
        for field in ("source_commit", "source_tree"):
            require_hash(
                backend,
                field,
                HEX40,
                "observed_deployment.wolf.merged_mining_backend",
            )
        require_hash(
            backend,
            "binary_sha256",
            HEX64,
            "observed_deployment.wolf.merged_mining_backend",
        )
        for field in ("source_base_commit", "source_tree"):
            require_hash(
                wcash_node,
                field,
                HEX40,
                "observed_deployment.wolf.wcash_node",
            )
        for field in ("source_tree_sha256", "binary_sha256"):
            require_hash(
                wcash_node,
                field,
                HEX64,
                "observed_deployment.wolf.wcash_node",
            )

    networks = manifest.get("networks")
    require_exact_object(networks, EXPECTED_NETWORKS, "networks")
    if isinstance(networks, dict):
        wcash_network = networks.get("wcash")
        zcash_network = networks.get("zcash")
        require_hash(wcash_network, "genesis_hash", HEX64, "networks.wcash")
        require_hash(zcash_network, "genesis_hash", HEX64, "networks.zcash")

    policy = manifest.get("payout_policy")
    require_exact_object(policy, EXPECTED_PAYOUT_POLICY, "payout_policy")

    observed = manifest.get("observed_runtime")
    require(isinstance(observed, dict), "observed_runtime must be an object")
    if isinstance(observed, dict):
        portal_runtime = observed.get("portal")
        wec_runtime = observed.get("wec")
        zec_runtime = observed.get("zec")
        require(observed.get("kind") == "snapshot", "observed_runtime.kind must be snapshot")
        require(
            observed.get("observed_at") == manifest.get("recorded_at"),
            "observed_runtime timestamp must match recorded_at",
        )
        require(
            isinstance(observed.get("registration_open"), bool),
            "observed registration state must be boolean",
        )
        require(
            isinstance(observed.get("mining_ready"), bool),
            "observed mining readiness must be boolean",
        )
        require(isinstance(portal_runtime, dict), "observed portal state must be an object")
        require(isinstance(wec_runtime, dict), "observed WEC state must be an object")
        require(isinstance(zec_runtime, dict), "observed ZEC state must be an object")
        if isinstance(portal_runtime, dict):
            require(
                portal_runtime.get("payout_execution") == "deferred",
                "observed portal payout execution must be deferred",
            )
        if isinstance(wec_runtime, dict):
            require(
                isinstance(wec_runtime.get("worker_live"), bool),
                "observed WEC worker state must be boolean",
            )
        if isinstance(zec_runtime, dict):
            require(
                zec_runtime.get("worker_live") is None,
                "observed ZEC worker state must be null while policy is manual",
            )

    routes = manifest.get("mining_routes")
    require_exact_object(routes, EXPECTED_MINING_ROUTES, "mining_routes")

    endpoints = manifest.get("public_endpoints")
    require_exact_object(endpoints, EXPECTED_ENDPOINTS, "public_endpoints")
    if isinstance(endpoints, dict) and isinstance(routes, dict):
        legacy = routes.get("legacy_direct_wolf")
        account = routes.get("account_pool")
        if isinstance(legacy, dict):
            require(
                endpoints.get("legacy_direct_wolf")
                == f"stratum+tcp://mainnet.zecwec.com:{legacy.get('port')}",
                "legacy endpoint does not match the legacy mining route",
            )
        if isinstance(account, dict):
            require(
                endpoints.get("account_pool_asic")
                == f"stratum+tcp://mainnet.zecwec.com:{account.get('asic_port')}",
                "ASIC endpoint does not match the account mining route",
            )
            require(
                endpoints.get("account_pool_gpu_cpu")
                == f"stratum+tcp://mainnet.zecwec.com:{account.get('gpu_cpu_port')}",
                "GPU/CPU endpoint does not match the account mining route",
            )

    limitations = manifest.get("known_limitations")
    require(isinstance(limitations, list) and bool(limitations), "known_limitations must be non-empty")
    if isinstance(limitations, list):
        identifiers = [
            item.get("id")
            for item in limitations
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ]
        require(len(identifiers) == len(limitations), "every limitation must have a string id")
        require(len(set(identifiers)) == len(identifiers), "limitation ids must be unique")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"production-manifest: cannot read valid JSON: {error}")
        return 1
    errors = validate(document)
    if errors:
        for error in errors:
            print(f"production-manifest: {error}")
        return 1
    print("production-manifest: validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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


def validate(manifest: Any) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

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
    require(isinstance(deployment, dict), "observed_deployment must be an object")
    if isinstance(deployment, dict):
        pool = deployment.get("pool", {})
        require(
            isinstance(pool, dict)
            and isinstance(pool.get("source_commit"), str)
            and HEX40.fullmatch(pool["source_commit"]) is not None,
            "observed pool source_commit must be a full Git commit",
        )
        require(
            isinstance(pool, dict)
            and isinstance(pool.get("binary_sha256"), str)
            and HEX64.fullmatch(pool["binary_sha256"]) is not None,
            "observed pool binary_sha256 must be a SHA-256 digest",
        )

    policy = manifest.get("payout_policy")
    require(isinstance(policy, dict), "payout_policy must be an object")
    if isinstance(policy, dict):
        wec_policy = policy.get("wec")
        zec_policy = policy.get("zec")
        require(isinstance(wec_policy, dict), "WEC payout policy must be an object")
        require(isinstance(zec_policy, dict), "ZEC payout policy must be an object")
        if isinstance(wec_policy, dict):
            require(wec_policy.get("mode") == "automatic", "WEC policy must be automatic")
        if isinstance(zec_policy, dict):
            require(zec_policy.get("mode") == "manual", "ZEC policy must remain manual")

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
    require(isinstance(routes, dict), "mining_routes must be an object")
    if isinstance(routes, dict):
        legacy = routes.get("legacy_direct_wolf")
        account = routes.get("account_pool")
        require(isinstance(legacy, dict), "legacy Wolf route must be an object")
        require(isinstance(account, dict), "account pool route must be an object")
        if isinstance(legacy, dict):
            require(legacy.get("port") == 3333, "legacy Wolf port must be 3333")
            for capability in ("account_ledger", "pplns", "pool_payouts"):
                require(legacy.get(capability) is False, f"legacy Wolf {capability} must be false")
        if isinstance(account, dict):
            require(account.get("asic_port") == 3336, "account ASIC port must be 3336")
            require(account.get("gpu_cpu_port") == 3338, "account GPU/CPU port must be 3338")
            require(account.get("account_ledger") is True, "account route must use the ledger")
            require(account.get("pplns") is True, "account route must use PPLNS")

    endpoints = manifest.get("public_endpoints")
    require(isinstance(endpoints, dict), "public_endpoints must be an object")
    if isinstance(endpoints, dict):
        require(
            endpoints.get("production_manifest")
            == "https://pool.zecwec.com/api/v1/production-manifest",
            "production manifest endpoint changed",
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

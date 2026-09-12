#!/usr/bin/env python3
"""Bind an independently restored Wcash wallet to its frozen authority."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys
import uuid
from typing import NoReturn


ATTESTATION_SCHEMA_VERSION = 1
AUTHORITY_SCHEMA_VERSION = 1
SUCCESS_PROTOCOL_VERSION = 2
WCASH_TESTNET_BRANCH_ID = "b3cfd27e"
WCASH_TESTNET_GENESIS = "0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"verify-wcash-wallet-recovery: {message}")


def read_object(path: str, label: str) -> dict:
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail(f"{label} is unavailable or invalid")
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value


def canonical_json(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_authority(value: dict) -> None:
    required = {
        "schema_version",
        "network",
        "genesis_hash",
        "branch_id",
        "account_id",
        "collector_payout_commitment",
        "collector_address",
        "transparent_coinbase_address",
        "birthday_height",
        "fund_source",
        "synchronized",
        "initial_balances_zero",
    }
    if set(value) != required:
        fail("wallet authority has an unexpected schema")
    try:
        account = uuid.UUID(value["account_id"])
    except (AttributeError, TypeError, ValueError):
        fail("wallet authority account is invalid")
    if account.int == 0 or str(account) != value["account_id"]:
        fail("wallet authority account is not canonical")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != AUTHORITY_SCHEMA_VERSION
        or value["network"] != "testnet"
        or value["genesis_hash"] != WCASH_TESTNET_GENESIS
        or value["branch_id"] != WCASH_TESTNET_BRANCH_ID
        or not isinstance(value["collector_payout_commitment"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["collector_payout_commitment"]) is None
        or int(value["collector_payout_commitment"], 16) == 0
        or type(value["birthday_height"]) is not int
        or not 1 <= value["birthday_height"] <= 0xFFFF_FFFF
        or value["fund_source"] != "ironwood"
        or value["synchronized"] is not True
        or value["initial_balances_zero"] is not True
    ):
        fail("wallet authority differs from the reviewed Testnet policy")
    for field in ("collector_address", "transparent_coinbase_address"):
        address = value[field]
        if (
            not isinstance(address, str)
            or not 8 <= len(address) <= 512
            or any(character.isspace() for character in address)
        ):
            fail("wallet authority contains an invalid address")


def validate_recovery(authority: dict, initialized: dict, identity: dict) -> None:
    initialized_fields = {
        "account_id",
        "birthday_height",
        "address",
        "transparent_coinbase_address",
        "created",
    }
    identity_fields = {
        "protocol_version",
        "network",
        "genesis_hash",
        "branch_id",
        "account_id",
        "collector_payout_commitment",
        "fund_source",
        "synchronized",
    }
    if set(initialized) != initialized_fields or set(identity) != identity_fields:
        fail("restored wallet output has an unexpected schema")
    if (
        initialized["created"] is not True
        or type(initialized["birthday_height"]) is not int
        or not isinstance(initialized["account_id"], str)
        or any(
            not isinstance(initialized[field], str)
            for field in ("address", "transparent_coinbase_address")
        )
    ):
        fail("recovery did not use a fresh isolated wallet database")
    expected_initialized = {
        "account_id": authority["account_id"],
        "birthday_height": authority["birthday_height"],
        "address": authority["collector_address"],
        "transparent_coinbase_address": authority["transparent_coinbase_address"],
    }
    if any(initialized[field] != expected for field, expected in expected_initialized.items()):
        fail("restored wallet account differs from the frozen authority")
    expected_identity = {
        "protocol_version": SUCCESS_PROTOCOL_VERSION,
        "network": authority["network"],
        "genesis_hash": authority["genesis_hash"],
        "branch_id": authority["branch_id"],
        "account_id": authority["account_id"],
        "collector_payout_commitment": authority["collector_payout_commitment"],
        "fund_source": authority["fund_source"],
        "synchronized": True,
    }
    if (
        type(identity["protocol_version"]) is not int
        or identity["synchronized"] is not True
        or identity != expected_identity
    ):
        fail("restored wallet identity differs from the frozen authority")


def binding(authority: dict) -> dict:
    return {
        "network": authority["network"],
        "genesis_hash": authority["genesis_hash"],
        "branch_id": authority["branch_id"],
        "account_id": authority["account_id"],
        "collector_payout_commitment": authority["collector_payout_commitment"],
        "collector_address": authority["collector_address"],
        "transparent_coinbase_address": authority["transparent_coinbase_address"],
        "birthday_height": authority["birthday_height"],
        "fund_source": authority["fund_source"],
    }


def expected_attestation(authority: dict) -> dict:
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "network": "testnet",
        "authority_sha256": sha256(canonical_json(authority)),
        "collector_binding_sha256": sha256(canonical_json(binding(authority))),
        "fresh_isolated_recovery_verified": True,
        "offline_backup_recovery_acknowledged": True,
    }


def write_once(path: str, value: dict) -> None:
    target = pathlib.Path(path)
    serialized = canonical_json(value)
    if target.exists():
        try:
            existing = target.read_bytes()
        except OSError:
            fail("existing recovery attestation cannot be read")
        if existing != serialized:
            fail("existing recovery attestation differs")
        return
    temporary = target.with_name(f".{target.name}.new.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    if len(sys.argv) == 6 and sys.argv[1] == "seal":
        authority = read_object(sys.argv[2], "wallet authority")
        initialized = read_object(sys.argv[3], "restored wallet initialization")
        identity = read_object(sys.argv[4], "restored wallet identity")
        validate_authority(authority)
        validate_recovery(authority, initialized, identity)
        write_once(sys.argv[5], expected_attestation(authority))
        return
    if len(sys.argv) == 4 and sys.argv[1] == "verify":
        authority = read_object(sys.argv[2], "wallet authority")
        attestation = read_object(sys.argv[3], "recovery attestation")
        validate_authority(authority)
        if attestation != expected_attestation(authority):
            fail("recovery attestation does not bind the frozen authority")
        return
    fail(
        "usage: verify-wcash-wallet-recovery.py "
        "seal <authority> <recovery-init> <recovery-identity> <attestation> | "
        "verify <authority> <attestation>"
    )


if __name__ == "__main__":
    main()

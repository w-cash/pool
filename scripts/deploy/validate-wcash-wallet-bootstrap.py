#!/usr/bin/env python3
"""Validate and freeze the exact Wcash payout-wallet bootstrap authority."""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import uuid
from typing import NoReturn


# Wolf 8090bd0 and wcash-poold speak version 2 for every successful payout
# identity, payout request/response, and wallet-observation message. The CLI's
# version-1 error envelope is a separate failure-only protocol.
WCASH_WALLET_SUCCESS_PROTOCOL_VERSION = 2
AUTHORITY_SCHEMA_VERSION = 1
DISCOVERY_SENTINEL = "BOOTSTRAP_DISCOVERY_REQUIRED"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"validate-wcash-wallet-bootstrap: {message}")


def read_json(path: str, label: str) -> dict:
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{label} output is invalid: {error}")
    if not isinstance(value, dict):
        fail(f"{label} output is not an object")
    return value


def main() -> None:
    if len(sys.argv) != 9:
        fail(
            "usage: validate-wcash-wallet-bootstrap.py "
            "<init-json> <balance-json> <identity-json> <authority-json> "
            "<birthday> <genesis> <account-or-discovery> "
            "<commitment-or-discovery>"
        )

    (
        init_path,
        balance_path,
        identity_path,
        authority_path,
        expected_birthday,
        expected_genesis,
        expected_account,
        expected_commitment,
    ) = sys.argv[1:]

    initialized = read_json(init_path, "wallet initialization")
    required_initialized = {
        "account_id",
        "birthday_height",
        "address",
        "transparent_coinbase_address",
        "created",
    }
    if set(initialized) != required_initialized:
        fail("wallet initialization output has an unexpected schema")

    identity = read_json(identity_path, "wallet identity")
    required_identity = {
        "protocol_version",
        "network",
        "genesis_hash",
        "branch_id",
        "account_id",
        "collector_payout_commitment",
        "fund_source",
        "synchronized",
    }
    if set(identity) != required_identity:
        fail("wallet identity output has an unexpected schema")

    try:
        account = uuid.UUID(initialized["account_id"])
    except (AttributeError, TypeError, ValueError):
        fail("wallet account identifier is invalid")
    if account.int == 0 or str(account) != initialized["account_id"]:
        fail("wallet account identifier is not canonical")
    if identity["account_id"] != str(account):
        fail("wallet initialization and payout identity accounts differ")
    if (
        type(initialized["birthday_height"]) is not int
        or initialized["birthday_height"] != int(expected_birthday, 10)
    ):
        fail("wallet birthday differs from the rendered policy")
    if not isinstance(initialized["created"], bool):
        fail("wallet initialization creation marker is invalid")
    for address_key in ("address", "transparent_coinbase_address"):
        address = initialized[address_key]
        if not isinstance(address, str) or not address or len(address) > 512:
            fail("wallet initialization returned an invalid address")

    commitment = identity["collector_payout_commitment"]
    if (
        type(identity["protocol_version"]) is not int
        or identity["protocol_version"] != WCASH_WALLET_SUCCESS_PROTOCOL_VERSION
        or identity["network"] != "testnet"
        or identity["genesis_hash"] != expected_genesis
        or not isinstance(identity["branch_id"], str)
        or re.fullmatch(r"[0-9a-f]{8}", identity["branch_id"]) is None
        or identity["fund_source"] != "ironwood"
        or identity["synchronized"] is not True
        or not isinstance(commitment, str)
        or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
        or int(commitment, 16) == 0
    ):
        fail("wallet payout identity differs from the reviewed Testnet policy")
    if expected_account != DISCOVERY_SENTINEL and str(account) != expected_account:
        fail("wallet account differs from the reviewed signer account")
    if expected_commitment != DISCOVERY_SENTINEL and commitment != expected_commitment:
        fail("wallet commitment differs from the reviewed payout commitment")

    balance = read_json(balance_path, "wallet balance")
    required_balance = {
        "chain_tip_height",
        "fully_scanned_height",
        "synchronized",
        "accounts",
    }
    if set(balance) != required_balance:
        fail("wallet balance output has an unexpected schema")
    if (
        type(balance["chain_tip_height"]) is not int
        or balance["chain_tip_height"] < 0
        or type(balance["fully_scanned_height"]) is not int
        or balance["fully_scanned_height"] != balance["chain_tip_height"]
        or balance["synchronized"] is not True
        or not isinstance(balance["accounts"], list)
        or len(balance["accounts"]) != 1
    ):
        fail("wallet is not synchronized to one exact account")

    account_balance = balance["accounts"][0]
    value_fields = {
        "ironwood_total_zat",
        "ironwood_spendable_zat",
        "ironwood_locked_zat",
        "ironwood_pending_change_zat",
        "ironwood_pending_spendability_zat",
        "sapling_total_zat",
        "orchard_total_zat",
        "transparent_total_zat",
        "transparent_coinbase_total_zat",
        "transparent_coinbase_spendable_zat",
        "transparent_coinbase_pending_zat",
        "transparent_regular_total_zat",
    }
    if not isinstance(account_balance, dict) or set(account_balance) != value_fields | {
        "account_id"
    }:
        fail("wallet account balance has an unexpected schema")
    if account_balance["account_id"] != str(account):
        fail("wallet balance belongs to a different account")
    if any(
        type(account_balance[field]) is not int or account_balance[field] < 0
        for field in value_fields
    ):
        fail("wallet balance contains an invalid value")
    non_ironwood_fields = {
        "sapling_total_zat",
        "orchard_total_zat",
        "transparent_total_zat",
        "transparent_coinbase_total_zat",
        "transparent_coinbase_spendable_zat",
        "transparent_coinbase_pending_zat",
        "transparent_regular_total_zat",
    }
    if any(account_balance[field] != 0 for field in non_ironwood_fields):
        fail("collector contains value outside the direct Ironwood pool")

    authority = {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "network": "testnet",
        "genesis_hash": expected_genesis,
        "branch_id": identity["branch_id"],
        "account_id": str(account),
        "collector_payout_commitment": commitment,
        "collector_address": initialized["address"],
        "transparent_coinbase_address": initialized["transparent_coinbase_address"],
        "birthday_height": initialized["birthday_height"],
        "fund_source": "ironwood",
        "synchronized": True,
        "initial_balances_zero": True,
    }
    target = pathlib.Path(authority_path)
    serialized = json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n"
    if target.exists():
        try:
            existing = target.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail(f"existing wallet authority cannot be read: {error}")
        if existing != serialized:
            fail("existing wallet authority differs; manual recovery is required")
    else:
        if any(account_balance[field] != 0 for field in value_fields):
            fail("new collector is not a fresh, completely empty wallet account")
        temporary = target.with_name(f".{target.name}.new.{os.getpid()}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
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
    sys.stdout.write(serialized)


if __name__ == "__main__":
    main()

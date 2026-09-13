#!/usr/bin/env python3
"""Capture and verify one independently recovered Zcash Testnet collector."""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid
from typing import NoReturn


ATTESTATION_SCHEMA_VERSION = 3
CAPTURE_SCHEMA_VERSION = 3
TRUSTED_UID = 0
ZCASH_TESTNET_GENESIS = (
    "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
)
ZCASH_NU6_3_BRANCH_ID = "37a5165b"
PAYOUT_COMMITMENT_DOMAIN = b"Wcash/Zcash parent payout address/v1\0"
ACCOUNT_NAME = "ZecWec Testnet collector"
DEFAULT_RECEIVER_TYPES = ("orchard", "sapling", "p2pkh")
MAX_DIVERSIFIER_INDEX = 2**88 - 1
BECH32M_RESIDUE = 0x2BC830A3
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_VALUES = {character: index for index, character in enumerate(BECH32_CHARSET)}
MAX_INPUT_BYTES = 262_144
MAX_RPC_BYTES = 131_072
RPC_CALL_TIMEOUT = 30.0
SYNC_DEADLINE_SECONDS = 1_080.0

CHAIN_SETTING_FIELDS = {"ZCASH_GENESIS_DISPLAY", "ZCASH_GENESIS_WIRE"}
FINAL_SETTING_FIELDS = CHAIN_SETTING_FIELDS | {
    "ZCASH_SIGNER_ACCOUNT",
    "ZCASH_SIGNER_ACCOUNT_INDEX",
    "ZCASH_PAYOUT_COMMITMENT_WIRE",
}
CAPTURE_FIELDS = {
    "schema_version",
    "capture_kind",
    "network",
    "genesis_hash",
    "consensus_branch_id",
    "capture_nonce",
    "birthday_height",
    "rpc_transcript",
}
TRANSCRIPT_FIELDS = {
    "pre_status",
    "pre_accounts",
    "account_operation",
    "account_before_collector",
    "default_address",
    "derived_address",
    "account",
    "accounts",
    "post_status",
}
PORTABLE_FIELDS = (
    "seedfp",
    "zip32_account_index",
    "birthday_height",
    "default_diversifier_index",
    "default_unified_address",
    "diversifier_index",
    "receiver_types",
    "unified_address",
    "collector_payout_commitment",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"verify-zec-wallet-recovery: {message}")


def require_root() -> None:
    if os.geteuid() != 0:
        fail("this ceremony must run as root")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > maximum:
        fail("input exceeds its size limit")
    return value


def read_private_regular(
    path: str, label: str, allowed_modes: tuple[int, ...] = (0o400, 0o600)
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"{label} is unavailable or unsafe")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID
            or stat.S_IMODE(metadata.st_mode) not in allowed_modes
            or metadata.st_nlink != 1
        ):
            fail(f"{label} ownership, mode, or link count is unsafe")
        return read_descriptor(descriptor, MAX_INPUT_BYTES)
    except OSError:
        fail(f"{label} cannot be read")
    finally:
        os.close(descriptor)


def reject_constant(_value: str) -> NoReturn:
    fail("JSON contains a non-finite number")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            fail("JSON contains a duplicate object key")
        value[key] = item
    return value


def parse_json(raw: bytes, label: str) -> object:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError):
        fail(f"{label} is invalid JSON")


def read_object(path: str, label: str) -> dict:
    value = parse_json(read_private_regular(path, label), label)
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value


def read_settings(path: str, final: bool) -> dict[str, str]:
    try:
        text = read_private_regular(path, "deployment settings").decode(
            "utf-8", errors="strict"
        )
    except UnicodeError:
        fail("deployment settings are not UTF-8")
    values: dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"deployment settings line {line_number} has no '='")
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None:
            fail(f"deployment settings line {line_number} has an invalid key")
        if key in values:
            fail(f"deployment setting is duplicated: {key}")
        if not value or value != value.strip() or any(ord(char) < 0x20 for char in value):
            fail(f"deployment setting is empty or contains control whitespace: {key}")
        values[key] = value
    required = FINAL_SETTING_FIELDS if final else CHAIN_SETTING_FIELDS
    missing = sorted(required - values.keys())
    if missing:
        fail(f"deployment settings are missing: {', '.join(missing)}")
    selected = {key: values[key] for key in required}
    if selected["ZCASH_GENESIS_DISPLAY"] != ZCASH_TESTNET_GENESIS:
        fail("deployment settings are not pinned to Zcash Testnet genesis")
    wire = selected["ZCASH_GENESIS_WIRE"]
    if (
        re.fullmatch(r"[0-9a-f]{64}", wire) is None
        or bytes.fromhex(ZCASH_TESTNET_GENESIS)[::-1] != bytes.fromhex(wire)
    ):
        fail("deployment Zcash genesis byte orders disagree")
    if final:
        validate_uuid(selected["ZCASH_SIGNER_ACCOUNT"], "configured collector account")
        index = parse_canonical_decimal(
            selected["ZCASH_SIGNER_ACCOUNT_INDEX"], "configured ZIP-32 account index"
        )
        if not 0 <= index < 2**31:
            fail("configured ZIP-32 account index is outside its safe range")
        commitment = selected["ZCASH_PAYOUT_COMMITMENT_WIRE"]
        if re.fullmatch(r"[0-9a-f]{64}", commitment) is None or int(commitment, 16) == 0:
            fail("configured Zcash payout commitment is invalid")
    return selected


def parse_canonical_decimal(value: object, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        fail(f"{label} is not a canonical decimal integer")
    return int(value, 10)


def validate_uuid(value: object, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} is not a UUID string")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        fail(f"{label} is invalid")
    if parsed.int == 0 or str(parsed) != value:
        fail(f"{label} is not a canonical nonzero UUID")
    return value


def validate_seedfp(value: object) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"zip32seedfp1[02-9ac-hj-np-z]{58}", value) is None
        or value != value.lower()
    ):
        fail("ZIP-32 seed fingerprint is not canonical")
    hrp, encoded_text = value.rsplit("1", 1)
    try:
        encoded = [BECH32_VALUES[character] for character in encoded_text]
    except KeyError:
        fail("ZIP-32 seed fingerprint contains an invalid Bech32m character")
    if bech32_polymod(hrp_expand(hrp) + encoded) != BECH32M_RESIDUE:
        fail("ZIP-32 seed fingerprint checksum is invalid")
    if len(convert_bits(encoded[:-6], 5, 8, False)) != 32:
        fail("ZIP-32 seed fingerprint does not encode exactly 32 bytes")
    return value


def bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        high = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (high >> index) & 1:
                checksum ^= generator
    return checksum


def hrp_expand(hrp: str) -> list[int]:
    return [ord(character) >> 5 for character in hrp] + [0] + [
        ord(character) & 31 for character in hrp
    ]


def convert_bits(
    values: list[int], from_bits: int, to_bits: int, pad: bool
) -> bytes:
    accumulator = 0
    bits = 0
    result = bytearray()
    maximum = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            fail("Bech32m data contains an invalid value")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & maximum)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & maximum)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & maximum):
        fail("Bech32m data has non-canonical padding")
    return bytes(result)


def validate_tip(value: object, label: str) -> tuple[int, str]:
    if not isinstance(value, dict) or set(value) != {"height", "blockhash"}:
        fail(f"{label} has an unexpected schema")
    height = value["height"]
    blockhash = value["blockhash"]
    if type(height) is not int or not 0 < height <= 0xFFFF_FFFF:
        fail(f"{label} height is invalid")
    if (
        not isinstance(blockhash, str)
        or re.fullmatch(r"[0-9a-f]{64}", blockhash) is None
        or int(blockhash, 16) == 0
    ):
        fail(f"{label} hash is invalid")
    return height, blockhash


def validate_status(value: object, label: str, accounts_exist: bool) -> int:
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    expected = {"node_tip", "wallet_tip", "locked"}
    if accounts_exist:
        expected.add("fully_synced_height")
    if set(value) != expected:
        fail(f"{label} is not an exact unlocked fully-synced status")
    if accounts_exist:
        if value["locked"] is not False:
            fail(f"{label} is not an exact unlocked fully-synced status")
    elif value["locked"] is not True and value["locked"] is not False:
        fail(f"{label} has an invalid synchronization-lock state")
    node_height, node_hash = validate_tip(value["node_tip"], f"{label} node tip")
    wallet_height, wallet_hash = validate_tip(value["wallet_tip"], f"{label} wallet tip")
    if (wallet_height, wallet_hash) != (node_height, node_hash):
        fail(f"{label} node and wallet tips disagree")
    if accounts_exist:
        synced = value["fully_synced_height"]
        if type(synced) is not int or synced != node_height:
            fail(f"{label} fully-synced height disagrees")
    return node_height


def validate_rpc_pair(
    value: object,
    nonce: str,
    sequence: int,
    method: str,
    params: object,
    label: str,
) -> object:
    if not isinstance(value, dict) or set(value) != {"request", "response"}:
        fail(f"{label} RPC pair has an unexpected schema")
    request = value["request"]
    response = value["response"]
    request_id = f"zecwec-recovery:{nonce}:{sequence}"
    if not isinstance(request, dict) or request != {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }:
        fail(f"{label} RPC request differs from the ceremony")
    if (
        not isinstance(response, dict)
        or set(response) != {"jsonrpc", "id", "result"}
        or response["jsonrpc"] != "2.0"
        or response["id"] != request_id
    ):
        fail(f"{label} RPC response envelope is invalid")
    return response["result"]


def native_validate(program: str, address: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(program, flags)
    except OSError:
        fail("native Orchard validator is unavailable or unsafe")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        ):
            fail("native Orchard validator ownership or mode is unsafe")
    finally:
        os.close(descriptor)
    try:
        result = subprocess.run(
            (program, "validate-zec-testnet-orchard"),
            input=address + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        fail("native Orchard validator could not run")
    expected = '{"valid":true,"network":"testnet","receiver":"orchard"}\n'
    if result.returncode != 0 or result.stdout != expected:
        fail("collector address failed native Orchard validation")


def validate_list_account(value: object, expected_uuid: str | None) -> dict:
    expected_fields = {
        "account_uuid",
        "name",
        "seedfp",
        "zip32_account_index",
        "account",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        fail("z_listaccounts account has an unexpected schema")
    account_uuid = validate_uuid(value["account_uuid"], "listed account UUID")
    if expected_uuid is not None and account_uuid != expected_uuid:
        fail("z_listaccounts returned another account UUID")
    if value["name"] != ACCOUNT_NAME:
        fail("collector account name differs from policy")
    validate_seedfp(value["seedfp"])
    index = value["zip32_account_index"]
    if (
        type(index) is not int
        or not 0 <= index < 2**31
        or type(value["account"]) is not int
        or value["account"] != index
    ):
        fail("listed ZIP-32 account index is invalid")
    return value


def recovery_operation_params(pair: object, birthday: int) -> list:
    params = (
        pair.get("request", {}).get("params") if isinstance(pair, dict) else None
    )
    if (
        not isinstance(params, list)
        or len(params) != 1
        or not isinstance(params[0], list)
        or len(params[0]) != 1
        or not isinstance(params[0][0], dict)
    ):
        fail("z_recoveraccounts parameters are invalid")
    account = params[0][0]
    if set(account) != {
        "name",
        "seedfp",
        "zip32_account_index",
        "birthday_height",
    }:
        fail("z_recoveraccounts account parameters have an unexpected schema")
    if account["name"] != ACCOUNT_NAME or account["birthday_height"] != birthday:
        fail("z_recoveraccounts did not use the frozen name and birthday")
    validate_seedfp(account["seedfp"])
    index = account["zip32_account_index"]
    if type(index) is not int or not 0 <= index < 2**31:
        fail("z_recoveraccounts ZIP-32 account index is invalid")
    return params


def validate_account_result(value: object, expected_uuid: str, label: str) -> dict:
    expected_fields = {
        "account_uuid",
        "name",
        "seedfp",
        "zip32_account_index",
        "addresses",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        fail(f"{label} z_getaccount response has an unexpected schema")
    if value["account_uuid"] != expected_uuid or value["name"] != ACCOUNT_NAME:
        fail(f"{label} z_getaccount identity differs from the operation")
    seedfp = validate_seedfp(value["seedfp"])
    account_index = value["zip32_account_index"]
    if type(account_index) is not int or not 0 <= account_index < 2**31:
        fail(f"{label} z_getaccount ZIP-32 account index is invalid")
    addresses = value["addresses"]
    if not isinstance(addresses, list):
        fail(f"{label} z_getaccount addresses are not a list")
    validated_addresses: list[dict[str, object]] = []
    seen_indices: set[int] = set()
    seen_addresses: set[str] = set()
    for entry in addresses:
        if not isinstance(entry, dict) or set(entry) != {"diversifier_index", "ua"}:
            fail(f"{label} z_getaccount address has an unexpected schema")
        index = entry["diversifier_index"]
        address = entry["ua"]
        if (
            type(index) is not int
            or not 0 <= index <= MAX_DIVERSIFIER_INDEX
            or not isinstance(address, str)
            or not 8 <= len(address) <= 512
            or not address.isascii()
            or any(character.isspace() for character in address)
        ):
            fail(f"{label} z_getaccount address is invalid")
        if index in seen_indices or address in seen_addresses:
            fail(f"{label} z_getaccount address set contains a duplicate")
        seen_indices.add(index)
        seen_addresses.add(address)
        validated_addresses.append({"diversifier_index": index, "ua": address})
    return {
        "seedfp": seedfp,
        "zip32_account_index": account_index,
        "addresses": validated_addresses,
    }


def validate_derived_address(
    value: object,
    expected_uuid: str,
    expected_index: int,
    expected_receiver_types: list[str],
    label: str,
) -> str:
    expected_fields = {
        "account_uuid",
        "diversifier_index",
        "receiver_types",
        "address",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        fail(f"{label} response has an unexpected schema")
    address = value["address"]
    if (
        value["account_uuid"] != expected_uuid
        or type(value["diversifier_index"]) is not int
        or value["diversifier_index"] != expected_index
        or value["receiver_types"] != expected_receiver_types
        or not isinstance(address, str)
        or not 8 <= len(address) <= 512
        or not address.isascii()
        or any(character.isspace() for character in address)
    ):
        fail(f"{label} differs from the frozen derivation policy")
    return address


def collector_diversifier_index(default_index: int) -> int:
    # Zallet beta.3 creates and exposes a default AllAvailableKeys UA as part
    # of account creation. Preserve the preferred Orchard index zero unless
    # that default already occupies it; index one is then the deterministic
    # non-colliding choice. Orchard derivation accepts either index.
    return 0 if default_index != 0 else 1


def validate_capture(
    value: dict, expected_kind: str, settings: dict[str, str], native_program: str
) -> dict:
    if set(value) != CAPTURE_FIELDS:
        fail(f"{expected_kind} authenticated capture has an unexpected schema")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != CAPTURE_SCHEMA_VERSION
    ):
        fail(f"{expected_kind} authenticated capture has an unsupported schema")
    if (
        value["capture_kind"] != expected_kind
        or value["network"] != "testnet"
        or value["genesis_hash"] != settings["ZCASH_GENESIS_DISPLAY"]
        or value["consensus_branch_id"] != ZCASH_NU6_3_BRANCH_ID
    ):
        fail(f"{expected_kind} authenticated capture differs from chain policy")
    nonce = value["capture_nonce"]
    if (
        not isinstance(nonce, str)
        or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        or int(nonce, 16) == 0
    ):
        fail(f"{expected_kind} authenticated capture nonce is invalid")
    birthday = value["birthday_height"]
    if type(birthday) is not int or not 0 < birthday <= 0xFFFF_FFFF:
        fail(f"{expected_kind} birthday height is invalid")
    transcript = value["rpc_transcript"]
    if not isinstance(transcript, dict) or set(transcript) != TRANSCRIPT_FIELDS:
        fail(f"{expected_kind} RPC transcript has an unexpected schema")

    pre_status = validate_rpc_pair(
        transcript["pre_status"], nonce, 1, "getwalletstatus", [], "pre-status"
    )
    pre_tip_height = validate_status(
        pre_status, "pre-operation wallet status", False
    )
    if expected_kind == "original_wallet_creation":
        if pre_tip_height != birthday:
            fail("birthday is not derived from the original synchronized tip")
    elif pre_tip_height < birthday:
        fail("recovery wallet tip predates the frozen original birthday")
    pre_accounts = validate_rpc_pair(
        transcript["pre_accounts"],
        nonce,
        2,
        "z_listaccounts",
        [False],
        "pre-accounts",
    )
    if pre_accounts != []:
        fail("collector ceremony did not begin with an empty wallet account set")

    if expected_kind == "original_wallet_creation":
        operation_method = "z_getnewaccount"
        operation_params: object = [ACCOUNT_NAME]
    elif expected_kind == "independent_mnemonic_recovery":
        operation_method = "z_recoveraccounts"
        operation_params = recovery_operation_params(
            transcript["account_operation"], birthday
        )
    else:
        fail("authenticated capture kind is unsupported")

    operation = validate_rpc_pair(
        transcript["account_operation"],
        nonce,
        3,
        operation_method,
        operation_params,
        "account-operation",
    )
    if expected_kind == "original_wallet_creation":
        if not isinstance(operation, dict) or set(operation) != {"account_uuid"}:
            fail("z_getnewaccount response has an unexpected schema")
        account_uuid = validate_uuid(operation["account_uuid"], "created account UUID")
    else:
        if (
            not isinstance(operation, dict)
            or set(operation) != {"accounts"}
            or not isinstance(operation["accounts"], list)
            or len(operation["accounts"]) != 1
            or not isinstance(operation["accounts"][0], dict)
            or set(operation["accounts"][0])
            != {"account_uuid", "seedfp", "zip32_account_index"}
        ):
            fail("z_recoveraccounts response has an unexpected schema")
        recovered = operation["accounts"][0]
        account_uuid = validate_uuid(
            recovered["account_uuid"], "recovered account UUID"
        )
        request_account = operation_params[0][0]
        if (
            recovered["seedfp"] != request_account["seedfp"]
            or type(recovered["zip32_account_index"]) is not int
            or recovered["zip32_account_index"]
            != request_account["zip32_account_index"]
        ):
            fail("z_recoveraccounts response differs from its request")

    account_before_result = validate_rpc_pair(
        transcript["account_before_collector"],
        nonce,
        4,
        "z_getaccount",
        [account_uuid],
        "account-before-collector",
    )
    account_before = validate_account_result(
        account_before_result, account_uuid, "pre-collector"
    )
    if len(account_before["addresses"]) != 1:
        fail("new account does not contain exactly Zallet's automatic default address")
    default_entry = account_before["addresses"][0]
    default_index = default_entry["diversifier_index"]
    default_address = default_entry["ua"]

    default_result = validate_rpc_pair(
        transcript["default_address"],
        nonce,
        5,
        "z_getaddressforaccount",
        [account_uuid, list(DEFAULT_RECEIVER_TYPES), default_index],
        "default-address",
    )
    rederived_default = validate_derived_address(
        default_result,
        account_uuid,
        default_index,
        list(DEFAULT_RECEIVER_TYPES),
        "default address",
    )
    if rederived_default != default_address:
        fail("Zallet's automatic default address cannot be re-derived exactly")

    collector_index = collector_diversifier_index(default_index)
    address_result = validate_rpc_pair(
        transcript["derived_address"],
        nonce,
        6,
        "z_getaddressforaccount",
        [account_uuid, ["orchard"], collector_index],
        "derived-address",
    )
    address = validate_derived_address(
        address_result,
        account_uuid,
        collector_index,
        ["orchard"],
        "derived collector address",
    )
    native_validate(native_program, address)

    account_result = validate_rpc_pair(
        transcript["account"], nonce, 7, "z_getaccount", [account_uuid], "account"
    )
    account = validate_account_result(account_result, account_uuid, "post-collector")
    seedfp = account["seedfp"]
    account_index = account["zip32_account_index"]
    if (
        seedfp != account_before["seedfp"]
        or account_index != account_before["zip32_account_index"]
    ):
        fail("z_getaccount derivation identity changed during the ceremony")
    expected_addresses = {
        (default_index, default_address),
        (collector_index, address),
    }
    actual_addresses = {
        (entry["diversifier_index"], entry["ua"])
        for entry in account["addresses"]
    }
    if len(account["addresses"]) != 2 or actual_addresses != expected_addresses:
        fail("z_getaccount address set is not exactly the default and frozen collector")

    accounts_result = validate_rpc_pair(
        transcript["accounts"], nonce, 8, "z_listaccounts", [False], "accounts"
    )
    if not isinstance(accounts_result, list) or len(accounts_result) != 1:
        fail("z_listaccounts did not return exactly one collector")
    listed = validate_list_account(accounts_result[0], account_uuid)
    if (
        listed["seedfp"] != seedfp
        or listed["zip32_account_index"] != account_index
    ):
        fail("z_listaccounts and z_getaccount derivation data disagree")

    post_status = validate_rpc_pair(
        transcript["post_status"], nonce, 9, "getwalletstatus", [], "post-status"
    )
    post_tip_height = validate_status(
        post_status, "post-operation wallet status", True
    )
    if post_tip_height < birthday:
        fail("post-operation wallet tip predates the frozen birthday")
    commitment = sha256(PAYOUT_COMMITMENT_DOMAIN + address.encode("ascii"))
    portable = {
        "seedfp": seedfp,
        "zip32_account_index": account_index,
        "birthday_height": birthday,
        "default_diversifier_index": default_index,
        "default_unified_address": default_address,
        "diversifier_index": collector_index,
        "receiver_types": ["orchard"],
        "unified_address": address,
        "collector_payout_commitment": commitment,
    }
    if expected_kind == "independent_mnemonic_recovery":
        request_account = operation_params[0][0]
        if (
            request_account["seedfp"] != seedfp
            or request_account["zip32_account_index"] != account_index
        ):
            fail("recovery request differs from the recovered portable identity")
    return {"account_uuid": account_uuid, **portable}


def parse_socket(value: str) -> tuple[str, int]:
    try:
        host, encoded_port = value.rsplit(":", 1)
        host = host.strip("[]")
        address = ipaddress.ip_address(host)
        port = int(encoded_port, 10)
    except (ValueError, TypeError):
        fail("RPC endpoint is invalid")
    if not address.is_loopback or not 1 <= port <= 65535:
        fail("RPC endpoint must be loopback-only")
    return host, port


def read_cookie(path: str) -> str:
    try:
        cookie = read_private_regular(
            path, "root-owned RPC cookie", (0o400,)
        ).decode("ascii", errors="strict").strip()
    except UnicodeError:
        fail("RPC cookie is not ASCII")
    if ":" not in cookie or any(character.isspace() for character in cookie):
        fail("RPC cookie is invalid")
    return cookie


def rpc_call(
    host: str,
    port: int,
    cookie: str,
    nonce: str,
    sequence: int,
    method: str,
    params: object,
) -> dict:
    request = {
        "jsonrpc": "2.0",
        "id": f"zecwec-recovery:{nonce}:{sequence}",
        "method": method,
        "params": params,
    }
    authorization = base64.b64encode(cookie.encode("ascii")).decode("ascii")
    connection = http.client.HTTPConnection(host, port, timeout=RPC_CALL_TIMEOUT)
    try:
        connection.request(
            "POST",
            "/",
            body=canonical_json(request),
            headers={
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        raw = response.read(MAX_RPC_BYTES + 1)
        if response.status != 200 or len(raw) > MAX_RPC_BYTES:
            fail("authenticated RPC returned an invalid HTTP response")
    except (OSError, http.client.HTTPException):
        fail("authenticated RPC call failed")
    finally:
        connection.close()
    envelope = parse_json(raw, "authenticated RPC response")
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"jsonrpc", "id", "result"}
        or envelope["jsonrpc"] != "2.0"
        or envelope["id"] != request["id"]
    ):
        fail("authenticated RPC response envelope is invalid")
    return {"request": request, "response": envelope}


def wait_for_status(
    host: str,
    port: int,
    cookie: str,
    nonce: str,
    sequence: int,
    accounts_exist: bool,
) -> dict:
    deadline = time.monotonic() + SYNC_DEADLINE_SECONDS
    while True:
        pair = rpc_call(
            host, port, cookie, nonce, sequence, "getwalletstatus", []
        )
        try:
            validate_status(
                pair["response"]["result"], "wallet status", accounts_exist
            )
            return pair
        except SystemExit:
            if time.monotonic() >= deadline:
                fail(
                    "wallet did not reach exact synchronized readiness before the deadline"
                )
            time.sleep(2)


def output_directory(path: pathlib.Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("output directory is unavailable or unsafe")
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != TRUSTED_UID
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(descriptor)
        fail("output directory must be root-owned and private")
    return descriptor


def require_output_absent(path: str) -> None:
    target = pathlib.Path(path)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        fail("capture output path must be absolute")
    directory = output_directory(target.parent)
    try:
        for name, label in (
            (target.name, "capture output"),
            (f"{target.name}.mutation-intent", "mutation intent"),
            (f"{target.name}.mutation-receipt", "mutation receipt"),
            (f"{target.name}.pending", "pending capture"),
        ):
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                fail(f"{label} path cannot be inspected safely")
            fail(f"{label} already exists; refusing a mutating RPC ceremony")
    finally:
        os.close(directory)


def mutation_intent_name(output: str) -> str:
    target = pathlib.Path(output)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        fail("capture output path must be absolute")
    return f"{target.name}.mutation-intent"


def mutation_receipt_path(output: str) -> str:
    return f"{output}.mutation-receipt"


def pending_capture_path(output: str) -> str:
    return f"{output}.pending"


def create_mutation_intent(output: str, operation: str, nonce: str) -> bytes:
    target = pathlib.Path(output)
    serialized = canonical_json(
        {
            "schema_version": 1,
            "network": "testnet",
            "operation": operation,
            "capture_nonce": nonce,
        }
    )
    directory = output_directory(target.parent)
    name = mutation_intent_name(output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(name, flags, 0o400, dir_fd=directory)
        except OSError:
            fail("mutation intent already exists or cannot be created safely")
        try:
            offset = 0
            while offset < len(serialized):
                written = os.write(descriptor, serialized[offset:])
                if written <= 0:
                    fail("cannot write mutation intent")
                offset += written
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)
    return serialized


def remove_exact_private_file(path: str, expected: bytes, label: str) -> None:
    target = pathlib.Path(path)
    directory = output_directory(target.parent)
    name = target.name
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except OSError:
            fail(f"{label} is unavailable after the RPC operation")
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != TRUSTED_UID
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1
                or read_descriptor(descriptor, len(expected)) != expected
            ):
                fail(f"{label} changed during the RPC operation")
        finally:
            os.close(descriptor)
        try:
            os.unlink(name, dir_fd=directory)
        except OSError:
            fail(f"{label} cannot be removed after durable capture")
        os.fsync(directory)
    finally:
        os.close(directory)


def clear_mutation_intent(output: str, expected: bytes) -> None:
    target = pathlib.Path(output)
    remove_exact_private_file(
        os.fspath(target.parent / mutation_intent_name(output)),
        expected,
        "mutation intent",
    )


def verify_existing(descriptor: int, name: str, serialized: bytes) -> bool:
    try:
        existing = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
    except FileNotFoundError:
        return False
    except OSError:
        fail("existing output cannot be opened safely")
    try:
        metadata = os.fstat(existing)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
        ):
            fail("existing output ownership or mode is unsafe")
        value = read_descriptor(existing, len(serialized))
    finally:
        os.close(existing)
    if value != serialized:
        fail("existing output differs")
    return True


def write_once(path: str, value: dict) -> None:
    target = pathlib.Path(path)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        fail("output path must be absolute")
    serialized = canonical_json(value)
    directory = output_directory(target.parent)
    temporary = f".{target.name}.new.{os.getpid()}"
    created = False
    try:
        if verify_existing(directory, target.name, serialized):
            return
        try:
            output = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o400,
                dir_fd=directory,
            )
            created = True
        except OSError:
            fail("cannot create temporary output")
        try:
            offset = 0
            while offset < len(serialized):
                written = os.write(output, serialized[offset:])
                if written <= 0:
                    fail("cannot write output")
                offset += written
            os.fchmod(output, 0o400)
            os.fsync(output)
        finally:
            os.close(output)
        try:
            os.link(
                temporary,
                target.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError:
            if not verify_existing(directory, target.name, serialized):
                fail("concurrent output creation failed")
        except OSError:
            fail("cannot install output")
        finally:
            os.unlink(temporary, dir_fd=directory)
            created = False
        os.fsync(directory)
        if not verify_existing(directory, target.name, serialized):
            fail("installed output cannot be verified")
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def capture_original(
    settings_path: str,
    socket: str,
    cookie_path: str,
    output: str,
    native_program: str,
) -> None:
    require_output_absent(output)
    settings = read_settings(settings_path, False)
    host, port = parse_socket(socket)
    cookie = read_cookie(cookie_path)
    nonce = secrets.token_hex(32)
    pre_status = wait_for_status(host, port, cookie, nonce, 1, False)
    birthday = validate_status(
        pre_status["response"]["result"], "pre-operation status", False
    )
    pre_accounts = rpc_call(
        host, port, cookie, nonce, 2, "z_listaccounts", [False]
    )
    if pre_accounts["response"]["result"] != []:
        fail("original collector wallet already contains an account")
    intent = create_mutation_intent(output, "z_getnewaccount", nonce)
    operation = rpc_call(
        host, port, cookie, nonce, 3, "z_getnewaccount", [ACCOUNT_NAME]
    )
    receipt = {
        "schema_version": 1,
        "capture_kind": "original_wallet_creation",
        "network": "testnet",
        "genesis_hash": settings["ZCASH_GENESIS_DISPLAY"],
        "consensus_branch_id": ZCASH_NU6_3_BRANCH_ID,
        "capture_nonce": nonce,
        "birthday_height": birthday,
        "rpc_transcript": {
            "pre_status": pre_status,
            "pre_accounts": pre_accounts,
            "account_operation": operation,
        },
    }
    receipt_path = mutation_receipt_path(output)
    write_once(receipt_path, receipt)
    operation_result = operation["response"]["result"]
    if not isinstance(operation_result, dict) or set(operation_result) != {
        "account_uuid"
    }:
        fail("z_getnewaccount response has an unexpected schema")
    account_uuid = validate_uuid(
        operation_result["account_uuid"], "created account UUID"
    )
    account_before_collector = rpc_call(
        host, port, cookie, nonce, 4, "z_getaccount", [account_uuid]
    )
    account_before_result = validate_rpc_pair(
        account_before_collector,
        nonce,
        4,
        "z_getaccount",
        [account_uuid],
        "account-before-collector",
    )
    account_before = validate_account_result(
        account_before_result, account_uuid, "pre-collector"
    )
    if len(account_before["addresses"]) != 1:
        fail("new account does not contain exactly Zallet's automatic default address")
    default_entry = account_before["addresses"][0]
    default_index = default_entry["diversifier_index"]
    default_address = rpc_call(
        host,
        port,
        cookie,
        nonce,
        5,
        "z_getaddressforaccount",
        [account_uuid, list(DEFAULT_RECEIVER_TYPES), default_index],
    )
    collector_index = collector_diversifier_index(default_index)
    address = rpc_call(
        host,
        port,
        cookie,
        nonce,
        6,
        "z_getaddressforaccount",
        [account_uuid, ["orchard"], collector_index],
    )
    address_result = address["response"]["result"]
    if not isinstance(address_result, dict) or not isinstance(
        address_result.get("address"), str
    ):
        fail("z_getaddressforaccount response is invalid")
    native_validate(native_program, address_result["address"])
    account = rpc_call(host, port, cookie, nonce, 7, "z_getaccount", [account_uuid])
    accounts = rpc_call(
        host, port, cookie, nonce, 8, "z_listaccounts", [False]
    )
    post_status = wait_for_status(host, port, cookie, nonce, 9, True)
    capture = {
        "schema_version": CAPTURE_SCHEMA_VERSION,
        "capture_kind": "original_wallet_creation",
        "network": "testnet",
        "genesis_hash": settings["ZCASH_GENESIS_DISPLAY"],
        "consensus_branch_id": ZCASH_NU6_3_BRANCH_ID,
        "capture_nonce": nonce,
        "birthday_height": birthday,
        "rpc_transcript": {
            "pre_status": pre_status,
            "pre_accounts": pre_accounts,
            "account_operation": operation,
            "account_before_collector": account_before_collector,
            "default_address": default_address,
            "derived_address": address,
            "account": account,
            "accounts": accounts,
            "post_status": post_status,
        },
    }
    pending_path = pending_capture_path(output)
    write_once(pending_path, capture)
    validate_capture(capture, "original_wallet_creation", settings, native_program)
    write_once(output, capture)
    remove_exact_private_file(
        pending_path, canonical_json(capture), "pending capture"
    )
    remove_exact_private_file(
        receipt_path, canonical_json(receipt), "mutation receipt"
    )
    clear_mutation_intent(output, intent)


def capture_recovered(
    settings_path: str,
    original_path: str,
    socket: str,
    cookie_path: str,
    output: str,
    native_program: str,
    acknowledged: bool,
) -> None:
    if not acknowledged:
        fail("fresh isolated mnemonic import acknowledgement is required")
    require_output_absent(output)
    settings = read_settings(settings_path, False)
    original_capture = read_object(
        original_path, "original authenticated RPC capture"
    )
    original = validate_capture(
        original_capture, "original_wallet_creation", settings, native_program
    )
    host, port = parse_socket(socket)
    cookie = read_cookie(cookie_path)
    nonce = secrets.token_hex(32)
    pre_status = wait_for_status(host, port, cookie, nonce, 1, False)
    pre_accounts = rpc_call(
        host, port, cookie, nonce, 2, "z_listaccounts", [False]
    )
    if pre_accounts["response"]["result"] != []:
        fail("recovery wallet already contains an account")
    birthday = original["birthday_height"]
    recovery_account = {
        "name": ACCOUNT_NAME,
        "seedfp": original["seedfp"],
        "zip32_account_index": original["zip32_account_index"],
        "birthday_height": birthday,
    }
    intent = create_mutation_intent(output, "z_recoveraccounts", nonce)
    operation = rpc_call(
        host,
        port,
        cookie,
        nonce,
        3,
        "z_recoveraccounts",
        [[recovery_account]],
    )
    receipt = {
        "schema_version": 1,
        "capture_kind": "independent_mnemonic_recovery",
        "network": "testnet",
        "genesis_hash": settings["ZCASH_GENESIS_DISPLAY"],
        "consensus_branch_id": ZCASH_NU6_3_BRANCH_ID,
        "capture_nonce": nonce,
        "birthday_height": birthday,
        "rpc_transcript": {
            "pre_status": pre_status,
            "pre_accounts": pre_accounts,
            "account_operation": operation,
        },
    }
    receipt_path = mutation_receipt_path(output)
    write_once(receipt_path, receipt)
    operation_result = operation["response"]["result"]
    if (
        not isinstance(operation_result, dict)
        or not isinstance(operation_result.get("accounts"), list)
        or len(operation_result["accounts"]) != 1
        or not isinstance(operation_result["accounts"][0], dict)
    ):
        fail("z_recoveraccounts response is invalid")
    account_uuid = validate_uuid(
        operation_result["accounts"][0].get("account_uuid"),
        "recovered account UUID",
    )
    account_before_collector = rpc_call(
        host, port, cookie, nonce, 4, "z_getaccount", [account_uuid]
    )
    account_before_result = validate_rpc_pair(
        account_before_collector,
        nonce,
        4,
        "z_getaccount",
        [account_uuid],
        "account-before-collector",
    )
    account_before = validate_account_result(
        account_before_result, account_uuid, "pre-collector"
    )
    if len(account_before["addresses"]) != 1:
        fail("recovered account does not contain exactly Zallet's automatic default address")
    default_entry = account_before["addresses"][0]
    default_index = default_entry["diversifier_index"]
    default_address = rpc_call(
        host,
        port,
        cookie,
        nonce,
        5,
        "z_getaddressforaccount",
        [account_uuid, list(DEFAULT_RECEIVER_TYPES), default_index],
    )
    collector_index = collector_diversifier_index(default_index)
    address = rpc_call(
        host,
        port,
        cookie,
        nonce,
        6,
        "z_getaddressforaccount",
        [account_uuid, ["orchard"], collector_index],
    )
    address_result = address["response"]["result"]
    if not isinstance(address_result, dict) or not isinstance(
        address_result.get("address"), str
    ):
        fail("z_getaddressforaccount response is invalid")
    native_validate(native_program, address_result["address"])
    account = rpc_call(host, port, cookie, nonce, 7, "z_getaccount", [account_uuid])
    accounts = rpc_call(
        host, port, cookie, nonce, 8, "z_listaccounts", [False]
    )
    post_status = wait_for_status(host, port, cookie, nonce, 9, True)
    capture = {
        "schema_version": CAPTURE_SCHEMA_VERSION,
        "capture_kind": "independent_mnemonic_recovery",
        "network": "testnet",
        "genesis_hash": settings["ZCASH_GENESIS_DISPLAY"],
        "consensus_branch_id": ZCASH_NU6_3_BRANCH_ID,
        "capture_nonce": nonce,
        "birthday_height": birthday,
        "rpc_transcript": {
            "pre_status": pre_status,
            "pre_accounts": pre_accounts,
            "account_operation": operation,
            "account_before_collector": account_before_collector,
            "default_address": default_address,
            "derived_address": address,
            "account": account,
            "accounts": accounts,
            "post_status": post_status,
        },
    }
    pending_path = pending_capture_path(output)
    write_once(pending_path, capture)
    recovered = validate_capture(
        capture, "independent_mnemonic_recovery", settings, native_program
    )
    if any(original[field] != recovered[field] for field in PORTABLE_FIELDS):
        fail("independent recovery differs from the original portable collector identity")
    write_once(output, capture)
    remove_exact_private_file(
        pending_path, canonical_json(capture), "pending capture"
    )
    remove_exact_private_file(
        receipt_path, canonical_json(receipt), "mutation receipt"
    )
    clear_mutation_intent(output, intent)


def policy_binding(settings: dict[str, str]) -> dict:
    return {
        "network": "testnet",
        "genesis_hash": settings["ZCASH_GENESIS_DISPLAY"],
        "genesis_wire": settings["ZCASH_GENESIS_WIRE"],
        "consensus_branch_id": ZCASH_NU6_3_BRANCH_ID,
        "collector_account": settings["ZCASH_SIGNER_ACCOUNT"],
        "collector_account_index": int(
            settings["ZCASH_SIGNER_ACCOUNT_INDEX"], 10
        ),
        "collector_payout_commitment": settings[
            "ZCASH_PAYOUT_COMMITMENT_WIRE"
        ],
    }


def expected_attestation(
    settings: dict[str, str],
    original_capture: dict,
    recovered_capture: dict,
    portable: dict,
) -> dict:
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "network": "testnet",
        "genesis_hash": settings["ZCASH_GENESIS_DISPLAY"],
        "consensus_branch_id": ZCASH_NU6_3_BRANCH_ID,
        "collector_payout_commitment": portable["collector_payout_commitment"],
        "policy_binding_sha256": sha256(canonical_json(policy_binding(settings))),
        "portable_binding_sha256": sha256(canonical_json(portable)),
        "original_authenticated_rpc_capture_sha256": sha256(
            canonical_json(original_capture)
        ),
        "recovered_authenticated_rpc_capture_sha256": sha256(
            canonical_json(recovered_capture)
        ),
        "operator_acknowledged_fresh_isolated_mnemonic_recovery": True,
        "native_orchard_receiver_validation": "orchard-0.15.5",
    }


def validate_final_bindings(
    settings: dict[str, str], original: dict, recovered: dict
) -> None:
    if original["account_uuid"] != settings["ZCASH_SIGNER_ACCOUNT"]:
        fail("original collector UUID differs from final deployment settings")
    if original["zip32_account_index"] != int(
        settings["ZCASH_SIGNER_ACCOUNT_INDEX"], 10
    ):
        fail("original ZIP-32 index differs from final deployment settings")
    if (
        original["collector_payout_commitment"]
        != settings["ZCASH_PAYOUT_COMMITMENT_WIRE"]
    ):
        fail("original payout commitment differs from final deployment settings")
    if any(original[field] != recovered[field] for field in PORTABLE_FIELDS):
        fail("independent recovery differs from the original portable collector identity")


def expected_from_inputs(
    settings_path: str,
    original_path: str,
    recovered_path: str,
    native_program: str,
) -> dict:
    settings = read_settings(settings_path, True)
    original_capture = read_object(
        original_path, "original authenticated RPC capture"
    )
    recovered_capture = read_object(
        recovered_path, "recovered authenticated RPC capture"
    )
    original = validate_capture(
        original_capture, "original_wallet_creation", settings, native_program
    )
    recovered = validate_capture(
        recovered_capture,
        "independent_mnemonic_recovery",
        settings,
        native_program,
    )
    if original_capture["capture_nonce"] == recovered_capture["capture_nonce"]:
        fail("original and recovered RPC captures reuse one ceremony nonce")
    validate_final_bindings(settings, original, recovered)
    portable = {field: original[field] for field in PORTABLE_FIELDS}
    return expected_attestation(
        settings, original_capture, recovered_capture, portable
    )


def usage() -> NoReturn:
    fail(
        "usage: verify-zec-wallet-recovery.py "
        "capture-original <settings> <loopback-rpc> <root-cookie> <capture> "
        "<wcash-poold> | capture-recovered <settings> <original-capture> "
        "<loopback-rpc> <root-cookie> <capture> <wcash-poold> "
        "--ack-fresh-isolated-mnemonic-import | seal <settings> "
        "<original-capture> <recovered-capture> <attestation> <wcash-poold> "
        "--ack-fresh-isolated-mnemonic-recovery | verify <settings> "
        "<original-capture> <recovered-capture> <attestation> <wcash-poold>"
    )


def main() -> None:
    require_root()
    if len(sys.argv) < 2:
        usage()
    mode = sys.argv[1]
    if mode == "capture-original" and len(sys.argv) == 7:
        capture_original(*sys.argv[2:])
    elif mode == "capture-recovered" and len(sys.argv) == 9:
        capture_recovered(
            *sys.argv[2:8],
            sys.argv[8] == "--ack-fresh-isolated-mnemonic-import",
        )
    elif mode == "seal" and len(sys.argv) == 8:
        if sys.argv[7] != "--ack-fresh-isolated-mnemonic-recovery":
            fail("fresh isolated mnemonic recovery acknowledgement is required")
        expected = expected_from_inputs(
            sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[6]
        )
        write_once(sys.argv[5], expected)
    elif mode == "verify" and len(sys.argv) == 7:
        expected = expected_from_inputs(
            sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[6]
        )
        attestation = read_object(sys.argv[5], "ZEC recovery attestation")
        if attestation != expected:
            fail(
                "ZEC recovery attestation differs from authenticated recovery evidence"
            )
    else:
        usage()


if __name__ == "__main__":
    main()

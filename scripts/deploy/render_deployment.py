#!/usr/bin/env python3
"""Render a strictly validated, Testnet-only deployment without secrets."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import urllib.parse
import uuid
from typing import NoReturn


REQUIRED = {
    "DEPLOYMENT_ID",
    "POOL_INSTANCE",
    "WCASH_SIGNER_ACCOUNT",
    "ZCASH_SIGNER_ACCOUNT",
    "WCASH_CHAIN_ID",
    "WCASH_GENESIS_DISPLAY",
    "WCASH_GENESIS_WIRE",
    "ZCASH_GENESIS_DISPLAY",
    "ZCASH_GENESIS_WIRE",
    "WCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_PAYOUT_COMMITMENT_WIRE",
    "WCASH_PAYOUT_MODE",
    "INITIAL_SHARE_TARGET_BE",
    "EASIEST_SHARE_TARGET_BE",
    "APEX_HOST",
    "PORTAL_HOST",
    "MINING_HOST",
    "PORTAL_ORIGIN",
    "PORTAL_LISTEN",
    "STRATUM_LISTEN",
    "STRATUM_TLS_PORT",
    "LEGACY_STRATUM_PORT",
    "WCASH_RPC_URL",
    "WCASH_NODE_RPC",
    "ZCASH_TEMPLATE_RPC_URL",
    "ZCASH_VALIDATOR_RPC_URL",
    "WCASH_LIGHTWALLETD_ENDPOINT",
    "WCASH_LIGHTWALLETD_UNIT",
    "ZALLET_RPC",
    "ZCASH_NODE_RPC",
    "WCASH_NODE_UNIT",
    "ZCASH_TEMPLATE_UNIT",
    "ZCASH_VALIDATOR_UNIT",
    "WCASH_RPC_COOKIE_SOURCE",
    "ZCASH_TEMPLATE_COOKIE_SOURCE",
    "ZCASH_VALIDATOR_COOKIE_SOURCE",
    "POOL_STATE_DIR",
    "BACKEND_STATE_DIR",
    "BACKEND_RUNTIME_DIR",
    "BACKEND_SOCKET",
    "WEC_SEED_FILE",
    "ZALLET_STATE_DIR",
    "ZALLET_CONFIG_FILE",
    "WCASH_WALLET_DATABASE",
    "WCASH_WALLET_BIRTHDAY",
    "WCASH_WALLET_SYNC_BATCH_SIZE",
    "WCASH_WALLET_SYNC_TIMEOUT_SECONDS",
    "WEC_SIGNER_JOURNAL",
    "ZEC_SIGNER_JOURNAL",
    "WCASH_PAYOUT_ADDRESS_CREDENTIAL",
    "WCASH_PAYOUT_IVK_CREDENTIAL",
    "ZCASH_PAYOUT_ADDRESS_CREDENTIAL",
    "PORTAL_TOKEN_PEPPER_CREDENTIAL",
    "PORTAL_TOTP_KEY_CREDENTIAL",
    "DATABASE_MIGRATOR_URL_CREDENTIAL",
    "DATABASE_RUNTIME_URL_CREDENTIAL",
    "POSTGRES_DATABASE",
    "POSTGRES_MIGRATOR_ROLE",
    "POSTGRES_RUNTIME_ROLE",
    "NONCE_NAMESPACE",
    "NONCE_RESERVATION",
    "DATABASE_CONNECTIONS",
    "MAXIMUM_MINERS",
    "MAXIMUM_MINERS_PER_IP",
    "AUTHENTICATION_PARALLELISM",
    "BACKEND_LISTENERS",
    "WCASH_VALIDATION_LIMIT",
    "WEC_PPLNS_WINDOW_WORK",
    "WEC_PAYOUT_THRESHOLD_ZAT",
    "WEC_REQUIRED_CONFIRMATIONS",
    "WEC_MAXIMUM_PAYOUT_OUTPUTS",
    "WEC_MAXIMUM_NETWORK_FEE_ZAT",
    "WEC_MAXIMUM_NETWORK_FEE_BPS",
    "WEC_POLICY_VERSION",
    "ZEC_PPLNS_WINDOW_WORK",
    "ZEC_PAYOUT_THRESHOLD_ZAT",
    "ZEC_REQUIRED_CONFIRMATIONS",
    "ZEC_MAXIMUM_PAYOUT_OUTPUTS",
    "ZEC_MAXIMUM_NETWORK_FEE_ZAT",
    "ZEC_MAXIMUM_NETWORK_FEE_BPS",
    "ZEC_POLICY_VERSION",
    "ZCASH_SIGNER_ACCOUNT_INDEX",
    "CLOUDFLARE_ORIGIN_PULL_CA",
    "APEX_TLS_CERT",
    "APEX_TLS_KEY",
    "PORTAL_TLS_CERT",
    "PORTAL_TLS_KEY",
    "MINING_TLS_CERT",
    "MINING_TLS_KEY",
}

PATH_KEYS = {
    key
    for key in REQUIRED
    if key != "POSTGRES_DATABASE"
    and (
        key.endswith("_SOURCE")
        or key.endswith("_CREDENTIAL")
        or key.endswith("_DIR")
        or key.endswith("_FILE")
        or key.endswith("_DATABASE")
        or key.endswith("_JOURNAL")
        or key.endswith("_CERT")
        or key.endswith("_KEY")
        or key in {"BACKEND_SOCKET"}
    )
} | {"CLOUDFLARE_ORIGIN_PULL_CA"}

HEX_KEYS = {
    "WCASH_GENESIS_DISPLAY",
    "WCASH_GENESIS_WIRE",
    "ZCASH_GENESIS_DISPLAY",
    "ZCASH_GENESIS_WIRE",
    "WCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_PAYOUT_COMMITMENT_WIRE",
    "INITIAL_SHARE_TARGET_BE",
    "EASIEST_SHARE_TARGET_BE",
}

UUID_KEYS = {
    "DEPLOYMENT_ID",
    "POOL_INSTANCE",
    "WCASH_SIGNER_ACCOUNT",
    "ZCASH_SIGNER_ACCOUNT",
}

INTEGER_RANGES = {
    "WCASH_CHAIN_ID": (1, 2**32 - 1),
    "STRATUM_TLS_PORT": (1, 65535),
    "LEGACY_STRATUM_PORT": (1, 65535),
    "NONCE_NAMESPACE": (1, 127),
    "NONCE_RESERVATION": (1, 16_777_216),
    "DATABASE_CONNECTIONS": (1, 64),
    "MAXIMUM_MINERS": (1, 65_535),
    "MAXIMUM_MINERS_PER_IP": (1, 65_535),
    "AUTHENTICATION_PARALLELISM": (1, 32),
    "BACKEND_LISTENERS": (1, 16),
    "WCASH_VALIDATION_LIMIT": (1, 1024),
    "WCASH_WALLET_BIRTHDAY": (1, 2**32 - 1),
    "WCASH_WALLET_SYNC_BATCH_SIZE": (1, 16),
    "WCASH_WALLET_SYNC_TIMEOUT_SECONDS": (30, 900),
    "WEC_PPLNS_WINDOW_WORK": (1, 2**256 - 1),
    "WEC_PAYOUT_THRESHOLD_ZAT": (1, 2**64 - 1),
    "WEC_REQUIRED_CONFIRMATIONS": (100, 1_000_000),
    "WEC_MAXIMUM_PAYOUT_OUTPUTS": (1, 200),
    "WEC_MAXIMUM_NETWORK_FEE_ZAT": (1, 2**64 - 1),
    "WEC_MAXIMUM_NETWORK_FEE_BPS": (1, 1000),
    "WEC_POLICY_VERSION": (1, 2**64 - 1),
    "ZEC_PPLNS_WINDOW_WORK": (1, 2**256 - 1),
    "ZEC_PAYOUT_THRESHOLD_ZAT": (1, 2**64 - 1),
    "ZEC_REQUIRED_CONFIRMATIONS": (100, 1_000_000),
    "ZEC_MAXIMUM_PAYOUT_OUTPUTS": (1, 200),
    "ZEC_MAXIMUM_NETWORK_FEE_ZAT": (1, 2**64 - 1),
    "ZEC_MAXIMUM_NETWORK_FEE_BPS": (1, 1000),
    "ZEC_POLICY_VERSION": (1, 2**64 - 1),
    "ZCASH_SIGNER_ACCOUNT_INDEX": (0, 2**31 - 1),
}

DISCOVERY_SENTINEL = "BOOTSTRAP_DISCOVERY_REQUIRED"
DISCOVERABLE_UUID_KEYS = {"WCASH_SIGNER_ACCOUNT", "ZCASH_SIGNER_ACCOUNT"}
DISCOVERABLE_HEX_KEYS = {
    "WCASH_PAYOUT_COMMITMENT_WIRE",
    "ZCASH_PAYOUT_COMMITMENT_WIRE",
}
DISCOVERABLE_INTEGER_KEYS = {"ZCASH_SIGNER_ACCOUNT_INDEX"}

WALLET_BOOTSTRAP_TEMPLATES = {
    "deploy/config/wcash-wallet-bootstrap.env.in": "wcash-wallet-bootstrap.env",
    "deploy/config/zallet.testnet.toml.in": "zallet.toml",
    "deploy/config/zallet-recovery.testnet.toml.in": "zallet-recovery.toml",
    "deploy/systemd/wcash-pool-wallet-init.service.in": "systemd/wcash-pool-wallet-init.service",
    "deploy/systemd/zecwec-zallet.service.in": "systemd/zecwec-zallet.service",
    "deploy/systemd/zecwec-zallet-recovery.service.in": "systemd/zecwec-zallet-recovery.service",
}

DEPLOYMENT_TEMPLATES = {
    **WALLET_BOOTSTRAP_TEMPLATES,
    "deploy/config/zec-authority.testnet.toml.in": "zec-authority.testnet.toml",
    "deploy/config/backend.env.in": "backend.env",
    "deploy/systemd/wcash-pool-zec-authority-bootstrap.service.in": "systemd/wcash-pool-zec-authority-bootstrap.service",
    "deploy/systemd/wcash-pool-backend-init.service.in": "systemd/wcash-pool-backend-init.service",
    "deploy/systemd/wcash-pool-backend.service.in": "systemd/wcash-pool-backend.service",
    "deploy/systemd/wcash-pool-migrate.service.in": "systemd/wcash-pool-migrate.service",
    "deploy/systemd/wcash-pool-custody-gate.service.in": "systemd/wcash-pool-custody-gate.service",
    "deploy/systemd/wcash-pool.service.in": "systemd/wcash-pool.service",
    "deploy/systemd/wcash-pool-preflight.service.in": "systemd/wcash-pool-preflight.service",
    "deploy/systemd/zecwec-cookie-refresh.path.in": "systemd/zecwec-cookie-refresh.path",
    "deploy/systemd/zecwec-cookie-refresh.service.in": "systemd/zecwec-cookie-refresh.service",
    "deploy/systemd/wcash-pool-health.service.in": "systemd/wcash-pool-health.service",
    "deploy/systemd/wcash-pool-health.timer.in": "systemd/wcash-pool-health.timer",
    "deploy/systemd/zecwec-testnet-pool.target.in": "systemd/zecwec-testnet-pool.target",
    "deploy/nginx/zecwec-testnet-portal.conf.in": "nginx/zecwec-testnet-portal.conf",
    "deploy/nginx/zecwec-testnet-stratum.conf.in": "nginx/zecwec-testnet-stratum.conf",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"render-deployment: {message}")


def read_settings(path: pathlib.Path, phase: str) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        fail("settings must be a regular, non-symlink file")
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"settings line {line_number} has no '='")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            fail(f"settings line {line_number} has an invalid key")
        if key in values:
            fail(f"settings key is duplicated: {key}")
        if not value or value != value.strip() or any(ord(char) < 0x20 for char in value):
            fail(f"settings value is empty or contains control whitespace: {key}")
        values[key] = value
    missing = sorted(REQUIRED - values.keys())
    if missing:
        fail(f"missing settings: {', '.join(missing)}")
    unexpected = sorted(values.keys() - REQUIRED)
    if unexpected:
        fail(f"unexpected settings: {', '.join(unexpected)}")
    if any("CHANGE_ME" in values[key] for key in REQUIRED):
        fail("every CHANGE_ME value must be replaced")
    sentinel_keys = {key for key, value in values.items() if value == DISCOVERY_SENTINEL}
    allowed_sentinels = (
        DISCOVERABLE_UUID_KEYS | DISCOVERABLE_HEX_KEYS | DISCOVERABLE_INTEGER_KEYS
    )
    if sentinel_keys - allowed_sentinels:
        fail("bootstrap discovery sentinel is not valid for this setting")
    if sentinel_keys and phase != "wallet-bootstrap":
        fail("bootstrap discovery values must be replaced before authority initialization")
    return values


def validate_path(value: str, key: str) -> None:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or "." in path.parts or ".." in path.parts:
        fail(f"{key} must be an absolute normalized path")
    if str(path).startswith(("/tmp/", "/home/", "/root/")):
        fail(f"{key} must not use a temporary or home directory")


def parse_socket(value: str, key: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    try:
        host, port = value.rsplit(":", 1)
        host = host.strip("[]")
        address = ipaddress.ip_address(host)
        parsed_port = int(port)
    except (ValueError, TypeError):
        fail(f"{key} must be an IP socket address")
    if not 1 <= parsed_port <= 65535:
        fail(f"{key} has an invalid port")
    return address, parsed_port


def validate_loopback_url(value: str, key: str) -> None:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in {"", "/"}:
        fail(f"{key} must be a credential-free loopback HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        fail(f"{key} must use a literal loopback address")
    if not address.is_loopback or not parsed.port:
        fail(f"{key} must use a literal loopback address and nonzero port")


def validate(values: dict[str, str], phase: str) -> None:
    for key in PATH_KEYS:
        validate_path(values[key], key)

    for key in HEX_KEYS:
        if phase == "wallet-bootstrap" and values[key] == DISCOVERY_SENTINEL:
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", values[key]) or int(values[key], 16) == 0:
            fail(f"{key} must be nonzero lowercase 32-byte hexadecimal")

    for key in UUID_KEYS:
        if phase == "wallet-bootstrap" and values[key] == DISCOVERY_SENTINEL:
            continue
        try:
            parsed = uuid.UUID(values[key])
        except ValueError:
            fail(f"{key} must be a canonical UUID")
        if parsed.int == 0 or str(parsed) != values[key]:
            fail(f"{key} must be a canonical nonzero UUID")
    configured_uuids = [
        values[key] for key in UUID_KEYS if values[key] != DISCOVERY_SENTINEL
    ]
    if len(set(configured_uuids)) != len(configured_uuids):
        fail("deployment, pool, and signer UUIDs must be distinct")

    for key, (minimum, maximum) in INTEGER_RANGES.items():
        if phase == "wallet-bootstrap" and values[key] == DISCOVERY_SENTINEL:
            continue
        try:
            number = int(values[key], 10)
        except ValueError:
            fail(f"{key} must be a base-10 integer")
        if not minimum <= number <= maximum or str(number) != values[key]:
            fail(f"{key} is outside its safe canonical range")

    if int(values["MAXIMUM_MINERS_PER_IP"]) > int(values["MAXIMUM_MINERS"]):
        fail("MAXIMUM_MINERS_PER_IP must not exceed MAXIMUM_MINERS")
    if int(values["INITIAL_SHARE_TARGET_BE"], 16) > int(values["EASIEST_SHARE_TARGET_BE"], 16):
        fail("initial share target must not be easier than the safety ceiling")
    if values["WCASH_PAYOUT_MODE"] != "ironwood":
        fail("WCASH_PAYOUT_MODE must be ironwood for the Testnet pool")

    for prefix in ("WCASH", "ZCASH"):
        display = bytes.fromhex(values[f"{prefix}_GENESIS_DISPLAY"])
        wire = bytes.fromhex(values[f"{prefix}_GENESIS_WIRE"])
        if display[::-1] != wire:
            fail(f"{prefix} display and wire genesis values are not exact byte reversals")

    hostname_pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    for key in ("APEX_HOST", "PORTAL_HOST", "MINING_HOST"):
        if not re.fullmatch(hostname_pattern, values[key]):
            fail(f"{key} must be a lowercase DNS hostname")
    if (
        values["APEX_HOST"] != "zecwec.com"
        or values["PORTAL_HOST"] != "testnet.zecwec.com"
        or values["MINING_HOST"] != "testnet-mine.zecwec.com"
    ):
        fail("hostnames must match the reviewed Testnet-only DNS contract")
    if values["PORTAL_ORIGIN"] != f'https://{values["PORTAL_HOST"]}':
        fail("PORTAL_ORIGIN must exactly match the HTTPS portal host")

    portal_ip, _ = parse_socket(values["PORTAL_LISTEN"], "PORTAL_LISTEN")
    stratum_ip, stratum_port = parse_socket(values["STRATUM_LISTEN"], "STRATUM_LISTEN")
    zallet_ip, _ = parse_socket(values["ZALLET_RPC"], "ZALLET_RPC")
    wcash_node_ip, wcash_node_port = parse_socket(values["WCASH_NODE_RPC"], "WCASH_NODE_RPC")
    zcash_node_ip, _ = parse_socket(values["ZCASH_NODE_RPC"], "ZCASH_NODE_RPC")
    if (
        not portal_ip.is_loopback
        or not zallet_ip.is_loopback
        or not wcash_node_ip.is_loopback
        or not zcash_node_ip.is_loopback
    ):
        fail("portal and payout RPC listeners must be loopback-only")
    if stratum_ip.is_loopback or stratum_ip.is_multicast or not stratum_ip.is_unspecified:
        fail("STRATUM_LISTEN must use an unspecified non-loopback bind address")
    if len({stratum_port, int(values["STRATUM_TLS_PORT"]), int(values["LEGACY_STRATUM_PORT"])}) != 3:
        fail("current plaintext, TLS, and legacy Stratum ports must differ")
    if stratum_port != 3333 or int(values["STRATUM_TLS_PORT"]) != 3443:
        fail("Stratum ports must match the reviewed Testnet contract")

    for key in (
        "WCASH_RPC_URL",
        "ZCASH_TEMPLATE_RPC_URL",
        "ZCASH_VALIDATOR_RPC_URL",
        "WCASH_LIGHTWALLETD_ENDPOINT",
    ):
        validate_loopback_url(values[key], key)
    wcash_backend = urllib.parse.urlsplit(values["WCASH_RPC_URL"])
    if (wcash_backend.hostname, wcash_backend.port) != (str(wcash_node_ip), wcash_node_port):
        fail("WCASH_NODE_RPC must match the Wcash backend RPC origin")

    for key in (
        "WCASH_NODE_UNIT",
        "WCASH_LIGHTWALLETD_UNIT",
        "ZCASH_TEMPLATE_UNIT",
        "ZCASH_VALIDATOR_UNIT",
    ):
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}\.service", values[key]):
            fail(f"{key} must be a concrete systemd service name")
    for key in ("POSTGRES_DATABASE", "POSTGRES_MIGRATOR_ROLE", "POSTGRES_RUNTIME_ROLE"):
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", values[key]):
            fail(f"{key} must be a safe lowercase PostgreSQL identifier")
    if values["POSTGRES_MIGRATOR_ROLE"] == values["POSTGRES_RUNTIME_ROLE"]:
        fail("PostgreSQL migration and runtime roles must be distinct")

    exact_paths = {
        "POOL_STATE_DIR": "/var/lib/wcash-pool",
        "BACKEND_STATE_DIR": "/var/lib/wcash-pool-backend",
        "BACKEND_RUNTIME_DIR": "/run/wcash-pool-backend",
        "BACKEND_SOCKET": "/run/wcash-pool-backend/backend.sock",
        "WEC_SEED_FILE": "/var/lib/wcash-pool-secrets/wcash-seed",
        "ZALLET_STATE_DIR": "/var/lib/zecwec-zallet",
        "ZALLET_CONFIG_FILE": "/etc/wcash-pool/zallet.toml",
        "WCASH_WALLET_DATABASE": "/var/lib/wcash-pool/wcash-wallet.sqlite",
        "WEC_SIGNER_JOURNAL": "/var/lib/wcash-pool/wec-payout-journal",
        "ZEC_SIGNER_JOURNAL": "/var/lib/wcash-pool/zec-payout-journal",
        "WCASH_PAYOUT_ADDRESS_CREDENTIAL": "/etc/wcash-pool/credentials/wcash-payout-address",
        "WCASH_PAYOUT_IVK_CREDENTIAL": "/etc/wcash-pool/credentials/wcash-payout-ivk",
        "ZCASH_PAYOUT_ADDRESS_CREDENTIAL": "/etc/wcash-pool/credentials/zcash-payout-address",
        "PORTAL_TOKEN_PEPPER_CREDENTIAL": "/etc/wcash-pool/credentials/portal-token-pepper",
        "PORTAL_TOTP_KEY_CREDENTIAL": "/etc/wcash-pool/credentials/portal-totp-key",
        "DATABASE_MIGRATOR_URL_CREDENTIAL": "/etc/wcash-pool/credentials/database-url-migrator",
        "DATABASE_RUNTIME_URL_CREDENTIAL": "/etc/wcash-pool/credentials/database-url-runtime",
        "CLOUDFLARE_ORIGIN_PULL_CA": "/etc/wcash-pool/tls/cloudflare-origin-pull-ca.pem",
    }
    for key, expected in exact_paths.items():
        if values[key] != expected:
            fail(f"{key} must match the reviewed systemd policy: {expected}")
    for key in (
        "WCASH_RPC_COOKIE_SOURCE",
        "ZCASH_TEMPLATE_COOKIE_SOURCE",
        "ZCASH_VALIDATOR_COOKIE_SOURCE",
    ):
        path = pathlib.PurePosixPath(values[key])
        if path.name != ".cookie" or not str(path).startswith(("/run/", "/var/lib/")):
            fail(f"{key} must be a .cookie below /run or /var/lib")
    for key in (
        "APEX_TLS_CERT",
        "APEX_TLS_KEY",
        "PORTAL_TLS_CERT",
        "PORTAL_TLS_KEY",
        "MINING_TLS_CERT",
        "MINING_TLS_KEY",
    ):
        if not values[key].startswith("/etc/"):
            fail(f"{key} must be below /etc")


def load_authority(
    path: pathlib.Path,
    chain_id: int,
    listener_workers: int,
    expected: dict[str, str],
) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        fail("finalize requires the backend authority file")
    try:
        authority = json.loads(path.read_text(encoding="utf-8"))
        backend = uuid.UUID(authority["backend_instance"])
        journal = uuid.UUID(authority["journal_stream"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        fail("backend authority file is invalid")
    required = {
        "command",
        "result",
        "backend_instance",
        "journal_stream",
        "event_seq",
        "chain_id",
        "listener_workers",
        "wcash_genesis",
        "zcash_genesis",
        "wcash_payout_commitment",
        "zcash_payout_commitment",
        "share_target_ceiling",
        "share_target_ceiling_byte_order",
    }
    if set(authority) != required:
        fail("backend authority has an unexpected schema")
    if (
        authority.get("command") != "pool-backend-init"
        or authority.get("result")
        not in {"initialized", "resumed_identity", "already_initialized"}
        or authority.get("chain_id") != chain_id
        or authority.get("listener_workers") != listener_workers
        or authority.get("share_target_ceiling_byte_order") != "big_endian"
        or not isinstance(authority.get("event_seq"), int)
        or authority["event_seq"] < 0
    ):
        fail("backend authority does not match the configured chain")
    for key, configured in expected.items():
        if authority.get(key) != configured:
            fail(f"backend authority field does not match the configured chain: {key}")
    if (
        backend.int == 0
        or journal.int == 0
        or backend == journal
        or str(backend) != authority["backend_instance"]
        or str(journal) != authority["journal_stream"]
    ):
        fail("backend authority identities are invalid")
    return {"BACKEND_INSTANCE": str(backend), "JOURNAL_STREAM": str(journal)}


def hash_file(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"release artifact is unavailable: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render(template: pathlib.Path, output: pathlib.Path, values: dict[str, str]) -> None:
    text = template.read_text(encoding="utf-8")
    keys = set(re.findall(r"@([A-Z][A-Z0-9_]*)@", text))
    missing = sorted(keys - values.keys())
    if missing:
        fail(f"template {template.name} needs missing values: {', '.join(missing)}")
    for key in keys:
        text = text.replace(f"@{key}@", values[key])
    if re.search(r"@[A-Z][A-Z0-9_]*@", text):
        fail(f"template {template.name} retains an unresolved placeholder")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.new.{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("wallet-bootstrap", "bootstrap", "finalize"))
    parser.add_argument("--settings", required=True, type=pathlib.Path)
    parser.add_argument("--authority", type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--release-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--pool-uid", required=True, type=int)
    args = parser.parse_args()

    values = read_settings(args.settings, args.phase)
    validate(values, args.phase)
    try:
        release_root = args.release_root.resolve(strict=True)
    except OSError:
        fail("release root is unavailable")
    if release_root != args.release_root or not release_root.is_dir() or release_root.is_symlink():
        fail("release root must be one exact canonical directory, never a symlink")
    values["POOL_UID"] = str(args.pool_uid)
    values["WCASH_RELEASE_ROOT"] = str(release_root)
    values["WCASH_WALLET_AUTHORITY"] = "/var/lib/wcash-pool/wcash-wallet-authority.json"
    values["ZALLET_RECOVERY_RPC"] = "127.0.0.1:28242"
    values["ZALLET_RECOVERY_STATE_DIR"] = "/var/lib/zecwec-zallet-recovery"
    values["ZALLET_RECOVERY_CONFIG_FILE"] = "/etc/wcash-pool/zallet-recovery.toml"
    values["ZCASH_INITIAL_ZERO_RESULT"] = (
        "/var/lib/zecwec-custody/zec-collector-initial-zero.json"
    )
    values["ZCASH_INITIAL_ZERO_ATTESTATION"] = (
        "/var/lib/zecwec-custody/zec-collector-initial-zero.attestation"
    )
    values["ZCASH_INITIAL_ZERO_STAGING_RESULT"] = (
        "/var/lib/wcash-pool-backend/zec-collector-initial-zero.json"
    )
    values["ZCASH_INITIAL_ZERO_STAGING_ATTESTATION"] = (
        "/var/lib/wcash-pool-backend/zec-collector-initial-zero.attestation"
    )
    values["WCASH_WALLET_SHA256"] = hash_file(release_root / "wcash-wallet")
    values["ZCASH_VALIDATOR_RPC_SOCKET"] = urllib.parse.urlsplit(
        values["ZCASH_VALIDATOR_RPC_URL"]
    ).netloc
    values["STRATUM_PORT"] = values["STRATUM_LISTEN"].rsplit(":", 1)[1]
    values["WCASH_IVK_LOAD_CREDENTIAL"] = (
        f'LoadCredential=wcash-payout-ivk:{values["WCASH_PAYOUT_IVK_CREDENTIAL"]}'
    )

    runtime_dir = "/run/credentials/wcash-pool.service"
    preflight_dir = "/run/credentials/wcash-pool-preflight.service"
    migrate_dir = "/run/credentials/wcash-pool-migrate.service"
    values.update(
        {
            "DATABASE_URL_RUNTIME_PATH": f"{runtime_dir}/database-url",
            "ZALLET_CONFIG_RUNTIME_PATH": f"{runtime_dir}/zallet-config",
            "ZALLET_COOKIE_RUNTIME_PATH": f"{runtime_dir}/zallet-cookie",
            "WCASH_COOKIE_RUNTIME_PATH": f"{runtime_dir}/wcash-node-cookie",
            "ZCASH_COOKIE_RUNTIME_PATH": f"{runtime_dir}/zcash-node-cookie",
            "PORTAL_PEPPER_RUNTIME_PATH": f"{runtime_dir}/portal-token-pepper",
            "PORTAL_TOTP_RUNTIME_PATH": f"{runtime_dir}/portal-totp-key",
        }
    )

    templates = (
        WALLET_BOOTSTRAP_TEMPLATES
        if args.phase == "wallet-bootstrap"
        else DEPLOYMENT_TEMPLATES
    )
    for source, destination in templates.items():
        render(args.source_root / source, args.output / destination, values)

    if args.phase == "finalize":
        if args.authority is None:
            fail("--authority is required during finalize")
        values.update(
            load_authority(
                args.authority,
                int(values["WCASH_CHAIN_ID"]),
                int(values["BACKEND_LISTENERS"]),
                {
                    "wcash_genesis": values["WCASH_GENESIS_WIRE"],
                    "zcash_genesis": values["ZCASH_GENESIS_WIRE"],
                    "wcash_payout_commitment": values["WCASH_PAYOUT_COMMITMENT_WIRE"],
                    "zcash_payout_commitment": values["ZCASH_PAYOUT_COMMITMENT_WIRE"],
                    "share_target_ceiling": values["EASIEST_SHARE_TARGET_BE"],
                },
            )
        )
        pool_template = args.source_root / "deploy/config/pool.testnet.toml.in"
        render(pool_template, args.output / "pool.runtime.toml", values)
        preflight_values = dict(values)
        preflight_values.update(
            {
                "DATABASE_URL_RUNTIME_PATH": f"{preflight_dir}/database-url",
                "ZALLET_CONFIG_RUNTIME_PATH": f"{preflight_dir}/zallet-config",
                "ZALLET_COOKIE_RUNTIME_PATH": f"{preflight_dir}/zallet-cookie",
                "WCASH_COOKIE_RUNTIME_PATH": f"{preflight_dir}/wcash-node-cookie",
                "ZCASH_COOKIE_RUNTIME_PATH": f"{preflight_dir}/zcash-node-cookie",
                "PORTAL_PEPPER_RUNTIME_PATH": f"{preflight_dir}/portal-token-pepper",
                "PORTAL_TOTP_RUNTIME_PATH": f"{preflight_dir}/portal-totp-key",
            }
        )
        render(pool_template, args.output / "pool.preflight.toml", preflight_values)
        migrate_values = dict(values)
        migrate_values.update(
            {
                "DATABASE_URL_RUNTIME_PATH": f"{migrate_dir}/database-url",
                "ZALLET_CONFIG_RUNTIME_PATH": f"{migrate_dir}/zallet-config",
                "ZALLET_COOKIE_RUNTIME_PATH": f"{migrate_dir}/zallet-cookie",
                "WCASH_COOKIE_RUNTIME_PATH": f"{migrate_dir}/wcash-node-cookie",
                "ZCASH_COOKIE_RUNTIME_PATH": f"{migrate_dir}/zcash-node-cookie",
                "PORTAL_PEPPER_RUNTIME_PATH": f"{migrate_dir}/portal-token-pepper",
                "PORTAL_TOTP_RUNTIME_PATH": f"{migrate_dir}/portal-totp-key",
            }
        )
        render(pool_template, args.output / "pool.migrate.toml", migrate_values)

    release_policy = args.output / "release.env"
    release_policy.write_text(
        f"ZECWEC_RELEASE_PATH={release_root}\nZECWEC_DEPLOYMENT_SCHEMA=1\n",
        encoding="utf-8",
    )
    os.chmod(release_policy, stat.S_IRUSR | stat.S_IWUSR)

    manifest = {
        "network": "testnet",
        "phase": args.phase,
        "deployment_id": values["DEPLOYMENT_ID"],
        "pool_instance": values["POOL_INSTANCE"],
        "wcash_wallet_sha256": values["WCASH_WALLET_SHA256"],
        "release_root": str(release_root),
        "deployment_schema": 1,
        "files": sorted(
            str(path.relative_to(args.output))
            for path in args.output.rglob("*")
            if path.is_file()
        ),
    }
    rendered_manifest = args.output / "render-manifest.json"
    rendered_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.chmod(rendered_manifest, stat.S_IRUSR | stat.S_IWUSR)


if __name__ == "__main__":
    main()

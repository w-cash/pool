#!/usr/bin/env python3
"""Bounded authenticated Zallet readiness probe with no credential argv."""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import pathlib
import time


def parse_socket(value: str) -> tuple[str, int]:
    host, encoded_port = value.rsplit(":", 1)
    host = host.strip("[]")
    address = ipaddress.ip_address(host)
    port = int(encoded_port)
    if not address.is_loopback or not 1 <= port <= 65535:
        raise ValueError("Zallet RPC must be loopback-only")
    return host, port


def read_cookie(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        raise ValueError("Zallet cookie is unavailable")
    cookie = path.read_text(encoding="ascii").strip()
    if ":" not in cookie or any(char.isspace() for char in cookie):
        raise ValueError("Zallet cookie is invalid")
    return cookie


def wallet_status_is_ready(result: object) -> bool:
    if not isinstance(result, dict) or result.get("locked") is not False:
        return False
    node_tip = result.get("node_tip")
    wallet_tip = result.get("wallet_tip")
    if not isinstance(node_tip, dict) or not isinstance(wallet_tip, dict):
        return False
    node_height = node_tip.get("height")
    wallet_height = wallet_tip.get("height")
    node_hash = node_tip.get("blockhash")
    wallet_hash = wallet_tip.get("blockhash")
    if (
        type(node_height) is not int
        or type(wallet_height) is not int
        or not 0 < node_height <= 0xFFFFFFFF
        or wallet_height != node_height
        or not isinstance(node_hash, str)
        or len(node_hash) != 64
        or node_hash == "0" * 64
        or any(char not in "0123456789abcdef" for char in node_hash)
        or wallet_hash != node_hash
    ):
        return False
    if "sync_work_remaining" in result:
        return False
    # Zallet omits this field until an account exists. The native authority gate
    # later requires it to equal the common tip for the frozen collector account.
    if "fully_synced_height" not in result:
        return True
    fully_synced_height = result["fully_synced_height"]
    return type(fully_synced_height) is int and fully_synced_height == wallet_height


def probe(host: str, port: int, cookie: str, timeout: float) -> bool:
    encoded = base64.b64encode(cookie.encode("ascii")).decode("ascii")
    body = json.dumps(
        {"jsonrpc": "2.0", "id": "zecwec-readiness", "method": "getwalletstatus", "params": []},
        separators=(",", ":"),
    )
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(
            "POST",
            "/",
            body=body,
            headers={
                "Authorization": f"Basic {encoded}",
                "Content-Type": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        payload = response.read(1024 * 1024)
        if response.status != 200:
            return False
        decoded = json.loads(payload)
        return (
            isinstance(decoded, dict)
            and decoded.get("id") == "zecwec-readiness"
            and decoded.get("error") is None
            and wallet_status_is_ready(decoded.get("result"))
        )
    except (OSError, ValueError, json.JSONDecodeError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--cookie", required=True, type=pathlib.Path)
    parser.add_argument("--deadline", type=int, default=240)
    args = parser.parse_args()
    if not 1 <= args.deadline <= 1200:
        raise SystemExit("zallet-rpc-health: deadline must be in 1..=1200 seconds")

    try:
        host, port = parse_socket(args.socket)
    except (ValueError, TypeError):
        raise SystemExit("zallet-rpc-health: invalid loopback socket") from None

    end = time.monotonic() + args.deadline
    while True:
        try:
            cookie = read_cookie(args.cookie)
        except (OSError, ValueError, UnicodeError):
            cookie = ""
        remaining = end - time.monotonic()
        if cookie and remaining > 0 and probe(host, port, cookie, min(20.0, remaining)):
            print('{"ready":true,"component":"zallet","network":"test"}')
            return
        if remaining <= 0:
            raise SystemExit("zallet-rpc-health: wallet did not become ready before the deadline")
        time.sleep(min(2.0, remaining))


if __name__ == "__main__":
    main()

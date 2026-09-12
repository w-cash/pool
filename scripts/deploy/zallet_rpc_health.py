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
        return decoded.get("error") is None and isinstance(decoded.get("result"), dict)
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

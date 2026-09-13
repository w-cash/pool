#!/usr/bin/env python3
"""Wait for the externally heartbeating payout worker without leaking secrets."""

from __future__ import annotations

import json
import http.client
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable


EXPECTED = {
    "ready": True,
    "component": "miner-portal",
    "network": "testnet",
    "payout_execution": "enabled",
}
REQUIRED_UNITS = (
    "wcash-pool-projector.service",
    "wcash-pool.service",
    "zecwec-zallet-payout.service",
    "wcash-payout-worker.service",
)
MAXIMUM_READINESS_TIMEOUT_SECONDS = 70 * 60


class UnitStopped(RuntimeError):
    """A required unit stopped before readiness was established."""


class ReadinessTimeout(RuntimeError):
    """The bounded readiness deadline expired."""


def wait_until_ready(
    timeout_seconds: float,
    inspect_units: Callable[[], tuple[str, ...]],
    fetch_readiness: Callable[[], object | None],
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Poll a bounded state machine; dependencies are injectable for tests."""

    if not 1 <= timeout_seconds <= MAXIMUM_READINESS_TIMEOUT_SECONDS:
        raise ValueError("readiness timeout is outside the reviewed range")
    deadline = monotonic() + timeout_seconds
    while True:
        states = inspect_units()
        if len(states) != len(REQUIRED_UNITS) or any(state != "active" for state in states):
            raise UnitStopped("a required Testnet service stopped during startup")
        if fetch_readiness() == EXPECTED:
            return
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ReadinessTimeout("payout readiness deadline expired")
        sleep(min(2.0, remaining))


def inspect_systemd_units() -> tuple[str, ...]:
    states: list[str] = []
    for unit in REQUIRED_UNITS:
        result = subprocess.run(
            ["systemctl", "show", "--property=ActiveState", "--value", unit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
        state = result.stdout.strip()
        if result.returncode != 0 or "\n" in state or not state:
            raise UnitStopped("required Testnet service state is unavailable")
        states.append(state)
    return tuple(states)


def validate_ready_url(url: str) -> int:
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("payout readiness port is invalid") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != "/readyz"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("payout readiness endpoint must be exact literal IPv4 loopback")
    return port


def fetch_portal_readiness(port: int) -> object | None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/readyz", headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(1025)
        if (
            response.status != 200
            or response.getheader("Content-Type") != "application/json"
            or len(body) > 1024
        ):
            return None
        return json.loads(body)
    except (OSError, UnicodeError, json.JSONDecodeError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: wait_payout_ready.py <loopback-ready-url> <timeout-seconds>", file=sys.stderr)
        return 64
    url = argv[1]
    try:
        timeout = int(argv[2], 10)
    except ValueError:
        print("payout readiness timeout is invalid", file=sys.stderr)
        return 64
    try:
        port = validate_ready_url(url)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 64
    try:
        wait_until_ready(
            timeout,
            inspect_systemd_units,
            lambda: fetch_portal_readiness(port),
        )
    except (ValueError, UnitStopped, ReadinessTimeout) as error:
        print(f"payout readiness failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

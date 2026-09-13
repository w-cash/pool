#!/usr/bin/env python3
"""Parse the explicit Testnet mining ingress policy."""

from __future__ import annotations

import ipaddress
import pathlib
import sys


PUBLIC_POLICY = "PUBLIC_TESTNET_STRATUM"


def fail(message: str) -> None:
    raise SystemExit(f"mining firewall policy is invalid: {message}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: parse-mining-firewall-policy.py <policy-file>")

    try:
        lines = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"policy file cannot be read as ASCII: {error}")

    public = False
    sources: list[str] = []
    for raw in lines:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if value == PUBLIC_POLICY:
            if public or sources:
                fail(f"{PUBLIC_POLICY} must be the sole non-comment entry")
            public = True
            continue
        if public:
            fail(f"{PUBLIC_POLICY} must be the sole non-comment entry")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            fail("mining allowlist entry is not a valid IP address")
        if network.prefixlen != network.max_prefixlen or network.is_unspecified:
            fail("mining allowlist entries must be exact host addresses")
        canonical = str(network)
        if canonical not in sources:
            sources.append(canonical)

    if public:
        print("public")
        return
    if not 1 <= len(sources) <= 32:
        fail("provide between one and 32 explicit miner addresses")
    print("open")
    print("\n".join(sources))


if __name__ == "__main__":
    main()

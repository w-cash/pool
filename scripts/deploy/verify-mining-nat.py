#!/usr/bin/env python3
"""Reject NAT translations that can bypass the reviewed Stratum ports."""

from __future__ import annotations

import ipaddress
import shlex
import sys


TRANSLATION_TARGETS = {"DNAT", "REDIRECT", "NETMAP"}


def fail(message: str) -> None:
    raise SystemExit(f"mining NAT verification failed: {message}")


def option(tokens: list[str], name: str) -> str | None:
    matches = [index for index, token in enumerate(tokens) if token == name]
    if not matches:
        return None
    if len(matches) != 1 or matches[0] + 1 >= len(tokens):
        fail(f"{name} is ambiguous")
    return tokens[matches[0] + 1]


def covered_ports(specification: str | None, managed: set[int]) -> set[int]:
    if specification is None:
        return set(managed)
    covered: set[int] = set()
    for component in specification.split(","):
        delimiter = ":" if ":" in component else "-" if "-" in component else None
        try:
            if delimiter is None:
                lower = upper = int(component)
            else:
                lower_text, upper_text = component.split(delimiter, 1)
                lower, upper = int(lower_text), int(upper_text)
        except ValueError:
            fail("translation has a non-numeric destination-port match")
        if not 1 <= lower <= upper <= 65_535:
            fail("translation has an invalid destination-port match")
        covered.update(port for port in managed if lower <= port <= upper)
    return covered


def translated_ports(tokens: list[str], managed: set[int]) -> set[int]:
    to_ports = option(tokens, "--to-ports")
    destination = option(tokens, "--to-destination")
    if to_ports is not None and destination is not None:
        fail("translation has ambiguous target ports")
    if to_ports is not None:
        return covered_ports(to_ports, managed)
    if destination is None:
        return set()

    port_spec: str | None = None
    if destination.startswith("["):
        closing = destination.rfind("]")
        if closing < 0:
            fail("translation has an invalid IPv6 destination")
        try:
            ipaddress.ip_address(destination[1:closing])
        except ValueError:
            fail("translation has an invalid IPv6 destination")
        suffix = destination[closing + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                fail("translation has an invalid IPv6 destination port")
            port_spec = suffix[1:]
    else:
        host, separator, suffix = destination.rpartition(":")
        candidate = host if separator else destination
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            fail("translation has an invalid destination")
        if separator:
            port_spec = suffix
    if port_spec is None:
        return set()
    return covered_ports(port_spec, managed)


def main() -> None:
    if len(sys.argv) != 4:
        fail("usage: verify-mining-nat.py <plain-port> <tls-port> <legacy-port>")
    try:
        plain_port, tls_port, legacy_port = map(int, sys.argv[1:])
    except ValueError:
        fail("managed port is not numeric")
    managed = {plain_port, tls_port, legacy_port}
    if len(managed) != 3 or any(not 1 <= port <= 65_535 for port in managed):
        fail("managed ports are invalid or overlap")

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line.startswith("-A "):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            fail("iptables-save returned an unparseable NAT rule")
        target = option(tokens, "-j")
        if target not in TRANSLATION_TARGETS:
            continue
        if "!" in tokens:
            fail("negated NAT translation can cover a managed port")
        protocol = option(tokens, "-p") or "all"
        if protocol not in {"all", "tcp", "6"}:
            continue
        destination_spec = option(tokens, "--dport")
        multiport_spec = option(tokens, "--dports")
        if destination_spec is not None and multiport_spec is not None:
            fail("translation has ambiguous destination-port matches")
        matched = covered_ports(destination_spec or multiport_spec, managed)
        translated = translated_ports(tokens, managed)
        if matched or translated.intersection(managed):
            fail("a NAT translation covers a managed mining port")


if __name__ == "__main__":
    main()

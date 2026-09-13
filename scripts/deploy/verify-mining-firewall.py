#!/usr/bin/env python3
"""Verify the fail-closed guard and normalized UFW mining rules."""

from __future__ import annotations

import ipaddress
import shlex
import sys


GUARD_CHAIN = "ZECWEC-MINING-GUARD"


def fail(message: str) -> None:
    raise SystemExit(f"mining firewall verification failed: {message}")


def option(tokens: list[str], name: str) -> str | None:
    try:
        index = tokens.index(name)
    except ValueError:
        return None
    if index + 1 >= len(tokens):
        fail(f"{name} has no value")
    return tokens[index + 1]


def covered_ports(specification: str | None, managed: set[int]) -> set[int]:
    if specification is None:
        return set(managed)
    covered: set[int] = set()
    for component in specification.split(","):
        if not component:
            fail("empty destination-port component")
        delimiter = ":" if ":" in component else "-" if "-" in component else None
        try:
            if delimiter is None:
                lower = upper = int(component)
            else:
                lower_text, upper_text = component.split(delimiter, 1)
                lower, upper = int(lower_text), int(upper_text)
        except ValueError:
            fail("non-numeric destination-port rule")
        if not 1 <= lower <= upper <= 65535:
            fail("invalid destination-port range")
        covered.update(port for port in managed if lower <= port <= upper)
    return covered


def parse_chain_definition(line: str) -> tuple[str, str] | None:
    if not line.startswith(":"):
        return None
    fields = line.split()
    if len(fields) != 3 or not fields[0][1:]:
        fail("iptables-save returned an invalid chain definition")
    return fields[0][1:], fields[1]


def parse_guard_rule(tokens: list[str]) -> dict[str, str]:
    """Parse only the deliberately tiny grammar emitted for the guard chain."""

    if len(tokens) < 4 or tokens[:2] != ["-A", GUARD_CHAIN]:
        fail("invalid managed guard rule")
    values: dict[str, str] = {}
    index = 2
    while index < len(tokens):
        name = tokens[index]
        if name == "-m":
            if index + 1 >= len(tokens) or tokens[index + 1] != "tcp" or "module" in values:
                fail("managed guard rule has an invalid match module")
            values["module"] = "tcp"
            index += 2
            continue
        if name not in {"-i", "-s", "-p", "--dport", "-j"}:
            fail("managed guard rule contains an unsupported predicate")
        if name in values or index + 1 >= len(tokens):
            fail("managed guard rule has an ambiguous option")
        values[name] = tokens[index + 1]
        index += 2
    return values


def verify_guard(
    family: int,
    mode: str,
    managed: set[int],
    plain_port: int,
    tls_port: int,
    legacy_port: int,
    sources: set[str],
    chain_policies: dict[str, str],
    rules: list[list[str]],
) -> None:
    """Require one exact first INPUT hook and a complete terminating guard."""

    if chain_policies.get("INPUT") != "DROP":
        fail("the filter INPUT policy is not DROP")
    if chain_policies.get(GUARD_CHAIN) != "-":
        fail("the managed mining guard chain is unavailable")

    input_rules = [tokens for tokens in rules if len(tokens) >= 2 and tokens[:2] == ["-A", "INPUT"]]
    exact_hook = ["-A", "INPUT", "-j", GUARD_CHAIN]
    if not input_rules or input_rules[0] != exact_hook:
        fail("the mining guard is not the first INPUT rule")

    references = [
        tokens
        for tokens in rules
        if tokens[:2] != ["-A", GUARD_CHAIN]
        and (option(tokens, "-j") == GUARD_CHAIN or option(tokens, "-g") == GUARD_CHAIN)
    ]
    if references != [exact_hook]:
        fail("the mining guard must have one exact INPUT hook")

    guard_rules = [
        tokens for tokens in rules if len(tokens) >= 2 and tokens[:2] == ["-A", GUARD_CHAIN]
    ]
    if len(guard_rules) < 4:
        fail("the managed mining guard is incomplete")

    loopback_source = "127.0.0.1/32" if family == 4 else "::1/128"
    source_rules = guard_rules[:-4]
    if mode == "open":
        if not source_rules:
            fail("managed guard loopback exception is missing")
        loopback_values = parse_guard_rule(source_rules[0])
        expected_loopback = {
            "-i": "lo",
            "-s": loopback_source,
            "-p": "tcp",
            "module": "tcp",
            "--dport": str(plain_port),
            "-j": "RETURN",
        }
        if loopback_values != expected_loopback:
            fail("managed guard loopback exception is not exact")
        source_rules = source_rules[1:]

    if mode == "public":
        if len(source_rules) != 2:
            fail("managed guard public exceptions are incomplete")
        for tokens, expected_port in zip(
            source_rules,
            (plain_port, tls_port),
            strict=True,
        ):
            values = parse_guard_rule(tokens)
            expected_values = {
                "-p": "tcp",
                "module": "tcp",
                "--dport": str(expected_port),
                "-j": "RETURN",
            }
            if values != expected_values:
                fail("managed guard public exception is not exact")
        source_rules = []

    expected_returns = {
        (source, port) for source in sources for port in (plain_port, tls_port)
    } if mode == "open" else set()
    seen_returns: set[tuple[str, int]] = set()
    for tokens in source_rules:
        values = parse_guard_rule(tokens)
        if set(values) != {"-s", "-p", "module", "--dport", "-j"}:
            fail("managed guard source exception is not exact")
        if values["-p"] != "tcp" or values["module"] != "tcp" or values["-j"] != "RETURN":
            fail("managed guard source exception has an unsafe action")
        try:
            source_network = ipaddress.ip_network(values["-s"], strict=True)
            port = int(values["--dport"])
        except ValueError:
            fail("managed guard source exception is invalid")
        source = str(source_network)
        if source_network.version != family or source_network.prefixlen != source_network.max_prefixlen:
            fail("managed guard source exception is not one exact host")
        key = (source, port)
        if key not in expected_returns or key in seen_returns:
            fail("managed guard contains an unexpected source exception")
        seen_returns.add(key)
    if seen_returns != expected_returns:
        fail("managed guard source exceptions are incomplete")

    for tokens, expected_port in zip(
        guard_rules[-4:-1],
        (plain_port, tls_port, legacy_port),
        strict=True,
    ):
        values = parse_guard_rule(tokens)
        if set(values) != {"-p", "module", "--dport", "-j"}:
            fail("managed guard drop rule is not exact")
        try:
            port = int(values["--dport"])
        except ValueError:
            fail("managed guard drop port is invalid")
        if (
            values["-p"] != "tcp"
            or values["module"] != "tcp"
            or values["-j"] != "DROP"
            or port != expected_port
            or port not in managed
        ):
            fail("managed guard drop sequence is invalid")

    final_values = parse_guard_rule(guard_rules[-1])
    if final_values != {"-j": "RETURN"}:
        fail("managed guard does not terminate with an exact RETURN")


def main() -> None:
    if len(sys.argv) < 6:
        fail(
            "usage: verify-mining-firewall.py <ipv4|ipv6> <open|public|closed> "
            "<plain-port> <tls-port> <legacy-port> [source...]"
        )
    family_name, mode = sys.argv[1:3]
    if family_name not in {"ipv4", "ipv6"} or mode not in {"open", "public", "closed"}:
        fail("invalid family or mode")
    family = 4 if family_name == "ipv4" else 6
    try:
        plain_port, tls_port, legacy_port = map(int, sys.argv[3:6])
    except ValueError:
        fail("managed port is not numeric")
    managed = {plain_port, tls_port, legacy_port}
    if len(managed) != 3 or any(not 1 <= port <= 65535 for port in managed):
        fail("managed ports are invalid or overlap")

    if mode == "public" and sys.argv[6:]:
        fail("public mining policy cannot include source addresses")

    sources: set[str] = set()
    for raw_source in sys.argv[6:]:
        try:
            network = ipaddress.ip_network(raw_source, strict=True)
        except ValueError:
            fail("approved source is not canonical")
        if network.prefixlen != network.max_prefixlen:
            fail("approved mining sources must be exact host addresses")
        if network.version == family:
            sources.add(str(network))
    any_source = "0.0.0.0/0" if family == 4 else "::/0"
    if mode == "open":
        expected = {
            (source, port) for source in sources for port in (plain_port, tls_port)
        }
    elif mode == "public":
        expected = {(any_source, port) for port in (plain_port, tls_port)}
    else:
        expected = set()
    seen: set[tuple[str, int]] = set()
    expected_chain = "ufw-user-input" if family == 4 else "ufw6-user-input"

    chain_policies: dict[str, str] = {}
    rules: list[list[str]] = []
    for raw_line in sys.stdin:
        line = raw_line.strip()
        definition = parse_chain_definition(line)
        if definition is not None:
            name, policy = definition
            if name in chain_policies:
                fail("iptables-save returned a duplicate chain definition")
            chain_policies[name] = policy
            continue
        if not line.startswith("-A "):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            fail("iptables-save returned an unparseable rule")
        rules.append(tokens)

    verify_guard(
        family,
        mode,
        managed,
        plain_port,
        tls_port,
        legacy_port,
        sources,
        chain_policies,
        rules,
    )

    for tokens in rules:
        if len(tokens) < 4 or tokens[0:2] != ["-A", expected_chain]:
            continue
        protocol = option(tokens, "-p") or "all"
        if protocol not in {"tcp", "all"}:
            continue
        if "!" in tokens:
            fail("negated user-input rule can bypass the managed-port policy")
        destination_spec = option(tokens, "--dport")
        multiport_spec = option(tokens, "--dports")
        if destination_spec is not None and multiport_spec is not None:
            fail("ambiguous destination-port rule")
        covered = covered_ports(destination_spec or multiport_spec, managed)
        if not covered:
            continue
        target = option(tokens, "-j")
        if target in {"DROP", "REJECT", "RETURN", "ufw-user-logging-input"}:
            continue
        if target != "ACCEPT":
            fail("unsupported user-input target covers a managed port")
        if mode == "closed":
            fail("an ACCEPT rule covers a closed mining port")
        if protocol != "tcp" or multiport_spec is not None or len(covered) != 1:
            fail("a non-exact ACCEPT rule covers a managed mining port")
        port = next(iter(covered))
        if destination_spec != str(port) or port == legacy_port:
            fail("a range, alias, or legacy ACCEPT rule covers mining")
        raw_source = option(tokens, "-s") or any_source
        try:
            source = str(ipaddress.ip_network(raw_source, strict=False))
        except ValueError:
            fail("ACCEPT rule has an invalid source")
        key = (source, port)
        if key not in expected:
            fail("an unapproved source can reach a managed mining port")
        if key in seen:
            fail("a duplicate mining ACCEPT rule exists")
        seen.add(key)

    if seen != expected:
        fail("the exact approved host/port rule set is incomplete")


if __name__ == "__main__":
    main()

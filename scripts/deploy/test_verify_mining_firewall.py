#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import subprocess
import unittest


VERIFIER = pathlib.Path(__file__).with_name("verify-mining-firewall.py")
GUARD_CHAIN = "ZECWEC-MINING-GUARD"


def rule(chain: str, source: str, ports: str, *, multiport: bool = False) -> str:
    option = "--dports" if multiport else "--dport"
    module = "-m multiport " if multiport else "-m tcp "
    return f"-A {chain} -s {source} -p tcp {module}{option} {ports} -j ACCEPT"


def guard_rules(family: str, mode: str, sources: tuple[str, ...]) -> list[str]:
    expected_family = 4 if family == "ipv4" else 6
    rules: list[str] = []
    if mode == "open":
        loopback = "127.0.0.1/32" if family == "ipv4" else "::1/128"
        rules.append(
            f"-A {GUARD_CHAIN} -i lo -s {loopback} -p tcp -m tcp "
            "--dport 3333 -j RETURN"
        )
        for source in sources:
            source_family = 6 if ":" in source else 4
            if source_family != expected_family:
                continue
            for port in (3333, 3443):
                rules.append(
                    f"-A {GUARD_CHAIN} -s {source} -p tcp -m tcp "
                    f"--dport {port} -j RETURN"
                )
    for port in (3333, 3443, 28237):
        rules.append(
            f"-A {GUARD_CHAIN} -p tcp -m tcp --dport {port} -j DROP"
        )
    rules.append(f"-A {GUARD_CHAIN} -j RETURN")
    return rules


def run_verifier(
    family: str,
    mode: str,
    sources: tuple[str, ...],
    rules: list[str],
    *,
    before_guard: tuple[str, ...] = (),
    chain_definitions: tuple[str, ...] = (),
):
    chain = "ufw-user-input" if family == "ipv4" else "ufw6-user-input"
    payload = "\n".join(
        (
            "*filter",
            ":INPUT DROP [0:0]",
            f":{GUARD_CHAIN} - [0:0]",
            f":{chain} - [0:0]",
            *chain_definitions,
            *before_guard,
            f"-A INPUT -j {GUARD_CHAIN}",
            *guard_rules(family, mode, sources),
            *rules,
            "COMMIT",
            "",
        )
    )
    return subprocess.run(
        [
            "python3",
            str(VERIFIER),
            family,
            mode,
            "3333",
            "3443",
            "28237",
            *sources,
        ],
        input=payload,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class MiningFirewallVerifierTests(unittest.TestCase):
    def assert_rejected(
        self,
        family: str,
        mode: str,
        sources: tuple[str, ...],
        rules: list[str],
        *,
        before_guard: tuple[str, ...] = (),
        chain_definitions: tuple[str, ...] = (),
    ) -> None:
        result = run_verifier(
            family,
            mode,
            sources,
            rules,
            before_guard=before_guard,
            chain_definitions=chain_definitions,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("mining firewall verification failed:", result.stderr)

    def test_exact_ipv4_and_ipv6_rules_are_accepted(self) -> None:
        ipv4 = "203.0.113.9/32"
        result = run_verifier(
            "ipv4",
            "open",
            (ipv4,),
            [rule("ufw-user-input", ipv4, "3333"), rule("ufw-user-input", ipv4, "3443")],
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        ipv6 = "2001:db8::9/128"
        result = run_verifier(
            "ipv6",
            "open",
            (ipv6,),
            [
                rule("ufw6-user-input", ipv6, "3333"),
                rule("ufw6-user-input", ipv6, "3443"),
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_closed_mode_accepts_no_managed_rules(self) -> None:
        result = run_verifier("ipv4", "closed", ("203.0.113.9/32",), [])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_closed_mode_rejects_any_managed_accept(self) -> None:
        self.assert_rejected(
            "ipv4",
            "closed",
            ("203.0.113.9/32",),
            [rule("ufw-user-input", "203.0.113.9/32", "3333")],
        )

    def test_direct_input_accept_before_guard_is_rejected(self) -> None:
        source = "203.0.113.9/32"
        self.assert_rejected(
            "ipv4",
            "open",
            (source,),
            [rule("ufw-user-input", source, "3333"), rule("ufw-user-input", source, "3443")],
            before_guard=("-A INPUT -p tcp -m tcp --dport 3333 -j ACCEPT",),
        )

    def test_early_custom_accepting_chain_before_guard_is_rejected(self) -> None:
        source = "203.0.113.9/32"
        self.assert_rejected(
            "ipv4",
            "open",
            (source,),
            [
                "-A EARLY-ACCEPT -p tcp -m tcp --dport 3443 -j ACCEPT",
                rule("ufw-user-input", source, "3333"),
                rule("ufw-user-input", source, "3443"),
            ],
            before_guard=("-A INPUT -j EARLY-ACCEPT",),
            chain_definitions=(":EARLY-ACCEPT - [0:0]",),
        )

    def test_open_mode_rejects_incomplete_duplicate_or_wrong_source_rules(self) -> None:
        source = "203.0.113.9/32"
        exact = rule("ufw-user-input", source, "3333")
        for rules in (
            [exact],
            [exact, exact, rule("ufw-user-input", source, "3443")],
            [exact, rule("ufw-user-input", "203.0.113.10/32", "3443")],
        ):
            with self.subTest(rules=rules):
                self.assert_rejected("ipv4", "open", (source,), rules)

    def test_broad_range_multiport_and_legacy_rules_are_rejected(self) -> None:
        source = "203.0.113.9/32"
        exact_tls = rule("ufw-user-input", source, "3443")
        candidates = (
            f"-A ufw-user-input -p tcp --dport 3333 -j ACCEPT",
            rule("ufw-user-input", source, "3000:4000"),
            rule("ufw-user-input", source, "3333,22", multiport=True),
            rule("ufw-user-input", source, "28237"),
            f"-A ufw-user-input -s {source} -p all -j ACCEPT",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assert_rejected("ipv4", "open", (source,), [candidate, exact_tls])

    def test_split_world_bypass_is_rejected(self) -> None:
        source = "203.0.113.9/32"
        self.assert_rejected(
            "ipv4",
            "open",
            (source,),
            [
                rule("ufw-user-input", "0.0.0.0/1", "3333"),
                rule("ufw-user-input", "128.0.0.0/1", "3333"),
                rule("ufw-user-input", source, "3443"),
            ],
        )

    def test_allowlist_requires_exact_host_addresses(self) -> None:
        result = run_verifier("ipv4", "open", ("203.0.113.0/24",), [])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact host addresses", result.stderr)


if __name__ == "__main__":
    unittest.main()

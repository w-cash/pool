#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


VERIFIER = pathlib.Path(__file__).with_name("verify-mining-firewall.py")
POLICY_PARSER = pathlib.Path(__file__).with_name("parse-mining-firewall-policy.py")
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
    elif mode == "public":
        for port in (3333, 3443):
            rules.append(
                f"-A {GUARD_CHAIN} -p tcp -m tcp --dport {port} -j RETURN"
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
    guard_override: tuple[str, ...] | None = None,
):
    chain = "ufw-user-input" if family == "ipv4" else "ufw6-user-input"
    selected_guard = (
        guard_rules(family, mode, sources)
        if guard_override is None
        else list(guard_override)
    )
    payload = "\n".join(
        (
            "*filter",
            ":INPUT DROP [0:0]",
            f":{GUARD_CHAIN} - [0:0]",
            f":{chain} - [0:0]",
            *chain_definitions,
            *before_guard,
            f"-A INPUT -j {GUARD_CHAIN}",
            *selected_guard,
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
        guard_override: tuple[str, ...] | None = None,
    ) -> None:
        result = run_verifier(
            family,
            mode,
            sources,
            rules,
            before_guard=before_guard,
            chain_definitions=chain_definitions,
            guard_override=guard_override,
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

    def test_public_ipv4_and_ipv6_rules_are_accepted(self) -> None:
        for family, chain, source in (
            ("ipv4", "ufw-user-input", "0.0.0.0/0"),
            ("ipv6", "ufw6-user-input", "::/0"),
        ):
            with self.subTest(family=family):
                result = run_verifier(
                    family,
                    "public",
                    (),
                    [rule(chain, source, "3333"), rule(chain, source, "3443")],
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_mode_rejects_narrow_incomplete_and_legacy_rules(self) -> None:
        chain = "ufw-user-input"
        public_plain = rule(chain, "0.0.0.0/0", "3333")
        public_tls = rule(chain, "0.0.0.0/0", "3443")
        candidates = (
            [public_plain],
            [rule(chain, "203.0.113.9/32", "3333"), public_tls],
            [public_plain, public_tls, rule(chain, "0.0.0.0/0", "28237")],
        )
        for rules in candidates:
            with self.subTest(rules=rules):
                self.assert_rejected("ipv4", "public", (), rules)

    def test_public_mode_rejects_source_arguments_and_restricted_guard(self) -> None:
        source = "203.0.113.9/32"
        public_rules = [
            rule("ufw-user-input", "0.0.0.0/0", "3333"),
            rule("ufw-user-input", "0.0.0.0/0", "3443"),
        ]
        self.assert_rejected("ipv4", "public", (source,), public_rules)
        self.assert_rejected(
            "ipv4",
            "public",
            (),
            public_rules,
            guard_override=tuple(guard_rules("ipv4", "open", (source,))),
        )

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


class MiningFirewallPolicyTests(unittest.TestCase):
    def parse(self, contents: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory, "miner-cidrs")
            policy.write_text(contents, encoding="ascii")
            return subprocess.run(
                ["python3", str(POLICY_PARSER), str(policy)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_public_marker_is_an_explicit_policy(self) -> None:
        result = self.parse("# intentional public Testnet ingress\nPUBLIC_TESTNET_STRATUM\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "public\n")

    def test_public_marker_must_be_the_only_policy_entry(self) -> None:
        for contents in (
            "PUBLIC_TESTNET_STRATUM\n203.0.113.9\n",
            "203.0.113.9\nPUBLIC_TESTNET_STRATUM\n",
            "PUBLIC_TESTNET_STRATUM\nPUBLIC_TESTNET_STRATUM\n",
        ):
            with self.subTest(contents=contents):
                result = self.parse(contents)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be the sole non-comment entry", result.stderr)

    def test_allowlist_remains_exact_canonical_and_deduplicated(self) -> None:
        result = self.parse(
            "203.0.113.9\n203.0.113.9/32\n2001:0db8:0:0:0:0:0:9\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "open\n203.0.113.9/32\n2001:db8::9/128\n")

    def test_broad_or_empty_policy_is_rejected(self) -> None:
        for contents in ("", "0.0.0.0/0\n", "2001:db8::/64\n"):
            with self.subTest(contents=contents):
                result = self.parse(contents)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("mining firewall policy is invalid:", result.stderr)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

import importlib.util
import pathlib
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("wait_payout_ready.py")
SPEC = importlib.util.spec_from_file_location("wait_payout_ready", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class WaitPayoutReadyTests(unittest.TestCase):
    def test_payout_readiness_endpoint_rejects_redirects(self) -> None:
        class RedirectResponse:
            status = 302

            @staticmethod
            def getheader(_name: str) -> str:
                return "text/html"

            @staticmethod
            def read(_limit: int) -> bytes:
                return b"redirect"

        connection = mock.Mock()
        connection.getresponse.return_value = RedirectResponse()
        with mock.patch.object(
            MODULE.http.client,
            "HTTPConnection",
            return_value=connection,
        ):
            self.assertIsNone(MODULE.fetch_portal_readiness(8080))

        connection.request.assert_called_once_with(
            "GET", "/readyz", headers={"Accept": "application/json"}
        )
        connection.close.assert_called_once_with()

    def test_ready_url_rejects_ambiguous_or_redirectable_authority(self) -> None:
        self.assertEqual(MODULE.validate_ready_url("http://127.0.0.1:8080/readyz"), 8080)
        for candidate in (
            "https://127.0.0.1:8080/readyz",
            "http://127.0.0.1:8080@attacker.test/readyz",
            "http://user@127.0.0.1:8080/readyz",
            "http://127.0.0.1/readyz",
            "http://127.0.0.1:8080/readyz?next=1",
            "http://127.0.0.1:8080/readyz#fragment",
            "http://127.0.0.1:8080/not-ready",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                MODULE.validate_ready_url(candidate)

    def test_delayed_external_heartbeat_eventually_succeeds(self) -> None:
        clock = FakeClock()
        attempts = iter((None, {**MODULE.EXPECTED, "payout_execution": "deferred"}, MODULE.EXPECTED))
        MODULE.wait_until_ready(
            10,
            lambda: ("active", "active", "active", "active"),
            lambda: next(attempts),
            clock.monotonic,
            clock.sleep,
        )
        self.assertEqual(clock.now, 4.0)

    def test_sigkill_takeover_readiness_budget_is_accepted(self) -> None:
        clock = FakeClock()
        MODULE.wait_until_ready(
            4200,
            lambda: ("active", "active", "active", "active"),
            lambda: MODULE.EXPECTED,
            clock.monotonic,
            clock.sleep,
        )
        self.assertEqual(clock.now, 0.0)

    def test_readiness_budget_cannot_exceed_reviewed_takeover_bound(self) -> None:
        for timeout in (0, 4201):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                MODULE.wait_until_ready(
                    timeout,
                    lambda: ("active", "active", "active", "active"),
                    lambda: MODULE.EXPECTED,
                )

    def test_required_unit_failure_aborts_without_waiting(self) -> None:
        clock = FakeClock()
        with self.assertRaises(MODULE.UnitStopped):
            MODULE.wait_until_ready(
                10,
                lambda: ("active", "failed", "active", "active"),
                lambda: MODULE.EXPECTED,
                clock.monotonic,
                clock.sleep,
            )
        self.assertEqual(clock.now, 0.0)

    def test_restarting_or_reloading_unit_cannot_inherit_old_readiness(self) -> None:
        for transitional_state in ("activating", "reloading", "deactivating"):
            fetched = False

            def fetch_readiness() -> object:
                nonlocal fetched
                fetched = True
                return MODULE.EXPECTED

            with self.subTest(state=transitional_state), self.assertRaises(MODULE.UnitStopped):
                MODULE.wait_until_ready(
                    10,
                    lambda: ("active", "active", "active", transitional_state),
                    fetch_readiness,
                )
            self.assertFalse(fetched)

    def test_missing_heartbeat_times_out_at_exact_bound(self) -> None:
        clock = FakeClock()
        with self.assertRaises(MODULE.ReadinessTimeout):
            MODULE.wait_until_ready(
                5,
                lambda: ("active", "active", "active", "active"),
                lambda: None,
                clock.monotonic,
                clock.sleep,
            )
        self.assertEqual(clock.now, 5.0)


if __name__ == "__main__":
    unittest.main()

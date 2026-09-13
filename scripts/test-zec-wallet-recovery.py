#!/usr/bin/env python3
"""Black-box-style tests for the Zcash collector recovery ceremony."""

from __future__ import annotations

import base64
import copy
import hashlib
import http.server
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parent / "deploy" / "verify-zec-wallet-recovery.py"
SPEC = importlib.util.spec_from_file_location("zec_recovery", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

GENESIS = "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
SEEDFP = "zip32seedfp1qhrfsdsqlj7xuvw3ncu76u98c2pxfyq2c24zdm5jr3pr6ms6dswss6dvur"
ADDRESS = (
    "utest10zg6frxk32ma8980kdv9473e4aclw7clq9hydzcj6l349pkqzxk2mmj3cn7j5x"
    "38w6l4wyryv50whnlrw0k9agzpdf5fxyj7kq96ukcp"
)
DEFAULT_ADDRESS = (
    "utest10c5kutapazdnf8ztl3pu43nkfsjx89fy3uuff8tsmxm6s86j37pe7uz94z5jhkl"
    "49pqe8yz75rlsaygexk6jpaxwx0esjr8wm5ut7d5s"
)
COMMITMENT = hashlib.sha256(
    b"Wcash/Zcash parent payout address/v1\0" + ADDRESS.encode("ascii")
).hexdigest()
ORIGINAL_UUID = "11111111-1111-4111-8111-111111111111"
RECOVERED_UUID = "22222222-2222-4222-8222-222222222222"
ORIGINAL_TIP = {"height": 4_300_000, "blockhash": "12" * 32}
RECOVERY_TIP = {"height": 4_300_007, "blockhash": "34" * 32}
COOKIE = "__cookie__:unit-test-only"


class RpcState:
    def __init__(
        self,
        recovered: bool,
        default_index: int = 1,
        pre_account_tips: list[dict[str, object]] | None = None,
    ) -> None:
        self.recovered = recovered
        self.tip = RECOVERY_TIP if recovered else ORIGINAL_TIP
        self.created = False
        self.collector_derived = False
        self.default_index = default_index
        self.pre_account_tips = list(pre_account_tips or [])
        self.pre_account_status_calls = 0
        self.authenticated_calls = 0

    @property
    def account_uuid(self) -> str:
        return RECOVERED_UUID if self.recovered else ORIGINAL_UUID

    def result(self, method: str, params: object) -> object:
        if method == "getwalletstatus":
            if not self.created:
                self.pre_account_status_calls += 1
            tip = (
                self.pre_account_tips.pop(0)
                if not self.created and self.pre_account_tips
                else self.tip
            )
            result = {
                "node_tip": tip,
                "wallet_tip": tip,
                # Pinned Zallet beta.3 cannot derive a fully-scanned height
                # before an account exists, so its synchronization lock stays
                # set in this otherwise terminal bootstrap state.
                "locked": not self.created,
            }
            if self.created:
                result["fully_synced_height"] = self.tip["height"]
            return result
        if method == "z_listaccounts":
            if params != [False]:
                raise ValueError("wrong list params")
            if not self.created:
                return []
            return [
                {
                    "account_uuid": self.account_uuid,
                    "name": MODULE.ACCOUNT_NAME,
                    "seedfp": SEEDFP,
                    "zip32_account_index": 0,
                    "account": 0,
                }
            ]
        if method == "z_getnewaccount" and not self.recovered:
            if params != [MODULE.ACCOUNT_NAME] or self.created:
                raise ValueError("invalid account creation")
            self.created = True
            return {"account_uuid": self.account_uuid}
        if method == "z_recoveraccounts" and self.recovered:
            if self.created:
                raise ValueError("duplicate recovery")
            account = params[0][0]
            if account != {
                "name": MODULE.ACCOUNT_NAME,
                "seedfp": SEEDFP,
                "zip32_account_index": 0,
                "birthday_height": ORIGINAL_TIP["height"],
            }:
                raise ValueError("invalid recovery")
            self.created = True
            return {
                "accounts": [
                    {
                        "account_uuid": self.account_uuid,
                        "seedfp": SEEDFP,
                        "zip32_account_index": 0,
                    }
                ]
            }
        if method == "z_getaddressforaccount" and self.created:
            if params == [
                self.account_uuid,
                list(MODULE.DEFAULT_RECEIVER_TYPES),
                self.default_index,
            ]:
                return {
                    "account_uuid": self.account_uuid,
                    "diversifier_index": self.default_index,
                    "receiver_types": list(MODULE.DEFAULT_RECEIVER_TYPES),
                    "address": DEFAULT_ADDRESS,
                }
            collector_index = MODULE.collector_diversifier_index(self.default_index)
            if params == [self.account_uuid, ["orchard"], collector_index]:
                self.collector_derived = True
                return {
                    "account_uuid": self.account_uuid,
                    "diversifier_index": collector_index,
                    "receiver_types": ["orchard"],
                    "address": ADDRESS,
                }
            raise ValueError("invalid derivation")
        if method == "z_getaccount" and self.created:
            if params != [self.account_uuid]:
                raise ValueError("wrong account")
            addresses = [
                {
                    "diversifier_index": self.default_index,
                    "ua": DEFAULT_ADDRESS,
                }
            ]
            if self.collector_derived:
                addresses.append(
                    {
                        "diversifier_index": MODULE.collector_diversifier_index(
                            self.default_index
                        ),
                        "ua": ADDRESS,
                    }
                )
                # The verifier must not rely on Zallet's current row ordering.
                if self.recovered:
                    addresses.reverse()
            return {
                "account_uuid": self.account_uuid,
                "name": MODULE.ACCOUNT_NAME,
                "seedfp": SEEDFP,
                "zip32_account_index": 0,
                "addresses": addresses,
            }
        raise ValueError(f"unexpected method {method}")


class RecoveryVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.root.chmod(0o700)
        MODULE.TRUSTED_UID = os.getuid()
        MODULE.SYNC_DEADLINE_SECONDS = 0.1
        MODULE.SYNC_POLL_SECONDS = 0.01
        self.settings = self.root / "deployment.env"
        self.settings.write_text(
            "\n".join(
                (
                    f"ZCASH_GENESIS_DISPLAY={GENESIS}",
                    f"ZCASH_GENESIS_WIRE={bytes.fromhex(GENESIS)[::-1].hex()}",
                    f"ZCASH_SIGNER_ACCOUNT={ORIGINAL_UUID}",
                    "ZCASH_SIGNER_ACCOUNT_INDEX=0",
                    f"ZCASH_PAYOUT_COMMITMENT_WIRE={COMMITMENT}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.settings.chmod(0o600)
        self.cookie = self.root / "rpc-cookie"
        self.cookie.write_text(COOKIE + "\n", encoding="ascii")
        self.cookie.chmod(0o400)
        self.native = self.root / "wcash-poold"
        self.native.write_text(
            "#!/bin/sh\n"
            "IFS= read -r address\n"
            f"[ \"$address\" = '{ADDRESS}' ] || exit 78\n"
            "[ \"$1\" = validate-zec-testnet-orchard ] || exit 78\n"
            "printf '%s\\n' '{\"valid\":true,\"network\":\"testnet\",\"receiver\":\"orchard\"}'\n",
            encoding="utf-8",
        )
        self.native.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def server(
        self,
        recovered: bool,
        default_index: int = 1,
        pre_account_tips: list[dict[str, object]] | None = None,
    ):
        state = RpcState(recovered, default_index, pre_account_tips)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(handler) -> None:
                expected = "Basic " + base64.b64encode(COOKIE.encode("ascii")).decode("ascii")
                if handler.headers.get("Authorization") != expected:
                    handler.send_response(401)
                    handler.end_headers()
                    return
                state.authenticated_calls += 1
                length = int(handler.headers["Content-Length"])
                request = json.loads(handler.rfile.read(length))
                result = state.result(request["method"], request["params"])
                response = json.dumps(
                    {"jsonrpc": "2.0", "id": request["id"], "result": result},
                    separators=(",", ":"),
                ).encode()
                handler.send_response(200)
                handler.send_header("Content-Type", "application/json")
                handler.send_header("Content-Length", str(len(response)))
                handler.end_headers()
                handler.wfile.write(response)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, state

    def capture_pair(self, default_index: int = 1) -> tuple[pathlib.Path, pathlib.Path]:
        original_server, original_thread, original_state = self.server(
            False, default_index
        )
        original = self.root / "original.rpc.json"
        try:
            MODULE.capture_original(
                os.fspath(self.settings),
                f"127.0.0.1:{original_server.server_port}",
                os.fspath(self.cookie),
                os.fspath(original),
                os.fspath(self.native),
            )
        finally:
            original_server.shutdown()
            original_thread.join()
            original_server.server_close()
        self.assertGreaterEqual(original_state.authenticated_calls, 9)
        for suffix in ("mutation-intent", "mutation-receipt", "pending"):
            self.assertFalse((self.root / f"{original.name}.{suffix}").exists())

        recovered_server, recovered_thread, recovered_state = self.server(
            True, default_index
        )
        recovered = self.root / "recovered.rpc.json"
        try:
            MODULE.capture_recovered(
                os.fspath(self.settings),
                os.fspath(original),
                f"127.0.0.1:{recovered_server.server_port}",
                os.fspath(self.cookie),
                os.fspath(recovered),
                os.fspath(self.native),
                True,
            )
        finally:
            recovered_server.shutdown()
            recovered_thread.join()
            recovered_server.server_close()
        self.assertGreaterEqual(recovered_state.authenticated_calls, 9)
        for suffix in ("mutation-intent", "mutation-receipt", "pending"):
            self.assertFalse((self.root / f"{recovered.name}.{suffix}").exists())
        return original, recovered


    def test_authenticated_capture_recovery_and_seal(self) -> None:
        original, recovered = self.capture_pair()
        expected = MODULE.expected_from_inputs(
            os.fspath(self.settings),
            os.fspath(original),
            os.fspath(recovered),
            os.fspath(self.native),
        )
        attestation = self.root / "attestation.json"
        MODULE.write_once(os.fspath(attestation), expected)
        self.assertEqual(stat.S_IMODE(attestation.stat().st_mode), 0o400)
        serialized = attestation.read_text(encoding="utf-8")
        self.assertNotIn(SEEDFP, serialized)
        self.assertNotIn(ADDRESS, serialized)
        self.assertNotIn("machine", serialized)
        self.assertIs(
            expected["operator_acknowledged_fresh_isolated_mnemonic_recovery"],
            True,
        )
        self.assertEqual(
            MODULE.read_object(os.fspath(attestation), "attestation"), expected
        )

    def test_pinned_zallet_default_and_collector_address_set(self) -> None:
        original, recovered = self.capture_pair()
        for path in (original, recovered):
            capture = MODULE.read_object(os.fspath(path), "capture")
            transcript = capture["rpc_transcript"]
            before = transcript["account_before_collector"]["response"]["result"]
            after = transcript["account"]["response"]["result"]
            default = transcript["default_address"]["response"]["result"]
            collector = transcript["derived_address"]["response"]["result"]
            self.assertEqual(len(before["addresses"]), 1)
            self.assertEqual(len(after["addresses"]), 2)
            self.assertEqual(
                default["receiver_types"], list(MODULE.DEFAULT_RECEIVER_TYPES)
            )
            self.assertEqual(collector["receiver_types"], ["orchard"])
            self.assertEqual(
                {
                    (entry["diversifier_index"], entry["ua"])
                    for entry in after["addresses"]
                },
                {
                    (default["diversifier_index"], default["address"]),
                    (collector["diversifier_index"], collector["address"]),
                },
            )

        value = json.loads(original.read_text(encoding="utf-8"))
        value["rpc_transcript"]["account"]["response"]["result"]["addresses"].append(
            {"diversifier_index": 2, "ua": DEFAULT_ADDRESS + "q"}
        )
        with self.assertRaises(SystemExit):
            MODULE.validate_capture(
                value,
                "original_wallet_creation",
                MODULE.read_settings(os.fspath(self.settings), False),
                os.fspath(self.native),
            )

    def test_collector_uses_index_one_when_default_owns_zero(self) -> None:
        original, recovered = self.capture_pair(default_index=0)
        settings = MODULE.read_settings(os.fspath(self.settings), False)
        original_identity = MODULE.validate_capture(
            MODULE.read_object(os.fspath(original), "capture"),
            "original_wallet_creation",
            settings,
            os.fspath(self.native),
        )
        recovered_identity = MODULE.validate_capture(
            MODULE.read_object(os.fspath(recovered), "capture"),
            "independent_mnemonic_recovery",
            settings,
            os.fspath(self.native),
        )
        self.assertEqual(original_identity["default_diversifier_index"], 0)
        self.assertEqual(original_identity["diversifier_index"], 1)
        self.assertEqual(recovered_identity["diversifier_index"], 1)

    def test_pre_account_lock_exception_is_exact_and_accountless(self) -> None:
        locked = {
            "node_tip": ORIGINAL_TIP,
            "wallet_tip": ORIGINAL_TIP,
            "locked": True,
        }
        self.assertEqual(
            MODULE.validate_status(locked, "pre-account status", False),
            ORIGINAL_TIP["height"],
        )

        for mutation in (
            {"sync_work_remaining": None},
            {"fully_synced_height": ORIGINAL_TIP["height"]},
            {"locked": 1},
            {"wallet_tip": {"height": ORIGINAL_TIP["height"] - 1, "blockhash": "56" * 32}},
        ):
            invalid = dict(locked)
            invalid.update(mutation)
            with self.assertRaises(SystemExit):
                MODULE.validate_status(invalid, "pre-account status", False)

        with self.assertRaises(SystemExit):
            MODULE.validate_status(locked, "post-account status", True)

        server, thread, state = self.server(False)
        original_result = state.result

        def nonempty_pre_accounts(method: str, params: object) -> object:
            if method == "z_listaccounts" and not state.created:
                return [{"unexpected": "account"}]
            return original_result(method, params)

        state.result = nonempty_pre_accounts  # type: ignore[method-assign]
        output = self.root / "nonempty-pre-accounts.rpc.json"
        try:
            with self.assertRaises(SystemExit):
                MODULE.capture_original(
                    os.fspath(self.settings),
                    f"127.0.0.1:{server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(output),
                    os.fspath(self.native),
                )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertFalse(output.exists())
        self.assertFalse((self.root / f"{output.name}.mutation-intent").exists())

    def test_rejects_mutated_or_hand_authored_transcript(self) -> None:
        original, recovered = self.capture_pair()
        value = json.loads(recovered.read_text(encoding="utf-8"))
        value["fresh_wallet_database"] = True
        recovered.chmod(0o600)
        recovered.write_text(json.dumps(value) + "\n", encoding="utf-8")
        recovered.chmod(0o400)
        with self.assertRaises(SystemExit):
            MODULE.expected_from_inputs(
                os.fspath(self.settings),
                os.fspath(original),
                os.fspath(recovered),
                os.fspath(self.native),
            )

        value.pop("fresh_wallet_database")
        value["rpc_transcript"]["account_operation"]["request"]["params"][0][0][
            "birthday_height"
        ] += 1
        recovered.chmod(0o600)
        recovered.write_text(json.dumps(value) + "\n", encoding="utf-8")
        recovered.chmod(0o400)
        with self.assertRaises(SystemExit):
            MODULE.expected_from_inputs(
                os.fspath(self.settings),
                os.fspath(original),
                os.fspath(recovered),
                os.fspath(self.native),
            )

    def test_requires_private_single_link_root_boundary(self) -> None:
        original, _recovered = self.capture_pair()
        original.chmod(0o644)
        with self.assertRaises(SystemExit):
            MODULE.read_object(os.fspath(original), "capture")
        original.chmod(0o400)
        hardlink = self.root / "hardlink"
        os.link(original, hardlink)
        with self.assertRaises(SystemExit):
            MODULE.read_object(os.fspath(original), "capture")

    def test_non_root_cli_is_rejected(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("test runner is root")
        result = subprocess.run(
            ("python3", os.fspath(SCRIPT)),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must run as root", result.stderr)

    def test_recovery_requires_explicit_fresh_datadir_acknowledgement(self) -> None:
        with self.assertRaises(SystemExit):
            MODULE.capture_recovered(
                os.fspath(self.settings),
                os.fspath(self.root / "not-read.json"),
                "127.0.0.1:1",
                os.fspath(self.cookie),
                os.fspath(self.root / "not-written.json"),
                os.fspath(self.native),
                False,
            )
        self.assertFalse((self.root / "not-written.json").exists())

    def test_recovery_waits_for_frozen_birthday_before_mutating_wallet(self) -> None:
        original, _ = self.capture_pair()
        lagging_tip = {
            "height": ORIGINAL_TIP["height"] - 1,
            "blockhash": "56" * 32,
        }
        server, thread, state = self.server(
            True,
            pre_account_tips=[lagging_tip, RECOVERY_TIP],
        )
        recovered = self.root / "caught-up-recovery.rpc.json"
        try:
            MODULE.capture_recovered(
                os.fspath(self.settings),
                os.fspath(original),
                f"127.0.0.1:{server.server_port}",
                os.fspath(self.cookie),
                os.fspath(recovered),
                os.fspath(self.native),
                True,
            )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertTrue(recovered.exists())
        self.assertGreaterEqual(state.pre_account_status_calls, 2)
        self.assertTrue(state.created)

    def test_recovery_tip_timeout_precedes_intent_and_mutating_rpc(self) -> None:
        original, _ = self.capture_pair()
        MODULE.SYNC_DEADLINE_SECONDS = 0.02
        lagging_tip = {
            "height": ORIGINAL_TIP["height"] - 1,
            "blockhash": "78" * 32,
        }
        server, thread, state = self.server(
            True,
            pre_account_tips=[lagging_tip] * 20,
        )
        recovered = self.root / "timed-out-recovery.rpc.json"
        try:
            with self.assertRaises(SystemExit):
                MODULE.capture_recovered(
                    os.fspath(self.settings),
                    os.fspath(original),
                    f"127.0.0.1:{server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(recovered),
                    os.fspath(self.native),
                    True,
                )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertFalse(state.created)
        self.assertFalse(recovered.exists())
        for suffix in ("mutation-intent", "mutation-receipt", "pending"):
            self.assertFalse((self.root / f"{recovered.name}.{suffix}").exists())

    def test_capture_refuses_stale_output_before_mutating_rpc(self) -> None:
        stale = self.root / "stale.rpc.json"
        stale.write_text("{}\n", encoding="utf-8")
        stale.chmod(0o400)
        server, thread, state = self.server(False)
        try:
            with self.assertRaises(SystemExit):
                MODULE.capture_original(
                    os.fspath(self.settings),
                    f"127.0.0.1:{server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(stale),
                    os.fspath(self.native),
                )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertEqual(state.authenticated_calls, 0)
        self.assertEqual(stale.read_text(encoding="utf-8"), "{}\n")

    def test_capture_refuses_stale_intent_before_any_rpc(self) -> None:
        output = self.root / "stale-intent.rpc.json"
        intent = self.root / "stale-intent.rpc.json.mutation-intent"
        intent.write_text("tainted\n", encoding="utf-8")
        intent.chmod(0o400)
        server, thread, state = self.server(False)
        try:
            with self.assertRaises(SystemExit):
                MODULE.capture_original(
                    os.fspath(self.settings),
                    f"127.0.0.1:{server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(output),
                    os.fspath(self.native),
                )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertEqual(state.authenticated_calls, 0)
        self.assertFalse(output.exists())
        self.assertEqual(intent.read_text(encoding="utf-8"), "tainted\n")

    def test_capture_refuses_stale_receipt_or_pending_before_any_rpc(self) -> None:
        for suffix in ("mutation-receipt", "pending"):
            with self.subTest(suffix=suffix):
                output = self.root / f"stale-{suffix}.rpc.json"
                artifact = self.root / f"{output.name}.{suffix}"
                artifact.write_text("tainted\n", encoding="utf-8")
                artifact.chmod(0o400)
                server, thread, state = self.server(False)
                try:
                    with self.assertRaises(SystemExit):
                        MODULE.capture_original(
                            os.fspath(self.settings),
                            f"127.0.0.1:{server.server_port}",
                            os.fspath(self.cookie),
                            os.fspath(output),
                            os.fspath(self.native),
                        )
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                self.assertEqual(state.authenticated_calls, 0)
                self.assertFalse(output.exists())
                self.assertEqual(artifact.read_text(encoding="utf-8"), "tainted\n")

    def test_intent_is_durable_before_each_mutation_and_cleared_on_success(self) -> None:
        original_server, original_thread, _state = self.server(False)
        original = self.root / "timed-original.rpc.json"
        original_intent = original.parent / MODULE.mutation_intent_name(
            os.fspath(original)
        )
        observations: list[dict[str, object]] = []
        real_rpc_call = MODULE.rpc_call

        def observe_original(*args: object, **kwargs: object) -> dict:
            method = args[5]
            if method == "z_getnewaccount":
                self.assertTrue(original_intent.exists())
                self.assertEqual(stat.S_IMODE(original_intent.stat().st_mode), 0o400)
                observations.append(json.loads(original_intent.read_text(encoding="utf-8")))
            return real_rpc_call(*args, **kwargs)

        try:
            with mock.patch.object(MODULE, "rpc_call", side_effect=observe_original):
                MODULE.capture_original(
                    os.fspath(self.settings),
                    f"127.0.0.1:{original_server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(original),
                    os.fspath(self.native),
                )
        finally:
            original_server.shutdown()
            original_thread.join()
            original_server.server_close()
        self.assertEqual(observations[0]["operation"], "z_getnewaccount")
        self.assertFalse(original_intent.exists())

        recovered_server, recovered_thread, _state = self.server(True)
        recovered = self.root / "timed-recovered.rpc.json"
        recovered_intent = recovered.parent / MODULE.mutation_intent_name(
            os.fspath(recovered)
        )

        def observe_recovered(*args: object, **kwargs: object) -> dict:
            method = args[5]
            if method == "z_recoveraccounts":
                self.assertTrue(recovered_intent.exists())
                self.assertEqual(stat.S_IMODE(recovered_intent.stat().st_mode), 0o400)
                observations.append(json.loads(recovered_intent.read_text(encoding="utf-8")))
            return real_rpc_call(*args, **kwargs)

        try:
            with mock.patch.object(MODULE, "rpc_call", side_effect=observe_recovered):
                MODULE.capture_recovered(
                    os.fspath(self.settings),
                    os.fspath(original),
                    f"127.0.0.1:{recovered_server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(recovered),
                    os.fspath(self.native),
                    True,
                )
        finally:
            recovered_server.shutdown()
            recovered_thread.join()
            recovered_server.server_close()
        self.assertEqual(observations[1]["operation"], "z_recoveraccounts")
        self.assertFalse(recovered_intent.exists())

    def test_mutation_and_post_mutation_failures_retain_intent(self) -> None:
        real_rpc_call = MODULE.rpc_call
        scenarios = ("rpc", "validation", "write")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                server, thread, _state = self.server(False)
                output = self.root / f"failed-{scenario}.rpc.json"
                intent = output.parent / MODULE.mutation_intent_name(
                    os.fspath(output)
                )

                def fail_at_requested_stage(*args: object, **kwargs: object) -> dict:
                    method = args[5]
                    if method == "z_getnewaccount" and scenario == "rpc":
                        raise SystemExit("simulated RPC failure")
                    result = real_rpc_call(*args, **kwargs)
                    if method == "z_getnewaccount" and scenario == "validation":
                        result["response"]["result"] = {}
                    return result

                patches = [mock.patch.object(MODULE, "rpc_call", side_effect=fail_at_requested_stage)]
                if scenario == "write":
                    patches.append(
                        mock.patch.object(
                            MODULE,
                            "write_once",
                            side_effect=SystemExit("simulated durable-write failure"),
                        )
                    )
                try:
                    with patches[0]:
                        if len(patches) == 2:
                            patches[1].start()
                        try:
                            with self.assertRaises(SystemExit):
                                MODULE.capture_original(
                                    os.fspath(self.settings),
                                    f"127.0.0.1:{server.server_port}",
                                    os.fspath(self.cookie),
                                    os.fspath(output),
                                    os.fspath(self.native),
                                )
                        finally:
                            if len(patches) == 2:
                                patches[1].stop()
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                self.assertFalse(output.exists())
                self.assertTrue(intent.exists())
                self.assertEqual(stat.S_IMODE(intent.stat().st_mode), 0o400)

    def test_post_validation_failure_retains_complete_pending_transcript(self) -> None:
        server, thread, state = self.server(False)
        output = self.root / "failed-final-validation.rpc.json"
        intent = self.root / f"{output.name}.mutation-intent"
        receipt = pathlib.Path(MODULE.mutation_receipt_path(os.fspath(output)))
        pending = pathlib.Path(MODULE.pending_capture_path(os.fspath(output)))
        original_result = state.result

        def add_unexpected_exposed_address(method: str, params: object) -> object:
            result = original_result(method, params)
            if method == "z_getaccount" and state.collector_derived:
                assert isinstance(result, dict)
                result["addresses"].append(
                    {"diversifier_index": 2, "ua": DEFAULT_ADDRESS + "q"}
                )
            return result

        state.result = add_unexpected_exposed_address  # type: ignore[method-assign]
        try:
            with self.assertRaises(SystemExit):
                MODULE.capture_original(
                    os.fspath(self.settings),
                    f"127.0.0.1:{server.server_port}",
                    os.fspath(self.cookie),
                    os.fspath(output),
                    os.fspath(self.native),
                )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertFalse(output.exists())
        for artifact in (intent, receipt, pending):
            self.assertTrue(artifact.exists())
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o400)
        receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            set(receipt_value["rpc_transcript"]),
            {"pre_status", "pre_accounts", "account_operation"},
        )
        pending_value = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(set(pending_value["rpc_transcript"]), MODULE.TRANSCRIPT_FIELDS)

    def test_bool_aliases_are_rejected_in_recovery_transcript(self) -> None:
        original, recovered = self.capture_pair()
        value = json.loads(recovered.read_text(encoding="utf-8"))
        for path in (
            ("account_operation", "response", "result", "accounts", 0, "zip32_account_index"),
            ("account", "response", "result", "addresses", 0, "diversifier_index"),
            ("accounts", "response", "result", 0, "account"),
        ):
            mutated = copy.deepcopy(value)
            cursor = mutated["rpc_transcript"]
            for component in path[:-1]:
                cursor = cursor[component]
            cursor[path[-1]] = False
            recovered.chmod(0o600)
            recovered.write_text(json.dumps(mutated) + "\n", encoding="utf-8")
            recovered.chmod(0o400)
            with self.assertRaises(SystemExit):
                MODULE.expected_from_inputs(
                    os.fspath(self.settings),
                    os.fspath(original),
                    os.fspath(recovered),
                    os.fspath(self.native),
                )

    def test_native_validator_fails_closed(self) -> None:
        MODULE.native_validate(os.fspath(self.native), ADDRESS)
        with self.assertRaises(SystemExit):
            MODULE.native_validate(os.fspath(self.native), ADDRESS[:-1] + "q")
        self.native.chmod(0o722)
        with self.assertRaises(SystemExit):
            MODULE.native_validate(os.fspath(self.native), ADDRESS)


if __name__ == "__main__":
    unittest.main()

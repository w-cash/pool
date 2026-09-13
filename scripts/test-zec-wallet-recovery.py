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
COMMITMENT = hashlib.sha256(
    b"Wcash/Zcash parent payout address/v1\0" + ADDRESS.encode("ascii")
).hexdigest()
ORIGINAL_UUID = "11111111-1111-4111-8111-111111111111"
RECOVERED_UUID = "22222222-2222-4222-8222-222222222222"
ORIGINAL_TIP = {"height": 4_300_000, "blockhash": "12" * 32}
RECOVERY_TIP = {"height": 4_300_007, "blockhash": "34" * 32}
COOKIE = "__cookie__:unit-test-only"


class RpcState:
    def __init__(self, recovered: bool) -> None:
        self.recovered = recovered
        self.tip = RECOVERY_TIP if recovered else ORIGINAL_TIP
        self.created = False
        self.authenticated_calls = 0

    @property
    def account_uuid(self) -> str:
        return RECOVERED_UUID if self.recovered else ORIGINAL_UUID

    def result(self, method: str, params: object) -> object:
        if method == "getwalletstatus":
            result = {"node_tip": self.tip, "wallet_tip": self.tip, "locked": False}
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
            if params != [self.account_uuid, ["orchard"], 0]:
                raise ValueError("invalid derivation")
            return {
                "account_uuid": self.account_uuid,
                "diversifier_index": 0,
                "receiver_types": ["orchard"],
                "address": ADDRESS,
            }
        if method == "z_getaccount" and self.created:
            if params != [self.account_uuid]:
                raise ValueError("wrong account")
            return {
                "account_uuid": self.account_uuid,
                "name": MODULE.ACCOUNT_NAME,
                "seedfp": SEEDFP,
                "zip32_account_index": 0,
                "addresses": [{"diversifier_index": 0, "ua": ADDRESS}],
            }
        raise ValueError(f"unexpected method {method}")


class RecoveryVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.root.chmod(0o700)
        MODULE.TRUSTED_UID = os.getuid()
        MODULE.SYNC_DEADLINE_SECONDS = 0.1
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

    def server(self, recovered: bool):
        state = RpcState(recovered)

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

    def capture_pair(self) -> tuple[pathlib.Path, pathlib.Path]:
        original_server, original_thread, original_state = self.server(False)
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
        self.assertGreaterEqual(original_state.authenticated_calls, 7)

        recovered_server, recovered_thread, recovered_state = self.server(True)
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
        self.assertGreaterEqual(recovered_state.authenticated_calls, 7)
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

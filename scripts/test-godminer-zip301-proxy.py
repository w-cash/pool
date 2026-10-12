#!/usr/bin/env python3
"""Hermetic admission, cleanup, and protocol tests for the ZIP-301 adapter."""

import asyncio
import importlib.util
import ipaddress
import json
from pathlib import Path
import shlex
import sys
import tomllib
import unittest
from unittest.mock import AsyncMock, patch


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("zip301_proxy", ROOT / "deploy/godminer_zip301_proxy.py")
PROXY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROXY)


class FakeWriter:
    def __init__(self, peer=("198.51.100.1", 12345), close_error=None):
        self.peer = peer
        self.closed = False
        self.close_error = close_error
        self.written = []
        self.transport = self
        self.aborted = False

    def get_extra_info(self, name):
        return self.peer if name == "peername" else None

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def abort(self):
        self.aborted = True
        self.closed = True

    async def wait_closed(self):
        if self.close_error is not None:
            raise self.close_error


class AdmissionTests(unittest.TestCase):
    def test_distinct_peers_can_exceed_eight_connections_up_to_aggregate_limit(self):
        limits = PROXY.ConnectionLimits(64, 8)
        held = []
        for index in range(8):
            address = ipaddress.ip_address(f"198.51.100.{index + 1}")
            for _ in range(8):
                self.assertTrue(limits.try_acquire(address))
                held.append(address)
            self.assertFalse(limits.try_acquire(address))
        self.assertEqual(limits.active, 64)
        self.assertFalse(limits.try_acquire(ipaddress.ip_address("203.0.113.9")))
        for address in held:
            limits.release(address)
        self.assertEqual(limits.active, 0)
        self.assertEqual(limits.sources, {})

    def test_native_and_mapped_ipv4_share_one_source_quota(self):
        limits = PROXY.ConnectionLimits(64, 1)
        native = PROXY.peer_address(("198.51.100.1", 1000))
        mapped = PROXY.peer_address(("::ffff:198.51.100.1", 2000, 0, 0))
        self.assertEqual(native, mapped)
        self.assertTrue(limits.try_acquire(native))
        self.assertFalse(limits.try_acquire(mapped))

    def test_invalid_limits_are_rejected(self):
        for aggregate, per_ip in [(0, 1), (65536, 1), (64, 0), (64, 65)]:
            with self.subTest(aggregate=aggregate, per_ip=per_ip):
                with self.assertRaises(ValueError):
                    PROXY.ConnectionLimits(aggregate, per_ip)
        for value in ["0", "-1", "65536", "unbounded"]:
            with self.subTest(value=value):
                with self.assertRaises(PROXY.argparse.ArgumentTypeError):
                    PROXY.connection_limit(value)

    def test_both_routes_allow_aggregate_loopback_connections_and_limit_public_peers(self):
        for directory, config_name, unit_name, upstream_port in [
            ("mainnet-compat", "pool-z15pro-compat.toml", "zecwec-godminer-proxy.service", "3337"),
            ("mainnet-gpu", "pool-gpu.toml", "zecwec-gpu-proxy.service", "3339"),
        ]:
            with self.subTest(route=directory):
                route = ROOT / "deploy" / directory
                config = tomllib.loads((route / config_name).read_text())
                command = next(
                    line.removeprefix("ExecStart=")
                    for line in (route / unit_name).read_text().splitlines()
                    if line.startswith("ExecStart=")
                )
                arguments = shlex.split(command)
                aggregate = int(arguments[arguments.index("--maximum-connections") + 1])
                per_ip = int(arguments[arguments.index("--maximum-connections-per-ip") + 1])
                self.assertEqual(aggregate, 64)
                self.assertEqual(per_ip, 8)
                self.assertEqual(config["maximum_miners"], aggregate)
                self.assertEqual(config["maximum_miners_per_ip"], aggregate)
                self.assertEqual(
                    arguments[arguments.index("--upstream") + 1], f"127.0.0.1:{upstream_port}"
                )


class ConnectionCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_stalled_writer_close_aborts_after_deadline(self):
        class StalledWriter(FakeWriter):
            async def wait_closed(self):
                await asyncio.Future()

        writer = StalledWriter()
        with patch.object(PROXY, "WRITER_CLOSE_TIMEOUT", 0.01):
            await asyncio.wait_for(PROXY.close_writer(writer), 1)
        self.assertTrue(writer.closed)
        self.assertTrue(writer.aborted)

    async def test_cancellation_during_writer_close_aborts_and_propagates(self):
        started = asyncio.Event()

        class StalledWriter(FakeWriter):
            async def wait_closed(self):
                started.set()
                await asyncio.Future()

        writer = StalledWriter()
        closing = asyncio.create_task(PROXY.close_writer(writer))
        await started.wait()
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertTrue(writer.closed)
        self.assertTrue(writer.aborted)

    async def test_excess_connection_closes_before_upstream_and_cannot_spoof_its_source(self):
        limits = PROXY.ConnectionLimits(64, 1)
        address = PROXY.peer_address(("198.51.100.1", 1000))
        self.assertTrue(limits.try_acquire(address))
        reader = asyncio.StreamReader()
        reader.feed_data(b"PROXY TCP4 203.0.113.1 127.0.0.1 5000 3336\r\n")
        reader.feed_data(b'{"method":"mining.authorize","params":["203.0.113.2.worker","x"]}\n')
        writer = FakeWriter(("198.51.100.1", 2000))
        with patch.object(PROXY.asyncio, "open_connection", new_callable=AsyncMock) as upstream:
            await PROXY.serve_connection(reader, writer, "127.0.0.1", 3337, limits)
            upstream.assert_not_awaited()
        self.assertTrue(writer.closed)
        self.assertEqual(limits.active, 1)
        limits.release(address)

    async def test_missing_peer_closes_before_upstream(self):
        limits = PROXY.ConnectionLimits(64, 8)
        writer = FakeWriter(None)
        with patch.object(PROXY.asyncio, "open_connection", new_callable=AsyncMock) as upstream:
            await PROXY.serve_connection(asyncio.StreamReader(), writer, "127.0.0.1", 3337, limits)
            upstream.assert_not_awaited()
        self.assertTrue(writer.closed)
        self.assertEqual(limits.sources, {})

    async def test_failed_upstream_setup_releases_both_limits(self):
        limits = PROXY.ConnectionLimits(1, 1)
        writer = FakeWriter()
        with patch.object(PROXY.asyncio, "open_connection", new_callable=AsyncMock) as upstream:
            upstream.side_effect = ConnectionRefusedError()
            await PROXY.serve_connection(asyncio.StreamReader(), writer, "127.0.0.1", 3337, limits)
        self.assertTrue(writer.closed)
        self.assertEqual(limits.active, 0)
        self.assertEqual(limits.sources, {})
        address = PROXY.peer_address(writer.peer)
        self.assertTrue(limits.try_acquire(address))
        limits.release(address)

    async def test_cancellation_during_setup_releases_both_limits(self):
        limits = PROXY.ConnectionLimits(1, 1)
        writer = FakeWriter()
        started = asyncio.Event()

        async def pending_setup(*_args, **_kwargs):
            started.set()
            await asyncio.Future()

        with patch.object(PROXY.asyncio, "open_connection", side_effect=pending_setup):
            connection = asyncio.create_task(
                PROXY.serve_connection(asyncio.StreamReader(), writer, "127.0.0.1", 3337, limits)
            )
            await started.wait()
            connection.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await connection
        self.assertTrue(writer.closed)
        self.assertEqual(limits.active, 0)
        self.assertEqual(limits.sources, {})

    async def test_active_relay_cancellation_releases_limits_despite_stalled_close(self):
        started = asyncio.Event()

        class ActiveReader(asyncio.StreamReader):
            async def readline(self):
                started.set()
                return await super().readline()

        class StalledWriter(FakeWriter):
            async def wait_closed(self):
                await asyncio.Future()

        limits = PROXY.ConnectionLimits(1, 1)
        client_writer = StalledWriter()
        upstream_writer = StalledWriter()
        with patch.object(PROXY.asyncio, "open_connection", new_callable=AsyncMock) as upstream:
            upstream.return_value = asyncio.StreamReader(), upstream_writer
            with patch.object(PROXY, "WRITER_CLOSE_TIMEOUT", 0.01):
                connection = asyncio.create_task(
                    PROXY.serve_connection(
                        ActiveReader(), client_writer, "127.0.0.1", 3337, limits
                    )
                )
                await started.wait()
                self.assertEqual(limits.active, 1)
                connection.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(connection, 1)
        self.assertTrue(client_writer.closed)
        self.assertTrue(upstream_writer.closed)
        self.assertTrue(client_writer.aborted)
        self.assertTrue(upstream_writer.aborted)
        self.assertEqual(limits.active, 0)
        self.assertEqual(limits.sources, {})

    async def test_either_peer_closing_releases_limits_and_closes_other_side(self):
        for client_closes in [False, True]:
            with self.subTest(client_closes=client_closes):
                limits = PROXY.ConnectionLimits(1, 1)
                client_reader = asyncio.StreamReader()
                upstream_reader = asyncio.StreamReader()
                client_writer = FakeWriter()
                upstream_writer = FakeWriter()
                started = asyncio.Event()

                async def connected(*_args, **_kwargs):
                    started.set()
                    return upstream_reader, upstream_writer

                with patch.object(PROXY.asyncio, "open_connection", side_effect=connected):
                    connection = asyncio.create_task(
                        PROXY.serve_connection(client_reader, client_writer, "127.0.0.1", 3337, limits)
                    )
                    await started.wait()
                    (client_reader if client_closes else upstream_reader).feed_eof()
                    await connection
                self.assertTrue(client_writer.closed)
                self.assertTrue(upstream_writer.closed)
                self.assertEqual(limits.active, 0)
                self.assertEqual(limits.sources, {})

    async def test_cleanup_error_does_not_leak_admission(self):
        limits = PROXY.ConnectionLimits(1, 1)
        reader = asyncio.StreamReader()
        reader.feed_eof()
        client_writer = FakeWriter(close_error=OSError("closed transport"))
        upstream_writer = FakeWriter(close_error=OSError("closed transport"))
        with patch.object(PROXY.asyncio, "open_connection", new_callable=AsyncMock) as upstream:
            upstream.return_value = asyncio.StreamReader(), upstream_writer
            await PROXY.serve_connection(reader, client_writer, "127.0.0.1", 3337, limits)
        self.assertTrue(client_writer.closed)
        self.assertTrue(upstream_writer.closed)
        self.assertEqual(limits.active, 0)
        self.assertEqual(limits.sources, {})


class ProtocolTests(unittest.TestCase):
    def test_job_alias_translation_preserves_every_proof_field(self):
        aliases = PROXY.JobAliases()
        job_id = "ab" * 32
        notify_params = [job_id, "04000000", "cd" * 32, "ef" * 32, "01" * 32, "00803366", "ffff031d", True]
        notify = {"id": None, "method": "mining.notify", "params": notify_params}
        transformed = json.loads(PROXY.server_message(PROXY.encode_message(notify), aliases))
        self.assertEqual(transformed["params"], ["00000001", *notify_params[1:]])
        submit_params = ["account.worker", "00000001", "00803366", "12" * 28, "fd4005" + "34" * 1344]
        submit = {"id": 4, "method": "mining.submit", "params": submit_params}
        transformed, submitted = PROXY.client_message(PROXY.encode_message(submit), aliases)
        self.assertTrue(submitted)
        self.assertEqual(json.loads(transformed)["params"], [submit_params[0], job_id, *submit_params[2:]])

    def test_other_messages_pass_through_byte_for_byte(self):
        aliases = PROXY.JobAliases()
        for message in [b'{ "id": 1, "method": "mining.authorize", "params": ["alice.z15", "x"] }\n',
                        b'{"id":4,"result":true,"error":null}\n', b"not JSON\n"]:
            self.assertEqual(PROXY.server_message(message, aliases), message)
            self.assertEqual(PROXY.client_message(message, aliases), (message, False))


if __name__ == "__main__":
    unittest.main()

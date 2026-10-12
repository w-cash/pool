#!/usr/bin/env python3
"""Bounded ZIP-301 adapter for GodMiner clients with short job-id storage."""

import argparse
import asyncio
import ipaddress
import json
import logging
import socket
from collections import deque


MAX_LINE_BYTES = 64 * 1024
MAX_CONNECTIONS = 64
MAX_CONNECTIONS_PER_IP = 8
MAX_CONFIGURED_CONNECTIONS = 65_535
MAX_JOB_ALIASES = 32


class ConnectionLimits:
    """Immediate admission limits, owned by the proxy's single event loop."""

    def __init__(self, maximum_connections, maximum_connections_per_ip):
        if not 1 <= maximum_connections <= MAX_CONFIGURED_CONNECTIONS:
            raise ValueError("invalid aggregate connection limit")
        if not 1 <= maximum_connections_per_ip <= maximum_connections:
            raise ValueError("invalid per-IP connection limit")
        self.maximum_connections = maximum_connections
        self.maximum_connections_per_ip = maximum_connections_per_ip
        self.active = 0
        self.sources = {}

    def try_acquire(self, address):
        count = self.sources.get(address, 0)
        if self.active >= self.maximum_connections or count >= self.maximum_connections_per_ip:
            return False
        self.active += 1
        self.sources[address] = count + 1
        return True

    def release(self, address):
        count = self.sources[address]
        self.active -= 1
        if count == 1:
            del self.sources[address]
        else:
            self.sources[address] = count - 1


def peer_address(peer):
    try:
        address = ipaddress.ip_address(peer[0])
    except (ValueError, TypeError, IndexError):
        return None
    # Dual-stack sockets must share the same quota for native and mapped IPv4.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


class JobAliases:
    def __init__(self):
        self._next = 1
        self._full_to_short = {}
        self._short_to_full = {}
        self._order = deque()

    def shorten(self, full):
        alias = self._full_to_short.get(full)
        if alias is not None:
            return alias
        alias = f"{self._next:08x}"
        self._next += 1
        self._full_to_short[full] = alias
        self._short_to_full[alias] = full
        self._order.append((alias, full))
        while len(self._order) > MAX_JOB_ALIASES:
            old_alias, old_full = self._order.popleft()
            self._short_to_full.pop(old_alias, None)
            self._full_to_short.pop(old_full, None)
        return alias

    def expand(self, alias):
        return self._short_to_full.get(alias, alias)


def encode_message(message):
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def server_message(line, aliases):
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return line
    if (
        isinstance(message, dict)
        and message.get("method") == "mining.notify"
        and isinstance(message.get("params"), list)
        and message["params"]
        and isinstance(message["params"][0], str)
    ):
        message["params"][0] = aliases.shorten(message["params"][0])
        return encode_message(message)
    return line


def client_message(line, aliases):
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return line, False
    submitted = False
    if (
        isinstance(message, dict)
        and message.get("method") == "mining.submit"
        and isinstance(message.get("params"), list)
        and len(message["params"]) >= 2
        and isinstance(message["params"][1], str)
    ):
        message["params"][1] = aliases.expand(message["params"][1])
        submitted = True
        return encode_message(message), submitted
    return line, submitted


async def relay_client(reader, writer, aliases, peer):
    submits = 0
    while True:
        line = await reader.readline()
        if not line:
            return
        transformed, submitted = client_message(line, aliases)
        if submitted:
            submits += 1
            if submits == 1 or submits % 100 == 0:
                logging.info("peer=%s forwarded_submits=%d", peer, submits)
        writer.write(transformed)
        await writer.drain()


async def relay_server(reader, writer, aliases):
    while True:
        line = await reader.readline()
        if not line:
            return
        writer.write(server_message(line, aliases))
        await writer.drain()


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, BrokenPipeError):
        pass


async def serve_connection(client_reader, client_writer, upstream_host, upstream_port, permits):
    peer = client_writer.get_extra_info("peername")
    address = peer_address(peer)
    # Only the kernel-provided TCP peer establishes the source quota. Admission
    # happens before upstream setup and has no queue of excess open sockets.
    if address is None or not permits.try_acquire(address):
        logging.warning("peer=%s rejected connection capacity", peer)
        await close_writer(client_writer)
        return
    upstream_writer = None
    tasks = set()
    try:
        client_socket = client_writer.get_extra_info("socket")
        if client_socket is not None:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(upstream_host, upstream_port, limit=MAX_LINE_BYTES),
            timeout=5,
        )
        aliases = JobAliases()
        logging.info("peer=%s connected", peer)
        tasks = {
            asyncio.create_task(relay_client(client_reader, upstream_writer, aliases, peer)),
            asyncio.create_task(relay_server(upstream_reader, client_writer, aliases)),
        }
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (asyncio.TimeoutError, ConnectionError, OSError, ValueError) as error:
        logging.warning("peer=%s closed error=%s", peer, type(error).__name__)
    finally:
        for task in tasks:
            task.cancel()
        writers = [client_writer]
        if upstream_writer is not None:
            writers.append(upstream_writer)
        # Initiate closure before awaiting cleanup, including on cancellation.
        for writer in writers:
            writer.close()
        try:
            await asyncio.gather(
                *tasks, *(close_writer(writer) for writer in writers), return_exceptions=True
            )
        finally:
            permits.release(address)
            logging.info("peer=%s disconnected", peer)


def endpoint(value):
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("endpoint must be HOST:PORT")
    try:
        number = int(port)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if number < 1 or number > 65535:
        raise argparse.ArgumentTypeError("port is out of range")
    return host, number


def connection_limit(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("connection limit must be an integer") from error
    if not 1 <= number <= MAX_CONFIGURED_CONNECTIONS:
        raise argparse.ArgumentTypeError("connection limit must be in 1..65535")
    return number


def self_test():
    aliases = JobAliases()
    full = "ab" * 32
    notify = encode_message(
        {"id": None, "method": "mining.notify", "params": [full, "04000000"]}
    )
    shortened = json.loads(server_message(notify, aliases))
    assert shortened["params"][0] == "00000001"
    submit = encode_message(
        {"id": 4, "method": "mining.submit", "params": ["worker", "00000001"]}
    )
    expanded, submitted = client_message(submit, aliases)
    assert submitted
    assert json.loads(expanded)["params"][1] == full


async def run(listen, upstream, maximum_connections, maximum_connections_per_ip):
    permits = ConnectionLimits(maximum_connections, maximum_connections_per_ip)
    server = await asyncio.start_server(
        lambda reader, writer: serve_connection(
            reader, writer, upstream[0], upstream[1], permits
        ),
        listen[0],
        listen[1],
        limit=MAX_LINE_BYTES,
        backlog=128,
    )
    logging.info("listening=%s:%d upstream=%s:%d", *listen, *upstream)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=endpoint, required=True)
    parser.add_argument("--upstream", type=endpoint, required=True)
    parser.add_argument("--maximum-connections", type=connection_limit, default=MAX_CONNECTIONS)
    parser.add_argument(
        "--maximum-connections-per-ip", type=connection_limit, default=MAX_CONNECTIONS_PER_IP
    )
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.maximum_connections_per_ip > arguments.maximum_connections:
        parser.error("per-IP connection limit must not exceed aggregate connection limit")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if arguments.self_test:
        self_test()
        return
    asyncio.run(
        run(
            arguments.listen, arguments.upstream,
            arguments.maximum_connections, arguments.maximum_connections_per_ip,
        )
    )


if __name__ == "__main__":
    main()

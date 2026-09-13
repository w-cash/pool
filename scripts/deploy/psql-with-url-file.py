#!/usr/bin/env python3

"""Execute psql using a protected, canonical loopback connection URL."""

import os
import pathlib
import re
import stat
import sys
import urllib.parse
from typing import NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(f"psql-with-url-file: {message}")


def parse_url_file(path: pathlib.Path) -> dict[str, str]:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError:
        fail("database credential is unavailable")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("database credential is not a regular file")
        with os.fdopen(descriptor, "rb") as credential:
            descriptor = -1
            raw = credential.read(513)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not 1 <= len(raw) <= 512:
        fail("database credential has an invalid size")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or any(byte < 0x20 or byte == 0x7F for byte in raw):
        fail("database credential contains control data")
    try:
        value = raw.decode("ascii")
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (UnicodeDecodeError, ValueError):
        fail("database credential is malformed")

    user = parsed.username or ""
    password = parsed.password or ""
    database = parsed.path.removeprefix("/")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", user):
        fail("database user is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", password):
        fail("database password representation is invalid")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", database):
        fail("database name is invalid")
    expected = f"postgresql://{user}:{password}@127.0.0.1:5432/{database}?sslmode=disable"
    if value != expected or parsed.hostname != "127.0.0.1" or port != 5432:
        fail("database credential does not match the loopback policy")

    return {
        "PGHOST": "127.0.0.1",
        "PGPORT": "5432",
        "PGUSER": user,
        "PGPASSWORD": password,
        "PGDATABASE": database,
        "PGSSLMODE": "disable",
    }


def main(argv: list[str]) -> None:
    if len(argv) < 3:
        fail("usage: psql-with-url-file.py <url-file> <psql-arguments...>")
    connection = parse_url_file(pathlib.Path(argv[1]))
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("PG")
    }
    environment.update(connection)
    try:
        os.execve("/usr/bin/psql", ["psql", *argv[2:]], environment)
    except OSError:
        fail("psql is unavailable")


if __name__ == "__main__":
    main(sys.argv)

#!/usr/bin/env python3

import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parent / "deploy" / "psql-with-url-file.py"
SPEC = importlib.util.spec_from_file_location("psql_with_url_file", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PsqlUrlFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temporary.name) / "database-url"
        self.user = "zecwec_pool_migrator"
        self.password = "ab" * 32
        self.database = "zecwec_testnet"
        self.url = (
            f"postgresql://{self.user}:{self.password}"
            f"@127.0.0.1:5432/{self.database}?sslmode=disable"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, value: bytes) -> None:
        if self.path.exists() and not self.path.is_symlink():
            self.path.chmod(0o600)
        self.path.write_bytes(value)
        self.path.chmod(0o400)

    def test_parses_canonical_loopback_url(self) -> None:
        self.write((self.url + "\n").encode("ascii"))
        self.assertEqual(
            MODULE.parse_url_file(self.path),
            {
                "PGHOST": "127.0.0.1",
                "PGPORT": "5432",
                "PGUSER": self.user,
                "PGPASSWORD": self.password,
                "PGDATABASE": self.database,
                "PGSSLMODE": "disable",
            },
        )

    def test_exec_uses_environment_without_secret_argv(self) -> None:
        self.write(self.url.encode("ascii"))
        inherited = {"PATH": "/usr/bin", "PGSERVICE": "unsafe"}
        with mock.patch.dict(os.environ, inherited, clear=True), mock.patch.object(
            MODULE.os, "execve", side_effect=RuntimeError("executed")
        ) as execute:
            with self.assertRaisesRegex(RuntimeError, "executed"):
                MODULE.main(["helper", str(self.path), "--no-psqlrc"])
        program, arguments, environment = execute.call_args.args
        self.assertEqual(program, "/usr/bin/psql")
        self.assertEqual(arguments, ["psql", "--no-psqlrc"])
        self.assertNotIn(self.password, "\0".join(arguments))
        self.assertNotIn("PGSERVICE", environment)
        self.assertEqual(environment["PGUSER"], self.user)
        self.assertEqual(environment["PGPASSWORD"], self.password)

    def test_rejects_noncanonical_or_unsafe_urls(self) -> None:
        rejected = (
            b"",
            (self.url + "\nextra").encode("ascii"),
            self.url.replace("127.0.0.1", "localhost").encode("ascii"),
            self.url.replace(":5432", ":5433").encode("ascii"),
            self.url.replace("postgresql://", "postgres://").encode("ascii"),
            self.url.replace("?sslmode=disable", "").encode("ascii"),
            self.url.replace(self.password, "secret").encode("ascii"),
            self.url.replace(self.user, "Bad-Role").encode("ascii"),
            self.url.replace(self.database, "bad/name").encode("ascii"),
            (self.url + "\x00").encode("ascii"),
        )
        for value in rejected:
            with self.subTest(value_length=len(value)):
                self.write(value)
                with self.assertRaises(SystemExit):
                    MODULE.parse_url_file(self.path)

    def test_rejects_symlink(self) -> None:
        target = self.path.with_name("target")
        target.write_text(self.url, encoding="ascii")
        self.path.symlink_to(target)
        with self.assertRaises(SystemExit):
            MODULE.parse_url_file(self.path)


if __name__ == "__main__":
    unittest.main()

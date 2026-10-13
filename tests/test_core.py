from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ida_ai.cli import _query
from ida_ai.db import connect, operation, record_operation, set_metadata
from ida_ai.runner import run_ida
from ida_ai.selection import parse_hex_bytes, parse_pattern, select_function_addresses


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = Path(self.temporary.name) / "analysis.sqlite"
        with closing(connect(self.db_path)) as connection:
            connection.executemany(
                "INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
                [(0x1000, 0x1100, "alpha", 0x100), (0x2000, 0x2100, "beta", 0x100)],
            )
            connection.execute(
                "INSERT INTO basic_blocks(function_ea,block_index,start_ea,end_ea) VALUES(?,?,?,?)",
                (0x1000, 0, 0x3000, 0x3020),
            )
            connection.commit()

    def test_function_selection_including_discontiguous_block(self):
        with closing(connect(self.db_path)) as connection:
            self.assertEqual(select_function_addresses(connection, all_functions=True), [0x1000, 0x2000])
            self.assertEqual(select_function_addresses(connection, address="0x3004"), [0x1000])
            self.assertEqual(select_function_addresses(connection, address_range=["0x1080", "0x2050"]), [0x1000, 0x2000])
            self.assertEqual(select_function_addresses(connection, address_range=["0x3004", "0x3010"]), [0x1000])
            self.assertEqual(select_function_addresses(connection, name="BETA"), [0x2000])
            with self.assertRaises(ValueError):
                select_function_addresses(connection, all_functions=True, name="alpha")

    def test_patterns_and_bytes(self):
        self.assertEqual(parse_hex_bytes("90 0xCC"), b"\x90\xCC")
        wildcard = parse_pattern("48 8B ?? ??")
        self.assertTrue(wildcard.matches(bytes.fromhex("48 8B 12 34")))
        self.assertFalse(wildcard.matches(bytes.fromhex("48 89 12 34")))
        masked = parse_pattern("48 8B 00 00", "FF FF 00 00")
        self.assertTrue(masked.matches(bytes.fromhex("48 8B 12 34")))
        with self.assertRaises(ValueError):
            parse_pattern("48 8B", "FF")

    def test_sql_read_only_and_explicit_write(self):
        result = _query(self.db_path, "SELECT name, start_ea FROM functions ORDER BY start_ea", 1)
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["truncated"])
        with self.assertRaises(sqlite3.OperationalError):
            _query(self.db_path, "DELETE FROM functions", 10)
        _query(self.db_path, "UPDATE functions SET name='renamed' WHERE start_ea=4096", 10, write=True)
        result = _query(self.db_path, "SELECT name FROM functions WHERE start_ea=4096", 10)
        self.assertEqual(result["rows"], [{"name": "renamed"}])

    def test_operation_round_trip(self):
        with closing(connect(self.db_path)) as connection:
            record_operation(connection, "request-1", "search", "ok", {"matches": [{"address": 0x1000}]})
            result = operation(connection, "request-1")
        self.assertEqual(result["result"]["matches"][0]["address"], 0x1000)

    def test_runner_reads_result_from_sqlite(self):
        binary = Path(self.temporary.name) / "sample.bin"
        binary.write_bytes(b"\x90\xC3")
        idb = Path(self.temporary.name) / "analysis.i64"

        def fake_run(command, **kwargs):
            self.assertEqual(command[1], "-A")
            self.assertTrue(command[2].startswith("-S"))
            request = json.loads(Path(kwargs["env"]["IDA_AI_REQUEST"]).read_text(encoding="utf-8"))
            self.assertEqual(request["idb_path"], str(idb))
            with closing(connect(self.db_path)) as connection:
                set_metadata(connection, {"idb_path": str(idb)})
                connection.commit()
                record_operation(connection, request["request_id"], request["action"], "ok", {"functions": 2})
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("ida_ai.runner.find_idat", return_value=binary), patch("ida_ai.runner.subprocess.run", side_effect=fake_run):
            result = run_ida("init", self.db_path, binary=binary, idb_path=str(idb))
        self.assertEqual(result, {"functions": 2})


if __name__ == "__main__":
    unittest.main()

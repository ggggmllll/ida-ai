from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ida_ai.cli import _cache_file, _cached_search, _clear_searches, _query
from ida_ai.db import SCHEMA_VERSION, connect, ida_ea, operation, record_operation, set_metadata, sqlite_ea
from ida_ai.function_classification import is_nullstub_sequence
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

    def test_unsigned_high_addresses_remain_queryable(self):
        high = 0xFF00000000000040
        self.assertEqual(ida_ea(sqlite_ea(high)), high)
        with closing(connect(self.db_path)) as connection:
            connection.execute(
                "INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
                (sqlite_ea(high), sqlite_ea(high + 0x20), "high_func", 0x20),
            )
            connection.commit()
            self.assertEqual(select_function_addresses(connection, address=hex(high + 1)), [high])
            self.assertEqual(select_function_addresses(connection, address_range=[hex(high), hex(high + 0x20)]), [high])

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

    def test_search_cache_restores_records_and_clear_removes_cache(self):
        idb_path = Path(self.temporary.name) / "analysis.i64"
        idb_path.write_bytes(b"idb snapshot")
        with closing(connect(self.db_path)) as connection:
            set_metadata(connection, {"idb_path": str(idb_path)})
            connection.commit()
        result = {"search_id": "ida-request", "count": 1, "truncated": False,
                  "matches": [{"address": 0x1234, "address_hex": "0x1234", "pattern_index": 0}]}
        with patch("ida_ai.cli.run_ida", return_value=result) as run:
            first = _cached_search(self.db_path, "search", {"patterns": [{"pattern": "90", "mask": None}], "start": None, "end": None, "limit": 100}, {})
            second = _cached_search(self.db_path, "search", {"patterns": [{"pattern": "90", "mask": None}], "start": None, "end": None, "limit": 100}, {})
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        run.assert_called_once()
        with closing(connect(self.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM search_matches").fetchone()[0], 1)
        self.assertTrue(_clear_searches(self.db_path)["cache_cleared"])
        with closing(connect(self.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM search_matches").fetchone()[0], 0)
        self.assertFalse(_cache_file(self.db_path).exists())

    def test_legacy_xrefs_table_is_migrated(self):
        old_path = Path(self.temporary.name) / "legacy.sqlite"
        with closing(sqlite3.connect(old_path)) as connection:
            connection.execute(
                "CREATE TABLE xrefs(source_ea INTEGER NOT NULL,target_ea INTEGER NOT NULL,xref_type INTEGER NOT NULL,"
                "is_code INTEGER NOT NULL DEFAULT 0,is_data INTEGER NOT NULL DEFAULT 0,"
                "source_function_ea INTEGER,target_function_ea INTEGER,"
                "PRIMARY KEY(source_ea,target_ea,xref_type))"
            )
            connection.execute(
                "CREATE TABLE functions(start_ea INTEGER PRIMARY KEY,end_ea INTEGER NOT NULL,name TEXT NOT NULL,"
                "demangled_name TEXT,signature TEXT,flags INTEGER,size INTEGER NOT NULL,segment_name TEXT,"
                "is_library INTEGER NOT NULL DEFAULT 0,is_thunk INTEGER NOT NULL DEFAULT 0,comment TEXT,repeatable_comment TEXT)"
            )
            connection.execute(
                "INSERT INTO functions(start_ea,end_ea,name,size,is_thunk) VALUES(4096,4112,'legacy_thunk',16,1)"
            )
            connection.commit()
        with closing(connect(old_path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(xrefs)")}
            self.assertIn("type_name", columns)
            function_columns = {row[1] for row in connection.execute("PRAGMA table_info(functions)")}
            self.assertIn("thunk_target_ea", function_columns)
            self.assertIn("is_nullstub", function_columns)
            function = connection.execute(
                "SELECT is_thunk,thunk_target_ea,is_nullstub FROM functions WHERE start_ea=4096"
            ).fetchone()
            self.assertEqual(tuple(function), (1, None, 0))
            self.assertEqual(connection.execute("SELECT value FROM schema_info WHERE key='version'").fetchone()[0], str(SCHEMA_VERSION))

    def test_nullstub_classification_is_conservative(self):
        self.assertTrue(is_nullstub_sequence([("endbr64", False), ("nop", False), ("ret", True)]))
        self.assertFalse(is_nullstub_sequence([]))
        self.assertFalse(is_nullstub_sequence([("ret", True), ("nop", False)]))
        self.assertFalse(is_nullstub_sequence([("mov", False), ("ret", True)]))
        self.assertFalse(is_nullstub_sequence([("jz", False), ("ret", True)]))

    def test_runner_reads_result_from_sqlite(self):
        binary = Path(self.temporary.name) / "sample.bin"
        binary.write_bytes(b"\x90\xC3")
        idb = Path(self.temporary.name) / "analysis.i64"

        def fake_run(command, **kwargs):
            self.assertEqual(command[1], "-A")
            self.assertEqual(command[2], f"-o{idb}")
            self.assertTrue(command[3].startswith("-S"))
            request = json.loads(Path(kwargs["env"]["IDA_AI_REQUEST"]).read_text(encoding="utf-8"))
            self.assertEqual(request["idb_path"], str(idb))
            with closing(connect(self.db_path)) as connection:
                set_metadata(connection, {"idb_path": str(idb)})
                connection.commit()
                record_operation(connection, request["request_id"], request["action"], "ok", {"functions": 2})
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("ida_ai.runner.find_idat", return_value=binary), patch("ida_ai.runner.subprocess.run", side_effect=fake_run):
            result = run_ida("init", self.db_path, binary=binary, idb_path=str(idb))
        self.assertEqual(result["functions"], 2)
        self.assertTrue(result["job_review"]["applied"])


if __name__ == "__main__":
    unittest.main()

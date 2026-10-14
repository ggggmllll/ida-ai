"""Optional real-IDA smoke test: set IDAT and IDA_AI_TEST_BINARY to enable."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.db import connect, ida_ea
from ida_ai.runner import run_ida
from ida_ai.cli import _cached_search, _clear_searches


@unittest.skipUnless(os.environ.get("IDAT") and os.environ.get("IDA_AI_TEST_BINARY"), "requires IDAT and IDA_AI_TEST_BINARY")
class RealIDATests(unittest.TestCase):
    def test_headless_round_trip(self):
        source = Path(os.environ["IDA_AI_TEST_BINARY"]).resolve()
        idat = os.environ["IDAT"]
        with tempfile.TemporaryDirectory(prefix="ida-ai-real-") as temporary:
            directory = Path(temporary)
            binary = directory / source.name
            shutil.copy2(source, binary)
            db_path = directory / "analysis.sqlite"
            idb_path = directory / "analysis.i64"

            initialized = run_ida("init", db_path, binary=binary, idb_path=str(idb_path), idat=idat, timeout=240)
            self.assertGreater(initialized["functions"], 0)
            self.assertTrue(idb_path.is_file())
            with closing(connect(db_path)) as connection:
                ea = ida_ea(int(connection.execute("SELECT start_ea FROM functions ORDER BY start_ea LIMIT 1").fetchone()[0]))
                self.assertEqual(initialized["basic_blocks"], connection.execute("SELECT count(*) FROM basic_blocks").fetchone()[0])

            disassembly = run_ida("export_view", db_path, addresses=[ea], view="disassembly", idat=idat, timeout=120)
            self.assertEqual(disassembly["functions"], 1)
            pseudocode = run_ida("export_view", db_path, addresses=[ea], view="pseudocode", idat=idat, timeout=120)
            self.assertEqual(pseudocode["functions"], 1)
            # Simulate edits made by another IDA session, outside our exporter.
            with closing(connect(db_path)) as connection:
                dependent = ida_ea(connection.execute("SELECT start_ea FROM functions WHERE name='zError'").fetchone()[0])
            for view in ("disassembly", "pseudocode"):
                run_ida("export_view", db_path, addresses=[dependent], view=view, idat=idat, timeout=120)
            edit = directory / "edit.py"
            edit.write_text(
                "import ida_name, ida_loader, ida_pro, idc\n"
                f"assert ida_name.set_name({ea}, 'sync_test_function')\n"
                "g = ida_name.get_name_ea(0xffffffffffffffff, 'z_errmsg')\n"
                "assert g != 0xffffffffffffffff\n"
                "assert ida_name.set_name(g, 'sync_test_global')\n"
                "assert idc.SetType(g, 'const char *sync_test_global[10];')\n"
                f"assert ida_loader.save_database({str(idb_path)!r}, 0)\n"
                "ida_pro.qexit(0)\n", encoding="utf-8")
            subprocess.run([idat, "-A", f"-S{edit}", str(idb_path)], check=True, timeout=120, capture_output=True)
            synced = run_ida("sync", db_path, idat=idat, timeout=120)
            self.assertEqual(synced["views"]["disassembly"]["functions"], len({ea, dependent}))
            with closing(connect(db_path)) as connection:
                self.assertEqual(connection.execute("SELECT name FROM functions WHERE start_ea=?", (ea,)).fetchone()[0], "sync_test_function")
                symbol = connection.execute("SELECT type FROM symbols WHERE name='sync_test_global'").fetchone()
                self.assertIsNotNone(symbol)
                self.assertIn("char", symbol[0])
                pseudo = connection.execute("SELECT text,status FROM pseudocode WHERE function_ea=?", (ea,)).fetchone()
                self.assertEqual(pseudo[1], "ok")
                self.assertIn("sync_test_function", pseudo[0])
                for view in ("disassembly", "pseudocode"):
                    text = connection.execute(f"SELECT text FROM {view} WHERE function_ea=?", (dependent,)).fetchone()[0]
                    self.assertIn("sync_test_global", text)

            info = run_ida("info", db_path, address=ea, idat=idat, timeout=120)
            # Rename a true local (not a parameter) in another IDA process.
            with closing(connect(db_path)) as connection:
                local_ea = ida_ea(connection.execute("SELECT start_ea FROM functions WHERE name='compress2'").fetchone()[0])
                untouched = tuple(connection.execute("SELECT text,generated_at FROM pseudocode WHERE function_ea=?", (dependent,)).fetchone())
            run_ida("export_view", db_path, addresses=[local_ea], view="pseudocode", idat=idat, timeout=120)
            with closing(connect(db_path)) as connection:
                current_pseudocode = connection.execute("SELECT text FROM pseudocode WHERE function_ea=?", (local_ea,)).fetchone()[0]
                local_name = re.search(r"^\s+[\w\s\*]+\s+(\w+)(?:\[\d+\])?;\s*// \[", current_pseudocode, re.MULTILINE).group(1)
            local = run_ida("mutate", db_path, mutation="rename_local",
                            values={"address": local_ea, "old_name": local_name, "new_name": "local_sync_value"},
                            idat=idat, timeout=120)
            self.assertEqual(local["sync"]["function_ea"], local_ea)
            with closing(connect(db_path)) as connection:
                self.assertIn("local_sync_value", connection.execute("SELECT text FROM pseudocode WHERE function_ea=?", (local_ea,)).fetchone()[0])
                self.assertEqual(untouched, tuple(connection.execute("SELECT text,generated_at FROM pseudocode WHERE function_ea=?", (dependent,)).fetchone()))
            typed_local = run_ida(
                "mutate", db_path, mutation="set_local_type",
                values={"address": local_ea, "name": "local_sync_value", "declaration": "unsigned int"},
                idat=idat, timeout=120,
            )
            self.assertEqual(typed_local["sync"]["function_ea"], local_ea)
            with closing(connect(db_path)) as connection:
                self.assertIn("unsigned int local_sync_value", connection.execute(
                    "SELECT text FROM pseudocode WHERE function_ea=?", (local_ea,)
                ).fetchone()[0])
            self.assertTrue(info["mapped"])
            read = run_ida("read", db_path, address=ea, size=1, idat=idat, timeout=120)
            self.assertEqual(read["size"], 1)
            searched = run_ida(
                "search", db_path, patterns=[{"pattern": read["hex"], "mask": None}],
                start=ea, end=ea + 1, limit=10, idat=idat, timeout=120,
            )
            self.assertEqual(searched["count"], 1)
            self.assertEqual(searched["matches"][0]["address"], ea)
            search_options = dict(patterns=[{"pattern": read["hex"], "mask": None}], start=ea, end=ea+1, limit=10)
            runner_options = dict(idat=idat, timeout=120)
            cold = _cached_search(db_path, "search", search_options, runner_options)
            warm = _cached_search(db_path, "search", search_options, runner_options)
            self.assertFalse(cold["cached"])
            self.assertTrue(warm["cached"])
            self.assertEqual(cold["matches"], warm["matches"])
            pointer_options = dict(target=ea, start=None, end=None, pointer_size=8, limit=10)
            cold_pointer = _cached_search(db_path, "pointer_search", pointer_options, runner_options)
            warm_pointer = _cached_search(db_path, "pointer_search", pointer_options, runner_options)
            self.assertTrue(warm_pointer["cached"])
            self.assertEqual(cold_pointer["matches"], warm_pointer["matches"])

            written = run_ida("write", db_path, address=ea, data_hex=read["hex"].replace(" ", ""), idat=idat, timeout=120)
            self.assertEqual(written["written"]["bytes"], read["bytes"])
            self.assertFalse(_cached_search(db_path, "search", search_options, runner_options)["cached"])
            _clear_searches(db_path)
            with closing(connect(db_path)) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM search_matches").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT count(*) FROM operations WHERE action IN ('search','pointer_search')").fetchone()[0], 0)
            self.assertFalse(_cached_search(db_path, "search", search_options, runner_options)["cached"])
            with closing(connect(db_path)) as connection:
                self.assertGreater(connection.execute("SELECT count(*) FROM functions").fetchone()[0], 0)

            assembly_comment = run_ida(
                "mutate", db_path, mutation="assembly_comment",
                values={"address": ea, "comment": "MCP assembly marker"},
                idat=idat, timeout=120,
            )
            self.assertTrue(assembly_comment["saved"])
            function_comment = run_ida(
                "mutate", db_path, mutation="function_comment",
                values={"address": ea, "comment": "MCP function marker", "repeatable": False},
                idat=idat, timeout=120,
            )
            self.assertTrue(function_comment["saved"])
            pseudo_comment = run_ida(
                "mutate", db_path, mutation="pseudocode_comment",
                values={"address": local_ea, "comment": "MCP pseudocode marker"},
                idat=idat, timeout=120,
            )
            self.assertEqual(pseudo_comment["sync"]["function_ea"], local_ea)
            with closing(connect(db_path)) as connection:
                self.assertIsNotNone(connection.execute(
                    "SELECT 1 FROM comments WHERE address=? AND kind='assembly' AND text='MCP assembly marker'",
                    (ea,),
                ).fetchone())
                self.assertEqual(connection.execute(
                    "SELECT comment FROM functions WHERE start_ea=?", (ea,)
                ).fetchone()[0], "MCP function marker")
                self.assertIsNotNone(connection.execute(
                    "SELECT 1 FROM comments WHERE function_ea=? AND kind='pseudocode' AND text='MCP pseudocode marker'",
                    (local_ea,),
                ).fetchone())

            registered = run_ida(
                "mutate", db_path, mutation="register_type",
                values={"name": "McpTestType", "declaration": "typedef struct McpTestType { int value; } McpTestType;"},
                idat=idat, timeout=120,
            )
            self.assertTrue(registered["saved"])
            with closing(connect(db_path)) as connection:
                self.assertIsNotNone(connection.execute(
                    "SELECT 1 FROM type_definitions WHERE name='McpTestType'"
                ).fetchone())
                global_ea = ida_ea(connection.execute(
                    "SELECT address FROM symbols WHERE name='sync_test_global'"
                ).fetchone()[0])
            applied = run_ida(
                "mutate", db_path, mutation="apply_type",
                values={"address": global_ea, "declaration": "const unsigned char *sync_test_global[10];"},
                idat=idat, timeout=120,
            )
            self.assertIn("views", applied["sync"])
            renamed = run_ida(
                "mutate", db_path, mutation="rename_symbol",
                values={"address": global_ea, "name": "mcp_renamed_global"},
                idat=idat, timeout=120,
            )
            self.assertIn("views", renamed["sync"])
            with closing(connect(db_path)) as connection:
                symbol = connection.execute(
                    "SELECT name,type FROM symbols WHERE address=?", (global_ea,)
                ).fetchone()
                self.assertEqual(symbol["name"], "mcp_renamed_global")
                self.assertIn("unsigned", symbol["type"])
                self.assertIsNotNone(connection.execute(
                    "SELECT 1 FROM type_assignments WHERE address=?", (global_ea,)
                ).fetchone())


if __name__ == "__main__":
    unittest.main()

"""Optional real-IDA smoke test: set IDAT and IDA_AI_TEST_BINARY to enable."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.db import connect, ida_ea
from ida_ai.runner import run_ida


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

            info = run_ida("info", db_path, address=ea, idat=idat, timeout=120)
            self.assertTrue(info["mapped"])
            read = run_ida("read", db_path, address=ea, size=1, idat=idat, timeout=120)
            self.assertEqual(read["size"], 1)
            searched = run_ida(
                "search", db_path, patterns=[{"pattern": read["hex"], "mask": None}],
                start=ea, end=ea + 1, limit=10, idat=idat, timeout=120,
            )
            self.assertEqual(searched["count"], 1)
            self.assertEqual(searched["matches"][0]["address"], ea)

            written = run_ida("write", db_path, address=ea, data_hex=read["hex"].replace(" ", ""), idat=idat, timeout=120)
            self.assertEqual(written["written"]["bytes"], read["bytes"])
            with closing(connect(db_path)) as connection:
                self.assertGreater(connection.execute("SELECT count(*) FROM functions").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ida_ai.db import connect, set_metadata


class McpServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_schema_search_sql_and_unsafe_gate(self):
        with tempfile.TemporaryDirectory(prefix="ida-ai-mcp-test-") as temporary:
            root = Path(temporary)
            database = root / "analysis.sqlite"
            with closing(connect(database)) as connection:
                set_metadata(connection, {"root_filename": "fixture.bin"})
                connection.execute(
                    "INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
                    (0x1000, 0x1010, "fixture", 0x10),
                )
                connection.execute(
                    "INSERT INTO disassembly(function_ea,text,line_count,status,generated_at) VALUES(?,?,?,?,?)",
                    (0x1000, "1000: BL target_func\n1004: CMP X0, #0", 2, "ok", "now"),
                )
                connection.execute(
                    "INSERT INTO pseudocode(function_ea,text,status,generated_at) VALUES(?,?,?,?)",
                    (0x1000, "int fixture() { return target_func(value); }", "ok", "now"),
                )
                connection.execute(
                    "INSERT INTO comments(address,function_ea,kind,repeatable,item_preciser,text,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (0x1004, 0x1000, "assembly", 0, 0, "guard target_func input", "now"),
                )
                connection.execute(
                    "INSERT INTO comments(address,function_ea,kind,repeatable,item_preciser,text,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (0x1008, 0x1000, "pseudocode", 0, 2, "preserve target_func result", "now"),
                )
                connection.commit()

            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "ida_ai.mcp_server", "--db", str(database)],
                cwd=str(Path(__file__).resolve().parents[1]),
            )
            async with stdio_client(parameters) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    self.assertEqual(initialized.serverInfo.name, "ida-ai")
                    tools = await session.list_tools()
                    names = {item.name for item in tools.tools}
                    self.assertTrue({"database_summary", "sql_query", "search_code", "export_functions"} <= names)
                    self.assertNotIn("set_assembly_comment", names)
                    results = await session.call_tool(
                        "search_code",
                        {"terms": ["target_func", "return"], "operator": "any", "view": "both"},
                    )
                    self.assertFalse(results.isError, results.content[0].text if results.content else "no MCP error payload")
                    self.assertIn("target_func", results.content[0].text)
                    self.assertIn("pseudocode_comment", results.content[0].text)
                    regex_results = await session.call_tool(
                        "search_code",
                        {"terms": [r"target_\w+"], "use_regex": True, "view": "disassembly"},
                    )
                    self.assertFalse(regex_results.isError, regex_results.content[0].text if regex_results.content else "")
                    self.assertIn("target_func", regex_results.content[0].text)
                    schema = await session.read_resource("ida://database/schema")
                    self.assertIn("type_definitions", schema.contents[0].text)
                    denied = await session.call_tool(
                        "sql_query", {"query": "DELETE FROM functions", "limit": 10}
                    )
                    self.assertTrue(denied.isError)

    async def test_unsafe_tools_are_registered_only_when_enabled(self):
        with tempfile.TemporaryDirectory(prefix="ida-ai-mcp-gate-") as temporary:
            database = Path(temporary) / "analysis.sqlite"
            with closing(connect(database)):
                pass
            from ida_ai.mcp_server import create_server

            safe = {item.name for item in create_server(database)._tool_manager.list_tools()}
            unsafe = {item.name for item in create_server(database, unsafe=True)._tool_manager.list_tools()}
            self.assertNotIn("rename_symbol", safe)
            self.assertIn("rename_symbol", unsafe)
            self.assertIn("set_pseudocode_comment", unsafe)
            self.assertIn("set_local_variable_type", unsafe)


if __name__ == "__main__":
    unittest.main()

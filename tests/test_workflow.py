import io
import json
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from ida_ai.db import connect, sqlite_ea, reset_analysis
from ida_ai.cli import _parser, _run
from ida_ai.runner import attach_idb, _ProgressMonitor
from ida_ai.selection import selection_preview
from ida_ai.vtable_match import match_vtable_signature, normalize_signature
from ida_ai.discovery import import_callers
from ida_ai.derived_calls import import_derived_calls, mark_derived_calls_stale


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "work.sqlite"
        self.c = connect(self.db)
        self.addCleanup(self.c.close)
        self.c.executemany("INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",[(0x1000,0x1020,"one",32),(0x2000,0x2020,"two",32)])
        self.c.execute("INSERT INTO basic_blocks VALUES(?,?,?,?)",(0x2000,0,0x1000,0x1020))
        self.c.commit()

    def test_preview_explains_shared_cfg_and_batch_unions(self):
        r = selection_preview(self.c,address_range=["0x1000","0x1010"],max_functions=1)
        self.assertTrue(r["budget_exceeded"])
        self.assertEqual(r["functions"][1]["reasons"],["cfg_overlap_outside_entry_range"])
        args = _parser().parse_args(["export","batch","--db",str(self.db),"--addresses","0x1000","0x2000","0x1000","--views","pseudocode","disassembly"])
        with patch("ida_ai.cli.run_ida",return_value={}) as run:
            _run(args)
            self.assertEqual(run.call_count,1)
            self.assertEqual(run.call_args.kwargs["addresses"],[0x1000,0x2000])
            self.assertEqual(run.call_args.args[0],"export_batch")
        args.max_functions=1
        with patch("ida_ai.cli.run_ida") as run:
            with self.assertRaises(ValueError):
                _run(args)
            run.assert_not_called()

    def test_preview_explains_function_chunk_and_multi_address_entry(self):
        self.c.execute(
            "INSERT INTO function_chunks VALUES(?,?,?,?,?,?)",
            (0x2000, 0, 0x2000, 0x2020, None, 0),
        )
        self.c.execute(
            "INSERT INTO function_chunks VALUES(?,?,?,?,?,?)",
            (0x2000, 1, 0x3000, 0x3020, 0x2000, 1),
        )
        self.c.commit()
        r = selection_preview(self.c, addresses=["0x3000"])
        self.assertEqual(r["functions"][0]["reasons"], ["function_chunk_contains_address"])

    def test_derived_call_import_is_separate_and_idempotent(self):
        self.c.execute(
            "INSERT INTO instructions(ea,function_ea,offset,size,text,mnemonic,operands,bytes_hex) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (0x1004, 0x1000, 4, 4, "BL target", "BL", "target", "00000094"),
        )
        self.c.commit()
        source = self.root / "resolved.json"
        source.write_text(json.dumps([
            {"call_ea": "0x1004", "caller": "0x1000", "tail_target": "0x2000"}
        ]), encoding="utf-8")
        first = import_derived_calls(
            self.c, source, resolver="fixture", method="static_replay",
            confidence=0.75, source_ref="file:fixture",
        )
        second = import_derived_calls(
            self.c, source, resolver="fixture", method="static_replay",
            confidence=0.75, source_ref="file:fixture",
        )
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(self.c.execute("SELECT count(*) FROM derived_calls").fetchone()[0], 1)
        self.assertEqual(self.c.execute("SELECT count(*) FROM xrefs").fetchone()[0], 0)
        row = self.c.execute(
            "SELECT target_ea,confidence,method FROM derived_calls"
        ).fetchone()
        self.assertEqual(tuple(row), (0x2000, 0.75, "static_replay"))
        self.assertEqual(mark_derived_calls_stale(
            self.c, [0x1000], reason="disassembly refreshed"
        ), 1)
        self.assertEqual(self.c.execute(
            "SELECT stale,stale_reason FROM derived_calls"
        ).fetchone()[0], 1)
        reset_analysis(self.c)
        self.assertEqual(self.c.execute("SELECT count(*) FROM derived_calls").fetchone()[0], 0)
        self.assertEqual(self.c.execute("SELECT count(*) FROM derived_call_runs").fetchone()[0], 1)

    def test_read_cli_forwards_inline_format_and_output(self):
        output = self.root / "read.bin"
        args = _parser().parse_args([
            "read", "--db", str(self.db), "--address", "0x1000", "--size", "8192",
            "--format", "none", "--max-inline-bytes", "16", "--output", str(output),
        ])
        with patch("ida_ai.cli.run_ida", return_value={}) as run:
            _run(args)
        self.assertEqual(run.call_args.kwargs["output_format"], "none")
        self.assertEqual(run.call_args.kwargs["max_inline_bytes"], 16)
        self.assertEqual(run.call_args.kwargs["output_path"], str(output.resolve()))
        args.output = self.db
        with patch("ida_ai.cli.run_ida") as run:
            with self.assertRaises(ValueError):
                _run(args)
            run.assert_not_called()

    def test_attach_copies_without_binary_and_refuses_overwrite(self):
        source = self.root / "source.i64"
        source.write_bytes(b"IDB fixture")
        db = self.root / "new.sqlite"
        with patch("ida_ai.runner.find_idat",return_value=source), patch("ida_ai.runner.run_ida",return_value={}) as run:
            r=attach_idb(db,source)
            self.assertTrue(r["copied"])
            self.assertEqual(Path(r["idb_path"]).read_bytes(),source.read_bytes())
            self.assertEqual(run.call_args.args[0],"sync")
            with self.assertRaises(FileExistsError):
                attach_idb(db,source)
            with self.assertRaises(ValueError):
                attach_idb(self.root/"other.sqlite",source,destination=source)

    def test_progress_keeps_partial_line_until_completed(self):
        path=self.root/"progress"
        path.write_text('{"stage":"x"}\n{"stage":')
        monitor=_ProgressMonitor(path,"sync")
        output=io.StringIO()
        with redirect_stderr(output):
            monitor.drain()
            with path.open("a") as stream:
                stream.write('"y"}\n')
            monitor.drain()
            monitor.drain()
        self.assertEqual([json.loads(s)["stage"] for s in output.getvalue().splitlines()],["x","y"])

    def pointers(self, base, values):
        for i,value in enumerate(values):
            kind="null" if value==0 else "function"
            self.c.execute("INSERT INTO data_pointer_slots VALUES(?,?,?,?,?,?,?,?,?,?)",(sqlite_ea(base+i*8),sqlite_ea(value),sqlite_ea(value) if value else None,8,"data","code",sqlite_ea(value) if value else None,"f",kind,"now"))

    def test_signature_positions_wildcards_null_and_high_addresses(self):
        high=0xFF00000000001000
        for base,values in [(0x4000,[1,2,3,0]),(0x5000,[3,2,1,0]),(high,[1,7,3,0])]:
            self.pointers(base,values)
        spec={"slots":[{"offset":0,"target":1},{"offset":16,"target":3},{"offset":24,"kind":"null"},{"offset":8,"kind":"function"}]}
        r=match_vtable_signature(self.c,spec)
        self.assertEqual({x["address"] for x in r["matches"]},{"0x4000",f"0x{high:X}"})
        self.assertFalse(r["truncated"])
        self.assertTrue(match_vtable_signature(self.c,spec,limit=1)["truncated"])
        self.assertTrue(match_vtable_signature(self.c,spec,max_anchors=1)["truncated"])
        self.assertEqual(match_vtable_signature(self.c,spec,start=0x4000,end=0x4018)["count"],0)
        with self.assertRaises(ValueError):
            normalize_signature({"slots":[{"offset":0,"kind":"function"}]})

    def test_import_frontier_and_got_stub_navigation(self):
        # Import -> GOT data -> PLT stub -> calling function.
        for source,target,function,code in [(0x4000,0x8000,None,0),(0x5000,0x4000,0x5000,1),(0x1004,0x5000,0x1000,1)]:
            self.c.execute("INSERT INTO xrefs(source_ea,target_ea,xref_type,is_code,is_data,source_function_ea,type_name) VALUES(?,?,?,?,?,?,?)",(source,target,1,code,1-code,function,"test"))
        r=import_callers(self.c,0x8000)
        self.assertIn("0x1000",[x["function"] for x in r["callers"]])
        self.assertEqual(import_callers(self.c,0x9999)["frontier"][0]["reason"],"no_exported_incoming_xrefs_not_proof_unused")
        self.assertTrue(import_callers(self.c,0x8000,max_edges=1)["truncated"])
        self.c.execute("INSERT INTO discovered_strings VALUES(1,0,'text','aa','now')")
        reset_analysis(self.c)
        self.assertEqual(self.c.execute("SELECT count(*) FROM discovered_strings").fetchone()[0],0)

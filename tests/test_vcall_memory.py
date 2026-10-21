from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, reset_analysis, set_metadata
from ida_ai.jobs import _artifact_fingerprint
from ida_ai.vcall_memory import MemoryQuery
from ida_ai.vcall_trace import trace_virtual_call, show_trace
from ida_ai.virtual_tables import build_vcall_index, build_vtable_index, invalidate_function_virtual_artifacts


def local(index, size=8):
    return {"kind": "local", "local_index": index, "local_offset": 0, "size": size}


def num(value, size=8):
    return {"kind": "number", "value": value, "size": size}


def nested(opcode, left, right=None):
    return {"kind": "nested", "size": 8, "instruction": {"opcode": opcode, "l": left, "r": right or {}, "d": {}}}


def ins(opcode, left=None, right=None, dest=None, block=0):
    return {"opcode": opcode, "l": left or {}, "r": right or {}, "d": dest or {}, "block_serial": block}


def store(value, address=None, block=0, size=8):
    return ins("stx", num(value, size), dest=address or local(0), block=block)


def call(callee, actual=None):
    return ins("call", {"kind": "global", "address": callee}, dest={"kind": "arglist", "callee": callee, "arguments": [actual or local(0)]})


class MemoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "analysis.sqlite"
        self.c = connect(self.path)
        self.addCleanup(self.c.close)
        set_metadata(self.c, {"bitness": 64, "big_endian": False, "architecture": "metapc"})

    def put(self, ea, instructions, *, view="microcode", cfg=None, args=None, returned=None):
        cfg = cfg or [(0, [], [])]
        self.c.execute("INSERT OR IGNORE INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)", (ea, ea+0x100, f"sub_{ea:x}", 0x100))
        self.c.execute(f"DELETE FROM {view} WHERE function_ea=?", (ea,))
        self.c.execute(f"INSERT INTO {view}(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at,relations_json) VALUES(?,?,?,?,?,?,?,?)",
                       (ea, "MMAT_LVARS" if view == "micro_flow" else "MMAT_GLBOPT3", "fixture", "ok", len(instructions), "fixture", "now", json.dumps({"cfg": {"complete": True, "block_count": len(cfg)}})))
        if view == "micro_flow":
            self.c.execute("UPDATE micro_flow SET arguments_json=?,return_json=? WHERE function_ea=?", (json.dumps(args or []), json.dumps(returned or {}), ea))
        table = "micro_instructions" if view == "microcode" else "micro_flow_instructions"
        self.c.execute(f"DELETE FROM {table} WHERE function_ea=?", (ea,))
        self.c.execute("DELETE FROM micro_blocks WHERE function_ea=? AND view_name=?", (ea, view))
        counts = {}
        for ordinal, item in enumerate(instructions):
            block = item["block_serial"]
            counts[block] = counts.get(block, 0) + 1
            self.c.execute(f"INSERT INTO {table} VALUES(?,?,?,?,?,?,?,?,?)", (ea, block, ordinal, ea+ordinal*4, item["opcode"], item["opcode"], json.dumps(item["l"]), json.dumps(item["r"]), json.dumps(item["d"])))
        for block, preds, succs in cfg:
            self.c.execute("INSERT INTO micro_blocks VALUES(?,?,?,?,?,?)", (view, ea, block, json.dumps(preds), json.dumps(succs), counts.get(block, 0)))
        self.c.commit()

    def query(self, ea=0x1000, *, view="microcode", before=100, operand=None, **budgets):
        q = MemoryQuery(self.c, view=view, **budgets)
        leaves = q.scan(ea, operand or local(0), 0, (0, before))
        return q, leaves

    def test_nested_memory_destination_is_not_readonly(self):
        expr = nested("mov", num(1))
        expr["instruction"]["d"] = {"kind": "global", "address": 0x8000, "size": 8}
        self.put(0x2000, [ins("mov", expr, dest=local(1))])
        self.put(0x1000, [store(0x5000), call(0x2000)])
        query, leaves = self.query()
        self.assertFalse(query._readonly(0x2000))
        self.assertTrue(any(x["status"] == "unknown" for x in leaves))
        self.put(0x1000, [store(0x5000), ins("mov", expr, dest=local(1))])
        query, leaves = self.query()
        self.assertIn("nested_memory_destination_unresolved", [x["code"] for x in query.frontier])

    def test_nearest_overwrite_wins(self):
        self.put(0x1000, [store(0x5000), store(0x5100)])
        _, leaves = self.query()
        self.assertEqual([x["address_point"] for x in leaves], [0x5100])

    def test_query_is_at_load_not_call_time(self):
        self.put(0x1000, [store(0x5000), ins("ldx", right=local(0), dest=local(1)), store(0x5100), call(0x9000)])
        _, leaves = self.query(before=1)
        self.assertEqual(leaves[0]["address_point"], 0x5000)

    def test_partial_store_blocks_old_value(self):
        self.put(0x1000, [store(0x5000), store(0, size=4)])
        _, leaves = self.query()
        self.assertEqual(leaves[0]["reason"], "partial_overlapping_store")

    def test_same_root_disjoint_field_is_safe(self):
        self.put(0x1000, [store(0x5000), store(0, nested("add", local(0), num(16)))])
        _, leaves = self.query()
        self.assertEqual(leaves[0]["address_point"], 0x5000)

    def test_different_pointers_may_alias(self):
        self.put(0x1000, [store(0x5000), store(0, local(9))])
        _, leaves = self.query()
        self.assertEqual(leaves[0]["reason"], "may_alias_store")

    def test_global_address_and_absolute_overlap(self):
        global_address = {"kind": "address", "size": 8, "operand": {"kind": "global", "address": 0x8000}}
        self.put(0x1000, [store(0x5000, global_address), store(0, num(0x8004), size=4)])
        _, leaves = self.query(operand=global_address)
        self.assertEqual(leaves[0]["reason"], "partial_overlapping_store")

    def test_copy_alias_and_width_loss(self):
        for width, expected in ((8, "observed_reaching_store_under_model"), (4, "object_identity_unresolved")):
            self.put(0x1000, [store(0x5000), ins("mov", local(0, width), dest=local(2))])
            _, leaves = self.query(operand=local(2))
            self.assertEqual(leaves[0]["status"] if width == 8 else leaves[0]["reason"], expected)

    def test_unknown_call_is_a_barrier(self):
        self.put(0x1000, [store(0x5000), call(0x9000)])
        _, leaves = self.query()
        self.assertEqual(leaves[0]["reason"], "call_side_effect_unknown")

    def test_loaded_global_snapshot_is_not_a_constant(self):
        self.put(0x1000, [ins("ldx", right={"kind": "global", "address": 0x8000}, dest=local(2)),
                          ins("stx", local(2), dest=local(0))])
        self.c.execute("INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_kind,generated_at) VALUES(?,?,?,?,?,?,?)", (0x8000, 0x5000, 0x5000, 8, ".data", "data", "now"))
        _, leaves = self.query()
        self.assertIsNone(leaves[0]["address_point"])

    def test_verified_readonly_call_preserves_store(self):
        self.put(0x9000, [ins("ret")])
        self.put(0x1000, [store(0x5000), call(0x9000)])
        _, leaves = self.query()
        self.assertEqual(leaves[0]["address_point"], 0x5000)

    def test_lvars_callee_overwrite(self):
        self.put(0x9000, [store(0x5100)], view="micro_flow", args=[{"local_index": 0, "size": 8}])
        self.put(0x1000, [store(0x5000), call(0x9000)], view="micro_flow")
        _, leaves = self.query(view="micro_flow")
        self.assertEqual(leaves[0]["address_point"], 0x5100)
        self.assertEqual(leaves[0]["path"][0]["kind"], "direct_call_effect")

    def test_lvars_callee_may_alias_does_not_preserve_store(self):
        self.put(0x9000, [store(0x5100, local(1))], view="micro_flow", args=[{"local_index": 0, "size": 8}])
        self.put(0x1000, [store(0x5000), call(0x9000)], view="micro_flow")
        _, leaves = self.query(view="micro_flow")
        self.assertEqual(leaves[0]["reason"], "may_alias_store")

    def test_exported_caller_keeps_external_frontier(self):
        self.put(0x9000, [ins("nop")], view="micro_flow", args=[{"local_index": 0, "size": 8}])
        self.put(0x1000, [store(0x5000), call(0x9000)], view="micro_flow")
        _, leaves = self.query(ea=0x9000, view="micro_flow")
        self.assertIn(0x5000, [x.get("address_point") for x in leaves])
        self.assertIn("external_or_unexported_callers", [x.get("reason") for x in leaves])

    def test_return_alias_is_bound_to_exact_caller(self):
        self.put(0x9000, [ins("mov", local(0), dest=local(2))], view="micro_flow",
                 args=[{"local_index": 0, "size": 8}], returned={"local_index": 2, "size": 8})
        returned_call = nested("call", {"kind": "global", "address": 0x9000})
        returned_call["instruction"]["d"] = {"kind": "arglist", "callee": 0x9000, "arguments": [local(0)]}
        self.put(0x1000, [store(0x5000), ins("mov", returned_call, dest=local(3))], view="micro_flow")
        _, leaves = self.query(view="micro_flow", operand=local(3))
        self.assertEqual([x.get("address_point") for x in leaves], [0x5000])

    def test_unknown_allocator_return_remains_unknown(self):
        allocation = nested("call", {"kind": "global", "address": 0x9000})
        self.put(0x1000, [ins("mov", allocation, dest=local(3))], view="micro_flow")
        _, leaves = self.query(view="micro_flow", operand=local(3))
        self.assertEqual(leaves[0]["reason"], "external_or_missing_return_source")

    def test_cfg_branches_remain_separate(self):
        self.put(0x1000, [ins("nop"), store(0x5000, block=1), store(0x5100, block=2), ins("nop", block=3)],
                 cfg=[(0, [], [1, 2]), (1, [0], [3]), (2, [0], [3]), (3, [1, 2], [])])
        q = MemoryQuery(self.c)
        leaves = q.scan(0x1000, local(0), 0, (3, 100))
        self.assertEqual({x.get("address_point") for x in leaves}, {0x5000, 0x5100})

    def test_loop_and_budget_terminate(self):
        self.put(0x1000, [ins("nop"), ins("nop", block=1)], cfg=[(0, [], [1]), (1, [0, 1], [1])])
        q = MemoryQuery(self.c, max_edges=15, max_hops=2)
        leaves = q.scan(0x1000, local(0), 0, (1, 100))
        self.assertTrue(any(x["status"] == "unknown" for x in leaves))
        self.assertLess(q.edges, 30)

    def test_missing_instruction_invalidates_view(self):
        self.put(0x1000, [store(0x5000), ins("nop")])
        self.c.execute("DELETE FROM micro_instructions WHERE ordinal=1")
        _, leaves = self.query()
        self.assertEqual(leaves[0]["reason"], "view_missing_or_error")

    def dispatch(self, *, flow=False, mismatch=False):
        code = [store(0x5000), ins("ldx", right=local(0), dest=local(1)),
                ins("ldx", right=nested("add", local(1), num(8)), dest=local(2)),
                ins("icall", right=local(2), dest={"kind": "arglist", "arguments": [local(0)]})]
        self.put(0x2000, code)
        if flow:
            if mismatch:
                code[2]["r"] = nested("add", local(1), num(16))
            self.put(0x2000, code, view="micro_flow")
        self.c.executemany("INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_kind,target_function_ea,generated_at) VALUES(?,?,?,?,?,?,?,?)",
                           [(0x5000, 0x1000, 0x1000, 8, ".rdata", "function", 0x1000, "now"), (0x5008, 0x1100, 0x1100, 8, ".rdata", "function", 0x1100, "now")])
        self.c.executemany("INSERT OR IGNORE INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)", [(0x1000, 0x1010, "a", 16), (0x1100, 0x1110, "b", 16)])
        self.c.commit()
        build_vtable_index(self.c, abi="itanium")
        build_vcall_index(self.c, function_eas=[0x2000])
        return self.c.execute("SELECT call_id FROM vcall_sites WHERE stale=0").fetchone()[0]

    def test_trace_targets_cache_and_cli(self):
        call_id = self.dispatch()
        result = trace_virtual_call(self.c, call_id=call_id)
        self.assertEqual(result["targets"][0]["target_ea"], 0x1100)
        self.assertEqual(result["resolution_status"], "unique_under_assumptions")
        self.assertFalse(result["runtime_reachability_proven"])
        self.assertEqual(result["completeness"], "partial")
        self.assertEqual(result["local_memory"]["local_store_history"]["events"][0]["address_point"], 0x5000)
        self.assertTrue(trace_virtual_call(self.c, call_id=call_id)["cached"])
        with patch("ida_ai.cli.run_ida", side_effect=AssertionError("offline command launched IDA")):
            output = _run(_parser().parse_args(["vcall-trace", "--db", str(self.path), "--call-id", call_id]))
            shown = _run(_parser().parse_args(["vcall-trace-show", "--db", str(self.path), "--run-id", result["run_id"]]))
        self.assertEqual(output["run_id"], shown["run_id"])

    def test_structural_bridge_and_mismatch(self):
        call_id = self.dispatch(flow=True)
        result = trace_virtual_call(self.c, call_id=call_id)
        self.assertEqual(result["bridge"]["status"], "unique_structural_bridge")
        self.assertEqual(result["object_memory"]["address_points"], [0x5000])
        self.c.execute("UPDATE micro_flow_instructions SET r_json=? WHERE function_ea=? AND ordinal=2", (json.dumps(nested("add", local(1), num(16))), 0x2000))
        result = trace_virtual_call(self.c, call_id=call_id)
        self.assertEqual(result["bridge"]["reason"], "maturity_shape_or_argument_mismatch")
        self.assertIsNone(result["object_memory"])

    def test_trace_stale_job_and_history_preserved(self):
        call_id = self.dispatch()
        result = trace_virtual_call(self.c, call_id=call_id)
        evidence = f"vtrace:{result['run_id']}"
        before = _artifact_fingerprint(self.c, evidence)
        invalidate_function_virtual_artifacts(self.c, [0x9999], view_name="micro_flow")
        with self.assertRaisesRegex(ValueError, "stale"):
            show_trace(self.c, result["run_id"])
        self.assertNotEqual(before, _artifact_fingerprint(self.c, evidence))
        self.assertTrue(show_trace(self.c, result["run_id"], include_stale=True)["stale"])
        new = trace_virtual_call(self.c, call_id=call_id)
        self.assertNotEqual(new["run_id"], result["run_id"])
        self.assertEqual(self.c.execute("SELECT count(*) FROM vcall_trace_runs").fetchone()[0], 2)
        reset_analysis(self.c)
        self.assertTrue(show_trace(self.c, new["run_id"], include_stale=True)["stale"])

    def test_trace_budget_validation(self):
        for options in ({"max_hops": 0}, {"max_hops": 65}, {"max_context": 17}, {"max_edges": -1}):
            with self.assertRaises(ValueError):
                trace_virtual_call(self.c, call_id="absent", **options)

    def test_raw_row_changes_stale_trace_and_call_source(self):
        call_id = self.dispatch()
        result = trace_virtual_call(self.c, call_id=call_id)
        self.c.execute("UPDATE micro_instructions SET l_json=? WHERE function_ea=8192 AND ordinal=0", (json.dumps(num(0x5100)),))
        with self.assertRaisesRegex(ValueError, "stale"):
            show_trace(self.c, result["run_id"])
        with self.assertRaisesRegex(ValueError, "source changed"):
            trace_virtual_call(self.c, call_id=call_id)

    def test_slot_row_changes_invalidate_trace_even_without_status_change(self):
        call_id = self.dispatch()
        result = trace_virtual_call(self.c, call_id=call_id)
        self.c.execute("UPDATE vtable_slots SET target_ea=4096 WHERE slot_index=1")
        with self.assertRaisesRegex(ValueError, "stale"):
            show_trace(self.c, result["run_id"])


if __name__ == "__main__":
    unittest.main()

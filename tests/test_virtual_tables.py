from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, reset_analysis, set_metadata, sqlite_ea
from ida_ai.virtual_tables import (
    analyze_vcall,
    build_vcall_index,
    build_vtable_index,
    list_vcalls,
    list_vtables,
    search_vtables,
    show_vcall,
    show_vtable,
)


def _operand(kind: str, **values) -> dict:
    return {"kind": kind, **values}


def _reg(value_number: int, *, register: int = 0, size: int = 8) -> dict:
    return _operand("register", register=register, value_number=value_number, size=size)


def _number(value: int) -> dict:
    return _operand("number", value=value, size=8)


def _nested(opcode: str, left: dict, right: dict, ea: int) -> dict:
    return _operand("nested", instruction={"opcode": opcode, "l": left, "r": right,
        "d": _operand("empty"), "ea": ea})


def _insn(function: int, block: int, ordinal: int, ea: int, opcode: str,
          left: dict | None = None, right: dict | None = None, dest: dict | None = None) -> tuple:
    return (sqlite_ea(function), block, ordinal, sqlite_ea(ea), opcode, opcode,
        json.dumps(left or _operand("empty")), json.dumps(right or _operand("empty")),
        json.dumps(dest or _operand("empty")))


class VirtualTableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ida-ai-vtable-")
        self.addCleanup(self.temporary.cleanup)
        self.db_path = Path(self.temporary.name) / "analysis.sqlite"
        self.connection = connect(self.db_path)
        self.addCleanup(self.connection.close)
        set_metadata(self.connection, {"root_filename": "fixture", "input_path": "fixture",
            "imagebase": 0, "bitness": 64, "big_endian": False, "architecture": "metapc"})
        self.connection.executemany(
            "INSERT INTO functions(start_ea,end_ea,name,demangled_name,signature,size,is_thunk,thunk_target_ea,is_nullstub) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            [(0x1000, 0x1010, "f_a", "A::f", "void f()", 0x10, 0, None, 0),
             (0x1100, 0x1110, "f_b", "B::f", "void f()", 0x10, 0, None, 0),
             (0x1200, 0x1210, "thunk_c", "C::f [thunk]", "void f()", 0x10, 1, 0x1300, 0),
             (0x1300, 0x1310, "f_c", "C::f", "void f()", 0x10, 0, None, 0)],
        )
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(0x5000, 0x1000, 0x1000, 8, ".data.rel.ro", ".text", 0x1000, "A::f", "function", "now"),
             (0x5008, 0x1200, 0x1200, 8, ".data.rel.ro", ".text", 0x1200, "C::f [thunk]", "function", "now"),
             (0x5100, 0x1100, 0x1100, 8, ".data.rel.ro", ".text", 0x1100, "B::f", "function", "now"),
             (0x5108, 0, None, 8, ".data.rel.ro", None, None, None, "null", "now"),
             (0x5110, 0x1300, 0x1300, 8, ".data.rel.ro", ".text", 0x1300, "C::f", "function", "now")],
        )
        self.connection.commit()

    def _add_vcall_fixture(self):
        function = 0x2000
        self.connection.execute("INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
            (sqlite_ea(function), sqlite_ea(function + 0x100), "call_virtual", 0x100))
        receiver = _reg(99, register=0)
        object_plus = _nested("add", receiver, _number(0x10), 0x2000)
        vptr = _reg(1, register=9)
        vptr_plus = _nested("add", vptr, _number(8), 0x2008)
        callee = _reg(2, register=10)
        rows = [
            _insn(function, 0, 0, 0x2000, "ldx", _reg(50), object_plus, vptr),
            _insn(function, 0, 1, 0x2008, "ldx", _reg(51), vptr_plus, callee),
            _insn(function, 0, 2, 0x200C, "icall", _reg(3), callee,
                _operand("arglist", callee=0xFFFFFFFFFFFFFFFF, arguments=[])),
        ]
        self.connection.execute("INSERT INTO microcode(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at) VALUES(?,?,?,?,?,?,?)",
            (sqlite_ea(function), "MMAT_GLBOPT3", "test", "ok", len(rows), "virtual-call-fixture", "now"))
        self.connection.executemany("INSERT INTO micro_instructions VALUES(?,?,?,?,?,?,?,?,?)", rows)
        self.connection.commit()
        return function

    def test_vtable_candidate_slots_and_thunk_chain(self):
        result = build_vtable_index(self.connection, abi="itanium")
        self.assertEqual(result["candidate_count"], 2)
        listing = list_vtables(self.connection, limit=10)
        self.assertEqual(listing["total"], 2)
        first = show_vtable(self.connection, address=0x5000)["items"][0]
        self.assertEqual([slot["target_ea"] for slot in first["slots"]], [0x1000, 0x1200])
        self.assertTrue(first["slots"][1]["is_thunk"])
        self.assertEqual(first["slots"][1]["thunk_chain"], [0x1200, 0x1300])
        matches = search_vtables(self.connection, target_eas=[0x1000, 0x1200])
        self.assertEqual(matches["count"], 1)
        self.assertEqual(matches["items"][0]["address_point"], 0x5000)
        rerun = build_vtable_index(self.connection, abi="itanium")
        self.assertTrue(rerun["cached"])

    def test_vcall_candidate_keeps_receiver_and_partial_resolution(self):
        self._add_vcall_fixture()
        build_vtable_index(self.connection, abi="itanium")
        result = build_vcall_index(self.connection, function_eas=[0x2000])
        self.assertEqual(result["pattern_candidate_count"], 1)
        listed = list_vcalls(self.connection)
        self.assertEqual(listed["count"], 1)
        site = listed["items"][0]
        self.assertEqual(site["slot_offset"], 8)
        self.assertEqual(site["callee"]["vptr_offset"], 0x10)
        self.assertFalse(site["callee"]["control_flow_dominance_verified"])
        analyzed = analyze_vcall(self.connection, call_id=site["call_id"])
        self.assertEqual(analyzed["resolution"]["resolution_status"], "candidate_set")
        self.assertEqual(len(analyzed["resolution"]["targets"]), 1)
        self.assertEqual(analyzed["resolution"]["targets"][0]["target_ea"], 0x1200)
        shown = show_vcall(self.connection, call_id=site["call_id"])
        self.assertEqual(len(shown["targets"]), 1)

    def test_direct_callback_is_not_promoted_to_two_load_pattern(self):
        function = 0x2100
        self.connection.execute("INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
            (sqlite_ea(function), sqlite_ea(function + 0x100), "call_callback", 0x100))
        callback = _reg(2, register=10)
        rows = [
            _insn(function, 0, 0, function, "ldx", _reg(50), _nested("add", _reg(99), _number(0x18), function), callback),
            _insn(function, 0, 1, function + 4, "icall", _reg(3), callback,
                _operand("arglist", callee=0xFFFFFFFFFFFFFFFF, arguments=[])),
        ]
        self.connection.execute("INSERT INTO microcode(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at) VALUES(?,?,?,?,?,?,?)",
            (sqlite_ea(function), "MMAT_GLBOPT3", "test", "ok", len(rows), "callback-only", "now"))
        self.connection.executemany("INSERT INTO micro_instructions VALUES(?,?,?,?,?,?,?,?,?)", rows)
        self.connection.commit()
        result = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(result["unknown_indirect_count"], 1)
        self.assertEqual(list_vcalls(self.connection)["items"][0]["status"], "indirect_unknown")

    def test_stale_rows_survive_full_analysis_reset_and_job_fingerprint_changes(self):
        result = build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5000)["items"][0]["candidate_id"]
        from ida_ai.jobs import _artifact_fingerprint
        before = _artifact_fingerprint(self.connection, f"vtable:{candidate}")
        reset_analysis(self.connection)
        self.connection.commit()
        after = _artifact_fingerprint(self.connection, f"vtable:{candidate}")
        self.assertNotEqual(before, after)
        self.assertEqual(list_vtables(self.connection)["total"], 0)
        self.assertEqual(list_vtables(self.connection, include_stale=True)["total"], 2)

    def test_cli_offline_commands_and_validations(self):
        parser = _parser()
        args = parser.parse_args(["vtable-build", "--db", str(self.db_path), "--no-refresh"])
        self.assertEqual(_run(args)["candidate_count"], 2)
        args = parser.parse_args(["vtable-search", "--db", str(self.db_path), "--target", "0x1000"])
        self.assertEqual(_run(args)["count"], 1)
        with self.assertRaisesRegex(ValueError, "target_eas or slot_index"):
            search_vtables(self.connection)
        with self.assertRaisesRegex(ValueError, "unsupported ABI"):
            build_vtable_index(self.connection, abi="msvc")


if __name__ == "__main__":
    unittest.main()

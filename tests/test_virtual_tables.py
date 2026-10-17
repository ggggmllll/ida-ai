from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, reset_analysis, set_metadata, sqlite_ea
from ida_ai.virtual_tables import (
    _trace_vcall_pattern,
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
                _operand("arglist", callee=0xFFFFFFFFFFFFFFFF, arguments=[object_plus])),
        ]
        self.connection.execute("INSERT INTO microcode(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at) VALUES(?,?,?,?,?,?,?)",
            (sqlite_ea(function), "MMAT_GLBOPT3", "test", "ok", len(rows), "virtual-call-fixture", "now"))
        self.connection.executemany("INSERT INTO micro_instructions VALUES(?,?,?,?,?,?,?,?,?)", rows)
        self.connection.commit()
        return function

    def _vcall_instructions(self, *, vptr_block: int, use_block: int) -> list[dict]:
        receiver = _reg(99, register=0)
        object_plus = _nested("add", receiver, _number(0x10), 0x2000)
        vptr_plus = _nested("add", _reg(1, register=9), _number(8), 0x2008)
        slot_ordinal = 1 if vptr_block == use_block else 0
        call_ordinal = slot_ordinal + 1
        return [
            {"block_serial": vptr_block, "ordinal": 0, "ea": 0x1000, "opcode": "ldx",
             "text": "load vptr", "l": _reg(50), "r": object_plus, "d": _reg(1, register=9)},
            {"block_serial": use_block, "ordinal": slot_ordinal, "ea": 0x2008, "opcode": "ldx",
             "text": "load slot", "l": _reg(51), "r": vptr_plus, "d": _reg(2, register=10)},
            {"block_serial": use_block, "ordinal": call_ordinal, "ea": 0x2010, "opcode": "icall",
             "text": "indirect call", "l": _reg(3), "r": _reg(2, register=10),
             "d": _operand("arglist", callee=0xFFFFFFFFFFFFFFFF,
                           arguments=[_nested("add", receiver, _number(0x10), 0x2010)])},
        ]

    def test_vcall_does_not_use_ea_order_across_unrelated_blocks(self):
        instructions = self._vcall_instructions(vptr_block=1, use_block=0)
        self.assertIsNone(_trace_vcall_pattern(instructions, instructions[-1], {}))

    def test_vcall_accepts_unique_definition_in_dominating_microcode_block(self):
        instructions = self._vcall_instructions(vptr_block=0, use_block=1)
        relations = {"cfg": {"complete": True, "blocks": [
            {"serial": 0, "predecessors": [], "successors": [1]},
            {"serial": 1, "predecessors": [0], "successors": []},
        ]}}
        pattern = _trace_vcall_pattern(instructions, instructions[-1], relations)
        self.assertIsNotNone(pattern)
        self.assertEqual(pattern["vptr_offset"], 0x10)
        self.assertEqual(pattern["slot_offset"], 8)
        self.assertTrue(pattern["control_flow_dominance_verified"])

    def test_vcall_records_receiver_argument_identity(self):
        instructions = self._vcall_instructions(vptr_block=0, use_block=0)
        instructions[-1]["d"]["arguments"] = [
            _nested("add", _reg(99, register=0), _number(0x10), 0x2010)]
        pattern = _trace_vcall_pattern(instructions, instructions[-1], {})
        self.assertEqual(pattern["pattern_status"], "candidate")
        self.assertEqual(pattern["receiver_binding"]["status"], "subobject_offset_match")

    def test_vcall_rejects_receiver_argument_with_different_subobject_offset(self):
        instructions = self._vcall_instructions(vptr_block=0, use_block=0)
        adjusted = _nested("add", _reg(99, register=0), _number(8), 0x2010)
        instructions[-1]["d"]["arguments"] = [adjusted]
        pattern = _trace_vcall_pattern(instructions, instructions[-1], {})
        self.assertEqual(pattern["pattern_status"], "receiver_unbound")
        self.assertEqual(pattern["receiver_binding"]["status"], "offset_mismatch")

    def test_vcall_keeps_unbound_receiver_as_unknown(self):
        instructions = self._vcall_instructions(vptr_block=0, use_block=0)
        instructions[-1]["d"]["arguments"] = [_reg(77, register=3)]
        pattern = _trace_vcall_pattern(instructions, instructions[-1], {})
        self.assertIsNotNone(pattern)
        self.assertEqual(pattern["pattern_status"], "receiver_unbound")

    def test_vcall_rejects_merge_with_a_possible_alternate_vptr_definition(self):
        instructions = self._vcall_instructions(vptr_block=0, use_block=2)
        alternate = dict(instructions[0], block_serial=1, ea=0x1100,
            r=_nested("add", _reg(98, register=1), _number(0x20), 0x1100))
        instructions.insert(1, alternate)
        relations = {"cfg": {"complete": True, "blocks": [
            {"serial": 0, "predecessors": [], "successors": [1, 2]},
            {"serial": 1, "predecessors": [0], "successors": [2]},
            {"serial": 2, "predecessors": [0, 1], "successors": []},
        ]}}
        self.assertIsNone(_trace_vcall_pattern(instructions, instructions[-1], relations))

    def test_vtable_candidate_slots_and_thunk_chain(self):
        result = build_vtable_index(self.connection, abi="itanium")
        self.assertEqual(result["candidate_count"], 2)
        listing = list_vtables(self.connection, limit=10)
        self.assertEqual(listing["total"], 2)
        first = show_vtable(self.connection, address=0x5000)["items"][0]
        self.assertEqual([slot["target_ea"] for slot in first["slots"]], [0x1000, 0x1200])
        self.assertEqual([slot["entry_classification"] for slot in first["slots"]], ["function", "thunk"])
        self.assertTrue(first["slots"][1]["is_thunk"])
        self.assertEqual(first["slots"][1]["thunk_chain"], [0x1200, 0x1300])
        matches = search_vtables(self.connection, target_eas=[0x1000, 0x1200])
        self.assertEqual(matches["count"], 1)
        self.assertEqual(matches["items"][0]["address_point"], 0x5000)
        rerun = build_vtable_index(self.connection, abi="itanium")
        self.assertTrue(rerun["cached"])

    def test_vtable_keeps_nonzero_offset_to_top_as_weak_prefix_evidence(self):
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(sqlite_ea(0x4FF0), sqlite_ea(0xFFFFFFFFFFFFFFF8), None, 8, ".data.rel.ro", None, None, None, "scalar", "now"),
             (sqlite_ea(0x4FF8), 0x6000, 0x6000, 8, ".data.rel.ro", ".data.rel.ro", None, "typeinfo", "data", "now")],
        )
        self.connection.commit()
        build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5000)["items"][0]
        prefix = candidate["evidence"]["address_point_prefix"]
        self.assertEqual(prefix["offset_to_top"], -8)
        self.assertFalse(prefix["status"] == "confirmed")
        self.assertEqual(candidate["slot_count"], 2)

    def test_vtable_resolves_explicit_itanium_typeinfo_layout_without_claiming_class_hierarchy(self):
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(sqlite_ea(0x4FF0), sqlite_ea(0xFFFFFFFFFFFFFFF8), None, 8, ".data.rel.ro", None, None, None, "scalar", "now"),
             (sqlite_ea(0x4FF8), 0x6000, 0x6000, 8, ".data.rel.ro", ".data.rel.ro", None, "_ZTI3Foo", "data", "now"),
             (0x6000, 0x7010, 0x7010, 8, ".data.rel.ro", ".data.rel.ro", None, "_ZTVN10__cxxabiv117__class_type_infoE", "data", "now"),
             (0x6008, 0x8000, 0x8000, 8, ".data.rel.ro", ".rodata", None, "_ZTS3Foo", "data", "now")],
        )
        self.connection.executemany(
            "INSERT INTO symbols(address,name,type) VALUES(?,?,NULL)",
            [(0x4FF0, "_ZTV3Foo"), (0x6000, "_ZTI3Foo"), (0x7000, "_ZTVN10__cxxabiv117__class_type_infoE"),
             (0x8000, "_ZTS3Foo")],
        )
        self.connection.commit()

        result = build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5000)["items"][0]
        prefix = candidate["evidence"]["address_point_prefix"]
        typeinfo = prefix["typeinfo"]
        self.assertEqual(typeinfo["status"], "confirmed_itanium_typeinfo_layout")
        self.assertEqual(typeinfo["descriptor_kind"], "class_type_info")
        self.assertEqual(typeinfo["typeinfo_symbol"], "_ZTI3Foo")
        self.assertEqual(typeinfo["type_name_symbol"], "_ZTS3Foo")
        self.assertTrue(candidate["evidence"]["typeinfo_layout_confirmed"])
        self.assertTrue(candidate["evidence"]["address_point_symbol_match"])
        self.assertEqual(candidate["evidence"]["expected_table_symbol"], "_ZTV3Foo")
        self.assertEqual(candidate["table_address"], 0x4FF0)
        self.assertEqual(candidate["address_point"], 0x5000)
        self.assertFalse(candidate["evidence"]["rtti_confirmed"])
        self.assertEqual(result["coverage"]["typeinfo_layout_confirmed"], 1)

    def test_itanium_typeinfo_symbol_mismatch_remains_candidate(self):
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(sqlite_ea(0x4FF0), sqlite_ea(0xFFFFFFFFFFFFFFF8), None, 8, ".data.rel.ro", None, None, None, "scalar", "now"),
             (sqlite_ea(0x4FF8), 0x6000, 0x6000, 8, ".data.rel.ro", ".data.rel.ro", None, "_ZTI3Foo", "data", "now"),
             (0x6000, 0x7010, 0x7010, 8, ".data.rel.ro", ".data.rel.ro", None, "_ZTVN10__cxxabiv117__class_type_infoE", "data", "now"),
             (0x6008, 0x8000, 0x8000, 8, ".data.rel.ro", ".rodata", None, "_ZTS3Bar", "data", "now")],
        )
        self.connection.executemany(
            "INSERT INTO symbols(address,name,type) VALUES(?,?,NULL)",
            [(0x6000, "_ZTI3Foo"), (0x7000, "_ZTVN10__cxxabiv117__class_type_infoE"),
             (0x8000, "_ZTS3Bar")],
        )
        self.connection.commit()

        build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5000)["items"][0]
        typeinfo = candidate["evidence"]["address_point_prefix"]["typeinfo"]
        self.assertEqual(typeinfo["status"], "candidate_itanium_typeinfo_layout")
        self.assertFalse(typeinfo["checks"]["type_name_symbol_matches_typeinfo"])
        self.assertFalse(candidate["evidence"]["typeinfo_layout_confirmed"])
        self.assertEqual(candidate["table_address"], 0x4FF0)
        self.assertEqual(candidate["address_point"], 0x5000)

    def test_vtable_cache_tracks_scan_coverage_but_ignores_scan_timestamp(self):
        first = build_vtable_index(self.connection, abi="itanium")
        set_metadata(self.connection, {"data_pointer_scan": {
            "scope": {"start": None, "end": None}, "truncated": False,
            "scanned_bytes": 1024, "skipped": [], "generated_at": "first"}})
        self.connection.commit()
        second = build_vtable_index(self.connection, abi="itanium")
        self.assertNotEqual(first["run_id"], second["run_id"])
        set_metadata(self.connection, {"data_pointer_scan": {
            "scope": {"start": None, "end": None}, "truncated": False,
            "scanned_bytes": 1024, "skipped": [], "generated_at": "later"}})
        self.connection.commit()
        third = build_vtable_index(self.connection, abi="itanium")
        self.assertEqual(second["run_id"], third["run_id"])
        self.assertTrue(third["cached"])

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
        self.assertEqual(shown["targets"][0]["entry_classification"], "thunk")

    def test_table_slot_classifications_preserve_nullstub_runtime_and_library_traits(self):
        self.connection.executemany(
            "INSERT INTO functions(start_ea,end_ea,name,demangled_name,size,is_library,is_thunk,is_nullstub) "
            "VALUES(?,?,?,?,?,?,?,?)",
            [(0x1400, 0x1410, "empty_stub", "empty_stub", 0x10, 0, 0, 1),
             (0x1500, 0x1510, "runtime_library", "runtime_library", 0x10, 1, 0, 0),
             (0x1600, 0x1610, "import_thunk", "import_thunk [thunk]", 0x10, 1, 1, 0),
             (0x1700, 0x1710, "__cxa_pure_virtual", "__cxa_pure_virtual", 0x10, 1, 0, 0),
             (0x1800, 0x1810, "__cxa_deleted_virtual", "__cxa_deleted_virtual", 0x10, 1, 0, 0)],
        )
        rows = [(0x5200, 0x1400, 0x1400, 8, "rtti", ".text", 0x1400, "empty_stub", "function", "now"),
                (0x5208, 0x1500, 0x1500, 8, "rtti", ".text", 0x1500, "runtime_library", "function", "now"),
                (0x5210, 0x1600, 0x1600, 8, "rtti", ".text", 0x1600, "import_thunk", "function", "now"),
                (0x5218, 0x1700, 0x1700, 8, "rtti", ".text", 0x1700, "__cxa_pure_virtual", "function", "now"),
                (0x5220, 0x1800, 0x1800, 8, "rtti", ".text", 0x1800, "__cxa_deleted_virtual", "function", "now"),
                (0x5228, 0, None, 8, "rtti", None, None, None, "null", "now")]
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        self.connection.commit()

        build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5200)["items"][0]
        self.assertEqual([slot["entry_classification"] for slot in candidate["slots"]],
            ["nullstub", "library_function", "import_thunk", "pure_virtual_runtime_named",
             "deleted_virtual_runtime_named", "null_slot"])
        self.assertEqual(candidate["slots"][0]["is_nullstub"], 1)
        self.assertEqual(candidate["slots"][1]["is_library"], 1)

    def test_vcall_uses_normalized_microcode_cfg_tables(self):
        function = self._add_vcall_fixture()
        self.connection.execute("UPDATE microcode SET relations_json=? WHERE function_ea=?",
            (json.dumps({"version": 2, "truncated": False,
                "cfg": {"complete": True, "block_count": 1, "edge_count": 0},
                "def_use": {"coverage": "direct register operands carrying a Hex-Rays value_number"}}),
             sqlite_ea(function)))
        self.connection.execute("INSERT INTO micro_blocks VALUES(?,?,?,?,?,?)",
            ("microcode", sqlite_ea(function), 0, "[]", "[]", 3))
        self.connection.commit()
        result = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(result["pattern_candidate_count"], 1)
        site = list_vcalls(self.connection, function_ea=function)["items"][0]
        pattern = site["evidence"]["pattern"]
        self.assertTrue(pattern["cfg_complete"])
        self.assertTrue(pattern["control_flow_dominance_verified"])
        self.assertEqual(pattern["definition_use_chain"][0]["relationship"],
            "same_block_ordered_candidate")

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
        self.connection.execute("INSERT INTO micro_blocks VALUES(?,?,?,?,?,?)",
            ("microcode", sqlite_ea(0x1000), 0, "[]", "[]", 0))
        self.connection.execute("INSERT INTO micro_value_refs VALUES(?,?,?,?,?,?,?,?)",
            ("microcode", sqlite_ea(0x1000), 1, "definition", 0, 0, sqlite_ea(0x1000), "d"))
        self.connection.commit()
        from ida_ai.jobs import _artifact_fingerprint
        before = _artifact_fingerprint(self.connection, f"vtable:{candidate}")
        reset_analysis(self.connection)
        self.connection.commit()
        self.assertEqual(self.connection.execute("SELECT count(*) FROM micro_blocks").fetchone()[0], 0)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM micro_value_refs").fetchone()[0], 0)
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

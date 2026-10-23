from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, reset_analysis, set_metadata, sqlite_ea
from ida_ai.propagation import add_seed, preview_seed
from ida_ai.vtable_types import (assert_type_application_revision, class_relationships,
                                 preview_vtable_type_plan, type_application_revision)
from ida_ai.virtual_tables import (
    _trace_vcall_pattern,
    _unknown_vcall_reason,
    _source_hash,
    analyze_vcall,
    build_vcall_index,
    build_vtable_index,
    build_vptr_write_index,
    invalidate_function_virtual_artifacts,
    list_vcalls,
    list_vtables,
    parse_itanium_typeinfo_descriptor,
    search_vtables,
    show_vcall,
    show_vtable,
    store_itanium_rtti_descriptors,
    trace_vptr_object_flows,
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

    def _nested_vcall(self, slot_offset=8):
        call = self._vcall_instructions(vptr_block=0, use_block=0)[-1]
        receiver = _reg(99)
        vptr = _nested("ldx", _reg(50), receiver, 0x2000)
        slot_address = (_nested("add", vptr, _number(slot_offset), 0x2008)
                        if slot_offset else vptr)
        call["r"] = _nested("ldx", _reg(51), slot_address, 0x2008)
        call["d"]["arguments"] = [receiver]
        return call

    def _loaded_pointer_receiver_vcall(self, *, slot_offset=0x10, argument_matches=True):
        call = self._vcall_instructions(vptr_block=0, use_block=0)[-1]
        object_pointer = _nested("ldx", _reg(238),
            _nested("add", _reg(240), _number(0x4588), 0x2000), 0x2000)
        object_pointer["value_number"] = 238
        vptr = _nested("ldx", _reg(239), object_pointer, 0x2008)
        vptr["value_number"] = 239
        slot_address = _nested("add", vptr, _number(slot_offset), 0x2010)
        call["r"] = _nested("ldx", _reg(241), slot_address, 0x2010)
        call["d"]["arguments"] = [object_pointer if argument_matches else _reg(77)]
        return call

    def test_loaded_pointer_receiver_needs_exact_call_argument_binding(self):
        call = self._loaded_pointer_receiver_vcall(argument_matches=True)
        pattern = _trace_vcall_pattern([call], call, {})
        self.assertIsNotNone(pattern)
        self.assertEqual(pattern["pattern_status"], "candidate")
        self.assertEqual(pattern["receiver_binding"]["status"], "exact_identity_match")
        self.assertEqual(pattern["basis"], "loaded_pointer_receiver_then_vptr_and_constant_slot")
        self.assertEqual(pattern["vptr_offset"], 0)
        self.assertEqual(pattern["slot_offset"], 0x10)
        self.assertEqual(pattern["receiver_derivation"]["pointer_field_offset"], 0x4588)
        self.assertEqual(len(pattern["definition_chain"]), 3)

        # A different exported value identity must not bind as the receiver.
        call = self._loaded_pointer_receiver_vcall(argument_matches=False)
        self.assertIsNone(_trace_vcall_pattern([call], call, {}))
        self.assertEqual(_unknown_vcall_reason(call, None, {})["code"], "extra_load_chain")

    def test_loaded_pointer_receiver_rejects_nonconstant_pointer_field(self):
        call = self._loaded_pointer_receiver_vcall()
        pointer_load = call["r"]["instruction"]["r"]["instruction"]["l"]["instruction"]["r"]["instruction"]
        pointer_load["r"] = _nested("add", _reg(240), _reg(88), 0x2000)
        self.assertIsNone(_trace_vcall_pattern([call], call, {}))
        self.assertEqual(_unknown_vcall_reason(call, None, {})["code"], "extra_load_chain")

    def test_loaded_pointer_receiver_is_indexed_and_persisted(self):
        function = self._add_vcall_fixture()
        call = self._loaded_pointer_receiver_vcall()
        self.connection.execute("UPDATE micro_instructions SET r_json=?,d_json=? "
            "WHERE function_ea=? AND opcode='icall'",
            (json.dumps(call["r"]), json.dumps(call["d"]), function))
        self.connection.commit()
        result = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(result["pattern_candidate_count"], 1)
        site = list_vcalls(self.connection, function_ea=function)["items"][0]
        self.assertEqual(site["status"], "vtable_pattern_candidate")
        self.assertEqual(site["callee"]["receiver_derivation"]["kind"], "loaded_pointer_argument")
        self.assertEqual(site["slot_offset"], 0x10)

    def test_vcall_expanded_loads_need_no_intermediate_value_numbers(self):
        for offset in (0, 8, 32):
            with self.subTest(offset=offset):
                call = self._nested_vcall(offset)
                pattern = _trace_vcall_pattern([call], call, {})
                self.assertEqual(pattern["pattern_status"], "candidate")
                self.assertEqual(pattern["slot_offset"], offset)
                self.assertEqual(len(pattern["definition_chain"]), 2)
                self.assertFalse(pattern["cxx_virtual_call_confirmed"])

    def test_call_nested_in_result_move_is_indexed_analyzed_and_traced(self):
        from ida_ai.vcall_trace import trace_virtual_call
        function = self._add_vcall_fixture()
        call = self._nested_vcall(32)
        call['opcode'] = 'icall'
        call['ea'] = 0x200C
        self.connection.execute("UPDATE micro_instructions SET opcode='mov',l_json=?,r_json='{}',d_json=? "
            "WHERE function_ea=? AND opcode='icall'",
            (json.dumps({'kind':'nested','instruction':call}), json.dumps(_reg(400)), function))
        self.connection.commit()
        result = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(result['site_count'], 1)
        site = list_vcalls(self.connection)['items'][0]
        self.assertEqual(site['evidence']['operand_path'], 'l.instruction')
        self.assertEqual(site['slot_offset'], 32)
        analyzed = analyze_vcall(self.connection, call_id=site['call_id'])
        self.assertIsInstance(analyzed, dict)
        traced = trace_virtual_call(self.connection, call_id=site['call_id'])
        self.assertIsInstance(traced, dict)

    def test_nested_vcall_is_persisted_and_cache_preserves_candidate(self):
        function = self._add_vcall_fixture()
        call = self._nested_vcall(0)
        self.connection.execute("UPDATE micro_instructions SET r_json=?,d_json=? "
            "WHERE function_ea=? AND opcode='icall'",
            (json.dumps(call["r"]), json.dumps(call["d"]), function))
        self.connection.commit()
        result = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(result["pattern_candidate_count"], 1)
        site = list_vcalls(self.connection)["items"][0]
        self.assertEqual(site["slot_offset"], 0)
        self.assertEqual(site["callee"]["receiver_binding"]["status"], "exact_identity_match")
        cached = build_vcall_index(self.connection, function_eas=[function])
        self.assertTrue(cached["cached"])
        self.assertEqual(cached["run_id"], result["run_id"])

    def test_nested_vcall_receiver_binding_remains_required(self):
        for arguments, status in (([], "mismatch"), ([_reg(77)], "mismatch"),
                                  ([_reg(99), _reg(99)], "ambiguous")):
            with self.subTest(status=status, arguments=arguments):
                call = self._nested_vcall()
                call["d"]["arguments"] = arguments
                pattern = _trace_vcall_pattern([call], call, {})
                self.assertEqual(pattern["pattern_status"], "receiver_unbound")
                self.assertEqual(pattern["receiver_binding"]["status"], status)

    def test_nested_vcall_truncated_callee_or_arguments_are_unknown(self):
        for root in ("r", "d"):
            call = self._nested_vcall()
            call[root]["truncated"] = True
            self.assertIsNone(_trace_vcall_pattern([call], call, {}))
            self.assertEqual(_unknown_vcall_reason(call, None, {})["code"],
                             "call_operand_tree_truncated")

    def test_nested_vcall_does_not_promote_extra_object_load(self):
        call = self._nested_vcall(0)
        call["r"]["instruction"]["r"]["instruction"]["r"] = _nested(
            "ldx", _reg(50), _reg(99), 0x2000)
        self.assertIsNone(_trace_vcall_pattern([call], call, {}))
        self.assertEqual(_unknown_vcall_reason(call, None, {})["code"], "extra_load_chain")

    def test_nested_load_can_be_moved_into_callee_register(self):
        call = self._nested_vcall()
        move = dict(call, opcode="mov", ordinal=0, l=call["r"], r=_operand("empty"), d=_reg(2))
        call["r"] = _reg(2)
        pattern = _trace_vcall_pattern([move, call], call, {})
        self.assertEqual(pattern["pattern_status"], "candidate")

    def test_vcall_diagnostics_describe_actual_definition_failure(self):
        instructions = self._vcall_instructions(vptr_block=0, use_block=2)
        instructions.insert(1, dict(instructions[0], block_serial=1))
        diagnostics = []
        pattern = _trace_vcall_pattern(instructions, instructions[-1], {}, diagnostics=diagnostics)
        reason = _unknown_vcall_reason(instructions[-1], pattern, {}, diagnostics)
        self.assertEqual(reason["code"], "multiple_cross_block_definitions")
        self.assertEqual(reason["evidence"][0]["definition_count"], 2)
        self.assertEqual(reason["evidence"][0]["use"]["block_serial"], 2)
        # An exporter capability flag is not evidence of multiple definitions.
        reason = _unknown_vcall_reason(dict(instructions[-1], r=_reg(88)), None,
            {"def_use": {"cross_block_reaching_definitions": True}, "truncated": True})
        self.assertEqual(reason["code"], "function_operand_tree_truncated")
        self.assertEqual(reason["scope"], "function")

    def test_vtable_candidate_slots_and_thunk_chain(self):
        result = build_vtable_index(self.connection, abi="itanium")
        self.assertEqual(result["candidate_count"], 2)
        listing = list_vtables(self.connection, limit=10)
        self.assertEqual(listing["total"], 2)
        first = show_vtable(self.connection, address=0x5000)["items"][0]
        self.assertIsNone(first["table_address"])
        self.assertEqual(first["table_address_status"], "unresolved")
        self.assertEqual(first["candidate_start_address"], 0x5000)
        self.assertEqual([slot["target_ea"] for slot in first["slots"]], [0x1000, 0x1200])
        self.assertEqual([slot["entry_classification"] for slot in first["slots"]], ["function", "thunk"])
        self.assertTrue(first["slots"][1]["is_thunk"])
        self.assertEqual(first["slots"][1]["thunk_chain"], [0x1200, 0x1300])
        matches = search_vtables(self.connection, target_eas=[0x1000, 0x1200])
        self.assertEqual(matches["count"], 1)
        self.assertEqual(matches["items"][0]["address_point"], 0x5000)
        rerun = build_vtable_index(self.connection, abi="itanium")
        self.assertTrue(rerun["cached"])

    def test_search_follows_multihop_thunks_and_fixups_change_revision(self):
        self.connection.execute("UPDATE functions SET is_thunk=1,thunk_target_ea=4096 WHERE start_ea=4864")
        build_vtable_index(self.connection, abi="itanium")
        result = search_vtables(self.connection, target_eas=[0x1200, 0x1000], slot_index=1)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["matching_slots"][0]["thunk_chain"], [0x1200, 0x1300, 0x1000])
        before = _source_hash(self.connection, "vtable")
        self.connection.execute("INSERT INTO data_fixups VALUES(?,?,?)", (0x5000, '{"type":7}', 'now'))
        self.assertNotEqual(before, _source_hash(self.connection, "vtable"))
        before = _source_hash(self.connection, "vtable")
        self.connection.execute("UPDATE data_fixups SET generated_at='later'")
        self.assertEqual(before, _source_hash(self.connection, "vtable"))
        reset_analysis(self.connection)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM data_fixups").fetchone()[0], 0)

    def test_vtable_uses_ztv_symbol_for_boundary_when_prefix_was_not_exported(self):
        self.connection.execute("INSERT INTO symbols(address,name,type) VALUES(?,?,NULL)",
            (0x4FF0, "_ZTV3Foo"))
        self.connection.commit()
        build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5000)["items"][0]
        self.assertEqual(candidate["table_address"], 0x4FF0)
        self.assertEqual(candidate["table_address_status"], "candidate_from_ztv_symbol")
        self.assertEqual(candidate["evidence"]["table_start_symbol"], "_ZTV3Foo")

    def test_parse_itanium_vmi_bases_with_signed_offsets_and_flags(self):
        def word(value: int, width: int) -> bytes:
            return int(value).to_bytes(width, "little", signed=False)

        negative_offset_flags = ((-0x18 << 8) | 0x3) & ((1 << 64) - 1)
        raw = (word(0x8000, 8) + word(0x9000, 8) + word(0x2, 4) + word(2, 4)
               + word(0xA000, 8) + word(negative_offset_flags, 8)
               + word(0xB000, 8) + word((0x20 << 8) | 0x2, 8))
        parsed = parse_itanium_typeinfo_descriptor(typeinfo_ea=0x7000,
            descriptor_kind="multiple_or_virtual_inheritance", raw=raw,
            pointer_size=8, byteorder="little")
        self.assertEqual(parsed["parse_status"], "parsed")
        self.assertEqual(parsed["flags"], 2)
        self.assertTrue(parsed["evidence"]["vmi_header"]["diamond_shaped"])
        self.assertEqual([base["typeinfo_ea"] for base in parsed["bases"]], [0xA000, 0xB000])
        self.assertEqual(parsed["bases"][0]["byte_offset"], -0x18)
        self.assertTrue(parsed["bases"][0]["is_virtual"])
        self.assertTrue(parsed["bases"][0]["is_public"])
        self.assertEqual(parsed["bases"][1]["byte_offset"], 0x20)
        self.assertFalse(parsed["bases"][1]["is_virtual"])

    def test_itanium_descriptor_missing_and_truncated_bytes_remain_unknown(self):
        unknown = parse_itanium_typeinfo_descriptor(typeinfo_ea=0x7000,
            descriptor_kind=None, raw=b"\0" * 16, pointer_size=8, byteorder="little")
        self.assertEqual(unknown["parse_status"], "unknown_descriptor_kind")
        truncated = parse_itanium_typeinfo_descriptor(typeinfo_ea=0x7000,
            descriptor_kind="multiple_or_virtual_inheritance", raw=b"\0" * 20,
            pointer_size=8, byteorder="little")
        self.assertEqual(truncated["parse_status"], "truncated_vmi_header")

    def test_store_rtti_descriptor_run_is_versioned_and_append_only(self):
        raw = (0x8000).to_bytes(8, "little") + (0x9000).to_bytes(8, "little")
        observation = {"typeinfo_ea": 0x7000, "descriptor_kind": "class_type_info",
            "descriptor_symbol": "_ZTVN10__cxxabiv117__class_type_infoE",
            "symbol": "_ZTI3Foo", "type_name_ea": 0x9000, "type_name_symbol": "_ZTS3Foo",
            "type_name": "3Foo", "raw_hex": raw.hex(), "read_status": "header_read"}
        coverage = {"pointer_size": 8, "byteorder": "little", "max_bases": 128, "truncated": False}
        first = store_itanium_rtti_descriptors(self.connection,
            input_snapshot_hash="snapshot-one", descriptors=[observation], coverage=coverage)
        second = store_itanium_rtti_descriptors(self.connection,
            input_snapshot_hash="snapshot-two", descriptors=[observation], coverage=coverage)
        self.assertNotEqual(first["rtti_run_id"], second["rtti_run_id"])
        self.assertEqual(self.connection.execute("SELECT count(*) FROM rtti_runs").fetchone()[0], 2)
        row = self.connection.execute("SELECT parse_status,base_count FROM rtti_typeinfos WHERE rtti_run_id=?",
            (second["rtti_run_id"],)).fetchone()
        self.assertEqual(tuple(row), ("parsed_no_bases", 0))

    def test_vtable_snapshot_and_candidate_include_matching_rtti_run(self):
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(sqlite_ea(0x4FF0), 0, None, 8, ".data.rel.ro", None, None, None, "scalar", "now"),
             (0x4FF8, 0x6000, 0x6000, 8, ".data.rel.ro", ".data.rel.ro", None, "_ZTI3Foo", "data", "now"),
             (0x6000, 0x7010, 0x7010, 8, ".data.rel.ro", ".data.rel.ro", None,
              "_ZTVN10__cxxabiv117__class_type_infoE", "data", "now"),
             (0x6008, 0x8000, 0x8000, 8, ".data.rel.ro", ".rodata", None, "_ZTS3Foo", "data", "now")],
        )
        self.connection.executemany("INSERT INTO symbols(address,name,type) VALUES(?,?,NULL)",
            [(0x4FF0, "_ZTV3Foo"), (0x6000, "_ZTI3Foo"),
             (0x7000, "_ZTVN10__cxxabiv117__class_type_infoE"), (0x8000, "_ZTS3Foo")])
        self.connection.commit()
        base_hash = _source_hash(self.connection, "vtable", include_rtti=False)
        raw = (0x7010).to_bytes(8, "little") + (0x8000).to_bytes(8, "little")
        stored = store_itanium_rtti_descriptors(self.connection, input_snapshot_hash=base_hash,
            descriptors=[{"typeinfo_ea": 0x6000, "descriptor_kind": "class_type_info",
                "descriptor_symbol": "_ZTVN10__cxxabiv117__class_type_infoE",
                "symbol": "_ZTI3Foo", "type_name_ea": 0x8000, "type_name_symbol": "_ZTS3Foo",
                "type_name": "3Foo", "raw_hex": raw.hex(), "read_status": "header_read"}],
            coverage={"pointer_size": 8, "byteorder": "little", "max_bases": 128, "truncated": False})
        result = build_vtable_index(self.connection, abi="itanium")
        candidate = show_vtable(self.connection, address=0x5000)["items"][0]
        self.assertEqual(candidate["evidence"]["rtti_run_id"], stored["rtti_run_id"])
        self.assertEqual(candidate["evidence"]["typeinfo_descriptor"]["parse_status"], "parsed_no_bases")
        self.assertEqual(candidate["evidence"]["class_relationship_status"], "descriptor_has_no_base_edges")
        self.assertEqual(result["rtti_typeinfo_count"], 1)

    def test_class_relationship_and_type_preview_are_revision_checked(self):
        self.connection.executemany(
            "INSERT INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(0x4FF0, 0, None, 8, ".data.rel.ro", None, None, None, "scalar", "now"),
             (0x4FF8, 0x6000, 0x6000, 8, ".data.rel.ro", ".rodata", None, "derived typeinfo", "data", "now"),
             (0x50F0, 0, None, 8, ".data.rel.ro", None, None, None, "scalar", "now"),
             (0x50F8, 0x6100, 0x6100, 8, ".data.rel.ro", ".rodata", None, "base typeinfo", "data", "now")],
        )
        self.connection.commit()
        input_hash = _source_hash(self.connection, "vtable", include_rtti=False)
        base_raw = (0x7000).to_bytes(8, "little") + (0x7100).to_bytes(8, "little")
        derived_raw = base_raw + (0).to_bytes(4, "little") + (1).to_bytes(4, "little")
        derived_raw += (0x6100).to_bytes(8, "little") + ((0x18 << 8) | 2).to_bytes(8, "little")
        descriptors = [
            {"typeinfo_ea": 0x6000, "descriptor_kind": "multiple_or_virtual_inheritance",
             "symbol": "_ZTI7Derived", "type_name_ea": 0x7100, "type_name": "7Derived",
             "raw_hex": derived_raw.hex(), "read_status": "descriptor_read"},
            {"typeinfo_ea": 0x6100, "descriptor_kind": "class_type_info",
             "symbol": "_ZTI4Base", "type_name_ea": 0x7100, "type_name": "4Base",
             "raw_hex": base_raw.hex(), "read_status": "descriptor_read"},
        ]
        store_itanium_rtti_descriptors(self.connection, input_snapshot_hash=input_hash,
            descriptors=descriptors,
            coverage={"pointer_size": 8, "byteorder": "little", "max_bases": 128, "truncated": False})
        build_vtable_index(self.connection, abi="itanium")
        relationships = class_relationships(self.connection, limit=0)
        self.assertEqual(relationships["total"], 1)
        relation = relationships["items"][0]
        self.assertEqual(relation["derived_typeinfo_ea"], 0x6000)
        self.assertEqual(relation["base_typeinfo_ea"], 0x6100)
        self.assertEqual(relation["inheritance"]["byte_offset"], 0x18)
        self.assertFalse(relation["table_associations"]["derived_ambiguous"])
        candidate = self.connection.execute("SELECT candidate_id FROM vtable_candidates "
            "WHERE address_point=? AND stale=0", (sqlite_ea(0x5000),)).fetchone()[0]
        preview = preview_vtable_type_plan(self.connection, {
            "candidate_id": candidate, "relation_id": relation["relation_id"],
            "type_definition": {"name": "Derived", "declaration": "struct Derived { void *vptr; };"},
            "assignments": [{"address": "0x5000", "declaration": "void **"}],
            "rationale": "layout remains a hypothesis"})
        self.assertTrue(preview["preview_only"])
        self.assertEqual(preview["plan"]["assignments"][0]["evidence_roles"], ["address_point", "slot_entry"])
        revision = type_application_revision(self.connection)
        self.assertEqual(revision, preview["revision_token"])
        assert_type_application_revision(self.connection, revision)
        with self.assertRaisesRegex(ValueError, "outside this candidate"):
            preview_vtable_type_plan(self.connection, {"candidate_id": candidate,
                "type_definition": {"name": "Bad", "declaration": "struct Bad {};"},
                "assignments": [{"address": "0x9999", "declaration": "void *"}]})
        self.connection.execute("INSERT INTO type_definitions(name,declaration,updated_at) VALUES(?,?,?)",
            ("Changed", "struct Changed {};", "now"))
        self.connection.commit()
        with self.assertRaisesRegex(ValueError, "revision is stale"):
            assert_type_application_revision(self.connection, revision)

        from ida_ai.jobs import _artifact_fingerprint
        relation_ref = f"vrel:{relation['relation_id']}"
        self.assertNotEqual(_artifact_fingerprint(self.connection, relation_ref),
                            hashlib.sha256(b"missing").hexdigest())
        store_itanium_rtti_descriptors(self.connection, input_snapshot_hash=input_hash,
            descriptors=descriptors,
            coverage={"pointer_size": 8, "byteorder": "little", "max_bases": 128, "truncated": True})
        build_vtable_index(self.connection, abi="itanium")
        refreshed_relations = class_relationships(self.connection, limit=0)
        self.assertEqual(refreshed_relations["total"], 1)
        self.assertNotEqual(refreshed_relations["rtti_run_id"], relationships["rtti_run_id"])
        self.assertEqual(self.connection.execute(
            "SELECT stale FROM vtable_class_relationships WHERE relation_id=?", (relation["relation_id"],)
        ).fetchone()["stale"], 1)
        self.assertEqual(_artifact_fingerprint(self.connection, relation_ref),
                         hashlib.sha256(b"missing").hexdigest())

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
        self.assertEqual(analyzed["resolution"]["candidate_counts"]["compatible_table_slot_rows"], 1)
        self.assertEqual(analyzed["resolution"]["candidate_counts"]["compatible_distinct_target_eas"], 1)
        self.assertEqual(analyzed["resolution"]["prior_vptr_writes"]["status"], "not_indexed")
        self.assertEqual(analyzed["resolution"]["targets"][0]["target_ea"], 0x1200)
        shown = show_vcall(self.connection, call_id=site["call_id"])
        self.assertEqual(len(shown["targets"]), 1)
        self.assertEqual(shown["targets"][0]["entry_classification"], "thunk")

        build_vptr_write_index(self.connection, function_eas=[0x2000])
        analyzed = analyze_vcall(self.connection, call_id=site["call_id"])
        self.assertEqual(analyzed["resolution"]["prior_vptr_writes"]["status"], "no_matching_observed_store")
        shown = show_vcall(self.connection, call_id=site["call_id"])
        self.assertEqual(len(shown["receiver_flows"]), 1)
        self.assertEqual(shown["receiver_flows"][0]["status"], "unknown")
        self.assertEqual(shown["receiver_flows"][0]["edge"]["kind"], "prior_vptr_write_scan_result")

    def test_vcall_unknown_reason_is_reported_with_run_counts(self):
        function = self._add_vcall_fixture()
        self.connection.execute("UPDATE micro_instructions SET r_json=? WHERE function_ea=? AND opcode='icall'",
            (json.dumps({"kind": "register", "value_number": 2, "register": 10,
                "size": 8, "truncated": True}), sqlite_ea(function)))
        self.connection.commit()
        build_vtable_index(self.connection, abi="itanium")
        result = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(result["pattern_candidate_count"], 0)
        self.assertEqual(result["unknown_reason_counts"], {"call_operand_tree_truncated": 1})
        site = list_vcalls(self.connection, function_ea=function)["items"][0]
        self.assertEqual(site["evidence"]["unknown_reason"]["code"], "call_operand_tree_truncated")

    def test_rebuilding_vtable_index_stales_saved_vcall_targets(self):
        function = self._add_vcall_fixture()
        build_vtable_index(self.connection, abi="itanium")
        build_vcall_index(self.connection, function_eas=[function])
        site = list_vcalls(self.connection, function_ea=function)["items"][0]
        analyze_vcall(self.connection, call_id=site["call_id"])
        self.assertEqual(len(show_vcall(self.connection, call_id=site["call_id"])["targets"]), 1)

        self.connection.execute(
            "UPDATE data_pointer_slots SET target_name='changed_symbol' WHERE source_ea=?", (0x5100,))
        self.connection.commit()
        build_vtable_index(self.connection, abi="itanium")
        self.assertEqual(show_vcall(self.connection, call_id=site["call_id"])["targets"], [])
        historical = show_vcall(self.connection, call_id=site["call_id"], include_stale=True)
        self.assertEqual(len(historical["targets"]), 1)
        self.assertTrue(historical["targets"][0]["stale"])

    def test_prior_same_function_vptr_store_is_linked_as_candidate_evidence(self):
        function = self._add_vcall_fixture()
        rows = [tuple(row) for row in self.connection.execute(
            "SELECT * FROM micro_instructions WHERE function_ea=? ORDER BY block_serial,ordinal",
            (sqlite_ea(function),))]
        self.connection.execute("DELETE FROM micro_instructions WHERE function_ea=?", (sqlite_ea(function),))
        store = _insn(function, 0, 0, function - 4, "stx", _number(0x5000),
            _operand("empty"), _nested("add", _reg(99, register=0), _number(0x10), function - 4))
        shifted = [tuple([row[0], row[1], row[2] + 1, row[3] + 4, *row[4:]]) for row in rows]
        self.connection.executemany("INSERT INTO micro_instructions VALUES(?,?,?,?,?,?,?,?,?)", [store, *shifted])
        self.connection.execute("UPDATE microcode SET instruction_count=? WHERE function_ea=?",
            (len(shifted) + 1, sqlite_ea(function)))
        self.connection.commit()
        build_vtable_index(self.connection, abi="itanium")
        writes = build_vptr_write_index(self.connection, function_eas=[function])
        self.assertEqual(writes["write_count"], 1)
        indexed = self.connection.execute("SELECT * FROM vptr_writes WHERE stale=0").fetchone()
        self.assertEqual(indexed["address_point"], sqlite_ea(0x5000))
        build_vcall_index(self.connection, function_eas=[function])
        call = list_vcalls(self.connection, function_ea=function)["items"][0]
        analyzed = analyze_vcall(self.connection, call_id=call["call_id"])
        prior = analyzed["resolution"]["prior_vptr_writes"]
        self.assertEqual(prior["status"], "candidate")
        self.assertEqual(prior["items"][0]["order_relation"], "same_block_prior_store")
        self.assertTrue(analyzed["resolution"]["targets"][0]["matching_prior_vptr_write_candidate"])
        self.assertEqual(analyzed["resolution"]["candidate_counts"]["prior_store_narrowed_table_slot_rows"], 1)
        shown = show_vcall(self.connection, call_id=call["call_id"])
        self.assertEqual(len(shown["receiver_flows"]), 1)
        self.assertEqual(shown["receiver_flows"][0]["edge"]["kind"], "observed_prior_vptr_store_candidate")

    def test_vptr_write_cache_retains_partial_status_and_function_refresh_stales_it(self):
        function = self._add_vcall_fixture()
        build_vtable_index(self.connection, abi="itanium")
        first = build_vptr_write_index(self.connection, function_eas=[function, 0xDEAD])
        self.assertEqual(first["status"], "partial")
        cached = build_vptr_write_index(self.connection, function_eas=[function, 0xDEAD])
        self.assertTrue(cached["cached"])
        self.assertEqual(cached["status"], "partial")
        empty_run = build_vptr_write_index(self.connection, function_eas=[function])
        self.assertEqual(empty_run["write_count"], 0)
        calls = build_vcall_index(self.connection, function_eas=[function])
        self.assertEqual(calls["site_count"], 1)
        current_candidate = self.connection.execute(
            "SELECT candidate_id,address_point FROM vtable_candidates WHERE stale=0 ORDER BY address_point LIMIT 1").fetchone()
        self.connection.execute("INSERT INTO vptr_writes(write_id,run_id,function_ea,address_point,candidate_id,status,evidence_json,source_snapshot_hash) "
            "VALUES(?,?,?,?,?,?,?,?)", ("fixture-write", empty_run["run_id"], sqlite_ea(function),
                current_candidate["address_point"], current_candidate["candidate_id"], "test", "{}",
                empty_run["coverage"]["source_snapshot_hash"]))
        self.connection.commit()
        from ida_ai.jobs import _artifact_fingerprint
        before = _artifact_fingerprint(self.connection, "vptr:fixture-write")
        invalidated = invalidate_function_virtual_artifacts(self.connection, [function])
        self.assertEqual(invalidated["vptr_writes"], 1)
        self.assertEqual(self.connection.execute("SELECT stale FROM vptr_writes WHERE write_id='fixture-write'").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT status FROM vptr_write_runs WHERE run_id=?",
            (empty_run["run_id"],)).fetchone()[0], "stale")
        self.assertEqual(self.connection.execute("SELECT status FROM vptr_write_runs WHERE run_id=?",
            (empty_run["run_id"],)).fetchone()[0], "stale")
        self.assertEqual(self.connection.execute("SELECT status FROM vcall_runs WHERE run_id=?",
            (calls["run_id"],)).fetchone()[0], "stale")
        self.assertNotEqual(before, _artifact_fingerprint(self.connection, "vptr:fixture-write"))

    def test_vptr_write_trace_follows_direct_call_argument_flow(self):
        writer, caller = 0x3000, 0x4000
        self.connection.executemany(
            "INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
            [(sqlite_ea(writer), sqlite_ea(writer + 0x100), "write_vptr", 0x100),
             (sqlite_ea(caller), sqlite_ea(caller + 0x100), "call_writer", 0x100)],
        )
        self.connection.executemany(
            "INSERT INTO micro_flow(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at,arguments_json,return_json,locals_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(sqlite_ea(writer), "MMAT_LVARS", "test", "ok", 1, "writer-flow", "now",
              json.dumps([{"local_index": 0, "name": "this", "size": 8}]), "{}", "[]"),
             (sqlite_ea(caller), "MMAT_LVARS", "test", "ok", 1, "caller-flow", "now", "[]", "{}", "[]")],
        )
        store_address = _nested("add", _operand("local", local_index=0, local_offset=0, size=8), _number(0), writer)
        store = _insn(writer, 0, 0, writer, "stx", _number(0x5000), _operand("empty"), store_address)
        actual = _operand("local", local_index=1, local_offset=0, size=8)
        call = _insn(caller, 0, 0, caller, "call", _operand("global", address=writer),
            _operand("empty"), _operand("arglist", callee=writer, arguments=[actual]))
        self.connection.executemany("INSERT INTO micro_flow_instructions VALUES(?,?,?,?,?,?,?,?,?)", [store, call])
        self.connection.commit()
        build_vtable_index(self.connection, abi="itanium")
        indexed = build_vptr_write_index(self.connection, function_eas=[writer], view_name="micro_flow")
        self.assertEqual(indexed["write_count"], 1)
        write = self.connection.execute("SELECT write_id FROM vptr_writes WHERE run_id=?", (indexed["run_id"],)).fetchone()
        result = trace_vptr_object_flows(self.connection, write_id=write["write_id"])
        self.assertEqual(result["status"], "object_flow_paths_found")
        self.assertEqual(result["object_flow_path_count"], 1)
        self.assertEqual(result["object_flow_paths"][0]["function_ea"], caller)
        self.assertTrue(any(edge["family"] == "parameter" for edge in result["object_flow_paths"][0]["trace"]))
        self.assertNotIn("caller_paths", result)
        seed = add_seed(self.connection, {
            "node": {"kind": "local", "function": writer, "local_index": 0},
            "constraint": {"kind": "type", "type_name": "derived_t", "offset": 0},
            "basis": "hypothesis",
            "evidence": [{"source_ref": f"vptr:{write['write_id']}", "description": "observed address-point store"}],
        })
        seed_evidence = self.connection.execute(
            "SELECT provenance_json FROM propagation_constraints WHERE constraint_id=?", (seed["seed_id"],),
        ).fetchone()
        self.assertEqual(json.loads(seed_evidence[0])["evidence"][0]["binding"]["candidate_id"],
            self.connection.execute("SELECT candidate_id FROM vptr_writes WHERE write_id=?",
                (write["write_id"],)).fetchone()[0])
        preview = preview_seed(self.connection, seed["seed_id"])
        self.assertIn(f"local:0x{caller:X}:1", {item["node_id"] for item in preview["proposals"]})
        self.assertFalse(next(item for item in preview["proposals"]
            if item["node_id"] == f"local:0x{caller:X}:1")["acceptable"])
        with self.assertRaisesRegex(ValueError, "only seed a hypothesis"):
            add_seed(self.connection, {"node": {"kind": "local", "function": writer, "local_index": 0},
                "constraint": {"kind": "type", "type_name": "observed_t", "offset": 0}, "basis": "observed",
                "evidence": [{"source_ref": f"vptr:{write['write_id']}", "description": "unconfirmed type identity"}]})
        with self.assertRaisesRegex(ValueError, "does not match seed node"):
            add_seed(self.connection, {"node": {"kind": "local", "function": writer, "local_index": 9},
                "constraint": {"kind": "type", "type_name": "wrong_t", "offset": 0}, "basis": "hypothesis",
                "evidence": [{"source_ref": f"vptr:{write['write_id']}", "description": "wrong binding"}]})
        with self.assertRaisesRegex(ValueError, "offset must match"):
            add_seed(self.connection, {"node": {"kind": "local", "function": writer, "local_index": 0},
                "constraint": {"kind": "type", "type_name": "wrong_t", "offset": 8}, "basis": "hypothesis",
                "evidence": [{"source_ref": f"vptr:{write['write_id']}", "description": "wrong offset"}]})
        self.assertEqual(invalidate_function_virtual_artifacts(self.connection, [writer],
            view_name="micro_flow")["vptr_writes"], 1)
        with self.assertRaisesRegex(ValueError, "stale"):
            add_seed(self.connection, {"node": {"kind": "local", "function": writer, "local_index": 0},
                "constraint": {"kind": "type", "type_name": "stale_t", "offset": 0}, "basis": "hypothesis",
                "evidence": [{"source_ref": f"vptr:{write['write_id']}", "description": "stale write"}]})
        microcode_run = build_vptr_write_index(self.connection, function_eas=[writer])
        self.connection.execute("INSERT INTO vptr_writes(write_id,run_id,function_ea,status,evidence_json,source_snapshot_hash) "
            "VALUES(?,?,?,?,?,?)", ("microcode-write", microcode_run["run_id"], sqlite_ea(writer),
                "test", "{}", microcode_run["coverage"]["source_snapshot_hash"]))
        self.connection.commit()
        with self.assertRaisesRegex(ValueError, "requires a micro_flow"):
            trace_vptr_object_flows(self.connection, write_id="microcode-write")

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
            ["nullstub", "library_function", "library_thunk", "pure_virtual_runtime_named",
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
        function = self._add_vcall_fixture()
        args = parser.parse_args(["vptr-write-build", "--db", str(self.db_path),
            "--address", hex(function), "--no-refresh"])
        self.assertEqual(_run(args)["coverage"]["selected_functions"], 1)
        args = parser.parse_args(["vptr-write-build", "--db", str(self.db_path),
            "--address", hex(function), "--no-refresh", "--view", "micro_flow"])
        self.assertEqual(_run(args)["coverage"]["source_view"], "micro_flow")
        args = parser.parse_args(["vptr-write-list", "--db", str(self.db_path),
            "--function", hex(function + 0x50)])
        self.assertEqual(_run(args)["total"], 0)
        args = parser.parse_args(["vcall-build", "--db", str(self.db_path),
            "--address", hex(function), "--no-refresh"])
        result = _run(args)
        self.assertIn("vptr_write_index", result)
        self.assertEqual(result["site_count"], 1)
        relations = parser.parse_args(["vtable-class-relations", "--db", str(self.db_path), "--limit", "0"])
        self.assertEqual(_run(relations)["total"], 0)
        build_vtable_index(self.connection, abi="itanium")
        candidate_id = self.connection.execute("SELECT candidate_id FROM vtable_candidates WHERE stale=0 LIMIT 1").fetchone()[0]
        spec_path = Path(self.temporary.name) / "vtable-type-plan.json"
        spec_path.write_text(json.dumps({"candidate_id": candidate_id,
            "type_definition": {"name": "Demo", "declaration": "struct Demo { void *vptr; };"},
            "assignments": []}), encoding="utf-8")
        preview_args = parser.parse_args(["vtable-type-preview", "--db", str(self.db_path), "--spec", str(spec_path)])
        preview = _run(preview_args)
        self.assertTrue(preview["preview_only"])
        apply_args = parser.parse_args(["vtable-type-apply", "--db", str(self.db_path), "--spec", str(spec_path),
            "--preview-id", preview["preview_id"], "--revision-token", preview["revision_token"]])
        self.assertEqual(apply_args.command, "vtable-type-apply")


if __name__ == "__main__":
    unittest.main()

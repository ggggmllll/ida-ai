from __future__ import annotations

import unittest

from ida_ai.microcode_relations import build_relations


def _reg(value_number: int) -> dict:
    return {"kind": "register", "register": 1, "value_number": value_number, "size": 8}


def _insn(block: int, ordinal: int, *, left=None, dest=None) -> dict:
    return {"block_serial": block, "ordinal": ordinal, "ea": 0x1000 + block * 0x100 + ordinal * 4,
            "opcode": "mov", "l": left or {"kind": "empty"}, "r": {"kind": "empty"},
            "d": dest or {"kind": "empty"}}


class MicrocodeRelationsTests(unittest.TestCase):
    def test_cfg_and_same_block_value_number_evidence(self):
        instructions = [
            _insn(0, 0, left={"kind": "number", "value": 3}, dest=_reg(11)),
            _insn(0, 1, left=_reg(11), dest=_reg(12)),
            _insn(1, 0, left=_reg(11)),
        ]
        blocks = [
            {"serial": 0, "predecessors": [], "successors": [1], "instruction_count": 2},
            {"serial": 1, "predecessors": [0], "successors": [], "instruction_count": 1},
        ]
        result = build_relations(instructions, blocks)
        self.assertTrue(result["cfg"]["complete"])
        self.assertEqual(result["cfg"]["edges"], [{"source": 0, "target": 1}])
        self.assertEqual(result["def_use"]["definition_count"], 2)
        self.assertEqual(result["def_use"]["use_count"], 2)
        self.assertFalse(result["def_use"]["cross_block_reaching_definitions"])

    def test_missing_cfg_and_truncated_operand_are_explicit(self):
        result = build_relations(
            [_insn(0, 0, left={"kind": "nested", "truncated": True})],
            [{"serial": 0, "predecessors": None, "successors": []}],
        )
        self.assertFalse(result["cfg"]["complete"])
        self.assertFalse(result["def_use"]["complete_for_exported_register_value_numbers"])
        self.assertTrue(result["truncated"])

    def test_only_direct_register_destination_is_a_definition(self):
        nested_destination = {"kind": "nested", "value_number": 11,
            "instruction": {"opcode": "add", "l": _reg(1), "r": _reg(2), "d": _reg(11)}}
        result = build_relations([_insn(0, 0, dest=nested_destination)],
            [{"serial": 0, "predecessors": [], "successors": []}])
        self.assertEqual(result["def_use"]["definition_count"], 0)


if __name__ == "__main__":
    unittest.main()

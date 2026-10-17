from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, sqlite_ea
from ida_ai.type_features import normalize_spec, scan_type_features


def reg(index=1, size=8):
    return {"kind": "register", "register": index, "size": size}


def num(value, size=8):
    return {"kind": "number", "value": value, "size": size}


def ins(opcode, l=None, r=None, d=None, ea=0x1004):
    return {"opcode": opcode, "l": l or {}, "r": r or {}, "d": d or {}, "ea": ea, "text": opcode}


def nested(instruction):
    return {"kind": "nested", "instruction": instruction, "size": 8}


def load(width=1, address=None):
    return ins("ldx", reg(848, 2), address or reg(), {"kind": "empty", "size": width})


class TypeFeatureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db_path = Path(temporary.name) / "analysis.sqlite"
        self.connection = connect(self.db_path)
        self.addCleanup(self.connection.close)
        self.connection.executemany(
            "INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
            [(0x1000, 0x1100, "alpha", 256), (0x2000, 0x2100, "beta", 256)])

    def add(self, instruction, ordinal=0, block=0, function=0x1000):
        self.connection.execute(
            "INSERT OR REPLACE INTO microcode(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at) "
            "VALUES(?, 'MMAT_GLBOPT3','test','ok',1,'hash','now')", (sqlite_ea(function),))
        self.connection.execute(
            "INSERT INTO micro_instructions VALUES(?,?,?,?,?,?,?,?,?)",
            (sqlite_ea(function), block, ordinal, sqlite_ea(instruction["ea"]), instruction["opcode"],
             instruction["text"], *(json.dumps(instruction[key]) for key in ("l", "r", "d"))))
        self.connection.commit()

    def scan(self, features=None, **kwargs):
        spec = {"features": features or [{"kind": "memory_access", "width": 1}], "min_score": 1}
        return scan_type_features(self.connection, spec, **kwargs)

    def test_nested_load_width_and_location(self):
        self.add(ins("add", reg(), nested(ins("xdu", nested(load()), d=reg())), reg()))
        result = self.scan()
        self.assertEqual(result["candidate_count"], 1)
        match = result["matches"][0]
        self.assertEqual(match["opcode"], "ldx")
        self.assertNotIn("..", match["operand_path"])
        self.assertEqual(match["address"], "0x1004")
        self.assertEqual(self.scan([{"kind": "memory_access", "width": 8}])["candidate_count"], 0)

    def test_offset_uses_address_not_stored_value(self):
        address = nested(ins("add", reg(), num((1 << 64) - 4), reg()))
        self.add(ins("stx", num(123, 4), reg(848, 2), address))
        self.assertEqual(self.scan([{"kind": "memory_access", "direction": "write", "offset": -4,
                                     "width": 4}])["candidate_count"], 1)
        self.assertEqual(self.scan([{"kind": "memory_access", "offset": 123}])["candidate_count"], 0)

    def test_access_profile_preserves_mixed_widths_hidden_by_exact_width_filter(self):
        def at_offset(width, opcode, ea):
            address = nested(ins("add", reg(9), num(0x68), reg(), ea=ea))
            if opcode == "ldx":
                return ins(opcode, reg(848, 2), address, {"kind": "empty", "size": width}, ea=ea)
            return ins(opcode, num(0, width), reg(848, 2), address, ea=ea)

        self.add(at_offset(4, "ldx", 0x1004), ordinal=0)
        self.add(at_offset(8, "stx", 0x1008), ordinal=1)
        result = self.scan([{"kind": "memory_access", "direction": "read", "width": 4,
                             "offset": 0x68}])

        # The requested width filters the candidate location, but must not erase
        # contrary-width evidence at the same requested offset.
        self.assertEqual(result["candidate_count"], 1)
        profile = result["access_profiles"]["profiles"][0]
        self.assertEqual(profile["offset"], 0x68)
        self.assertTrue(profile["mixed_width"])
        self.assertEqual(profile["observed_widths"], [4, 8])
        self.assertEqual([(item["width"], item["count"], item["read_count"], item["write_count"])
                          for item in profile["width_counts"]], [(4, 1, 1, 0), (8, 1, 0, 1)])
        self.assertEqual(profile["by_function"][0]["observed_widths"], [4, 8])
        self.assertEqual([item["address"] for item in profile["width_counts"][1]["sample_locations"]],
                         ["0x1008"])
        self.assertIn("not proven", result["access_profiles"]["grouping"])

    def test_access_profile_separates_same_offset_across_function_scopes(self):
        address = nested(ins("add", reg(9), num(0x68), reg()))
        self.add(ins("ldx", reg(848, 2), address, {"kind": "empty", "size": 4}, ea=0x1004))
        self.add(ins("ldx", reg(848, 2), address, {"kind": "empty", "size": 8}, ea=0x2004),
                 function=0x2000)
        result = self.scan([{"kind": "memory_access", "offset": 0x68}],
                           function_eas=[0x1000, 0x2000])
        profile = result["access_profiles"]["profiles"][0]
        self.assertTrue(profile["mixed_width"])
        self.assertEqual([item["observed_widths"] for item in profile["by_function"]], [[4], [8]])

    def test_weighted_partial_unknown_and_conflict(self):
        self.add(load(address=nested(ins("mul", reg(), num(3), reg()))))
        result = self.scan([{"kind": "memory_access", "width": 1, "weight": 3},
                            {"kind": "memory_access", "offset": 4},
                            {"kind": "opcode", "value": "stx"}], min_score=0.5)
        match = result["matches"][0]
        self.assertEqual(match["score"], 0.6)
        self.assertEqual(len(match["missing"]), 1)
        self.assertEqual(len(match["conflicts"]), 1)
        self.assertFalse(match["compatible"])
        self.assertEqual(match["match_kind"], "partial")

    def test_operand_constraints_must_match_same_operand(self):
        self.add(ins("add", reg(1, 8), reg(2, 4), reg(3, 8)))
        self.assertEqual(self.scan([{"kind": "operand", "register": 1, "width": 4}])["candidate_count"], 0)
        self.assertEqual(self.scan([{"kind": "operand", "register": 2, "width": 4}])["candidate_count"], 1)

    def test_nested_dereference_is_syntactic(self):
        self.add(load(8, nested(load(8))))
        result = self.scan([{"kind": "dereference", "depth": 2}])
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["matches"][0]["fact"]["deref_depth"], 2)

    def test_call_argument_and_badaddr_fallback(self):
        self.add(ins("call", {"kind": "global", "address": 0x5000, "size": 8},
                     d={"kind": "arglist", "callee": (1 << 64) - 1, "arguments": [reg()]}))
        self.assertEqual(self.scan([{"kind": "call", "callee": "0x5000", "arg_index": 0}])["candidate_count"], 1)
        self.assertEqual(self.scan([{"kind": "call", "arg_index": 1}])["candidate_count"], 0)

    def test_callee_and_argument_refer_to_same_call(self):
        first = ins("call", {"kind": "global", "address": 0x5000},
                    d={"kind": "arglist", "arguments": []})
        second = ins("call", {"kind": "global", "address": 0x6000},
                     d={"kind": "arglist", "arguments": [reg()]})
        self.add(ins("add", nested(first), nested(second), reg()))
        self.assertEqual(self.scan([{"kind": "call", "callee": "0x5000", "arg_index": 0}])["candidate_count"], 0)
        self.assertGreater(self.scan([{"kind": "call", "callee": "0x6000", "arg_index": 0}])["candidate_count"], 0)

    def test_sequence_finds_best_ordered_combination_and_respects_window(self):
        for ordinal, instruction in enumerate([ins("mov"), ins("and", reg(), num(1)),
                                                ins("ret"), ins("and", reg(), num(2))]):
            self.add(instruction, ordinal)
        spec = {"sequence": [{"kind": "opcode", "value": "mov"},
                              {"constraints": [{"kind": "opcode", "value": "and"},
                                               {"kind": "constant", "value": 2}]},
                              {"kind": "return", "weight": 2}], "window": 4, "min_score": 0.75}
        # Greedy picks the later and (2/2), losing ret; optimal picks earlier and (1/2) + ret.
        result = scan_type_features(self.connection, spec)
        self.assertEqual(result["matches"][0]["score"], 0.8)
        self.assertEqual([e["ordinal"] for e in result["matches"][0]["sequence_evidence"]], [0, 1, 2])
        spec["window"] = 2
        self.assertEqual(scan_type_features(self.connection, spec)["candidate_count"], 0)

    def test_sequence_never_crosses_block_or_function(self):
        self.add(ins("mov"))
        self.add(ins("ret"), block=1)
        self.add(ins("ret"), function=0x2000)
        result = scan_type_features(self.connection, {"sequence": [{"kind": "opcode", "value": "mov"},
                                                                   {"kind": "return"}], "min_score": 1})
        self.assertEqual(result["candidate_count"], 0)

    def test_coverage_limit_and_scope(self):
        self.add(load())
        self.add(load(), ordinal=1)
        result = self.scan(function_eas=[0x1000, 0x2000], limit=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total_candidates"], 2)
        self.assertEqual(result["coverage"]["missing_functions"], [0x2000])
        self.assertEqual(self.scan(function_eas=[])["candidate_count"], 0)

    def test_invalid_specs(self):
        for spec in [{}, {"features": []}, {"features": [{"kind": "bad"}]},
                     {"features": [{"kind": "operand", "width": True}]},
                     {"features": [{"kind": "constant", "value": 1.5}]},
                     {"features": [{"kind": "return", "typo": 1}]},
                     {"features": [{"kind": "return", "weight": float("nan")}]},
                     {"features": [{"kind": "return", "weight": 1e308}, {"kind": "return", "weight": 1e308}]},
                     {"features": [{"kind": "operand", "object": []}]},
                     {"features": [{"kind": "extension", "extension": []}]},
                     {"features": [{"kind": "return"}], "min_score": float("nan")},
                     {"features": [{"kind": "return"}], "window": 0}]:
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                normalize_spec(spec)

    def test_cli_refresh_selectors_and_offline(self):
        self.add(load())
        spec = self.db_path.with_suffix(".json")
        spec.write_text(json.dumps({"features": [{"kind": "memory_access", "width": 1}]}), encoding="utf-8")
        for selector in [["--all"], ["--address", "0x1004"], ["--range", "0x1000", "0x1100"], ["--name", "alpha"]]:
            args = _parser().parse_args(["type-scan", "--db", str(self.db_path), "--spec", str(spec), *selector])
            with patch("ida_ai.cli.run_ida", return_value={"statuses": {"ok": 1}}) as run:
                result = _run(args)
                self.assertTrue(result["scope"]["refreshed"])
                self.assertEqual(run.call_args.kwargs["view"], "microcode")
                self.assertIn(0x1000, run.call_args.kwargs["addresses"])
            args.no_refresh = True
            with patch("ida_ai.cli.run_ida") as run:
                self.assertEqual(_run(args)["candidate_count"], 1)
                run.assert_not_called()

    def test_high_address(self):
        high = 0xFF00000000000040
        self.connection.execute("INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
                                (sqlite_ea(high), sqlite_ea(high + 32), "high", 32))
        self.add(ins("ret", ea=high), function=high)
        result = self.scan([{"kind": "return"}], function_eas=[high])
        self.assertEqual(result["matches"][0]["ea"], high)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ida_ai.cli import _parser, _run
from ida_ai.db import connect, sqlite_ea
from ida_ai.jobs import create_job, show_job
from ida_ai.propagation import (
    _apply_transform,
    _snapshot_hash,
    accept_propagation,
    add_edge,
    add_seed,
    preview_seed,
    show_node,
)


def _local(index: int, value_number: int | None = None) -> dict:
    result = {"kind": "local", "local_index": index, "local_offset": 0, "size": 8, "text": f"v{index}"}
    if value_number is not None:
        result["value_number"] = value_number
    return result


def _instruction(function_ea: int, ordinal: int, opcode: str, left=None, right=None, destination=None) -> tuple:
    return (sqlite_ea(function_ea), 0, ordinal, sqlite_ea(function_ea + ordinal * 4), opcode, opcode,
            json.dumps(left or {}), json.dumps(right or {}), json.dumps(destination or {}))


class PropagationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ida-ai-propagation-")
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "analysis.sqlite"
        self.connection = connect(self.db_path)
        self.addCleanup(self.connection.close)
        self._add_function(0x1000, args=[0], returned=1, instructions=[
            _instruction(0x1000, 1, "mov", _local(0, 1), destination=_local(1, 2)),
            _instruction(0x1000, 2, "call", {"kind": "global", "address": 0x2000, "size": 8},
                         destination={"kind": "arglist", "callee": 0x2000, "arguments": [_local(1, 2)]}),
        ])
        self._add_function(0x2000, args=[0], returned=1, instructions=[
            _instruction(0x2000, 1, "mov", _local(0, 3), destination=_local(1, 4)),
        ])
        self.connection.commit()

    def _add_function(self, ea: int, *, args: list[int], returned: int, instructions: list[tuple]) -> None:
        locals_list = sorted(set(args + [returned]))
        self.connection.execute("INSERT INTO functions(start_ea,end_ea,name,size) VALUES(?,?,?,?)",
                                (sqlite_ea(ea), sqlite_ea(ea + 0x100), f"f_{ea:x}", 0x100))
        arguments = [{"local_index": index, "name": f"arg{arg_index}", "size": 8}
                     for arg_index, index in enumerate(args)]
        returned_local = {"local_index": returned, "name": "result", "size": 8}
        variables = [{"local_index": index, "name": f"v{index}", "size": 8} for index in locals_list]
        self.connection.execute(
            "INSERT INTO micro_flow(function_ea,maturity,backend,status,instruction_count,content_hash,generated_at,"
            "arguments_json,return_json,locals_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (sqlite_ea(ea), "MMAT_LVARS", "test", "ok", len(instructions), f"hash-{ea:x}", "now",
             json.dumps(arguments), json.dumps(returned_local), json.dumps(variables)),
        )
        self.connection.executemany("INSERT INTO micro_flow_instructions VALUES(?,?,?,?,?,?,?,?,?)", instructions)

    def _seed(self, *, node=None, constraint=None, basis="confirmed") -> dict:
        return add_seed(self.connection, {
            "node": node or {"kind": "arg", "function": 0x1000, "arg_index": 0},
            "constraint": constraint or {"kind": "type", "type_name": "sample_t", "width": 8},
            "basis": basis,
            "evidence": [{"source_ref": "micro_flow:0x1000", "description": "fixture flow evidence"}],
        })

    def test_parameters_returns_and_reference_flow_have_complete_trace(self):
        seed = self._seed()
        result = preview_seed(self.connection, seed["seed_id"])
        targets = {proposal["node_id"] for proposal in result["proposals"]}
        self.assertIn("local:0x1000:0", targets)
        self.assertIn("arg:0x2000:0", targets)
        self.assertIn("return:0x1000", targets)
        self.assertTrue(all(proposal["trace"] for proposal in result["proposals"]))
        self.assertTrue(any(edge["family"] == "parameter" for p in result["proposals"] for edge in p["trace"]))

    def test_manual_confirmed_edge_is_preserved_and_acceptance_records_provenance(self):
        source, target = "local:0x1000:0", "global:0x9000"
        link = add_edge(self.connection, {
            "source": source, "target": target, "family": "reference", "direction": "forward",
            "confidence": "confirmed", "evidence": "analyst confirmed shared storage",
            "transform": {"operation": "identity"},
        })
        seed = self._seed(node={"node_id": source})
        result = preview_seed(self.connection, seed["seed_id"])
        proposal = next(item for item in result["proposals"] if item["node_id"] == target)
        self.assertEqual(proposal["trace"][0]["confidence"], "confirmed")
        accepted = accept_propagation(self.connection, result["run_id"], [proposal["proposal_id"]])
        self.assertEqual(accepted["accepted"][0]["node_id"], target)
        node = show_node(self.connection, target)
        constraint = next(item for item in node["constraints"] if item["constraint"].get("type_name") == "sample_t")
        self.assertEqual(constraint["provenance"]["run_id"], result["run_id"])
        self.assertTrue(any(item["edge_id"] == link["edge_id"] for item in node["edges"]))

    def test_preview_keeps_derived_edges_ephemeral_and_accepted_nodes_inspectable(self):
        seed = self._seed()
        result = preview_seed(self.connection, seed["seed_id"])
        self.assertEqual(self.connection.execute("SELECT count(*) FROM propagation_edges").fetchone()[0], 0)
        proposal = next(item for item in result["proposals"] if item["node_id"] == "local:0x1000:0")
        accept_propagation(self.connection, result["run_id"], [proposal["proposal_id"]])
        node = show_node(self.connection, "local:0x1000:0")
        self.assertIsNotNone(node["node"])
        self.assertEqual(node["node"]["source_snapshot_hash"], result["snapshot_hash"])

    def test_accept_rechecks_conflicts_added_after_preview(self):
        source, target = "local:0x1000:0", "global:0x9000"
        add_edge(self.connection, {
            "source": source, "target": target, "family": "reference", "confidence": "confirmed",
            "evidence": "analyst confirmed shared storage", "transform": {"operation": "identity"},
        })
        seed = self._seed(node={"node_id": source})
        preview = preview_seed(self.connection, seed["seed_id"])
        proposal = next(item for item in preview["proposals"] if item["node_id"] == target)
        self._seed(node={"node_id": target}, constraint={"kind": "type", "type_name": "different_t", "width": 4})
        with self.assertRaisesRegex(ValueError, "conflict.*preview again"):
            accept_propagation(self.connection, preview["run_id"], [proposal["proposal_id"]])
        accepted = self.connection.execute(
            "SELECT count(*) FROM propagation_constraints WHERE node_id=? AND source_snapshot_hash=?",
            (target, preview["snapshot_hash"]),
        ).fetchone()[0]
        self.assertEqual(accepted, 1)

    def test_hypothesis_paths_are_preview_only_and_acceptance_rejects_them(self):
        add_edge(self.connection, {
            "source": "local:0x1000:0", "target": "global:0x9000", "family": "reference",
            "confidence": "hypothesis", "evidence": "possible alias", "transform": {"operation": "identity"},
        })
        result = preview_seed(self.connection, self._seed(node={"node_id": "local:0x1000:0"})["seed_id"])
        proposal = next(item for item in result["proposals"] if item["node_id"] == "global:0x9000")
        self.assertFalse(proposal["acceptable"])
        with self.assertRaisesRegex(ValueError, "hypothesis-only"):
            accept_propagation(self.connection, result["run_id"], [proposal["proposal_id"]])

    def test_conflicting_paths_remain_alternatives_and_are_not_acceptable(self):
        source, target = "local:0x1000:0", "global:0x9000"
        for transform in ({"operation": "offset", "delta": 8}, {"operation": "offset", "delta": 16}):
            add_edge(self.connection, {
                "source": source, "target": target, "family": "reference", "confidence": "confirmed",
                "evidence": json.dumps(transform), "transform": transform,
            })
        result = preview_seed(self.connection, self._seed(node={"node_id": source})["seed_id"])
        proposals = [item for item in result["proposals"] if item["node_id"] == target and item["depth"] == 1]
        self.assertEqual(len(proposals), 2)
        self.assertTrue(all(not item["acceptable"] for item in proposals))
        self.assertTrue(any(item.get("tentative") for item in result["conflicts"]))

    def test_transformations_preserve_offset_extent_width_and_pointer_depth(self):
        base = {"kind": "usage", "width": 8, "pointer_depth": 1}
        field = _apply_transform(base, {"operation": "field_projection", "delta": 12, "extent": 4})
        self.assertEqual(field["offset"], 12)
        self.assertEqual(field["min_extent"], 4)
        truncated = _apply_transform(field, {"operation": "truncate", "width": 2})
        self.assertEqual(truncated["width"], 2)
        self.assertTrue(truncated["lossy"])
        self.assertEqual(_apply_transform(base, {"operation": "pointer_depth", "delta": -1})["pointer_depth"], 0)

    def test_snapshot_change_invalidates_seed_and_preview(self):
        seed = self._seed()
        run = preview_seed(self.connection, seed["seed_id"])
        self.connection.execute("UPDATE micro_flow SET content_hash='changed' WHERE function_ea=?", (sqlite_ea(0x1000),))
        self.connection.commit()
        self.assertNotEqual(_snapshot_hash(self.connection), run["snapshot_hash"])
        with self.assertRaisesRegex(ValueError, "seed is stale"):
            preview_seed(self.connection, seed["seed_id"])
        with self.assertRaisesRegex(ValueError, "preview is stale"):
            accept_propagation(self.connection, run["run_id"], [run["proposals"][0]["proposal_id"]])

    def test_propagation_cycle_and_budgets_terminate(self):
        result = preview_seed(self.connection, self._seed()["seed_id"], max_hops=2, max_nodes=2, max_edges=3)
        self.assertLessEqual(result["limits"]["visited_nodes"], 3)
        self.assertLessEqual(result["limits"]["expanded_edges"], 4)
        self.assertTrue(any(result["limits"]["truncated"].values()))

    def test_indirect_call_is_reported_as_unresolved(self):
        call = _instruction(0x1000, 3, "icall", _local(0, 5), destination={
            "kind": "arglist", "callee": (1 << 64) - 1, "arguments": [_local(0, 5)]
        })
        self.connection.execute("INSERT INTO micro_flow_instructions VALUES(?,?,?,?,?,?,?,?,?)", call)
        self.connection.execute("UPDATE micro_flow SET instruction_count=3 WHERE function_ea=?", (sqlite_ea(0x1000),))
        self.connection.commit()
        result = preview_seed(self.connection, self._seed()["seed_id"])
        self.assertTrue(any("unresolved call" in item["reason"] for item in result["unresolved"]))

    def test_indirect_calls_outside_reached_functions_are_not_reported(self):
        self._add_function(0x3000, args=[0], returned=1, instructions=[
            _instruction(0x3000, 1, "icall", _local(0, 5), destination={
                "kind": "arglist", "callee": (1 << 64) - 1, "arguments": [_local(0, 5)]
            }),
        ])
        self.connection.commit()
        result = preview_seed(self.connection, self._seed()["seed_id"])
        self.assertFalse(any(item.get("function_ea") == 0x3000 for item in result["unresolved"]))

    def test_cli_seed_preview_accept_and_node(self):
        spec = Path(self.temp.name) / "seed.json"
        spec.write_text(json.dumps({
            "node": {"kind": "arg", "function": "0x1000", "arg_index": 0},
            "constraint": {"kind": "type", "type_name": "sample_t", "width": 8},
            "basis": "confirmed", "evidence": [{"source_ref": "micro_flow:0x1000", "description": "fixture"}],
        }), encoding="utf-8")
        parser = _parser()
        args = parser.parse_args(["type-propagate", "seed", "--db", str(self.db_path), "--spec", str(spec), "--no-refresh"])
        seed = _run(args)
        args = parser.parse_args(["type-propagate", "preview", "--db", str(self.db_path), "--seed-id", seed["seed_id"]])
        preview = _run(args)
        self.assertTrue(preview["proposals"])
        proposal = preview["proposals"][0]
        args = parser.parse_args(["type-propagate", "accept", "--db", str(self.db_path), "--run-id", preview["run_id"], "--proposal", proposal["proposal_id"]])
        accepted = _run(args)
        self.assertEqual(len(accepted["accepted"]), 1)
        args = parser.parse_args(["type-propagate", "node", "--db", str(self.db_path), "--node", proposal["node_id"]])
        self.assertIsNotNone(_run(args)["node"])

    def test_accepted_propagation_can_be_recorded_in_job_vcs(self):
        job = create_job(self.connection, title="type recovery", objective="Track recovered type constraints")
        target = "global:0x9000"
        add_edge(self.connection, {"source": "local:0x1000:0", "target": target, "family": "reference",
                                  "confidence": "confirmed", "evidence": "reviewed", "transform": {"operation": "identity"}})
        result = preview_seed(self.connection, self._seed(node={"node_id": "local:0x1000:0"})["seed_id"])
        proposal = next(item for item in result["proposals"] if item["node_id"] == target)
        accepted = accept_propagation(self.connection, result["run_id"], [proposal["proposal_id"]], job_id=job["job_id"])
        self.assertIn("job_revision", accepted)
        self.assertTrue(any(item["source_ref"] == f"propagation:{result['run_id']}"
                            for item in show_job(self.connection, job["job_id"])["evidence"]))


if __name__ == "__main__":
    unittest.main()

"""Revision-bound receiver/memory traces, kept separately from slot compatibility."""
from __future__ import annotations

import hashlib
import json
import uuid

from .db import ida_ea, sqlite_ea, utc_now
from .vcall_memory import MemoryQuery
from .virtual_tables import (
    _current_vtable_candidates, _id, _instructions_for_function, _json,
    _microcode_relations_for_function, _source_hash, _trace_vcall_pattern,
)

TRACE_VERSION = "1"


def trace_snapshot(connection):
    """Hash durable inputs, including rows rather than trusting export hash columns."""
    h = hashlib.sha256()
    for table, columns, order in (
        ("microcode", "function_ea,maturity,status,content_hash,relations_json", "function_ea"),
        ("micro_flow", "function_ea,maturity,status,content_hash,relations_json,arguments_json,return_json", "function_ea"),
        ("micro_instructions", "*", "function_ea,block_serial,ordinal"),
        ("micro_flow_instructions", "*", "function_ea,block_serial,ordinal"),
        ("micro_blocks", "*", "view_name,function_ea,block_serial"),
        ("vcall_sites", "call_id,status,callee_json,source_snapshot_hash,stale", "call_id"),
        ("vtable_slots", "*", "candidate_id,slot_index"),
    ):
        h.update(table.encode())
        for row in connection.execute(f"SELECT {columns} FROM {table} ORDER BY {order}"):
            h.update(_json(tuple(row)).encode())
            h.update(b"\n")
    h.update(_source_hash(connection, "vtable").encode())
    h.update(_json(_current_vtable_candidates(connection)).encode())
    return h.hexdigest()


def _call(connection, call_id, address):
    if (call_id is None) == (address is None):
        raise ValueError("provide exactly one of call_id or address")
    if address is not None:
        rows = connection.execute("SELECT * FROM vcall_sites WHERE call_ea=? AND stale=0",
                                  (sqlite_ea(address),)).fetchall()
        if len(rows) != 1:
            raise ValueError("call address is absent or ambiguous; use a current call-id")
        row = rows[0]
    else:
        row = connection.execute("SELECT * FROM vcall_sites WHERE call_id=? AND stale=0", (call_id,)).fetchone()
    if row is None:
        raise ValueError("current call not found; rebuild the call index")
    run = connection.execute("SELECT * FROM vcall_runs WHERE run_id=?", (row["run_id"],)).fetchone()
    if run is None:
        raise ValueError("call source run missing; rebuild the call index")
    scope = json.loads(run["scope_json"])
    if run["status"] == "stale" or _source_hash(connection, "vcall", scope["function_eas"]) != row["source_snapshot_hash"]:
        raise ValueError("call source changed; rebuild the call index")
    return row


def _bridge(connection, row):
    """Join maturities by a unique call EA + shape/argument slot, never VN/local index."""
    function = ida_ea(row["function_ea"])
    summary = connection.execute("SELECT * FROM micro_flow WHERE function_ea=?", (row["function_ea"],)).fetchone()
    if summary is None or summary["status"] != "ok":
        return {"status": "unknown", "reason": "micro_flow_missing_or_error"}, None
    original = json.loads(row["callee_json"])
    if original.get("pattern_status") != "candidate":
        return {"status": "unknown", "reason": "original_pattern_incomplete"}, None
    instructions = _instructions_for_function(connection, function, "micro_flow")
    originals = [i for i in _instructions_for_function(connection, function)
                 if i["opcode"] == "icall" and i.get("ea") == ida_ea(row["call_ea"])] if row["call_ea"] is not None else []
    if len(originals) != 1:
        return {"status": "unknown", "reason": "original_call_ea_missing_or_ambiguous"}, None
    calls = [i for i in instructions if i["opcode"] == "icall" and i.get("ea") == ida_ea(row["call_ea"])] if row["call_ea"] is not None else []
    if len(calls) != 1:
        return {"status": "unknown", "reason": "flow_call_ea_missing_or_ambiguous", "matches": len(calls)}, None
    relations = _microcode_relations_for_function(connection, function, summary, "micro_flow")
    pattern = _trace_vcall_pattern(instructions, calls[0], relations)
    if not pattern or pattern.get("pattern_status") != "candidate":
        return {"status": "unknown", "reason": "flow_pattern_incomplete_or_receiver_unbound"}, None
    original_arg = original["receiver_binding"]["matches"][0]["argument_index"]
    flow_arg = pattern["receiver_binding"]["matches"][0]["argument_index"]
    if (original["slot_offset"], original["vptr_offset"], original_arg) != (pattern["slot_offset"], pattern["vptr_offset"], flow_arg):
        return {"status": "unknown", "reason": "maturity_shape_or_argument_mismatch"}, None
    return {"status": "unique_structural_bridge", "basis": "unique_call_ea_constant_offsets_receiver_argument_index",
            "function_ea": function, "call_ea": ida_ea(row["call_ea"]), "argument_index": flow_arg,
            "glbopt3": {"block_serial": row["block_serial"], "ordinal": row["ordinal"],
                        "source_snapshot_hash": row["source_snapshot_hash"]},
            "lvars": {"block_serial": calls[0]["block_serial"], "ordinal": calls[0]["ordinal"],
                      "content_hash": summary["content_hash"]},
            "assumption": "same instruction EA and compatible exported structure denote the same call; no cross-maturity value-number equality is assumed"}, pattern


def trace_virtual_call(connection, *, call_id=None, address=None, max_hops=6, max_nodes=500,
                       max_edges=4000, max_alternatives=16, max_context=4):
    budgets = dict(max_hops=max_hops, max_nodes=max_nodes, max_edges=max_edges,
                   max_alternatives=max_alternatives, max_context=max_context)
    # Validate even when a pattern/bridge is missing.
    MemoryQuery(connection, **budgets)
    row = _call(connection, call_id, address)
    snapshot = trace_snapshot(connection)
    scope = {"call_id": row["call_id"], **budgets}
    run_id = _id("VTRACE", {"snapshot": snapshot, "scope": scope, "version": TRACE_VERSION})
    cached = connection.execute("SELECT result_json FROM vcall_trace_runs WHERE source_snapshot_hash=? AND scope_json=? AND version=? AND status!='stale' ORDER BY created_at DESC LIMIT 1",
                                (snapshot, _json(scope), TRACE_VERSION)).fetchone()
    if cached:
        return {**json.loads(cached[0]), "cached": True}
    if connection.execute("SELECT 1 FROM vcall_trace_runs WHERE run_id=?", (run_id,)).fetchone():
        # Explicit refresh can stale unchanged content. Preserve that historical run.
        run_id = _id("VTRACE", {"base": run_id, "refresh": uuid.uuid4().hex})
    function = ida_ea(row["function_ea"])
    pattern = json.loads(row["callee_json"])
    bridge, flow_pattern = _bridge(connection, row)
    local = (MemoryQuery(connection, **budgets).result(function, pattern)
             if pattern.get("pattern_status") == "candidate" else {"memory_status": "unknown", "leaves": [],
                 "address_points": [], "reason": "call_pattern_incomplete", "truncated": False})
    flow = (MemoryQuery(connection, view="micro_flow", **budgets).result(function, flow_pattern)
            if flow_pattern else None)
    memory = flow or local
    current = _current_vtable_candidates(connection)
    by_address = {}
    for table in current:
        by_address.setdefault(ida_ea(table["address_point"]), []).append(table["candidate_id"])
    targets = []
    coverage_frontier = []
    for ap in memory["address_points"]:
        matched = False
        for candidate in by_address.get(ap, []):
            for slot in connection.execute("SELECT * FROM vtable_slots WHERE candidate_id=? AND byte_offset=? AND stale=0",
                                            (candidate, row["slot_offset"])):
                matched = True
                targets.append({"candidate_id": candidate, "address_point": ap, "slot_index": slot["slot_index"],
                    "target_ea": ida_ea(slot["target_ea"]) if slot["target_ea"] is not None else None,
                    "thunk_chain": json.loads(slot["thunk_chain_json"]),
                    "adjustment": json.loads(slot["adjustment_json"]),
                    "entry_classification": slot["entry_classification"],
                    "status": "memory_supported_candidate"})
        if not matched:
            coverage_frontier.append({"code": "address_point_or_slot_not_indexed", "address_point": ap})
    alternatives = {(t["candidate_id"], t["target_ea"]) for t in targets}
    status = "candidate_set" if targets else "unknown"
    if (len(alternatives) == 1 and memory["memory_status"] == "complete_within_model"
            and not coverage_frontier and all(t["target_ea"] is not None for t in targets)):
        status = "unique_under_assumptions"
    result = {"run_id": run_id, "call_id": row["call_id"], "cached": False, "version": TRACE_VERSION,
              "source_snapshot_hash": snapshot, "scope": scope, "bridge": bridge,
              "local_memory": local, "object_memory": flow, "targets": targets,
              "index_frontier": coverage_frontier,
              "resolution_status": status, "completeness": "partial",
              "runtime_reachability_proven": False,
              "next_action": "inspect the first frontier or independently validate ABI/object lifetime; do not reuse inferred IDA types as proof",
              "truncated": bool(local.get("truncated") or (flow or {}).get("truncated"))}
    with connection:
        connection.execute("UPDATE vcall_trace_runs SET status='stale' WHERE call_id=? AND source_snapshot_hash<>?",
                           (row["call_id"], snapshot))
        connection.execute("INSERT INTO vcall_trace_runs(run_id,call_id,source_snapshot_hash,scope_json,version,status,result_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                           (run_id, row["call_id"], snapshot, _json(scope), TRACE_VERSION, "partial", _json(result), utc_now()))
    return result


def show_trace(connection, run_id, *, include_stale=False):
    row = connection.execute("SELECT * FROM vcall_trace_runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        raise ValueError("virtual-call trace not found")
    stale = row["status"] == "stale" or row["source_snapshot_hash"] != trace_snapshot(connection)
    if stale and not include_stale:
        raise ValueError("virtual-call trace is stale; rerun vcall-trace or request historical output")
    return {**json.loads(row["result_json"]), "stale": stale}

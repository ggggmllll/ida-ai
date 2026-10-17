"""Bounded, provenance-preserving propagation over exported Hex-Rays flow.

The graph is deliberately conservative.  It uses value numbers, local/argument
locations and direct call argument lists as observations; an IDA xref alone is
never treated as an alias.  Preview runs are durable and can be accepted only
while the analysis snapshot that produced them is unchanged.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections import defaultdict, deque
from typing import Any

from .db import get_metadata, ida_ea, sqlite_ea, utc_now
from .jobs import revise_job


FAMILIES = {"reference", "parameter", "return"}
BADADDR = (1 << 64) - 1
DEFAULTS = {"max_hops": 6, "max_nodes": 500, "max_edges": 2000, "max_alternatives": 8}


def _integer(value: Any, name: str, *, nonnegative: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{name} must be an integer")
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if nonnegative and parsed < 0:
        raise ValueError(f"{name} must be non-negative")
    return parsed


def _node(node: Any) -> dict[str, Any]:
    if isinstance(node, str):
        return {"node_id": node}
    if not isinstance(node, dict):
        raise ValueError("seed.node must be an object or node_id string")
    unknown = set(node) - {"node_id", "kind", "function", "value_number", "address", "local_index", "arg_index"}
    if unknown:
        raise ValueError(f"unsupported seed node fields: {', '.join(sorted(unknown))}")
    if "node_id" in node:
        value = str(node["node_id"]).strip()
        if not value:
            raise ValueError("seed node_id must not be empty")
        return {"node_id": value}
    kind = str(node.get("kind", "")).strip().lower()
    kind = {"parameter": "arg", "function_argument": "arg", "function_return": "return"}.get(kind, kind)
    if kind not in {"value", "global", "local", "stack", "arg", "return"}:
        raise ValueError("seed node kind must be value, global, local, stack, arg, or return")
    result: dict[str, Any] = {"kind": kind}
    if kind in {"value", "local", "stack", "arg", "return"}:
        if "function" not in node:
            raise ValueError(f"seed {kind} node requires function")
        result["function"] = _integer(node["function"], "seed node function", nonnegative=True)
    if kind == "value":
        if "value_number" not in node:
            raise ValueError("seed value node requires value_number")
        result["value_number"] = _integer(node["value_number"], "seed value_number", nonnegative=True)
    elif kind == "global":
        if "address" not in node:
            raise ValueError("seed global node requires address")
        result["address"] = _integer(node["address"], "seed global address", nonnegative=True)
    elif kind == "local":
        if "local_index" not in node:
            raise ValueError("seed local node requires local_index")
        result["local_index"] = _integer(node["local_index"], "seed local_index", nonnegative=True)
    elif kind == "stack":
        if "address" not in node:
            raise ValueError("seed stack node requires address (frame-bottom offset)")
        result["address"] = _integer(node["address"], "seed stack offset")
    elif kind == "arg":
        if "arg_index" not in node:
            raise ValueError("seed arg node requires arg_index")
        result["arg_index"] = _integer(node["arg_index"], "seed arg_index", nonnegative=True)
    return result


def _node_id(node: dict[str, Any]) -> str:
    if "node_id" in node:
        return node["node_id"]
    kind = node["kind"]
    if kind == "global":
        return f"global:0x{node['address']:X}"
    if kind == "return":
        return f"return:0x{node['function']:X}"
    if kind == "arg":
        return f"arg:0x{node['function']:X}:{node['arg_index']}"
    if kind == "value":
        return f"value:0x{node['function']:X}:{node['value_number']}"
    if kind == "local":
        return f"local:0x{node['function']:X}:{node['local_index']}"
    if kind == "stack":
        return f"stack:0x{node['function']:X}:{node['address']}"
    raise ValueError(f"cannot construct node id for {kind}")


def _node_function(node_id: str) -> int | None:
    kind, separator, identity = node_id.partition(":")
    if not separator or kind not in {"local", "stack", "arg", "return", "value", "callarg", "callresult"}:
        return None
    function_text = identity.partition(":")[0]
    try:
        return int(function_text, 0)
    except ValueError:
        return None


def _signed_immediate(value: dict[str, Any]) -> int:
    raw = int(value["value"])
    size = int(value.get("size") or 0)
    if size > 0 and raw >= (1 << (size * 8 - 1)):
        raw -= 1 << (size * 8)
    return raw


def _constraint(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ValueError("seed.constraint must be a non-empty object")
    unknown = set(value) - {"kind", "type", "type_name", "width", "min_width", "offset", "pointer_depth",
                            "min_extent", "signed", "lossy", "view", "alternative", "evidence_id", "source_ref"}
    if unknown:
        raise ValueError(f"unsupported constraint fields: {', '.join(sorted(unknown))}")
    result = dict(value)
    result["kind"] = str(result.get("kind", "usage")).strip() or "usage"
    for key in ("width", "min_width", "pointer_depth", "min_extent", "offset"):
        if key in result:
            result[key] = _integer(result[key], f"constraint.{key}")
            if key != "offset" and result[key] < 0:
                raise ValueError(f"constraint.{key} must be non-negative")
    if "signed" in result and not isinstance(result["signed"], bool):
        raise ValueError("constraint.signed must be boolean")
    if "lossy" in result and not isinstance(result["lossy"], bool):
        raise ValueError("constraint.lossy must be boolean")
    for key in ("type", "type_name", "view", "alternative", "evidence_id", "source_ref"):
        if key in result and not isinstance(result[key], str):
            raise ValueError(f"constraint.{key} must be a string")
    return result


def normalize_seed(seed: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(seed, dict):
        raise ValueError("propagation seed must be a JSON object")
    if "seed" in seed:
        nested = seed["seed"]
        if not isinstance(nested, dict):
            raise ValueError("seed must be an object")
        merged = dict(nested)
        for key in ("max_hops", "max_nodes", "max_edges", "max_alternatives", "families", "basis", "source_seed_id"):
            if key in seed and key not in merged:
                merged[key] = seed[key]
        seed = merged
    unknown = set(seed) - {"node", "constraint", "max_hops", "max_nodes", "max_edges", "max_alternatives",
                           "families", "edges", "basis", "source_seed_id"}
    if unknown:
        raise ValueError(f"unsupported seed fields: {', '.join(sorted(unknown))}")
    if "node" not in seed or "constraint" not in seed:
        raise ValueError("propagation seed requires node and constraint")
    result = {"node": _node(seed["node"]), "constraint": _constraint(seed["constraint"])}
    for key, default in DEFAULTS.items():
        result[key] = _integer(seed.get(key, default), key, nonnegative=True)
        if result[key] == 0:
            raise ValueError(f"{key} must be positive")
    families = seed.get("families", sorted(FAMILIES))
    if not isinstance(families, list) or not families or not set(families) <= FAMILIES:
        raise ValueError("families must be a non-empty list containing reference, parameter, or return")
    result["families"] = list(dict.fromkeys(families))
    result["basis"] = seed.get("basis", "confirmed")
    if result["basis"] not in {"observed", "confirmed", "hypothesis"}:
        raise ValueError("basis must be observed, confirmed, or hypothesis")
    if "source_seed_id" in seed:
        result["source_seed_id"] = str(seed["source_seed_id"])
    edges = seed.get("edges", [])
    if not isinstance(edges, list) or len(edges) > 10000:
        raise ValueError("edges must be a list of at most 10000 explicit relationships")
    normalized_edges = []
    allowed_edge = {"edge_id", "source", "target", "family", "direction", "confidence", "transform", "evidence", "context"}
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise ValueError(f"edges[{index}] must be an object")
        extra = set(edge) - allowed_edge
        if extra:
            raise ValueError(f"unsupported edges[{index}] fields: {', '.join(sorted(extra))}")
        source = _node_id(_node(edge.get("source")))
        target = _node_id(_node(edge.get("target")))
        family = edge.get("family")
        direction = edge.get("direction", "forward")
        confidence = edge.get("confidence", "confirmed")
        if family not in FAMILIES:
            raise ValueError(f"edges[{index}].family must be reference, parameter, or return")
        if direction not in {"forward", "reverse", "both"}:
            raise ValueError(f"edges[{index}].direction must be forward, reverse, or both")
        if confidence not in {"observed", "confirmed", "hypothesis"}:
            raise ValueError(f"edges[{index}].confidence must be observed, confirmed, or hypothesis")
        transform = edge.get("transform", {"operation": "identity"})
        if not isinstance(transform, dict) or set(transform) - {"operation", "delta", "width", "signed", "extent", "steps"}:
            raise ValueError(f"edges[{index}].transform has unsupported fields")
        operation = transform.get("operation", "identity")
        if operation not in {"identity", "offset", "pointer_depth", "truncate", "extend", "field_projection", "composite"}:
            raise ValueError(f"edges[{index}].transform.operation is unsupported")
        normalized_transform = {"operation": operation}
        if operation == "composite":
            steps = transform.get("steps")
            if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
                raise ValueError(f"edges[{index}].transform composite requires 1..8 steps")
            normalized_transform["steps"] = []
            for step_index, step in enumerate(steps):
                if not isinstance(step, dict) or step.get("operation") == "composite":
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}] must be a simple transform")
                normalized_step = dict(step)
                if set(normalized_step) - {"operation", "delta", "width", "signed", "extent"}:
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}] has unsupported fields")
                step_operation = normalized_step.get("operation", "identity")
                if step_operation not in {"identity", "offset", "pointer_depth", "truncate", "extend", "field_projection"}:
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}] operation is unsupported")
                for field in ("delta", "width", "extent"):
                    if field in normalized_step:
                        normalized_step[field] = _integer(normalized_step[field], f"edges[{index}].transform.steps[{step_index}].{field}")
                if step_operation in {"offset", "pointer_depth"} and "delta" not in normalized_step:
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}] requires delta")
                if step_operation in {"truncate", "extend"} and normalized_step.get("width", 0) <= 0:
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}] requires positive width")
                if step_operation == "field_projection" and ("delta" not in normalized_step or normalized_step.get("extent", 0) <= 0):
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}] requires delta and positive extent")
                if "signed" in normalized_step and not isinstance(normalized_step["signed"], bool):
                    raise ValueError(f"edges[{index}].transform.steps[{step_index}].signed must be boolean")
                normalized_transform["steps"].append(normalized_step)
            transform = normalized_transform
        if operation != "composite":
            for key in ("delta", "width", "extent"):
                if key in transform:
                    normalized_transform[key] = _integer(transform[key], f"edges[{index}].transform.{key}")
            if operation in {"offset", "pointer_depth"} and "delta" not in normalized_transform:
                raise ValueError(f"edges[{index}] {operation} transform requires delta")
            if operation in {"truncate", "extend"} and normalized_transform.get("width", 0) <= 0:
                raise ValueError(f"edges[{index}] {operation} transform requires positive width")
            if operation == "field_projection" and ("delta" not in normalized_transform or normalized_transform.get("extent", 0) <= 0):
                raise ValueError(f"edges[{index}] field_projection requires delta and positive extent")
            if "signed" in transform:
                if not isinstance(transform["signed"], bool):
                    raise ValueError(f"edges[{index}].transform.signed must be boolean")
                normalized_transform["signed"] = transform["signed"]
        evidence = edge.get("evidence", [])
        if isinstance(evidence, str):
            evidence = [evidence]
        if not isinstance(evidence, list) or not evidence or not all(isinstance(item, str) and item.strip() for item in evidence):
            raise ValueError(f"edges[{index}].evidence must be non-empty text or a list of text")
        context = edge.get("context", {})
        if not isinstance(context, dict):
            raise ValueError(f"edges[{index}].context must be an object")
        normalized_edges.append({"edge_id": str(edge.get("edge_id", f"E{index + 1:04d}")),
                                 "source": source, "target": target, "family": family,
                                 "direction": direction, "confidence": confidence,
                                 "transform": normalized_transform, "evidence": evidence, "context": context})
    result["edges"] = normalized_edges
    result["node_id"] = _node_id(result["node"])
    return result


def _snapshot_hash(connection: sqlite3.Connection) -> str:
    # Export timestamps are deliberately excluded. Re-exporting unchanged IDA
    # observations must not invalidate a proposal; actual flow or function
    # contract changes still produce a different content snapshot.
    identity = {key: get_metadata(connection, key)
                for key in ("root_filename", "input_path", "imagebase", "bitness")}
    functions = [tuple(row) for row in connection.execute(
        "SELECT start_ea,end_ea FROM functions ORDER BY start_ea,end_ea")]
    flow = [tuple(row) for row in connection.execute(
        "SELECT function_ea,maturity,backend,status,error,decompiler_version,instruction_count,content_hash,"
        "arguments_json,return_json,locals_json,relations_json FROM micro_flow ORDER BY function_ea")]
    virtual_evidence = {
        "vptr_write_runs": [tuple(row) for row in connection.execute(
            "SELECT run_id,source_snapshot_hash,status,result_json FROM vptr_write_runs ORDER BY run_id")],
        "vptr_writes": [tuple(row) for row in connection.execute(
            "SELECT write_id,run_id,function_ea,write_ea,block_serial,ordinal,object_json,vptr_offset,address_point,"
            "candidate_id,status,evidence_json,source_snapshot_hash,stale FROM vptr_writes ORDER BY write_id")],
    }
    encoded = json.dumps({"identity": identity, "functions": functions, "micro_flow": flow,
                          "virtual_evidence": virtual_evidence},
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _operand_walk(value: Any, path: str = ""):
    if not isinstance(value, dict):
        return
    yield path, value
    nested = value.get("instruction")
    if isinstance(nested, dict):
        for key in ("l", "r", "d"):
            yield from _operand_walk(nested.get(key), f"{path}.instruction.{key}" if path else f"instruction.{key}")
    nested = value.get("operand")
    if isinstance(nested, dict):
        yield from _operand_walk(nested, f"{path}.operand" if path else "operand")
    for index, argument in enumerate(value.get("arguments", []) or []):
        yield from _operand_walk(argument, f"{path}.arguments[{index}]" if path else f"arguments[{index}]")
    for key in ("low", "high"):
        yield from _operand_walk(value.get(key), f"{path}.{key}" if path else key)


def _expressions(value: dict[str, Any]):
    seen = set()

    def nested_expressions(operand):
        if not isinstance(operand, dict):
            return
        nested = operand.get("instruction")
        if isinstance(nested, dict):
            if id(nested) not in seen:
                seen.add(id(nested))
                yield nested
                yield from _expressions(nested)
            return
        for key in ("operand", "low", "high"):
            yield from nested_expressions(operand.get(key))
        for argument in operand.get("arguments", []) or []:
            yield from nested_expressions(argument)

    yield value
    for role in ("l", "r", "d"):
        yield from nested_expressions(value.get(role, {}))


def _ref(item: dict[str, Any], function_ea: int) -> dict[str, Any] | None:
    kind = item.get("kind")
    if kind == "global" and item.get("address") is not None:
        return {"node_id": f"global:0x{int(item['address']):X}", "kind": "global", "text": item.get("text", "")}
    if kind == "stack" and item.get("stack_offset") is not None:
        return {"node_id": f"stack:0x{function_ea:X}:{int(item['stack_offset'])}", "kind": "stack",
                "text": item.get("text", "")}
    if kind == "local" and item.get("local_index") is not None:
        return {"node_id": f"local:0x{function_ea:X}:{int(item['local_index'])}", "kind": "local",
                "local_index": int(item["local_index"]), "text": item.get("text", "")}
    if item.get("value_number") is not None:
        return {"node_id": f"value:0x{function_ea:X}:{int(item['value_number'])}", "kind": "value",
                "value_number": int(item["value_number"]), "text": item.get("text", "")}
    return None


def _refs(value: dict[str, Any], function_ea: int) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    item = value
    if item.get("kind") == "nested" and isinstance(item.get("instruction"), dict):
        nested = item["instruction"]
        if nested.get("opcode") in {"call", "icall"} and nested.get("ea") is not None:
            return [{"node_id": f"callresult:0x{function_ea:X}:0x{int(nested['ea']):X}",
                     "kind": "callresult", "path": "root", "size": value.get("size"),
                     "pointer_delta": 0}]
        if nested.get("opcode") in {"add", "sub"}:
            left, right = nested.get("l", {}), nested.get("r", {})
            if right.get("kind") == "number" and right.get("value") is not None:
                offset = _signed_immediate(right)
                offset = -offset if nested.get("opcode") == "sub" else offset
                refs = _refs(left, function_ea)
                for ref in refs:
                    ref["offset"] = int(ref.get("offset", 0)) + offset
                return refs
            if nested.get("opcode") == "add" and left.get("kind") == "number" and left.get("value") is not None:
                refs = _refs(right, function_ea)
                for ref in refs:
                    ref["offset"] = int(ref.get("offset", 0)) + _signed_immediate(left)
                return refs
            refs = _refs(left, function_ea)
            for ref in refs:
                ref["offset_uncertain"] = True
            return refs
        return []
    pointer_delta = 0
    if item.get("kind") == "address":
        result = _refs(item.get("operand", {}), function_ea)
        for ref in result:
            ref["pointer_delta"] = int(ref.get("pointer_delta", 0)) + 1
            ref["size"] = value.get("size")
        return result
    result = []
    ref = _ref(item, function_ea)
    if ref is not None:
        ref["path"] = "root"
        ref["size"] = value.get("size")
        ref["pointer_delta"] = pointer_delta
        ref["offset"] = 0
        result.append(ref)
    if item.get("value_number") is not None and (ref is None or ref.get("kind") != "value"):
        value_ref = {"node_id": f"value:0x{function_ea:X}:{int(item['value_number'])}", "kind": "value",
                     "value_number": int(item["value_number"]), "path": "root", "size": value.get("size"),
                     "pointer_delta": pointer_delta, "offset": 0}
        result.append(value_ref)
    return result


def _edge(edges: dict[tuple, dict], source: str, target: str, family: str, transform: dict, evidence: dict,
          *, uncertain: bool = False, confidence: str | None = None) -> None:
    if source == target:
        return
    key = (source, target, family, json.dumps(transform, sort_keys=True))
    item = edges.get(key)
    if item is None:
        confidence = confidence or ("hypothesis" if uncertain else "observed")
        edges[key] = {"source": source, "target": target, "family": family, "transform": transform,
                      "uncertain": confidence == "hypothesis", "confidence": confidence,
                      "direction": "forward", "context": {}, "evidence": [evidence]}
    else:
        incoming = confidence or ("hypothesis" if uncertain else "observed")
        rank = {"hypothesis": 0, "observed": 1, "confirmed": 2}
        if rank[incoming] > rank[item["confidence"]]:
            item["confidence"] = incoming
        item["uncertain"] = item["confidence"] == "hypothesis"
        evidence_key = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        known_evidence = {json.dumps(entry, sort_keys=True, separators=(",", ":"))
                          for entry in item["evidence"]}
        if evidence_key not in known_evidence and len(item["evidence"]) < 4:
            item["evidence"].append(evidence)


def _memory_transform(ref: dict[str, Any], size: int | None, pointer_delta: int) -> tuple[dict[str, Any], bool]:
    del size  # Width is retained on the microcode evidence; it is not an extent proof.
    steps = []
    if pointer_delta:
        steps.append({"operation": "pointer_depth", "delta": pointer_delta})
    offset = int(ref.get("offset", 0))
    if offset:
        steps.append({"operation": "offset", "delta": offset})
    if not steps:
        return {"operation": "identity"}, False
    return (steps[0] if len(steps) == 1 else {"operation": "composite", "steps": steps}), bool(offset)


def _reference_transform(pointer_delta: int = 0, offset: int = 0) -> dict[str, Any]:
    steps = []
    if pointer_delta:
        steps.append({"operation": "pointer_depth", "delta": int(pointer_delta)})
    if offset:
        steps.append({"operation": "offset", "delta": int(offset)})
    if not steps:
        return {"operation": "identity"}
    return steps[0] if len(steps) == 1 else {"operation": "composite", "steps": steps}


def _callee(expression: dict[str, Any]) -> int | None:
    for _, item in _operand_walk(expression.get("d", {})):
        if item.get("kind") == "arglist":
            value = item.get("callee")
            if value is not None and value != BADADDR:
                return int(value)
    left = expression.get("l", {})
    if left.get("kind") == "global" and left.get("address") is not None:
        return int(left["address"])
    return None


def _graph(connection: sqlite3.Connection, *, families: set[str], snapshot_hash: str,
           function_eas: set[int] | None = None):
    edges: dict[tuple, dict] = {}
    unresolved = []
    rows = connection.execute(
        "SELECT f.function_ea,f.arguments_json,f.return_json,i.block_serial,i.ordinal,i.ea,i.opcode,i.text,"
        "i.l_json,i.r_json,i.d_json FROM micro_flow f LEFT JOIN micro_flow_instructions i "
        "ON i.function_ea=f.function_ea WHERE f.status='ok' ORDER BY i.function_ea,i.block_serial,i.ordinal"
    )
    grouped: dict[int, list[sqlite3.Row]] = defaultdict(list)
    contracts = {}
    for row in rows:
        function_ea = ida_ea(row["function_ea"])
        if function_eas is None or function_ea in function_eas:
            grouped.setdefault(function_ea, [])
            contracts[function_ea] = json.loads(row["arguments_json"] or "[]")
            if row["opcode"] is not None:
                grouped[function_ea].append(row)
    incoming_args = {}
    for function_ea, arguments in contracts.items():
        for arg_index, argument in enumerate(arguments):
            local_index = argument.get("local_index")
            if local_index is not None:
                incoming_args[(function_ea, int(local_index))] = arg_index
                arg_node = f"arg:0x{function_ea:X}:{arg_index}"
                local_node = f"local:0x{function_ea:X}:{int(local_index)}"
                if "parameter" in families:
                    _edge(edges, arg_node, local_node, "parameter", {"operation": "formal_to_local"},
                          {"function_ea": function_ea, "kind": "argument", "arg_index": arg_index})
                    _edge(edges, local_node, arg_node, "parameter", {"operation": "formal_to_local"},
                          {"function_ea": function_ea, "kind": "argument", "arg_index": arg_index})
    for function_ea, function_rows in grouped.items():
        for row in function_rows:
            instruction = {"opcode": row["opcode"], "ea": ida_ea(row["ea"]) if row["ea"] is not None else None,
                           "text": row["text"], "l": json.loads(row["l_json"]), "r": json.loads(row["r_json"]),
                           "d": json.loads(row["d_json"])}
            evidence = {"function_ea": function_ea, "block_serial": int(row["block_serial"]),
                        "ordinal": int(row["ordinal"]), "ea": instruction["ea"], "opcode": row["opcode"],
                        "text": row["text"]}
            for expression in _expressions(instruction):
                opcode = expression.get("opcode")
                destination = _refs(expression.get("d", {}), function_ea)
                sources = _refs(expression.get("l", {}), function_ea) + _refs(expression.get("r", {}), function_ea)
                if "reference" in families:
                    for role in ("l", "r", "d"):
                        same_operand = _refs(expression.get(role, {}), function_ea)
                        for left_index, left_ref in enumerate(same_operand):
                            for right_ref in same_operand[left_index + 1:]:
                                kinds = {left_ref.get("kind"), right_ref.get("kind")}
                                if "value" in kinds and kinds & {"local", "global", "stack"}:
                                    _edge(edges, left_ref["node_id"], right_ref["node_id"], "reference",
                                          {"operation": "identity"}, {**evidence, "kind": "local/value binding"})
                                    _edge(edges, right_ref["node_id"], left_ref["node_id"], "reference",
                                          {"operation": "identity"}, {**evidence, "kind": "local/value binding"})
                if opcode in {"ldx", "stx"}:
                    if "reference" in families:
                        address_operand = expression.get("r", {}) if opcode == "ldx" else expression.get("d", {})
                        data_operand = expression.get("d", {}) if opcode == "ldx" else expression.get("l", {})
                        bases = _refs(address_operand, function_ea)
                        values = _refs(data_operand, function_ea)
                        for base in bases:
                            for value in values:
                                # IDA LVARS microcode uses r as ldx's address and
                                # d as stx's address. l is the segment selector.
                                # Treat a load/store as a typed memory relation,
                                # not a value copy from/to the segment operand.
                                if base.get("kind") in {"global", "stack"}:
                                    pointer_delta = int(base.get("pointer_delta", 0))
                                else:
                                    pointer_delta = (-1 + int(base.get("pointer_delta", 0))) if opcode == "ldx" else (1 - int(base.get("pointer_delta", 0)))
                                transform = _reference_transform(pointer_delta, int(base.get("offset", 0)))
                                trace = {**evidence, "memory_operation": "read" if opcode == "ldx" else "write",
                                         "address_operand": address_operand, "data_operand": data_operand,
                                         "address_base": base, "data_value": value}
                                uncertain = bool(base.get("offset_uncertain") or base.get("offset"))
                                if opcode == "ldx":
                                    _edge(edges, base["node_id"], value["node_id"], "reference", transform, trace,
                                          uncertain=uncertain)
                                    inverse = _inverse(transform)
                                    if inverse is not None:
                                        _edge(edges, value["node_id"], base["node_id"], "reference", inverse,
                                              {**trace, "direction": "reverse read relation"}, uncertain=uncertain)
                                else:
                                    _edge(edges, value["node_id"], base["node_id"], "reference", transform, trace,
                                          uncertain=uncertain)
                                    inverse = _inverse(transform)
                                    if inverse is not None:
                                        _edge(edges, base["node_id"], value["node_id"], "reference", inverse,
                                              {**trace, "direction": "reverse write relation"}, uncertain=uncertain)
                else:
                    if opcode in {"mov", "xdu", "xds", "low", "high"}:
                        for source in sources:
                            for target in destination:
                                if "reference" not in families:
                                    continue
                                left_size, right_size = source.get("size"), target.get("size")
                                confidence = "observed" if left_size == right_size else "hypothesis"
                                if opcode in {"low", "high"}:
                                    transform = {"operation": "truncate", "width": max(1, int(target.get("size") or 0))}
                                elif opcode in {"xdu", "xds"}:
                                    transform = {"operation": "extend", "width": max(1, int(target.get("size") or 0)),
                                                 "signed": opcode == "xds"}
                                else:
                                    transform = {"operation": "identity"}
                                uncertain = confidence != "observed"
                                trace = {**evidence, "source_path": source.get("path"), "target_path": target.get("path")}
                                _edge(edges, source["node_id"], target["node_id"], "reference", transform,
                                      trace, uncertain=uncertain)
                                if opcode == "mov" and confidence == "observed":
                                    _edge(edges, target["node_id"], source["node_id"], "reference", transform,
                                          {**trace, "direction": "reverse copy"})
                    elif opcode in {"add", "sub"}:
                        immediate = expression.get("r", {})
                        if immediate.get("kind") == "number" and immediate.get("value") is not None:
                            offset = _signed_immediate(immediate)
                            offset = -offset if opcode == "sub" else offset
                            source_items = _refs(expression.get("l", {}), function_ea)
                            for source in source_items:
                                for target in destination:
                                    transform = _reference_transform(0, offset)
                                    trace = {**evidence, "source_path": source.get("path"),
                                             "target_path": target.get("path"), "address_offset": offset}
                                    _edge(edges, source["node_id"], target["node_id"], "reference", transform,
                                          trace, uncertain=True)
                for ref in destination + sources:
                    local_index = ref.get("local_index")
                    if local_index is not None and (function_ea, local_index) in incoming_args and "parameter" in families:
                        arg_node = f"arg:0x{function_ea:X}:{incoming_args[(function_ea, local_index)]}"
                        _edge(edges, arg_node, ref["node_id"], "parameter", {"operation": "formal_local"}, evidence)
                        _edge(edges, ref["node_id"], arg_node, "parameter", {"operation": "formal_local"}, evidence)
                if opcode in {"call", "icall"}:
                    callee = _callee(expression)
                    arglists = [item for _, item in _operand_walk(expression.get("d", {})) if item.get("kind") == "arglist"]
                    if not arglists and expression.get("d", {}).get("kind") == "arglist":
                        arglists = [expression["d"]]
                    if callee is not None and "return" in families:
                        call_ea = expression.get("ea") or instruction.get("ea")
                        result_node = f"callresult:0x{function_ea:X}:0x{int(call_ea or 0):X}"
                        result_operand = expression.get("d", {})
                        result_dest = _refs(result_operand, function_ea)
                        if not result_dest and expression is instruction:
                            result_dest = _refs(instruction.get("d", {}), function_ea)
                        _edge(edges, f"return:0x{callee:X}", result_node, "return", {"operation": "call_result"},
                              {**evidence, "callee": callee, "call_ea": call_ea}, uncertain=callee == function_ea)
                        _edge(edges, result_node, f"return:0x{callee:X}", "return", {"operation": "call_result"},
                              {**evidence, "callee": callee, "call_ea": call_ea}, uncertain=callee == function_ea)
                        for target in result_dest:
                            _edge(edges, result_node, target["node_id"], "reference", {"operation": "identity"},
                                  {**evidence, "callee": callee, "call_ea": call_ea, "target": target})
                            _edge(edges, target["node_id"], result_node, "reference", {"operation": "identity"},
                                  {**evidence, "callee": callee, "call_ea": call_ea, "target": target})
                    if callee is None:
                        if arglists:
                            unresolved.append({**evidence, "ea": expression.get("ea"),
                                               "reason": "indirect or unresolved call target"})
                    elif "parameter" in families:
                        for arglist in arglists:
                            for index, argument in enumerate(arglist.get("arguments", []) or []):
                                for source in _refs(argument, function_ea):
                                    call_ea = expression.get("ea") or instruction.get("ea")
                                    actual_node = f"callarg:0x{function_ea:X}:0x{int(call_ea or 0):X}:{index}"
                                    transform = _reference_transform(source.get("pointer_delta", 0), source.get("offset", 0))
                                    trace = {**evidence, "ea": call_ea, "callee": callee,
                                             "arg_index": index, "actual": source}
                                    _edge(edges, source["node_id"], actual_node, "parameter", transform, trace,
                                          uncertain=bool(source.get("pointer_delta") or source.get("offset") or source.get("offset_uncertain")))
                                    _edge(edges, actual_node, source["node_id"], "parameter", _inverse(transform), trace,
                                          uncertain=bool(source.get("pointer_delta") or source.get("offset") or source.get("offset_uncertain")))
                                    formal = f"arg:0x{callee:X}:{index}"
                                    _edge(edges, actual_node, formal, "parameter", {"operation": "identity"}, trace)
                                    _edge(edges, formal, actual_node, "parameter", {"operation": "identity"}, trace)
        if "return" in families:
            # LVARS has an explicit result variable even when MMAT_LVARS emits no ret opcode.
            return_row = connection.execute("SELECT return_json FROM micro_flow WHERE function_ea=?", (sqlite_ea(function_ea),)).fetchone()
            returned = json.loads(return_row[0] or "{}") if return_row else {}
            if returned.get("local_index") is not None:
                local_node = f"local:0x{function_ea:X}:{int(returned['local_index'])}"
                _edge(edges, local_node, f"return:0x{function_ea:X}", "return", {"operation": "result_variable"},
                      {"function_ea": function_ea, "kind": "return_variable", "local_index": returned["local_index"]})
                _edge(edges, f"return:0x{function_ea:X}", local_node, "return", {"operation": "result_variable"},
                      {"function_ea": function_ea, "kind": "return_variable", "local_index": returned["local_index"]})
    manual = connection.execute("SELECT * FROM propagation_edges WHERE source_snapshot_hash=? ORDER BY edge_id",
                                (snapshot_hash,)).fetchall()
    stale_manual = connection.execute("SELECT count(*) FROM propagation_edges WHERE source_snapshot_hash<>?",
                                      (snapshot_hash,)).fetchone()[0]
    for row in manual:
        if row["family"] not in families:
            continue
        transform = json.loads(row["transform_json"])
        evidence = {"edge_id": row["edge_id"], "sources": json.loads(row["evidence_json"]),
                    "context": json.loads(row["context_json"])}
        confidence = row["confidence"]
        if row["direction"] in {"forward", "both"}:
            source, target = row["source_node"], row["target_node"]
            _edge(edges, source, target, row["family"], transform, evidence,
                  uncertain=confidence == "hypothesis", confidence=confidence)
            key = (source, target, row["family"], json.dumps(transform, sort_keys=True))
            edges[key]["edge_id"] = row["edge_id"]
        if row["direction"] in {"reverse", "both"}:
            inverse = _inverse(transform)
            if inverse is None:
                unresolved.append({"edge_id": row["edge_id"], "source": row["target_node"],
                                   "target": row["source_node"], "reason": "transformation is not reversible"})
            else:
                source, target = row["target_node"], row["source_node"]
                _edge(edges, source, target, row["family"], inverse, evidence,
                      uncertain=confidence == "hypothesis", confidence=confidence)
                key = (source, target, row["family"], json.dumps(inverse, sort_keys=True))
                edges[key]["edge_id"] = row["edge_id"]
    return list(edges.values()), unresolved, {"functions": len(grouped), "edges": len(edges),
                                                "active_snapshot_edges": len(manual),
                                                "stale_manual_edges": stale_manual}


def _inverse(transform: dict[str, Any]) -> dict[str, Any] | None:
    operation = transform.get("operation", "identity")
    if operation == "composite":
        steps = []
        for step in reversed(transform.get("steps", [])):
            inverse = _inverse(step)
            if inverse is None:
                return None
            steps.append(inverse)
        return steps[0] if len(steps) == 1 else {"operation": "composite", "steps": steps}
    if operation in {"identity", "offset", "pointer_depth"}:
        return {**transform, "delta": -int(transform.get("delta", 0))} if operation != "identity" else dict(transform)
    return None


def _apply_transform(constraint: dict[str, Any], transform: dict[str, Any]) -> dict[str, Any]:
    if transform.get("operation") == "composite":
        result = dict(constraint)
        for step in transform.get("steps", []):
            result = _apply_transform(result, step)
        return result
    result = dict(constraint)
    operation = transform.get("operation", "identity")
    if operation in {"offset", "field_projection"}:
        result["offset"] = int(result.get("offset", 0)) + int(transform.get("delta", 0))
    if operation == "field_projection":
        result["view"] = f"subobject@{result['offset']}"
        result["min_extent"] = min(int(result.get("min_extent", transform["extent"])), transform["extent"])
    if operation == "pointer_depth":
        depth = int(result.get("pointer_depth", 0)) + int(transform["delta"])
        if depth < 0:
            raise ValueError("pointer-depth transformation would underflow")
        result["pointer_depth"] = depth
    if operation == "truncate":
        result["width"] = min(int(result.get("width", transform["width"])), transform["width"])
        if "min_width" in result:
            result["min_width"] = min(result["min_width"], transform["width"])
        result["lossy"] = True
    if operation == "extend":
        result["width"] = max(int(result.get("width", 0)), transform["width"])
        if "signed" in transform:
            result["signed"] = transform["signed"]
    if "extent" in transform and operation != "field_projection":
        result["min_extent"] = max(int(result.get("min_extent", 0)), int(transform["extent"]))
    return result


def _conflict(left: dict[str, Any], right: dict[str, Any]) -> list[dict[str, Any]]:
    if left.get("alternative") and right.get("alternative") and left["alternative"] != right["alternative"]:
        return []
    conflicts = []
    for key in set(left) & set(right):
        if key in {"min_extent", "min_width"}:
            continue
        if key != "kind" and left[key] != right[key]:
            conflicts.append({"field": key, "existing": left[key], "incoming": right[key]})
    if left.get("kind") != right.get("kind"):
        conflicts.append({"field": "kind", "existing": left.get("kind"), "incoming": right.get("kind")})
    return conflicts


def _persist_edges(connection: sqlite3.Connection, edges: list[dict[str, Any]], snapshot_hash: str) -> list[str]:
    persisted = []
    now = utc_now()
    for edge in edges:
        core = {key: edge.get(key, {} if key in {"context", "transform"} else [])
                for key in ("source", "target", "family", "direction", "confidence",
                            "transform", "evidence", "context")}
        edge_id = "E" + hashlib.sha256(json.dumps({**core, "snapshot_hash": snapshot_hash},
                                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
        for node_id in (edge["source"], edge["target"]):
            node_kind = node_id.split(":", 1)[0]
            identity = json.dumps({"node_id": node_id, "kind": node_kind}, sort_keys=True)
            connection.execute("INSERT OR IGNORE INTO propagation_nodes(node_id,kind,identity_json,source_snapshot_hash,created_at) VALUES(?,?,?,?,?)",
                               (node_id, node_kind, identity, snapshot_hash, now))
        connection.execute("INSERT OR IGNORE INTO propagation_edges(edge_id,source_node,target_node,family,direction,"
                           "confidence,transform_json,evidence_json,context_json,source_snapshot_hash,created_at) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (edge_id, edge["source"], edge["target"], edge["family"], edge.get("direction", "forward"),
                            edge.get("confidence", "hypothesis" if edge.get("uncertain") else "observed"),
                            json.dumps(edge["transform"], sort_keys=True),
                            json.dumps(edge["evidence"], sort_keys=True), json.dumps(edge.get("context", {}), sort_keys=True),
                            snapshot_hash, now))
        persisted.append(edge_id)
    connection.commit()
    return persisted


def _persist_nodes(connection: sqlite3.Connection, node_ids: set[str], snapshot_hash: str) -> None:
    now = utc_now()
    for node_id in node_ids:
        kind = node_id.split(":", 1)[0]
        identity = json.dumps({"node_id": node_id, "kind": kind}, sort_keys=True)
        connection.execute("INSERT OR IGNORE INTO propagation_nodes(node_id,kind,identity_json,source_snapshot_hash,created_at) "
                           "VALUES(?,?,?,?,?)", (node_id, kind, identity, snapshot_hash, now))


def add_node(connection: sqlite3.Connection, node_id: str, kind: str, identity: dict[str, Any] | None = None) -> dict[str, Any]:
    node_id, kind = str(node_id).strip(), str(kind).strip().lower()
    if not node_id or not kind or not isinstance(identity or {}, dict):
        raise ValueError("node requires a non-empty id and kind, with object identity")
    snapshot_hash = _snapshot_hash(connection)
    encoded = json.dumps(identity or {}, sort_keys=True)
    existing = connection.execute("SELECT kind,identity_json,source_snapshot_hash FROM propagation_nodes WHERE node_id=? AND source_snapshot_hash=?",
                                  (node_id, snapshot_hash)).fetchone()
    if existing:
        if existing["kind"] != kind or existing["identity_json"] != encoded:
            raise ValueError("node id already exists with a different immutable identity")
        return {"node_id": node_id, "kind": kind, "existing": True}
    connection.execute("INSERT INTO propagation_nodes(node_id,kind,identity_json,source_snapshot_hash,created_at) VALUES(?,?,?,?,?)",
                       (node_id, kind, encoded, snapshot_hash, utc_now()))
    connection.commit()
    return {"node_id": node_id, "kind": kind, "identity": identity or {}, "existing": False}


def add_edge(connection: sqlite3.Connection, edge: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(edge, dict):
        raise ValueError("edge must be a JSON object")
    wrapper = normalize_seed({"node": {"node_id": "__edge_validation__"}, "constraint": {"kind": "validation"},
                             "edges": [edge]})
    normalized = wrapper["edges"][0]
    snapshot_hash = _snapshot_hash(connection)
    edge_ids = _persist_edges(connection, [normalized], snapshot_hash)
    return {**normalized, "edge_id": edge_ids[0], "snapshot_hash": snapshot_hash}


def _vptr_seed_binding(
    connection: sqlite3.Connection, source_ref: str, node_id: str, constraint: dict[str, Any], basis: str,
) -> dict[str, Any]:
    table, separator, write_id = source_ref.partition(":")
    if not separator or table != "vptr" or not write_id:
        raise ValueError(f"invalid vptr evidence source_ref: {source_ref}")
    if basis != "hypothesis":
        raise ValueError("vptr evidence can only seed a hypothesis; it does not establish source-level class identity")
    row = connection.execute(
        "SELECT w.*,r.scope_json,r.source_snapshot_hash AS run_source_hash,r.status AS run_status "
        "FROM vptr_writes w JOIN vptr_write_runs r ON r.run_id=w.run_id WHERE w.write_id=?", (write_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"evidence source is absent: {source_ref}")
    scope = json.loads(row["scope_json"])
    if row["stale"] or row["run_status"] not in ("ok", "partial"):
        raise ValueError(f"evidence source is stale: {source_ref}")
    if scope.get("view_name", "microcode") != "micro_flow":
        raise ValueError("vptr seed evidence requires a micro_flow vptr-write row")
    function_eas = [int(ea) for ea in scope.get("function_eas", [])]
    from .virtual_tables import _vptr_write_node, _vptr_write_source_snapshot
    current = _vptr_write_source_snapshot(connection, function_eas, "micro_flow")
    if current != row["run_source_hash"] or current != row["source_snapshot_hash"]:
        raise ValueError(f"evidence source has changed: {source_ref}")
    candidate = connection.execute(
        "SELECT stale FROM vtable_candidates WHERE candidate_id=?", (row["candidate_id"],),
    ).fetchone()
    if candidate is None or candidate["stale"]:
        raise ValueError(f"evidence source refers to a stale table candidate: {source_ref}")
    expected_node, object_view = _vptr_write_node(row)
    if expected_node is None or expected_node != node_id:
        raise ValueError(f"vptr evidence object identity does not match seed node {node_id}")
    observed_offset = int(row["vptr_offset"] or 0)
    if int(constraint.get("offset", 0)) != observed_offset:
        raise ValueError(f"seed constraint offset must match the observed vptr subobject offset {observed_offset}")
    return {"write_id": write_id, "node_id": node_id, "function_ea": ida_ea(row["function_ea"]),
        "write_ea": ida_ea(row["write_ea"]) if row["write_ea"] is not None else None,
        "object": object_view, "vptr_offset": observed_offset,
        "address_point": ida_ea(row["address_point"]), "candidate_id": row["candidate_id"],
        "source_snapshot_hash": current, "source_view": "micro_flow"}


def add_seed(connection: sqlite3.Connection, spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError("seed specification must be a JSON object")
    unknown = set(spec) - {"node", "constraint", "basis", "evidence"}
    if unknown:
        raise ValueError(f"unsupported seed fields: {', '.join(sorted(unknown))}")
    if "node" not in spec or "constraint" not in spec:
        raise ValueError("seed requires node and constraint")
    basis = spec.get("basis", "observed")
    if basis not in {"observed", "confirmed", "hypothesis"}:
        raise ValueError("seed basis must be observed, confirmed, or hypothesis")
    node = _node(spec["node"])
    node_id = _node_id(node)
    constraint = _constraint(spec["constraint"])
    evidence = spec.get("evidence")
    if isinstance(evidence, str):
        evidence = [{"source_ref": "analyst:" + evidence, "description": evidence}]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("seed requires evidence items")
    snapshot_hash = _snapshot_hash(connection)
    normalized_evidence = []
    artifact_families = set()
    for index, item in enumerate(evidence):
        if isinstance(item, str):
            item = {"source_ref": "analyst:" + item, "description": item}
        if not isinstance(item, dict) or set(item) - {"source_ref", "description"}:
            raise ValueError(f"evidence[{index}] requires source_ref and description")
        source_ref, description = str(item.get("source_ref", "")).strip(), str(item.get("description", "")).strip()
        if not source_ref or not description:
            raise ValueError(f"evidence[{index}] requires source_ref and description")
        fingerprint = None
        table, sep, ea_text = source_ref.partition(":")
        if sep and table in {"microcode", "micro_flow", "pseudocode", "disassembly", "vptr"}:
            if table == "vptr":
                from .jobs import _artifact_fingerprint
                binding = _vptr_seed_binding(connection, source_ref, node_id, constraint, basis)
                fingerprint = _artifact_fingerprint(connection, source_ref)
                if fingerprint is None or fingerprint == hashlib.sha256(b"missing").hexdigest():
                    raise ValueError(f"evidence source is absent or stale: {source_ref}")
                artifact_families.add("vptr")
                normalized_evidence.append({"source_ref": source_ref, "description": description,
                    "fingerprint": fingerprint, "binding": binding})
                continue
            try:
                ea = _integer(ea_text, "evidence address", nonnegative=True)
            except ValueError as exc:
                raise ValueError(f"invalid evidence source_ref: {source_ref}") from exc
            row = connection.execute(f"SELECT status,content_hash FROM {table} WHERE function_ea=?", (sqlite_ea(ea),)).fetchone()
            if row is None or row["status"] != "ok" or not row["content_hash"]:
                raise ValueError(f"evidence source is absent or unsuccessful: {source_ref}")
            fingerprint = row["content_hash"]
            artifact_families.add(table)
        elif table not in {"analyst", "job", "external"}:
            raise ValueError(f"unsupported evidence source_ref: {source_ref}")
        normalized_evidence.append({"source_ref": source_ref, "description": description, "fingerprint": fingerprint})
    if basis == "observed" and not artifact_families:
        raise ValueError("observed seed requires successful IDA microcode or pseudocode evidence")
    known = connection.execute("SELECT 1 FROM propagation_nodes WHERE node_id=? AND source_snapshot_hash=?",
                               (node_id, snapshot_hash)).fetchone()
    if known is None:
        edge_nodes = connection.execute("SELECT 1 FROM propagation_edges WHERE source_snapshot_hash=? AND (source_node=? OR target_node=?)",
                                        (snapshot_hash, node_id, node_id)).fetchone()
        if edge_nodes is None:
            edges, _, _ = _graph(connection, families=FAMILIES, snapshot_hash=snapshot_hash)
            if not any(node_id in (edge["source"], edge["target"]) for edge in edges):
                raise ValueError(f"seed node is not present in current flow graph: {node_id}")
    node_kind = node.get("kind", node_id.split(":", 1)[0])
    connection.execute("INSERT OR IGNORE INTO propagation_nodes(node_id,kind,identity_json,source_snapshot_hash,created_at) "
                       "VALUES(?,?,?,?,?)", (node_id, node_kind, json.dumps(node, sort_keys=True),
                                                snapshot_hash, utc_now()))
    seed_id = uuid.uuid4().hex
    run_spec = {"kind": "seed", "node_id": node_id, "constraint": constraint,
                "basis": basis, "evidence": normalized_evidence}
    connection.execute("INSERT INTO propagation_runs(run_id,request_hash,snapshot_hash,request_json,result_json,created_at) VALUES(?,?,?,?,?,?)",
                       (seed_id, hashlib.sha256(json.dumps(run_spec, sort_keys=True).encode()).hexdigest(), snapshot_hash,
                        json.dumps(run_spec, sort_keys=True), json.dumps({"seed_id": seed_id, **run_spec}, sort_keys=True), utc_now()))
    connection.execute("INSERT INTO propagation_constraints(constraint_id,run_id,proposal_id,node_id,constraint_json,"
                       "provenance_json,source_snapshot_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
                       (seed_id, seed_id, "SEED", node_id, json.dumps(run_spec["constraint"], sort_keys=True),
                        json.dumps({"basis": basis, "evidence": normalized_evidence}, sort_keys=True), snapshot_hash, utc_now()))
    connection.commit()
    return {"seed_id": seed_id, "node_id": node_id, "basis": basis, "constraint": run_spec["constraint"],
            "snapshot_hash": snapshot_hash, "evidence": normalized_evidence}


def show_node(connection: sqlite3.Connection, node_id: str) -> dict[str, Any]:
    current_hash = _snapshot_hash(connection)
    node = connection.execute("SELECT * FROM propagation_nodes WHERE node_id=? "
                              "ORDER BY (source_snapshot_hash=?) DESC,created_at DESC LIMIT 1",
                              (node_id, current_hash)).fetchone()
    constraints = [dict(row) for row in connection.execute("SELECT * FROM propagation_constraints WHERE node_id=? ORDER BY created_at",
                                                           (node_id,))]
    edges = [dict(row) for row in connection.execute("SELECT * FROM propagation_edges WHERE source_node=? OR target_node=? ORDER BY created_at",
                                                     (node_id, node_id))]
    for row in constraints:
        row["constraint"] = json.loads(row.pop("constraint_json"))
        row["provenance"] = json.loads(row.pop("provenance_json"))
        row["stale"] = row["source_snapshot_hash"] != current_hash
    for row in edges:
        for key in ("transform_json", "evidence_json", "context_json"):
            row[key.removesuffix("_json")] = json.loads(row.pop(key))
        row["stale"] = row["source_snapshot_hash"] != current_hash
    return {"node": dict(node) if node else None, "constraints": constraints, "edges": edges,
            "snapshot_hash": current_hash}


def _stored_seed(connection: sqlite3.Connection, seed_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    row = connection.execute("SELECT c.*,r.result_json,r.snapshot_hash AS run_snapshot FROM propagation_constraints c "
                             "JOIN propagation_runs r ON r.run_id=c.run_id WHERE c.constraint_id=? AND c.proposal_id='SEED'",
                             (seed_id,)).fetchone()
    if row is None:
        raise ValueError(f"propagation seed not found: {seed_id}")
    return {"node_id": row["node_id"], "constraint": json.loads(row["constraint_json"]),
            "basis": json.loads(row["provenance_json"]).get("basis", "hypothesis"),
            "source_snapshot_hash": row["source_snapshot_hash"]}, dict(row)


def preview_seed(connection: sqlite3.Connection, seed_id: str, *, families: list[str] | None = None,
                 max_hops: int = 6, max_nodes: int = 500, max_edges: int = 2000,
                 max_alternatives: int = 8) -> dict[str, Any]:
    stored, row = _stored_seed(connection, seed_id)
    current = _snapshot_hash(connection)
    if stored["source_snapshot_hash"] != current:
        raise ValueError("seed is stale against current IDA analysis; create or reconfirm it from refreshed evidence")
    return preview_propagation(connection, {"node": {"node_id": stored["node_id"]},
                                           "constraint": stored["constraint"], "families": families or list(FAMILIES),
                                           "max_hops": max_hops, "max_nodes": max_nodes,
                                           "max_edges": max_edges, "max_alternatives": max_alternatives,
                                           "basis": stored["basis"], "source_seed_id": seed_id})


def preview_propagation(connection: sqlite3.Connection, seed: dict[str, Any], *, function_eas: list[int] | None = None) -> dict[str, Any]:
    normalized = normalize_seed(seed)
    snapshot_hash = _snapshot_hash(connection)
    explicit_edge_ids = _persist_edges(connection, normalized["edges"], snapshot_hash)
    edges, unresolved, graph_stats = _graph(connection, families=set(normalized["families"]),
                                            snapshot_hash=snapshot_hash,
                                            function_eas=set(function_eas) if function_eas is not None else None)
    # Microcode-derived relationships are a deterministic view of the current
    # snapshot. Persisting every inferred edge duplicates the source artifact,
    # grows the database on every preview, and can make the CLI response larger
    # than the proposal evidence itself. Only caller-supplied relationships
    # belong in the immutable edge table; inferred edges remain in the preview
    # trace and can be rebuilt from micro_flow at any time.
    persisted_edge_ids = explicit_edge_ids
    adjacency: dict[str, list[dict]] = defaultdict(list)
    for edge in edges:
        adjacency[edge["source"]].append(edge)
    accepted: dict[str, list[dict]] = defaultdict(list)
    stale_constraints = connection.execute("SELECT count(*) FROM propagation_constraints WHERE source_snapshot_hash<>?",
                                           (snapshot_hash,)).fetchone()[0]
    for row in connection.execute("SELECT node_id,constraint_json,provenance_json FROM propagation_constraints WHERE source_snapshot_hash=?",
                                  (snapshot_hash,)):
        accepted[row["node_id"]].append({"constraint": json.loads(row["constraint_json"]),
                                           "provenance": json.loads(row["provenance_json"])})
    queue = deque([(normalized["node_id"], normalized["constraint"], 0, [])])
    visited = {(normalized["node_id"], json.dumps(normalized["constraint"], sort_keys=True))}
    proposals_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    proposals_by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
    conflicts = []
    truncated = {"max_hops": False, "max_nodes": False, "max_edges": False, "max_alternatives": False}
    expanded_edges = 0
    visited_nodes = {normalized["node_id"]}
    while queue:
        source, current, depth, trace = queue.popleft()
        if depth >= normalized["max_hops"]:
            if adjacency.get(source):
                truncated["max_hops"] = True
            continue
        for edge in adjacency.get(source, []):
            if expanded_edges >= normalized["max_edges"]:
                truncated["max_edges"] = True
                queue.clear()
                break
            expanded_edges += 1
            target = edge["target"]
            try:
                transformed = _apply_transform(current, edge["transform"])
            except ValueError as exc:
                unresolved.append({"edge": edge, "reason": str(exc)})
                continue
            item_trace = trace + [edge]
            key = (target, json.dumps(transformed, sort_keys=True))
            if key in visited:
                existing_proposal = proposals_by_key.get(key)
                if existing_proposal is not None:
                    trace_key = json.dumps(item_trace, sort_keys=True, separators=(",", ":"))
                    known_traces = {json.dumps(item, sort_keys=True, separators=(",", ":"))
                                    for item in existing_proposal.get("alternative_traces", [])}
                    if trace_key not in known_traces and len(known_traces) < normalized["max_alternatives"]:
                        existing_proposal.setdefault("alternative_traces", []).append(item_trace)
                continue
            if target not in visited_nodes and len(visited_nodes) >= normalized["max_nodes"]:
                truncated["max_nodes"] = True
                queue.clear()
                break
            visited.add(key)
            visited_nodes.add(target)
            existing = accepted.get(target, [])
            prior_conflicts = [item for item in existing for item in _conflict(item["constraint"], transformed)]
            if prior_conflicts:
                conflicts.append({"node_id": target, "incoming": transformed, "existing": existing,
                                  "conflicts": prior_conflicts, "trace": item_trace})
                continue
            prior_proposals = proposals_by_node[target]
            incompatible = [item for item in prior_proposals
                            if _conflict(item["constraint"], transformed)]
            if len(prior_proposals) >= normalized["max_alternatives"]:
                truncated["max_alternatives"] = True
                continue
            uncertain = normalized["basis"] == "hypothesis" or any(item["uncertain"] for item in item_trace)
            proposal = {"node_id": target, "constraint": transformed, "depth": depth + 1,
                        "family": edge["family"], "uncertain": uncertain,
                        "acceptable": not uncertain and not incompatible, "trace": item_trace}
            if incompatible:
                details = [detail for item in incompatible for detail in _conflict(item["constraint"], transformed)]
                for item in incompatible:
                    item["acceptable"] = False
                    item.setdefault("conflicts", []).append({"constraint": transformed, "details": details})
                conflicts.append({"node_id": target, "incoming": transformed,
                                  "existing": [{"proposal_id": item.get("proposal_id"),
                                                "constraint": item["constraint"]} for item in incompatible],
                                  "conflicts": details,
                                  "trace": item_trace, "tentative": True})
            proposals_by_key[key] = proposal
            proposals_by_node[target].append(proposal)
            queue.append((target, transformed, depth + 1, item_trace))
    # Keep a stable compact result and assign IDs only after sorting.
    proposals = list(proposals_by_key.values())
    proposals.sort(key=lambda item: (item["depth"], item["node_id"], json.dumps(item["constraint"], sort_keys=True)))
    for index, proposal in enumerate(proposals, 1):
        proposal["proposal_id"] = f"P{index:04d}"
    proposal_ids_by_key = {(item["node_id"], json.dumps(item["constraint"], sort_keys=True)): item["proposal_id"]
                           for item in proposals}
    for conflict in conflicts:
        if conflict.get("tentative"):
            for existing in conflict.get("existing", []):
                existing["proposal_id"] = proposal_ids_by_key.get(
                    (conflict["node_id"], json.dumps(existing["constraint"], sort_keys=True)))
    _persist_nodes(connection, {normalized["node_id"], *(item["node_id"] for item in proposals)}, snapshot_hash)
    reached_functions = {_node_function(node_id) for node_id in visited_nodes}
    relevant_unresolved = [item for item in unresolved
                           if item.get("reason") != "indirect or unresolved call target"
                           or item.get("function_ea") in reached_functions]
    run_id = uuid.uuid4().hex
    request = {"seed": normalized, "function_eas": function_eas}
    request_json = json.dumps(request, sort_keys=True, separators=(",", ":"))
    result = {"run_id": run_id, "snapshot_hash": snapshot_hash, "seed": normalized,
              "proposals": proposals, "conflicts": conflicts, "unresolved": relevant_unresolved,
              "persisted_edge_ids": persisted_edge_ids, "stale_accepted_constraints": stale_constraints,
              "limits": {**{key: normalized[key] for key in DEFAULTS}, "expanded_edges": expanded_edges,
                          "visited_nodes": len(visited_nodes), "truncated": truncated},
              "graph": graph_stats,
              "meaning": "bounded derived constraints with explicit edge traces; not proof of source-level type identity"}
    connection.execute("INSERT INTO propagation_runs(run_id,request_hash,snapshot_hash,request_json,result_json,created_at) VALUES(?,?,?,?,?,?)",
                       (run_id, hashlib.sha256(request_json.encode()).hexdigest(), snapshot_hash, request_json,
                        json.dumps(result, sort_keys=True), utc_now()))
    connection.commit()
    return result


def accept_propagation(connection: sqlite3.Connection, run_id: str, proposal_ids: list[str],
                       *, job_id: int | None = None) -> dict[str, Any]:
    if not proposal_ids:
        raise ValueError("accept requires at least one proposal id")
    if any(not isinstance(item, str) or not item.strip() for item in proposal_ids):
        raise ValueError("proposal ids must be non-empty strings")
    row = connection.execute("SELECT snapshot_hash,result_json FROM propagation_runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        raise ValueError(f"propagation run not found: {run_id}")
    current = _snapshot_hash(connection)
    if current != row["snapshot_hash"]:
        raise ValueError("propagation preview is stale; refresh and preview again")
    result = json.loads(row["result_json"])
    selected = {str(item) for item in proposal_ids}
    proposals = [item for item in result["proposals"] if item["proposal_id"] in selected]
    if len(proposals) != len(selected):
        missing = sorted(selected - {item["proposal_id"] for item in proposals})
        raise ValueError(f"unknown proposal ids: {', '.join(missing)}")
    if any(not item.get("acceptable", False) for item in proposals):
        raise ValueError("hypothesis-only propagation proposals cannot be accepted; confirm the relationship first")
    if job_id is not None:
        if isinstance(job_id, bool) or int(job_id) < 1:
            raise ValueError("job_id must be a positive integer")
        if connection.execute("SELECT 1 FROM jobs WHERE job_id=?", (int(job_id),)).fetchone() is None:
            raise ValueError(f"job {job_id} does not exist")
    connection.execute("BEGIN IMMEDIATE")
    if _snapshot_hash(connection) != row["snapshot_hash"]:
        connection.rollback()
        raise ValueError("propagation preview became stale; refresh and preview again")
    pending_constraints: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for proposal in proposals:
        existing_constraints = [json.loads(item[0]) for item in connection.execute(
            "SELECT constraint_json FROM propagation_constraints WHERE node_id=? AND source_snapshot_hash=?",
            (proposal["node_id"], row["snapshot_hash"]))]
        conflicts = [detail for existing in existing_constraints + pending_constraints[proposal["node_id"]]
                     for detail in _conflict(existing, proposal["constraint"])]
        if conflicts:
            connection.rollback()
            raise ValueError(f"accepted constraints changed since preview and conflict at {proposal['node_id']}; preview again")
        pending_constraints[proposal["node_id"]].append(proposal["constraint"])
    now = utc_now()
    accepted = []
    for proposal in proposals:
        constraint_id = uuid.uuid4().hex
        provenance = {"run_id": run_id, "proposal_id": proposal["proposal_id"], "trace": proposal["trace"],
                      "seed": result["seed"]}
        node_kind = proposal["node_id"].split(":", 1)[0]
        identity = json.dumps({"node_id": proposal["node_id"], "kind": node_kind}, sort_keys=True)
        connection.execute("INSERT OR IGNORE INTO propagation_nodes(node_id,kind,identity_json,source_snapshot_hash,created_at) "
                           "VALUES(?,?,?,?,?)", (proposal["node_id"], node_kind, identity, row["snapshot_hash"], now))
        connection.execute("INSERT INTO propagation_constraints(constraint_id,run_id,proposal_id,node_id,constraint_json,provenance_json,source_snapshot_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
                           (constraint_id, run_id, proposal["proposal_id"], proposal["node_id"],
                            json.dumps(proposal["constraint"], sort_keys=True), json.dumps(provenance, sort_keys=True),
                            row["snapshot_hash"], now))
        accepted.append({"constraint_id": constraint_id, "proposal_id": proposal["proposal_id"], "node_id": proposal["node_id"]})
    connection.commit()
    result = {"run_id": run_id, "snapshot_hash": current, "accepted": accepted}
    if job_id is not None:
        evidence = {
            "kind": "derived",
            "origin": "analyst",
            "source_ref": f"propagation:{run_id}",
            "description": f"Accepted {len(accepted)} bounded type-propagation proposal(s): "
                           + ", ".join(item["proposal_id"] for item in accepted),
        }
        try:
            result["job_revision"] = revise_job(
                connection, int(job_id),
                message=f"Accept type propagation run {run_id}",
                details="Accepted proposals retain their immutable run, snapshot, and edge traces in SQLite.",
                add_evidence=[json.dumps(evidence, ensure_ascii=False)],
            )
        except Exception as exc:
            # The durable constraint acceptance must remain inspectable even if
            # recording optional job evidence is rejected by the job state.
            result["job_error"] = str(exc)
    return result

"""Explainable utilization-form matching over exported microcode instructions.

This module deliberately performs candidate search only. It never creates or
applies an IDA type. The microcode exporter records the structured operands;
this scanner evaluates a caller supplied JSON form against those observations.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from .db import ida_ea


DEFAULT_MIN_SCORE = 0.5
DEFAULT_WINDOW = 8
ACCESS_PROFILE_SAMPLE_LIMIT = 16
SUPPORTED_KINDS = {
    "opcode", "memory_access", "operand", "dereference", "mask", "constant",
    "call", "return", "extension", "comparison",
}
MEMORY_OPCODES = {"ldx", "stx"}
READ_OPCODES = {"ldx"}
WRITE_OPCODES = {"stx"}
EXTENSION_OPCODES = {"xdu": "zero", "xds": "sign", "xdu_1": "zero", "xds_1": "sign"}
COMPARISON_OPCODES = {"jz", "jnz", "jae", "jb", "ja", "jbe", "jg", "jge", "jl", "jle",
                      "sets", "seto", "setp", "setz", "setnz", "setae", "setb", "seta", "setbe",
                      "setg", "setge", "setl", "setle"}
FIELDS = {
    "opcode": {"value"}, "memory_access": {"direction", "width", "min_width", "offset", "object"},
    "operand": {"object", "width", "address", "stack_offset", "local_index", "register"},
    "dereference": {"depth"}, "mask": {"value"}, "constant": {"value"},
    "call": {"callee", "arg_index"}, "return": set(), "extension": {"extension"}, "comparison": set(),
}


def _number(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{description} must be an integer")
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{description} must be an integer") from exc


def _constraint_list(value: Any, description: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{description} must be a non-empty list")
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{description}[{index}] must be an object")
        if "kind" not in item:
            raise ValueError(f"{description}[{index}] requires kind")
        kind = str(item["kind"]).strip().lower()
        if kind not in SUPPORTED_KINDS:
            raise ValueError(f"{description}[{index}] kind must be one of: {', '.join(sorted(SUPPORTED_KINDS))}")
        constraint = dict(item)
        constraint["kind"] = kind
        weight = constraint.get("weight", 1.0)
        if isinstance(weight, bool):
            raise ValueError(f"{description}[{index}] weight must be a positive number")
        try:
            weight = float(weight)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{description}[{index}] weight must be a positive number") from exc
        if not math.isfinite(weight) or weight <= 0:
            raise ValueError(f"{description}[{index}] weight must be positive")
        constraint["weight"] = weight
        unknown = set(constraint) - FIELDS[kind] - {"kind", "weight"}
        if unknown:
            raise ValueError(f"unsupported {kind} fields: {', '.join(sorted(unknown))}")
        for key in ("width", "min_width", "offset", "depth", "address", "stack_offset",
                    "local_index", "register", "arg_index", "callee"):
            if key in constraint:
                constraint[key] = _number(constraint[key], f"{kind}.{key}")
                if key in {"width", "min_width", "depth"} and constraint[key] <= 0:
                    raise ValueError(f"{kind}.{key} must be positive")
                if key in {"arg_index", "local_index", "register", "address", "callee"} and constraint[key] < 0:
                    raise ValueError(f"{kind}.{key} must be non-negative")
        if kind in {"constant", "mask"} and "value" in constraint:
            constraint["value"] = _number(constraint["value"], f"{kind}.value")
        if kind == "opcode":
            values = constraint.get("value")
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
                raise ValueError("opcode.value must be a name or non-empty list of names")
            constraint["value"] = [v.lower() for v in values]
        if "direction" in constraint and constraint["direction"] not in ("read", "write"):
            raise ValueError("memory_access.direction must be read or write")
        if "object" in constraint and constraint["object"] not in ("any", "global", "stack", "local", "register"):
            raise ValueError(f"invalid {kind}.object")
        if kind == "extension" and constraint.get("extension") not in ("sign", "zero"):
            raise ValueError("extension.extension must be sign or zero")
        result.append(constraint)
    return result


def normalize_spec(spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError("type scan specification must be a JSON object")
    unknown = set(spec) - {"name", "features", "sequence", "min_score", "window"}
    if unknown:
        raise ValueError(f"unsupported specification fields: {', '.join(sorted(unknown))}")
    features = _constraint_list(spec["features"], "features") if "features" in spec else []
    sequence_raw = spec.get("sequence", [])
    if not isinstance(sequence_raw, list):
        raise ValueError("sequence must be a list")
    sequence = []
    for index, step in enumerate(sequence_raw):
        if isinstance(step, dict) and "constraints" in step:
            if set(step) != {"constraints"}:
                raise ValueError(f"sequence[{index}] only accepts constraints")
            constraints = _constraint_list(step["constraints"], f"sequence[{index}].constraints")
        elif isinstance(step, dict):
            constraints = _constraint_list([step], f"sequence[{index}]")
        else:
            raise ValueError(f"sequence[{index}] must be an object")
        sequence.append(constraints)
    if not features and not sequence:
        raise ValueError("type scan specification requires features or sequence")
    total_weight = sum(item["weight"] for item in features) + sum(item["weight"] for step in sequence for item in step)
    if not math.isfinite(total_weight):
        raise ValueError("total constraint weight must be finite")
    threshold = spec.get("min_score", DEFAULT_MIN_SCORE)
    try:
        threshold = float(threshold)
    except (TypeError, ValueError) as exc:
        raise ValueError("min_score must be a number between 0 and 1") from exc
    if not 0 <= threshold <= 1:
        raise ValueError("min_score must be between 0 and 1")
    window = _number(spec.get("window", DEFAULT_WINDOW), "window")
    if window < 1 or window > 1000:
        raise ValueError("window must be between 1 and 1000")
    return {"name": str(spec.get("name", "unnamed utilization form")), "features": features,
            "sequence": sequence, "min_score": threshold, "window": window}


def _walk(value: dict, path: str = "") -> Iterable[tuple[str, dict]]:
    yield path, value
    nested = value.get("operand")
    if isinstance(nested, dict):
        yield from _walk(nested, f"{path}.operand" if path else "operand")
    nested = value.get("instruction")
    if isinstance(nested, dict):
        for key in ("l", "r", "d"):
            child = nested.get(key)
            if isinstance(child, dict):
                yield from _walk(child, f"{path}.instruction.{key}" if path else f"instruction.{key}")
    for key in ("low", "high"):
        nested = value.get(key)
        if isinstance(nested, dict):
            yield from _walk(nested, f"{path}.{key}" if path else key)
    for index, nested in enumerate(value.get("arguments", []) or []):
        if isinstance(nested, dict):
            yield from _walk(nested, f"{path}.arguments[{index}]")


def _operands(instruction: dict) -> list[tuple[str, dict]]:
    result = []
    for name in ("l", "r", "d"):
        operand = instruction.get(name)
        if isinstance(operand, dict):
            result.extend((f"{name}.{path}" if path else name, item) for path, item in _walk(operand))
    return result


def _integers(instruction: dict) -> list[int]:
    return [int(item[1]["value"]) for item in _operands(instruction)
            if item[1].get("kind") == "number" and item[1].get("value") is not None]


def _address_objects(instruction: dict) -> list[dict]:
    return [item for _, item in _operands(instruction)
            if item.get("kind") in {"global", "stack", "local", "register"}]


def _offsets(instruction: dict) -> list[int]:
    # Only decompose the address expression, never a constant in the stored value.
    address = instruction.get("r" if instruction.get("opcode") == "ldx" else "d", {})
    def offset(operand):
        if operand.get("kind") in {"register", "global", "stack", "local", "address"}:
            return 0
        nested = operand.get("instruction") or {}
        if nested.get("opcode") not in {"add", "sub"}:
            return None
        left, right = nested.get("l", {}), nested.get("r", {})
        if right.get("kind") == "number" and right.get("value") is not None:
            base = offset(left)
            width = right.get("size", 0)
            number = int(right["value"])
            if width > 0 and number >= (1 << (width * 8 - 1)):
                number -= 1 << (width * 8)
            return None if base is None else base + (number if nested["opcode"] == "add" else -number)
        if nested.get("opcode") == "add" and left.get("kind") == "number" and left.get("value") is not None:
            base = offset(right)
            return None if base is None else base + int(left["value"])
        return None
    value = offset(address)
    return [] if value is None else [value]


def _deref_depth(instruction: dict) -> int:
    """Syntactically nested address loads, not a register data-flow proof."""
    if instruction.get("opcode") not in MEMORY_OPCODES:
        return 0
    address = instruction.get("r" if instruction["opcode"] == "ldx" else "d", {})
    children = [item["instruction"] for _, item in _walk(address)
                if isinstance(item.get("instruction"), dict)]
    return 1 + max((_deref_depth(child) for child in children), default=0)


def _fact(instruction: dict) -> dict[str, Any]:
    opcode = str(instruction.get("opcode", "")).lower()
    operands = _operands(instruction)
    objects = _address_objects(instruction)
    integers = _integers(instruction)
    calls = []
    expressions = [instruction] + [operand["instruction"] for _, operand in operands
                                  if isinstance(operand.get("instruction"), dict)]
    for expression in expressions:
        if expression.get("opcode") not in {"call", "icall"}:
            continue
        infos = [expression.get(key, {}) for key in ("l", "r", "d")
                 if expression.get(key, {}).get("kind") == "arglist"]
        for info in infos or [{}]:
            site = dict(info)
            if site.get("callee") in {None, (1 << 64) - 1}:
                target = expression.get("l", {})
                site["callee"] = target.get("address") if target.get("kind") == "global" else None
            calls.append(site)
    address_operand = instruction.get("r" if opcode == "ldx" else "d", {})
    address_objects = [obj for _, obj in _walk(address_operand)
                       if obj.get("kind") in {"global", "stack", "local", "register"}]
    data_operand = instruction.get("d" if opcode == "ldx" else "l", {})
    memory_width = data_operand.get("size", 0)
    return {
        "opcode": opcode,
        "widths": sorted({int(operand.get("size")) for _, operand in operands
                           if isinstance(operand.get("size"), int) and operand.get("size") > 0}),
        "objects": objects,
        "object_kinds": sorted({str(item.get("kind")) for item in objects}),
        "global_addresses": sorted({int(item["address"]) for item in objects if item.get("kind") == "global" and item.get("address") is not None}),
        "stack_offsets": sorted({int(item["stack_offset"]) for item in objects if item.get("kind") == "stack" and item.get("stack_offset") is not None}),
        "local_indices": sorted({int(item["local_index"]) for item in objects if item.get("kind") == "local" and item.get("local_index") is not None}),
        "integers": integers,
        "offsets": _offsets(instruction),
        "memory_width": memory_width if isinstance(memory_width, int) and memory_width > 0 else None,
        "memory_object_kinds": sorted({obj["kind"] for obj in address_objects}),
        "memory": opcode in MEMORY_OPCODES,
        "direction": "read" if opcode in READ_OPCODES else "write" if opcode in WRITE_OPCODES else None,
        "deref_depth": _deref_depth(instruction),
        "calls": calls,
        "return": opcode == "ret",
        "extension": EXTENSION_OPCODES.get(opcode),
        "comparison": opcode in COMPARISON_OPCODES,
    }


def _expected_values(value: Any) -> set[Any]:
    return {value} if not isinstance(value, list) else set(value)


def _result(state: str, evidence: str | None = None) -> tuple[str, str | None]:
    return state, evidence


def _evaluate(constraint: dict[str, Any], instruction: dict, fact: dict[str, Any]) -> tuple[str, str]:
    kind = constraint["kind"]
    if kind == "opcode":
        expected = {str(item).lower() for item in _expected_values(constraint.get("value", constraint.get("opcode", "")))}
        return _result("match" if fact["opcode"] in expected else "conflict", f"opcode={fact['opcode']}")
    if kind == "memory_access":
        if not fact["memory"]:
            return _result("conflict", f"opcode={fact['opcode']} is not a memory access")
        if "direction" in constraint and constraint["direction"] != fact["direction"]:
            return _result("conflict", f"direction={fact['direction']}")
        if "width" in constraint:
            width = _number(constraint["width"], "memory_access.width")
            if fact["memory_width"] is None:
                return _result("unknown", "memory access width unavailable")
            if width != fact["memory_width"]:
                return _result("conflict", f"memory width={fact['memory_width']}")
        if "min_width" in constraint:
            if fact["memory_width"] is None:
                return _result("unknown", "operand width unavailable")
            if fact["memory_width"] < _number(constraint["min_width"], "memory_access.min_width"):
                return _result("conflict", f"memory width={fact['memory_width']}")
        if "offset" in constraint:
            if not fact["offsets"]:
                return _result("unknown", "address offset unavailable")
            if _number(constraint["offset"], "memory_access.offset") not in fact["offsets"]:
                return _result("conflict", f"observed offsets={fact['offsets']}")
        if "object" in constraint and constraint["object"] != "any":
            if not fact["memory_object_kinds"]:
                return _result("unknown", "address object kind unavailable")
            if constraint["object"] not in fact["memory_object_kinds"]:
                return _result("conflict", f"address object kinds={fact['memory_object_kinds']}")
        return _result("match", f"{fact['direction']} width={fact['memory_width']} offsets={fact['offsets']}")
    if kind == "operand":
        candidates = fact["objects"]
        wanted = str(constraint.get("object", constraint.get("object_kind", "any")))
        if wanted != "any":
            candidates = [item for item in candidates if item.get("kind") == wanted]
        if not candidates:
            return _result("unknown" if fact["objects"] else "conflict", "operand object unavailable")
        # All constraints must describe the same operand.
        keys = {"width": "size", "address": "address", "stack_offset": "stack_offset",
                "local_index": "local_index", "register": "register"}
        if not any(all(item.get(field) == constraint[key] for key, field in keys.items() if key in constraint)
                   for item in candidates):
            return _result("conflict", "no single operand satisfies all requested fields")
        return _result("match", f"operand={wanted}")
    if kind == "dereference":
        depth = _number(constraint.get("depth", 1), "dereference.depth")
        return _result("match" if fact["deref_depth"] >= depth else "conflict", f"depth={fact['deref_depth']}")
    if kind == "mask":
        if fact["opcode"] not in {"and", "or", "xor"}:
            return _result("conflict", f"opcode={fact['opcode']}")
        if not fact["integers"]:
            return _result("unknown", "mask constant unavailable")
        if "value" in constraint:
            expected = _number(constraint["value"], "mask.value")
            return _result("match" if expected in fact["integers"] else "conflict", f"constants={fact['integers']}")
        return _result("match", f"constants={fact['integers']}")
    if kind == "constant":
        if not fact["integers"]:
            return _result("conflict", "no integer constant")
        if "value" in constraint:
            expected = _number(constraint["value"], "constant.value")
            return _result("match" if expected in fact["integers"] else "conflict", f"constants={fact['integers']}")
        return _result("match", f"constants={fact['integers']}")
    if kind == "call":
        sites = fact["calls"]
        if not sites:
            return _result("conflict", f"opcode={fact['opcode']}")
        if "callee" in constraint:
            expected = constraint["callee"]
            callees = [item.get("callee") for item in sites if item.get("callee") is not None]
            if expected not in callees:
                return _result("unknown" if not callees else "conflict", f"callees={callees}")
            sites = [item for item in sites if item.get("callee") == expected]
        if "arg_index" in constraint:
            index = _number(constraint["arg_index"], "call.arg_index")
            if not any(index < len(item.get("arguments", [])) for item in sites):
                state = "conflict" if all("arguments" in item for item in sites) else "unknown"
                return _result(state, "requested argument not observed at matching call site")
        return _result("match", "call")
    if kind == "return":
        return _result("match" if fact["return"] else "conflict", f"opcode={fact['opcode']}")
    if kind == "extension":
        wanted = constraint["extension"]
        return _result("match" if fact["extension"] == wanted else "conflict", f"extension={fact['extension']}")
    if kind == "comparison":
        return _result("match" if fact["comparison"] else "conflict", f"opcode={fact['opcode']}")
    return _result("unknown", f"unsupported constraint={kind}")


def _score(constraints: list[dict[str, Any]], instruction: dict) -> dict[str, Any]:
    fact = _fact(instruction)
    total = sum(float(item["weight"]) for item in constraints)
    matched = 0.0
    matched_items, missing, conflicts = [], [], []
    for index, constraint in enumerate(constraints):
        state, evidence = _evaluate(constraint, instruction, fact)
        item = {"index": index, "constraint": constraint, "kind": constraint["kind"],
                "weight": constraint["weight"], "state": state, "evidence": evidence}
        if state == "match":
            matched += float(constraint["weight"])
            matched_items.append(item)
        elif state == "unknown":
            missing.append(item)
        else:
            conflicts.append(item)
    return {"score": matched / total if total else 0.0, "matched_weight": matched, "total_weight": total,
            "matched": matched_items, "missing": missing, "conflicts": conflicts,
            "fact": fact}


def _candidate(row: sqlite3.Row, function_name: str, score: dict[str, Any]) -> dict[str, Any]:
    return {"function_ea": ida_ea(row["function_ea"]), "function_address": f"0x{ida_ea(row['function_ea']):X}",
            "function_name": function_name, "block_serial": int(row["block_serial"]),
            "ordinal": int(row["ordinal"]), "ea": ida_ea(row["ea"]) if row["ea"] is not None else None,
            "address": f"0x{ida_ea(row['ea']):X}" if row["ea"] is not None else None,
            "opcode": row["opcode"], "text": row["text"], **score}


def _requested_access_offsets(spec: dict[str, Any]) -> set[int]:
    constraints = list(spec["features"])
    constraints.extend(item for step in spec["sequence"] for item in step)
    return {int(item["offset"]) for item in constraints
            if item["kind"] == "memory_access" and "offset" in item}


def _width_summary(observations: list[dict[str, Any]], *, include_function: bool) -> dict[str, Any]:
    by_width: dict[int, list[dict[str, Any]]] = defaultdict(list)
    unknown_widths = 0
    for observation in observations:
        width = observation["width"]
        if width is None:
            unknown_widths += 1
        else:
            by_width[int(width)].append(observation)

    widths = sorted(by_width)
    width_counts = []
    for width in widths:
        matching = by_width[width]
        locations = []
        for observation in matching[:ACCESS_PROFILE_SAMPLE_LIMIT]:
            location = {key: observation[key] for key in (
                "block_serial", "ordinal", "operand_path", "ea", "address", "opcode", "direction")}
            if include_function:
                location.update(function_ea=observation["function_ea"],
                                function_address=observation["function_address"],
                                function_name=observation["function_name"],
                                microcode_hash=observation["microcode_hash"])
            locations.append(location)
        width_counts.append({
            "width": width,
            "count": len(matching),
            "read_count": sum(item["direction"] == "read" for item in matching),
            "write_count": sum(item["direction"] == "write" for item in matching),
            "sample_locations": locations,
            "sample_truncated": len(matching) > ACCESS_PROFILE_SAMPLE_LIMIT,
        })

    return {
        "observation_count": len(observations),
        "observed_widths": widths,
        "mixed_width": len(widths) > 1,
        "width_status": ("mixed" if len(widths) > 1 else
                         "single" if widths and not unknown_widths else
                         "partially_known" if widths else "unknown"),
        "unknown_width_count": unknown_widths,
        "width_candidates": [{"width": item["width"], "observation_count": item["count"],
                              "read_count": item["read_count"], "write_count": item["write_count"]}
                             for item in width_counts],
        "ambiguities": ([{
            "kind": "mixed_access_width",
            "widths": widths,
            "reason": "multiple access widths were observed at this numeric offset; common object and alias are not proven",
        }] if len(widths) > 1 else []),
        "width_counts": width_counts,
    }


def _access_profiles(observations: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    profiles = []
    for offset, items in sorted(observations.items()):
        by_function: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for item in items:
            by_function[item["function_ea"]].append(item)
        function_profiles = []
        for function_ea, function_items in sorted(by_function.items()):
            first = function_items[0]
            function_profiles.append({
                "function_ea": function_ea,
                "function_address": first["function_address"],
                "function_name": first["function_name"],
                "microcode_hash": first["microcode_hash"],
                **_width_summary(function_items, include_function=False),
            })
        profiles.append({
            "offset": offset,
            **_width_summary(items, include_function=True),
            "by_function": function_profiles,
        })
    return {
        "grouping": "same numeric offset relative to the immediate address expression, across selected functions; base identity and aliasing are not proven",
        "sample_locations_per_width": ACCESS_PROFILE_SAMPLE_LIMIT,
        "profiles": profiles,
    }


def _row_instruction(row: sqlite3.Row) -> dict:
    return {"ea": ida_ea(row["ea"]) if row["ea"] is not None else None, "opcode": row["opcode"],
            "text": row["text"], "l": json.loads(row["l_json"]), "r": json.loads(row["r_json"]),
            "d": json.loads(row["d_json"])}


def _nodes(instruction: dict, path: str = "root"):
    """Expose every expression instruction, including optimized nested loads/calls."""
    yield path, instruction
    for operand_path, operand in _operands(instruction):
        nested = operand.get("instruction")
        if isinstance(nested, dict):
            # _operands already descends recursively; yield each nested instruction once.
            yield f"{path}.{operand_path}.instruction", nested


def _sequence_matches(rows: list, start: int, steps: list, window: int) -> list:
    """Maximum satisfied weight for ordered positions; step zero is anchored.

    A state records the next available position and the best evidence so far.
    Skipping a step preserves its weight in the denominator of the final score.
    """
    end = min(len(rows), start + window)
    first = _score(steps[0], rows[start][2])
    initial = [(0, start, first)] if first["matched_weight"] > 0 else []
    states = {start + 1: (first["matched_weight"], initial)}
    for step_index, step in enumerate(steps[1:], 1):
        updated = dict(states)  # Missing steps are allowed for partial matches.
        prefix = None
        for position in range(start + 1, end):
            state = states.get(position)
            if state is not None and (prefix is None or state[0] > prefix[0]):
                prefix = state
            if prefix is None:
                continue
            score = _score(step, rows[position][2])
            if score["matched_weight"] <= 0:
                continue
            weight = prefix[0] + score["matched_weight"]
            if position + 1 not in updated or weight > updated[position + 1][0]:
                updated[position + 1] = (weight, prefix[1] + [(step_index, position, score)])
        states = updated
    return max(states.values(), key=lambda state: state[0])[1]


def scan_type_features(connection: sqlite3.Connection, spec: dict[str, Any], *,
                       function_ea: int | None = None, limit: int = 1000,
                       min_score: float | None = None, function_eas: list[int] | None = None) -> dict[str, Any]:
    normalized = normalize_spec(spec)
    threshold = normalized["min_score"] if min_score is None else float(min_score)
    if not 0 <= threshold <= 1:
        raise ValueError("min_score must be between 0 and 1")
    if limit < 0:
        raise ValueError("limit must be non-negative")
    selected = set(function_eas) if function_eas is not None else None
    if function_ea is not None:
        selected = {function_ea} if selected is None else selected.intersection({function_ea})
    rows = connection.execute(
        "SELECT i.*,m.content_hash,f.name FROM micro_instructions i "
        "JOIN microcode m ON m.function_ea=i.function_ea "
        "LEFT JOIN functions f ON f.start_ea=i.function_ea "
        "WHERE m.status='ok' ORDER BY i.function_ea,i.block_serial,i.ordinal")
    grouped: dict[tuple[int, int], list] = {}
    requested_offsets = _requested_access_offsets(normalized)
    access_observations: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if selected is None or ida_ea(row["function_ea"]) in selected:
            for path, instruction in _nodes(_row_instruction(row)):
                grouped.setdefault((row["function_ea"], row["block_serial"]), []).append((row, path, instruction))
                if requested_offsets:
                    fact = _fact(instruction)
                    if fact["memory"] and fact["offsets"]:
                        for offset in fact["offsets"]:
                            if offset not in requested_offsets:
                                continue
                            function_value = ida_ea(row["function_ea"])
                            ea = instruction.get("ea")
                            access_observations[offset].append({
                                "function_ea": function_value,
                                "function_address": f"0x{function_value:X}",
                                "function_name": row["name"] or "",
                                "microcode_hash": row["content_hash"],
                                "block_serial": int(row["block_serial"]),
                                "ordinal": int(row["ordinal"]),
                                "operand_path": path,
                                "ea": ea,
                                "address": f"0x{ea:X}" if ea is not None else None,
                                "opcode": fact["opcode"],
                                "direction": fact["direction"],
                                "width": fact["memory_width"],
                            })
    matches = []
    sequence = normalized["sequence"]
    for function_rows in grouped.values():
        for index, (row, path, anchor) in enumerate(function_rows):
            constraints = normalized["features"]
            score = _score(constraints, anchor)
            evidence = []
            if sequence:
                sequence_total = sum(float(item["weight"]) for step in sequence for item in step)
                sequence_matched = 0.0
                seq_missing = []
                chosen = {step: (position, item_score) for step, position, item_score
                          in _sequence_matches(function_rows, index, sequence, normalized["window"])}
                for step_index, step in enumerate(sequence):
                    if step_index not in chosen:
                        seq_missing.append({"step": step_index, "reason": "no matching instruction in window"})
                    else:
                        position, step_score = chosen[step_index]
                        sequence_matched += step_score["matched_weight"]
                        seq_row, seq_path, seq_instruction = function_rows[position]
                        seq_ea = seq_instruction.get("ea")
                        evidence.append({"step": step_index, **_candidate(seq_row, row["name"] or "", step_score),
                                         "operand_path": seq_path, "opcode": seq_instruction["opcode"],
                                         "text": seq_instruction.get("text", ""), "ea": seq_ea,
                                         "address": f"0x{seq_ea:X}" if seq_ea is not None else None})
                        for key in ("matched", "missing", "conflicts"):
                            score[key].extend({"step": step_index, **item} for item in step_score[key])
                score["matched_weight"] += sequence_matched
                score["total_weight"] += sequence_total
                score["score"] = score["matched_weight"] / score["total_weight"]
                score["missing"].extend(seq_missing)
                score["sequence_evidence"] = evidence
            if score["score"] < threshold or not (score["matched"] or evidence):
                continue
            result = _candidate(row, row["name"] or "", score)
            result.update(operand_path=path, opcode=anchor["opcode"], text=anchor.get("text", ""),
                          ea=anchor.get("ea"), address=f"0x{anchor['ea']:X}" if anchor.get("ea") is not None else None)
            result["min_score"] = threshold
            result["match_kind"] = "exact" if not score["missing"] and not score["conflicts"] else "partial"
            result["compatible"] = not bool(score["conflicts"])
            result["score"] = round(result["score"], 6)
            result["microcode_hash"] = row["content_hash"]
            matches.append(result)
    matches.sort(key=lambda item: (-item["score"], item["function_ea"], item["block_serial"], item["ordinal"]))
    total_candidates = len(matches)
    truncated = limit > 0 and total_candidates > limit
    if truncated:
        matches = matches[:limit]
    statuses = [dict(row) for row in connection.execute("SELECT function_ea,status,error FROM microcode")
                if selected is None or ida_ea(row["function_ea"]) in selected]
    exported = {ida_ea(row["function_ea"]) for row in statuses}
    return {"spec": normalized, "candidate_count": len(matches), "total_candidates": total_candidates,
            "truncated": truncated, "matches": matches,
            "access_profiles": _access_profiles(access_observations),
            "coverage": {"exported_functions": len(statuses), "ok_functions": sum(r["status"] == "ok" for r in statuses),
                         "errors": [{**r, "function_ea": ida_ea(r["function_ea"])} for r in statuses if r["status"] != "ok"],
                         "missing_functions": sorted(selected - exported) if selected is not None else []},
            "matching": {"score": "sum(matched weights) / sum(all constraint weights)",
                         "meaning": "compatibility with observed microcode constraints; not source-type identity",
                         "sequence": "maximum-weight ordered expression positions in one block, within one total window; not a data-flow or execution-path proof",
                         "limitations": "no alias/object binding or interprocedural propagation; offsets are relative to the immediate address base; memory_access covers ldx/stx only; dereference depth is syntactic nesting only"}}

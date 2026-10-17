"""Evidence-preserving virtual-table and indirect-call indexes.

The first version intentionally labels data-derived tables and indirect-call
patterns as candidates.  It does not claim that a function-pointer array is a
C++ vtable or that a slot candidate is reachable from a particular receiver.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from .db import get_metadata, ida_ea, sqlite_ea, utc_now


VTABLE_PARSER_VERSION = "1"
VCALL_DETECTOR_VERSION = "1"
SUPPORTED_ABIS = ("itanium",)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _id(prefix: str, value: Any) -> str:
    return prefix + _digest(value)[:32]


def _address(value: int | None) -> dict[str, int | str] | None:
    if value is None:
        return None
    value = ida_ea(value)
    return {"ea": value, "hex": f"0x{value:X}"}


def _identity(connection: sqlite3.Connection) -> dict[str, Any]:
    keys = ("root_filename", "input_path", "imagebase", "bitness", "big_endian")
    return {key: get_metadata(connection, key) for key in keys}


def _rows(connection: sqlite3.Connection, query: str, parameters: tuple = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, parameters)]


def _source_hash(connection: sqlite3.Connection, kind: str, function_eas: Iterable[int] | None = None) -> str:
    """Hash the exact durable inputs used by a virtual-analysis run."""

    identity = _identity(connection)
    functions = _rows(connection,
        "SELECT start_ea,end_ea,name,demangled_name,signature,flags,is_thunk,thunk_target_ea,is_nullstub "
        "FROM functions ORDER BY start_ea")
    if kind == "vtable":
        payload = {
            "identity": identity,
            "segments": _rows(connection, "SELECT start_ea,end_ea,name,class_name,permissions,bitness FROM segments ORDER BY start_ea"),
            "functions": functions,
            "symbols": _rows(connection, "SELECT address,name,type FROM symbols ORDER BY address"),
            "data_pointer_slots": _rows(connection, "SELECT source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind FROM data_pointer_slots ORDER BY source_ea"),
        }
    elif kind == "vcall":
        selected = None if function_eas is None else {sqlite_ea(ea) for ea in function_eas}
        microcode = _rows(connection,
            "SELECT function_ea,maturity,backend,status,error,decompiler_version,instruction_count,content_hash "
            "FROM microcode ORDER BY function_ea")
        if selected is not None:
            microcode = [row for row in microcode if row["function_ea"] in selected]
            functions = [row for row in functions if row["start_ea"] in selected]
        payload = {"identity": identity, "functions": functions, "microcode": microcode}
    else:
        raise ValueError(f"unknown virtual-analysis input kind: {kind}")
    return _digest(payload)


def _validate_abi(abi: str, pointer_size: int, byteorder: str) -> None:
    if abi not in SUPPORTED_ABIS:
        raise ValueError(f"unsupported ABI {abi!r}; supported ABIs: {', '.join(SUPPORTED_ABIS)}")
    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    if byteorder not in ("little", "big"):
        raise ValueError("byteorder must be little or big")


def _has_itanium_prefix(connection: sqlite3.Connection, address_point: int, pointer_size: int) -> dict[str, Any] | None:
    """Return a weak prefix-layout clue; this is not RTTI confirmation."""

    if address_point < 2 * pointer_size:
        return None
    rows = connection.execute(
        "SELECT source_ea,raw_value,target_ea,target_kind FROM data_pointer_slots "
        "WHERE source_ea IN (?,?) ORDER BY source_ea",
        (sqlite_ea(address_point - 2 * pointer_size), sqlite_ea(address_point - pointer_size)),
    ).fetchall()
    by_ea = {ida_ea(row["source_ea"]): row for row in rows}
    offset_row = by_ea.get(address_point - 2 * pointer_size)
    typeinfo_row = by_ea.get(address_point - pointer_size)
    if offset_row is None or typeinfo_row is None:
        return None
    offset_to_top = ida_ea(offset_row["raw_value"])
    if offset_to_top & (1 << (pointer_size * 8 - 1)):
        offset_to_top -= 1 << (pointer_size * 8)
    typeinfo_target = typeinfo_row["target_ea"]
    if typeinfo_target is None or typeinfo_row["target_kind"] != "data":
        return None
    if offset_to_top != 0 and abs(offset_to_top) > 0x10000:
        return None
    return {
        "layout": "itanium_address_point_prefix_candidate",
        "offset_to_top_ea": address_point - 2 * pointer_size,
        "offset_to_top": offset_to_top,
        "typeinfo_pointer_ea": address_point - pointer_size,
        "typeinfo_target_ea": ida_ea(typeinfo_target),
        "status": "heuristic_candidate",
    }


def build_vtable_index(
    connection: sqlite3.Connection,
    *,
    abi: str,
    pointer_size: int | None = None,
    byteorder: str | None = None,
    start: int | None = None,
    end: int | None = None,
    min_function_slots: int = 2,
    max_slots: int = 512,
) -> dict[str, Any]:
    """Build a conservative index from IDA's aligned data-pointer snapshot."""

    if pointer_size is None:
        pointer_size = 8 if get_metadata(connection, "bitness", 64) == 64 else 4
    if byteorder is None:
        byteorder = "big" if get_metadata(connection, "big_endian", False) else "little"
    _validate_abi(abi, pointer_size, byteorder)
    if min_function_slots < 2 or max_slots < min_function_slots:
        raise ValueError("slot limits require 2 <= min_function_slots <= max_slots")
    if start is not None and end is not None and end <= start:
        raise ValueError("end must be greater than start")

    scope = {"start": start, "end": end, "min_function_slots": min_function_slots, "max_slots": max_slots}
    source_snapshot_hash = _source_hash(connection, "vtable")
    run_id = _id("VT", {"source": source_snapshot_hash, "abi": abi, "pointer_size": pointer_size,
                          "byteorder": byteorder, "scope": scope, "parser": VTABLE_PARSER_VERSION})
    existing = connection.execute("SELECT status,source_snapshot_hash,result_json FROM vtable_runs WHERE run_id=?", (run_id,)).fetchone()
    if existing is not None and existing["source_snapshot_hash"] == source_snapshot_hash:
        with connection:
            connection.execute("UPDATE vtable_runs SET status='ok' WHERE run_id=?", (run_id,))
            connection.execute("UPDATE vtable_candidates SET stale=0 WHERE run_id=?", (run_id,))
            connection.execute("UPDATE vtable_slots SET stale=0 WHERE candidate_id IN (SELECT candidate_id FROM vtable_candidates WHERE run_id=?)", (run_id,))
            connection.execute("UPDATE vtable_evidence SET stale=0 WHERE subject_id IN (SELECT candidate_id FROM vtable_candidates WHERE run_id=?)", (run_id,))
        return {"run_id": run_id, "cached": True, **json.loads(existing["result_json"])}

    candidates: list[dict[str, Any]] = []
    slots_by_candidate: list[tuple[str, list[dict[str, Any]]]] = []
    query = "SELECT * FROM data_pointer_slots"
    parameters: tuple[Any, ...] = ()
    if start is not None or end is not None:
        clauses, values = [], []
        if start is not None:
            clauses.append("source_ea>=?"); values.append(sqlite_ea(start))
        if end is not None:
            clauses.append("source_ea<?"); values.append(sqlite_ea(end))
        query += " WHERE " + " AND ".join(clauses)
        parameters = tuple(values)
    query += " ORDER BY source_ea"
    pointer_rows = [dict(row) for row in connection.execute(query, parameters)]
    functions = {ida_ea(row["start_ea"]): dict(row) for row in connection.execute(
        "SELECT start_ea,name,demangled_name,is_thunk,thunk_target_ea,is_nullstub FROM functions")}

    run_slots: list[dict[str, Any]] = []
    run_start: int | None = None
    run_previous: int | None = None
    run_function_count = 0

    def flush_run() -> None:
        nonlocal run_slots, run_start, run_previous, run_function_count
        if run_start is not None and run_function_count >= min_function_slots:
            address_point = run_start
            candidate_id = _id("VTB", {"run": run_id, "address_point": address_point})
            prefix = _has_itanium_prefix(connection, address_point, pointer_size)
            evidence = {
                "method": "contiguous_aligned_mapped_function_pointer_sequence",
                "status": "heuristic_candidate",
                "function_slot_count": run_function_count,
                "total_slot_count": len(run_slots),
                "rtti_confirmed": False,
                "address_point_prefix": prefix,
                "limits": {"max_slots": max_slots, "truncated": len(run_slots) >= max_slots},
            }
            candidates.append({
                "candidate_id": candidate_id, "table_address": address_point,
                "address_point": address_point,
                "table_end": run_previous + pointer_size if run_previous is not None else None,
                "slot_count": len(run_slots), "abi": abi, "architecture": get_metadata(connection, "architecture"),
                "pointer_size": pointer_size, "byteorder": byteorder,
                "discovery_source": "data_pointer_sequence", "status": "candidate",
                "confidence": None, "evidence": evidence,
                "source_snapshot_hash": source_snapshot_hash,
            })
            normalized_slots = []
            for index, item in enumerate(run_slots):
                target = item.get("target_ea")
                target_func = functions.get(ida_ea(target)) if target is not None else None
                normalized_slots.append({
                    "candidate_id": candidate_id, "slot_index": index,
                    "byte_offset": index * pointer_size,
                    "entry_address": ida_ea(item["source_ea"]),
                    "raw_value": ida_ea(item["raw_value"]),
                    "target_ea": ida_ea(target) if target is not None else None,
                    "target_kind": item["target_kind"],
                    "target_name": (target_func["demangled_name"] or target_func["name"]) if target_func else item.get("target_name"),
                    "is_thunk": int(bool(target_func and target_func["is_thunk"])),
                    "thunk_target_ea": ida_ea(target_func["thunk_target_ea"]) if target_func and target_func["thunk_target_ea"] is not None else None,
                    "thunk_chain_json": _json([ida_ea(target), ida_ea(target_func["thunk_target_ea"])])
                        if target_func and target_func["is_thunk"] and target_func["thunk_target_ea"] is not None else "[]",
                    "adjustment_json": "{}",
                    "evidence_json": _json({"source": "data_pointer_slots", "entry_address": f"0x{ida_ea(item['source_ea']):X}"}),
                    "source_snapshot_hash": source_snapshot_hash,
                })
            slots_by_candidate.append((candidate_id, normalized_slots))
        run_slots = []
        run_start = run_previous = None
        run_function_count = 0

    for item in pointer_rows:
        address = ida_ea(item["source_ea"])
        if item["pointer_size"] != pointer_size:
            flush_run()
            continue
        is_function = item["target_kind"] in ("function", "code") and item["target_ea"] is not None
        is_null = item["target_kind"] == "null"
        in_scope = (start is None or address >= start) and (end is None or address < end)
        contiguous = run_previous is not None and address == run_previous + pointer_size
        if not in_scope or (not is_function and not is_null) or (run_slots and not contiguous):
            flush_run()
            if not in_scope or (not is_function and not is_null):
                continue
        if run_start is None:
            run_start = address
        if len(run_slots) >= max_slots:
            flush_run()
            run_start = address
        run_slots.append(item)
        run_previous = address
        run_function_count += int(is_function)
    flush_run()

    now = utc_now()
    result = {
        "abi": abi, "pointer_size": pointer_size, "byteorder": byteorder,
        "source_snapshot_hash": source_snapshot_hash, "candidate_count": len(candidates),
        "slot_count": sum(len(slots) for _, slots in slots_by_candidate),
        "coverage": {"pointer_observations": len(pointer_rows), "source": "data_pointer_slots",
                     "rtti_parsed": False, "heuristic_only": True,
                     "data_pointer_scan": get_metadata(connection, "data_pointer_scan")},
        "scope": scope,
    }
    with connection:
        connection.execute("UPDATE vtable_candidates SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vtable_slots SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vtable_evidence SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vtable_runs SET status='stale' WHERE status NOT IN ('stale','error')")
        connection.execute(
            "INSERT INTO vtable_runs(run_id,source_snapshot_hash,abi,architecture,pointer_size,byteorder,scope_json,parser_version,status,result_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, source_snapshot_hash, abi, get_metadata(connection, "architecture"), pointer_size,
             byteorder, _json(scope), VTABLE_PARSER_VERSION, "ok", _json(result), now),
        )
        for candidate in candidates:
            connection.execute(
                "INSERT INTO vtable_candidates(candidate_id,run_id,table_address,address_point,table_end,slot_count,abi,architecture,pointer_size,byteorder,discovery_source,status,confidence,evidence_json,source_snapshot_hash,stale,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (candidate["candidate_id"], run_id, sqlite_ea(candidate["table_address"]),
                 sqlite_ea(candidate["address_point"]), sqlite_ea(candidate["table_end"]), candidate["slot_count"],
                 abi, candidate["architecture"], pointer_size, byteorder, candidate["discovery_source"],
                 candidate["status"], candidate["confidence"], _json(candidate["evidence"]),
                 source_snapshot_hash, 0, now),
            )
            evidence_id = _id("VE", {"candidate": candidate["candidate_id"], "source": source_snapshot_hash})
            connection.execute(
                "INSERT INTO vtable_evidence(evidence_id,subject_kind,subject_id,evidence_type,polarity,source_ea,source_view,source_hash,details_json,source_snapshot_hash,stale,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (evidence_id, "vtable_candidate", candidate["candidate_id"], "contiguous_function_pointer_sequence",
                 "support", sqlite_ea(candidate["address_point"]), "data_pointer_slots", source_snapshot_hash,
                 _json(candidate["evidence"]), source_snapshot_hash, 0, now),
            )
        for candidate_id, slots in slots_by_candidate:
            connection.executemany(
                "INSERT INTO vtable_slots(candidate_id,slot_index,byte_offset,entry_address,raw_value,target_ea,target_kind,target_name,is_thunk,thunk_target_ea,thunk_chain_json,adjustment_json,evidence_json,source_snapshot_hash,stale) "
                "VALUES(:candidate_id,:slot_index,:byte_offset,:entry_address,:raw_value,:target_ea,:target_kind,:target_name,:is_thunk,:thunk_target_ea,:thunk_chain_json,:adjustment_json,:evidence_json,:source_snapshot_hash,0)",
                [{**slot, "entry_address": sqlite_ea(slot["entry_address"]),
                  "raw_value": sqlite_ea(slot["raw_value"]),
                  "target_ea": sqlite_ea(slot["target_ea"]) if slot["target_ea"] is not None else None,
                  "thunk_target_ea": sqlite_ea(slot["thunk_target_ea"]) if slot["thunk_target_ea"] is not None else None}
                 for slot in slots],
            )
    return {"run_id": run_id, "cached": False, **result}


def list_vtables(
    connection: sqlite3.Connection, *, abi: str | None = None, status: str | None = None,
    limit: int = 100, offset: int = 0, include_stale: bool = False,
) -> dict[str, Any]:
    if limit < 0 or offset < 0:
        raise ValueError("limit and offset must be non-negative")
    clauses, parameters = [], []
    if not include_stale:
        clauses.append("c.stale=0")
    if abi:
        clauses.append("c.abi=?"); parameters.append(abi)
    if status:
        clauses.append("c.status=?"); parameters.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    total = connection.execute("SELECT count(*) FROM vtable_candidates c" + where, parameters).fetchone()[0]
    sql_limit = -1 if limit == 0 else limit
    rows = connection.execute(
        "SELECT c.* FROM vtable_candidates c" + where +
        " ORDER BY c.address_point,c.candidate_id LIMIT ? OFFSET ?", (*parameters, sql_limit, offset),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["table_address_hex"] = f"0x{ida_ea(item['table_address']):X}"
        item["address_point_hex"] = f"0x{ida_ea(item['address_point']):X}"
        item["evidence"] = json.loads(item.pop("evidence_json"))
        items.append(item)
    return {"count": len(items), "total": total, "truncated": offset + len(items) < total,
            "items": items, "include_stale": include_stale}


def show_vtable(
    connection: sqlite3.Connection, *, candidate_id: str | None = None, address: int | None = None,
    include_stale: bool = False,
) -> dict[str, Any]:
    if (candidate_id is None) == (address is None):
        raise ValueError("provide exactly one of candidate_id or address")
    clauses = ["c.candidate_id=?"] if candidate_id is not None else ["c.address_point=?"]
    parameters: list[Any] = [candidate_id] if candidate_id is not None else [sqlite_ea(address)]
    if not include_stale:
        clauses.append("c.stale=0")
    rows = connection.execute("SELECT c.* FROM vtable_candidates c WHERE " + " AND ".join(clauses) +
                              " ORDER BY c.created_at DESC", parameters).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        candidate = item["candidate_id"]
        item["table_address_hex"] = f"0x{ida_ea(item['table_address']):X}"
        item["address_point_hex"] = f"0x{ida_ea(item['address_point']):X}"
        item["evidence"] = json.loads(item.pop("evidence_json"))
        slots = []
        for slot in connection.execute(
            "SELECT * FROM vtable_slots WHERE candidate_id=?" + ("" if include_stale else " AND stale=0") +
            " ORDER BY slot_index", (candidate,),
        ):
            value = dict(slot)
            value["entry_address_hex"] = f"0x{ida_ea(value['entry_address']):X}"
            value["target_ea_hex"] = f"0x{ida_ea(value['target_ea']):X}" if value["target_ea"] is not None else None
            value["target_ea"] = ida_ea(value["target_ea"]) if value["target_ea"] is not None else None
            value["raw_value"] = ida_ea(value["raw_value"])
            value["thunk_target_ea"] = ida_ea(value["thunk_target_ea"]) if value["thunk_target_ea"] is not None else None
            value["thunk_chain"] = json.loads(value.pop("thunk_chain_json"))
            value["adjustment"] = json.loads(value.pop("adjustment_json"))
            value["evidence"] = json.loads(value.pop("evidence_json"))
            slots.append(value)
        item["slots"] = slots
        items.append(item)
    return {"count": len(items), "items": items, "include_stale": include_stale}


def search_vtables(
    connection: sqlite3.Connection, *, target_eas: list[int] | None = None,
    slot_index: int | None = None, abi: str | None = None,
    limit: int = 100, include_stale: bool = False,
) -> dict[str, Any]:
    if limit < 0:
        raise ValueError("limit must be non-negative")
    targets = list(dict.fromkeys(int(ea) for ea in (target_eas or [])))
    if not targets and slot_index is None:
        raise ValueError("provide target_eas or slot_index")
    if slot_index is not None and slot_index < 0:
        raise ValueError("slot_index must be non-negative")
    clauses = []
    parameters: list[Any] = []
    if not include_stale:
        clauses.append("c.stale=0 AND s.stale=0")
    if abi:
        clauses.append("c.abi=?"); parameters.append(abi)
    if slot_index is not None:
        clauses.append("s.slot_index=?"); parameters.append(slot_index)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = connection.execute(
        "SELECT c.candidate_id,c.address_point,c.abi,c.status,s.slot_index,s.byte_offset,s.target_ea,s.target_name,s.is_thunk,s.thunk_target_ea "
        "FROM vtable_candidates c JOIN vtable_slots s USING(candidate_id)" + where +
        " ORDER BY c.address_point,s.slot_index", parameters,
    ).fetchall()
    grouped: dict[str, dict[str, Any]] = {}
    target_slots: dict[str, set[int]] = defaultdict(set)
    wanted = set(targets)
    for row in rows:
        target = ida_ea(row["target_ea"]) if row["target_ea"] is not None else None
        if wanted and target not in wanted:
            continue
        key = row["candidate_id"]
        item = grouped.setdefault(key, {"candidate_id": key, "address_point": ida_ea(row["address_point"]),
            "address_point_hex": f"0x{ida_ea(row['address_point']):X}", "abi": row["abi"], "status": row["status"], "matching_slots": []})
        item["matching_slots"].append({"slot_index": row["slot_index"], "byte_offset": row["byte_offset"],
            "target_ea": target, "target_ea_hex": f"0x{target:X}" if target is not None else None,
            "target_name": row["target_name"], "is_thunk": bool(row["is_thunk"]),
            "thunk_target_ea": ida_ea(row["thunk_target_ea"]) if row["thunk_target_ea"] is not None else None})
        if target in wanted:
            target_slots[key].add(target)
    items = [item for key, item in grouped.items() if wanted.issubset(target_slots[key])]
    items = items[:limit] if limit else items
    return {"count": len(items), "truncated": bool(limit and len(grouped) > limit),
            "query": {"target_eas": targets, "slot_index": slot_index, "abi": abi}, "items": items}


def _decode_json(value: str | None) -> dict[str, Any]:
    try:
        result = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return result if isinstance(result, dict) else {}


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(value, dict):
        return
    yield value
    for key in ("operand", "instruction", "l", "r", "d"):
        child = value.get(key)
        if isinstance(child, dict):
            yield from _walk(child)
    for child in value.get("arguments", []):
        yield from _walk(child)


def _key(operand: dict[str, Any]) -> tuple[str, int] | None:
    if operand.get("kind") != "register" or operand.get("value_number") is None:
        return None
    return ("register", int(operand["value_number"]))


def _constant(operand: dict[str, Any]) -> int | None:
    if operand.get("kind") == "number" and isinstance(operand.get("value"), int):
        return int(operand["value"])
    return None


def _address_expression(operand: dict[str, Any]) -> dict[str, Any] | None:
    if operand.get("kind") == "register":
        return {"base": operand, "offset": 0}
    if operand.get("kind") != "nested":
        return None
    instruction = operand.get("instruction")
    if not isinstance(instruction, dict):
        return None
    opcode = instruction.get("opcode")
    left, right = instruction.get("l", {}), instruction.get("r", {})
    if opcode in ("add", "sub"):
        amount = _constant(right)
        base = left
        sign = -1 if opcode == "sub" else 1
        if amount is None and opcode == "add":
            amount = _constant(left)
            base = right
        if amount is None:
            return None
        return {"base": base, "offset": sign * amount, "address_ea": instruction.get("ea")}
    return None


def _instructions_for_function(connection: sqlite3.Connection, function_ea: int) -> list[dict[str, Any]]:
    result = []
    for row in connection.execute(
        "SELECT block_serial,ordinal,ea,opcode,text,l_json,r_json,d_json FROM micro_instructions "
        "WHERE function_ea=? ORDER BY block_serial,ordinal", (sqlite_ea(function_ea),),
    ):
        result.append({"block_serial": row[0], "ordinal": row[1], "ea": ida_ea(row[2]) if row[2] is not None else None,
            "opcode": row[3], "text": row[4], "l": _decode_json(row[5]), "r": _decode_json(row[6]),
            "d": _decode_json(row[7])})
    return result


def _trace_vcall_pattern(instructions: list[dict[str, Any]], call: dict[str, Any]) -> dict[str, Any] | None:
    definitions: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for instruction in instructions:
        key = _key(instruction.get("d", {}))
        if key is not None:
            definitions[key].append(instruction)

    def resolve_load(value: dict[str, Any], visited: set[tuple[str, int]]) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        key = _key(value)
        if key is None or key in visited:
            return None
        visited.add(key)
        candidates = [item for item in definitions.get(key, []) if
            (item["block_serial"] == call["block_serial"] and item["ordinal"] < call["ordinal"])
            or (item["block_serial"] != call["block_serial"] and call.get("ea") is not None
                and item.get("ea") is not None and item["ea"] < call["ea"])]
        if len(candidates) != 1:
            return None
        definition = candidates[0]
        if definition["opcode"] == "ldx":
            return definition, [definition]
        if definition["opcode"] == "mov":
            source = definition.get("l", {})
            if _key(source) is None:
                return None
            result = resolve_load(source, visited)
            if result is None:
                return None
            load, chain = result
            return load, [definition, *chain]
        return None

    # In IDA microcode icall stores the indirect callee in r on supported
    # architectures. Nested callee expressions are handled without text parsing.
    callee = call.get("r", {}) if call.get("r", {}).get("kind") != "empty" else call.get("l", {})
    slot_result = resolve_load(callee, set())
    slot_chain: list[dict[str, Any]] = []
    if slot_result is None:
        if callee.get("kind") == "nested" and isinstance(callee.get("instruction"), dict):
            nested = callee["instruction"]
            if nested.get("opcode") == "ldx":
                slot_load = {**nested, "opcode": "ldx", "ea": nested.get("ea"), "l": nested.get("l", {}),
                             "r": nested.get("r", {}), "d": nested.get("d", {})}
                slot_result = (slot_load, [slot_load])
    if slot_result is None:
        return None
    slot_load, slot_chain = slot_result
    slot_address = _address_expression(slot_load.get("r", {}))
    if slot_address is None or slot_address["offset"] < 0:
        return None
    vptr_value = slot_address["base"]
    vptr_result = resolve_load(vptr_value, set())
    if vptr_result is None:
        return None
    vptr_load, vptr_chain = vptr_result
    object_address = _address_expression(vptr_load.get("r", {}))
    if object_address is None:
        return None
    receiver = object_address["base"]
    if receiver.get("kind") not in ("register", "local", "stack", "global"):
        return None
    return {
        "receiver": receiver,
        "vptr_offset": object_address["offset"],
        "slot_offset": slot_address["offset"],
        "vptr_load_ea": vptr_load.get("ea"),
        "slot_load_ea": slot_load.get("ea"),
        "definition_chain": [{"block_serial": item["block_serial"], "ordinal": item["ordinal"],
            "ea": item.get("ea"), "opcode": item["opcode"], "text": item["text"]}
            for item in [*vptr_chain, *slot_chain]],
        "callee_operand": callee,
        "basis": "two_dependent_indirect_loads_in_exported_microcode",
        "control_flow_dominance_verified": False,
        "cxx_virtual_call_confirmed": False,
    }


def build_vcall_index(
    connection: sqlite3.Connection, *, function_eas: list[int],
    max_calls: int = 100000,
) -> dict[str, Any]:
    if max_calls < 1:
        raise ValueError("max_calls must be positive")
    selected = sorted(set(int(ea) for ea in function_eas))
    snapshot = _source_hash(connection, "vcall", selected)
    scope = {"function_eas": selected, "max_calls": max_calls}
    run_id = _id("VC", {"source": snapshot, "scope": scope, "detector": VCALL_DETECTOR_VERSION})
    existing = connection.execute("SELECT status,source_snapshot_hash,result_json FROM vcall_runs WHERE run_id=?", (run_id,)).fetchone()
    if existing is not None and existing["source_snapshot_hash"] == snapshot:
        with connection:
            connection.execute("UPDATE vcall_runs SET status='ok' WHERE run_id=?", (run_id,))
            connection.execute("UPDATE vcall_sites SET stale=0 WHERE run_id=?", (run_id,))
            connection.execute("UPDATE vcall_targets SET stale=0 WHERE call_id IN (SELECT call_id FROM vcall_sites WHERE run_id=?)", (run_id,))
            connection.execute("UPDATE receiver_flows SET stale=0 WHERE call_id IN (SELECT call_id FROM vcall_sites WHERE run_id=?)", (run_id,))
        return {"run_id": run_id, "cached": True, **json.loads(existing["result_json"])}

    missing = []
    failures = []
    sites: list[dict[str, Any]] = []
    for function_ea in selected:
        summary = connection.execute("SELECT status FROM microcode WHERE function_ea=?", (sqlite_ea(function_ea),)).fetchone()
        if summary is None:
            missing.append(function_ea); continue
        if summary["status"] != "ok":
            failures.append({"function_ea": function_ea, "status": summary["status"]}); continue
        instructions = _instructions_for_function(connection, function_ea)
        for instruction in instructions:
            if instruction["opcode"] != "icall":
                continue
            pattern = _trace_vcall_pattern(instructions, instruction)
            call_id = _id("VCALL", {"run": run_id, "function": function_ea,
                "block": instruction["block_serial"], "ordinal": instruction["ordinal"]})
            site = {
                "call_id": call_id, "run_id": run_id, "call_ea": instruction["ea"],
                "function_ea": function_ea, "block_serial": instruction["block_serial"],
                "ordinal": instruction["ordinal"], "kind": "indirect_call",
                "status": "vtable_pattern_candidate" if pattern else "indirect_unknown",
                "opcode": instruction["opcode"], "receiver": pattern.get("receiver", {}) if pattern else {},
                "callee": pattern or {"operand_l": instruction["l"], "operand_r": instruction["r"]},
                "slot_offset": pattern.get("slot_offset") if pattern else None,
                "pointer_size": 8 if get_metadata(connection, "bitness", 64) == 64 else 4,
                "evidence": {"instruction": instruction["text"], "microcode_source": "micro_instructions",
                    "source_snapshot_hash": snapshot, "pattern": pattern},
                "source_snapshot_hash": snapshot,
            }
            sites.append(site)
            if len(sites) >= max_calls:
                break
        if len(sites) >= max_calls:
            break

    now = utc_now()
    result = {"site_count": len(sites), "pattern_candidate_count": sum(s["status"] == "vtable_pattern_candidate" for s in sites),
        "unknown_indirect_count": sum(s["status"] == "indirect_unknown" for s in sites),
        "coverage": {"selected_functions": len(selected), "functions_missing_microcode": missing,
            "functions_with_export_errors": failures, "candidate_limit": max_calls,
            "truncated": len(sites) >= max_calls}, "scope": scope, "source_snapshot_hash": snapshot}
    with connection:
        if selected:
            placeholders = ",".join("?" for _ in selected)
            stored_selected = [sqlite_ea(ea) for ea in selected]
            affected_runs = [row[0] for row in connection.execute(
                f"SELECT DISTINCT run_id FROM vcall_sites WHERE function_ea IN ({placeholders}) AND stale=0",
                stored_selected)]
            connection.execute(f"UPDATE vcall_sites SET stale=1 WHERE function_ea IN ({placeholders}) AND stale=0",
                               stored_selected)
            connection.execute(f"UPDATE vcall_targets SET stale=1 WHERE call_id IN "
                f"(SELECT call_id FROM vcall_sites WHERE function_ea IN ({placeholders})) AND stale=0",
                stored_selected)
            connection.execute(f"UPDATE receiver_flows SET stale=1 WHERE call_id IN "
                f"(SELECT call_id FROM vcall_sites WHERE function_ea IN ({placeholders})) AND stale=0",
                stored_selected)
            if affected_runs:
                run_placeholders = ",".join("?" for _ in affected_runs)
                connection.execute(f"UPDATE vcall_runs SET status='stale' WHERE run_id IN ({run_placeholders})",
                                   affected_runs)
        connection.execute("INSERT INTO vcall_runs(run_id,source_snapshot_hash,scope_json,detector_version,status,result_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, snapshot, _json(scope), VCALL_DETECTOR_VERSION, "ok", _json(result), now))
        connection.executemany(
            "INSERT INTO vcall_sites(call_id,run_id,call_ea,function_ea,block_serial,ordinal,kind,status,opcode,receiver_json,callee_json,slot_offset,pointer_size,evidence_json,source_snapshot_hash,stale,created_at) "
            "VALUES(:call_id,:run_id,:call_ea,:function_ea,:block_serial,:ordinal,:kind,:status,:opcode,:receiver_json,:callee_json,:slot_offset,:pointer_size,:evidence_json,:source_snapshot_hash,0,:created_at)",
            [{**site, "call_ea": sqlite_ea(site["call_ea"]) if site["call_ea"] is not None else None,
              "function_ea": sqlite_ea(site["function_ea"]), "receiver_json": _json(site["receiver"]),
              "callee_json": _json(site["callee"]), "evidence_json": _json(site["evidence"]), "created_at": now}
             for site in sites],
        )
    return {"run_id": run_id, "cached": False, **result}


def list_vcalls(
    connection: sqlite3.Connection, *, function_ea: int | None = None,
    status: str | None = None, limit: int = 100, offset: int = 0,
    include_stale: bool = False,
) -> dict[str, Any]:
    if limit < 0 or offset < 0:
        raise ValueError("limit and offset must be non-negative")
    clauses, parameters = [], []
    if not include_stale:
        clauses.append("stale=0")
    if function_ea is not None:
        clauses.append("function_ea=?"); parameters.append(sqlite_ea(function_ea))
    if status:
        clauses.append("status=?"); parameters.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    total = connection.execute("SELECT count(*) FROM vcall_sites" + where, parameters).fetchone()[0]
    sql_limit = -1 if limit == 0 else limit
    rows = connection.execute("SELECT * FROM vcall_sites" + where +
        " ORDER BY function_ea,block_serial,ordinal LIMIT ? OFFSET ?", (*parameters, sql_limit, offset)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["call_ea"] = ida_ea(item["call_ea"]) if item["call_ea"] is not None else None
        item["call_ea_hex"] = f"0x{item['call_ea']:X}" if item["call_ea"] is not None else None
        item["function_ea"] = ida_ea(item["function_ea"])
        item["function_ea_hex"] = f"0x{item['function_ea']:X}"
        item["receiver"] = json.loads(item.pop("receiver_json"))
        item["callee"] = json.loads(item.pop("callee_json"))
        item["evidence"] = json.loads(item.pop("evidence_json"))
        items.append(item)
    return {"count": len(items), "total": total, "truncated": offset + len(items) < total,
        "include_stale": include_stale, "items": items}


def _resolve_vcall_targets(connection: sqlite3.Connection, call_id: str) -> dict[str, Any]:
    site = connection.execute("SELECT * FROM vcall_sites WHERE call_id=? AND stale=0", (call_id,)).fetchone()
    if site is None:
        raise ValueError(f"current virtual-call site not found: {call_id}")
    if site["status"] != "vtable_pattern_candidate" or site["slot_offset"] is None:
        return {"call_id": call_id, "resolution_status": "unknown", "targets": [],
            "reason": "the indirect call did not produce a complete two-load vtable-shaped pattern"}
    if site["slot_offset"] % site["pointer_size"]:
        return {"call_id": call_id, "resolution_status": "partial", "targets": [],
            "reason": "slot byte offset is not aligned to the recorded pointer width"}
    rows = connection.execute(
        "SELECT s.candidate_id,s.slot_index,s.byte_offset,s.target_ea,s.target_name,s.is_thunk,s.thunk_target_ea,c.address_point,c.abi "
        "FROM vtable_slots s JOIN vtable_candidates c USING(candidate_id) "
        "WHERE s.stale=0 AND c.stale=0 AND s.target_ea IS NOT NULL AND s.target_kind IN ('function','code') "
        "AND s.byte_offset=? AND c.pointer_size=? ORDER BY c.address_point,s.slot_index",
        (site["slot_offset"], site["pointer_size"]),
    ).fetchall()
    targets = []
    for row in rows:
        target_ea = ida_ea(row["target_ea"]) if row["target_ea"] is not None else None
        targets.append({"candidate_id": row["candidate_id"], "address_point": ida_ea(row["address_point"]),
            "address_point_hex": f"0x{ida_ea(row['address_point']):X}", "abi": row["abi"],
            "slot_index": row["slot_index"], "byte_offset": row["byte_offset"],
            "target_ea": target_ea, "target_ea_hex": f"0x{target_ea:X}" if target_ea is not None else None,
            "target_name": row["target_name"], "is_thunk": bool(row["is_thunk"]),
            "thunk_target_ea": ida_ea(row["thunk_target_ea"]) if row["thunk_target_ea"] is not None else None,
            "status": "candidate", "reason": "slot offset matches an indexed table; receiver-to-table reachability is unproven"})
    status = "candidate_set" if targets else "unknown"
    reason = "matching indexed slots are candidates only; object identity and dynamic reachability are not resolved" if targets else "no current indexed table has this slot offset"
    return {"call_id": call_id, "resolution_status": status, "completeness": "partial",
        "targets": targets, "reason": reason,
        "unknown_frontier": ["receiver dynamic type", "receiver-to-address-point relation", "external or unindexed tables"]}


def analyze_vcall(connection: sqlite3.Connection, *, call_id: str | None = None, address: int | None = None) -> dict[str, Any]:
    if (call_id is None) == (address is None):
        raise ValueError("provide exactly one of call_id or address")
    if address is not None:
        row = connection.execute("SELECT call_id FROM vcall_sites WHERE call_ea=? AND stale=0 ORDER BY created_at DESC LIMIT 1",
                                 (sqlite_ea(address),)).fetchone()
        if row is None:
            raise ValueError(f"no current indirect-call site at 0x{address:X}; build the call index first")
        call_id = row[0]
    row = connection.execute("SELECT * FROM vcall_sites WHERE call_id=? AND stale=0", (call_id,)).fetchone()
    if row is None:
        raise ValueError(f"current virtual-call site not found: {call_id}")
    site = dict(row)
    site["call_ea"] = ida_ea(site["call_ea"]) if site["call_ea"] is not None else None
    site["function_ea"] = ida_ea(site["function_ea"])
    site["receiver"] = json.loads(site.pop("receiver_json"))
    site["callee"] = json.loads(site.pop("callee_json"))
    site["evidence"] = json.loads(site.pop("evidence_json"))
    resolution = _resolve_vcall_targets(connection, call_id)
    with connection:
        connection.execute("DELETE FROM vcall_targets WHERE call_id=?", (call_id,))
        for ordinal, target in enumerate(resolution["targets"]):
            target_id = _id("VCT", {"call": call_id, "target": target})
            connection.execute(
                "INSERT INTO vcall_targets(call_id,target_id,candidate_id,slot_index,target_ea,thunk_target_ea,status,reason,evidence_json,source_snapshot_hash,stale) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                (call_id,target_id,target["candidate_id"],target["slot_index"],
                 sqlite_ea(target["target_ea"]) if target["target_ea"] is not None else None,
                 sqlite_ea(target["thunk_target_ea"]) if target["thunk_target_ea"] is not None else None,
                 target["status"],target["reason"],_json(target),site["source_snapshot_hash"]),
            )
    return {"site": site, "resolution": resolution}


def show_vcall(connection: sqlite3.Connection, *, call_id: str | None = None, address: int | None = None,
               include_stale: bool = False) -> dict[str, Any]:
    if (call_id is None) == (address is None):
        raise ValueError("provide exactly one of call_id or address")
    if address is not None:
        clauses = ["call_ea=?"]
        parameters: list[Any] = [sqlite_ea(address)]
    else:
        clauses = ["call_id=?"]
        parameters = [call_id]
    if not include_stale:
        clauses.append("stale=0")
    row = connection.execute("SELECT * FROM vcall_sites WHERE " + " AND ".join(clauses) +
        " ORDER BY created_at DESC LIMIT 1", parameters).fetchone()
    if row is None:
        raise ValueError("virtual-call site not found")
    site = dict(row)
    site["call_ea"] = ida_ea(site["call_ea"]) if site["call_ea"] is not None else None
    site["call_ea_hex"] = f"0x{site['call_ea']:X}" if site["call_ea"] is not None else None
    site["function_ea"] = ida_ea(site["function_ea"])
    site["function_ea_hex"] = f"0x{site['function_ea']:X}"
    site["receiver"] = json.loads(site.pop("receiver_json"))
    site["callee"] = json.loads(site.pop("callee_json"))
    site["evidence"] = json.loads(site.pop("evidence_json"))
    targets = []
    for target in connection.execute("SELECT * FROM vcall_targets WHERE call_id=?" +
        ("" if include_stale else " AND stale=0") + " ORDER BY target_id", (site["call_id"],)):
        item = dict(target)
        item["target_ea"] = ida_ea(item["target_ea"]) if item["target_ea"] is not None else None
        item["thunk_target_ea"] = ida_ea(item["thunk_target_ea"]) if item["thunk_target_ea"] is not None else None
        item["evidence"] = json.loads(item.pop("evidence_json"))
        targets.append(item)
    flows = []
    for flow in connection.execute("SELECT * FROM receiver_flows WHERE call_id=?" +
        ("" if include_stale else " AND stale=0") + " ORDER BY path_order", (site["call_id"],)):
        item = dict(flow)
        item["node"] = json.loads(item.pop("node_json"))
        item["edge"] = json.loads(item.pop("edge_json"))
        flows.append(item)
    site["targets"] = targets
    site["receiver_flows"] = flows
    return site


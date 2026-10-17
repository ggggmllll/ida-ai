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

from .db import get_metadata, ida_ea, set_metadata, sqlite_ea, utc_now


VTABLE_PARSER_VERSION = "6"
VCALL_DETECTOR_VERSION = "3"
VPTR_WRITE_DETECTOR_VERSION = "1"
SUPPORTED_ABIS = ("itanium",)
MAX_RTTI_BASES = 128


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


def _classify_table_entry(target_kind: str, target_name: str | None, *, is_nullstub: bool,
                          is_thunk: bool, is_library: bool) -> str:
    """Describe observable slot-entry traits without inferring override semantics."""

    lowered = (target_name or "").casefold()
    if target_kind == "null":
        return "null_slot"
    if "__cxa_pure_virtual" in lowered or "_purecall" in lowered:
        return "pure_virtual_runtime_named"
    if "__cxa_deleted_virtual" in lowered:
        return "deleted_virtual_runtime_named"
    if is_nullstub:
        return "nullstub"
    if is_thunk and is_library:
        return "library_thunk"
    if is_thunk:
        return "thunk"
    if is_library:
        return "library_function"
    if target_kind == "function":
        return "function"
    if target_kind == "code":
        return "unclassified_code"
    if target_kind == "data":
        return "data_pointer"
    return "unknown"


def _identity(connection: sqlite3.Connection) -> dict[str, Any]:
    keys = ("root_filename", "input_path", "imagebase", "bitness", "big_endian")
    return {key: get_metadata(connection, key) for key in keys}


def _rows(connection: sqlite3.Connection, query: str, parameters: tuple = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, parameters)]


def _source_hash(connection: sqlite3.Connection, kind: str, function_eas: Iterable[int] | None = None,
                 *, include_rtti: bool = True) -> str:
    """Hash the exact durable inputs used by a virtual-analysis run."""

    identity = _identity(connection)
    scan_coverage = get_metadata(connection, "data_pointer_scan")
    if isinstance(scan_coverage, dict):
        scan_coverage = {key: value for key, value in scan_coverage.items() if key != "generated_at"}
    functions = _rows(connection,
        "SELECT start_ea,end_ea,name,demangled_name,signature,flags,is_library,is_thunk,thunk_target_ea,is_nullstub "
        "FROM functions ORDER BY start_ea")
    if kind == "vtable":
        payload = {
            "identity": identity,
            "segments": _rows(connection, "SELECT start_ea,end_ea,name,class_name,permissions,bitness FROM segments ORDER BY start_ea"),
            "functions": functions,
            "symbols": _rows(connection, "SELECT address,name,type FROM symbols ORDER BY address"),
            "data_pointer_slots": _rows(connection, "SELECT source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind FROM data_pointer_slots ORDER BY source_ea"),
            "data_pointer_scan": scan_coverage,
        }
        if include_rtti:
            base_hash = _digest(payload)
            active_run = get_metadata(connection, "active_rtti_run_id")
            if isinstance(active_run, str):
                rtti = connection.execute(
                    "SELECT input_snapshot_hash,descriptor_snapshot_hash FROM rtti_runs WHERE rtti_run_id=?",
                    (active_run,),
                ).fetchone()
                if rtti is not None and rtti["input_snapshot_hash"] == base_hash:
                    payload["rtti_descriptor_snapshot"] = {
                        "rtti_run_id": active_run,
                        "descriptor_snapshot_hash": rtti["descriptor_snapshot_hash"],
                    }
    elif kind == "vcall":
        selected = None if function_eas is None else {sqlite_ea(ea) for ea in function_eas}
        microcode = _rows(connection,
            "SELECT function_ea,maturity,backend,status,error,decompiler_version,instruction_count,content_hash,relations_json "
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


def _symbol_name_at(connection: sqlite3.Connection, address: int | None) -> str | None:
    if address is None:
        return None
    row = connection.execute("SELECT name FROM symbols WHERE address=?", (sqlite_ea(address),)).fetchone()
    return str(row[0]) if row is not None else None


def _resolve_itanium_typeinfo(connection: sqlite3.Connection, typeinfo_ea: int,
                              pointer_size: int) -> dict[str, Any]:
    """Resolve only the explicit Itanium RTTI symbols and pointer layout we can observe."""

    fields = connection.execute(
        "SELECT source_ea,target_ea,target_kind FROM data_pointer_slots WHERE source_ea IN (?,?)",
        (sqlite_ea(typeinfo_ea), sqlite_ea(typeinfo_ea + pointer_size)),
    ).fetchall()
    by_ea = {ida_ea(row["source_ea"]): row for row in fields}
    vptr = by_ea.get(typeinfo_ea)
    name_pointer = by_ea.get(typeinfo_ea + pointer_size)
    vptr_target = ida_ea(vptr["target_ea"]) if vptr is not None and vptr["target_ea"] is not None else None
    name_target = ida_ea(name_pointer["target_ea"]) if name_pointer is not None and name_pointer["target_ea"] is not None else None
    vptr_is_data = bool(vptr and vptr["target_kind"] == "data" and vptr_target is not None)
    name_is_data = bool(name_pointer and name_pointer["target_kind"] == "data" and name_target is not None)

    typeinfo_symbol = _symbol_name_at(connection, typeinfo_ea)
    type_name_symbol = _symbol_name_at(connection, name_target)
    typeinfo_vtable_symbol = None
    typeinfo_vtable_start = None
    descriptor_kind = None
    expected_vtable_start = vptr_target - 2 * pointer_size if vptr_target is not None else None
    if expected_vtable_start is not None and expected_vtable_start >= 0:
        possible_symbol = _symbol_name_at(connection, expected_vtable_start)
        if possible_symbol and possible_symbol.startswith("_ZTVN10__cxxabiv1"):
            typeinfo_vtable_symbol = possible_symbol
            typeinfo_vtable_start = expected_vtable_start
            for token, kind in (
                ("__vmi_class_type_infoE", "multiple_or_virtual_inheritance"),
                ("__si_class_type_infoE", "single_inheritance"),
                ("__class_type_infoE", "class_type_info"),
            ):
                if possible_symbol.endswith(token):
                    descriptor_kind = kind
                    break

    expected_type_name = ("_ZTS" + typeinfo_symbol[4:]
                          if typeinfo_symbol and typeinfo_symbol.startswith("_ZTI") else None)
    checks = {
        "typeinfo_symbol": bool(typeinfo_symbol and typeinfo_symbol.startswith("_ZTI")),
        "typeinfo_vptr_is_data_pointer": vptr_is_data,
        "typeinfo_vtable_symbol_matches_abi": typeinfo_vtable_symbol is not None,
        "recognized_typeinfo_descriptor": descriptor_kind is not None,
        "type_name_is_data_pointer": name_is_data,
        "type_name_symbol_matches_typeinfo": bool(expected_type_name and type_name_symbol == expected_type_name),
    }
    if all(checks.values()):
        status = "confirmed_itanium_typeinfo_layout"
    elif any(checks.values()):
        status = "candidate_itanium_typeinfo_layout"
    else:
        status = "unresolved"
    return {
        "status": status,
        "typeinfo_ea": typeinfo_ea,
        "typeinfo_symbol": typeinfo_symbol,
        "vptr_target_ea": vptr_target,
        "typeinfo_vtable_start_ea": typeinfo_vtable_start,
        "typeinfo_vtable_symbol": typeinfo_vtable_symbol,
        "descriptor_kind": descriptor_kind,
        "type_name_ea": name_target,
        "type_name_symbol": type_name_symbol,
        "expected_type_name_symbol": expected_type_name,
        "checks": checks,
        "scope_note": "RTTI object/layout evidence only; does not prove class hierarchy, object dynamic type, or call reachability",
    }


def parse_itanium_typeinfo_descriptor(
    *, typeinfo_ea: int, descriptor_kind: str | None, raw: bytes,
    pointer_size: int, byteorder: str, max_bases: int = MAX_RTTI_BASES,
    type_name_ea: int | None = None, type_name: str | None = None,
) -> dict[str, Any]:
    """Parse a bounded Itanium type_info payload from explicitly read bytes.

    This helper does not infer descriptor kinds from object shape. The caller
    must identify the ABI descriptor vtable independently; unknown layouts
    stay unknown. The returned bases are structural RTTI edges, not proof of
    an object's dynamic type or of a vtable's runtime reachability.
    """

    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    if byteorder not in ("little", "big"):
        raise ValueError("byteorder must be little or big")
    if max_bases < 0 or max_bases > 4096:
        raise ValueError("max_bases must be between 0 and 4096")
    raw = bytes(raw)

    def read_uint(offset: int, width: int) -> int | None:
        if offset < 0 or offset + width > len(raw):
            return None
        return int.from_bytes(raw[offset:offset + width], byteorder, signed=False)

    vptr = read_uint(0, pointer_size)
    name_pointer = read_uint(pointer_size, pointer_size)
    evidence = {
        "raw_bytes_hex": raw.hex(),
        "raw_bytes_length": len(raw),
        "header": {
            "vptr_ea": vptr,
            "name_pointer_ea": name_pointer,
            "typeinfo_ea": int(typeinfo_ea),
        },
        "maximum_bases": max_bases,
        "scope_note": "bounded Itanium RTTI descriptor bytes; base edges do not prove object dynamic type",
    }
    result: dict[str, Any] = {
        "typeinfo_ea": int(typeinfo_ea),
        "descriptor_kind": descriptor_kind,
        "parse_status": "unknown_descriptor_kind",
        "type_name_ea": type_name_ea if type_name_ea is not None else name_pointer,
        "type_name": type_name,
        "flags": None,
        "base_count": None,
        "bases": [],
        "evidence": evidence,
    }
    if vptr is None or name_pointer is None:
        result["parse_status"] = "truncated_typeinfo_header"
        return result

    base_offset = 2 * pointer_size
    if descriptor_kind == "class_type_info":
        result["parse_status"] = "parsed_no_bases"
        result["base_count"] = 0
        return result
    if descriptor_kind == "single_inheritance":
        base = read_uint(base_offset, pointer_size)
        if base is None:
            result["parse_status"] = "truncated_single_base_descriptor"
            return result
        result["base_count"] = 1
        result["bases"] = [{
            "typeinfo_ea": base,
            "inheritance_kind": "single_public_nonvirtual_descriptor",
            "byte_offset": None,
            "offset_evidence": "not_encoded_in___si_class_type_info",
        }]
        result["parse_status"] = "parsed"
        evidence["base_typeinfo_pointer_ea"] = int(typeinfo_ea) + base_offset
        return result
    if descriptor_kind != "multiple_or_virtual_inheritance":
        return result

    flags = read_uint(base_offset, 4)
    count = read_uint(base_offset + 4, 4)
    if flags is None or count is None:
        result["parse_status"] = "truncated_vmi_header"
        return result
    result["flags"] = flags
    result["base_count"] = count
    result["evidence"]["vmi_header"] = {
        "flags_ea": int(typeinfo_ea) + base_offset,
        "base_count_ea": int(typeinfo_ea) + base_offset + 4,
        "flags": flags,
        "base_count": count,
        "diamond_shaped": bool(flags & 0x2),
        "non_diamond_repeat": bool(flags & 0x1),
        "unknown_flag_bits": flags & ~0x3,
    }
    bounded_count = min(count, max_bases)
    stride = 2 * pointer_size
    entries_start = base_offset + 8
    bases = []
    for index in range(bounded_count):
        entry = entries_start + index * stride
        base = read_uint(entry, pointer_size)
        offset_flags = read_uint(entry + pointer_size, pointer_size)
        if base is None or offset_flags is None:
            result["parse_status"] = "truncated_base_array"
            result["bases"] = bases
            result["evidence"]["decoded_base_count"] = len(bases)
            return result
        sign_bit = 1 << (pointer_size * 8 - 1)
        signed_offset_flags = offset_flags - (1 << (pointer_size * 8)) if offset_flags & sign_bit else offset_flags
        base_flags = offset_flags & 0xFF
        bases.append({
            "index": index,
            "typeinfo_ea": base,
            "offset_flags": offset_flags,
            "offset_flags_signed": signed_offset_flags,
            "byte_offset": signed_offset_flags >> 8,
            "flags": base_flags,
            "is_virtual": bool(base_flags & 0x1),
            "is_public": bool(base_flags & 0x2),
            "unknown_flag_bits": base_flags & ~0x3,
            "typeinfo_pointer_ea": int(typeinfo_ea) + entry,
            "offset_flags_ea": int(typeinfo_ea) + entry + pointer_size,
        })
    result["bases"] = bases
    result["evidence"]["decoded_base_count"] = len(bases)
    if count > max_bases:
        result["parse_status"] = "truncated_base_limit"
        result["evidence"]["omitted_base_count"] = count - max_bases
    else:
        result["parse_status"] = "parsed"
    return result


def _active_rtti_descriptors(connection: sqlite3.Connection, input_snapshot_hash: str) -> tuple[str | None, list[dict[str, Any]]]:
    run_id = get_metadata(connection, "active_rtti_run_id")
    if not isinstance(run_id, str):
        return None, []
    run = connection.execute(
        "SELECT input_snapshot_hash,descriptor_snapshot_hash FROM rtti_runs WHERE rtti_run_id=?",
        (run_id,),
    ).fetchone()
    if run is None or run["input_snapshot_hash"] != input_snapshot_hash:
        return None, []
    rows = _rows(connection,
        "SELECT typeinfo_ea,descriptor_kind,parse_status,type_name_ea,type_name,flags,base_count,bases_json,evidence_json "
        "FROM rtti_typeinfos WHERE rtti_run_id=? ORDER BY typeinfo_ea", (run_id,))
    for row in rows:
        row["typeinfo_ea"] = ida_ea(row["typeinfo_ea"])
        row["type_name_ea"] = ida_ea(row["type_name_ea"]) if row["type_name_ea"] is not None else None
        row["bases"] = json.loads(row.pop("bases_json"))
        row["evidence"] = json.loads(row.pop("evidence_json"))
    return run_id, rows


def store_itanium_rtti_descriptors(
    connection: sqlite3.Connection, *, input_snapshot_hash: str,
    descriptors: list[dict[str, Any]], coverage: dict[str, Any],
) -> dict[str, Any]:
    """Persist bounded IDA byte reads as an immutable RTTI observation run."""

    normalized = []
    parsed = []
    for item in descriptors:
        raw_hex = str(item.get("raw_hex") or "")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            raw = b""
        decoded = parse_itanium_typeinfo_descriptor(
            typeinfo_ea=int(item["typeinfo_ea"]),
            descriptor_kind=item.get("descriptor_kind"), raw=raw,
            pointer_size=int(coverage.get("pointer_size", 8)),
            byteorder=str(coverage.get("byteorder", "little")),
            max_bases=int(coverage.get("max_bases", MAX_RTTI_BASES)),
            type_name_ea=int(item["type_name_ea"]) if item.get("type_name_ea") is not None else None,
            type_name=item.get("type_name"),
        )
        decoded["evidence"].update({
            "descriptor_symbol": item.get("descriptor_symbol"),
            "typeinfo_symbol": item.get("symbol"),
            "type_name_symbol": item.get("type_name_symbol"),
            "ida_read_status": item.get("read_status"),
        })
        normalized.append({
            "typeinfo_ea": int(item["typeinfo_ea"]),
            "descriptor_kind": item.get("descriptor_kind"),
            "raw_hex": raw_hex,
            "read_status": item.get("read_status"),
            "decoded": decoded,
        })
        parsed.append(decoded)
    descriptor_snapshot_hash = _digest({"coverage": coverage, "descriptors": normalized})
    rtti_run_id = _id("RTTI", {"input": input_snapshot_hash,
        "descriptor_snapshot": descriptor_snapshot_hash, "parser": VTABLE_PARSER_VERSION})
    existing = connection.execute("SELECT rtti_run_id FROM rtti_runs WHERE rtti_run_id=?", (rtti_run_id,)).fetchone()
    result = {
        "rtti_run_id": rtti_run_id,
        "input_snapshot_hash": input_snapshot_hash,
        "descriptor_snapshot_hash": descriptor_snapshot_hash,
        "typeinfo_count": len(parsed),
        "parsed_count": sum(item["parse_status"] in ("parsed", "parsed_no_bases") for item in parsed),
        "unknown_count": sum(item["parse_status"] == "unknown_descriptor_kind" for item in parsed),
        "coverage": coverage,
    }
    with connection:
        if existing is None:
            connection.execute(
                "INSERT INTO rtti_runs(rtti_run_id,input_snapshot_hash,descriptor_snapshot_hash,status,result_json,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (rtti_run_id, input_snapshot_hash, descriptor_snapshot_hash,
                 "partial" if coverage.get("truncated") else "ok", _json(result), utc_now()),
            )
            connection.executemany(
                "INSERT INTO rtti_typeinfos(rtti_run_id,typeinfo_ea,descriptor_kind,parse_status,type_name_ea,type_name,flags,base_count,bases_json,evidence_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(rtti_run_id, sqlite_ea(item["typeinfo_ea"]), item["descriptor_kind"],
                  item["parse_status"], sqlite_ea(item["type_name_ea"]) if item["type_name_ea"] is not None else None,
                  item["type_name"], item["flags"], item["base_count"], _json(item["bases"]), _json(item["evidence"]))
                 for item in parsed],
            )
        set_metadata(connection, {"active_rtti_run_id": rtti_run_id})
    return {**result, "cached": existing is not None}


def _has_itanium_prefix(connection: sqlite3.Connection, address_point: int, pointer_size: int) -> dict[str, Any] | None:
    """Return an Itanium address-point prefix observation and its RTTI evidence."""

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
    if offset_row["target_kind"] in ("function", "code"):
        return None
    offset_to_top = ida_ea(offset_row["raw_value"])
    if offset_to_top & (1 << (pointer_size * 8 - 1)):
        offset_to_top -= 1 << (pointer_size * 8)
    typeinfo_target = typeinfo_row["target_ea"]
    if typeinfo_target is None or typeinfo_row["target_kind"] != "data":
        return None
    if offset_to_top != 0 and abs(offset_to_top) > 0x10000:
        return None
    typeinfo_evidence = _resolve_itanium_typeinfo(connection, ida_ea(typeinfo_target), pointer_size)
    return {
        "layout": "itanium_address_point_prefix_candidate",
        "offset_to_top_ea": address_point - 2 * pointer_size,
        "offset_to_top": offset_to_top,
        "typeinfo_pointer_ea": address_point - pointer_size,
        "typeinfo_target_ea": ida_ea(typeinfo_target),
        "status": "heuristic_candidate",
        "typeinfo": typeinfo_evidence,
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
    rtti_run_id, rtti_descriptors = _active_rtti_descriptors(
        connection, _source_hash(connection, "vtable", include_rtti=False))
    rtti_by_ea = {item["typeinfo_ea"]: item for item in rtti_descriptors}
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
        "SELECT start_ea,name,demangled_name,is_library,is_thunk,thunk_target_ea,is_nullstub FROM functions")}

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
            typeinfo = (prefix or {}).get("typeinfo") or {}
            typeinfo_descriptor = rtti_by_ea.get(typeinfo.get("typeinfo_ea"))
            table_symbol = _symbol_name_at(connection, address_point - 2 * pointer_size) if prefix else None
            typeinfo_symbol = typeinfo.get("typeinfo_symbol")
            expected_table_symbol = ("_ZTV" + typeinfo_symbol[4:]
                                     if typeinfo_symbol and typeinfo_symbol.startswith("_ZTI") else None)
            table_symbol_matches_typeinfo = bool(expected_table_symbol and table_symbol == expected_table_symbol)
            evidence = {
                "method": "contiguous_aligned_mapped_function_pointer_sequence",
                "status": "heuristic_candidate",
                "function_slot_count": run_function_count,
                "total_slot_count": len(run_slots),
                "rtti_confirmed": False,
                "typeinfo_layout_confirmed": typeinfo.get("status") == "confirmed_itanium_typeinfo_layout",
                "address_point_symbol_match": table_symbol_matches_typeinfo,
                "table_symbol": table_symbol,
                "expected_table_symbol": expected_table_symbol,
                "address_point_prefix": prefix,
                "address_point_boundary": ("two_word_prefix_with_matching_vtable_symbol"
                    if table_symbol_matches_typeinfo else "two_word_itanium_prefix_candidate"
                    if prefix is not None else "function_sequence_start_unconfirmed"),
                "rtti_run_id": rtti_run_id,
                "typeinfo_descriptor": typeinfo_descriptor,
                "class_relationship_evidence": (typeinfo_descriptor or {}).get("bases", []),
                "class_relationship_status": (
                    "descriptor_base_edges_observed" if typeinfo_descriptor
                    and typeinfo_descriptor.get("parse_status") == "parsed"
                    and typeinfo_descriptor.get("bases") else
                    "descriptor_has_no_base_edges" if typeinfo_descriptor
                    and typeinfo_descriptor.get("parse_status") == "parsed_no_bases" else
                    "unknown_or_unavailable"),
                "class_relationship_scope_note": (
                    "RTTI descriptor edges are explicit metadata; they do not prove this table is active for an object"),
                "limits": {"max_slots": max_slots, "truncated": len(run_slots) >= max_slots},
            }
            candidates.append({
                "candidate_id": candidate_id,
                "table_address": (address_point - 2 * pointer_size if prefix is not None else address_point),
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
                target_name = ((target_func["demangled_name"] or target_func["name"])
                               if target_func else item.get("target_name"))
                is_nullstub = bool(target_func and target_func["is_nullstub"])
                is_thunk = bool(target_func and target_func["is_thunk"])
                is_library = bool(target_func and target_func["is_library"])
                normalized_slots.append({
                    "candidate_id": candidate_id, "slot_index": index,
                    "byte_offset": index * pointer_size,
                    "entry_address": ida_ea(item["source_ea"]),
                    "raw_value": ida_ea(item["raw_value"]),
                    "target_ea": ida_ea(target) if target is not None else None,
                    "target_kind": item["target_kind"],
                    "target_name": target_name,
                    "entry_classification": _classify_table_entry(item["target_kind"], target_name,
                        is_nullstub=is_nullstub, is_thunk=is_thunk, is_library=is_library),
                    "is_nullstub": int(is_nullstub), "is_library": int(is_library),
                    "is_thunk": int(is_thunk),
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
        "rtti_run_id": rtti_run_id,
        "rtti_typeinfo_count": len(rtti_descriptors),
        "coverage": {"pointer_observations": sum(item["target_kind"] != "scalar" for item in pointer_rows),
                     "scalar_prefix_observations": sum(item["target_kind"] == "scalar" for item in pointer_rows),
                     "source": "data_pointer_slots",
                     "rtti_parsed": any(item["parse_status"] in ("parsed", "parsed_no_bases")
                                          for item in rtti_descriptors),
                     "rtti_typeinfos_seen": len(rtti_descriptors),
                     "rtti_base_edges_observed": sum(len(item["bases"]) for item in rtti_descriptors),
                     "rtti_unknown_descriptors": sum(item["parse_status"] == "unknown_descriptor_kind"
                                                     for item in rtti_descriptors),
                     "typeinfo_symbol_layouts_checked": sum(
                         bool((candidate["evidence"].get("address_point_prefix") or {}).get("typeinfo"))
                         for candidate in candidates),
                     "typeinfo_layout_confirmed": sum(
                         bool(candidate["evidence"].get("typeinfo_layout_confirmed")) for candidate in candidates),
                     "candidate_tables_remain_heuristic": True,
                     "data_pointer_scan": get_metadata(connection, "data_pointer_scan")},
        "scope": scope,
    }
    with connection:
        connection.execute("UPDATE vtable_candidates SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vtable_slots SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vtable_evidence SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vcall_targets SET stale=1 WHERE stale=0")
        connection.execute("UPDATE receiver_flows SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vptr_writes SET stale=1 WHERE stale=0")
        connection.execute("UPDATE vptr_write_runs SET status='stale' WHERE status NOT IN ('stale','error')")
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
                "INSERT INTO vtable_slots(candidate_id,slot_index,byte_offset,entry_address,raw_value,target_ea,target_kind,target_name,entry_classification,is_nullstub,is_library,is_thunk,thunk_target_ea,thunk_chain_json,adjustment_json,evidence_json,source_snapshot_hash,stale) "
                "VALUES(:candidate_id,:slot_index,:byte_offset,:entry_address,:raw_value,:target_ea,:target_kind,:target_name,:entry_classification,:is_nullstub,:is_library,:is_thunk,:thunk_target_ea,:thunk_chain_json,:adjustment_json,:evidence_json,:source_snapshot_hash,0)",
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
        "SELECT c.candidate_id,c.address_point,c.abi,c.status,s.slot_index,s.byte_offset,s.target_ea,s.target_name,"
        "s.entry_classification,s.is_nullstub,s.is_library,s.is_thunk,s.thunk_target_ea "
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
            "target_name": row["target_name"], "entry_classification": row["entry_classification"],
            "is_nullstub": bool(row["is_nullstub"]), "is_library": bool(row["is_library"]),
            "is_thunk": bool(row["is_thunk"]),
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


def _operand_truncated(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("truncated")) or any(_operand_truncated(child) for child in value.values())
    if isinstance(value, list):
        return any(_operand_truncated(child) for child in value)
    return False


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
    if operand.get("kind") == "register" and operand.get("value_number") is not None:
        return ("register", int(operand["value_number"]))
    if operand.get("kind") == "local" and operand.get("local_index") is not None:
        return ("local", int(operand["local_index"]))
    if operand.get("kind") == "stack" and operand.get("stack_offset") is not None:
        return ("stack", int(operand["stack_offset"]))
    return None


def _constant(operand: dict[str, Any]) -> int | None:
    if operand.get("kind") == "number" and isinstance(operand.get("value"), int):
        return int(operand["value"])
    return None


def _address_expression(operand: dict[str, Any]) -> dict[str, Any] | None:
    if operand.get("kind") in ("register", "local", "stack", "global"):
        return {"base": operand, "offset": 0}
    if operand.get("kind") != "nested":
        return None
    instruction = operand.get("instruction")
    if not isinstance(instruction, dict):
        return None
    opcode = instruction.get("opcode")
    left, right = instruction.get("l", {}), instruction.get("r", {})
    if opcode in ("add", "sub"):
        amount = _offset_constant(right)
        base = left
        sign = -1 if opcode == "sub" else 1
        if amount is None and opcode == "add":
            amount = _offset_constant(left)
            base = right
        if amount is None:
            return None
        return {"base": base, "offset": sign * amount, "address_ea": instruction.get("ea")}
    return None


def _offset_constant(operand: dict[str, Any]) -> int | None:
    value = _constant(operand)
    if value is None:
        return None
    width = int(operand.get("size") or 0) * 8
    if width and value & (1 << (width - 1)):
        value -= 1 << width
    return value


def _operand_identity(operand: dict[str, Any]) -> tuple[Any, int] | None:
    expression = _address_expression(operand)
    if expression is None:
        return None
    base = expression["base"]
    key = _key(base)
    if key is not None:
        return key, int(expression["offset"])
    kind = base.get("kind")
    if kind == "global" and base.get("address") is not None:
        return ("global", int(base["address"])), int(expression["offset"])
    if kind == "local" and base.get("local_index") is not None:
        return ("local", int(base["local_index"])), int(expression["offset"])
    if kind == "stack" and base.get("stack_offset") is not None:
        return ("stack", int(base["stack_offset"])), int(expression["offset"])
    return None


def _call_arglist(call: dict[str, Any]) -> dict[str, Any] | None:
    for root in ("d", "l", "r"):
        for operand in _walk(call.get(root, {})):
            if operand.get("kind") == "arglist" and isinstance(operand.get("arguments"), list):
                return operand
    return None


def _receiver_binding(call: dict[str, Any], receiver: dict[str, Any],
                      receiver_offset: int) -> dict[str, Any]:
    arglist = _call_arglist(call)
    if arglist is None:
        return {"status": "not_observed", "reason": "icall has no exported argument list"}
    receiver_identity = _operand_identity(receiver)
    if receiver_identity is None:
        return {"status": "unresolved", "reason": "receiver expression has no stable identity"}
    expected_offset = receiver_identity[1] + int(receiver_offset)
    matches = []
    for index, argument in enumerate(arglist["arguments"]):
        identity = _operand_identity(argument)
        if identity is not None and identity[0] == receiver_identity[0]:
            matches.append({"argument_index": index, "argument": argument,
                            "argument_offset": identity[1],
                            "receiver_offset": expected_offset,
                            "offset_delta": identity[1] - expected_offset})
    if len(matches) == 1:
        status = ("exact_identity_match" if expected_offset == 0 else "subobject_offset_match")
        if matches[0]["offset_delta"] != 0:
            return {"status": "offset_mismatch", "matches": matches,
                    "argument_count": len(arglist["arguments"])}
        return {"status": status, "matches": matches,
                "argument_count": len(arglist["arguments"])}
    if len(matches) > 1:
        return {"status": "ambiguous", "matches": matches,
                "argument_count": len(arglist["arguments"])}
    return {"status": "mismatch", "matches": [],
            "argument_count": len(arglist["arguments"])}


def _instructions_for_function(connection: sqlite3.Connection, function_ea: int,
                               view_name: str = "microcode") -> list[dict[str, Any]]:
    if view_name not in ("microcode", "micro_flow"):
        raise ValueError("unsupported microcode view")
    rows_table = "micro_instructions" if view_name == "microcode" else "micro_flow_instructions"
    result = []
    for row in connection.execute(
        f"SELECT block_serial,ordinal,ea,opcode,text,l_json,r_json,d_json FROM {rows_table} "
        "WHERE function_ea=? ORDER BY block_serial,ordinal", (sqlite_ea(function_ea),),
    ):
        result.append({"block_serial": row[0], "ordinal": row[1], "ea": ida_ea(row[2]) if row[2] is not None else None,
            "opcode": row[3], "text": row[4], "l": _decode_json(row[5]), "r": _decode_json(row[6]),
            "d": _decode_json(row[7])})
    return result


def _microcode_relations_for_function(connection: sqlite3.Connection, function_ea: int,
                                      summary: sqlite3.Row, view_name: str = "microcode") -> dict[str, Any]:
    metadata = _decode_json(summary["relations_json"])
    cfg_summary = metadata.get("cfg", {})
    blocks = []
    for row in connection.execute(
        "SELECT block_serial,predecessors_json,successors_json,instruction_count FROM micro_blocks "
        "WHERE view_name=? AND function_ea=? ORDER BY block_serial",
        (view_name, sqlite_ea(function_ea)),
    ):
        try:
            predecessors = json.loads(row["predecessors_json"])
            successors = json.loads(row["successors_json"])
        except (TypeError, json.JSONDecodeError):
            predecessors = successors = None
        blocks.append({"serial": row["block_serial"], "predecessors": predecessors,
                       "successors": successors, "instruction_count": row["instruction_count"]})
    expected_count = cfg_summary.get("block_count")
    complete = (cfg_summary.get("complete") is True and isinstance(expected_count, int)
                and expected_count == len(blocks))
    block_serials = {block["serial"] for block in blocks}
    predecessor_edges = set()
    successor_edges = set()
    for block in blocks:
        predecessors, successors = block["predecessors"], block["successors"]
        if not isinstance(predecessors, list) or not isinstance(successors, list):
            complete = False
            continue
        predecessor_edges.update((value, block["serial"]) for value in predecessors)
        successor_edges.update((block["serial"], value) for value in successors)
        if any(value not in block_serials for value in [*predecessors, *successors]):
            complete = False
    if predecessor_edges != successor_edges:
        complete = False
    return {
        "version": metadata.get("version"), "truncated": metadata.get("truncated"),
        "cfg": {"complete": complete, "blocks": blocks},
        "def_use": metadata.get("def_use", {}),
    }


def _microcode_dominators(relations: dict[str, Any] | None) -> dict[int, set[int]] | None:
    """Return block dominators only for a complete exported micro CFG."""
    cfg = (relations or {}).get("cfg") or {}
    if not cfg.get("complete"):
        return None
    blocks = cfg.get("blocks") or []
    serials = {int(block["serial"]) for block in blocks if "serial" in block}
    if not serials:
        return None
    predecessors = {int(block["serial"]): {int(value) for value in block.get("predecessors", [])}
                    for block in blocks if "serial" in block}
    roots = [block for block in serials if not predecessors.get(block)]
    if len(roots) != 1:
        return None
    entry = roots[0]
    all_blocks = set(serials)
    reachable = {entry}
    pending = [entry]
    successors = {int(block["serial"]): {int(value) for value in block.get("successors", [])}
                  for block in blocks if "serial" in block}
    while pending:
        source = pending.pop()
        for target in successors.get(source, set()) & all_blocks:
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    dominators = {block: ({entry} if block == entry else set(all_blocks)) for block in serials}
    dominators = {block: dominators[block] for block in reachable}
    changed = True
    while changed:
        changed = False
        for block in sorted(reachable - {entry}):
            preds = predecessors.get(block, set()) & reachable
            next_set = {block} if not preds else {block} | set.intersection(
                *(dominators[pred] for pred in preds))
            if next_set != dominators[block]:
                dominators[block] = next_set
                changed = True
    return dominators


def _trace_vcall_pattern(instructions: list[dict[str, Any]], call: dict[str, Any],
                        relations: dict[str, Any] | None = None) -> dict[str, Any] | None:
    definitions: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for instruction in instructions:
        key = _key(instruction.get("d", {}))
        if key is not None:
            definitions[key].append(instruction)

    dominators = _microcode_dominators(relations)
    def_use_chain: list[dict[str, Any]] = []

    def resolve_load(value: dict[str, Any], visited: set[tuple[str, int]],
                     use_location: tuple[int, int]) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        key = _key(value)
        if key is None or key in visited:
            return None
        visited.add(key)
        # Only same-block order is a local proof. EA order across microcode
        # blocks says nothing about path reachability or dominance.
        candidates = []
        same_block = [item for item in definitions.get(key, [])
            if item["block_serial"] == use_location[0] and item["ordinal"] < use_location[1]]
        if same_block:
            definition = max(same_block, key=lambda item: item["ordinal"])
            relationship = "same_block_ordered_candidate"
        else:
            # A dominating definition is safe here only when this value
            # number has exactly one definition in the function. This avoids
            # overlooking a conditional overwrite from another predecessor.
            cross_block = definitions.get(key, [])
            if (len(cross_block) != 1 or dominators is None
                    or cross_block[0]["block_serial"] == use_location[0]
                    or cross_block[0]["block_serial"] not in dominators.get(use_location[0], set())):
                return None
            definition = cross_block[0]
            relationship = "unique_definition_in_dominating_block_candidate"
        def_use_chain.append({"value_number": key[1], "relationship": relationship,
            "definition": {"block_serial": definition["block_serial"],
                           "ordinal": definition["ordinal"], "ea": definition.get("ea")},
            "use": {"block_serial": use_location[0], "ordinal": use_location[1]}})
        if definition["opcode"] == "ldx":
            return definition, [definition]
        if definition["opcode"] == "mov":
            source = definition.get("l", {})
            if _key(source) is None:
                return None
            result = resolve_load(source, visited,
                (int(definition["block_serial"]), int(definition["ordinal"])))
            if result is None:
                return None
            load, chain = result
            return load, [definition, *chain]
        return None

    # In IDA microcode icall stores the indirect callee in r on supported
    # architectures. Nested callee expressions are handled without text parsing.
    callee = call.get("r", {}) if call.get("r", {}).get("kind") != "empty" else call.get("l", {})
    call_location = (int(call["block_serial"]), int(call["ordinal"]))
    slot_result = resolve_load(callee, set(), call_location)
    slot_chain: list[dict[str, Any]] = []
    if slot_result is None:
        if callee.get("kind") == "nested" and isinstance(callee.get("instruction"), dict):
            nested = callee["instruction"]
            if nested.get("opcode") == "ldx":
                slot_load = {**nested, "opcode": "ldx", "ea": nested.get("ea"), "l": nested.get("l", {}),
                             "r": nested.get("r", {}), "d": nested.get("d", {}),
                             "block_serial": call["block_serial"], "ordinal": call["ordinal"]}
                slot_result = (slot_load, [slot_load])
    if slot_result is None:
        return None
    slot_load, slot_chain = slot_result
    slot_address = _address_expression(slot_load.get("r", {}))
    if slot_address is None or slot_address["offset"] < 0:
        return None
    vptr_value = slot_address["base"]
    vptr_result = resolve_load(vptr_value, set(),
        (int(slot_load["block_serial"]), int(slot_load["ordinal"]))
        if "block_serial" in slot_load and "ordinal" in slot_load else call_location)
    if vptr_result is None:
        return None
    vptr_load, vptr_chain = vptr_result
    object_address = _address_expression(vptr_load.get("r", {}))
    if object_address is None:
        return None
    if (_operand_truncated(callee)
            or any(_operand_truncated(item.get(root)) for item in [*vptr_chain, *slot_chain]
                   for root in ("l", "r", "d"))):
        return None
    receiver = object_address["base"]
    if receiver.get("kind") not in ("register", "local", "stack", "global"):
        return None
    receiver_binding = _receiver_binding(call, receiver, object_address["offset"])
    chain_blocks = {call_location[0]} | {edge["definition"]["block_serial"]
        for edge in def_use_chain} | {edge["use"]["block_serial"] for edge in def_use_chain}
    dominance_verified = (dominators is not None
        and chain_blocks.issubset(dominators.keys()))
    return {
        "receiver": receiver,
        "receiver_binding": receiver_binding,
        "pattern_status": ("candidate" if receiver_binding["status"] in (
            "exact_identity_match", "subobject_offset_match") else "receiver_unbound"),
        "vptr_offset": object_address["offset"],
        "slot_offset": slot_address["offset"],
        "vptr_load_ea": vptr_load.get("ea"),
        "slot_load_ea": slot_load.get("ea"),
        "definition_chain": [{"block_serial": item["block_serial"], "ordinal": item["ordinal"],
            "ea": item.get("ea"), "opcode": item["opcode"], "text": item["text"]}
            for item in [*vptr_chain, *slot_chain]],
        "definition_use_chain": def_use_chain,
        "callee_operand": callee,
        "basis": "two_dependent_indirect_loads_in_exported_microcode",
        "same_block_order_checked": True,
        "cfg_complete": (relations or {}).get("cfg", {}).get("complete"),
        "operand_tree_truncated": (relations or {}).get("truncated"),
        "cross_block_reaching_definitions_computed": False,
        "def_use_coverage": (relations or {}).get("def_use", {}).get("coverage"),
        "unknown_frontier": ["the matched argument is the ABI this receiver under this calling convention",
            "receiver dynamic type and object lifetime",
            "memory aliasing and definitions without exported register value numbers",
            "cross-block reaching definitions beyond the single-dominating-definition subset"],
        "control_flow_dominance_verified": dominance_verified,
        "cxx_virtual_call_confirmed": False,
    }


def _static_address_value(operand: dict[str, Any], pointer_size: int) -> tuple[int | None, list[dict[str, Any]]]:
    """Resolve only literals/global address operands and their move chain."""

    if operand.get("kind") == "address" and isinstance(operand.get("operand"), dict):
        return _static_address_value(operand["operand"], pointer_size)
    if operand.get("kind") == "global" and isinstance(operand.get("address"), int):
        return int(operand["address"]), []
    if operand.get("kind") == "number" and isinstance(operand.get("value"), int):
        return int(operand["value"]) & ((1 << (pointer_size * 8)) - 1), []
    if operand.get("kind") == "nested":
        expression = _address_expression(operand)
        if expression is not None:
            base, chain = _static_address_value(expression["base"], pointer_size)
            if base is not None:
                return (base + int(expression["offset"])) & ((1 << (pointer_size * 8)) - 1), chain
    if operand.get("kind") != "register" or operand.get("value_number") is None:
        return None, []
    return None, []


def _trace_static_store_value(connection: sqlite3.Connection, instructions: list[dict[str, Any]], value: dict[str, Any],
                              use_location: tuple[int, int], relations: dict[str, Any] | None,
                              *, pointer_size: int) -> tuple[int | None, list[dict[str, Any]]]:
    definitions: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for instruction in instructions:
        key = _key(instruction.get("d", {}))
        if key is not None:
            definitions[key].append(instruction)
    dominators = _microcode_dominators(relations)
    visited: set[tuple[str, int]] = set()

    def resolve(operand: dict[str, Any], location: tuple[int, int]) -> tuple[int | None, list[dict[str, Any]]]:
        direct, chain = _static_address_value(operand, pointer_size)
        if direct is not None:
            return direct, chain
        key = _key(operand)
        if key is None or key in visited:
            return None, []
        visited.add(key)
        candidates = definitions.get(key, [])
        same_block = [item for item in candidates if item["block_serial"] == location[0]
                      and item["ordinal"] < location[1]]
        if same_block:
            definition = max(same_block, key=lambda item: item["ordinal"])
            relationship = "same_block_ordered_candidate"
        elif (len(candidates) == 1 and dominators is not None
              and candidates[0]["block_serial"] != location[0]
              and candidates[0]["block_serial"] in dominators.get(location[0], set())):
            definition = candidates[0]
            relationship = "unique_definition_in_dominating_block_candidate"
        else:
            return None, []
        record = {"block_serial": definition["block_serial"], "ordinal": definition["ordinal"],
                  "ea": definition.get("ea"), "opcode": definition["opcode"],
                  "relationship": relationship}
        if definition["opcode"] == "mov":
            resolved, previous = resolve(definition.get("l", {}),
                (int(definition["block_serial"]), int(definition["ordinal"])))
            if resolved is None:
                return None, []
            return resolved, [record, *previous]
        if definition["opcode"] == "ldx":
            address = _address_expression(definition.get("r", {}))
            if address is None or address["base"].get("kind") != "global":
                return None, []
            global_ea = address["base"].get("address")
            if not isinstance(global_ea, int):
                return None, []
            slot = connection.execute(
                "SELECT target_ea FROM data_pointer_slots WHERE source_ea=? AND target_ea IS NOT NULL",
                (sqlite_ea(global_ea + int(address["offset"])),),
            ).fetchone()
            if slot is None:
                return None, []
            return ida_ea(slot[0]), [record]
        return None, []

    return resolve(value, use_location)


def _store_address_operand(instruction: dict[str, Any]) -> dict[str, Any]:
    # GLBOPT3 represents stx's destination in d on current Hex-Rays versions;
    # tolerate r only when d is absent in an older/exported fixture.
    destination = instruction.get("d", {})
    return destination if destination.get("kind") != "empty" else instruction.get("r", {})


def _object_view(operand: dict[str, Any], offset: int) -> dict[str, Any] | None:
    identity = _operand_identity(operand)
    if identity is None:
        return None
    root, root_offset = identity
    return {"identity": [root[0], root[1]], "offset": int(root_offset) + int(offset),
            "root_kind": root[0], "root_value": root[1], "root_text": operand.get("text")}


def _vptr_write_source_snapshot(connection: sqlite3.Connection, function_eas: Iterable[int]) -> str:
    """Hash the exact microcode and table candidates consumed by a write scan."""
    selected = sorted(set(int(ea) for ea in function_eas))
    microcode_hash = _source_hash(connection, "vcall", selected)
    table_rows = _rows(connection,
        "SELECT c.candidate_id,c.address_point,c.table_address,c.pointer_size,c.abi "
        "FROM vtable_candidates c WHERE c.stale=0 ORDER BY c.address_point,c.candidate_id")
    return _digest({"microcode": microcode_hash, "tables": table_rows})


def build_vptr_write_index(
    connection: sqlite3.Connection, *, function_eas: list[int], max_writes: int = 100000,
) -> dict[str, Any]:
    """Index function-local stores of exact indexed address points.

    This records observed stores and source chains; it does not prove object
    construction, lifetime, or absence of aliasing writes through memory.
    """

    if max_writes < 1:
        raise ValueError("max_writes must be positive")
    selected = sorted(set(int(ea) for ea in function_eas))
    source_snapshot_hash = _vptr_write_source_snapshot(connection, selected)
    table_rows = _rows(connection,
        "SELECT c.candidate_id,c.address_point,c.table_address,c.pointer_size,c.abi "
        "FROM vtable_candidates c WHERE c.stale=0 ORDER BY c.address_point,c.candidate_id")
    scope = {"function_eas": selected, "max_writes": max_writes}
    run_id = _id("VPWR", {"source": source_snapshot_hash, "scope": scope,
        "detector": VPTR_WRITE_DETECTOR_VERSION})
    existing = connection.execute("SELECT status,result_json FROM vptr_write_runs WHERE run_id=?",
        (run_id,)).fetchone()
    if existing is not None:
        cached_result = json.loads(existing["result_json"])
        cached_status = cached_result.get("status", "partial" if existing["status"] == "partial" else "ok")
        with connection:
            connection.execute("UPDATE vptr_write_runs SET status=? WHERE run_id=?", (cached_status, run_id))
            connection.execute("UPDATE vptr_writes SET stale=0 WHERE run_id=?", (run_id,))
        return {"run_id": run_id, "cached": True, **cached_result}

    by_address: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in table_rows:
        by_address[ida_ea(row["address_point"])].append(row)
    writes = []
    missing, failures = [], []
    truncated = False
    for function_ea in selected:
        summary = connection.execute("SELECT status,relations_json FROM microcode WHERE function_ea=?",
            (sqlite_ea(function_ea),)).fetchone()
        if summary is None:
            missing.append(function_ea)
            continue
        if summary["status"] != "ok":
            failures.append({"function_ea": function_ea, "status": summary["status"]})
            continue
        instructions = _instructions_for_function(connection, function_ea)
        relations = _microcode_relations_for_function(connection, function_ea, summary)
        for instruction in instructions:
            if instruction["opcode"] != "stx":
                continue
            address = _address_expression(_store_address_operand(instruction))
            if address is None:
                continue
            object_view = _object_view(address["base"], address["offset"])
            if object_view is None:
                continue
            location = (int(instruction["block_serial"]), int(instruction["ordinal"]))
            value, chain = _trace_static_store_value(connection, instructions, instruction.get("l", {}), location,
                relations, pointer_size=8 if get_metadata(connection, "bitness", 64) == 64 else 4)
            if value is None:
                continue
            matches = by_address.get(value, [])
            if not matches:
                continue
            for table in matches:
                item = {"function_ea": function_ea, "write_ea": instruction.get("ea"),
                    "block_serial": instruction["block_serial"], "ordinal": instruction["ordinal"],
                    "object": object_view, "vptr_offset": object_view["offset"],
                    "address_point": value, "candidate_id": table["candidate_id"],
                    "status": "observed_address_point_store",
                    "evidence": {"instruction": instruction["text"], "store_value": instruction["l"],
                        "store_address": _store_address_operand(instruction), "value_definition_chain": chain,
                        "control_flow_cfg_complete": relations.get("cfg", {}).get("complete"),
                        "source_snapshot_hash": source_snapshot_hash,
                        "unknown_frontier": ["memory aliases and non-register stores",
                            "constructor/destructor semantics and object lifetime",
                            "writes reached through calls or external code"]}}
                item["write_id"] = _id("VPW", {"run": run_id, "function": function_ea,
                    "block": item["block_serial"], "ordinal": item["ordinal"],
                    "candidate": table["candidate_id"]})
                if len(writes) >= max_writes:
                    truncated = True
                    break
                writes.append(item)
            if truncated:
                break
        if truncated:
            break
    has_gaps = bool(missing or failures or not table_rows or not selected)
    status = "partial" if truncated or has_gaps else "ok"
    result = {"write_count": len(writes), "coverage": {
        "selected_functions": len(selected), "functions_missing_microcode": missing,
        "functions_with_export_errors": failures, "candidate_limit": max_writes,
        "current_vtable_candidates": len(table_rows),
        "vtable_candidates_available": bool(table_rows),
        "truncated": truncated, "source_snapshot_hash": source_snapshot_hash}, "scope": scope,
        "status": status}
    affected_call_runs = _runs_intersecting_functions(connection, "vcall_runs", selected)
    now = utc_now()
    with connection:
        old_runs = _runs_intersecting_functions(connection, "vptr_write_runs", selected)
        if old_runs:
            run_marks = ",".join("?" for _ in old_runs)
            connection.execute(f"UPDATE vptr_writes SET stale=1 WHERE run_id IN ({run_marks})", old_runs)
            connection.execute(f"UPDATE vptr_write_runs SET status='stale' WHERE run_id IN ({run_marks})", old_runs)
        connection.execute("INSERT INTO vptr_write_runs(run_id,source_snapshot_hash,scope_json,detector_version,status,result_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, source_snapshot_hash, _json(scope), VPTR_WRITE_DETECTOR_VERSION,
             status, _json(result), now))
        # A saved call resolution may cite writes from a previous detector run.
        # Keep call patterns current but force only overlapping run scopes to
        # refresh their derived target/flow view.
        if affected_call_runs:
            run_marks = ",".join("?" for _ in affected_call_runs)
            connection.execute(f"UPDATE vcall_targets SET stale=1 WHERE call_id IN "
                f"(SELECT call_id FROM vcall_sites WHERE run_id IN ({run_marks}))", affected_call_runs)
            connection.execute(f"UPDATE receiver_flows SET stale=1 WHERE call_id IN "
                f"(SELECT call_id FROM vcall_sites WHERE run_id IN ({run_marks}))", affected_call_runs)
        connection.executemany(
            "INSERT INTO vptr_writes(write_id,run_id,function_ea,write_ea,block_serial,ordinal,object_json,vptr_offset,address_point,candidate_id,status,evidence_json,source_snapshot_hash,stale) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            [(item["write_id"], run_id, sqlite_ea(item["function_ea"]),
              sqlite_ea(item["write_ea"]) if item["write_ea"] is not None else None,
              item["block_serial"], item["ordinal"], _json(item["object"]), item["vptr_offset"],
              sqlite_ea(item["address_point"]), item["candidate_id"], item["status"],
              _json(item["evidence"]), source_snapshot_hash) for item in writes],
        )
    return {"run_id": run_id, "cached": False, **result}


def _prior_vptr_write_candidates(
    connection: sqlite3.Connection, site: sqlite3.Row, pattern: dict[str, Any],
) -> dict[str, Any]:
    """Return same-function stores that may establish this receiver's vptr.

    Exact object identity and CFG order are required for a candidate. The result
    remains conditional because aliases, intervening memory writes, and calls
    can invalidate a stored vptr without appearing in the register def-use data.
    """
    receiver = pattern.get("receiver")
    identity = _operand_identity(receiver) if isinstance(receiver, dict) else None
    if identity is None:
        return {"status": "unknown", "items": [],
            "reason": "call receiver has no stable exported identity"}
    expected_offset = int(identity[1]) + int(pattern.get("vptr_offset", 0))
    function_ea = ida_ea(int(site["function_ea"]))
    call_block, call_ordinal = int(site["block_serial"]), int(site["ordinal"])
    call_relations = connection.execute(
        "SELECT status,relations_json FROM microcode WHERE function_ea=?",
        (sqlite_ea(function_ea),),
    ).fetchone()
    if call_relations is None or call_relations["status"] != "ok":
        return {"status": "unknown", "items": [], "reason": "call microcode is unavailable"}
    relations = _microcode_relations_for_function(connection, function_ea, call_relations)
    dominators = _microcode_dominators(relations)

    scoped_runs = []
    current_runs = []
    for run in connection.execute("SELECT * FROM vptr_write_runs ORDER BY created_at DESC"):
        try:
            run_scope = json.loads(run["scope_json"])
            run_functions = [int(ea) for ea in run_scope.get("function_eas", [])]
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if function_ea not in run_functions:
            continue
        scoped_runs.append(run)
        if run["status"] in ("ok", "partial"):
            current_hash = _vptr_write_source_snapshot(connection, run_functions)
            if current_hash == run["source_snapshot_hash"]:
                current_runs.append(run)
    if current_runs:
        chosen_run = current_runs[0]
        index_status = "current" if chosen_run["status"] == "ok" else "partial_coverage"
        index_run_id = chosen_run["run_id"]
    elif scoped_runs:
        index_status = "stale_or_source_changed"
        index_run_id = scoped_runs[0]["run_id"]
    else:
        index_status = "not_indexed"
        index_run_id = None

    rows = connection.execute(
        "SELECT w.*,r.scope_json,r.status AS run_status "
        "FROM vptr_writes w JOIN vptr_write_runs r ON r.run_id=w.run_id "
        "WHERE w.function_ea=? AND w.stale=0 AND r.status IN ('ok','partial') "
        "ORDER BY w.block_serial,w.ordinal,w.write_id", (sqlite_ea(function_ea),),
    ).fetchall()
    matches = []
    validated_snapshots: dict[tuple[int, ...], str] = {}
    for row in rows:
        try:
            scope = json.loads(row["scope_json"])
            selected = scope.get("function_eas", [])
        except (TypeError, json.JSONDecodeError):
            continue
        if function_ea not in selected:
            continue
        selected_key = tuple(sorted(int(ea) for ea in selected))
        current_hash = validated_snapshots.get(selected_key)
        if current_hash is None:
            current_hash = _vptr_write_source_snapshot(connection, selected_key)
            validated_snapshots[selected_key] = current_hash
        if current_hash != row["source_snapshot_hash"]:
            continue
        object_view = json.loads(row["object_json"])
        if object_view.get("identity") != list(identity[0]) or int(row["vptr_offset"] or 0) != expected_offset:
            continue
        write_block, write_ordinal = int(row["block_serial"]), int(row["ordinal"])
        if write_block == call_block:
            if write_ordinal >= call_ordinal:
                continue
            order = "same_block_prior_store"
        elif dominators is not None and write_block in dominators.get(call_block, set()):
            order = "dominating_block_store_candidate"
        else:
            continue
        item = dict(row)
        item["function_ea"] = ida_ea(item["function_ea"])
        item["write_ea"] = ida_ea(item["write_ea"]) if item["write_ea"] is not None else None
        item["address_point"] = ida_ea(item["address_point"])
        item["object"] = object_view
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["order_relation"] = order
        item["status"] = "prior_vptr_write_candidate"
        matches.append(item)
    status = ("candidate" if matches else
        "no_matching_observed_store" if index_status == "current" else
        "partial_no_matching_observed_store" if index_status == "partial_coverage" else index_status)
    return {"status": status, "index_status": index_status, "index_run_id": index_run_id,
        "items": matches,
        "expected_object_identity": list(identity[0]),
        "expected_vptr_offset": expected_offset,
        "unknown_frontier": [
            "intervening aliasing stores or memory writes not represented by the exported relation graph",
            "calls that mutate this object or write through an alias",
            "object lifetime and whether the store is a constructor-phase vptr",
            "other predecessor paths or writes not indexed in the selected analysis scope",
        ]}


def list_vptr_writes(
    connection: sqlite3.Connection, *, function_ea: int | None = None,
    address_point: int | None = None, limit: int = 100, offset: int = 0,
    include_stale: bool = False,
) -> dict[str, Any]:
    if limit < 0 or offset < 0:
        raise ValueError("limit and offset must be non-negative")
    clauses, parameters = [], []
    if not include_stale:
        clauses.append("stale=0")
    if function_ea is not None:
        clauses.append("function_ea=?"); parameters.append(sqlite_ea(function_ea))
    if address_point is not None:
        clauses.append("address_point=?"); parameters.append(sqlite_ea(address_point))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    total = connection.execute("SELECT count(*) FROM vptr_writes" + where, parameters).fetchone()[0]
    rows = connection.execute("SELECT * FROM vptr_writes" + where +
        " ORDER BY function_ea,block_serial,ordinal,write_id LIMIT ? OFFSET ?",
        (*parameters, -1 if limit == 0 else limit, offset)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["function_ea"] = ida_ea(item["function_ea"])
        item["write_ea"] = ida_ea(item["write_ea"]) if item["write_ea"] is not None else None
        item["address_point"] = ida_ea(item["address_point"])
        item["object"] = json.loads(item.pop("object_json"))
        item["evidence"] = json.loads(item.pop("evidence_json"))
        items.append(item)
    return {"count": len(items), "total": total, "truncated": offset + len(items) < total,
        "include_stale": include_stale, "items": items}


def _runs_intersecting_functions(
    connection: sqlite3.Connection, table: str, function_eas: Iterable[int],
) -> list[str]:
    if table not in ("vcall_runs", "vptr_write_runs"):
        raise ValueError("unsupported virtual-analysis run table")
    selected = set(int(ea) for ea in function_eas)
    if not selected:
        return []
    affected = []
    for row in connection.execute(f"SELECT run_id,scope_json FROM {table} WHERE status NOT IN ('stale','error')"):
        try:
            run_functions = {int(ea) for ea in json.loads(row["scope_json"]).get("function_eas", [])}
        except (TypeError, ValueError, json.JSONDecodeError):
            affected.append(row["run_id"])
            continue
        if selected.intersection(run_functions):
            affected.append(row["run_id"])
    return affected


def invalidate_function_virtual_artifacts(
    connection: sqlite3.Connection, function_eas: Iterable[int],
) -> dict[str, int]:
    """Stale function-derived call and vptr-write observations after microcode refresh."""
    selected = sorted(set(sqlite_ea(int(ea)) for ea in function_eas))
    if not selected:
        return {"vcall_sites": 0, "vptr_writes": 0}
    with connection:
        call_runs = _runs_intersecting_functions(connection, "vcall_runs", [ida_ea(ea) for ea in selected])
        call_ids = []
        if call_runs:
            run_marks = ",".join("?" for _ in call_runs)
            call_ids = [row[0] for row in connection.execute(
                f"SELECT call_id FROM vcall_sites WHERE run_id IN ({run_marks})", call_runs)]
            connection.execute(f"UPDATE vcall_sites SET stale=1 WHERE run_id IN ({run_marks})", call_runs)
        if call_ids:
            call_marks = ",".join("?" for _ in call_ids)
            connection.execute(f"UPDATE vcall_targets SET stale=1 WHERE call_id IN ({call_marks})", call_ids)
            connection.execute(f"UPDATE receiver_flows SET stale=1 WHERE call_id IN ({call_marks})", call_ids)
        if call_runs:
            run_marks = ",".join("?" for _ in call_runs)
            connection.execute(f"UPDATE vcall_runs SET status='stale' WHERE run_id IN ({run_marks})", call_runs)

        write_runs = _runs_intersecting_functions(connection, "vptr_write_runs", [ida_ea(ea) for ea in selected])
        write_ids = []
        if write_runs:
            run_marks = ",".join("?" for _ in write_runs)
            write_ids = [row[0] for row in connection.execute(
                f"SELECT write_id FROM vptr_writes WHERE run_id IN ({run_marks}) AND stale=0", write_runs)]
            # A run hash covers every selected function, so all rows from a
            # multi-function run must become stale if any dependency changes.
            connection.execute(f"UPDATE vptr_writes SET stale=1 WHERE run_id IN ({run_marks})", write_runs)
            connection.execute(f"UPDATE vptr_write_runs SET status='stale' WHERE run_id IN ({run_marks})", write_runs)
    return {"vcall_sites": len(call_ids), "vptr_writes": len(write_ids)}


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
        cached_result = json.loads(existing["result_json"])
        cached_status = cached_result.get("status", "partial" if existing["status"] == "partial" else "ok")
        with connection:
            connection.execute("UPDATE vcall_runs SET status=? WHERE run_id=?", (cached_status, run_id))
            connection.execute("UPDATE vcall_sites SET stale=0 WHERE run_id=?", (run_id,))
        return {"run_id": run_id, "cached": True, **cached_result}

    missing = []
    failures = []
    sites: list[dict[str, Any]] = []
    truncated = False
    for function_ea in selected:
        summary = connection.execute("SELECT status,relations_json FROM microcode WHERE function_ea=?",
            (sqlite_ea(function_ea),)).fetchone()
        if summary is None:
            missing.append(function_ea); continue
        if summary["status"] != "ok":
            failures.append({"function_ea": function_ea, "status": summary["status"]}); continue
        instructions = _instructions_for_function(connection, function_ea)
        relations = _microcode_relations_for_function(connection, function_ea, summary)
        for instruction in instructions:
            if instruction["opcode"] != "icall":
                continue
            if len(sites) >= max_calls:
                truncated = True
                break
            pattern = _trace_vcall_pattern(instructions, instruction, relations)
            pattern_candidate = bool(pattern and pattern.get("pattern_status") == "candidate")
            call_id = _id("VCALL", {"run": run_id, "function": function_ea,
                "block": instruction["block_serial"], "ordinal": instruction["ordinal"]})
            site = {
                "call_id": call_id, "run_id": run_id, "call_ea": instruction["ea"],
                "function_ea": function_ea, "block_serial": instruction["block_serial"],
                "ordinal": instruction["ordinal"], "kind": "indirect_call",
                "status": "vtable_pattern_candidate" if pattern_candidate else "indirect_unknown",
                "opcode": instruction["opcode"], "receiver": pattern.get("receiver", {}) if pattern else {},
                "callee": pattern or {"operand_l": instruction["l"], "operand_r": instruction["r"]},
                "slot_offset": pattern.get("slot_offset") if pattern_candidate else None,
                "pointer_size": 8 if get_metadata(connection, "bitness", 64) == 64 else 4,
                "evidence": {"instruction": instruction["text"], "microcode_source": "micro_instructions",
                    "source_snapshot_hash": snapshot, "pattern": pattern,
                    "microcode_relations": {"version": relations.get("version"),
                        "cfg_complete": (relations.get("cfg") or {}).get("complete"),
                        "operand_tree_truncated": relations.get("truncated"),
                        "cross_block_reaching_definitions": (relations.get("def_use") or {}).get(
                            "cross_block_reaching_definitions")}},
                "source_snapshot_hash": snapshot,
            }
            sites.append(site)
        if truncated:
            break

    now = utc_now()
    run_status = "partial" if missing or failures or truncated or not selected else "ok"
    result = {"site_count": len(sites), "pattern_candidate_count": sum(s["status"] == "vtable_pattern_candidate" for s in sites),
        "unknown_indirect_count": sum(s["status"] == "indirect_unknown" for s in sites),
        "coverage": {"selected_functions": len(selected), "functions_missing_microcode": missing,
            "functions_with_export_errors": failures, "candidate_limit": max_calls,
            "truncated": truncated}, "scope": scope, "source_snapshot_hash": snapshot,
        "status": run_status}
    with connection:
        affected_runs = _runs_intersecting_functions(connection, "vcall_runs", selected)
        if affected_runs:
            run_placeholders = ",".join("?" for _ in affected_runs)
            connection.execute(f"UPDATE vcall_sites SET stale=1 WHERE run_id IN ({run_placeholders})", affected_runs)
            connection.execute(f"UPDATE vcall_targets SET stale=1 WHERE call_id IN "
                f"(SELECT call_id FROM vcall_sites WHERE run_id IN ({run_placeholders}))", affected_runs)
            connection.execute(f"UPDATE receiver_flows SET stale=1 WHERE call_id IN "
                f"(SELECT call_id FROM vcall_sites WHERE run_id IN ({run_placeholders}))", affected_runs)
            connection.execute(f"UPDATE vcall_runs SET status='stale' WHERE run_id IN ({run_placeholders})", affected_runs)
        connection.execute("INSERT INTO vcall_runs(run_id,source_snapshot_hash,scope_json,detector_version,status,result_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, snapshot, _json(scope), VCALL_DETECTOR_VERSION, run_status, _json(result), now))
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
        "SELECT s.candidate_id,s.slot_index,s.byte_offset,s.target_ea,s.target_name,s.entry_classification,"
        "s.is_nullstub,s.is_library,s.is_thunk,s.thunk_target_ea,c.address_point,c.abi "
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
            "target_name": row["target_name"], "entry_classification": row["entry_classification"],
            "is_nullstub": bool(row["is_nullstub"]), "is_library": bool(row["is_library"]),
            "is_thunk": bool(row["is_thunk"]),
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
    prior_writes = _prior_vptr_write_candidates(connection, row, site["callee"])
    resolution["prior_vptr_writes"] = prior_writes
    candidate_ids = {item["candidate_id"] for item in prior_writes.get("items", [])}
    for target in resolution["targets"]:
        target["matching_prior_vptr_write_candidate"] = target["candidate_id"] in candidate_ids
        if target["matching_prior_vptr_write_candidate"]:
            target["prior_vptr_write_ids"] = [item["write_id"] for item in prior_writes["items"]
                if item["candidate_id"] == target["candidate_id"]]
        else:
            target["prior_vptr_write_ids"] = []
    with connection:
        connection.execute("DELETE FROM vcall_targets WHERE call_id=?", (call_id,))
        connection.execute("DELETE FROM receiver_flows WHERE call_id=?", (call_id,))
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
        flow_items = prior_writes.get("items", []) or [{
            "status": prior_writes.get("status", "unknown"),
            "reason": prior_writes.get("reason"),
            "index_status": prior_writes.get("index_status"),
            "index_run_id": prior_writes.get("index_run_id"),
            "expected_object_identity": prior_writes.get("expected_object_identity"),
            "expected_vptr_offset": prior_writes.get("expected_vptr_offset"),
            "unknown_frontier": prior_writes.get("unknown_frontier", []),
        }]
        for path_order, item in enumerate(flow_items):
            node = {key: item.get(key) for key in ("write_id", "function_ea", "write_ea", "block_serial",
                "ordinal", "object", "vptr_offset", "address_point", "candidate_id", "status",
                "reason", "index_status", "index_run_id", "expected_object_identity", "expected_vptr_offset")}
            is_write = item.get("write_id") is not None
            edge = {"kind": "observed_prior_vptr_store_candidate" if is_write else "prior_vptr_write_scan_result",
                "order_relation": item.get("order_relation"),
                "source_snapshot_hash": item.get("source_snapshot_hash", site["source_snapshot_hash"]),
                "evidence": item.get("evidence", {}),
                "unknown_frontier": prior_writes.get("unknown_frontier", item.get("unknown_frontier", []))}
            flow_id = _id("VFLOW", {"call": call_id, "write": item.get("write_id"),
                "result": prior_writes.get("status")})
            connection.execute(
                "INSERT INTO receiver_flows(flow_id,call_id,path_order,node_json,edge_json,status,source_snapshot_hash,stale,created_at) "
                "VALUES(?,?,?,?,?,?,?,0,?)",
                (flow_id, call_id, path_order, _json(node), _json(edge),
                 "candidate" if is_write else "unknown", edge["source_snapshot_hash"], utc_now()),
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
        item["entry_classification"] = item["evidence"].get("entry_classification", "unknown")
        item["is_nullstub"] = bool(item["evidence"].get("is_nullstub", False))
        item["is_library"] = bool(item["evidence"].get("is_library", False))
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


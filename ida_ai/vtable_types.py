"""Conservative class-relationship evidence and revision-checked type previews."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Any

from .db import get_metadata, ida_ea, sqlite_ea


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def type_application_revision(connection: sqlite3.Connection) -> str:
    """Content revision for vtable-oriented type edits, excluding timestamps."""
    definitions = [tuple(row) for row in connection.execute(
        "SELECT name,declaration FROM type_definitions ORDER BY name")]
    assignments = [tuple(row) for row in connection.execute(
        "SELECT address,declaration FROM type_assignments ORDER BY address")]
    candidates = [tuple(row) for row in connection.execute(
        "SELECT candidate_id,table_address,address_point,table_end,slot_count,abi,pointer_size,byteorder,status,"
        "evidence_json,source_snapshot_hash,stale FROM vtable_candidates ORDER BY candidate_id")]
    slots = [tuple(row) for row in connection.execute(
        "SELECT candidate_id,slot_index,byte_offset,entry_address,raw_value,target_ea,target_kind,target_name,"
        "entry_classification,is_nullstub,is_library,is_thunk,thunk_target_ea,thunk_chain_json,adjustment_json,"
        "source_snapshot_hash,stale FROM vtable_slots ORDER BY candidate_id,slot_index")]
    functions = [tuple(row) for row in connection.execute(
        "SELECT start_ea,end_ea,signature,is_thunk,thunk_target_ea FROM functions ORDER BY start_ea")]
    vptr_runs = [tuple(row) for row in connection.execute(
        "SELECT run_id,source_snapshot_hash,scope_json,status,result_json FROM vptr_write_runs ORDER BY run_id")]
    vptr_writes = [tuple(row) for row in connection.execute(
        "SELECT write_id,run_id,function_ea,write_ea,block_serial,ordinal,object_json,vptr_offset,address_point,"
        "candidate_id,status,evidence_json,source_snapshot_hash,stale FROM vptr_writes ORDER BY write_id")]
    active_rtti = get_metadata(connection, "active_rtti_run_id")
    rtti = []
    if isinstance(active_rtti, str):
        rtti_run = connection.execute("SELECT * FROM rtti_runs WHERE rtti_run_id=?", (active_rtti,)).fetchone()
        if rtti_run is not None:
            rtti = [dict(rtti_run), [tuple(row) for row in connection.execute(
                "SELECT typeinfo_ea,descriptor_kind,parse_status,type_name_ea,type_name,flags,base_count,bases_json,evidence_json "
                "FROM rtti_typeinfos WHERE rtti_run_id=? ORDER BY typeinfo_ea", (active_rtti,))]]
    identity = {key: get_metadata(connection, key)
        for key in ("root_filename", "input_path", "imagebase", "bitness", "architecture")}
    payload = {"identity": identity, "definitions": definitions, "assignments": assignments,
        "candidates": candidates, "slots": slots, "functions": functions,
        "vptr_runs": vptr_runs, "vptr_writes": vptr_writes, "active_rtti": active_rtti, "rtti": rtti}
    return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()


def _class_relationship_source(connection: sqlite3.Connection) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    from .virtual_tables import (_current_vtable_candidates, _source_hash,
                                 _vptr_write_source_snapshot, _active_rtti_descriptors)

    table_hash = _source_hash(connection, "vtable")
    rtti_input_hash = _source_hash(connection, "vtable", include_rtti=False)
    rtti_run_id, rtti_descriptors = _active_rtti_descriptors(connection, rtti_input_hash)
    current_candidates = _current_vtable_candidates(connection)
    candidate_ids = {item["candidate_id"] for item in current_candidates}
    valid_writes = []
    run_inputs = []
    for run in connection.execute(
        "SELECT * FROM vptr_write_runs WHERE status IN ('ok','partial') ORDER BY run_id"):
        try:
            scope = json.loads(run["scope_json"])
            view_name = scope.get("view_name", "microcode")
            function_eas = [int(ea) for ea in scope.get("function_eas", [])]
            current = _vptr_write_source_snapshot(connection, function_eas, view_name)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if current != run["source_snapshot_hash"]:
            continue
        run_inputs.append({"run_id": run["run_id"], "source_snapshot_hash": current,
            "view_name": view_name, "status": run["status"]})
        for row in connection.execute(
            "SELECT write_id,run_id,function_ea,write_ea,block_serial,ordinal,object_json,vptr_offset,address_point,"
            "candidate_id,status,evidence_json,source_snapshot_hash FROM vptr_writes "
            "WHERE run_id=? AND stale=0 ORDER BY function_ea,block_serial,ordinal,write_id", (run["run_id"],)):
            if row["candidate_id"] not in candidate_ids:
                continue
            valid_writes.append({"write_id": row["write_id"], "run_id": row["run_id"],
                "function_ea": ida_ea(row["function_ea"]),
                "write_ea": ida_ea(row["write_ea"]) if row["write_ea"] is not None else None,
                "block_serial": row["block_serial"], "ordinal": row["ordinal"],
                "object": json.loads(row["object_json"]), "vptr_offset": row["vptr_offset"],
                "address_point": ida_ea(row["address_point"]), "candidate_id": row["candidate_id"],
                "status": row["status"], "evidence": json.loads(row["evidence_json"]),
                "source_snapshot_hash": row["source_snapshot_hash"], "source_view": view_name})
    thunks = [dict(row) for row in connection.execute(
        "SELECT s.candidate_id,s.slot_index,s.target_ea,s.thunk_target_ea,s.adjustment_json,s.evidence_json "
        "FROM vtable_slots s WHERE s.stale=0 AND s.is_thunk=1 ORDER BY s.candidate_id,s.slot_index")
        if row["candidate_id"] in candidate_ids]
    payload = {"current_vtable_snapshot_hash": table_hash, "current_candidates": current_candidates,
        "active_rtti_run_id": rtti_run_id, "active_rtti_descriptors": rtti_descriptors,
        "vptr_write_runs": run_inputs, "vptr_writes": valid_writes, "thunks": thunks}
    source_hash = hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()
    return source_hash, valid_writes, thunks


def class_relationships(
    connection: sqlite3.Connection, *, derived_typeinfo_ea: int | None = None,
    limit: int = 100, offset: int = 0,
) -> dict[str, Any]:
    """Join parsed Itanium RTTI base edges with heuristic address-point candidates."""
    if limit < 0 or offset < 0:
        raise ValueError("limit and offset must be non-negative")
    from .virtual_tables import (_active_rtti_descriptors, _current_vtable_candidates, _source_hash)

    vtable_input_hash = _source_hash(connection, "vtable", include_rtti=False)
    rtti_run_id, descriptors = _active_rtti_descriptors(connection, vtable_input_hash)
    current_vtable_hash = _source_hash(connection, "vtable")
    relation_source_hash, valid_writes, _ = _class_relationship_source(connection)
    current_candidate_ids = {item["candidate_id"] for item in _current_vtable_candidates(connection)}
    current_candidates = [dict(row) for row in connection.execute(
        "SELECT candidate_id,address_point,evidence_json,source_snapshot_hash FROM vtable_candidates "
        "WHERE stale=0 ORDER BY address_point,candidate_id") if row["candidate_id"] in current_candidate_ids]
    by_typeinfo: dict[int, list[dict[str, Any]]] = {}
    for candidate in current_candidates:
        evidence = json.loads(candidate["evidence_json"])
        prefix = evidence.get("address_point_prefix") or {}
        info = prefix.get("typeinfo") or {}
        typeinfo_ea = info.get("typeinfo_ea")
        if isinstance(typeinfo_ea, int):
            by_typeinfo.setdefault(typeinfo_ea, []).append(candidate)

    descriptor_by_ea = {item["typeinfo_ea"]: item for item in descriptors}
    valid_writes_by_candidate: dict[str, list[dict[str, Any]]] = {}
    for write in valid_writes:
        valid_writes_by_candidate.setdefault(write["candidate_id"], []).append(write)

    def thunk_observations(candidate_ids: list[str]) -> list[dict[str, Any]]:
        if not candidate_ids:
            return []
        placeholders = ",".join("?" for _ in candidate_ids)
        result = []
        for slot in connection.execute(
            f"SELECT candidate_id,slot_index,target_ea,thunk_target_ea,adjustment_json,evidence_json "
            f"FROM vtable_slots WHERE candidate_id IN ({placeholders}) AND stale=0 AND is_thunk=1 "
            "ORDER BY candidate_id,slot_index", candidate_ids):
            adjustment = json.loads(slot["adjustment_json"] or "{}")
            result.append({"candidate_id": slot["candidate_id"], "slot_index": slot["slot_index"],
                "target_ea": ida_ea(slot["target_ea"]) if slot["target_ea"] is not None else None,
                "thunk_target_ea": ida_ea(slot["thunk_target_ea"]) if slot["thunk_target_ea"] is not None else None,
                "adjustment": adjustment, "adjustment_status": "decoded" if adjustment else "unknown",
                "evidence": json.loads(slot["evidence_json"] or "{}")})
        return result

    relations = []
    malformed_edges = []
    for derived_ea, descriptor in sorted(descriptor_by_ea.items()):
        if descriptor["parse_status"] != "parsed":
            continue
        bases = descriptor.get("bases") or []
        for index, base in enumerate(bases):
            base_ea = base.get("typeinfo_ea")
            if not isinstance(base_ea, int):
                malformed_edges.append({"derived_typeinfo_ea": derived_ea, "base_index": index,
                    "reason": "base descriptor has no decoded typeinfo address"})
                continue
            if derived_typeinfo_ea is not None and derived_ea != int(derived_typeinfo_ea):
                continue
            derived_tables = by_typeinfo.get(derived_ea, [])
            base_tables = by_typeinfo.get(base_ea, [])
            derived_candidate_ids = [item["candidate_id"] for item in derived_tables]
            base_candidate_ids = [item["candidate_id"] for item in base_tables]
            relation_core = {"rtti_run_id": rtti_run_id, "derived_typeinfo_ea": derived_ea,
                "base_typeinfo_ea": base_ea, "base_index": index, "inheritance": base,
                "source_snapshot_hash": relation_source_hash}
            relation_id = "VREL" + hashlib.sha256(_json(relation_core).encode()).hexdigest()[:28]
            relations.append({"relation_id": relation_id, "derived_typeinfo_ea": derived_ea,
                "derived_type_name": descriptor.get("type_name"), "base_typeinfo_ea": base_ea,
                "base_type_name": descriptor_by_ea.get(base_ea, {}).get("type_name"),
                "inheritance": base,
                "table_associations": {"derived_candidates": [item["candidate_id"] for item in derived_tables],
                    "base_candidates": [item["candidate_id"] for item in base_tables],
                    "derived_ambiguous": len(derived_tables) > 1, "base_ambiguous": len(base_tables) > 1},
                "supporting_observations": {
                    "derived_vptr_stores": [write for candidate_id in derived_candidate_ids
                        for write in valid_writes_by_candidate.get(candidate_id, [])],
                    "base_vptr_stores": [write for candidate_id in base_candidate_ids
                        for write in valid_writes_by_candidate.get(candidate_id, [])],
                    "adjustment_thunks": thunk_observations([*derived_candidate_ids, *base_candidate_ids]),
                    "thunk_adjustments_decoded": False},
                "evidence": {"rtti_run_id": rtti_run_id,
                    "descriptor_evidence": descriptor.get("evidence", {}),
                    "vtable_candidates_are_heuristic": True,
                    "interpretation": "RTTI base descriptor edge; candidate-table associations do not prove active object layout"},
                "status": "rtti_base_edge_candidate", "source_snapshot_hash": relation_source_hash})
    relations.sort(key=lambda item: (item["derived_typeinfo_ea"], item["base_typeinfo_ea"], item["relation_id"]))
    total = len(relations)
    scope = {"kind": "itanium_rtti_base_edges", "all_current_typeinfos": True}
    run_id = "VCR" + hashlib.sha256(_json({"source_snapshot_hash": relation_source_hash,
        "rtti_run_id": rtti_run_id, "scope": scope}).encode("utf-8")).hexdigest()[:29]
    existing = connection.execute(
        "SELECT status,result_json FROM vtable_class_relation_runs WHERE run_id=?", (run_id,),
    ).fetchone()
    build_status = "ok" if rtti_run_id is not None else "partial"
    result_payload = {"run_id": run_id, "rtti_run_id": rtti_run_id,
        "source_snapshot_hash": relation_source_hash,
        "rtti_input_current": rtti_run_id is not None,
        "coverage": {"parsed_typeinfos": sum(item["parse_status"] == "parsed" for item in descriptors),
            "candidate_tables_with_typeinfo": len(by_typeinfo), "unmatched_base_edges": sum(
                1 for item in relations if not item["table_associations"]["base_candidates"]),
            "unmatched_derived_edges": sum(1 for item in relations if not item["table_associations"]["derived_candidates"]),
            "malformed_edges": malformed_edges, "class_identity_is_not_confirmed": True},
        "status": build_status, "scope": scope, "relationship_count": total,
        "items": relations}
    if existing is None:
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        with connection:
            connection.execute(
                "UPDATE vtable_class_relationships SET stale=1 WHERE stale=0 AND source_snapshot_hash<>?",
                (relation_source_hash,))
            connection.execute(
                "UPDATE vtable_class_relation_runs SET status='stale' WHERE status NOT IN ('stale','error') "
                "AND source_snapshot_hash<>?", (relation_source_hash,))
            connection.execute(
                "INSERT INTO vtable_class_relation_runs(run_id,source_snapshot_hash,rtti_run_id,scope_json,status,result_json,created_at) "
                "VALUES(?,?,?,?,?,?,?)", (run_id, relation_source_hash, rtti_run_id, _json(scope),
                    build_status, _json(result_payload), now))
            connection.executemany(
                "INSERT INTO vtable_class_relationships(relation_id,run_id,derived_typeinfo_ea,base_typeinfo_ea,base_index,status,evidence_json,source_snapshot_hash,stale) "
                "VALUES(?,?,?,?,?,?,?,?,0)",
                [(item["relation_id"], run_id, sqlite_ea(item["derived_typeinfo_ea"]),
                  sqlite_ea(item["base_typeinfo_ea"]), int(item["inheritance"].get("index", 0)),
                  item["status"], _json(item), relation_source_hash) for item in relations])
    else:
        result_payload = json.loads(existing["result_json"])
        with connection:
            connection.execute("UPDATE vtable_class_relation_runs SET status=? WHERE run_id=?",
                (result_payload.get("status", existing["status"]), run_id))
            connection.execute("UPDATE vtable_class_relationships SET stale=0 WHERE run_id=?", (run_id,))
    all_items = result_payload["items"]
    filtered = [item for item in all_items if derived_typeinfo_ea is None
        or int(item["derived_typeinfo_ea"]) == int(derived_typeinfo_ea)]
    total = len(filtered)
    page = filtered[offset:] if limit == 0 else filtered[offset:offset + limit]
    result_payload.update({"cached": existing is not None, "count": len(page), "total": total,
        "truncated": offset + len(page) < total, "items": page,
        "source_vtable_snapshot_hash": current_vtable_hash})
    return result_payload


def preview_vtable_type_plan(connection: sqlite3.Connection, spec: dict[str, Any]) -> dict[str, Any]:
    """Validate a caller-authored type plan against one current table revision."""
    if not isinstance(spec, dict) or set(spec) - {"candidate_id", "relation_id", "type_definition", "assignments", "rationale"}:
        raise ValueError("type preview requires candidate_id and only supported plan fields")
    candidate_id = str(spec.get("candidate_id", "")).strip()
    if not candidate_id:
        raise ValueError("candidate_id is required")
    from .virtual_tables import _current_vtable_candidates
    if candidate_id not in {item["candidate_id"] for item in _current_vtable_candidates(connection)}:
        candidate = None
    else:
        candidate = connection.execute(
            "SELECT * FROM vtable_candidates WHERE candidate_id=? AND stale=0", (candidate_id,),
        ).fetchone()
    if candidate is None:
        raise ValueError("current vtable candidate not found; rebuild the table index")
    if not isinstance(spec.get("type_definition"), dict):
        raise ValueError("type_definition must contain name and declaration")
    definition = spec["type_definition"]
    if set(definition) != {"name", "declaration"}:
        raise ValueError("type_definition requires exactly name and declaration")
    name = str(definition["name"]).strip()
    declaration = str(definition["declaration"]).strip()
    if not name or not declaration or len(declaration) > 65536:
        raise ValueError("type name and declaration must be non-empty, with at most 64 KiB of declaration text")
    if re.search(r"\b" + re.escape(name) + r"\b", declaration) is None:
        raise ValueError("type_definition.name must appear as a named declaration in type_definition.declaration")
    assignments = spec.get("assignments", [])
    if not isinstance(assignments, list) or len(assignments) > 512:
        raise ValueError("assignments must be a list of at most 512 explicit address/declaration pairs")
    allowed: dict[int, set[str]] = {}
    allowed.setdefault(ida_ea(candidate["table_address"]), set()).add("table_start")
    allowed.setdefault(ida_ea(candidate["address_point"]), set()).add("address_point")
    for slot in connection.execute("SELECT * FROM vtable_slots WHERE candidate_id=? AND stale=0 ORDER BY slot_index",
                                   (candidate_id,)):
        allowed.setdefault(ida_ea(slot["entry_address"]), set()).add("slot_entry")
        if slot["target_ea"] is not None:
            allowed.setdefault(ida_ea(slot["target_ea"]), set()).add("slot_implementation")
        if slot["thunk_target_ea"] is not None:
            allowed.setdefault(ida_ea(slot["thunk_target_ea"]), set()).add("thunk_target")
    normalized = []
    seen = set()
    shared_implementations = []
    current_candidate_ids = {item["candidate_id"] for item in _current_vtable_candidates(connection)}
    for index, item in enumerate(assignments):
        if not isinstance(item, dict) or set(item) != {"address", "declaration"}:
            raise ValueError(f"assignments[{index}] requires exactly address and declaration")
        try:
            address = int(item["address"], 0) if isinstance(item["address"], str) else int(item["address"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"assignments[{index}].address must be an integer") from exc
        text = str(item["declaration"]).strip()
        if not text or len(text) > 65536:
            raise ValueError(f"assignments[{index}].declaration must be non-empty and at most 64 KiB")
        if address not in allowed:
            raise ValueError(f"assignment address 0x{address:X} is outside this candidate's table/slot evidence")
        if address in seen:
            raise ValueError(f"duplicate type assignment address 0x{address:X}")
        seen.add(address)
        functions = [dict(row) for row in connection.execute(
            "SELECT start_ea,demangled_name,signature,is_thunk,thunk_target_ea FROM functions WHERE start_ea=?",
            (sqlite_ea(address),))]
        shared = []
        if current_candidate_ids:
            marks = ",".join("?" for _ in current_candidate_ids)
            for row in connection.execute(
                "SELECT DISTINCT c.candidate_id,c.address_point FROM vtable_slots s "
                "JOIN vtable_candidates c USING(candidate_id) WHERE c.candidate_id<>? AND c.stale=0 "
                f"AND c.candidate_id IN ({marks}) AND s.stale=0 "
                "AND (s.target_ea=? OR s.thunk_target_ea=?) ORDER BY c.address_point,c.candidate_id",
                (candidate_id, *sorted(current_candidate_ids), sqlite_ea(address), sqlite_ea(address)),
            ):
                shared.append({"candidate_id": row["candidate_id"], "address_point": ida_ea(row["address_point"])})
        if shared:
            shared_implementations.append({"address": address, "candidate_id": candidate_id,
                "also_referenced_by": shared, "warning": "a shared implementation may serve multiple class/table candidates"})
        normalized.append({"address": address, "address_hex": f"0x{address:X}",
            "declaration": text, "evidence_roles": sorted(allowed[address]), "functions": functions,
            "shared_table_candidates": shared})
    relation_id = spec.get("relation_id")
    relationship_context = None
    if relation_id is not None:
        relations = class_relationships(connection, limit=0)["items"]
        relationship_context = next((item for item in relations if item["relation_id"] == relation_id), None)
        if relationship_context is None:
            raise ValueError("relation_id is not a current RTTI relationship candidate")
        associated = set(relationship_context["table_associations"]["derived_candidates"])
        associated.update(relationship_context["table_associations"]["base_candidates"])
        if candidate_id not in associated:
            raise ValueError("candidate_id is not associated with the selected RTTI relationship")
    revision = type_application_revision(connection)
    plan = {"candidate_id": candidate_id, "relation_id": relation_id,
        "type_definition": {"name": name, "declaration": declaration}, "assignments": normalized,
        "rationale": str(spec.get("rationale", "")), "revision_token": revision,
        "candidate_source_snapshot_hash": candidate["source_snapshot_hash"],
        "candidate_fingerprint_scope": {"candidate_id": candidate_id,
            "address_point": ida_ea(candidate["address_point"]), "slot_count": candidate["slot_count"]},
        "relationship": relationship_context,
        "shared_implementation_warnings": shared_implementations,
        "application_order": ["register_type", *["apply_type" for _ in normalized]],
        "apply_guard": "Pass revision_token to the dedicated batch apply tool; any later edit requires a new preview.",
        "declaration_parse_status": "not_checked_by_IDA",
        "atomicity": "The plan runs in one IDA batch and saves once, but it is not a database transaction; inspect per-assignment results and resynchronize after failure."}
    preview_id = "VTP" + hashlib.sha256(_json(plan).encode("utf-8")).hexdigest()[:28]
    plan["preview_id"] = preview_id
    return {"preview_id": preview_id, "preview_only": True, "revision_token": revision,
        "plan": plan, "warnings": ["This is an application preview, not an IDA type change.",
            "Class names and object layouts remain caller hypotheses unless independently established.",
            "Slot targets and RTTI associations are candidates; shared functions require per-reference review."]}


def assert_type_application_revision(connection: sqlite3.Connection, expected: str | None) -> None:
    if expected is None:
        return
    current = type_application_revision(connection)
    if expected != current:
        raise ValueError(f"type application revision is stale; expected {expected}, current {current}; refresh the preview")


def validate_vtable_type_preview(connection: sqlite3.Connection, preview: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(preview, dict) or not isinstance(preview.get("plan"), dict):
        raise ValueError("preview must be the complete vtable_type_preview result")
    plan = preview["plan"]
    spec = {key: plan[key] for key in ("candidate_id", "relation_id", "type_definition", "rationale")
        if key in plan}
    spec["assignments"] = [{"address": item["address"], "declaration": item["declaration"]}
        for item in plan.get("assignments", [])]
    current = preview_vtable_type_plan(connection, spec)
    if preview.get("preview_id") != current["preview_id"]:
        raise ValueError("vtable type preview content does not match the current plan")
    if preview.get("revision_token") != current["revision_token"]:
        raise ValueError("vtable type preview revision is stale; refresh the preview")
    return spec, current

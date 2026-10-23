"""Persist explicitly resolved call edges without modifying IDA xrefs."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from pathlib import Path
from typing import Any

from .db import ida_ea, sqlite_ea, utc_now
from .selection import parse_int


def mark_derived_calls_stale(
    connection: sqlite3.Connection,
    function_eas: list[int] | tuple[int, ...] | set[int],
    *,
    reason: str,
) -> int:
    """Mark resolver output stale after its source instruction view changes."""
    selected = [sqlite_ea(int(ea)) for ea in function_eas]
    if not selected:
        return 0
    placeholders = ",".join("?" for _ in selected)
    cursor = connection.execute(
        f"UPDATE derived_calls SET stale=1,stale_reason=? "
        f"WHERE function_ea IN ({placeholders}) AND stale=0",
        [reason, *selected],
    )
    return int(cursor.rowcount)


def _field(row: dict[str, Any], *names: str):
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def _confidence(value: Any) -> float | None:
    if value is None:
        return None
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError("derived-call confidence must be between 0 and 1")
    return number


def import_derived_calls(
    connection: sqlite3.Connection,
    input_path: str | Path,
    *,
    resolver: str,
    method: str,
    confidence: float | None = None,
    source_ref: str | None = None,
    notes: str | None = None,
) -> dict:
    """Import one bounded resolver output into current and historical tables.

    The input is either a JSON list or an object with a ``calls`` list. Each
    row must identify ``call_ea``, ``function_ea`` and ``target_ea``; common
    ``caller``/``tail_target`` aliases are accepted for resolver interoperability.
    """
    path = Path(input_path).expanduser().resolve()
    resolver = resolver.strip()
    method = method.strip()
    if not resolver or not method:
        raise ValueError("resolver and method must not be empty")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"derived-call input is not valid UTF-8 JSON: {exc}") from exc
    records = payload.get("calls") if isinstance(payload, dict) else payload
    if not isinstance(records, list) or not records:
        raise ValueError("derived-call input must contain a non-empty list or calls list")
    if len(records) > 10000:
        raise ValueError("derived-call import is limited to 10000 records")
    default_confidence = _confidence(confidence)
    source_ref = (source_ref or f"file:{path}").strip()
    if not source_ref:
        raise ValueError("source_ref must not be empty")
    notes = notes.strip() if notes else None

    normalized: dict[int, dict] = {}
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            raise ValueError(f"derived-call record {index} must be an object")
        try:
            call_ea = parse_int(_field(item, "call_ea", "call_address"))
            function_ea = parse_int(_field(item, "function_ea", "caller", "caller_ea"))
            target_ea = parse_int(_field(item, "target_ea", "tail_target"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"derived-call record {index} has invalid address fields") from exc
        instruction = connection.execute(
            "SELECT function_ea,mnemonic FROM instructions WHERE ea=?",
            (sqlite_ea(call_ea),),
        ).fetchone()
        if instruction is None:
            raise ValueError(f"call address 0x{call_ea:X} is absent from exported instructions")
        exported_function = ida_ea(instruction["function_ea"])
        if exported_function != function_ea:
            raise ValueError(
                f"call 0x{call_ea:X} belongs to function 0x{exported_function:X}, "
                f"not declared function 0x{function_ea:X}"
            )
        record = {
            "call_ea": call_ea,
            "function_ea": function_ea,
            "target_ea": target_ea,
            "mnemonic": str(instruction["mnemonic"] or ""),
            "target_name": _field(item, "target_name"),
            "confidence": _confidence(item.get("confidence")) if item.get("confidence") is not None else default_confidence,
            "source_ref": str(item.get("source_ref") or source_ref),
            "notes": str(item.get("notes") or notes or "").strip() or None,
        }
        previous = normalized.get(call_ea)
        if previous is not None and previous["target_ea"] != target_ea:
            raise ValueError(f"duplicate call 0x{call_ea:X} has conflicting targets")
        normalized[call_ea] = record

    config_hash = hashlib.sha256(json.dumps(
        {"resolver": resolver, "method": method, "source_ref": source_ref,
         "confidence": default_confidence, "notes": notes},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    run_id = "DCR" + hashlib.sha256(raw + config_hash.encode("ascii")).hexdigest()[:32]
    duplicate = connection.execute(
        "SELECT 1 FROM derived_call_runs WHERE run_id=?", (run_id,)
    ).fetchone() is not None

    now = utc_now()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT OR IGNORE INTO derived_call_runs(run_id,input_sha256,resolver,method,record_count,input_path,notes,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (run_id, hashlib.sha256(raw).hexdigest(), resolver, method, len(normalized),
             str(path), notes, now),
        )
        connection.execute("DELETE FROM derived_calls WHERE resolver=?", (resolver,))
        rows = []
        for record in normalized.values():
            target_name = record["target_name"]
            if not target_name:
                row = connection.execute(
                    "SELECT name FROM functions WHERE start_ea=?",
                    (sqlite_ea(record["target_ea"]),),
                ).fetchone()
                target_name = row[0] if row else None
            rows.append((
                resolver, sqlite_ea(record["call_ea"]), sqlite_ea(record["function_ea"]),
                record["mnemonic"], sqlite_ea(record["target_ea"]), target_name,
                record["confidence"], method, record["source_ref"], run_id,
                record["notes"], 0, None, now,
            ))
        connection.executemany(
            "INSERT INTO derived_calls(resolver,call_ea,function_ea,mnemonic,target_ea,target_name,"
            "confidence,method,source_ref,run_id,notes,stale,stale_reason,generated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {"run_id": run_id, "resolver": resolver, "method": method,
            "records": len(normalized), "duplicate": duplicate, "table": "derived_calls",
            "provenance": "derived resolver output, separate from native IDA xrefs"}

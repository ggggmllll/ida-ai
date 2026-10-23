"""Offline audit of native calls that may hide callsite-dependent semantics."""

from __future__ import annotations

import re
import sqlite3
from collections import defaultdict

from .db import ida_ea, sqlite_ea


CALL_TYPES = {"code_near_call", "code_far_call"}
RETURN_ADDRESS_MNEMONICS = {
    "ADD", "ADDS", "SUB", "SUBS", "MOV", "MOVK", "EOR", "AND", "ORN",
    "LDR", "LDRB", "LDRH", "LDRSW", "LDUR", "LDURB", "LDURH", "ADR", "ADRL",
}


def _return_address_hints(disassembly: str | None) -> list[str]:
    """Find a small, explainable subset of dataflow involving the link register."""
    if not disassembly:
        return []
    hints = []
    for line in disassembly.splitlines():
        text = line.split(":", 1)[-1].strip()
        if not text:
            continue
        mnemonic = text.split(None, 1)[0]
        if mnemonic in RETURN_ADDRESS_MNEMONICS and re.search(r"\b(?:X30|LR)\b", text):
            hints.append(text)
            if len(hints) >= 5:
                break
    return hints


def audit_shared_calls(
    connection: sqlite3.Connection,
    function_eas: list[int],
    *,
    min_fan_in: int = 256,
    max_results: int = 10000,
) -> dict:
    """Report high-fan-in native calls whose target consumes the return address.

    This is a diagnostic over exported SQLite evidence. It neither resolves a
    callsite-specific implementation nor creates a derived call edge.
    """
    if min_fan_in < 1 or max_results < 1:
        raise ValueError("min_fan_in and max_results must be positive")

    selected = sorted({int(ea) for ea in function_eas})
    call_rows = []
    for offset in range(0, len(selected), 500):
        batch = selected[offset:offset + 500]
        placeholders = ",".join("?" for _ in batch)
        call_rows.extend(
            tuple(row) for row in connection.execute(
                "SELECT source_ea,source_function_ea,target_ea,type_name "
                f"FROM xrefs WHERE source_function_ea IN ({placeholders}) "
                "AND type_name IN ('code_near_call','code_far_call')",
                [sqlite_ea(ea) for ea in batch],
            )
        )

    if not call_rows:
        return {
            "scope": {"functions": len(selected), "addresses": selected},
            "thresholds": {"min_fan_in": min_fan_in, "max_results": max_results},
            "targets": [],
            "call_sites": [],
            "counts": {"candidate_call_sites": 0, "ambiguous_call_sites": 0},
            "truncated": False,
            "semantics": "callsite-dependent dispatch suspected; target not resolved",
        }

    target_addresses = sorted({int(row[2]) for row in call_rows if row[2] is not None})
    fan_in: dict[int, tuple[int, int]] = {}
    disassembly: dict[int, str] = {}
    names: dict[int, str] = {}
    for offset in range(0, len(target_addresses), 500):
        batch = target_addresses[offset:offset + 500]
        placeholders = ",".join("?" for _ in batch)
        for target, calls, callers in connection.execute(
            "SELECT target_ea,count(*),count(DISTINCT source_function_ea) "
            f"FROM xrefs WHERE target_ea IN ({placeholders}) "
            "AND type_name IN ('code_near_call','code_far_call') "
            "GROUP BY target_ea",
            [sqlite_ea(ea) for ea in batch],
        ):
            fan_in[ida_ea(target)] = (int(calls), int(callers))
        disassembly.update({
            ida_ea(row[0]): str(row[1] or "")
            for row in connection.execute(
                f"SELECT function_ea,text FROM disassembly WHERE function_ea IN ({placeholders})",
                [sqlite_ea(ea) for ea in batch],
            )
        })
        names.update({
            ida_ea(row[0]): str(row[1])
            for row in connection.execute(
                f"SELECT start_ea,name FROM functions WHERE start_ea IN ({placeholders})",
                [sqlite_ea(ea) for ea in batch],
            )
        })

    flagged = {}
    targets = []
    target_counts = defaultdict(int)
    for target, (calls, callers) in fan_in.items():
        hints = _return_address_hints(disassembly.get(target))
        if calls < min_fan_in:
            continue
        classification = (
            "ambiguous_callsite_dependent_dispatch"
            if hints else "high_fan_in_target_needs_manual_review"
        )
        flagged[target] = classification
        target_counts[target] = sum(
            1 for source, _, candidate, _ in call_rows if int(candidate) == target
        )
        targets.append({
            "target_ea": target,
            "target_name": names.get(target),
            "native_call_count": calls,
            "caller_function_count": callers,
            "selected_scope_call_count": target_counts[target],
            "return_address_hints": hints,
            "classification": classification,
            "target_identity_resolved": classification != "ambiguous_callsite_dependent_dispatch",
            "disassembly_available": target in disassembly,
        })

    targets.sort(key=lambda item: (-item["native_call_count"], item["target_ea"]))
    call_sites = []
    ambiguous_count = 0
    flagged_count = sum(
        1 for _, _, target, _ in call_rows
        if int(target) in flagged
    )
    for source, function, target, xref_type in sorted(call_rows):
        target = int(target)
        if target not in flagged:
            continue
        if flagged[target] == "ambiguous_callsite_dependent_dispatch":
            ambiguous_count += 1
        if len(call_sites) >= max_results:
            continue
        call_sites.append({
            "source_ea": ida_ea(source),
            "source_function_ea": ida_ea(function) if function is not None else None,
            "target_ea": target,
            "xref_type": xref_type,
            "classification": flagged[target],
            "target_identity_resolved": flagged[target] != "ambiguous_callsite_dependent_dispatch",
        })

    return {
        "scope": {"functions": len(selected), "addresses": selected},
        "thresholds": {"min_fan_in": min_fan_in, "max_results": max_results},
        "targets": targets,
        "call_sites": call_sites,
        "counts": {
            "selected_native_calls": len(call_rows),
            "candidate_call_sites": flagged_count,
            "ambiguous_call_sites": ambiguous_count,
        },
        "truncated": flagged_count > len(call_sites),
        "semantics": "callsite-dependent dispatch suspected; target not resolved",
    }

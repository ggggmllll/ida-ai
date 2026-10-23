"""Position-aware matching of raw loaded pointer observations."""
from .db import ida_ea, sqlite_ea, get_metadata
from .selection import parse_int


def normalize_signature(spec):
    size = int(spec.get("pointer_size", 8))
    if size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    slots = []
    for item in spec.get("slots", []):
        offset = parse_int(str(item["offset"]))
        kind = item.get("kind", "exact" if "target" in item else "function")
        if offset < 0 or offset > 65536 or offset % size or kind not in {"exact", "function", "null"}:
            raise ValueError("slots need aligned offsets <=65536 and exact/function/null kinds")
        slot = dict(offset=offset, kind=kind)
        if kind == "exact":
            slot["target"] = parse_int(str(item["target"]))
            if not 0 < slot["target"] < 1 << 64:
                raise ValueError("exact anchor target must be a nonzero unsigned address")
        slots.append(slot)
    if not slots or len(slots) > 128 or len({s["offset"] for s in slots}) != len(slots):
        raise ValueError("provide 1..128 distinct slots")
    if not any(s["kind"] == "exact" for s in slots):
        raise ValueError("at least one exact anchor is required")
    return dict(pointer_size=size, slots=slots)


def match_vtable_signature(connection, spec, *, start=None, end=None, limit=1000, max_anchors=100000):
    spec = normalize_signature(spec)
    if limit < 1 or max_anchors < 1 or (start is not None and end is not None and end <= start):
        raise ValueError("positive match budgets and increasing range required")
    anchor = next(s for s in spec["slots"] if s["kind"] == "exact")
    # Indexed anchor lookup; never loads the complete pointer snapshot into Python.
    cursor = connection.execute("SELECT source_ea FROM data_pointer_slots WHERE raw_value=? AND pointer_size=? ORDER BY source_ea",
                                (sqlite_ea(anchor["target"]), spec["pointer_size"]))
    matches, examined, budget = [], 0, False
    for row in cursor:
        base = ida_ea(row[0]) - anchor["offset"]
        if base < 0 or (start is not None and base < start) or (end is not None and base + max(s["offset"] for s in spec["slots"]) + spec["pointer_size"] > end):
            continue
        if examined >= max_anchors:
            budget = True
            break
        examined += 1
        evidence = []
        for slot in spec["slots"]:
            if base + slot["offset"] >= 1 << 64:
                break
            item = connection.execute("SELECT * FROM data_pointer_slots WHERE source_ea=? AND pointer_size=?",
                                      (sqlite_ea(base + slot["offset"]),spec["pointer_size"])).fetchone()
            if item is None:
                break
            value = ida_ea(item["raw_value"])
            if (slot["kind"] == "exact" and value != slot["target"]) or (slot["kind"] == "function" and item["target_kind"] != "function") or (slot["kind"] == "null" and value != 0):
                break
            evidence.append(dict(offset=slot["offset"], value=f"0x{value:X}", kind=item["target_kind"]))
        else:
            matches.append(dict(address=f"0x{base:X}", slots=evidence))
            if len(matches) > limit:
                break
    return dict(spec=spec, matches=matches[:limit], count=min(len(matches),limit),
                truncated=budget or len(matches)>limit, anchors_examined=examined,
                coverage=get_metadata(connection,"data_pointer_scan"),
                interpretation="structural_candidates_only", exact_match="raw_loaded_pointer_value")

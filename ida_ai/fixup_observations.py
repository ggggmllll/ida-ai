"""Bounded loader-fixup observations; never a runtime pointer decoder."""
from __future__ import annotations


def collect_fixups(api, read_bytes, ranges, badaddr, *, max_entries=100000):
    if max_entries < 1:
        raise ValueError("max_entries must be positive")
    # Merge chunks so fixups spanning an export chunk boundary remain readable.
    merged = []
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    coverage = {"status": "complete_within_ranges", "ranges": merged,
        "max_entries": max_entries, "visited": 0, "errors": [],
        "interpretation": "loader_metadata_only_not_runtime_targets",
        "bytes_source": "loaded_idb_image_not_original_disk", "runtime_targets_decoded": False}
    items = []
    if api is None:
        coverage["status"] = "unsupported_api"
        return items, coverage
    try:
        # Seek per range: do not walk millions of unrelated fixups first.
        seen = set()
        for start, end in merged:
            ea = api.get_first_fixup_ea() if start == 0 else api.get_next_fixup_ea(start - 1)
            previous = start - 1
            while ea != badaddr and ea < end:
                if ea <= previous or ea < start:
                    raise ValueError("non_monotonic_fixup_enumeration")
                previous = ea
                if ea in seen:
                    raise ValueError("duplicate_fixup_enumeration")
                if coverage["visited"] >= max_entries:
                    coverage["status"] = "truncated"
                    coverage["errors"].append({"ea": ea, "reason": "max_entries"})
                    return items, coverage
                seen.add(ea)
                coverage["visited"] += 1
                item = {"source_ea": int(ea), "status": "ok"}
                try:
                    fd = api.fixup_data_t()
                    if not api.get_fixup(fd, ea):
                        raise ValueError("get_fixup_failed")
                    for name in ("get_type", "get_flags", "get_base", "is_custom", "is_extdef", "is_unused"):
                        method = getattr(fd, name, None)
                        if method is not None:
                            item[name.removeprefix("get_")] = method()
                    for name in ("sel", "off", "displacement"):
                        value = getattr(fd, name, None)
                        if value is not None:
                            item[name] = int(value)
                    size = int(api.calc_fixup_size(item["type"]))
                    item["size"] = size if size > 0 else None
                    # Never read outside observed ranges or trust a custom size blindly.
                    if size <= 0 or size > 64 or ea + size > end:
                        item.update(status="partial", bytes_status="unknown_size_or_outside_range")
                    else:
                        raw = read_bytes(ea, size)
                        if raw is None or len(raw) != size:
                            item.update(status="partial", bytes_status="unreadable")
                        else:
                            item.update(loaded_bytes_hex=bytes(raw).hex(), bytes_status="ok")
                except Exception as exc:
                    item.update(status="partial", error=str(exc))
                if item["status"] != "ok":
                    coverage["status"] = "partial"
                    coverage["errors"].append({"ea": int(ea), "reason": item.get("error", item.get("bytes_status"))})
                items.append(item)
                ea = api.get_next_fixup_ea(ea)
    except Exception as exc:
        coverage["status"] = "partial"
        coverage["errors"].append({"reason": str(exc)})
    return items, coverage

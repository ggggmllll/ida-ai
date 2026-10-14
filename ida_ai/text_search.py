"""Bounded literal search over exported disassembly, pseudocode, and comments."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
from typing import Literal

import regex

from .db import connect, ida_ea
from .selection import parse_int


def search_code(
    db_path: str | Path,
    terms: list[str],
    *,
    view: Literal["both", "disassembly", "pseudocode"] = "both",
    operator: Literal["all", "any"] = "all",
    use_regex: bool = False,
    case_sensitive: bool = False,
    start_address: str | None = None,
    end_address: str | None = None,
    limit: int = 100,
) -> dict:
    if view not in ("both", "disassembly", "pseudocode"):
        raise ValueError("view must be both, disassembly, or pseudocode")
    if operator not in ("all", "any"):
        raise ValueError("operator must be all or any")
    if not terms or any(not term.strip() for term in terms):
        raise ValueError("terms must contain at least one non-empty string")
    if len(terms) > 16 or any(len(term) > 256 for term in terms):
        raise ValueError("provide at most 16 search terms, each at most 256 characters")
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    start = parse_int(start_address) if start_address is not None else None
    end = parse_int(end_address) if end_address is not None else None
    if start is not None and end is not None and end <= start:
        raise ValueError("end_address must be greater than start_address")
    flags = 0 if case_sensitive else regex.IGNORECASE
    try:
        patterns = [regex.compile(term, flags) if use_regex else None for term in terms]
    except regex.error as exc:
        raise ValueError(f"invalid search expression: {exc}") from exc

    def find_matches(text: str) -> list[bool]:
        if use_regex:
            try:
                return [bool(pattern.search(text, timeout=0.05)) for pattern in patterns]
            except TimeoutError as exc:
                raise ValueError("regular expression search exceeded its 50 ms per-term limit") from exc
        haystack = text if case_sensitive else text.casefold()
        needles = terms if case_sensitive else [term.casefold() for term in terms]
        return [needle in haystack for needle in needles]

    views = ("disassembly", "pseudocode") if view == "both" else (view,)
    candidates = []
    with closing(connect(db_path)) as connection:
        for current_view in views:
            rows = connection.execute(
                f"SELECT f.start_ea, f.end_ea, f.name, v.text FROM {current_view} v "
                "JOIN functions f ON f.start_ea=v.function_ea "
                "WHERE v.status='ok' ORDER BY f.start_ea"
            )
            for row in rows:
                function_ea = ida_ea(row["start_ea"])
                function_end = ida_ea(row["end_ea"])
                if start is not None and function_end <= start:
                    continue
                if end is not None and function_ea >= end:
                    continue
                text = row["text"] or ""
                found = find_matches(text)
                if all(found) if operator == "all" else any(found):
                    candidates.append((current_view, function_ea, row["name"], text, found))
        if view in ("both", "disassembly"):
            rows = connection.execute(
                "SELECT c.address,c.function_ea,f.name,c.text FROM comments c "
                "LEFT JOIN functions f ON f.start_ea=c.function_ea WHERE c.kind='assembly' "
                "ORDER BY c.address"
            )
            for row in rows:
                address = ida_ea(row["address"])
                if (start is not None and address < start) or (end is not None and address >= end):
                    continue
                text = row["text"] or ""
                found = find_matches(text)
                if all(found) if operator == "all" else any(found):
                    func_ea = ida_ea(row["function_ea"]) if row["function_ea"] is not None else None
                    candidates.append(("assembly_comment", func_ea, row["name"], text, found, address))
            function_comments = connection.execute(
                "SELECT start_ea,name,comment,repeatable_comment FROM functions "
                "WHERE comment IS NOT NULL OR repeatable_comment IS NOT NULL ORDER BY start_ea"
            )
            for row in function_comments:
                address = ida_ea(row["start_ea"])
                if (start is not None and address < start) or (end is not None and address >= end):
                    continue
                for text in (row["comment"], row["repeatable_comment"]):
                    if not text:
                        continue
                    found = find_matches(text)
                    if all(found) if operator == "all" else any(found):
                        candidates.append(("function_comment", address, row["name"], text, found, address))

        if view in ("both", "pseudocode"):
            rows = connection.execute(
                "SELECT c.address,c.function_ea,f.name,c.text FROM comments c "
                "LEFT JOIN functions f ON f.start_ea=c.function_ea WHERE c.kind='pseudocode' "
                "ORDER BY c.address"
            )
            for row in rows:
                address = ida_ea(row["address"])
                if (start is not None and address < start) or (end is not None and address >= end):
                    continue
                text = row["text"] or ""
                found = find_matches(text)
                if all(found) if operator == "all" else any(found):
                    func_ea = ida_ea(row["function_ea"]) if row["function_ea"] is not None else None
                    candidates.append(("pseudocode_comment", func_ea, row["name"], text, found, address))

    candidates.sort(key=lambda item: (item[1] if item[1] is not None else item[-1], item[0]))
    matches = []
    for item in candidates[:limit]:
        source, function_ea, name, text, found, *extra = item
        if source in ("assembly_comment", "function_comment", "pseudocode_comment"):
            snippets = [{"address": f"0x{extra[0]:X}", "line": text}]
        else:
            snippets = []
            for index, line in enumerate(text.splitlines()):
                if not any(find_matches(line)):
                    continue
                address = None
                if source == "disassembly" and ":" in line:
                    try:
                        address = f"0x{int(line.split(':', 1)[0], 16):X}"
                    except ValueError:
                        pass
                snippets.append({"address": address, "line_number": index + 1, "line": line})
                if len(snippets) >= 20:
                    break
        matches.append({
            "view": source,
            "function_ea": f"0x{function_ea:X}" if function_ea is not None else None,
            "function_name": name,
            "matched_terms": [terms[i] for i, value in enumerate(found) if value],
            "snippets": snippets,
        })
    return {"count": len(matches), "truncated": len(candidates) > limit, "matches": matches}

"""IDA-side headless exporter.

This module is loaded by ``idat -A -S``.  It intentionally contains no Qt or
``ida_kernwin`` dependency, so the same export works in batch mode and under
an idalib host.  The parent process only needs to read the resulting SQLite
file.
"""

from __future__ import annotations

from pathlib import Path
from contextlib import closing
import tempfile
from typing import Iterable
from collections import Counter

try:  # imported only inside IDA
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_gdl
    import ida_ida
    import ida_idaapi
    import ida_lines
    import ida_loader
    import ida_name
    import ida_nalt
    import ida_xref
    import ida_segment
    import idautils
    import idc
except ImportError as exc:  # pragma: no cover - exercised by IDA
    raise RuntimeError("ida_export.py must run inside IDA or idalib") from exc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from .db import connect, reset_analysis, set_metadata, sqlite_ea, ida_ea, utc_now
from .selection import BytePattern, parse_pattern


XREF_TYPE_NAMES = {
    getattr(ida_xref, "fl_U", -1): "data_unknown",
    getattr(ida_xref, "dr_O", -2): "data_offset",
    getattr(ida_xref, "dr_W", -3): "data_write",
    getattr(ida_xref, "dr_R", -4): "data_read",
    getattr(ida_xref, "dr_T", -5): "data_text",
    getattr(ida_xref, "dr_I", -6): "data_informational",
    getattr(ida_xref, "fl_CF", -7): "code_far_call",
    getattr(ida_xref, "fl_CN", -8): "code_near_call",
    getattr(ida_xref, "fl_JF", -9): "code_far_jump",
    getattr(ida_xref, "fl_JN", -10): "code_near_jump",
    getattr(ida_xref, "fl_F", -11): "ordinary_flow",
}


def _text(value) -> str | None:
    return str(value) if value not in (None, "") else None


def _safe(call, default=None):
    try:
        return call()
    except Exception:
        return default


def segment_permissions(perm: int) -> str:
    return "".join(("r" if perm & ida_segment.SEGPERM_READ else "-",
                    "w" if perm & ida_segment.SEGPERM_WRITE else "-",
                    "x" if perm & ida_segment.SEGPERM_EXEC else "-"))


def find_segment(ea: int):
    return ida_segment.getseg(ea)


def function_at(ea: int):
    func = ida_funcs.get_func(ea)
    return func


def function_name(ea: int) -> str:
    return ida_funcs.get_func_name(ea) or ida_name.get_name(ea) or f"sub_{ea:X}"


def add_segments(connection) -> None:
    rows = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        perm = int(getattr(seg, "perm", 0))
        rows.append((sqlite_ea(seg.start_ea), sqlite_ea(seg.end_ea), ida_segment.get_segm_name(seg) or "",
                     _text(_safe(lambda: ida_segment.get_segm_class(seg))), perm,
                     segment_permissions(perm), int(getattr(seg, "bitness", 0)),
                     int(getattr(seg, "sel", 0)), int(getattr(seg, "flags", 0))))
    connection.executemany("INSERT INTO segments(start_ea,end_ea,name,class_name,permissions,permissions_text,bitness,selector,flags) VALUES(?,?,?,?,?,?,?,?,?)", rows)


def add_functions(connection) -> list[int]:
    addresses = []
    rows = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func is None:
            continue
        name = function_name(ea)
        signature = _safe(lambda: idc.get_type(ea))
        demangled = _safe(lambda: idc.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN)))
        seg = find_segment(ea)
        rows.append((sqlite_ea(func.start_ea), sqlite_ea(func.end_ea), name, _text(demangled), _text(signature),
                     int(func.flags), int(func.end_ea - func.start_ea),
                     ida_segment.get_segm_name(seg) if seg else None,
                     int(bool(func.flags & ida_funcs.FUNC_LIB)),
                     int(bool(func.flags & getattr(ida_funcs, "FUNC_THUNK", 0))),
                     _safe(lambda: idc.get_func_cmt(ea, 0)), _safe(lambda: idc.get_func_cmt(ea, 1))))
        addresses.append(int(func.start_ea))
    connection.executemany("INSERT INTO functions(start_ea,end_ea,name,demangled_name,signature,flags,size,segment_name,is_library,is_thunk,comment,repeatable_comment) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return addresses


def add_xrefs(connection) -> None:
    rows = []
    statement = "INSERT OR IGNORE INTO xrefs(source_ea,target_ea,xref_type,is_code,is_data,source_function_ea,target_function_ea,type_name) VALUES(?,?,?,?,?,?,?,?)"
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        for item_ea in idautils.Heads(seg.start_ea, seg.end_ea):
            for ref in idautils.XrefsFrom(item_ea, 0):
                ref_target = int(ref.to)
                source_func = ida_funcs.get_func(ref.frm)
                target_func = ida_funcs.get_func(ref.to)
                rows.append((sqlite_ea(ref.frm), sqlite_ea(ref_target), int(ref.type), int(bool(ref.iscode)),
                             int(not bool(ref.iscode)),
                             sqlite_ea(source_func.start_ea) if source_func else None,
                             sqlite_ea(target_func.start_ea) if target_func else None,
                             XREF_TYPE_NAMES.get(int(ref.type), f"type_{int(ref.type)}")))
                if len(rows) >= 10000:
                    connection.executemany(statement, rows)
                    rows.clear()
    if rows:
        connection.executemany(statement, rows)


def add_cfg(connection, addresses: list[int]) -> None:
    for func_ea in addresses:
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue
        try:
            blocks = list(ida_gdl.FlowChart(func))
        except Exception:
            continue
        block_rows, edge_rows = [], []
        edge_index = 0
        for index, block in enumerate(blocks):
            block_rows.append((sqlite_ea(func_ea), index, sqlite_ea(block.start_ea), sqlite_ea(block.end_ea)))
            for successor in block.succs():
                edge_rows.append((sqlite_ea(func_ea), edge_index, sqlite_ea(block.start_ea), sqlite_ea(successor.start_ea)))
                edge_index += 1
        connection.executemany("INSERT INTO basic_blocks(function_ea,block_index,start_ea,end_ea) VALUES(?,?,?,?)", block_rows)
        connection.executemany("INSERT INTO cfg_edges(function_ea,edge_index,source_block_ea,target_block_ea) VALUES(?,?,?,?)", edge_rows)


def disassembly_lines(func_ea: int):
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return []
    lines = []
    for ea in idautils.FuncItems(func_ea):
        text = _safe(lambda: ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS), "") or ""
        text = ida_lines.tag_remove(text)
        size = int(_safe(lambda: ida_bytes.get_item_size(ea), 0) or 0)
        raw = _safe(lambda: ida_bytes.get_bytes(ea, size), b"") or b""
        lines.append((int(ea), int(ea - func.start_ea), size, text, text.split(None, 1)[0] if text else None,
                      text.split(None, 1)[1] if text and " " in text else None, bytes(raw).hex()))
    return lines


def add_disassembly(connection, addresses: list[int]) -> None:
    now = utc_now()
    for ordinal, func_ea in enumerate(addresses, 1):
        try:
            connection.execute("DELETE FROM instructions WHERE function_ea = ?", (sqlite_ea(func_ea),))
            lines = disassembly_lines(func_ea)
            text = "\n".join(f"{ea:X}: {line}" for ea, _, _, line, _, _, _ in lines)
            connection.execute("INSERT OR REPLACE INTO disassembly(function_ea,text,line_count,status,error,generated_at) VALUES(?,?,?,?,?,?)", (sqlite_ea(func_ea), text, len(lines), "ok", None, now))
            connection.executemany("INSERT OR REPLACE INTO instructions(ea,function_ea,offset,size,text,mnemonic,operands,bytes_hex) VALUES(?,?,?,?,?,?,?,?)", ((sqlite_ea(ea), sqlite_ea(func_ea), offset, size, text_line, mnemonic, operands, raw) for ea, offset, size, text_line, mnemonic, operands, raw in lines))
        except Exception as exc:
            connection.execute("INSERT OR REPLACE INTO disassembly(function_ea,text,line_count,status,error,generated_at) VALUES(?,?,?,?,?,?)", (sqlite_ea(func_ea), "", 0, "error", str(exc), now))
        if ordinal % 100 == 0:
            connection.commit()


def add_pseudocode(connection, addresses: list[int]) -> None:
    now = utc_now()
    decompiler_ready = ida_hexrays is not None and bool(_safe(ida_hexrays.init_hexrays_plugin, False))
    for ordinal, func_ea in enumerate(addresses, 1):
        try:
            if not decompiler_ready:
                raise RuntimeError("Hex-Rays decompiler unavailable")
            ida_hexrays.mark_cfunc_dirty(func_ea, False)
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc is None:
                raise RuntimeError("decompile returned None")
            connection.execute("INSERT OR REPLACE INTO pseudocode(function_ea,text,status,error,backend,generated_at) VALUES(?,?,?,?,?,?)", (sqlite_ea(func_ea), str(cfunc).strip(), "ok", None, "ida_hexrays", now))
        except Exception as exc:
            connection.execute("INSERT OR REPLACE INTO pseudocode(function_ea,text,status,error,backend,generated_at) VALUES(?,?,?,?,?,?)", (sqlite_ea(func_ea), None, "error", str(exc), "ida_hexrays", now))
        if ordinal % 100 == 0:
            connection.commit()


def export_views(connection, addresses: Iterable[int], view: str) -> dict:
    """Export one view for the requested functions into an existing database."""

    selected = [int(ea) for ea in addresses]
    if view == "disassembly":
        add_disassembly(connection, selected)
    elif view == "pseudocode":
        add_pseudocode(connection, selected)
    else:
        raise ValueError(f"unsupported function view: {view}")
    connection.commit()
    table = "disassembly" if view == "disassembly" else "pseudocode"
    counts: Counter[str] = Counter()
    for offset in range(0, len(selected), 500):
        batch = selected[offset:offset + 500]
        rows = connection.execute(
            f"SELECT status, count(*) AS count FROM {table} WHERE function_ea IN ({','.join('?' for _ in batch)}) GROUP BY status",
            [sqlite_ea(ea) for ea in batch],
        ).fetchall()
        counts.update({str(row[0]): int(row[1]) for row in rows})
    return {"view": view, "functions": len(selected), "statuses": dict(counts)}


def _segment_info(seg) -> dict | None:
    if seg is None:
        return None
    perm = int(getattr(seg, "perm", 0))
    return {
        "start": int(seg.start_ea),
        "end": int(seg.end_ea),
        "name": ida_segment.get_segm_name(seg) or "",
        "class_name": _text(_safe(lambda: ida_segment.get_segm_class(seg))),
        "permissions": perm,
        "permissions_text": segment_permissions(perm),
        "bitness": int(getattr(seg, "bitness", 0)),
    }


def address_info(ea: int) -> dict:
    """Return stable metadata for one effective address."""

    ea = int(ea)
    seg = find_segment(ea)
    flags = int(_safe(lambda: ida_bytes.get_full_flags(ea), 0) or 0)
    func = function_at(ea)
    item_start = int(_safe(lambda: ida_bytes.get_item_head(ea), ea) or ea)
    item_size = int(_safe(lambda: ida_bytes.get_item_size(item_start), 0) or 0)
    file_offset = int(_safe(lambda: ida_loader.get_fileregion_offset(ea), -1))
    return {
        "address": ea,
        "address_hex": f"0x{ea:X}",
        "mapped": seg is not None,
        "loaded": bool(_safe(lambda: ida_bytes.is_loaded(ea), False)),
        "segment": _segment_info(seg),
        "file_offset": file_offset,
        "flags": flags,
        "item_start": item_start,
        "item_size": item_size,
        "name": _text(_safe(lambda: ida_name.get_name(ea))),
        "function": {
            "start": int(func.start_ea),
            "end": int(func.end_ea),
            "name": function_name(func.start_ea),
        } if func else None,
    }


def file_offset_info(offset: int) -> dict:
    offset = int(offset)
    ea = int(ida_loader.get_fileregion_ea(offset))
    if ea == ida_idaapi.BADADDR or find_segment(ea) is None:
        raise ValueError(f"file offset 0x{offset:X} has no mapped IDA address")
    result = address_info(ea)
    result["requested_file_offset"] = offset
    return result


def _record_memory(connection, address: int, raw: bytes) -> None:
    now = utc_now()
    rows = []
    statement = "INSERT OR REPLACE INTO memory_bytes(address,value,flags,segment_name,permissions_text,updated_at) VALUES(?,?,?,?,?,?)"
    for offset, value in enumerate(raw):
        ea = int(address + offset)
        seg = find_segment(ea)
        perm_text = segment_permissions(int(getattr(seg, "perm", 0))) if seg else None
        seg_name = ida_segment.get_segm_name(seg) if seg else None
        rows.append((sqlite_ea(ea), int(value), int(_safe(lambda ea=ea: ida_bytes.get_full_flags(ea), 0) or 0), seg_name, perm_text, now))
        if len(rows) == 4096:
            connection.executemany(statement, rows)
            rows.clear()
    if rows:
        connection.executemany(statement, rows)


def read_bytes(connection, address: int, size: int) -> dict:
    address, size = int(address), int(size)
    if size < 0:
        raise ValueError("size must be non-negative")
    raw = b"" if size == 0 else ida_bytes.get_bytes(address, size)
    if raw is None:
        raise ValueError(f"unable to read {size} bytes at 0x{address:X}")
    raw = bytes(raw)
    _record_memory(connection, address, raw)
    connection.commit()
    return {"address": address, "address_hex": f"0x{address:X}", "size": len(raw), "hex": raw.hex(" "), "bytes": list(raw)}


def write_bytes(connection, address: int, raw: bytes, idb_path: str | Path) -> dict:
    address = int(address)
    raw = bytes(raw)
    if not raw:
        raise ValueError("write data cannot be empty")
    if ida_bytes.get_bytes(address, len(raw)) is None:
        raise ValueError(f"unable to write {len(raw)} bytes at 0x{address:X}")
    ida_bytes.patch_bytes(address, raw)
    if ida_bytes.get_bytes(address, len(raw)) != raw:
        raise RuntimeError("IDA did not retain the patched bytes")
    if not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete after patch")
    if not ida_loader.save_database(str(idb_path), 0):
        raise RuntimeError("IDA failed to save the patched database")
    _record_memory(connection, address, raw)
    connection.commit()
    return {"address": address, "address_hex": f"0x{address:X}", "size": len(raw), "hex": raw.hex(" "), "bytes": list(raw)}


SCAN_CHUNK_SIZE = 1 << 20


def _scan_chunks(start: int, end: int, overlap: int):
    """Read bounded chunks, retaining enough lookahead for boundary matches."""

    for chunk_start in range(start, end, SCAN_CHUNK_SIZE):
        primary_end = min(end, chunk_start + SCAN_CHUNK_SIZE)
        read_end = min(end, primary_end + overlap)
        raw = ida_bytes.get_bytes(chunk_start, read_end - chunk_start)
        if raw is not None:
            yield chunk_start, primary_end, bytes(raw)


def _loaded_span(address: int, size: int) -> bool:
    return all(ida_bytes.is_loaded(address + offset) for offset in range(size))


def search_patterns(connection, patterns: list[dict], *, start: int | None = None, end: int | None = None, search_id: str, limit: int = 1000) -> dict:
    parsed = [parse_pattern(str(item.get("pattern", "")), item.get("mask")) for item in patterns]
    if not parsed:
        raise ValueError("at least one search pattern is required")
    if any(pattern.length > 4096 for pattern in parsed):
        raise ValueError("search patterns must be at most 4096 bytes")
    if start is not None and end is not None and int(end) <= int(start):
        raise ValueError("search end must be greater than search start")
    if limit < 0:
        raise ValueError("limit must be non-negative")
    connection.execute("DELETE FROM search_matches WHERE search_id = ?", (search_id,))
    matches = []
    truncated = False
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        window_start = max(int(seg.start_ea), int(start)) if start is not None else int(seg.start_ea)
        window_end = min(int(seg.end_ea), int(end)) if end is not None else int(seg.end_ea)
        if window_end <= window_start:
            continue
        for chunk_start, primary_end, raw in _scan_chunks(window_start, window_end, max(p.length for p in parsed) - 1):
            for offset in range(primary_end - chunk_start):
                for pattern_index, pattern in enumerate(parsed):
                    if pattern.matches(raw, offset) and _loaded_span(chunk_start + offset, pattern.length):
                        if limit and len(matches) >= limit:
                            truncated = True
                            break
                        matches.append((chunk_start + offset, pattern_index))
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            break
    rows = [(search_id, ordinal, sqlite_ea(address), pattern_index, "pattern") for ordinal, (address, pattern_index) in enumerate(matches)]
    connection.executemany("INSERT INTO search_matches(search_id,ordinal,address,pattern_index,match_kind) VALUES(?,?,?,?,?)", rows)
    connection.commit()
    return {"search_id": search_id, "count": len(matches), "truncated": truncated, "matches": [{"address": ea, "address_hex": f"0x{ea:X}", "pattern_index": index} for ea, index in matches]}


def search_pointers(connection, *, target: int | None = None, start: int | None = None, end: int | None = None, pointer_size: int | None = None, search_id: str, limit: int = 1000) -> dict:
    pointer_size = int(pointer_size or (8 if ida_ida.inf_is_64bit() else 4))
    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    if start is not None and end is not None and int(end) <= int(start):
        raise ValueError("search end must be greater than search start")
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if target is not None and not 0 <= int(target) < (1 << (8 * pointer_size)):
        raise ValueError("target does not fit pointer size")
    connection.execute("DELETE FROM search_matches WHERE search_id = ?", (search_id,))
    matches = []
    truncated = False
    byteorder = "big" if ida_ida.inf_is_be() else "little"
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        window_start = max(int(seg.start_ea), int(start)) if start is not None else int(seg.start_ea)
        window_end = min(int(seg.end_ea), int(end)) if end is not None else int(seg.end_ea)
        if window_end - window_start < pointer_size:
            continue
        for chunk_start, primary_end, raw in _scan_chunks(window_start, window_end, pointer_size - 1):
            if target is not None:
                needle = int(target).to_bytes(pointer_size, byteorder, signed=False)
                offsets = []
                position = raw.find(needle)
                while position != -1:
                    offsets.append(position)
                    position = raw.find(needle, position + 1)
            else:
                offsets = range(0, primary_end - chunk_start, pointer_size)
            for offset in offsets:
                source = chunk_start + offset
                if source >= primary_end or offset + pointer_size > len(raw):
                    continue
                value = int.from_bytes(raw[offset:offset + pointer_size], byteorder)
                if target is None and (value == 0 or ida_segment.getseg(value) is None):
                    continue
                if not _loaded_span(source, pointer_size):
                    continue
                if limit and len(matches) >= limit:
                    truncated = True
                    break
                source_func = ida_funcs.get_func(source)
                target_func = ida_funcs.get_func(value)
                target_name = ida_name.get_name(value) or None
                if target_func:
                    target_type = "function"
                elif ida_bytes.is_strlit(ida_bytes.get_full_flags(value)):
                    target_type = "string"
                elif ida_bytes.is_code(ida_bytes.get_full_flags(value)):
                    target_type = "code"
                else:
                    target_type = "data"
                connection.execute(
                    "INSERT OR REPLACE INTO pointers(source_address,target_address,pointer_size,source_segment,target_name,target_type,source_function_ea,target_function_ea,source_kind) VALUES(?,?,?,?,?,?,?,?,?)",
                    (sqlite_ea(source), sqlite_ea(value), pointer_size, ida_segment.get_segm_name(seg) or "", target_name, target_type,
                     sqlite_ea(source_func.start_ea) if source_func else None, sqlite_ea(target_func.start_ea) if target_func else None, "raw_scan"),
                )
                matches.append({"source_address": source, "source_address_hex": f"0x{source:X}", "target_address": value, "target_address_hex": f"0x{value:X}", "pointer_size": pointer_size, "target_name": target_name, "target_type": target_type})
            if truncated:
                break
        if truncated:
            break
    connection.executemany(
        "INSERT INTO search_matches(search_id,ordinal,address,pattern_index,match_kind) VALUES(?,?,?,?,?)",
        ((search_id, index, sqlite_ea(item["source_address"]), None, "pointer") for index, item in enumerate(matches)),
    )
    connection.commit()
    return {"search_id": search_id, "pointer_size": pointer_size, "count": len(matches), "truncated": truncated, "matches": matches}


def synchronize_database(output: str | Path, idb_path: str | Path, all_views: bool = False) -> dict:
    """Rebuild observations in isolation, then publish one SQLite snapshot."""
    if not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete")
    if ida_hexrays is not None and ida_hexrays.init_hexrays_plugin():
        ida_hexrays.clear_cached_cfuncs()
    with closing(connect(output)) as source:
        selections = {view: [ida_ea(row[0]) for row in source.execute(
            f"SELECT function_ea FROM {view}")] for view in ("disassembly", "pseudocode")}
        with tempfile.TemporaryDirectory(prefix="ida-ai-sync-", dir=Path(output).parent) as directory:
            staging = Path(directory) / "snapshot.sqlite"
            with closing(connect(staging)) as target:
                source.backup(target)
            summary = export_database(staging, idb_path=idb_path, skip_analysis=True)
            with closing(connect(staging)) as target:
                functions = {ida_ea(row[0]) for row in target.execute("SELECT start_ea FROM functions")}
                views = {}
                for view, previous in selections.items():
                    selected = sorted(functions if all_views else functions.intersection(previous))
                    views[view] = export_views(target, selected, view)
                # Global symbols/types are part of the same revision as the views.
                target.execute("CREATE TABLE IF NOT EXISTS symbols(address INTEGER PRIMARY KEY,name TEXT,type TEXT)")
                target.execute("DELETE FROM symbols")
                target.executemany("INSERT INTO symbols VALUES(?,?,?)",
                    ((sqlite_ea(ea), name, idc.get_type(ea)) for ea, name in idautils.Names()))
                target.execute("DELETE FROM operations WHERE action IN ('search','pointer_search')")
                set_metadata(target, {"synchronized_at": utc_now()})
                target.commit()
                if not ida_loader.save_database(str(idb_path), 0):
                    raise RuntimeError("IDA failed to save synchronized database")
                target.backup(source)
    return {**summary, "views": views, "scope": "full analysis; all or previously exported views"}


def export_database(output: str | Path, *, idb_path: str | Path, skip_analysis: bool = False, clear_operations: bool = False) -> dict:
    if not skip_analysis and not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete")
    connection = connect(output)
    try:
        reset_analysis(connection, clear_operations=clear_operations)
        metadata = {
            "input_path": _safe(ida_nalt.get_input_file_path, ""),
            "root_filename": _safe(ida_nalt.get_root_filename, ""),
            "imagebase": int(_safe(ida_nalt.get_imagebase, 0) or 0),
            "min_ea": int(_safe(ida_ida.inf_get_min_ea, 0) or 0),
            "max_ea": int(_safe(ida_ida.inf_get_max_ea, 0) or 0),
            "bitness": 64 if ida_ida.inf_is_64bit() else 32,
            "big_endian": bool(ida_ida.inf_is_be()),
            "idb_path": str(Path(idb_path).resolve()),
            "generated_at": utc_now(),
        }
        set_metadata(connection, metadata)
        connection.executemany("INSERT INTO symbols VALUES(?,?,?)",
            ((sqlite_ea(ea), name, idc.get_type(ea)) for ea, name in idautils.Names()))
        add_segments(connection)
        addresses = add_functions(connection)
        add_xrefs(connection)
        add_cfg(connection, addresses)
        connection.commit()
        return {"functions": len(addresses),
                "segments": connection.execute("SELECT count(*) FROM segments").fetchone()[0],
                "xrefs": connection.execute("SELECT count(*) FROM xrefs").fetchone()[0],
                "basic_blocks": connection.execute("SELECT count(*) FROM basic_blocks").fetchone()[0],
                "cfg_edges": connection.execute("SELECT count(*) FROM cfg_edges").fetchone()[0]}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

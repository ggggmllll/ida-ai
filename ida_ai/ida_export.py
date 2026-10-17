"""IDA-side headless exporter.

This module is loaded by ``idat -A -S``. It performs no Qt or GUI operations;
microcode export uses ida_kernwin only for the kernel version. The parent
process only needs to read the resulting SQLite file.
"""

from __future__ import annotations

from pathlib import Path
from contextlib import closing
import tempfile
import re
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
    import ida_idp
    import ida_ua
    import ida_xref
    import ida_segment
    import ida_typeinf
    import idautils
    import idc
except ImportError as exc:  # pragma: no cover - exercised by IDA
    raise RuntimeError("ida_export.py must run inside IDA or idalib") from exc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from .db import connect, reset_analysis, set_metadata, sqlite_ea, ida_ea, utc_now
from .function_classification import is_nullstub_sequence
from .selection import BytePattern, parse_pattern
from .ida_microcode import export_microcode


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


def is_nullstub(func) -> bool:
    """Conservatively recognize an empty function from its actual instructions."""
    instructions = []
    for ea in idautils.FuncItems(func.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            return False
        insn = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(insn, ea))
        if size <= 0 or size != int(ida_bytes.get_item_size(ea)):
            return False
        mnemonic = ida_ua.print_insn_mnem(ea) or ""
        is_return = bool(_safe(lambda: ida_idp.is_ret_insn(insn, ida_idp.IRI_RET_LITERALLY), False))
        instructions.append((str(mnemonic), is_return))
    return is_nullstub_sequence(instructions)


def _thunk_target_ea(func):
    """Normalize IDA versions that expose the thunk target as a tuple."""
    target = _safe(lambda: ida_funcs.calc_thunk_func_target(func), ida_idaapi.BADADDR)
    if isinstance(target, (tuple, list)):
        target = target[0] if target else ida_idaapi.BADADDR
    try:
        target = int(target)
    except (TypeError, ValueError):
        return None
    return None if target == int(ida_idaapi.BADADDR) else target


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
        is_thunk = bool(func.flags & getattr(ida_funcs, "FUNC_THUNK", 0))
        thunk_target = _thunk_target_ea(func) if is_thunk else None
        rows.append((sqlite_ea(func.start_ea), sqlite_ea(func.end_ea), name, _text(demangled), _text(signature),
                     int(func.flags), int(func.end_ea - func.start_ea),
                     ida_segment.get_segm_name(seg) if seg else None,
                     int(bool(func.flags & ida_funcs.FUNC_LIB)),
                     int(is_thunk), sqlite_ea(thunk_target) if thunk_target is not None else None,
                     int(is_nullstub(func)) if not is_thunk else 0,
                     _safe(lambda: idc.get_func_cmt(ea, 0)), _safe(lambda: idc.get_func_cmt(ea, 1))))
        addresses.append(int(func.start_ea))
    connection.executemany("INSERT INTO functions(start_ea,end_ea,name,demangled_name,signature,flags,size,segment_name,is_library,is_thunk,thunk_target_ea,is_nullstub,comment,repeatable_comment) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return addresses


def add_assembly_comments(connection, addresses: Iterable[int] | None = None) -> None:
    """Refresh IDA's per-address comments without touching Hex-Rays comments."""
    selected = set(int(ea) for ea in addresses) if addresses is not None else None
    if selected is None:
        connection.execute("DELETE FROM comments WHERE kind='assembly'")
    elif selected:
        placeholders = ",".join("?" for _ in selected)
        connection.execute(
            f"DELETE FROM comments WHERE kind='assembly' AND function_ea IN ({placeholders})",
            [sqlite_ea(ea) for ea in selected],
        )
    rows = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            func = ida_funcs.get_func(ea)
            if selected is not None and (func is None or int(func.start_ea) not in selected):
                continue
            for repeatable in (0, 1):
                comment = ida_bytes.get_cmt(ea, repeatable)
                if comment:
                    rows.append((sqlite_ea(ea), sqlite_ea(func.start_ea) if func else None,
                                 "assembly", repeatable, 0, str(comment), utc_now()))
    connection.executemany(
        "INSERT OR REPLACE INTO comments(address,function_ea,kind,repeatable,item_preciser,text,updated_at) VALUES(?,?,?,?,?,?,?)",
        rows,
    )


def add_pseudocode_comments(connection, addresses: Iterable[int]) -> None:
    """Mirror the durable Hex-Rays comment map independently of rendered text."""
    if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
        return
    for func_ea in addresses:
        stored_ea = sqlite_ea(func_ea)
        connection.execute(
            "DELETE FROM comments WHERE kind='pseudocode' AND function_ea=?",
            (stored_ea,),
        )
        user_comments = ida_hexrays.restore_user_cmts(func_ea)
        if user_comments is None:
            continue
        try:
            iterator = ida_hexrays.user_cmts_begin(user_comments)
            for _ in range(int(ida_hexrays.user_cmts_size(user_comments))):
                location = ida_hexrays.user_cmts_first(iterator)
                comment = ida_hexrays.user_cmts_second(iterator).c_str()
                if comment:
                    connection.execute(
                        "INSERT OR REPLACE INTO comments(address,function_ea,kind,repeatable,item_preciser,text,updated_at) VALUES(?,?,?,?,?,?,?)",
                        (sqlite_ea(location.ea), stored_ea, "pseudocode", 0,
                         int(location.itp), comment, utc_now()),
                    )
                iterator = ida_hexrays.user_cmts_next(iterator)
        finally:
            ida_hexrays.user_cmts_free(user_comments)


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
        add_pseudocode_comments(connection, selected)
    elif view in {"microcode", "micro_flow"}:
        return export_microcode(connection, selected, flow=view == "micro_flow")
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


def apply_mutation(connection, idb_path: str | Path, kind: str, values: dict) -> dict:
    """Apply one typed write in IDA, persist it, and mirror its durable input to SQLite."""
    now = utc_now()
    address = int(values.get("address", 0))
    function = ida_funcs.get_func(address) if address else None
    if kind == "assembly_comment":
        comment = str(values["comment"])
        repeatable = bool(values.get("repeatable", False))
        if not ida_bytes.set_cmt(address, comment, repeatable):
            raise RuntimeError(f"failed to set assembly comment at {address:#x}")
        connection.execute(
            "DELETE FROM comments WHERE address=? AND kind='assembly' AND repeatable=? AND item_preciser=0",
            (sqlite_ea(address), int(repeatable)),
        )
        if comment:
            connection.execute(
                "INSERT INTO comments VALUES(?,?,?,?,?,?,?)",
                (sqlite_ea(address), sqlite_ea(function.start_ea) if function else None,
                 "assembly", int(repeatable), 0, comment, now),
            )
    elif kind == "function_comment":
        if function is None:
            raise ValueError(f"no function contains {address:#x}")
        repeatable = bool(values.get("repeatable", False))
        if not idc.set_func_cmt(function.start_ea, str(values["comment"]), repeatable):
            raise RuntimeError(f"failed to set function comment at {function.start_ea:#x}")
        connection.execute(
            "UPDATE functions SET comment=?,repeatable_comment=? WHERE start_ea=?",
            (idc.get_func_cmt(function.start_ea, False), idc.get_func_cmt(function.start_ea, True),
             sqlite_ea(function.start_ea)),
        )
    elif kind == "pseudocode_comment":
        if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler unavailable")
        if function is None:
            raise ValueError(f"no function contains {address:#x}")
        cfunc = ida_hexrays.decompile(function.start_ea)
        if cfunc is None:
            raise RuntimeError("failed to decompile function for pseudocode comment")
        item_preciser = int(values.get("item_preciser", ida_hexrays.ITP_SEMI))
        location = ida_hexrays.treeloc_t()
        location.ea = address
        location.itp = item_preciser
        comment = str(values["comment"])
        cfunc.set_user_cmt(location, comment)
        cfunc.save_user_cmts()
        connection.execute(
            "DELETE FROM comments WHERE address=? AND kind='pseudocode' AND repeatable=0 AND item_preciser=?",
            (sqlite_ea(address), item_preciser),
        )
        if comment:
            connection.execute(
                "INSERT INTO comments VALUES(?,?,?,?,?,?,?)",
                (sqlite_ea(address), sqlite_ea(function.start_ea), "pseudocode", 0,
                 item_preciser, comment, now),
            )
    elif kind == "register_type":
        declaration = str(values["declaration"]).strip()
        errors = int(idc.parse_decls(declaration, 0))
        if errors:
            raise ValueError(f"IDA rejected type declaration (parse errors: {errors})")
        match = re.search(r"\b(?:struct|union|enum|typedef)\s+([A-Za-z_]\w*)", declaration)
        name = str(values.get("name") or (match.group(1) if match else declaration[:128]))
        connection.execute(
            "INSERT INTO type_definitions(name,declaration,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET declaration=excluded.declaration,updated_at=excluded.updated_at",
            (name, declaration, now),
        )
    elif kind == "apply_type":
        declaration = str(values["declaration"])
        if not idc.SetType(address, declaration):
            raise RuntimeError(f"IDA rejected type for {address:#x}: {declaration}")
        connection.execute(
            "INSERT INTO type_assignments(address,declaration,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(address) DO UPDATE SET declaration=excluded.declaration,updated_at=excluded.updated_at",
            (sqlite_ea(address), declaration, now),
        )
    elif kind == "rename_symbol":
        name = str(values["name"])
        if not ida_name.set_name(address, name, ida_name.SN_NOWARN):
            raise RuntimeError(f"IDA rejected symbol rename at {address:#x}: {name}")
    elif kind == "rename_local":
        if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler unavailable")
        if function is None:
            raise ValueError(f"no function contains {address:#x}")
        ida_hexrays.mark_cfunc_dirty(function.start_ea, False)
        ida_hexrays.decompile(function.start_ea)
        locator = ida_hexrays.lvar_locator_t()
        if not ida_hexrays.locate_lvar(locator, function.start_ea, str(values["old_name"])):
            raise ValueError(f"local variable not found: {values['old_name']}")
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = locator
        info.name = str(values["new_name"])
        if not ida_hexrays.modify_user_lvar_info(function.start_ea, ida_hexrays.MLI_NAME, info):
            raise RuntimeError(f"IDA rejected local rename in {function.start_ea:#x}")
    elif kind == "set_local_type":
        if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler unavailable")
        if function is None:
            raise ValueError(f"no function contains {address:#x}")
        ida_hexrays.mark_cfunc_dirty(function.start_ea, False)
        ida_hexrays.decompile(function.start_ea)
        locator = ida_hexrays.lvar_locator_t()
        if not ida_hexrays.locate_lvar(locator, function.start_ea, str(values["name"])):
            raise ValueError(f"local variable not found: {values['name']}")
        declaration = str(values["declaration"]).strip().rstrip(";") + " __ida_ai_local;"
        local_type = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(
            local_type,
            ida_typeinf.get_idati(),
            declaration,
            ida_typeinf.PT_VAR | ida_typeinf.PT_SIL,
        ):
            raise ValueError(f"IDA rejected local variable type: {declaration}")
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = locator
        info.type = local_type
        if not ida_hexrays.modify_user_lvar_info(function.start_ea, ida_hexrays.MLI_TYPE, info):
            raise RuntimeError(f"IDA rejected local type change in {function.start_ea:#x}")
    else:
        raise ValueError(f"unknown mutation: {kind}")

    if not ida_loader.save_database(str(idb_path), 0):
        raise RuntimeError("IDA failed to save the modified database")
    connection.commit()
    return {"mutation": kind, "address": address or None, "saved": True}


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


def scan_data_pointer_slots(
    connection, *, pointer_size: int, start: int | None = None, end: int | None = None,
    max_bytes: int = 256 << 20,
) -> dict:
    """Persist aligned mapped pointer entries from readable, non-code segments.

    This is a durable input scan for the virtual-table index, not the raw
    pointer-search feature/cache. BSS and executable segments are excluded.
    """
    pointer_size = int(pointer_size)
    max_bytes = int(max_bytes)
    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    if max_bytes < pointer_size:
        raise ValueError("max_bytes must be at least one pointer wide")
    if start is not None and end is not None and int(end) <= int(start):
        raise ValueError("end must be greater than start")

    eligible = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        permission = int(getattr(seg, "perm", 0))
        seg_class = _text(_safe(lambda seg=seg: ida_segment.get_segm_class(seg))) or ""
        if not permission & int(getattr(ida_segment, "SEGPERM_READ", 4)):
            continue
        if permission & int(getattr(ida_segment, "SEGPERM_EXEC", 1)) or seg_class.upper() == "BSS":
            continue
        seg_start, seg_end = int(seg.start_ea), int(seg.end_ea)
        window_start = max(seg_start, int(start)) if start is not None else seg_start
        window_end = min(seg_end, int(end)) if end is not None else seg_end
        if window_end > window_start:
            eligible.append((seg, window_start, window_end, ida_segment.get_segm_name(seg) or ""))

    scoped_start = int(start) if start is not None else None
    scoped_end = int(end) if end is not None else None
    if scoped_start is None and scoped_end is None:
        connection.execute("DELETE FROM data_pointer_slots")
    else:
        clauses, values = [], []
        if scoped_start is not None:
            clauses.append("source_ea>=?"); values.append(sqlite_ea(scoped_start))
        if scoped_end is not None:
            clauses.append("source_ea<?"); values.append(sqlite_ea(scoped_end))
        connection.execute("DELETE FROM data_pointer_slots WHERE " + " AND ".join(clauses), values)

    scanned_bytes = 0
    bytes_requested = 0
    rows = []
    skipped = []
    total_entries = 0
    truncated = False
    byteorder = "big" if ida_ida.inf_is_be() else "little"
    now = utc_now()
    max_chunk = 1 << 20
    for seg, window_start, window_end, seg_name in eligible:
        if bytes_requested >= max_bytes:
            truncated = True
            skipped.append({"segment": seg_name, "start": window_start, "end": window_end, "reason": "max_bytes"})
            continue
        segment_start = window_start
        remaining_budget = max_bytes - bytes_requested
        allowed_end = min(window_end, segment_start + remaining_budget)
        if allowed_end < window_end:
            truncated = True
        cursor = segment_start
        first_aligned = cursor + ((pointer_size - (cursor % pointer_size)) % pointer_size)
        while cursor < allowed_end:
            primary_end = min(allowed_end, cursor + max_chunk)
            bytes_requested += primary_end - cursor
            raw = ida_bytes.get_bytes(cursor, primary_end - cursor)
            if raw is None:
                skipped.append({"segment": seg_name, "start": cursor, "end": primary_end, "reason": "unloaded_or_unreadable"})
                cursor = primary_end
                continue
            data = bytes(raw)
            scanned_bytes += len(data)
            position = first_aligned - cursor if first_aligned >= cursor else 0
            if position % pointer_size:
                position += pointer_size - (position % pointer_size)
            while position + pointer_size <= len(data):
                source_ea = cursor + position
                if source_ea >= primary_end:
                    break
                value = int.from_bytes(data[position:position + pointer_size], byteorder, signed=False)
                if value == 0:
                    target_ea, target_func_ea, target_name, target_kind, target_segment = None, None, None, "null", None
                else:
                    target_seg = ida_segment.getseg(value)
                    if target_seg is None:
                        position += pointer_size
                        continue
                    target_func = ida_funcs.get_func(value)
                    target_name = ida_name.get_name(value) or None
                    target_segment = ida_segment.get_segm_name(target_seg) or ""
                    if target_func is not None and int(target_func.start_ea) == value:
                        target_ea = int(target_func.start_ea)
                        target_func_ea = int(target_func.start_ea)
                        target_kind = "function"
                    elif ida_bytes.is_code(ida_bytes.get_full_flags(value)):
                        target_ea, target_func_ea, target_kind = value, None, "code"
                    else:
                        target_ea, target_func_ea, target_kind = value, None, "data"
                rows.append((sqlite_ea(source_ea), sqlite_ea(value),
                    sqlite_ea(target_ea) if target_ea is not None else None,
                    pointer_size, seg_name, target_segment,
                    sqlite_ea(target_func_ea) if target_func_ea is not None else None,
                    target_name, target_kind, now))
                total_entries += 1
                position += pointer_size
            if len(rows) >= 4096:
                connection.executemany(
                    "INSERT OR REPLACE INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )
                rows.clear()
            cursor = primary_end
            first_aligned = cursor + ((pointer_size - (cursor % pointer_size)) % pointer_size)
    if rows:
        connection.executemany(
            "INSERT OR REPLACE INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    # Preserve a possible Itanium offset-to-top word immediately before the
    # two-word metadata prefix of mapped code-pointer runs. Such scalar words
    # are otherwise discarded by pointer scanning because they are not mapped
    # addresses. Keep this narrowly scoped; arbitrary data words are not
    # exposed as pointer observations.
    prefix_words: set[int] = set()
    scalar_prefix_words = 0
    prefix_failures = 0
    prefix_bytes_read = 0
    prefix_budget_skipped = 0
    prefix_budget_exhausted = False
    code_query = "SELECT source_ea,source_segment FROM data_pointer_slots WHERE pointer_size=? AND target_kind IN ('function','code')"
    code_values: list[object] = [pointer_size]
    if scoped_start is not None:
        code_query += " AND source_ea>=?"
        code_values.append(sqlite_ea(scoped_start))
    if scoped_end is not None:
        code_query += " AND source_ea<?"
        code_values.append(sqlite_ea(scoped_end))
    code_query += " ORDER BY source_ea"
    code_entries = connection.execute(code_query, code_values).fetchall()
    for entry in code_entries:
        code_ea = ida_ea(entry["source_ea"])
        for distance in (1, 2):
            prefix_ea = code_ea - distance * pointer_size
            if prefix_ea < 0 or prefix_ea in prefix_words:
                continue
            if scoped_start is not None and prefix_ea < scoped_start:
                continue
            if scoped_end is not None and prefix_ea >= scoped_end:
                continue
            prefix_seg = ida_segment.getseg(prefix_ea)
            if prefix_seg is None or (ida_segment.get_segm_name(prefix_seg) or "") != entry["source_segment"]:
                continue
            if bytes_requested + pointer_size > max_bytes:
                truncated = True
                prefix_budget_skipped += 1
                prefix_budget_exhausted = True
                break
            bytes_requested += pointer_size
            prefix_raw = ida_bytes.get_bytes(prefix_ea, pointer_size)
            prefix_bytes_read += pointer_size
            if prefix_raw is None:
                prefix_failures += 1
                continue
            prefix_words.add(prefix_ea)
            raw_value = int.from_bytes(bytes(prefix_raw), byteorder, signed=False)
            if raw_value == 0 or ida_segment.getseg(raw_value) is not None:
                continue
            signed_value = raw_value
            sign_bit = 1 << (pointer_size * 8 - 1)
            if signed_value & sign_bit:
                signed_value -= 1 << (pointer_size * 8)
            if signed_value == 0 or not -0x10000 <= signed_value <= 0x10000:
                continue
            inserted = connection.execute(
                "INSERT OR IGNORE INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
                "VALUES(?,?,NULL,?,?,NULL,NULL,NULL,'scalar',?)",
                (sqlite_ea(prefix_ea), sqlite_ea(raw_value), pointer_size,
                 entry["source_segment"], now),
            ).rowcount
            scalar_prefix_words += int(inserted > 0)
        if prefix_budget_exhausted:
            break
    if prefix_budget_skipped:
        skipped.append({"reason": "max_bytes_prefix_probe", "candidate_reads_skipped": prefix_budget_skipped})
    connection.commit()
    result = {
        "pointer_size": pointer_size, "byteorder": byteorder,
        "segments_considered": len(eligible), "scanned_bytes": scanned_bytes,
        "bytes_requested": bytes_requested, "max_bytes": max_bytes,
        "pointer_entries": total_entries, "scalar_prefix_words": scalar_prefix_words,
        "prefix_bytes_read": prefix_bytes_read, "prefix_read_failures": prefix_failures,
        "prefix_budget_skipped": prefix_budget_skipped,
        "truncated": truncated, "skipped": skipped,
        "source": "aligned_loaded_pointers_in_readable_non_executable_non_bss_segments",
        "scope": {"start": scoped_start, "end": scoped_end},
    }
    set_metadata(connection, {"data_pointer_scan": {**result, "generated_at": now}})
    connection.commit()
    return result


def build_vtables(
    connection, *, abi: str, start: int | None = None, end: int | None = None,
    min_function_slots: int = 2, max_slots: int = 512, max_bytes: int = 256 << 20,
) -> dict:
    """Refresh durable data-pointer inputs and build the offline vtable index."""
    pointer_size = 8 if ida_ida.inf_is_64bit() else 4
    pointer_scan = scan_data_pointer_slots(
        connection, pointer_size=pointer_size, start=start, end=end, max_bytes=max_bytes,
    )
    from .virtual_tables import build_vtable_index

    result = build_vtable_index(
        connection, abi=abi, pointer_size=pointer_size,
        byteorder="big" if ida_ida.inf_is_be() else "little", start=start, end=end,
        min_function_slots=min_function_slots, max_slots=max_slots,
    )
    result["pointer_scan"] = pointer_scan
    return result


def synchronize_function(output: str | Path, idb_path: str | Path, address: int) -> dict:
    """Refresh one function after a function-local decompiler edit."""
    if not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete")
    function = ida_funcs.get_func(address)
    if function is None:
        raise ValueError(f"no function contains {address:#x}")
    ea = int(function.start_ea)
    with closing(connect(output)) as source:
        if source.execute("SELECT 1 FROM functions WHERE start_ea=?", (sqlite_ea(ea),)).fetchone() is None:
            raise ValueError("function is absent from snapshot; run full sync")
        with tempfile.TemporaryDirectory(prefix="ida-ai-local-sync-", dir=Path(output).parent) as directory:
            staging = Path(directory) / "snapshot.sqlite"
            with closing(connect(staging)) as target:
                source.backup(target)
                views = {}
                # Pseudocode is always regenerated, including its lvar user settings.
                views["pseudocode"] = export_views(target, [ea], "pseudocode")
                if target.execute("SELECT 1 FROM disassembly WHERE function_ea=?", (sqlite_ea(ea),)).fetchone():
                    views["disassembly"] = export_views(target, [ea], "disassembly")
                    add_assembly_comments(target, [ea])
                if target.execute("SELECT 1 FROM microcode WHERE function_ea=?", (sqlite_ea(ea),)).fetchone():
                    views["microcode"] = export_views(target, [ea], "microcode")
                if target.execute("SELECT 1 FROM micro_flow WHERE function_ea=?", (sqlite_ea(ea),)).fetchone():
                    views["micro_flow"] = export_views(target, [ea], "micro_flow")
                stale_calls = [row[0] for row in target.execute(
                    "SELECT call_id FROM vcall_sites WHERE function_ea=? AND stale=0", (sqlite_ea(ea),))]
                if stale_calls:
                    placeholders = ",".join("?" for _ in stale_calls)
                    target.execute(f"UPDATE vcall_sites SET stale=1 WHERE call_id IN ({placeholders})", stale_calls)
                    target.execute(f"UPDATE vcall_targets SET stale=1 WHERE call_id IN ({placeholders})", stale_calls)
                    target.execute(f"UPDATE receiver_flows SET stale=1 WHERE call_id IN ({placeholders})", stale_calls)
                    run_ids = [row[0] for row in target.execute(
                        f"SELECT DISTINCT run_id FROM vcall_sites WHERE call_id IN ({placeholders})", stale_calls)]
                    if run_ids:
                        run_placeholders = ",".join("?" for _ in run_ids)
                        target.execute(f"UPDATE vcall_runs SET status='stale' WHERE run_id IN ({run_placeholders})", run_ids)
                set_metadata(target, {f"function_sync:{ea:X}": utc_now()})
                target.commit()
                if not ida_loader.save_database(str(idb_path), 0):
                    raise RuntimeError("IDA failed to save locally synchronized database")
                target.backup(source)
    return {"function_ea": ea, "views": views, "stale_vcall_sites": len(stale_calls),
            "scope": "function-local views"}


def synchronize_database(output: str | Path, idb_path: str | Path, all_views: bool = False) -> dict:
    """Rebuild observations in isolation, then publish one SQLite snapshot."""
    if not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete")
    if ida_hexrays is not None and ida_hexrays.init_hexrays_plugin():
        ida_hexrays.clear_cached_cfuncs()
    with closing(connect(output)) as source:
        selections = {view: [ida_ea(row[0]) for row in source.execute(
            f"SELECT function_ea FROM {view}")] for view in ("disassembly", "pseudocode", "microcode", "micro_flow")}
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
            "architecture": _safe(ida_idp.get_idp_name, None),
            "idb_path": str(Path(idb_path).resolve()),
            "generated_at": utc_now(),
        }
        set_metadata(connection, metadata)
        connection.executemany("INSERT INTO symbols VALUES(?,?,?)",
            ((sqlite_ea(ea), name, idc.get_type(ea)) for ea, name in idautils.Names()))
        add_segments(connection)
        addresses = add_functions(connection)
        add_assembly_comments(connection)
        add_pseudocode_comments(connection, addresses)
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

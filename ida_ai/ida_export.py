"""IDA-side headless exporter.

This module is loaded by ``idat -A -S``. It performs no Qt or GUI operations;
microcode export uses ida_kernwin only for the kernel version. The parent
process only needs to read the resulting SQLite file.
"""

from __future__ import annotations

import hashlib
import json
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
    import ida_fixup
except ImportError:
    ida_fixup = None

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


def add_function_chunks(connection, addresses: Iterable[int] | None = None) -> None:
    """Persist IDA's main and tail chunk ranges for selected functions."""
    function_eas = [int(ea) for ea in (idautils.Functions() if addresses is None else addresses)]
    if addresses is None:
        connection.execute("DELETE FROM function_chunks")
    elif function_eas:
        placeholders = ",".join("?" for _ in function_eas)
        connection.execute(
            f"DELETE FROM function_chunks WHERE function_ea IN ({placeholders})",
            [sqlite_ea(ea) for ea in function_eas],
        )
    rows = []
    for function_ea in function_eas:
        function = ida_funcs.get_func(function_ea)
        if function is None:
            continue
        for chunk_index, chunk in enumerate(ida_funcs.func_tail_iterator_t(function)):
            chunk_function = ida_funcs.get_fchunk(int(chunk.start_ea))
            is_tail = bool(chunk_function and ida_funcs.is_func_tail(chunk_function))
            owner = int(getattr(chunk_function, "owner", 0) or 0) if is_tail else None
            rows.append((
                sqlite_ea(function.start_ea), chunk_index,
                sqlite_ea(chunk.start_ea), sqlite_ea(chunk.end_ea),
                sqlite_ea(owner) if owner else None, int(is_tail),
            ))
    connection.executemany(
        "INSERT INTO function_chunks(function_ea,chunk_index,start_ea,end_ea,owner_ea,is_tail) "
        "VALUES(?,?,?,?,?,?)",
        rows,
    )


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


from .progress import emit


def add_xrefs(connection) -> None:
    rows = []
    exported = 0
    statement = "INSERT OR IGNORE INTO xrefs(source_ea,target_ea,xref_type,is_code,is_data,source_function_ea,target_function_ea,type_name) VALUES(?,?,?,?,?,?,?,?)"
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        emit("xrefs_segment", segment=ida_segment.get_segm_name(seg), start=seg.start_ea, end=seg.end_ea)
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
                    exported += len(rows)
                    emit("xrefs", exported=exported)
                    rows.clear()
    if rows:
        connection.executemany(statement, rows)


def add_cfg(connection, addresses: list[int]) -> None:
    for ordinal, func_ea in enumerate(addresses):
        if ordinal % 1000 == 0:
            emit("cfg", completed=ordinal, total=len(addresses))
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
        if ordinal == 1 or ordinal % 10 == 0:
            emit("function_view", function=func_ea, completed=ordinal-1, total=len(addresses))
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
        if ordinal == 1 or ordinal % 10 == 0:
            emit("function_view", function=func_ea, completed=ordinal-1, total=len(addresses))
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
    emit("export_view", view=view, functions=len(selected))
    if view == "disassembly":
        add_disassembly(connection, selected)
        from .derived_calls import mark_derived_calls_stale
        mark_derived_calls_stale(
            connection, selected,
            reason="disassembly refreshed; reimport resolver output to refresh derived calls",
        )
    elif view == "pseudocode":
        add_pseudocode(connection, selected)
        add_pseudocode_comments(connection, selected)
    elif view in {"microcode", "micro_flow"}:
        result = export_microcode(connection, selected, flow=view == "micro_flow")
        from .virtual_tables import invalidate_function_virtual_artifacts
        result["virtual_artifacts_invalidated"] = invalidate_function_virtual_artifacts(
            connection, selected, view_name=view)
        return result
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
    if kind in ("register_type", "apply_type", "apply_vtable_type_plan") and values.get("expected_revision") is not None:
        from .vtable_types import assert_type_application_revision
        assert_type_application_revision(connection, str(values["expected_revision"]))
    type_plan = None
    type_plan_result = None
    if kind == "apply_vtable_type_plan":
        from .vtable_types import validate_vtable_type_preview
        spec, checked_preview = validate_vtable_type_preview(connection, values.get("preview"))
        type_plan = spec
        if values.get("expected_revision") != checked_preview["revision_token"]:
            raise ValueError("expected_revision does not match the checked preview")
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
    elif kind == "apply_vtable_type_plan":
        definition = type_plan["type_definition"]
        declaration = str(definition["declaration"]).strip()
        errors = int(idc.parse_decls(declaration, 0))
        if errors:
            raise ValueError(f"IDA rejected type declaration (parse errors: {errors})")
        connection.execute(
            "INSERT INTO type_definitions(name,declaration,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET declaration=excluded.declaration,updated_at=excluded.updated_at",
            (str(definition["name"]), declaration, now),
        )
        applied, failed = [], None
        for assignment in type_plan.get("assignments", []):
            target_ea = int(assignment["address"])
            target_declaration = str(assignment["declaration"])
            try:
                success = bool(idc.SetType(target_ea, target_declaration))
            except Exception as exc:
                failed = {"address": target_ea, "declaration": target_declaration, "error": str(exc)}
                break
            if not success:
                failed = {"address": target_ea, "declaration": target_declaration,
                    "error": "IDA rejected the type assignment"}
                break
            connection.execute(
                "INSERT INTO type_assignments(address,declaration,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(address) DO UPDATE SET declaration=excluded.declaration,updated_at=excluded.updated_at",
                (sqlite_ea(target_ea), target_declaration, now),
            )
            applied.append({"address": target_ea, "declaration": target_declaration})
        type_plan_result = {"preview_id": values["preview"]["preview_id"],
            "status": "partial" if failed else "applied", "registered_type": definition["name"],
            "assignments_applied": applied, "failure": failed,
            "atomic": False, "revision_token_consumed": values["expected_revision"]}
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
    result = {"mutation": kind, "address": address or None, "saved": True}
    if type_plan_result is not None:
        result["type_plan"] = type_plan_result
    return result


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
    chunk = ida_funcs.get_fchunk(ea) if func else None
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
            "chunk": {
                "start": int(chunk.start_ea),
                "end": int(chunk.end_ea),
                "is_tail": bool(ida_funcs.is_func_tail(chunk)),
                "owner": int(chunk.owner) if ida_funcs.is_func_tail(chunk) else None,
            } if chunk else None,
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


def read_bytes(
    connection,
    address: int,
    size: int,
    *,
    output_format: str = "auto",
    max_inline_bytes: int = 4096,
    output_path: str | Path | None = None,
) -> dict:
    address, size = int(address), int(size)
    if size < 0:
        raise ValueError("size must be non-negative")
    if output_format not in {"auto", "hex", "array", "both", "none"}:
        raise ValueError("output_format must be auto, hex, array, both, or none")
    if max_inline_bytes < 0:
        raise ValueError("max_inline_bytes must be non-negative")
    raw = b"" if size == 0 else ida_bytes.get_bytes(address, size)
    if raw is None:
        raise ValueError(f"unable to read {size} bytes at 0x{address:X}")
    raw = bytes(raw)
    _record_memory(connection, address, raw)
    connection.commit()
    selected_format = output_format
    if output_format == "auto":
        selected_format = "hex" if len(raw) <= max_inline_bytes else "none"
    result = {
        "address": address,
        "address_hex": f"0x{address:X}",
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "inline_format": selected_format,
        "inline_omitted": selected_format == "none" and bool(raw),
        "stored_rows": len(raw),
        "max_inline_bytes": max_inline_bytes,
    }
    if selected_format in {"hex", "both"}:
        result["hex"] = raw.hex(" ")
    if selected_format in {"array", "both"}:
        result["bytes"] = list(raw)
    if output_path is not None:
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        result["output_file"] = str(path)
    return result


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
        connection.execute("DELETE FROM data_fixups")
    else:
        clauses, values = [], []
        if scoped_start is not None:
            clauses.append("source_ea>=?"); values.append(sqlite_ea(scoped_start))
        if scoped_end is not None:
            clauses.append("source_ea<?"); values.append(sqlite_ea(scoped_end))
        connection.execute("DELETE FROM data_pointer_slots WHERE " + " AND ".join(clauses), values)
        connection.execute("DELETE FROM data_fixups WHERE " + " AND ".join(clauses), values)

    observed_ranges = []
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
            observed_ranges.append((cursor, cursor + len(data)))
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

    # Preserve possible Itanium offset-to-top words immediately before the
    # two-word metadata prefix of mapped code-pointer runs. Such scalar words
    # (including zero for a primary table) are otherwise discarded because
    # they are not mapped addresses. Keep this narrowly scoped; arbitrary
    # data words are not exposed as pointer observations.
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
            observed_ranges.append((prefix_ea, prefix_ea + len(prefix_raw)))
            prefix_words.add(prefix_ea)
            raw_value = int.from_bytes(bytes(prefix_raw), byteorder, signed=False)
            if raw_value != 0 and ida_segment.getseg(raw_value) is not None:
                continue
            signed_value = raw_value
            sign_bit = 1 << (pointer_size * 8 - 1)
            if signed_value & sign_bit:
                signed_value -= 1 << (pointer_size * 8)
            if not -0x10000 <= signed_value <= 0x10000:
                continue
            inserted = connection.execute(
                "INSERT OR REPLACE INTO data_pointer_slots(source_ea,raw_value,target_ea,pointer_size,source_segment,target_segment,target_function_ea,target_name,target_kind,generated_at) "
                "VALUES(?,?,NULL,?,?,NULL,NULL,NULL,'scalar',?)",
                (sqlite_ea(prefix_ea), sqlite_ea(raw_value), pointer_size,
                 entry["source_segment"], now),
            ).rowcount
            scalar_prefix_words += int(inserted > 0)
        if prefix_budget_exhausted:
            break
    from .fixup_observations import collect_fixups
    fixups, fixup_coverage = collect_fixups(ida_fixup, ida_bytes.get_bytes, observed_ranges, ida_idaapi.BADADDR)
    connection.executemany(
        "INSERT OR REPLACE INTO data_fixups(source_ea,observation_json,generated_at) VALUES(?,?,?)",
        [(sqlite_ea(item["source_ea"]), json.dumps(item, sort_keys=True), now) for item in fixups],
    )
    if prefix_budget_skipped:
        skipped.append({"reason": "max_bytes_prefix_probe", "candidate_reads_skipped": prefix_budget_skipped})
    connection.commit()
    result = {
        "pointer_size": pointer_size, "byteorder": byteorder,
        "segments_considered": len(eligible), "scanned_bytes": scanned_bytes,
        "bytes_requested": bytes_requested, "max_bytes": max_bytes,
        "fixups": fixup_coverage,
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
    from .virtual_tables import build_vtable_index, store_itanium_rtti_descriptors

    # The first pass finds candidate address points.  Only typeinfo pointers
    # structurally adjacent to those sequences are used as RTTI roots; the
    # bounded second pass follows explicit base pointers from those roots.
    result = build_vtable_index(
        connection, abi=abi, pointer_size=pointer_size,
        byteorder="big" if ida_ida.inf_is_be() else "little", start=start, end=end,
        min_function_slots=min_function_slots, max_slots=max_slots,
    )
    descriptor_observations = read_itanium_typeinfos_from_candidates(
        connection, pointer_size=pointer_size,
        max_objects=4096, max_bytes=min(max_bytes, 32 << 20), max_bases=128,
    ) if abi == "itanium" else {"items": [], "coverage": {"status": "unsupported_abi"}}
    from .virtual_tables import _source_hash
    base_snapshot_hash = _source_hash(connection, "vtable", include_rtti=False)
    rtti_result = store_itanium_rtti_descriptors(
        connection, input_snapshot_hash=base_snapshot_hash,
        descriptors=descriptor_observations["items"],
        coverage=descriptor_observations["coverage"],
    )
    result = build_vtable_index(
        connection, abi=abi, pointer_size=pointer_size,
        byteorder="big" if ida_ida.inf_is_be() else "little", start=start, end=end,
        min_function_slots=min_function_slots, max_slots=max_slots,
    )
    result["pointer_scan"] = pointer_scan
    result["rtti_scan"] = descriptor_observations["coverage"]
    result["rtti_run"] = rtti_result
    return result


def read_itanium_typeinfos_from_candidates(
    connection, *, pointer_size: int, max_objects: int = 4096,
    max_bytes: int = 32 << 20, max_bases: int = 128,
) -> dict:
    """Read only bounded Itanium RTTI records reached from table prefixes.

    This runs inside IDA. It deliberately returns partial coverage for unknown
    descriptors, unmapped data, invalid headers, and exhausted limits.
    """
    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    if max_objects < 1 or max_bytes < pointer_size or max_bases < 0:
        raise ValueError("invalid RTTI scan limits")
    byteorder = "big" if ida_ida.inf_is_be() else "little"
    code_entries = connection.execute(
        "SELECT source_ea,target_kind FROM data_pointer_slots WHERE pointer_size=? "
        "AND target_kind IN ('function','code') ORDER BY source_ea", (pointer_size,),
    ).fetchall()
    roots = set()
    for code in code_entries:
        code_ea = ida_ea(code["source_ea"])
        header_ea = code_ea - pointer_size
        scalar_ea = code_ea - 2 * pointer_size
        header = connection.execute(
            "SELECT target_ea,target_kind FROM data_pointer_slots WHERE source_ea=?",
            (sqlite_ea(header_ea),),
        ).fetchone()
        scalar = connection.execute(
            "SELECT raw_value,target_kind FROM data_pointer_slots WHERE source_ea=?",
            (sqlite_ea(scalar_ea),),
        ).fetchone()
        if (header is not None and header["target_kind"] == "data" and header["target_ea"] is not None
                and scalar is not None and scalar["target_kind"] == "scalar"):
            roots.add(ida_ea(header["target_ea"]))

    descriptor_tokens = (
        ("__vmi_class_type_infoE", "multiple_or_virtual_inheritance"),
        ("__si_class_type_infoE", "single_inheritance"),
        ("__class_type_infoE", "class_type_info"),
    )
    queue = sorted(roots)
    seen: set[int] = set()
    items = []
    bytes_read = 0
    skipped = []
    while queue and len(seen) < max_objects and bytes_read < max_bytes:
        typeinfo_ea = queue.pop(0)
        if typeinfo_ea in seen:
            continue
        seen.add(typeinfo_ea)
        header_len = 2 * pointer_size
        if ida_segment.getseg(typeinfo_ea) is None or bytes_read + header_len > max_bytes:
            skipped.append({"typeinfo_ea": typeinfo_ea, "reason": "unmapped_or_byte_budget"})
            continue
        header = ida_bytes.get_bytes(typeinfo_ea, header_len)
        bytes_read += header_len
        if header is None or len(header) != header_len:
            skipped.append({"typeinfo_ea": typeinfo_ea, "reason": "unreadable_header"})
            continue
        vptr = int.from_bytes(bytes(header[:pointer_size]), byteorder, signed=False)
        name_ea = int.from_bytes(bytes(header[pointer_size:]), byteorder, signed=False)
        descriptor_symbol = (ida_name.get_name(vptr - 2 * pointer_size) or "") if vptr >= 2 * pointer_size else ""
        descriptor_kind = next((kind for token, kind in descriptor_tokens if descriptor_symbol.endswith(token)), None)
        type_name_symbol = ida_name.get_name(name_ea) or None
        type_name = None
        name_budget = min(256, max(0, max_bytes - bytes_read))
        if name_ea and name_budget and ida_segment.getseg(name_ea) is not None:
            name_bytes = ida_bytes.get_bytes(name_ea, name_budget)
            if name_bytes:
                bytes_read += len(name_bytes)
                type_name = bytes(name_bytes).split(b"\0", 1)[0].decode("utf-8", errors="replace")
        wanted = header_len
        if descriptor_kind == "single_inheritance":
            wanted += pointer_size
        elif descriptor_kind == "multiple_or_virtual_inheritance":
            wanted += 8
        if descriptor_kind is None:
            raw = bytes(header)
            status = "unknown_descriptor_kind"
        else:
            if bytes_read + max(0, wanted - header_len) > max_bytes:
                skipped.append({"typeinfo_ea": typeinfo_ea, "reason": "byte_budget_before_descriptor_header"})
                raw = bytes(header)
                status = "byte_budget"
            else:
                tail = ida_bytes.get_bytes(typeinfo_ea + header_len, max(0, wanted - header_len))
                bytes_read += max(0, wanted - header_len)
                raw = bytes(header) + (bytes(tail) if tail else b"")
                status = "header_read" if tail is not None or wanted == header_len else "truncated_header"
                if descriptor_kind == "single_inheritance" and len(raw) >= header_len + pointer_size:
                    base_ea = int.from_bytes(raw[header_len:header_len + pointer_size], byteorder)
                    if ida_segment.getseg(base_ea) is not None and base_ea not in seen:
                        queue.append(base_ea)
                if descriptor_kind == "multiple_or_virtual_inheritance" and len(raw) >= header_len + 8:
                    count = int.from_bytes(raw[header_len + 4:header_len + 8], byteorder)
                    bounded_count = min(count, max_bases)
                    desired = header_len + 8 + bounded_count * 2 * pointer_size
                    extra = desired - len(raw)
                    if extra > 0 and bytes_read + extra <= max_bytes:
                        more = ida_bytes.get_bytes(typeinfo_ea + len(raw), extra)
                        bytes_read += extra
                        if more:
                            raw += bytes(more)
                        else:
                            status = "truncated_base_array"
                    elif extra > 0:
                        status = "byte_budget_base_array"
                    entries_start = header_len + 8
                    for index in range(min(count, max_bases)):
                        entry = entries_start + index * 2 * pointer_size
                        if entry + pointer_size > len(raw):
                            break
                        base_ea = int.from_bytes(raw[entry:entry + pointer_size], byteorder)
                        if ida_segment.getseg(base_ea) is not None and base_ea not in seen:
                            queue.append(base_ea)
        items.append({"typeinfo_ea": typeinfo_ea, "descriptor_kind": descriptor_kind,
            "descriptor_symbol": descriptor_symbol or None, "symbol": ida_name.get_name(typeinfo_ea) or None,
            "type_name_ea": name_ea, "type_name_symbol": type_name_symbol,
            "type_name": type_name, "raw_hex": raw.hex(), "read_status": status})
    if queue:
        skipped.extend({"typeinfo_ea": ea, "reason": "object_limit_or_byte_budget"} for ea in queue[:256])
    return {"items": items, "coverage": {"root_count": len(roots), "objects_seen": len(seen),
        "objects_decoded": len(items), "bytes_read": bytes_read, "max_objects": max_objects,
        "max_bytes": max_bytes, "max_bases": max_bases, "pointer_size": pointer_size,
        "byteorder": byteorder, "truncated": bool(queue or skipped),
        "skipped": skipped, "source": "bounded_typeinfo_objects_reached_from_itanium_address_point_prefixes"}}


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
                add_function_chunks(target, [ea])
                # Pseudocode is always regenerated, including its lvar user settings.
                views["pseudocode"] = export_views(target, [ea], "pseudocode")
                if target.execute("SELECT 1 FROM disassembly WHERE function_ea=?", (sqlite_ea(ea),)).fetchone():
                    views["disassembly"] = export_views(target, [ea], "disassembly")
                    add_assembly_comments(target, [ea])
                if target.execute("SELECT 1 FROM microcode WHERE function_ea=?", (sqlite_ea(ea),)).fetchone():
                    views["microcode"] = export_views(target, [ea], "microcode")
                if target.execute("SELECT 1 FROM micro_flow WHERE function_ea=?", (sqlite_ea(ea),)).fetchone():
                    views["micro_flow"] = export_views(target, [ea], "micro_flow")
                invalidated = views.get("microcode", {}).get("virtual_artifacts_invalidated",
                    {"vcall_sites": 0, "vptr_writes": 0})
                set_metadata(target, {f"function_sync:{ea:X}": utc_now()})
                target.commit()
                if not ida_loader.save_database(str(idb_path), 0):
                    raise RuntimeError("IDA failed to save locally synchronized database")
                target.backup(source)
    return {"function_ea": ea, "views": views, "invalidated_virtual_artifacts": invalidated,
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
        emit("snapshot_metadata")
        set_metadata(connection, metadata)
        connection.executemany("INSERT INTO symbols VALUES(?,?,?)",
            ((sqlite_ea(ea), name, idc.get_type(ea)) for ea, name in idautils.Names()))
        emit("add_segments")
        add_segments(connection)
        emit("add_functions")
        addresses = add_functions(connection)
        emit("add_function_chunks")
        add_function_chunks(connection, addresses)
        emit("add_assembly_comments")
        add_assembly_comments(connection)
        emit("add_pseudocode_comments")
        add_pseudocode_comments(connection, addresses)
        emit("add_xrefs")
        add_xrefs(connection)
        emit("add_cfg")
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


def discover(connection, *, kind="all", start=None, end=None, max_items=100000, max_bytes=32 << 20):
    if kind not in {"all", "strings", "imports"} or max_items < 1 or max_bytes < 1:
        raise ValueError("invalid discovery kind or budgets")
    if start is not None and end is not None and end <= start:
        raise ValueError("end must exceed start")
    now = utc_now()
    result = dict(kind=kind, start=start, end=end, max_items=max_items, max_bytes=max_bytes,
                  strings=0, imports=0, bytes=0, truncated=False, provenance="IDA-defined items and import enumeration")
    def inside(ea):
        return (start is None or ea >= start) and (end is None or ea < end)
    if kind in {"all", "strings"}:
        connection.execute("DELETE FROM discovered_strings")
        for index in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(index)
            lo, hi = max(seg.start_ea, start or seg.start_ea), min(seg.end_ea, end if end is not None else seg.end_ea)
            if hi <= lo:
                continue
            emit("discovery_strings", segment=ida_segment.get_segm_name(seg))
            for ea in idautils.Heads(lo, hi):
                if not ida_bytes.is_strlit(ida_bytes.get_full_flags(ea)):
                    continue
                size = min(int(ida_bytes.get_item_size(ea)), hi-ea)
                if result["strings"] >= max_items or result["bytes"] + size > max_bytes:
                    result["truncated"] = True
                    break
                typ = int(ida_nalt.get_str_type(ea))
                raw = ida_bytes.get_strlit_contents(ea, size, typ)
                if raw is None:
                    continue
                raw = bytes(raw)
                # IDA returns UTF-8 text for supported string literal types.
                connection.execute("INSERT INTO discovered_strings VALUES(?,?,?,?,?)",
                    (sqlite_ea(ea),typ,raw.decode("utf-8",errors="replace"),raw.hex(),now))
                result["strings"] += 1
                result["bytes"] += size
            if result["truncated"]:
                break
    if kind in {"all", "imports"}:
        connection.execute("DELETE FROM discovered_imports")
        for module_index in range(ida_nalt.get_import_module_qty()):
            module = ida_nalt.get_import_module_name(module_index)
            def callback(ea,name,ordinal):
                if not inside(ea):
                    return True
                if result["imports"] >= max_items:
                    result["truncated"] = True
                    return False
                refs = sum(1 for _ in idautils.XrefsTo(ea,0))
                connection.execute("INSERT OR REPLACE INTO discovered_imports VALUES(?,?,?,?,?,?,?)",
                    (sqlite_ea(ea),module,name,ordinal,refs,"has_direct_xrefs" if refs else "no_direct_xrefs_not_proof_unused",now))
                result["imports"] += 1
                return True
            ida_nalt.enum_import_names(module_index, callback)
            if result["imports"] >= max_items:
                result["truncated"] = True
                break
    set_metadata(connection,{"discovery_" + table_kind:dict(result,generated_at=now)
                             for table_kind in (("strings","imports") if kind == "all" else (kind,))})
    connection.commit()
    return result

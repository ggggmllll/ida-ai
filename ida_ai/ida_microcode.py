"""Structured Hex-Rays microcode export for the headless IDA entrypoint."""

from __future__ import annotations

import hashlib
import json
from collections import Counter

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None
import ida_idaapi
import ida_funcs
import ida_kernwin

from .db import sqlite_ea, utc_now
from .microcode_relations import build_relations


MATURITY = "MMAT_GLBOPT3"
MAX_OPERAND_DEPTH = 8


def _maybe(callback):
    try:
        return callback()
    except (AttributeError, TypeError, ValueError, RuntimeError, OverflowError):
        return None


def _operand(mop, depth: int = 0) -> dict:
    kind_code = int(mop.t)
    kinds = {
        "mop_z": "empty", "mop_r": "register", "mop_n": "number", "mop_str": "string",
        "mop_d": "nested", "mop_S": "stack", "mop_v": "global", "mop_b": "block",
        "mop_f": "arglist", "mop_l": "local", "mop_a": "address", "mop_h": "helper",
        "mop_c": "case", "mop_fn": "float", "mop_p": "pair",
    }
    kind = next((name for constant, name in kinds.items()
                 if getattr(ida_hexrays, constant, None) == kind_code), f"kind_{kind_code}")
    result = {"kind": kind, "size": int(mop.size), "text": str(_maybe(mop.dstr) or "")}
    value_number = _maybe(lambda: int(mop.valnum))
    if value_number:
        result["value_number"] = value_number
    if kind == "number":
        result["value"] = _maybe(lambda: int(mop.value(False)))
    elif kind == "global":
        result["address"] = _maybe(lambda: int(mop.g))
    elif kind == "register":
        result["register"] = _maybe(lambda: int(mop.r))
    elif kind == "stack":
        result["stack_offset"] = _maybe(lambda: int(mop.s.off))
    elif kind == "local":
        result["local_index"] = _maybe(lambda: int(mop.l.idx))
        result["local_offset"] = _maybe(lambda: int(mop.l.off))
    elif kind == "helper":
        result["helper"] = _maybe(lambda: str(mop.helper))
    if depth >= MAX_OPERAND_DEPTH:
        result["truncated"] = True
        return result
    if kind == "nested":
        nested = _maybe(lambda: mop.d)
        if nested is not None:
            result["instruction"] = _instruction(nested, depth + 1)
    elif kind == "address":
        nested = _maybe(lambda: mop.a)
        if nested is not None:
            result["operand"] = _operand(nested, depth + 1)
    elif kind == "arglist":
        info = _maybe(lambda: mop.f)
        if info is not None:
            result["callee"] = _maybe(lambda: int(info.callee))
            args = _maybe(lambda: list(info.args))
            if args is not None:
                result["arguments"] = [_operand(arg, depth + 1) for arg in args]
    elif kind == "pair":
        pair = _maybe(lambda: mop.pair)
        if pair is not None:
            result["low"] = _operand(pair.lop, depth + 1)
            result["high"] = _operand(pair.hop, depth + 1)
    return result


def _opcode_name(code: int) -> str:
    return _OPCODES.get(code, f"opcode_{code}")


_OPCODES = {value: name[2:] for name in dir(ida_hexrays) if name.startswith("m_")
            and isinstance((value := getattr(ida_hexrays, name)), int)
            and int(ida_hexrays.m_nop) <= value <= int(ida_hexrays.m_und)}


def _instruction(insn, depth: int = 0) -> dict:
    ea = int(insn.ea)
    return {
        "ea": None if ea == int(ida_idaapi.BADADDR) else ea,
        "opcode": _opcode_name(int(insn.opcode)),
        "text": str(_maybe(insn.dstr) or ""),
        "l": _operand(insn.l, depth), "r": _operand(insn.r, depth), "d": _operand(insn.d, depth),
    }


def _variable(variable, index: int) -> dict:
    location = "register" if variable.is_reg1() else "stack" if variable.is_stk_var() else "other"
    return {
        "local_index": index, "name": str(variable.name), "size": int(variable.width),
        "location": location,
        "register": int(variable.get_reg1()) if location == "register" else None,
        "stack_offset": int(variable.get_stkoff()) if location == "stack" else None,
    }


def export_microcode(connection, addresses: list[int], *, flow: bool = False) -> dict:
    """Replace selected GLBOPT3 microcode or LVARS flow microcode and status."""
    ready = bool(_maybe(lambda: ida_hexrays.init_hexrays_plugin()))
    now = utc_now()
    maturity_name = "MMAT_LVARS" if flow else MATURITY
    maturity = int(getattr(ida_hexrays, maturity_name, 0))
    summary_table = "micro_flow" if flow else "microcode"
    rows_table = "micro_flow_instructions" if flow else "micro_instructions"
    view_name = "micro_flow" if flow else "microcode"
    version = _maybe(lambda: str(ida_hexrays.get_hexrays_version()))
    statuses: Counter[str] = Counter()
    for ordinal, function_ea in enumerate(addresses):
        from .progress import emit
        emit("microcode_function", completed=ordinal, total=len(addresses), function=function_ea, flow=flow)
        stored_ea = sqlite_ea(function_ea)
        connection.execute(f"DELETE FROM {rows_table} WHERE function_ea=?", (stored_ea,))
        connection.execute("DELETE FROM micro_blocks WHERE view_name=? AND function_ea=?", (view_name, stored_ea))
        connection.execute("DELETE FROM micro_value_refs WHERE view_name=? AND function_ea=?", (view_name, stored_ea))
        try:
            if not ready:
                raise RuntimeError("Hex-Rays decompiler unavailable")
            if hasattr(ida_hexrays, "decomp_ranges_t"):
                ranges = ida_hexrays.decomp_ranges_t()
                ranges.func_ea = function_ea
            else:
                ranges = ida_hexrays.mba_ranges_t()
                ranges.pfn = ida_funcs.get_func(function_ea)
                if ranges.pfn is None:
                    raise ValueError(f"no IDA function at {function_ea:#x}")
            failure = ida_hexrays.hexrays_failure_t()
            mba = ida_hexrays.gen_microcode(ranges, failure, None, 0, maturity)
            if mba is None:
                raise RuntimeError(str(_maybe(failure.desc) or "gen_microcode returned None"))
            arguments = []
            returned = {}
            variables = []
            if flow:
                variables = [_variable(mba.vars[index], index) for index in range(len(mba.vars))]
                arguments = [_variable(mba.vars[int(index)], int(index)) for index in mba.argidx]
                result_index = int(mba.retvaridx)
                if result_index >= 0:
                    returned = _variable(mba.vars[result_index], result_index)
            rows = []
            blocks = []
            relation_instructions = []
            for block_serial in range(int(mba.qty)):
                block = mba.get_mblock(block_serial)
                predecessors = _maybe(lambda: [int(block.pred(i)) for i in range(block.npred())])
                successors = _maybe(lambda: [int(block.succ(i)) for i in range(block.nsucc())])
                blocks.append({"serial": block_serial, "predecessors": predecessors,
                               "successors": successors})
                insn = block.head
                ordinal = 0
                while insn is not None:
                    item = _instruction(insn)
                    relation_instructions.append({"block_serial": block_serial, "ordinal": ordinal,
                        "ea": item["ea"], "opcode": item["opcode"], "l": item["l"],
                        "r": item["r"], "d": item["d"]})
                    rows.append((stored_ea, block_serial, ordinal,
                                 sqlite_ea(item["ea"]) if item["ea"] is not None else None,
                                 item["opcode"], item["text"],
                                 json.dumps(item["l"], sort_keys=True),
                                 json.dumps(item["r"], sort_keys=True),
                                 json.dumps(item["d"], sort_keys=True)))
                    insn = insn.next
                    ordinal += 1
                blocks[-1]["instruction_count"] = ordinal
            relations = build_relations(relation_instructions, blocks)
            relation_summary = {
                "version": relations["version"], "truncated": relations["truncated"],
                "cfg": {"complete": relations["cfg"]["complete"],
                        "block_count": len(relations["cfg"]["blocks"]),
                        "edge_count": len(relations["cfg"]["edges"])},
                "def_use": {key: relations["def_use"][key] for key in (
                    "complete_for_exported_register_value_numbers", "coverage",
                    "definition_count", "use_count")},
            }
            encoded = json.dumps({"relations": relations, "rows": rows, "arguments": arguments, "return": returned,
                                  "locals": variables,
                                  "maturity": maturity_name, "hexrays": version,
                                  "ida": ida_kernwin.get_kernel_version()}, sort_keys=True, ensure_ascii=False)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            connection.executemany(
                f"INSERT INTO {rows_table}(function_ea,block_serial,ordinal,ea,opcode,text,l_json,r_json,d_json) "
                "VALUES(?,?,?,?,?,?,?,?,?)", rows)
            connection.executemany(
                "INSERT INTO micro_blocks(view_name,function_ea,block_serial,predecessors_json,successors_json,instruction_count) VALUES(?,?,?,?,?,?)",
                [(view_name, stored_ea, block["serial"], json.dumps(block["predecessors"], sort_keys=True),
                  json.dumps(block["successors"], sort_keys=True), block.get("instruction_count", 0))
                 for block in relations["cfg"]["blocks"]],
            )
            references = []
            for kind, key in (("definition", "definitions"), ("use", "uses")):
                for reference in relations["def_use"][key]:
                    locator = reference["locator"]
                    references.append((view_name, stored_ea, reference["value_number"], kind,
                        locator["block_serial"], locator["ordinal"],
                        sqlite_ea(locator["ea"]) if locator.get("ea") is not None else None,
                        reference["operand_path"]))
            connection.executemany(
                "INSERT INTO micro_value_refs(view_name,function_ea,value_number,reference_kind,block_serial,ordinal,ea,operand_path) VALUES(?,?,?,?,?,?,?,?)",
                references,
            )
            if flow:
                connection.execute(
                    "INSERT OR REPLACE INTO micro_flow(function_ea,maturity,backend,status,error,decompiler_version,"
                    "instruction_count,content_hash,generated_at,arguments_json,return_json,locals_json,relations_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (stored_ea, maturity_name, "ida_hexrays", "ok", None, version, len(rows), digest, now,
                     json.dumps(arguments, sort_keys=True), json.dumps(returned, sort_keys=True),
                     json.dumps(variables, sort_keys=True), json.dumps(relation_summary, sort_keys=True)))
            else:
                connection.execute(
                    "INSERT OR REPLACE INTO microcode(function_ea,maturity,backend,status,error,decompiler_version,"
                    "instruction_count,content_hash,generated_at,relations_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (stored_ea, maturity_name, "ida_hexrays", "ok", None, version, len(rows), digest, now,
                     json.dumps(relation_summary, sort_keys=True)))
            statuses["ok"] += 1
        except Exception as exc:
            if flow:
                connection.execute(
                    "INSERT OR REPLACE INTO micro_flow(function_ea,maturity,backend,status,error,decompiler_version,"
                    "instruction_count,content_hash,generated_at,arguments_json,return_json,locals_json,relations_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (stored_ea, maturity_name, "ida_hexrays", "error", str(exc), version, 0, None, now,
                     "[]", "{}", "[]", "{}"))
            else:
                connection.execute(
                    "INSERT OR REPLACE INTO microcode(function_ea,maturity,backend,status,error,decompiler_version,"
                    "instruction_count,content_hash,generated_at,relations_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (stored_ea, maturity_name, "ida_hexrays", "error", str(exc), version, 0, None, now, "{}"))
            statuses["error"] += 1
    connection.commit()
    return {"view": summary_table, "functions": len(addresses), "statuses": dict(statuses),
            "maturity": maturity_name}

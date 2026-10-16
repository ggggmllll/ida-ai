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


def export_microcode(connection, addresses: list[int]) -> dict:
    """Replace selected function microcode with structured instructions and status."""
    ready = bool(_maybe(lambda: ida_hexrays.init_hexrays_plugin()))
    now = utc_now()
    maturity = int(getattr(ida_hexrays, MATURITY, 0))
    version = _maybe(lambda: str(ida_hexrays.get_hexrays_version()))
    statuses: Counter[str] = Counter()
    for function_ea in addresses:
        stored_ea = sqlite_ea(function_ea)
        connection.execute("DELETE FROM micro_instructions WHERE function_ea=?", (stored_ea,))
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
            rows = []
            for block_serial in range(int(mba.qty)):
                block = mba.get_mblock(block_serial)
                insn = block.head
                ordinal = 0
                while insn is not None:
                    item = _instruction(insn)
                    rows.append((stored_ea, block_serial, ordinal,
                                 sqlite_ea(item["ea"]) if item["ea"] is not None else None,
                                 item["opcode"], item["text"],
                                 json.dumps(item["l"], sort_keys=True),
                                 json.dumps(item["r"], sort_keys=True),
                                 json.dumps(item["d"], sort_keys=True)))
                    insn = insn.next
                    ordinal += 1
            encoded = json.dumps({"rows": rows, "maturity": MATURITY, "hexrays": version,
                                  "ida": ida_kernwin.get_kernel_version()}, sort_keys=True, ensure_ascii=False)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            connection.executemany(
                "INSERT INTO micro_instructions(function_ea,block_serial,ordinal,ea,opcode,text,l_json,r_json,d_json) "
                "VALUES(?,?,?,?,?,?,?,?,?)", rows)
            connection.execute(
                "INSERT OR REPLACE INTO microcode(function_ea,maturity,backend,status,error,decompiler_version,"
                "instruction_count,content_hash,generated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (stored_ea, MATURITY, "ida_hexrays", "ok", None, version, len(rows), digest, now))
            statuses["ok"] += 1
        except Exception as exc:
            connection.execute(
                "INSERT OR REPLACE INTO microcode(function_ea,maturity,backend,status,error,decompiler_version,"
                "instruction_count,content_hash,generated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (stored_ea, MATURITY, "ida_hexrays", "error", str(exc), version, 0, None, now))
            statuses["error"] += 1
    connection.commit()
    return {"view": "microcode", "functions": len(addresses), "statuses": dict(statuses),
            "maturity": MATURITY}

"""Entry script executed by IDA's headless batch runner."""

from __future__ import annotations

import json
import os
import sys
import traceback
from contextlib import closing
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ida_auto  # noqa: E402
import ida_loader  # noqa: E402
import ida_pro  # noqa: E402

from ida_ai import ida_export  # noqa: E402
from ida_ai.db import connect, get_metadata, record_operation  # noqa: E402


def dispatch(request: dict) -> dict:
    action = request["action"]
    db_path = Path(request["db_path"]).resolve()
    if action == "init":
        idb_path = Path(request["idb_path"]).resolve()
        idb_path.parent.mkdir(parents=True, exist_ok=True)
        if not ida_auto.auto_wait():
            raise RuntimeError("IDA autoanalysis did not complete")
        if not ida_loader.save_database(str(idb_path), 0):
            raise RuntimeError(f"IDA could not save database to {idb_path}")
        result = ida_export.export_database(db_path, idb_path=idb_path, skip_analysis=True, clear_operations=True)
        return {"db_path": str(db_path), "idb_path": str(idb_path), **result}

    if action == "mutate":
        with closing(connect(db_path)) as connection:
            idb_path = get_metadata(connection, "idb_path")
            if not idb_path:
                raise RuntimeError("database has no IDA database path; run init first")
            result = ida_export.apply_mutation(connection, idb_path, request["mutation"], request["values"])
        mutation = request["mutation"]
        if mutation in ("rename_local", "set_local_type"):
            result["sync"] = ida_export.synchronize_function(db_path, idb_path, request["values"]["address"])
        elif mutation == "pseudocode_comment":
            result["sync"] = ida_export.synchronize_function(db_path, idb_path, request["values"]["address"])
        elif mutation == "assembly_comment":
            function = ida_export.ida_funcs.get_func(request["values"]["address"])
            if function is not None:
                result["sync"] = ida_export.synchronize_function(db_path, idb_path, request["values"]["address"])
        elif mutation in ("register_type", "apply_type", "rename_symbol"):
            result["sync"] = ida_export.synchronize_database(db_path, idb_path, False)
        return result

    with closing(connect(db_path)) as connection:
        idb_path = get_metadata(connection, "idb_path")
        if not idb_path:
            raise RuntimeError("database has no IDA database path; run init first")
        if action == "sync":
            if request.get("address") is not None:
                return ida_export.synchronize_function(db_path, idb_path, request["address"])
            return ida_export.synchronize_database(db_path, idb_path, request.get("all_views", False))
        if action == "export_view":
            return ida_export.export_views(connection, request["addresses"], request["view"])
        if action == "vtable_build":
            return ida_export.build_vtables(connection, abi=request["abi"], start=request.get("start"),
                end=request.get("end"), min_function_slots=request.get("min_function_slots", 2),
                max_slots=request.get("max_slots", 512), max_bytes=request.get("max_bytes", 256 << 20))
        if action == "info":
            if "file_offset" in request:
                return ida_export.file_offset_info(request["file_offset"])
            return ida_export.address_info(request["address"])
        if action == "read":
            return ida_export.read_bytes(connection, request["address"], request["size"])
        if action == "write":
            written = ida_export.write_bytes(connection, request["address"], bytes.fromhex(request["data_hex"]), idb_path)
        elif action == "search":
            return ida_export.search_patterns(
                connection, request["patterns"], start=request.get("start"), end=request.get("end"),
                search_id=request["request_id"], limit=request["limit"],
            )
        elif action == "pointer_search":
            return ida_export.search_pointers(
                connection, target=request.get("target"), start=request.get("start"),
                end=request.get("end"), pointer_size=request.get("pointer_size"),
                search_id=request["request_id"], limit=request["limit"],
            )
        else:
            raise ValueError(f"unknown IDA action: {action}")

    # A patch can change functions, xrefs, CFG, and cached views. Rebuild the
    # snapshot from the saved IDB so that the SQLite analysis stays coherent.
    refreshed = ida_export.export_database(db_path, idb_path=idb_path, skip_analysis=True)
    with closing(connect(db_path)) as connection:
        ida_export.read_bytes(connection, request["address"], len(bytes.fromhex(request["data_hex"])))
    return {"written": written, "refreshed": refreshed}


def main() -> None:
    request = None
    exit_code = 1
    try:
        request_file = os.environ["IDA_AI_REQUEST"]
        request = json.loads(Path(request_file).read_text(encoding="utf-8"))
        result = dispatch(request)
        with closing(connect(request["db_path"])) as connection:
            record_operation(connection, request["request_id"], request["action"], "ok", result=result)
        exit_code = 0
    except Exception as exc:
        traceback.print_exc()
        if request is not None:
            try:
                with closing(connect(request["db_path"])) as connection:
                    record_operation(connection, request["request_id"], request["action"], "error", error=traceback.format_exc())
            except Exception:
                traceback.print_exc()
    finally:
        ida_pro.qexit(exit_code)


main()

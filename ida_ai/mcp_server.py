"""MCP tools for the persisted IDA analysis snapshot and controlled IDB edits."""

from __future__ import annotations

import argparse
import json
from contextlib import closing
from pathlib import Path
from threading import Lock
from typing import Literal

from .cli import _query
from .db import connect
from .runner import run_ida
from .selection import parse_int, select_function_addresses
from .text_search import search_code as _search_code
from .virtual_tables import (analyze_vcall as _analyze_vcall, list_vcalls as _list_vcalls,
                             list_vtables as _list_vtables, search_vtables as _search_vtables,
                             show_vcall as _show_vcall, show_vtable as _show_vtable)


def create_server(db_path: str | Path, *, idat: str | None = None, timeout: int = 0, unsafe: bool = False):
    """Build the stdio MCP server. Unsafe IDB mutations are absent unless enabled."""
    from mcp.server.fastmcp import FastMCP

    database = Path(db_path).expanduser().resolve()
    if not database.is_file():
        raise FileNotFoundError(f"analysis database does not exist: {database}")
    app = FastMCP("ida-ai")
    ida_lock = Lock()

    @app.tool()
    def database_summary() -> dict:
        """Return the analyzed binary identity and current SQLite artifact counts."""
        with ida_lock:
            with closing(connect(database)) as connection:
                metadata = {row["key"]: json.loads(row["value"]) for row in connection.execute("SELECT key,value FROM metadata")}
                tables = ("functions", "xrefs", "basic_blocks", "disassembly", "pseudocode", "microcode", "micro_instructions",
                          "micro_blocks", "micro_value_refs", "micro_flow", "micro_flow_instructions", "propagation_runs", "propagation_nodes",
                          "propagation_edges", "propagation_constraints", "data_pointer_slots", "vtable_runs",
                          "vtable_candidates", "vtable_slots", "vcall_runs", "vcall_sites", "vcall_targets",
                          "receiver_flows", "symbols", "comments", "jobs", "job_revisions")
                counts = {table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in tables}
            return {"metadata": metadata, "counts": counts}

    @app.tool()
    def sql_query(query: str, limit: int = 1000) -> dict:
        """Run a read-only SQL query against the AI-facing analysis SQLite database."""
        with ida_lock:
            return _query(database, query, limit, write=False)

    @app.tool()
    def search_code(
        terms: list[str],
        view: Literal["both", "disassembly", "pseudocode"] = "both",
        operator: Literal["all", "any"] = "all",
        case_sensitive: bool = False,
        use_regex: bool = False,
        start_address: str | None = None,
        end_address: str | None = None,
        limit: int = 100,
    ) -> dict:
        """Search textual assembly/pseudocode snapshots, separate from byte-pattern search."""
        with ida_lock:
            return _search_code(database, terms, view=view, operator=operator, case_sensitive=case_sensitive,
                                use_regex=use_regex,
                                start_address=start_address, end_address=end_address, limit=limit)

    @app.tool()
    def export_functions(
        view: Literal["disassembly", "pseudocode"],
        all_functions: bool = False,
        address: str | None = None,
        name: str | None = None,
        start_address: str | None = None,
        end_address: str | None = None,
    ) -> dict:
        """Generate selected function views before inspecting or text-searching them."""
        selectors = int(all_functions) + int(address is not None) + int(name is not None) + int(start_address is not None or end_address is not None)
        if selectors != 1:
            raise ValueError("choose exactly one of all_functions, address, name, or start/end range")
        address_range = None
        if start_address is not None or end_address is not None:
            if start_address is None or end_address is None:
                raise ValueError("provide both start_address and end_address")
            address_range = [start_address, end_address]
        with ida_lock:
            with closing(connect(database)) as connection:
                addresses = select_function_addresses(connection, all_functions=all_functions, address=address,
                                                      address_range=address_range, name=name)
            result = run_ida("export_view", database, idat=idat, timeout=timeout, addresses=addresses, view=view)
            return result

    @app.tool()
    def vtable_list(abi: str | None = None, limit: int = 100, offset: int = 0,
                    include_stale: bool = False) -> dict:
        """List indexed vtable-shaped data candidates; candidates are not class confirmations."""
        with ida_lock, closing(connect(database)) as connection:
            return _list_vtables(connection, abi=abi, limit=limit, offset=offset, include_stale=include_stale)

    @app.tool()
    def vtable_show(candidate_id: str | None = None, address: str | None = None,
                    include_stale: bool = False) -> dict:
        """Show one indexed address point, raw slot entries, thunk links, and discovery evidence."""
        with ida_lock, closing(connect(database)) as connection:
            return _show_vtable(connection, candidate_id=candidate_id,
                address=parse_int(address) if address is not None else None, include_stale=include_stale)

    @app.tool()
    def vtable_search(target_addresses: list[str] | None = None, slot_index: int | None = None,
                      abi: str | None = None, limit: int = 100,
                      include_stale: bool = False) -> dict:
        """Search candidate tables by one or more slot targets and/or a slot index."""
        targets = [parse_int(item) for item in (target_addresses or [])]
        with ida_lock, closing(connect(database)) as connection:
            return _search_vtables(connection, target_eas=targets, slot_index=slot_index,
                                   abi=abi, limit=limit, include_stale=include_stale)

    @app.tool()
    def vcall_list(function_address: str | None = None, status: str | None = None,
                   limit: int = 100, offset: int = 0, include_stale: bool = False) -> dict:
        """List indexed indirect calls and the subset matching a two-load vtable-shaped pattern."""
        with ida_lock, closing(connect(database)) as connection:
            return _list_vcalls(connection,
                function_ea=parse_int(function_address) if function_address is not None else None,
                status=status, limit=limit, offset=offset, include_stale=include_stale)

    @app.tool()
    def analyze_virtual_call(call_id: str | None = None, address: str | None = None) -> dict:
        """Explain a stored call pattern and list compatible table slots without claiming runtime reachability."""
        with ida_lock, closing(connect(database)) as connection:
            return _analyze_vcall(connection, call_id=call_id,
                address=parse_int(address) if address is not None else None)

    @app.tool()
    def vcall_show(call_id: str | None = None, address: str | None = None,
                   include_stale: bool = False) -> dict:
        """Show a saved call candidate and any previously stored slot resolution."""
        with ida_lock, closing(connect(database)) as connection:
            return _show_vcall(connection, call_id=call_id,
                address=parse_int(address) if address is not None else None, include_stale=include_stale)

    @app.resource("ida://database/schema")
    def database_schema() -> str:
        """Describe the core analysis tables available to sql_query."""
        return """Core tables: metadata(key,value), segments, functions(start_ea,end_ea,name,demangled_name,signature,flags,size,segment_name,is_library,is_thunk,thunk_target_ea,is_nullstub,comment,repeatable_comment), xrefs, basic_blocks, cfg_edges, disassembly, instructions, pseudocode, microcode, micro_instructions, micro_blocks, micro_value_refs, micro_flow, micro_flow_instructions, data_pointer_slots, vtable_runs, vtable_candidates, vtable_slots, vtable_evidence, vcall_runs, vcall_sites, vcall_targets, receiver_flows, propagation_runs, propagation_nodes, propagation_edges, propagation_constraints, symbols, comments, type_definitions, type_assignments, memory_bytes, pointers, search_matches, operations, jobs, job_revisions. microcode.relations_json contains relation coverage metadata; query micro_blocks for CFG predecessors/successors and micro_value_refs for direct register value-number definition/use locations. These are not complete SSA or an alias graph. vtable_candidates are heuristic data-sequence candidates, not confirmed C++ classes; vcall_sites distinguish indirect calls from two-load vtable-shaped candidates, and target rows are slot compatibility only until receiver reachability is established. Rows carry source hashes and stale flags. is_nullstub conservatively identifies functions containing only harmless entry instructions and a return. Address integers use signed SQLite representations of unsigned ea_t values. Propagation remains a bounded evidence graph."""

    if unsafe:
        def mutate(kind: str, values: dict) -> dict:
            with ida_lock:
                result = run_ida("mutate", database, idat=idat, timeout=timeout, mutation=kind, values=values)
                from .cli import _cache_file
                _cache_file(database).unlink(missing_ok=True)
            return result

        @app.tool()
        def set_assembly_comment(address: str, comment: str, repeatable: bool = False) -> dict:
            """Set/delete an IDA disassembly address comment, distinct from a Hex-Rays comment."""
            return mutate("assembly_comment", {"address": parse_int(address), "comment": comment, "repeatable": repeatable})

        @app.tool()
        def set_function_comment(address: str, comment: str, repeatable: bool = False) -> dict:
            """Set/delete a function header comment in IDA; separate from line and pseudocode comments."""
            return mutate("function_comment", {"address": parse_int(address), "comment": comment, "repeatable": repeatable})

        @app.tool()
        def set_pseudocode_comment(address: str, comment: str, item_preciser: int | None = None) -> dict:
            """Set/delete a Hex-Rays ctree user comment at an address inside a function."""
            values = {"address": parse_int(address), "comment": comment}
            if item_preciser is not None:
                values["item_preciser"] = item_preciser
            return mutate("pseudocode_comment", values)

        @app.tool()
        def register_type(name: str, declaration: str) -> dict:
            """Parse and register one C type declaration in IDA's local type library."""
            return mutate("register_type", {"name": name, "declaration": declaration})

        @app.tool()
        def apply_type(address: str, declaration: str) -> dict:
            """Apply a C declaration to an IDA address and refresh affected SQL observations."""
            return mutate("apply_type", {"address": parse_int(address), "declaration": declaration})

        @app.tool()
        def rename_symbol(address: str, name: str) -> dict:
            """Rename a function or global IDA symbol at an address."""
            return mutate("rename_symbol", {"address": parse_int(address), "name": name})

        @app.tool()
        def rename_local_variable(function_address: str, old_name: str, new_name: str) -> dict:
            """Rename a Hex-Rays local variable by its current name within a function."""
            return mutate("rename_local", {"address": parse_int(function_address), "old_name": old_name, "new_name": new_name})

        @app.tool()
        def set_local_variable_type(function_address: str, name: str, declaration: str) -> dict:
            """Set a Hex-Rays local variable type and refresh that function's SQLite views."""
            return mutate("set_local_type", {
                "address": parse_int(function_address), "name": name, "declaration": declaration,
            })

        @app.tool()
        def sync_analysis(all_views: bool = False) -> dict:
            """Rebuild the SQLite snapshot from the saved IDB after external IDA edits."""
            with ida_lock:
                result = run_ida("sync", database, idat=idat, timeout=timeout, all_views=all_views)
                from .cli import _cache_file
                _cache_file(database).unlink(missing_ok=True)
            return result

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ida-ai-mcp", description="stdio MCP tools over an ida-ai SQLite snapshot")
    parser.add_argument("--db", required=True, type=Path, help="analysis SQLite database created by ida-ai init")
    parser.add_argument("--idat", help="IDA batch executable; defaults to IDAT/IDADIR/PATH discovery")
    parser.add_argument("--timeout", type=int, default=0, help="IDA batch timeout in seconds; 0 means unlimited")
    parser.add_argument("--unsafe", action="store_true", help="register IDB mutation tools")
    args = parser.parse_args(argv)
    if args.timeout < 0:
        parser.error("--timeout must be non-negative")
    create_server(args.db, idat=args.idat, timeout=args.timeout, unsafe=args.unsafe).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
                          "micro_flow", "micro_flow_instructions", "propagation_runs", "propagation_nodes",
                          "propagation_edges", "propagation_constraints", "symbols", "comments", "jobs", "job_revisions")
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

    @app.resource("ida://database/schema")
    def database_schema() -> str:
        """Describe the core analysis tables available to sql_query."""
        return """Core tables: metadata(key,value), segments, functions(start_ea,end_ea,name,demangled_name,signature,flags,size,segment_name,is_library,is_thunk,thunk_target_ea,is_nullstub,comment,repeatable_comment), xrefs(source_ea,target_ea,xref_type,...), basic_blocks, cfg_edges, disassembly(function_ea,text,status,...), instructions, pseudocode(function_ea,text,status,...), microcode(function_ea,maturity,status,error,content_hash,...), micro_instructions(function_ea,block_serial,ordinal,ea,opcode,text,l_json,r_json,d_json), micro_flow(function_ea,maturity,status,error,content_hash,arguments_json,return_json,locals_json,...), micro_flow_instructions(function_ea,block_serial,ordinal,ea,opcode,text,l_json,r_json,d_json), propagation_runs(run_id,snapshot_hash,request_json,result_json,...), propagation_nodes(node_id,kind,identity_json,source_snapshot_hash,...), propagation_edges(edge_id,source_node,target_node,family,direction,confidence,transform_json,evidence_json,context_json,source_snapshot_hash,...), propagation_constraints(constraint_id,run_id,proposal_id,node_id,constraint_json,provenance_json,source_snapshot_hash,...), symbols(address,name,type), comments(address,function_ea,kind,repeatable,item_preciser,text,updated_at), type_definitions(name,declaration,updated_at), type_assignments(address,declaration,updated_at), memory_bytes, pointers, search_matches, operations. Research job history uses jobs(job_id,parent_job_id,title,objective,status,head_revision_id) and immutable job_revisions(revision_id,job_id,revision_no,parent_revision_id,message,details,changes_json,snapshot_json,analysis_snapshot_json,state_hash). is_nullstub conservatively identifies functions containing only harmless entry instructions and a return. Address integers use signed SQLite representations of unsigned ea_t values. Propagation is a bounded preview graph: only explicitly accepted constraints are durable type results; stale snapshots must be re-seeded or re-previewed."""

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

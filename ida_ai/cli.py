"""Command line client for IDA analysis and SQLite artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import uuid
from contextlib import closing
from pathlib import Path

from .db import connect, get_metadata, record_operation, sqlite_ea
from .call_audit import audit_shared_calls
from .derived_calls import import_derived_calls
from .jobs import JOB_STATUSES, check_jobs, create_job, history as job_history, list_jobs, resume_job, revise_job, show_job
from .job_queries import diff_job, find_jobs, impact
from .type_features import normalize_spec, scan_type_features
from .propagation import add_edge as add_propagation_edge, add_seed as add_propagation_seed
from .propagation import accept_propagation, preview_seed, show_node as show_propagation_node
from .virtual_tables import (analyze_vcall, build_vcall_index, build_vtable_index,
                             build_vptr_write_index, list_vptr_writes,
                             list_vcalls, list_vtables, search_vtables,
                             show_vcall, show_vtable, trace_vptr_object_flows)
from .vtable_types import class_relationships, preview_vtable_type_plan
from .vcall_trace import trace_virtual_call, show_trace
from .runner import run_ida, attach_idb
from .selection import parse_hex_bytes, parse_int, parse_pattern, parse_range, select_function_addresses, selection_preview


def _add_db(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, type=Path, help="SQLite analysis database")


def _add_ida(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--idat", help="path to IDA's idat64/idat executable")
    parser.add_argument("--timeout", type=int, default=0, help="IDA timeout in seconds; 0 means unlimited")


def _add_range(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"), help="half-open address range")


def _cache_file(db_path: Path) -> Path:
    key = hashlib.sha256(str(db_path.expanduser().resolve()).encode("utf-8")).hexdigest()
    return db_path.expanduser().resolve().parent / ".ida-ai-cache" / f"{key}.json"


def _idb_fingerprint(db_path: Path) -> dict:
    if not db_path.is_file():
        raise FileNotFoundError(f"SQLite database does not exist: {db_path}")
    with closing(connect(db_path)) as connection:
        idb = get_metadata(connection, "idb_path")
    if not idb or not Path(idb).is_file():
        raise FileNotFoundError("saved IDA database is missing; run init first")
    path = Path(idb).resolve()
    stat = path.stat()
    return {"path": str(path), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def _restore_cached_search(db_path: Path, search_id: str, result: dict, pointer: bool) -> None:
    with closing(connect(db_path)) as connection:
        connection.execute("DELETE FROM search_matches WHERE search_id = ?", (search_id,))
        if pointer:
            for ordinal, item in enumerate(result["matches"]):
                connection.execute(
                    "INSERT OR IGNORE INTO pointers(source_address,target_address,pointer_size,target_name,target_type,source_kind) VALUES(?,?,?,?,?,?)",
                    (sqlite_ea(item["source_address"]), sqlite_ea(item["target_address"]), item["pointer_size"], item.get("target_name"), item.get("target_type"), "raw_scan"),
                )
                connection.execute(
                    "INSERT INTO search_matches(search_id,ordinal,address,pattern_index,match_kind) VALUES(?,?,?,?,?)",
                    (search_id, ordinal, sqlite_ea(item["source_address"]), None, "pointer"),
                )
        else:
            connection.executemany(
                "INSERT INTO search_matches(search_id,ordinal,address,pattern_index,match_kind) VALUES(?,?,?,?,?)",
                ((search_id, ordinal, sqlite_ea(item["address"]), item["pattern_index"], "pattern") for ordinal, item in enumerate(result["matches"])),
            )
        connection.commit()


def _clear_searches(db_path: Path) -> dict:
    if not db_path.is_file():
        raise FileNotFoundError(f"SQLite database does not exist: {db_path}")
    with closing(connect(db_path)) as connection:
        matches = connection.execute("SELECT count(*) FROM search_matches").fetchone()[0]
        connection.execute("DELETE FROM search_matches")
        connection.execute("DELETE FROM pointers WHERE source_kind='raw_scan'")
        connection.execute("DELETE FROM operations WHERE action IN ('search','pointer_search')")
        connection.commit()
    cache = _cache_file(db_path)
    cache.unlink(missing_ok=True)
    return {"cleared_search_matches": matches, "cache_cleared": True}


def _cached_search(db_path: Path, action: str, options: dict, ida_options: dict) -> dict:
    fingerprint = _idb_fingerprint(db_path)
    cache_path = _cache_file(db_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        cache = {"idb": fingerprint, "entries": {}}
    if not isinstance(cache, dict) or cache.get("idb") != fingerprint or not isinstance(cache.get("entries"), dict):
        cache = {"idb": fingerprint, "entries": {}}
    key = json.dumps({"idb": fingerprint, "action": action, "options": options}, sort_keys=True, separators=(",", ":"))
    key = hashlib.sha256(key.encode("utf-8")).hexdigest()
    if key in cache["entries"]:
        result = cache["entries"][key]
        search_id = uuid.uuid4().hex
        _restore_cached_search(db_path, search_id, result, action == "pointer_search")
        result = {**result, "search_id": search_id, "cached": True}
        with closing(connect(db_path)) as connection:
            record_operation(connection, search_id, action, "ok", result)
        return result
    result = run_ida(action, db_path, **ida_options, **options)
    # IDA may save its database even after a read-only batch request.
    fingerprint = _idb_fingerprint(db_path)
    cache = {"idb": fingerprint, "entries": {}}
    key = hashlib.sha256(json.dumps(
        {"idb": fingerprint, "action": action, "options": options},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    cache["entries"][key] = result
    temporary = cache_path.with_suffix(f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    temporary.replace(cache_path)
    return {**result, "cached": False}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ida-ai", description="Headless IDA export backed by SQLite")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="analyze a binary and index functions, xrefs, and CFG")
    _add_db(init)
    _add_ida(init)
    init.add_argument("--binary", required=True, type=Path)
    init.add_argument("--idb", type=Path, help="saved IDA database path; defaults to DB basename with .i64")

    attach = commands.add_parser("attach-idb", help="copy and index an existing IDB without its input binary")
    _add_db(attach)
    _add_ida(attach)
    attach.add_argument("--source", required=True, type=Path)
    attach.add_argument("--idb", type=Path)
    attach.add_argument("--reuse-idb", action="store_true")

    callers = commands.add_parser("import-callers", help="follow exported import/GOT/PLT incoming xrefs with explicit frontiers")
    _add_db(callers)
    callers.add_argument("--address", required=True)
    callers.add_argument("--max-hops", type=int, default=4)
    callers.add_argument("--max-nodes", type=int, default=1000)
    callers.add_argument("--max-edges", type=int, default=5000)

    discover = commands.add_parser("discover", help="snapshot decoded IDA strings and imports into SQLite")
    _add_db(discover)
    _add_ida(discover)
    _add_range(discover)
    discover.add_argument("--kind", choices=("all", "strings", "imports"), default="all")
    discover.add_argument("--max-items", type=int, default=100000)
    discover.add_argument("--max-bytes", type=int, default=32 << 20)

    disasm_range = commands.add_parser(
        "disasm-range",
        help="read decoded code/data items in an arbitrary range without creating functions",
    )
    _add_db(disasm_range)
    _add_ida(disasm_range)
    disasm_range.add_argument("--start", required=True, help="inclusive start address")
    disasm_range.add_argument("--end", required=True, help="exclusive end address")
    disasm_range.add_argument("--max-items", type=int, default=10000,
                              help="maximum decoded code entries to return")
    disasm_range.add_argument("--max-bytes", type=int, default=1 << 20,
                              help="maximum requested range size")

    match = commands.add_parser("vtable-match", help="match positional slot constraints against loaded pointer observations")
    _add_db(match)
    _add_ida(match)
    _add_range(match)
    match.add_argument("--spec", required=True, type=Path)
    match.add_argument("--no-refresh", action="store_true")
    match.add_argument("--limit", type=int, default=1000)
    match.add_argument("--max-anchors", type=int, default=100000)
    match.add_argument("--max-bytes", type=int, default=256 << 20)

    export = commands.add_parser("export", help="export a function view into SQLite")
    views = export.add_subparsers(dest="view", required=True)
    for name in ("disassembly", "pseudocode", "microcode", "flow", "batch"):
        view = views.add_parser(name, help=f"export {name} for selected functions")
        _add_db(view)
        _add_ida(view)
        view.add_argument("--preview", action="store_true", help="explain selection without starting IDA")
        view.add_argument("--max-functions", type=int, default=1000, help="selection budget; 0 unlimited")
        if name == "batch":
            view.add_argument("--views", nargs="+", required=True, choices=("disassembly", "pseudocode", "microcode", "flow"))
        selection = view.add_mutually_exclusive_group(required=True)
        selection.add_argument("--all", action="store_true", dest="all_functions")
        selection.add_argument("--address", help="address inside a function")
        selection.add_argument("--addresses", nargs="+", help="union of functions containing these addresses")
        selection.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"))
        selection.add_argument("--name", help="exact function or demangled name")

    info = commands.add_parser("info", help="inspect address, segment, permissions, and file offset")
    _add_db(info)
    _add_ida(info)
    info_location = info.add_mutually_exclusive_group(required=True)
    info_location.add_argument("--address")
    info_location.add_argument("--file-offset")

    read = commands.add_parser("read", help="read bytes from the saved IDA database")
    _add_db(read)
    _add_ida(read)
    read.add_argument("--address", required=True)
    read.add_argument("--size", required=True, type=int)
    read.add_argument("--format", dest="output_format", choices=("auto", "hex", "array", "both", "none"),
                      default="auto", help="inline result shape; auto uses hex up to 4096 bytes")
    read.add_argument("--max-inline-bytes", type=int, default=4096,
                      help="auto-mode threshold; larger reads remain in SQLite without duplicating bytes inline")
    read.add_argument("--output", type=Path, help="write the complete raw bytes to this file")

    write = commands.add_parser("write", help="patch bytes and refresh the analysis snapshot")
    _add_db(write)
    _add_ida(write)
    write.add_argument("--address", required=True)
    write.add_argument("--data", required=True, help="hex bytes, e.g. '90 90'")

    search = commands.add_parser("search", help="search data with union and masked byte patterns")
    _add_db(search)
    _add_ida(search)
    search.add_argument("--pattern", action="append", required=True, help="hex bytes with optional ?? wildcards; repeat for union")
    search.add_argument("--mask", action="append", help="hex mask paired with each --pattern")
    _add_range(search)
    search.add_argument("--limit", type=int, default=1000, help="maximum matches; 0 means unlimited")

    pointers = commands.add_parser("pointer-search", help="find raw pointers into mapped memory or to a target")
    _add_db(pointers)
    _add_ida(pointers)
    pointers.add_argument("--target", help="target address; without it, find mapped aligned pointers")
    pointers.add_argument("--pointer-size", type=int, choices=(4, 8), help="default is IDA database bitness")
    _add_range(pointers)
    pointers.add_argument("--limit", type=int, default=1000, help="maximum matches; 0 means unlimited")

    clear = commands.add_parser("clear-searches", help="clear persisted search records and local search cache")
    _add_db(clear)

    call_audit = commands.add_parser(
        "call-audit",
        help="flag high-fan-in callsites whose targets use return-address-dependent dispatch",
    )
    _add_db(call_audit)
    call_audit.add_argument("--min-fan-in", type=int, default=256)
    call_audit.add_argument("--max-functions", type=int, default=1000)
    call_audit.add_argument("--max-results", type=int, default=10000)
    call_scope = call_audit.add_mutually_exclusive_group(required=True)
    call_scope.add_argument("--all", action="store_true", dest="all_functions")
    call_scope.add_argument("--address", help="address inside a function")
    call_scope.add_argument("--addresses", nargs="+", help="union of functions containing these addresses")
    call_scope.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"))
    call_scope.add_argument("--name", help="exact function or demangled name")

    derived = commands.add_parser(
        "derived-call-import",
        help="import explicitly resolved call targets as derived evidence, separate from IDA xrefs",
    )
    _add_db(derived)
    derived.add_argument("--input", required=True, type=Path, help="resolver JSON list or object with calls list")
    derived.add_argument("--resolver", required=True, help="stable resolver identity")
    derived.add_argument("--method", required=True, help="resolver method or algorithm identifier")
    derived.add_argument("--confidence", type=float, help="default confidence from 0 to 1")
    derived.add_argument("--source-ref", help="provenance label; defaults to the input file path")
    derived.add_argument("--notes", help="optional provenance notes")
    sync = commands.add_parser("sync", help="rebuild the SQLite snapshot from the saved IDB")
    _add_db(sync)
    _add_ida(sync)
    sync_scope = sync.add_mutually_exclusive_group()
    sync_scope.add_argument("--all-views", action="store_true", help="generate disassembly, pseudocode, and microcode for every function")
    sync_scope.add_argument("--address", help="refresh one function after local variable edits")

    sql = commands.add_parser("sql", help="run a read-only SQLite query without starting IDA")
    _add_db(sql)
    sql.add_argument("--query", required=True)
    sql.add_argument("--limit", type=int, default=1000, help="maximum rows; 0 means unlimited")
    sql.add_argument("--write", action="store_true", help="allow a mutating SQL statement and commit it")

    job_create = commands.add_parser("job-create", help="create a hierarchical reverse-engineering research job")
    _add_db(job_create)
    job_create.add_argument("--title", required=True)
    job_create.add_argument("--objective", required=True)
    job_create.add_argument("--parent", type=int, help="parent research job ID")
    job_create.add_argument("--message", required=True, help="initial VCS revision message")

    job_list = commands.add_parser("job-list", help="list research jobs or print the job hierarchy")
    _add_db(job_list)
    job_list.add_argument("--parent", type=int, help="show direct children of this job")
    job_list.add_argument("--status", choices=JOB_STATUSES)
    job_list.add_argument("--tree", action="store_true", help="return the hierarchy as nested JSON")

    job_show = commands.add_parser("job-show", help="show current job claims, evidence, and revisions")
    _add_db(job_show)
    job_show.add_argument("--job", required=True, type=int)

    job_resume = commands.add_parser("job-resume", help="restore compact context before continuing a research job")
    _add_db(job_resume)
    job_resume.add_argument("--job", required=True, type=int)
    job_resume.add_argument("--recent", type=int, default=3, help="number of recent VCS revisions to include; 0 means all")

    job_history_parser = commands.add_parser("job-history", help="inspect immutable VCS revisions for a research job")
    _add_db(job_history_parser)
    job_history_parser.add_argument("--job", required=True, type=int)
    job_history_parser.add_argument("--limit", type=int, default=20, help="recent revisions; 0 means all")
    job_history_parser.add_argument("--include-state", action="store_true", help="include each full saved job snapshot")
    job_history_parser.add_argument("--revision", type=int, help="read one exact revision ID")

    job_revise = commands.add_parser("job-revise", help="append a VCS revision with claims, evidence, or job state changes")
    _add_db(job_revise)
    job_revise.add_argument("--job", required=True, type=int)
    job_revise.add_argument("--message", required=True, help="short reason for this revision")
    job_revise.add_argument("--details", default="", help="detailed analysis note stored in the VCS revision")
    job_revise.add_argument("--title")
    job_revise.add_argument("--objective")
    job_revise.add_argument("--status", choices=JOB_STATUSES)
    job_revise.add_argument("--add-claim", action="append", default=[], metavar="JSON")
    job_revise.add_argument("--update-claim", action="append", default=[], metavar="JSON")
    job_revise.add_argument("--withdraw-claim", action="append", default=[], metavar="JSON")
    job_revise.add_argument("--add-evidence", action="append", default=[], metavar="JSON")
    job_revise.add_argument("--add-question", action="append", default=[], metavar="TEXT")
    job_revise.add_argument("--resolve-question", action="append", default=[], metavar="JSON")
    job_revise.add_argument("--depends-on", action="append", default=[], type=int, metavar="JOB_ID")
    job_revise.add_argument("--remove-dependency", action="append", default=[], type=int, metavar="JOB_ID")
    job_revise.add_argument("--ida-operation", action="append", default=[], metavar="REQUEST_ID")
    job_revise.add_argument("--validation", action="append", default=[], metavar="TEXT")
    job_revise.add_argument("--restore-revision", type=int, help="append a new revision restoring an earlier saved state")
    job_revise.add_argument("--expected-revision", type=int, help="fail if the job head changed since the resume context")
    job_revise.add_argument("--handoff", help="JSON object with progress, next_action, and stop_condition")
    job_revise.add_argument("--patch-file", type=Path, help="UTF-8 JSON changes file; cannot be mixed with other change flags")

    job_diff = commands.add_parser("job-diff", help="compare two immutable job VCS revisions")
    _add_db(job_diff)
    job_diff.add_argument("--job", required=True, type=int)
    job_diff.add_argument("--from-revision", required=True, type=int)
    job_diff.add_argument("--to-revision", type=int, help="defaults to the current head")

    job_search = commands.add_parser("job-search", help="search current job claims, evidence, questions, or revision notes")
    _add_db(job_search)
    job_search.add_argument("--query", required=True)
    job_search.add_argument("--job", type=int)
    job_search.add_argument("--kind", choices=("all", "claim", "evidence", "question", "note"), default="all")
    job_search.add_argument("--history", action="store_true", help="search every historical revision, not only current heads")
    job_search.add_argument("--limit", type=int, default=30)

    job_impact = commands.add_parser("job-impact", help="show potential claim and dependency impact")
    _add_db(job_impact)
    job_impact.add_argument("--job", required=True, type=int)
    job_impact.add_argument("--claim", action="append", default=[], help="claim ID; repeat for multiple roots")

    job_check = commands.add_parser("job-check", help="detect analysis/evidence drift and optionally record review revisions")
    _add_db(job_check)
    job_check.add_argument("--apply", action="store_true", help="append review-required revisions for changed evidence")

    type_scan = commands.add_parser("type-scan", help="scan microcode for a structured type-usage form")
    _add_db(type_scan)
    _add_ida(type_scan)
    type_scan.add_argument("--spec", required=True, type=Path, help="UTF-8 JSON utilization-form specification")
    type_scan_selection = type_scan.add_mutually_exclusive_group(required=True)
    type_scan_selection.add_argument("--all", action="store_true", dest="all_functions",
                                     help="refresh and scan every indexed function")
    type_scan_selection.add_argument("--address", help="refresh and scan the function containing this address")
    type_scan_selection.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"),
                                     help="refresh and scan every function overlapping this half-open range")
    type_scan_selection.add_argument("--name", help="refresh and scan the exact function or demangled name")
    type_scan.add_argument("--no-refresh", action="store_true",
                           help="use existing SQLite microcode without launching IDA")
    type_scan.add_argument("--limit", type=int, default=1000, help="maximum returned candidate locations; 0 means unlimited")
    type_scan.add_argument("--min-score", type=float, help="override the specification score threshold")

    type_propagate = commands.add_parser("type-propagate", help="seed, link, preview, accept, and inspect bounded type-constraint propagation")
    type_actions = type_propagate.add_subparsers(dest="propagation_action", required=True)
    type_seed = type_actions.add_parser("seed", help="record an evidence-backed confirmed or observed constraint")
    _add_db(type_seed)
    _add_ida(type_seed)
    type_seed.add_argument("--spec", required=True, type=Path, help="UTF-8 JSON seed specification")
    type_seed.add_argument("--no-refresh", action="store_true", help="use current MMAT_LVARS flow snapshot")
    type_link = type_actions.add_parser("link", help="record an immutable evidence-backed relationship edge")
    _add_db(type_link)
    _add_ida(type_link)
    type_link.add_argument("--spec", required=True, type=Path, help="UTF-8 JSON relationship specification")
    type_preview = type_actions.add_parser("preview", help="preview bounded propagation from a stored seed")
    _add_db(type_preview)
    type_preview.add_argument("--seed-id", required=True)
    type_preview.add_argument("--family", action="append", choices=("reference", "parameter", "return"))
    type_preview.add_argument("--max-hops", type=int, default=6)
    type_preview.add_argument("--max-nodes", type=int, default=500)
    type_preview.add_argument("--max-edges", type=int, default=2000)
    type_preview.add_argument("--max-alternatives", type=int, default=8)
    type_accept = type_actions.add_parser("accept", help="accept selected proposals after snapshot and conflict checks")
    _add_db(type_accept)
    type_accept.add_argument("--run-id", required=True)
    type_accept.add_argument("--proposal", action="append", required=True)
    type_accept.add_argument("--job", type=int, help="append accepted proposals as job evidence")
    type_node = type_actions.add_parser("node", help="inspect evidence, accepted constraints, and relationship edges for a node")
    _add_db(type_node)
    type_node.add_argument("--node", required=True)

    vtable_build = commands.add_parser("vtable-build", help="scan durable data pointers and build heuristic Itanium vtable candidates")
    _add_db(vtable_build)
    _add_ida(vtable_build)
    vtable_build.add_argument("--abi", choices=("itanium",), default="itanium")
    vtable_build.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"),
                              help="optional half-open data-address range")
    vtable_build.add_argument("--no-refresh", action="store_true", help="use existing data_pointer_slots observations")
    vtable_build.add_argument("--max-bytes", type=int, default=256 << 20)
    vtable_build.add_argument("--min-function-slots", type=int, default=2)
    vtable_build.add_argument("--max-slots", type=int, default=512)

    vtable_list = commands.add_parser("vtable-list", help="list current virtual-table candidates")
    _add_db(vtable_list)
    vtable_list.add_argument("--abi", choices=("itanium",))
    vtable_list.add_argument("--status")
    vtable_list.add_argument("--limit", type=int, default=100)
    vtable_list.add_argument("--offset", type=int, default=0)
    vtable_list.add_argument("--include-stale", action="store_true")

    vtable_show = commands.add_parser("vtable-show", help="show one candidate, its slots, and evidence")
    _add_db(vtable_show)
    vtable_selector = vtable_show.add_mutually_exclusive_group(required=True)
    vtable_selector.add_argument("--candidate-id")
    vtable_selector.add_argument("--address")
    vtable_show.add_argument("--include-stale", action="store_true")

    vtable_search = commands.add_parser("vtable-search", help="search table candidates by implementations or slot index")
    _add_db(vtable_search)
    vtable_search.add_argument("--target", action="append", default=[], help="required slot target EA; repeat to require multiple entries")
    vtable_search.add_argument("--slot-index", type=int)
    vtable_search.add_argument("--abi", choices=("itanium",))
    vtable_search.add_argument("--limit", type=int, default=100)
    vtable_search.add_argument("--include-stale", action="store_true")

    vtable_relations = commands.add_parser("vtable-class-relations", help="join current RTTI base edges to heuristic vtable candidates")
    _add_db(vtable_relations)
    vtable_relations.add_argument("--derived-typeinfo", help="filter by derived typeinfo address")
    vtable_relations.add_argument("--limit", type=int, default=100)
    vtable_relations.add_argument("--offset", type=int, default=0)

    vtable_type_preview = commands.add_parser("vtable-type-preview", help="validate a vtable type plan without changing IDA")
    _add_db(vtable_type_preview)
    vtable_type_preview.add_argument("--spec", required=True, type=Path, help="UTF-8 JSON type plan")

    vtable_type_apply = commands.add_parser("vtable-type-apply", help="apply a current revision-checked vtable type plan")
    _add_db(vtable_type_apply)
    _add_ida(vtable_type_apply)
    vtable_type_apply.add_argument("--spec", required=True, type=Path, help="UTF-8 JSON type plan")
    vtable_type_apply.add_argument("--preview-id", required=True)
    vtable_type_apply.add_argument("--revision-token", required=True)

    vcall_build = commands.add_parser("vcall-build", help="refresh microcode and index indirect-call/vtable-pattern candidates")
    _add_db(vcall_build)
    _add_ida(vcall_build)
    vcall_selection = vcall_build.add_mutually_exclusive_group(required=True)
    vcall_selection.add_argument("--all", action="store_true", dest="all_functions")
    vcall_selection.add_argument("--address", help="address inside one function")
    vcall_selection.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"))
    vcall_selection.add_argument("--name", help="exact function or demangled name")
    vcall_build.add_argument("--no-refresh", action="store_true", help="use exported microcode only")
    vcall_build.add_argument("--max-calls", type=int, default=100000)

    vcall_analyze_parser = commands.add_parser("vcall-analyze", help="analyze a call candidate and list compatible indexed slots")
    _add_db(vcall_analyze_parser)
    vcall_selector = vcall_analyze_parser.add_mutually_exclusive_group(required=True)
    vcall_selector.add_argument("--call-id")
    vcall_selector.add_argument("--address")

    vcall_trace = commands.add_parser("vcall-trace", help="bounded receiver memory query at the vptr load, optionally across LVARS direct calls")
    _add_db(vcall_trace)
    trace_selector = vcall_trace.add_mutually_exclusive_group(required=True)
    trace_selector.add_argument("--call-id")
    trace_selector.add_argument("--address")
    for budget, default in (("hops", 6), ("nodes", 500), ("edges", 4000), ("alternatives", 16), ("context", 4)):
        vcall_trace.add_argument(f"--max-{budget}", type=int, default=default)

    trace_show = commands.add_parser("vcall-trace-show", help="read an immutable virtual-call memory trace")
    _add_db(trace_show)
    trace_show.add_argument("--run-id", required=True)
    trace_show.add_argument("--include-stale", action="store_true")

    vcall_show_parser = commands.add_parser("vcall-show", help="show an indexed call candidate and its saved resolution")
    _add_db(vcall_show_parser)
    vcall_show_selector = vcall_show_parser.add_mutually_exclusive_group(required=True)
    vcall_show_selector.add_argument("--call-id")
    vcall_show_selector.add_argument("--address")
    vcall_show_parser.add_argument("--include-stale", action="store_true")

    vptr_write_build = commands.add_parser("vptr-write-build", help="index function-local stores of indexed vtable address points")
    _add_db(vptr_write_build)
    _add_ida(vptr_write_build)
    vptr_write_selection = vptr_write_build.add_mutually_exclusive_group(required=True)
    vptr_write_selection.add_argument("--all", action="store_true", dest="all_functions")
    vptr_write_selection.add_argument("--address", help="address inside one function")
    vptr_write_selection.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"))
    vptr_write_selection.add_argument("--name", help="exact function or demangled name")
    vptr_write_build.add_argument("--no-refresh", action="store_true", help="use the selected exported microcode view only")
    vptr_write_build.add_argument("--max-writes", type=int, default=100000)
    vptr_write_build.add_argument("--view", choices=("microcode", "micro_flow"), default="microcode",
                                  help="index GLBOPT3 microcode or LVARS microcode")

    vptr_write_list = commands.add_parser("vptr-write-list", help="list current observed vptr stores")
    _add_db(vptr_write_list)
    vptr_write_list.add_argument("--function", help="filter by containing function start/address")
    vptr_write_list.add_argument("--address-point", help="filter by indexed address point")
    vptr_write_list.add_argument("--limit", type=int, default=100)
    vptr_write_list.add_argument("--offset", type=int, default=0)
    vptr_write_list.add_argument("--include-stale", action="store_true")

    vptr_write_trace = commands.add_parser("vptr-write-trace", help="trace LVARS object flow from a vptr store")
    _add_db(vptr_write_trace)
    vptr_write_trace.add_argument("--write-id", required=True)
    vptr_write_trace.add_argument("--max-hops", type=int, default=6)
    vptr_write_trace.add_argument("--max-nodes", type=int, default=500)
    vptr_write_trace.add_argument("--max-edges", type=int, default=4000)
    vptr_write_trace.add_argument("--max-paths", "--max-callers", dest="max_paths", type=int, default=2000,
                                  help="maximum object-flow paths (the --max-callers spelling is deprecated)")
    vptr_write_trace.add_argument("--max-alternatives", type=int, default=4)
    return parser


def _query(db_path: Path, query: str, limit: int, write: bool = False) -> dict:
    if limit < 0:
        raise ValueError("limit must be non-negative")
    db_path = db_path.expanduser().resolve()
    if not db_path.is_file():
        raise FileNotFoundError(f"SQLite database does not exist: {db_path}")
    connection_uri = db_path.as_uri() if write else db_path.as_uri() + "?mode=ro"
    with closing(sqlite3.connect(connection_uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        if not write:
            connection.execute("PRAGMA query_only = ON")
        cursor = connection.execute(query)
        if cursor.description is None:
            if write:
                connection.commit()
            return {"columns": [], "rows": [], "count": 0, "truncated": False}
        columns = [item[0] for item in cursor.description]
        rows = cursor.fetchall() if limit == 0 else cursor.fetchmany(limit + 1)
        truncated = limit > 0 and len(rows) > limit
        if truncated:
            rows = rows[:limit]
        if write:
            connection.commit()
        values = [
            {column: value.hex() if isinstance(value, bytes) else value for column, value in zip(columns, row)}
            for row in rows
        ]
        return {"columns": columns, "rows": values, "count": len(values), "truncated": truncated}


def _job_revision_options(args: argparse.Namespace) -> dict:
    options = {
        "details": args.details, "title": args.title, "objective": args.objective, "status": args.status,
        "add_claims": args.add_claim, "update_claims": args.update_claim,
        "withdraw_claims": args.withdraw_claim, "add_evidence": args.add_evidence,
        "add_questions": args.add_question, "resolve_questions": args.resolve_question,
        "add_dependencies": args.depends_on, "remove_dependencies": args.remove_dependency,
        "operation_ids": args.ida_operation, "validations": args.validation,
        "restore_revision_id": args.restore_revision,
        "expected_revision_id": args.expected_revision, "handoff": args.handoff,
    }
    if args.patch_file is None:
        return options
    if any(value for value in options.values()):
        raise ValueError("--patch-file cannot be combined with other job change flags")
    try:
        patch = json.loads(args.patch_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"job patch file must contain valid JSON: {exc.msg}") from exc
    if not isinstance(patch, dict):
        raise ValueError("job patch file must contain a JSON object")
    unknown = set(patch) - set(options)
    if unknown:
        raise ValueError(f"unsupported job patch fields: {', '.join(sorted(unknown))}")
    for key, value in patch.items():
        if key in ("add_claims", "update_claims", "withdraw_claims", "add_evidence", "resolve_questions"):
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                raise ValueError(f"{key} must be a list of JSON objects")
            options[key] = [json.dumps(item, ensure_ascii=False) for item in value]
        elif key in ("add_questions", "operation_ids", "validations"):
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"{key} must be a list of strings")
            options[key] = value
        elif key in ("add_dependencies", "remove_dependencies"):
            if not isinstance(value, list) or not all(isinstance(item, int) and not isinstance(item, bool) for item in value):
                raise ValueError(f"{key} must be a list of integer job IDs")
            options[key] = value
        elif key == "restore_revision_id":
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError("restore_revision_id must be an integer")
            options[key] = value
        elif key == "expected_revision_id":
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError("expected_revision_id must be an integer")
            options[key] = value
        elif key == "handoff" and isinstance(value, dict):
            options[key] = json.dumps(value, ensure_ascii=False)
        elif value is not None and not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        else:
            options[key] = value
    return options


def _run(args: argparse.Namespace) -> dict:
    if args.command == "sql":
        return _query(args.db, args.query, args.limit, args.write)
    if args.command == "clear-searches":
        return _clear_searches(args.db)
    if args.command == "derived-call-import":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite analysis database does not exist: {args.db}")
        with closing(connect(args.db)) as connection:
            return import_derived_calls(
                connection, args.input, resolver=args.resolver, method=args.method,
                confidence=args.confidence, source_ref=args.source_ref, notes=args.notes,
            )
    if args.command.startswith("job-"):
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite analysis database does not exist: {args.db}")
        with closing(connect(args.db)) as connection:
            if args.command == "job-create":
                return create_job(connection, title=args.title, objective=args.objective,
                                  parent_job_id=args.parent, message=args.message)
            if args.command == "job-list":
                return list_jobs(connection, parent_job_id=args.parent, status=args.status, tree=args.tree)
            if args.command == "job-show":
                return show_job(connection, args.job)
            if args.command == "job-resume":
                return resume_job(connection, args.job, recent=args.recent)
            if args.command == "job-history":
                return job_history(connection, args.job, limit=args.limit, include_state=args.include_state,
                                   revision_id=args.revision)
            if args.command == "job-revise":
                return revise_job(connection, args.job, message=args.message, **_job_revision_options(args))
            if args.command == "job-diff":
                return diff_job(connection, args.job, from_revision=args.from_revision, to_revision=args.to_revision)
            if args.command == "job-search":
                return find_jobs(connection, query=args.query, job_id=args.job, kind=args.kind,
                                 include_history=args.history, limit=args.limit)
            if args.command == "job-impact":
                state = show_job(connection, args.job)
                claim_ids = args.claim or [claim["id"] for claim in state["claims"] if claim["status"] in ("active", "review_required")]
                return impact(connection, args.job, claim_ids)
            if args.command == "job-check":
                return check_jobs(connection, apply=args.apply)
        raise ValueError(f"unknown job command: {args.command}")
    if args.command == "type-scan":
        if args.limit < 0:
            raise ValueError("type-scan limit must be non-negative")
        try:
            spec = json.loads(args.spec.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FileNotFoundError(f"type scan specification cannot be read: {args.spec}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"type scan specification must be valid JSON: {exc.msg}") from exc
        normalize_spec(spec)
        if args.timeout < 0:
            raise ValueError("timeout must be non-negative")
        if args.min_score is not None and not 0 <= args.min_score <= 1:
            raise ValueError("min_score must be between 0 and 1")
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite database does not exist: {args.db}")
        with closing(connect(args.db)) as connection:
            addresses = select_function_addresses(
                connection, all_functions=args.all_functions, address=args.address,
                address_range=args.address_range, name=args.name,
            )
        refresh = None
        if not args.no_refresh:
            refresh = run_ida("export_view", args.db, view="microcode", addresses=addresses,
                              idat=args.idat, timeout=args.timeout)
        with closing(connect(args.db)) as connection:
            result = scan_type_features(connection, spec, function_eas=addresses,
                                        limit=args.limit, min_score=args.min_score)
        result["refresh"] = refresh
        result["scope"] = {"function_count": len(addresses),
                           "function_addresses": [f"0x{address:X}" for address in addresses],
                           "refreshed": not args.no_refresh}
        return result
    if args.command == "type-propagate":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite database does not exist: {args.db}")
        if args.propagation_action in {"seed", "link"}:
            if args.timeout < 0:
                raise ValueError("timeout must be non-negative")
            try:
                spec = json.loads(args.spec.read_text(encoding="utf-8"))
            except OSError as exc:
                raise FileNotFoundError(f"propagation specification cannot be read: {args.spec}") from exc
            except json.JSONDecodeError as exc:
                raise ValueError(f"propagation specification must be valid JSON: {exc.msg}") from exc
            refresh = None
            if args.propagation_action == "seed" and not args.no_refresh:
                with closing(connect(args.db)) as connection:
                    addresses = select_function_addresses(connection, all_functions=True)
                refresh = run_ida("export_view", args.db, view="micro_flow", addresses=addresses,
                                  idat=args.idat, timeout=args.timeout)
            with closing(connect(args.db)) as connection:
                result = (add_propagation_seed(connection, spec) if args.propagation_action == "seed"
                          else add_propagation_edge(connection, spec))
            if refresh is not None:
                result["refresh"] = refresh
            return result
        if args.propagation_action == "preview":
            if min(args.max_hops, args.max_nodes, args.max_edges, args.max_alternatives) < 1:
                raise ValueError("propagation budgets must be positive")
            with closing(connect(args.db)) as connection:
                return preview_seed(connection, args.seed_id, families=args.family, max_hops=args.max_hops,
                                    max_nodes=args.max_nodes, max_edges=args.max_edges,
                                    max_alternatives=args.max_alternatives)
        if args.propagation_action == "accept":
            with closing(connect(args.db)) as connection:
                return accept_propagation(connection, args.run_id, args.proposal, job_id=args.job)
        if args.propagation_action == "node":
            with closing(connect(args.db)) as connection:
                return show_propagation_node(connection, args.node)
    if args.command == "vtable-build":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite analysis database does not exist: {args.db}")
        if args.max_bytes < 1 or args.min_function_slots < 2 or args.max_slots < args.min_function_slots:
            raise ValueError("invalid vtable scan limits")
        address_range = parse_range(args.address_range) if args.address_range else (None, None)
        if args.no_refresh:
            with closing(connect(args.db)) as connection:
                return build_vtable_index(connection, abi=args.abi, start=address_range[0], end=address_range[1],
                                          min_function_slots=args.min_function_slots, max_slots=args.max_slots)
        return run_ida("vtable_build", args.db, abi=args.abi, start=address_range[0], end=address_range[1],
                       min_function_slots=args.min_function_slots, max_slots=args.max_slots,
                       max_bytes=args.max_bytes, **{"idat": args.idat, "timeout": args.timeout})
    if args.command == "vtable-list":
        with closing(connect(args.db)) as connection:
            return list_vtables(connection, abi=args.abi, status=args.status, limit=args.limit,
                                offset=args.offset, include_stale=args.include_stale)
    if args.command == "vtable-show":
        with closing(connect(args.db)) as connection:
            return show_vtable(connection, candidate_id=args.candidate_id,
                               address=parse_int(args.address) if args.address is not None else None,
                               include_stale=args.include_stale)
    if args.command == "vtable-search":
        targets = [parse_int(value) for value in args.target]
        with closing(connect(args.db)) as connection:
            return search_vtables(connection, target_eas=targets, slot_index=args.slot_index,
                                  abi=args.abi, limit=args.limit, include_stale=args.include_stale)
    if args.command == "vtable-class-relations":
        with closing(connect(args.db)) as connection:
            return class_relationships(connection,
                derived_typeinfo_ea=parse_int(args.derived_typeinfo) if args.derived_typeinfo is not None else None,
                limit=args.limit, offset=args.offset)
    if args.command == "vtable-type-preview":
        try:
            spec = json.loads(args.spec.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FileNotFoundError(f"type preview specification cannot be read: {args.spec}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"type preview specification must be valid JSON: {exc.msg}") from exc
        with closing(connect(args.db)) as connection:
            return preview_vtable_type_plan(connection, spec)
    if args.command == "vtable-type-apply":
        try:
            spec = json.loads(args.spec.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FileNotFoundError(f"type application specification cannot be read: {args.spec}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"type application specification must be valid JSON: {exc.msg}") from exc
        with closing(connect(args.db)) as connection:
            preview = preview_vtable_type_plan(connection, spec)
        if args.preview_id != preview["preview_id"]:
            raise ValueError("preview ID does not match the current vtable type plan")
        if args.revision_token != preview["revision_token"]:
            raise ValueError("revision token is stale; create a fresh type preview")
        return run_ida("mutate", args.db, mutation="apply_vtable_type_plan",
            values={"preview": preview, "expected_revision": args.revision_token},
            idat=args.idat, timeout=args.timeout)
    if args.command == "vcall-build":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite analysis database does not exist: {args.db}")
        if args.max_calls < 1:
            raise ValueError("max_calls must be positive")
        with closing(connect(args.db)) as connection:
            addresses = select_function_addresses(connection, all_functions=args.all_functions,
                address=args.address, address_range=args.address_range, name=args.name)
        refresh = None
        if not args.no_refresh:
            refresh = run_ida("export_view", args.db, view="microcode", addresses=addresses,
                              idat=args.idat, timeout=args.timeout)
        with closing(connect(args.db)) as connection:
            vptr_writes = build_vptr_write_index(connection, function_eas=addresses)
            result = build_vcall_index(connection, function_eas=addresses, max_calls=args.max_calls)
        result["vptr_write_index"] = vptr_writes
        result["refresh"] = refresh
        result["scope"] = {"function_count": len(addresses),
                            "function_addresses": [f"0x{address:X}" for address in addresses],
                            "refreshed": not args.no_refresh}
        return result
    if args.command == "vcall-analyze":
        with closing(connect(args.db)) as connection:
            return analyze_vcall(connection, call_id=args.call_id,
                                 address=parse_int(args.address) if args.address is not None else None)
    if args.command == "vcall-trace":
        with closing(connect(args.db)) as connection:
            return trace_virtual_call(connection, call_id=args.call_id,
                address=parse_int(args.address) if args.address is not None else None,
                max_hops=args.max_hops, max_nodes=args.max_nodes, max_edges=args.max_edges,
                max_alternatives=args.max_alternatives, max_context=args.max_context)
    if args.command == "vcall-trace-show":
        with closing(connect(args.db)) as connection:
            return show_trace(connection, args.run_id, include_stale=args.include_stale)
    if args.command == "vcall-show":
        with closing(connect(args.db)) as connection:
            return show_vcall(connection, call_id=args.call_id,
                              address=parse_int(args.address) if args.address is not None else None,
                              include_stale=args.include_stale)
    if args.command == "vptr-write-build":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite analysis database does not exist: {args.db}")
        if args.max_writes < 1:
            raise ValueError("max_writes must be positive")
        with closing(connect(args.db)) as connection:
            addresses = select_function_addresses(connection, all_functions=args.all_functions,
                address=args.address, address_range=args.address_range, name=args.name)
        refresh = None
        if not args.no_refresh:
            refresh = run_ida("export_view", args.db, view=args.view, addresses=addresses,
                              idat=args.idat, timeout=args.timeout)
        with closing(connect(args.db)) as connection:
            result = build_vptr_write_index(connection, function_eas=addresses, max_writes=args.max_writes,
                                            view_name=args.view)
        result["refresh"] = refresh
        result["scope"] = {"function_count": len(addresses),
            "function_addresses": [f"0x{address:X}" for address in addresses],
            "refreshed": not args.no_refresh}
        return result
    if args.command == "vptr-write-trace":
        if min(args.max_hops, args.max_nodes, args.max_edges, args.max_paths, args.max_alternatives) < 1:
            raise ValueError("trace budgets must be positive")
        with closing(connect(args.db)) as connection:
            return trace_vptr_object_flows(connection, write_id=args.write_id,
                max_hops=args.max_hops, max_nodes=args.max_nodes, max_edges=args.max_edges,
                max_paths=args.max_paths, max_alternatives=args.max_alternatives)
    if args.command == "vptr-write-list":
        with closing(connect(args.db)) as connection:
            function_ea = None
            if args.function is not None:
                selected = select_function_addresses(connection, address=args.function)
                if not selected:
                    raise ValueError(f"no function contains {args.function}")
                function_ea = selected[0]
            return list_vptr_writes(connection,
                function_ea=function_ea,
                address_point=parse_int(args.address_point) if args.address_point is not None else None,
                limit=args.limit, offset=args.offset, include_stale=args.include_stale)
    if args.command == "import-callers":
        from .discovery import import_callers
        with closing(connect(args.db)) as connection:
            return import_callers(connection,parse_int(args.address),max_hops=args.max_hops,max_nodes=args.max_nodes,max_edges=args.max_edges)
    if args.command == "vtable-match":
        from .vtable_match import normalize_signature, match_vtable_signature
        spec = normalize_signature(json.loads(args.spec.read_text(encoding="utf-8-sig")))
        start,end = parse_range(args.address_range) if args.address_range else (None,None)
        if args.limit < 1 or args.max_anchors < 1 or args.max_bytes < spec["pointer_size"]:
            raise ValueError("positive match and scan budgets required")
        refresh = None
        if not args.no_refresh:
            refresh = run_ida("pointer_scan",args.db,pointer_size=spec["pointer_size"],start=start,end=end,
                              max_bytes=args.max_bytes,idat=args.idat,timeout=args.timeout)
        with closing(connect(args.db)) as connection:
            result = match_vtable_signature(connection,spec,start=start,end=end,limit=args.limit,max_anchors=args.max_anchors)
        result["refresh"] = refresh
        return result
    if args.command == "call-audit":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite database does not exist: {args.db}")
        with closing(connect(args.db)) as connection:
            addresses = select_function_addresses(
                connection, all_functions=args.all_functions, address=args.address,
                addresses=args.addresses, address_range=args.address_range, name=args.name,
            )
            if args.max_functions and len(addresses) > args.max_functions:
                raise ValueError(
                    f"selection contains {len(addresses)} functions; exceeds "
                    f"--max-functions {args.max_functions}"
                )
            return audit_shared_calls(
                connection, addresses, min_fan_in=args.min_fan_in,
                max_results=args.max_results,
            )
    options = {"idat": args.idat, "timeout": args.timeout}
    if args.command == "discover":
        start,end = parse_range(args.address_range) if args.address_range else (None,None)
        return run_ida("discover",args.db,kind=args.kind,start=start,end=end,max_items=args.max_items,max_bytes=args.max_bytes,**options)
    if args.command == "disasm-range":
        start, end = parse_range([args.start, args.end])
        if args.max_items < 1:
            raise ValueError("max_items must be positive")
        if args.max_bytes < 1 or end - start > args.max_bytes:
            raise ValueError(
                f"requested range has {end - start} bytes; exceeds --max-bytes {args.max_bytes}"
            )
        return run_ida(
            "disasm_range", args.db, start=start, end=end,
            max_items=args.max_items, **options,
        )
    if args.command == "attach-idb":
        return attach_idb(args.db, args.source, destination=args.idb, reuse=args.reuse_idb, **options)
    if args.command == "sync":
        result = run_ida("sync", args.db, all_views=args.all_views,
                         address=parse_int(args.address) if args.address is not None else None, **options)
        _cache_file(args.db).unlink(missing_ok=True)
        return result
    if args.command == "init":
        db_path = args.db.expanduser().resolve()
        idb_path = (args.idb or db_path.with_suffix(".i64")).expanduser().resolve()
        if idb_path == args.binary.expanduser().resolve():
            raise ValueError("output IDB must differ from input binary; use --idb")
        if idb_path == db_path:
            raise ValueError("output IDB must differ from SQLite database")
        result = run_ida("init", db_path, binary=args.binary, idb_path=str(idb_path), **options)
        return result
    if args.command == "export":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite database does not exist: {args.db}")
        selectors = dict(all_functions=args.all_functions, address=args.address,
                         addresses=args.addresses, address_range=args.address_range, name=args.name)
        with closing(connect(args.db)) as connection:
            preview = selection_preview(
                connection, max_functions=args.max_functions,
                include_selected=True, **selectors,
            )
            addresses = preview.pop("_selected_addresses")
            if args.preview:
                return preview
            if preview["budget_exceeded"]:
                raise ValueError(f"selection contains {preview['function_count']} functions; exceeds --max-functions {args.max_functions}; inspect --preview")
        if args.view == "batch":
            views = list(dict.fromkeys("micro_flow" if v == "flow" else v for v in args.views))
            result = run_ida("export_batch", args.db, views=views, addresses=addresses, **options)
        else:
            view = "micro_flow" if args.view == "flow" else args.view
            result = run_ida("export_view", args.db, view=view, addresses=addresses, **options)
        result["selection"] = preview
        return result
    if args.command == "info":
        location = {"address": parse_int(args.address)} if args.address is not None else {"file_offset": parse_int(args.file_offset)}
        return run_ida("info", args.db, **location, **options)
    if args.command == "read":
        if args.size < 1 or args.size > (1 << 20):
            raise ValueError("read size must be between 1 and 1048576 bytes")
        if args.max_inline_bytes < 0:
            raise ValueError("max inline bytes must be non-negative")
        output_path = args.output.expanduser().resolve() if args.output is not None else None
        if output_path is not None:
            protected = {args.db.expanduser().resolve()}
            with closing(connect(args.db)) as connection:
                idb_path = get_metadata(connection, "idb_path")
            if idb_path:
                protected.add(Path(idb_path).expanduser().resolve())
            if output_path in protected:
                raise ValueError("read output file must not overwrite the SQLite database or IDB")
        return run_ida(
            "read", args.db, address=parse_int(args.address), size=args.size,
            output_format=args.output_format, max_inline_bytes=args.max_inline_bytes,
            output_path=str(output_path) if output_path is not None else None,
            **options,
        )
    if args.command == "write":
        raw = parse_hex_bytes(args.data)
        if len(raw) > (1 << 20):
            raise ValueError("write data must be at most 1048576 bytes")
        result = run_ida("write", args.db, address=parse_int(args.address), data_hex=raw.hex(), **options)
        return result
    if args.command == "search":
        if args.limit < 0:
            raise ValueError("limit must be non-negative")
        if args.mask and len(args.mask) != len(args.pattern):
            raise ValueError("provide one --mask per --pattern, or no masks")
        masks = args.mask or [None] * len(args.pattern)
        patterns = []
        for value, mask in zip(args.pattern, masks):
            parse_pattern(value, mask)
            patterns.append({"pattern": value, "mask": mask})
        address_range = parse_range(args.address_range) if args.address_range else (None, None)
        search_options = {"patterns": patterns, "start": address_range[0], "end": address_range[1], "limit": args.limit}
        return _cached_search(args.db, "search", search_options, options)
    if args.command == "pointer-search":
        if args.limit < 0:
            raise ValueError("limit must be non-negative")
        address_range = parse_range(args.address_range) if args.address_range else (None, None)
        search_options = {"target": parse_int(args.target) if args.target is not None else None,
                          "pointer_size": args.pointer_size, "start": address_range[0],
                          "end": address_range[1], "limit": args.limit}
        return _cached_search(args.db, "pointer_search", search_options, options)
    raise ValueError(f"unknown command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except (ValueError, OSError, RuntimeError, TimeoutError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

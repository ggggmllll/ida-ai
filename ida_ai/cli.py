"""Command line client for IDA analysis and SQLite artifacts."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from .db import connect
from .runner import run_ida
from .selection import parse_hex_bytes, parse_int, parse_pattern, parse_range, select_function_addresses


def _add_db(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, type=Path, help="SQLite analysis database")


def _add_ida(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--idat", help="path to IDA's idat64/idat executable")
    parser.add_argument("--timeout", type=int, default=0, help="IDA timeout in seconds; 0 means unlimited")


def _add_range(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--range", dest="address_range", nargs=2, metavar=("START", "END"), help="half-open address range")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ida-ai", description="Headless IDA export backed by SQLite")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="analyze a binary and index functions, xrefs, and CFG")
    _add_db(init)
    _add_ida(init)
    init.add_argument("--binary", required=True, type=Path)
    init.add_argument("--idb", type=Path, help="saved IDA database path; defaults to DB basename with .i64")

    export = commands.add_parser("export", help="export a function view into SQLite")
    views = export.add_subparsers(dest="view", required=True)
    for name in ("disassembly", "pseudocode"):
        view = views.add_parser(name, help=f"export {name} for selected functions")
        _add_db(view)
        _add_ida(view)
        selection = view.add_mutually_exclusive_group(required=True)
        selection.add_argument("--all", action="store_true", dest="all_functions")
        selection.add_argument("--address", help="address inside a function")
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

    sql = commands.add_parser("sql", help="run a read-only SQLite query without starting IDA")
    _add_db(sql)
    sql.add_argument("--query", required=True)
    sql.add_argument("--limit", type=int, default=1000, help="maximum rows; 0 means unlimited")
    sql.add_argument("--write", action="store_true", help="allow a mutating SQL statement and commit it")
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


def _run(args: argparse.Namespace) -> dict:
    if args.command == "sql":
        return _query(args.db, args.query, args.limit, args.write)
    if args.timeout < 0:
        raise ValueError("timeout must be non-negative")
    options = {"idat": args.idat, "timeout": args.timeout}
    if args.command == "init":
        db_path = args.db.expanduser().resolve()
        idb_path = (args.idb or db_path.with_suffix(".i64")).expanduser().resolve()
        if idb_path == args.binary.expanduser().resolve():
            raise ValueError("output IDB must differ from input binary; use --idb")
        if idb_path == db_path:
            raise ValueError("output IDB must differ from SQLite database")
        return run_ida("init", db_path, binary=args.binary, idb_path=str(idb_path), **options)
    if args.command == "export":
        if not args.db.is_file():
            raise FileNotFoundError(f"SQLite database does not exist: {args.db}")
        with closing(connect(args.db)) as connection:
            addresses = select_function_addresses(
                connection, all_functions=args.all_functions, address=args.address,
                address_range=args.address_range, name=args.name,
            )
        return run_ida("export_view", args.db, view=args.view, addresses=addresses, **options)
    if args.command == "info":
        location = {"address": parse_int(args.address)} if args.address is not None else {"file_offset": parse_int(args.file_offset)}
        return run_ida("info", args.db, **location, **options)
    if args.command == "read":
        if args.size < 1 or args.size > (1 << 20):
            raise ValueError("read size must be between 1 and 1048576 bytes")
        return run_ida("read", args.db, address=parse_int(args.address), size=args.size, **options)
    if args.command == "write":
        raw = parse_hex_bytes(args.data)
        if len(raw) > (1 << 20):
            raise ValueError("write data must be at most 1048576 bytes")
        return run_ida("write", args.db, address=parse_int(args.address), data_hex=raw.hex(), **options)
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
        return run_ida("search", args.db, patterns=patterns, start=address_range[0], end=address_range[1], limit=args.limit, **options)
    if args.command == "pointer-search":
        if args.limit < 0:
            raise ValueError("limit must be non-negative")
        address_range = parse_range(args.address_range) if args.address_range else (None, None)
        return run_ida(
            "pointer_search", args.db, target=parse_int(args.target) if args.target is not None else None,
            pointer_size=args.pointer_size, start=address_range[0], end=address_range[1], limit=args.limit,
            **options,
        )
    raise ValueError(f"unknown command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except (ValueError, FileNotFoundError, RuntimeError, TimeoutError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

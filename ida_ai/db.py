"""SQLite storage for IDA analysis artifacts.

The database is the interchange format between the headless IDA exporter and
the command line client.  IDA is responsible for producing observations;
ordinary Python and AI clients can inspect them without loading IDA.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 6


def sqlite_ea(address: int) -> int:
    """Store an unsigned IDA ea_t losslessly in SQLite's signed INTEGER type."""

    value = int(address)
    if not 0 <= value < (1 << 64):
        raise ValueError(f"address is outside unsigned 64-bit range: {value}")
    return value if value < (1 << 63) else value - (1 << 64)


def ida_ea(stored: int) -> int:
    """Recover an unsigned IDA ea_t from a SQLite address column."""

    value = int(stored)
    return value if value >= 0 else value + (1 << 64)


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS symbols (
    address INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT
);
CREATE TABLE IF NOT EXISTS comments (
    address INTEGER NOT NULL,
    function_ea INTEGER,
    kind TEXT NOT NULL CHECK(kind IN ('assembly','pseudocode')),
    repeatable INTEGER NOT NULL DEFAULT 0,
    item_preciser INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(address,kind,repeatable,item_preciser)
);
CREATE INDEX IF NOT EXISTS idx_comments_function ON comments(function_ea,kind);
CREATE TABLE IF NOT EXISTS type_definitions (
    name TEXT PRIMARY KEY,
    declaration TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS type_assignments (
    address INTEGER PRIMARY KEY,
    declaration TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS segments (
    start_ea INTEGER PRIMARY KEY,
    end_ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    class_name TEXT,
    permissions INTEGER,
    permissions_text TEXT NOT NULL DEFAULT '',
    bitness INTEGER,
    selector INTEGER,
    flags INTEGER
);
CREATE INDEX IF NOT EXISTS idx_segments_end ON segments(end_ea);

CREATE TABLE IF NOT EXISTS functions (
    start_ea INTEGER PRIMARY KEY,
    end_ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    demangled_name TEXT,
    signature TEXT,
    flags INTEGER,
    size INTEGER NOT NULL,
    segment_name TEXT,
    is_library INTEGER NOT NULL DEFAULT 0,
    is_thunk INTEGER NOT NULL DEFAULT 0,
    thunk_target_ea INTEGER,
    is_nullstub INTEGER NOT NULL DEFAULT 0,
    comment TEXT,
    repeatable_comment TEXT
);
CREATE INDEX IF NOT EXISTS idx_functions_end ON functions(end_ea);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_functions_demangled ON functions(demangled_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS xrefs (
    source_ea INTEGER NOT NULL,
    target_ea INTEGER NOT NULL,
    xref_type INTEGER NOT NULL,
    is_code INTEGER NOT NULL DEFAULT 0,
    is_data INTEGER NOT NULL DEFAULT 0,
    source_function_ea INTEGER,
    target_function_ea INTEGER,
    type_name TEXT,
    PRIMARY KEY (source_ea, target_ea, xref_type)
);
CREATE INDEX IF NOT EXISTS idx_xrefs_target ON xrefs(target_ea);
CREATE INDEX IF NOT EXISTS idx_xrefs_source_function ON xrefs(source_function_ea);
CREATE INDEX IF NOT EXISTS idx_xrefs_target_function ON xrefs(target_function_ea);

CREATE TABLE IF NOT EXISTS basic_blocks (
    function_ea INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    start_ea INTEGER NOT NULL,
    end_ea INTEGER NOT NULL,
    PRIMARY KEY (function_ea, block_index)
);
CREATE INDEX IF NOT EXISTS idx_basic_blocks_range ON basic_blocks(start_ea, end_ea);

CREATE TABLE IF NOT EXISTS cfg_edges (
    function_ea INTEGER NOT NULL,
    edge_index INTEGER NOT NULL,
    source_block_ea INTEGER NOT NULL,
    target_block_ea INTEGER NOT NULL,
    PRIMARY KEY (function_ea, edge_index)
);
CREATE INDEX IF NOT EXISTS idx_cfg_edges_source ON cfg_edges(source_block_ea);
CREATE INDEX IF NOT EXISTS idx_cfg_edges_target ON cfg_edges(target_block_ea);

CREATE TABLE IF NOT EXISTS disassembly (
    function_ea INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    line_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ok',
    error TEXT,
    generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instructions (
    ea INTEGER PRIMARY KEY,
    function_ea INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    mnemonic TEXT,
    operands TEXT,
    bytes_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_instructions_function ON instructions(function_ea, offset);

CREATE TABLE IF NOT EXISTS pseudocode (
    function_ea INTEGER PRIMARY KEY,
    text TEXT,
    status TEXT NOT NULL,
    error TEXT,
    backend TEXT,
    generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS microcode (
    function_ea INTEGER PRIMARY KEY,
    maturity TEXT NOT NULL,
    backend TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    decompiler_version TEXT,
    instruction_count INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT,
    generated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS micro_instructions (
    function_ea INTEGER NOT NULL,
    block_serial INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    ea INTEGER,
    opcode TEXT NOT NULL,
    text TEXT NOT NULL,
    l_json TEXT NOT NULL,
    r_json TEXT NOT NULL,
    d_json TEXT NOT NULL,
    PRIMARY KEY(function_ea,block_serial,ordinal)
);
CREATE INDEX IF NOT EXISTS idx_micro_instructions_ea ON micro_instructions(ea);
CREATE INDEX IF NOT EXISTS idx_micro_instructions_opcode ON micro_instructions(opcode);

CREATE TABLE IF NOT EXISTS memory_bytes (
    address INTEGER PRIMARY KEY,
    value INTEGER NOT NULL CHECK(value >= 0 AND value <= 255),
    flags INTEGER,
    segment_name TEXT,
    permissions_text TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_value ON memory_bytes(value);

CREATE TABLE IF NOT EXISTS pointers (
    source_address INTEGER NOT NULL,
    target_address INTEGER NOT NULL,
    pointer_size INTEGER NOT NULL,
    source_segment TEXT,
    target_name TEXT,
    target_type TEXT,
    source_function_ea INTEGER,
    target_function_ea INTEGER,
    source_kind TEXT,
    PRIMARY KEY(source_address, target_address, pointer_size)
);
CREATE INDEX IF NOT EXISTS idx_pointers_target ON pointers(target_address);
CREATE INDEX IF NOT EXISTS idx_pointers_source_function ON pointers(source_function_ea);

CREATE TABLE IF NOT EXISTS search_matches (
    search_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    address INTEGER NOT NULL,
    pattern_index INTEGER,
    match_kind TEXT NOT NULL,
    PRIMARY KEY(search_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_search_matches_address ON search_matches(address);

CREATE TABLE IF NOT EXISTS operations (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_operations_created ON operations(created_at);

-- Job state is a compact head pointer; job_revisions stores immutable snapshots.
CREATE TABLE IF NOT EXISTS jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_job_id INTEGER REFERENCES jobs(job_id),
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('planned','active','blocked','done','stale','needs_review')),
    head_revision_id INTEGER REFERENCES job_revisions(revision_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_parent ON jobs(parent_job_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

CREATE TABLE IF NOT EXISTS job_revisions (
    revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(job_id),
    revision_no INTEGER NOT NULL,
    parent_revision_id INTEGER REFERENCES job_revisions(revision_id),
    message TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    changes_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    analysis_snapshot_json TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    restored_from_revision INTEGER REFERENCES job_revisions(revision_id),
    created_at TEXT NOT NULL,
    UNIQUE(job_id,revision_no)
);
CREATE INDEX IF NOT EXISTS idx_job_revisions_job ON job_revisions(job_id,revision_no DESC);
CREATE TRIGGER IF NOT EXISTS job_revisions_no_update BEFORE UPDATE ON job_revisions
BEGIN SELECT RAISE(ABORT, 'job revisions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS job_revisions_no_delete BEFORE DELETE ON job_revisions
BEGIN SELECT RAISE(ABORT, 'job revisions are immutable'); END;
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a database with dictionary-like rows and the project schema."""

    db_path = Path(path)
    if db_path.parent:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path), timeout=60)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 60000")
    connection.execute("PRAGMA foreign_keys = ON")
    initialize(connection)
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    xref_columns = {row[1] for row in connection.execute("PRAGMA table_info(xrefs)")}
    if "type_name" not in xref_columns:
        connection.execute("ALTER TABLE xrefs ADD COLUMN type_name TEXT")
    function_columns = {row[1] for row in connection.execute("PRAGMA table_info(functions)")}
    if "thunk_target_ea" not in function_columns:
        connection.execute("ALTER TABLE functions ADD COLUMN thunk_target_ea INTEGER")
    if "is_nullstub" not in function_columns:
        connection.execute("ALTER TABLE functions ADD COLUMN is_nullstub INTEGER NOT NULL DEFAULT 0")
    connection.execute(
        "INSERT INTO schema_info(key, value) VALUES('version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),),
    )
    connection.commit()


def reset_analysis(connection: sqlite3.Connection, *, clear_operations: bool = False) -> None:
    """Remove observations that are regenerated by an init export."""

    tables = (
        "symbols",
        "comments",
        "segments",
        "functions",
        "xrefs",
        "basic_blocks",
        "cfg_edges",
        "disassembly",
        "instructions",
        "pseudocode",
        "microcode",
        "micro_instructions",
        "memory_bytes",
        "pointers",
        "search_matches",
    )
    for table in tables:
        connection.execute(f"DELETE FROM {table}")
    connection.execute("DELETE FROM metadata")
    if clear_operations:
        connection.execute("DELETE FROM operations")


def set_metadata(connection: sqlite3.Connection, values: Mapping[str, Any]) -> None:
    connection.executemany(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        ((str(key), json.dumps(value, ensure_ascii=False)) for key, value in values.items()),
    )


def get_metadata(connection: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except (TypeError, json.JSONDecodeError):
        return row["value"]


def record_operation(
    connection: sqlite3.Connection,
    request_id: str,
    action: str,
    status: str,
    result: Any = None,
    error: str | None = None,
    *,
    started_at: str | None = None,
) -> None:
    """Persist a structured result so the parent CLI need not parse IDA logs."""

    now = utc_now()
    connection.execute(
        "INSERT INTO operations(request_id, action, status, result_json, error, created_at, finished_at) "
        "VALUES(?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(request_id) DO UPDATE SET action=excluded.action, status=excluded.status, "
        "result_json=excluded.result_json, error=excluded.error, finished_at=excluded.finished_at",
        (
            request_id,
            action,
            status,
            json.dumps(result, ensure_ascii=False) if result is not None else None,
            error,
            started_at or now,
            now,
        ),
    )
    connection.commit()


def operation(connection: sqlite3.Connection, request_id: str) -> dict[str, Any] | None:
    row = connection.execute("SELECT * FROM operations WHERE request_id = ?", (request_id,)).fetchone()
    if row is None:
        return None
    result: dict[str, Any] = dict(row)
    if result.get("result_json"):
        try:
            result["result"] = json.loads(result["result_json"])
        except json.JSONDecodeError:
            result["result"] = result["result_json"]
    else:
        result["result"] = None
    result.pop("result_json", None)
    return result


def bulk_insert(
    connection: sqlite3.Connection,
    sql: str,
    rows: Iterable[Iterable[Any]],
) -> None:
    connection.executemany(sql, rows)


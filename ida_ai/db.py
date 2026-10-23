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


SCHEMA_VERSION = 18


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

-- Results produced by an explicit resolver live separately from native IDA
-- xrefs. They are queryable navigation evidence, not claims that IDA recorded
-- the edge in its analysis database.
CREATE TABLE IF NOT EXISTS derived_call_runs (
    run_id TEXT PRIMARY KEY,
    input_sha256 TEXT NOT NULL,
    resolver TEXT NOT NULL,
    method TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    input_path TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS derived_calls (
    resolver TEXT NOT NULL,
    call_ea INTEGER NOT NULL,
    function_ea INTEGER NOT NULL,
    mnemonic TEXT NOT NULL,
    target_ea INTEGER NOT NULL,
    target_name TEXT,
    confidence REAL CHECK(confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    method TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES derived_call_runs(run_id),
    notes TEXT,
    stale INTEGER NOT NULL DEFAULT 0,
    stale_reason TEXT,
    generated_at TEXT NOT NULL,
    PRIMARY KEY (resolver, call_ea)
);
CREATE INDEX IF NOT EXISTS idx_derived_calls_function ON derived_calls(function_ea);
CREATE INDEX IF NOT EXISTS idx_derived_calls_target ON derived_calls(target_ea);

CREATE TABLE IF NOT EXISTS basic_blocks (
    function_ea INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    start_ea INTEGER NOT NULL,
    end_ea INTEGER NOT NULL,
    PRIMARY KEY (function_ea, block_index)
);
CREATE INDEX IF NOT EXISTS idx_basic_blocks_range ON basic_blocks(start_ea, end_ea);

CREATE TABLE IF NOT EXISTS function_chunks (
    function_ea INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    start_ea INTEGER NOT NULL,
    end_ea INTEGER NOT NULL,
    owner_ea INTEGER,
    is_tail INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (function_ea, chunk_index)
);
CREATE INDEX IF NOT EXISTS idx_function_chunks_range ON function_chunks(start_ea, end_ea);
CREATE INDEX IF NOT EXISTS idx_function_chunks_owner ON function_chunks(owner_ea);

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
    generated_at TEXT NOT NULL,
    relations_json TEXT NOT NULL DEFAULT '{}'
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
CREATE TABLE IF NOT EXISTS micro_blocks (
    view_name TEXT NOT NULL CHECK(view_name IN ('microcode','micro_flow')),
    function_ea INTEGER NOT NULL,
    block_serial INTEGER NOT NULL,
    predecessors_json TEXT NOT NULL,
    successors_json TEXT NOT NULL,
    instruction_count INTEGER NOT NULL,
    PRIMARY KEY(view_name,function_ea,block_serial)
);
CREATE INDEX IF NOT EXISTS idx_micro_blocks_function ON micro_blocks(function_ea,view_name,block_serial);
CREATE TABLE IF NOT EXISTS micro_value_refs (
    view_name TEXT NOT NULL CHECK(view_name IN ('microcode','micro_flow')),
    function_ea INTEGER NOT NULL,
    value_number INTEGER NOT NULL,
    reference_kind TEXT NOT NULL CHECK(reference_kind IN ('definition','use')),
    block_serial INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    ea INTEGER,
    operand_path TEXT NOT NULL,
    PRIMARY KEY(view_name,function_ea,value_number,reference_kind,block_serial,ordinal,operand_path)
);
CREATE INDEX IF NOT EXISTS idx_micro_value_refs_number ON micro_value_refs(view_name,value_number,function_ea);
CREATE INDEX IF NOT EXISTS idx_micro_value_refs_location ON micro_value_refs(view_name,function_ea,block_serial,ordinal);

CREATE TABLE IF NOT EXISTS micro_flow (
    function_ea INTEGER PRIMARY KEY,
    maturity TEXT NOT NULL,
    backend TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    decompiler_version TEXT,
    instruction_count INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT,
    generated_at TEXT NOT NULL,
    arguments_json TEXT NOT NULL DEFAULT '[]',
    return_json TEXT NOT NULL DEFAULT '{}',
    locals_json TEXT NOT NULL DEFAULT '[]',
    relations_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS micro_flow_instructions (
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
CREATE INDEX IF NOT EXISTS idx_micro_flow_opcode ON micro_flow_instructions(opcode);

CREATE TABLE IF NOT EXISTS propagation_runs (
    run_id TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    request_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_propagation_runs_created ON propagation_runs(created_at);

CREATE TABLE IF NOT EXISTS propagation_nodes (
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    identity_json TEXT NOT NULL,
    source_snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(node_id,source_snapshot_hash)
);
CREATE TRIGGER IF NOT EXISTS propagation_nodes_no_update BEFORE UPDATE ON propagation_nodes
BEGIN SELECT RAISE(ABORT, 'propagation nodes are immutable'); END;
CREATE TRIGGER IF NOT EXISTS propagation_nodes_no_delete BEFORE DELETE ON propagation_nodes
BEGIN SELECT RAISE(ABORT, 'propagation nodes are immutable'); END;

CREATE TABLE IF NOT EXISTS propagation_edges (
    edge_id TEXT PRIMARY KEY,
    source_node TEXT NOT NULL,
    target_node TEXT NOT NULL,
    family TEXT NOT NULL CHECK(family IN ('reference','parameter','return')),
    direction TEXT NOT NULL CHECK(direction IN ('forward','reverse','both')),
    confidence TEXT NOT NULL CHECK(confidence IN ('observed','confirmed','hypothesis')),
    transform_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    context_json TEXT NOT NULL,
    source_snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_propagation_edges_source ON propagation_edges(source_node,family);
CREATE INDEX IF NOT EXISTS idx_propagation_edges_target ON propagation_edges(target_node,family);
CREATE TRIGGER IF NOT EXISTS propagation_edges_no_update BEFORE UPDATE ON propagation_edges
BEGIN SELECT RAISE(ABORT, 'propagation edges are immutable'); END;
CREATE TRIGGER IF NOT EXISTS propagation_edges_no_delete BEFORE DELETE ON propagation_edges
BEGIN SELECT RAISE(ABORT, 'propagation edges are immutable'); END;

CREATE TABLE IF NOT EXISTS propagation_constraints (
    constraint_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES propagation_runs(run_id),
    proposal_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    constraint_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    source_snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, proposal_id)
);
CREATE INDEX IF NOT EXISTS idx_propagation_constraints_node ON propagation_constraints(node_id);
CREATE TRIGGER IF NOT EXISTS propagation_constraints_no_update BEFORE UPDATE ON propagation_constraints
BEGIN SELECT RAISE(ABORT, 'accepted propagation constraints are immutable'); END;
CREATE TRIGGER IF NOT EXISTS propagation_constraints_no_delete BEFORE DELETE ON propagation_constraints
BEGIN SELECT RAISE(ABORT, 'accepted propagation constraints are immutable'); END;

-- Virtual-table and virtual-call observations are derived from a particular
-- IDB/analysis snapshot.  They are append-only by run; ``stale`` keeps old
-- evidence queryable after a later IDA refresh without presenting it as live.
CREATE TABLE IF NOT EXISTS vtable_runs (
    run_id TEXT PRIMARY KEY,
    source_snapshot_hash TEXT NOT NULL,
    abi TEXT NOT NULL,
    architecture TEXT,
    pointer_size INTEGER NOT NULL,
    byteorder TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vtable_runs_snapshot ON vtable_runs(source_snapshot_hash,created_at DESC);

CREATE TABLE IF NOT EXISTS vtable_candidates (
    candidate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES vtable_runs(run_id),
    table_address INTEGER NOT NULL,
    address_point INTEGER NOT NULL,
    table_end INTEGER,
    slot_count INTEGER NOT NULL DEFAULT 0,
    abi TEXT NOT NULL,
    architecture TEXT,
    pointer_size INTEGER NOT NULL,
    byteorder TEXT NOT NULL,
    discovery_source TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence REAL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vtable_candidates_address ON vtable_candidates(address_point,table_address);
CREATE INDEX IF NOT EXISTS idx_vtable_candidates_run ON vtable_candidates(run_id,stale);
CREATE INDEX IF NOT EXISTS idx_vtable_candidates_status ON vtable_candidates(status,stale);

CREATE TABLE IF NOT EXISTS vtable_slots (
    candidate_id TEXT NOT NULL REFERENCES vtable_candidates(candidate_id),
    slot_index INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    entry_address INTEGER NOT NULL,
    raw_value INTEGER,
    target_ea INTEGER,
    target_kind TEXT NOT NULL,
    target_name TEXT,
    entry_classification TEXT NOT NULL DEFAULT 'unknown',
    is_nullstub INTEGER NOT NULL DEFAULT 0,
    is_library INTEGER NOT NULL DEFAULT 0,
    is_thunk INTEGER NOT NULL DEFAULT 0,
    thunk_target_ea INTEGER,
    thunk_chain_json TEXT NOT NULL DEFAULT '[]',
    adjustment_json TEXT NOT NULL DEFAULT '{}',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(candidate_id,slot_index)
);
CREATE INDEX IF NOT EXISTS idx_vtable_slots_target ON vtable_slots(target_ea,stale);
CREATE INDEX IF NOT EXISTS idx_vtable_slots_offset ON vtable_slots(byte_offset,stale);

CREATE TABLE IF NOT EXISTS vtable_evidence (
    evidence_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    polarity TEXT NOT NULL CHECK(polarity IN ('support','against','unknown')),
    source_ea INTEGER,
    function_ea INTEGER,
    source_view TEXT,
    source_hash TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vtable_evidence_subject ON vtable_evidence(subject_kind,subject_id,stale);

-- Bounded Itanium RTTI object decoding is a separate, versioned observation.
-- Keeping it separate lets a vtable run state exactly which bytes were
-- available without treating an aligned-pointer scan as full memory coverage.
CREATE TABLE IF NOT EXISTS rtti_runs (
    rtti_run_id TEXT PRIMARY KEY,
    input_snapshot_hash TEXT NOT NULL,
    descriptor_snapshot_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rtti_runs_input ON rtti_runs(input_snapshot_hash,created_at DESC);

CREATE TABLE IF NOT EXISTS rtti_typeinfos (
    rtti_run_id TEXT NOT NULL REFERENCES rtti_runs(rtti_run_id),
    typeinfo_ea INTEGER NOT NULL,
    descriptor_kind TEXT,
    parse_status TEXT NOT NULL,
    type_name_ea INTEGER,
    type_name TEXT,
    flags INTEGER,
    base_count INTEGER,
    bases_json TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(rtti_run_id,typeinfo_ea)
);
CREATE INDEX IF NOT EXISTS idx_rtti_typeinfos_ea ON rtti_typeinfos(typeinfo_ea,rtti_run_id);

CREATE TABLE IF NOT EXISTS vtable_class_relation_runs (
    run_id TEXT PRIMARY KEY,
    source_snapshot_hash TEXT NOT NULL,
    rtti_run_id TEXT,
    scope_json TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vtable_class_relation_runs_snapshot
    ON vtable_class_relation_runs(source_snapshot_hash,created_at DESC);

CREATE TABLE IF NOT EXISTS vtable_class_relationships (
    relation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES vtable_class_relation_runs(run_id),
    derived_typeinfo_ea INTEGER NOT NULL,
    base_typeinfo_ea INTEGER NOT NULL,
    base_index INTEGER NOT NULL,
    status TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_vtable_class_relationships_typeinfos
    ON vtable_class_relationships(derived_typeinfo_ea,base_typeinfo_ea,stale);
CREATE INDEX IF NOT EXISTS idx_vtable_class_relationships_run
    ON vtable_class_relationships(run_id,stale);

CREATE TABLE IF NOT EXISTS vcall_runs (
    run_id TEXT PRIMARY KEY,
    source_snapshot_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vcall_runs_snapshot ON vcall_runs(source_snapshot_hash,created_at DESC);

CREATE TABLE IF NOT EXISTS vcall_sites (
    call_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES vcall_runs(run_id),
    call_ea INTEGER,
    function_ea INTEGER NOT NULL,
    block_serial INTEGER,
    ordinal INTEGER,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    opcode TEXT NOT NULL,
    receiver_json TEXT NOT NULL DEFAULT '{}',
    callee_json TEXT NOT NULL DEFAULT '{}',
    slot_offset INTEGER,
    pointer_size INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vcall_sites_ea ON vcall_sites(call_ea,stale);
CREATE INDEX IF NOT EXISTS idx_vcall_sites_function ON vcall_sites(function_ea,stale);
CREATE INDEX IF NOT EXISTS idx_vcall_sites_status ON vcall_sites(status,stale);

CREATE TABLE IF NOT EXISTS vcall_trace_runs (
    run_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL REFERENCES vcall_sites(call_id),
    source_snapshot_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vcall_trace_call ON vcall_trace_runs(call_id,created_at DESC);

CREATE TABLE IF NOT EXISTS vptr_write_runs (
    run_id TEXT PRIMARY KEY,
    source_snapshot_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vptr_write_runs_snapshot ON vptr_write_runs(source_snapshot_hash,created_at DESC);

CREATE TABLE IF NOT EXISTS vptr_writes (
    write_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES vptr_write_runs(run_id),
    function_ea INTEGER NOT NULL,
    write_ea INTEGER,
    block_serial INTEGER,
    ordinal INTEGER,
    object_json TEXT NOT NULL DEFAULT '{}',
    vptr_offset INTEGER,
    address_point INTEGER,
    candidate_id TEXT,
    status TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_vptr_writes_function ON vptr_writes(function_ea,block_serial,ordinal,stale);
CREATE INDEX IF NOT EXISTS idx_vptr_writes_address_point ON vptr_writes(address_point,stale);

CREATE TABLE IF NOT EXISTS vcall_targets (
    call_id TEXT NOT NULL REFERENCES vcall_sites(call_id),
    target_id TEXT NOT NULL,
    candidate_id TEXT,
    slot_index INTEGER,
    target_ea INTEGER,
    thunk_target_ea INTEGER,
    status TEXT NOT NULL,
    reason TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(call_id,target_id)
);
CREATE INDEX IF NOT EXISTS idx_vcall_targets_target ON vcall_targets(target_ea,stale);

CREATE TABLE IF NOT EXISTS receiver_flows (
    flow_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL REFERENCES vcall_sites(call_id),
    path_order INTEGER NOT NULL,
    node_json TEXT NOT NULL,
    edge_json TEXT NOT NULL,
    status TEXT NOT NULL,
    source_snapshot_hash TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receiver_flows_call ON receiver_flows(call_id,path_order,stale);

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

-- Exhaustive aligned pointer observations from loaded non-executable segments.
-- Kept separate from user-triggered pointer-search results and their cache.
CREATE TABLE IF NOT EXISTS data_fixups (
    source_ea INTEGER PRIMARY KEY,
    observation_json TEXT NOT NULL,
    generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS data_pointer_slots (
    source_ea INTEGER PRIMARY KEY,
    raw_value INTEGER NOT NULL,
    target_ea INTEGER,
    pointer_size INTEGER NOT NULL,
    source_segment TEXT NOT NULL,
    target_segment TEXT,
    target_function_ea INTEGER,
    target_name TEXT,
    target_kind TEXT NOT NULL,
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_data_pointer_raw ON data_pointer_slots(raw_value,pointer_size);
CREATE TABLE IF NOT EXISTS discovered_strings (
    address INTEGER PRIMARY KEY, string_type INTEGER NOT NULL, text TEXT NOT NULL,
    bytes_hex TEXT NOT NULL, generated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS discovered_imports (
    address INTEGER PRIMARY KEY, module TEXT, name TEXT, ordinal INTEGER,
    direct_xrefs INTEGER NOT NULL, quality TEXT NOT NULL, generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_data_pointer_target ON data_pointer_slots(target_ea);
CREATE INDEX IF NOT EXISTS idx_data_pointer_segment ON data_pointer_slots(source_segment,source_ea);

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
    derived_call_columns = {row[1] for row in connection.execute("PRAGMA table_info(derived_calls)")}
    if "stale" not in derived_call_columns:
        connection.execute("ALTER TABLE derived_calls ADD COLUMN stale INTEGER NOT NULL DEFAULT 0")
    if "stale_reason" not in derived_call_columns:
        connection.execute("ALTER TABLE derived_calls ADD COLUMN stale_reason TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_derived_calls_stale ON derived_calls(stale,function_ea)"
    )
    vtable_slot_columns = {row[1] for row in connection.execute("PRAGMA table_info(vtable_slots)")}
    vtable_slot_migration_needed = False
    if "entry_classification" not in vtable_slot_columns:
        connection.execute("ALTER TABLE vtable_slots ADD COLUMN entry_classification TEXT NOT NULL DEFAULT 'unknown'")
        vtable_slot_migration_needed = True
    if "is_nullstub" not in vtable_slot_columns:
        connection.execute("ALTER TABLE vtable_slots ADD COLUMN is_nullstub INTEGER NOT NULL DEFAULT 0")
        vtable_slot_migration_needed = True
    if "is_library" not in vtable_slot_columns:
        connection.execute("ALTER TABLE vtable_slots ADD COLUMN is_library INTEGER NOT NULL DEFAULT 0")
        vtable_slot_migration_needed = True
    if vtable_slot_migration_needed:
        connection.execute(
            "UPDATE vtable_slots SET "
            "is_nullstub=COALESCE((SELECT is_nullstub FROM functions WHERE functions.start_ea=vtable_slots.target_ea),0), "
            "is_library=COALESCE((SELECT is_library FROM functions WHERE functions.start_ea=vtable_slots.target_ea),0)"
        )
        connection.execute(
            "UPDATE vtable_slots SET entry_classification=CASE "
            "WHEN target_kind='null' THEN 'null_slot' "
            "WHEN lower(COALESCE(target_name,'')) LIKE '%__cxa_pure_virtual%' OR lower(COALESCE(target_name,'')) LIKE '%_purecall%' THEN 'pure_virtual_runtime_named' "
            "WHEN lower(COALESCE(target_name,'')) LIKE '%__cxa_deleted_virtual%' THEN 'deleted_virtual_runtime_named' "
            "WHEN target_kind='function' AND is_nullstub=1 THEN 'nullstub' "
            "WHEN target_kind='function' AND is_thunk=1 AND is_library=1 THEN 'library_thunk' "
            "WHEN target_kind='function' AND is_thunk=1 THEN 'thunk' "
            "WHEN target_kind='function' AND is_library=1 THEN 'library_function' "
            "WHEN target_kind='function' THEN 'function' "
            "WHEN target_kind='code' THEN 'unclassified_code' "
            "WHEN target_kind='data' THEN 'data_pointer' ELSE 'unknown' END"
        )
    for table in ("microcode", "micro_flow"):
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "relations_json" not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN relations_json TEXT NOT NULL DEFAULT '{{}}'")
    flow_columns = {row[1] for row in connection.execute("PRAGMA table_info(micro_flow)")}
    if "arguments_json" not in flow_columns:
        connection.execute("ALTER TABLE micro_flow ADD COLUMN arguments_json TEXT NOT NULL DEFAULT '[]'")
    if "return_json" not in flow_columns:
        connection.execute("ALTER TABLE micro_flow ADD COLUMN return_json TEXT NOT NULL DEFAULT '{}'")
    if "locals_json" not in flow_columns:
        connection.execute("ALTER TABLE micro_flow ADD COLUMN locals_json TEXT NOT NULL DEFAULT '[]'")
    connection.execute(
        "INSERT INTO schema_info(key, value) VALUES('version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),),
    )
    node_info = connection.execute("PRAGMA table_info(propagation_nodes)").fetchall()
    node_pk = [row[1] for row in sorted((row for row in node_info if row[5]), key=lambda row: row[5])]
    if node_pk == ["node_id"]:
        connection.execute("DROP TRIGGER IF EXISTS propagation_nodes_no_update")
        connection.execute("DROP TRIGGER IF EXISTS propagation_nodes_no_delete")
        connection.execute("DROP INDEX IF EXISTS idx_propagation_nodes_snapshot")
        connection.execute("ALTER TABLE propagation_nodes RENAME TO propagation_nodes_v1")
        connection.execute("""CREATE TABLE propagation_nodes (
            node_id TEXT NOT NULL,kind TEXT NOT NULL,identity_json TEXT NOT NULL,
            source_snapshot_hash TEXT NOT NULL,created_at TEXT NOT NULL,
            PRIMARY KEY(node_id,source_snapshot_hash))""")
        connection.execute("INSERT OR IGNORE INTO propagation_nodes SELECT * FROM propagation_nodes_v1")
        connection.execute("DROP TABLE propagation_nodes_v1")
        connection.executescript("""CREATE TRIGGER propagation_nodes_no_update BEFORE UPDATE ON propagation_nodes
            BEGIN SELECT RAISE(ABORT, 'propagation nodes are immutable'); END;
            CREATE TRIGGER propagation_nodes_no_delete BEFORE DELETE ON propagation_nodes
            BEGIN SELECT RAISE(ABORT, 'propagation nodes are immutable'); END;""")
    connection.commit()


def reset_analysis(connection: sqlite3.Connection, *, clear_operations: bool = False) -> None:
    """Remove observations that are regenerated by an init export."""

    # Virtual-table/call rows are derived from the observations below.  Keep
    # their immutable historical runs, but never leave them looking current
    # while functions, xrefs, or microcode are being rebuilt.
    connection.execute("UPDATE vcall_trace_runs SET status='stale'")
    for table in ("vtable_candidates", "vtable_slots", "vtable_evidence", "vcall_sites", "vcall_targets", "receiver_flows"):
        connection.execute(f"UPDATE {table} SET stale=1")
    connection.execute("UPDATE vtable_runs SET status='stale' WHERE status NOT IN ('stale','error')")
    connection.execute("UPDATE vcall_runs SET status='stale' WHERE status NOT IN ('stale','error')")
    connection.execute("UPDATE rtti_runs SET status='stale' WHERE status NOT IN ('stale','error')")
    connection.execute("UPDATE vtable_class_relation_runs SET status='stale' WHERE status NOT IN ('stale','error')")
    connection.execute("UPDATE vtable_class_relationships SET stale=1")
    connection.execute("UPDATE vptr_write_runs SET status='stale' WHERE status NOT IN ('stale','error')")
    connection.execute("UPDATE vptr_writes SET stale=1")

    tables = (
        "discovered_strings",
        "discovered_imports",
        "symbols",
        "comments",
        "segments",
        "functions",
        "xrefs",
        "derived_calls",
        "basic_blocks",
        "function_chunks",
        "cfg_edges",
        "disassembly",
        "instructions",
        "pseudocode",
        "microcode",
        "micro_instructions",
        "micro_blocks",
        "micro_value_refs",
        "micro_flow",
        "micro_flow_instructions",
        "memory_bytes",
        "pointers",
        "data_pointer_slots",
        "data_fixups",
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


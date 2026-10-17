"""Hierarchical research jobs with append-only, resumable SQLite revisions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from .db import get_metadata, sqlite_ea, utc_now
from .selection import parse_int


JOB_STATUSES = ("planned", "active", "blocked", "done", "stale", "needs_review")
CLAIM_KINDS = ("fact", "hypothesis", "decision", "reject")
EVIDENCE_KINDS = ("observation", "derived", "experiment", "artifact", "external", "analyst_note")
EVIDENCE_ORIGINS = ("raw", "ida_analysis", "ida_type_dependent", "external", "analyst")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _decode(value: str) -> Any:
    return json.loads(value)


def analysis_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    """Describe the analysis view without hashing the job database itself."""

    identity_keys = ("root_filename", "input_path", "imagebase", "bitness")
    identity = {key: get_metadata(connection, key) for key in identity_keys}
    counts: dict[str, int] = {}
    for table in (
        "functions", "xrefs", "basic_blocks", "cfg_edges", "symbols", "comments",
        "disassembly", "instructions", "pseudocode", "microcode", "micro_instructions",
        "micro_blocks", "micro_value_refs", "micro_flow", "micro_flow_instructions",
    ):
        counts[table] = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    view_epochs = {
        table: connection.execute(f"SELECT max(generated_at) FROM {table}").fetchone()[0]
        for table in ("disassembly", "pseudocode", "microcode", "micro_flow")
    }
    comment_epoch = connection.execute("SELECT max(updated_at) FROM comments").fetchone()[0]
    type_state = {
        "type_definitions": [tuple(row) for row in connection.execute(
            "SELECT name,declaration FROM type_definitions ORDER BY name")],
        "type_assignments": [tuple(row) for row in connection.execute(
            "SELECT address,declaration FROM type_assignments ORDER BY address")],
    }
    return {
        "identity": identity,
        "analysis_epoch": get_metadata(connection, "synchronized_at") or get_metadata(connection, "generated_at"),
        "view_epochs": view_epochs,
        "comment_epoch": comment_epoch,
        "type_state_hash": hashlib.sha256(_json(type_state).encode("utf-8")).hexdigest(),
        "counts": counts,
    }

def _artifact_fingerprint(connection: sqlite3.Connection, source_ref: str) -> str | None:
    """Content identity for explicitly addressed artifacts; timestamps are excluded."""
    table, separator, address = source_ref.partition(":")
    keys = {"pseudocode": "function_ea", "disassembly": "function_ea", "microcode": "function_ea",
            "micro_flow": "function_ea",
            "functions": "start_ea", "instructions": "ea"}
    if not separator or table not in keys:
        if separator and table in ("vtable", "vcall"):
            artifact_table = "vtable_candidates" if table == "vtable" else "vcall_sites"
            id_column = "candidate_id" if table == "vtable" else "call_id"
            row = connection.execute(f"SELECT * FROM {artifact_table} WHERE {id_column}=?", (address,)).fetchone()
            if row is None:
                return hashlib.sha256(b"missing").hexdigest()
            data = {key: row[key] for key in row.keys() if key not in ("created_at",)}
            if table == "vtable":
                data["slots"] = [tuple(slot) for slot in connection.execute(
                    "SELECT slot_index,byte_offset,entry_address,raw_value,target_ea,target_kind,target_name,is_thunk,thunk_target_ea,thunk_chain_json,adjustment_json,evidence_json,source_snapshot_hash,stale "
                    "FROM vtable_slots WHERE candidate_id=? ORDER BY slot_index", (address,))]
            else:
                data["targets"] = [tuple(target) for target in connection.execute(
                    "SELECT candidate_id,slot_index,target_ea,thunk_target_ea,status,reason,evidence_json,source_snapshot_hash,stale "
                    "FROM vcall_targets WHERE call_id=? ORDER BY target_id", (address,))]
                data["flows"] = [tuple(flow) for flow in connection.execute(
                    "SELECT path_order,node_json,edge_json,status,source_snapshot_hash,stale "
                    "FROM receiver_flows WHERE call_id=? ORDER BY path_order", (address,))]
            return hashlib.sha256(_json(data).encode("utf-8")).hexdigest()
        return None
    try:
        ea = sqlite_ea(parse_int(address))
    except (TypeError, ValueError):
        return None
    row = connection.execute(f"SELECT * FROM {table} WHERE {keys[table]}=?", (ea,)).fetchone()
    data = {key: row[key] for key in row.keys() if key != "generated_at"} if row is not None else None
    if row is not None and table in ("microcode", "micro_flow"):
        data["micro_blocks"] = [tuple(item) for item in connection.execute(
            "SELECT block_serial,predecessors_json,successors_json,instruction_count "
            "FROM micro_blocks WHERE view_name=? AND function_ea=? ORDER BY block_serial",
            (table, ea),)]
        data["micro_value_refs"] = [tuple(item) for item in connection.execute(
            "SELECT value_number,reference_kind,block_serial,ordinal,ea,operand_path "
            "FROM micro_value_refs WHERE view_name=? AND function_ea=? "
            "ORDER BY value_number,reference_kind,block_serial,ordinal,operand_path",
            (table, ea),)]
    return hashlib.sha256(_json(data).encode("utf-8")).hexdigest()


def _evidence_drift(connection: sqlite3.Connection, evidence: dict, current: dict) -> bool | None:
    """Return detected drift, stable source, or None when no source fingerprint exists."""
    if _identity_changed(evidence.get("analysis_snapshot"), current):
        return True
    old_snapshot = evidence.get("analysis_snapshot") or {}
    if evidence.get("origin") == "ida_type_dependent" and old_snapshot.get("type_state_hash") != current.get("type_state_hash"):
        return True
    saved = evidence.get("artifact_fingerprint")
    if saved is not None:
        return saved != _artifact_fingerprint(connection, evidence["source_ref"])
    if evidence.get("origin") in ("raw", "external", "analyst"):
        return None
    return evidence.get("analysis_snapshot") != current


def _evidence_changed(connection: sqlite3.Connection, evidence: dict, current: dict) -> bool:
    return _evidence_drift(connection, evidence, current) is True


def _identity_changed(old: dict[str, Any] | None, new: dict[str, Any]) -> bool:
    if not old:
        return False
    before = old.get("identity") or {}
    after = new.get("identity") or {}
    old_values = [before.get(key) for key in ("root_filename", "input_path", "imagebase", "bitness")]
    new_values = [after.get(key) for key in ("root_filename", "input_path", "imagebase", "bitness")]
    return any(value is not None for value in old_values) and any(value is not None for value in new_values) and old_values != new_values


def _job_row(connection: sqlite3.Connection, job_id: int) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    if row is None:
        raise ValueError(f"job {job_id} does not exist")
    return row


def _state(connection: sqlite3.Connection, job_id: int) -> dict[str, Any]:
    row = _job_row(connection, job_id)
    if row["head_revision_id"] is None:
        raise ValueError(f"job {job_id} has no revision")
    revision = connection.execute(
        "SELECT snapshot_json FROM job_revisions WHERE revision_id=?", (row["head_revision_id"],)
    ).fetchone()
    if revision is None:
        raise RuntimeError(f"job {job_id} has a missing head revision")
    return _decode(revision["snapshot_json"])


def _head(connection: sqlite3.Connection, job_id: int) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM job_revisions WHERE revision_id=(SELECT head_revision_id FROM jobs WHERE job_id=?)",
        (job_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"job {job_id} has no revision")
    return row


def _append_revision(
    connection: sqlite3.Connection,
    job_id: int,
    snapshot: dict[str, Any],
    *,
    message: str,
    details: str = "",
    changes: list[dict[str, Any]],
    current_analysis: dict[str, Any] | None = None,
    restored_from: int | None = None,
) -> dict[str, Any]:
    if not message.strip():
        raise ValueError("revision message must not be empty")
    job = _job_row(connection, job_id)
    parent_revision = job["head_revision_id"]
    if parent_revision is None:
        revision_no = 1
    else:
        revision_no = connection.execute(
            "SELECT revision_no+1 FROM job_revisions WHERE revision_id=?", (parent_revision,)
        ).fetchone()[0]
    analysis = current_analysis if current_analysis is not None else analysis_snapshot(connection)
    encoded = _json(snapshot)
    state_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    now = utc_now()
    cursor = connection.execute(
        """INSERT INTO job_revisions(
            job_id,revision_no,parent_revision_id,message,details,changes_json,snapshot_json,
            analysis_snapshot_json,state_hash,restored_from_revision,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (job_id, revision_no, parent_revision, message.strip(), details, _json(changes), encoded,
         _json(analysis), state_hash, restored_from, now),
    )
    revision_id = cursor.lastrowid
    connection.execute(
        "UPDATE jobs SET title=?,objective=?,status=?,head_revision_id=?,updated_at=? WHERE job_id=?",
        (snapshot["title"], snapshot["objective"], snapshot["status"], revision_id, now, job_id),
    )
    return {"revision_id": revision_id, "revision_no": revision_no, "state_hash": state_hash}


def create_job(
    connection: sqlite3.Connection,
    *,
    title: str,
    objective: str,
    parent_job_id: int | None = None,
    message: str = "Create research job",
) -> dict[str, Any]:
    title, objective = title.strip(), objective.strip()
    if not title or not objective:
        raise ValueError("title and objective must not be empty")
    if not message.strip():
        raise ValueError("revision message must not be empty")
    connection.execute("BEGIN IMMEDIATE")
    try:
        if parent_job_id is not None:
            _job_row(connection, parent_job_id)
        now = utc_now()
        cursor = connection.execute(
            "INSERT INTO jobs(parent_job_id,title,objective,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (parent_job_id, title, objective, "planned", now, now),
        )
        job_id = cursor.lastrowid
        snapshot = {"title": title, "objective": objective, "status": "planned", "claims": [],
                    "evidence": [], "questions": [], "depends_on": [], "handoff": None}
        analysis = analysis_snapshot(connection)
        revision = _append_revision(connection, job_id, snapshot, message=message, changes=[{"kind": "job_created"}], current_analysis=analysis)
        connection.commit()
        return {"job_id": job_id, "parent_job_id": parent_job_id, **revision, "status": "planned"}
    except Exception:
        connection.rollback()
        raise


def _load_spec(raw: str, description: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} must be valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a JSON object")
    return value


def _used_ids(connection: sqlite3.Connection, job_id: int, key: str) -> set[str]:
    return {item["id"] for row in connection.execute(
        "SELECT snapshot_json FROM job_revisions WHERE job_id=?", (job_id,)
    ) for item in _decode(row[0]).get(key, [])}


def _next_id(used: set[str], prefix: str) -> str:
    number = 1
    while f"{prefix}{number:04d}" in used:
        number += 1
    return f"{prefix}{number:04d}"


def _normalize_relies_on(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("relies_on must be a list of {job_id, claim_id} objects")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or "job_id" not in item or "claim_id" not in item:
            raise ValueError("each relies_on item must contain job_id and claim_id")
        try:
            reference = {"job_id": int(item["job_id"]), "claim_id": str(item["claim_id"]).strip()}
        except (TypeError, ValueError) as exc:
            raise ValueError("relies_on job_id must be an integer") from exc
        if reference["job_id"] < 1 or not reference["claim_id"]:
            raise ValueError("relies_on must identify an existing job and claim")
        key = (reference["job_id"], reference["claim_id"])
        if key not in seen:
            result.append(reference)
            seen.add(key)
    return result


def _find_claim(connection: sqlite3.Connection, job_id: int, claim_id: str) -> dict[str, Any] | None:
    try:
        state = _state(connection, job_id)
    except ValueError:
        return None
    return next((item for item in state["claims"] if item["id"] == claim_id), None)


def _validate_references(
    connection: sqlite3.Connection, job_id: int, state: dict[str, Any],
    *, new_claim_ids: set[str] | None = None,
) -> None:
    new_claim_ids = new_claim_ids or set()
    current_analysis = analysis_snapshot(connection)
    for claim in state["claims"]:
        if claim["status"] not in ("active", "review_required"):
            continue
        for evidence_id in claim.get("evidence_ids", []):
            evidence = next((item for item in state["evidence"] if item["id"] == evidence_id), None)
            if evidence is None:
                raise ValueError(f"claim {claim['id']} refers to missing evidence {evidence_id}")
            if claim["id"] in new_claim_ids and _evidence_changed(connection, evidence, current_analysis):
                raise ValueError(f"claim {claim['id']} cites changed evidence {evidence_id}; record fresh evidence")
        for reference in claim.get("relies_on", []):
            upstream_job = int(reference["job_id"])
            upstream_claim = _find_claim(connection, upstream_job, reference["claim_id"])
            if upstream_job == job_id:
                upstream_claim = next((item for item in state["claims"] if item["id"] == reference["claim_id"]), None)
            if upstream_claim is None or (claim["id"] in new_claim_ids and upstream_claim["status"] != "active"):
                raise ValueError(
                    f"claim {claim['id']} relies on unavailable claim "
                    f"{upstream_job}:{reference['claim_id']}"
                )

    # New or revalidated claims require active upstream claims. Existing
    # claims may be invalidated below by a simultaneous upstream change.
    states: dict[int, dict[str, Any]] = {}
    for row in connection.execute("SELECT job_id FROM jobs"):
        current_id = int(row["job_id"])
        states[current_id] = state if current_id == job_id else _state(connection, current_id)
    graph: dict[tuple[int, str], list[tuple[int, str]]] = {}
    for owner_id, owner_state in states.items():
        for claim in owner_state["claims"]:
            if claim["status"] not in ("active", "review_required"):
                continue
            node = (owner_id, claim["id"])
            graph[node] = [(int(ref["job_id"]), ref["claim_id"]) for ref in claim.get("relies_on", [])]
    visiting: set[tuple[int, str]] = set()
    visited: set[tuple[int, str]] = set()

    def visit(node: tuple[int, str]) -> None:
        if node in visiting:
            raise ValueError("claim dependencies cannot contain a cycle")
        if node in visited:
            return
        visiting.add(node)
        for upstream in graph.get(node, []):
            visit(upstream)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def _validate_job_dependencies(connection: sqlite3.Connection, job_id: int, candidate: list[int]) -> None:
    if len(set(candidate)) != len(candidate):
        raise ValueError("duplicate job dependency")
    if job_id in candidate:
        raise ValueError("a job cannot depend on itself")
    for depends_on in candidate:
        _job_row(connection, depends_on)
    graph: dict[int, list[int]] = {}
    for row in connection.execute("SELECT job_id FROM jobs"):
        other_id = int(row["job_id"])
        graph[other_id] = list(map(int, candidate if other_id == job_id else _state(connection, other_id)["depends_on"]))
    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(node: int) -> None:
        if node in visiting:
            raise ValueError("job dependencies cannot contain a cycle")
        if node in visited:
            return
        visiting.add(node)
        for upstream in graph.get(node, []):
            visit(upstream)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def _claim_semantics(claim: dict[str, Any] | None) -> Any:
    if claim is None:
        return None
    return {key: claim.get(key) for key in ("kind", "basis", "text", "summary", "rationale", "status", "evidence_ids", "relies_on", "supersedes")}


def _changed_claims(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    old = {claim["id"]: claim for claim in before["claims"]}
    new = {claim["id"]: claim for claim in after["claims"]}
    return [claim_id for claim_id in sorted(old.keys() | new.keys()) if _claim_semantics(old.get(claim_id)) != _claim_semantics(new.get(claim_id))]


def _invalidate_dependents(
    connection: sqlite3.Connection,
    initial: list[tuple[int, str]],
    *,
    current_analysis: dict[str, Any],
) -> list[int]:
    queue = list(initial)
    seen_sources: set[tuple[int, str]] = set()
    affected: list[int] = []
    while queue:
        batch = []
        for node in queue:
            if node not in seen_sources:
                seen_sources.add(node)
                batch.append(node)
        queue = []
        if not batch:
            continue
        states = {
            int(row["job_id"]): _state(connection, int(row["job_id"]))
            for row in connection.execute("SELECT job_id FROM jobs")
        }
        changed_by_job: dict[int, list[str]] = {}
        reasons_by_job: dict[int, set[str]] = {}
        for source_job, source_claim in batch:
            for target_job, target_state in states.items():
                for target_claim in target_state["claims"]:
                    if target_claim["status"] not in ("active", "review_required"):
                        continue
                    references = {(int(item["job_id"]), item["claim_id"]) for item in target_claim.get("relies_on", [])}
                    if (source_job, source_claim) in references:
                        reason = f"{source_job}:{source_claim} changed"
                        was_active = target_claim["status"] == "active"
                        old_reasons = set(target_claim.get("review_reasons", []))
                        new_reasons = old_reasons | {reason}
                        target_claim["status"] = "review_required"
                        target_claim["review_reasons"] = sorted(new_reasons)
                        if was_active or new_reasons != old_reasons:
                            changed_by_job.setdefault(target_job, []).append(target_claim["id"])
                            reasons_by_job.setdefault(target_job, set()).add(reason)
                        queue.append((target_job, target_claim["id"]))
        for target_job, claim_ids in changed_by_job.items():
            target_state = states[target_job]
            old_status = target_state["status"]
            if old_status != "needs_review":
                target_state["status"] = "needs_review"
            changes = [{"kind": "claim_review_required", "claim_id": claim_id} for claim_id in sorted(set(claim_ids))]
            if old_status != target_state["status"]:
                changes.append({"kind": "status_changed", "from": old_status, "to": target_state["status"]})
            details = "Claims require review after upstream changes: " + ", ".join(sorted(reasons_by_job[target_job]))
            revision = _append_revision(
                connection, target_job, target_state,
                message="Upstream claim changed; review required", details=details, changes=changes,
                current_analysis=current_analysis,
            )
            affected.append(target_job)
    return sorted(set(affected))


def _invalidate_job_dependents(
    connection: sqlite3.Connection,
    initial_job_ids: list[int],
    *,
    current_analysis: dict[str, Any],
) -> list[int]:
    """Mark worked-on jobs that explicitly depend on changed upstream jobs."""

    queue = list(initial_job_ids)
    seen: set[int] = set()
    affected: list[int] = []
    while queue:
        source = queue.pop(0)
        if source in seen:
            continue
        seen.add(source)
        for row in connection.execute("SELECT job_id FROM jobs ORDER BY job_id"):
            target_id = int(row["job_id"])
            if target_id == source:
                continue
            target = _state(connection, target_id)
            if source not in target["depends_on"]:
                continue
            queue.append(target_id)
            if target["status"] in ("planned", "needs_review", "stale"):
                continue
            old_status = target["status"]
            target["status"] = "needs_review"
            _append_revision(
                connection, target_id, target,
                message="Upstream job changed; review required",
                details=f"Dependency job {source} changed after this job had work recorded.",
                changes=[{"kind": "status_changed", "from": old_status, "to": "needs_review"},
                         {"kind": "dependency_review_required", "upstream_job_id": source}],
                current_analysis=current_analysis,
            )
            affected.append(target_id)
    return sorted(set(affected))


def _review_plan(connection: sqlite3.Connection, current: dict) -> dict[int, dict]:
    """Compute evidence and transitive claim review without changing saved history."""
    states = {int(row[0]): _state(connection, int(row[0]))
              for row in connection.execute("SELECT job_id FROM jobs ORDER BY job_id")}
    pending: dict[int, dict[str, set[str]]] = {}
    for job_id, state in states.items():
        changed = {item["id"] for item in state["evidence"] if _evidence_changed(connection, item, current)}
        for claim in state["claims"]:
            if claim["status"] not in ("active", "review_required"):
                continue
            reasons = {f"evidence {eid} changed" for eid in changed.intersection(claim.get("evidence_ids", []))}
            if claim["status"] == "review_required":
                reasons.update(claim.get("review_reasons", []) or ["recorded review required"])
            if reasons:
                pending.setdefault(job_id, {})[claim["id"]] = reasons
    changed = True
    while changed:
        changed = False
        for job_id, state in states.items():
            for claim in state["claims"]:
                if claim["status"] not in ("active", "review_required"):
                    continue
                for ref in claim.get("relies_on", []):
                    upstream = states.get(ref["job_id"], {})
                    upstream_claim = next((c for c in upstream.get("claims", []) if c["id"] == ref["claim_id"]), None)
                    if (ref["claim_id"] in pending.get(ref["job_id"], {}) or upstream_claim is None or
                            upstream_claim["status"] in ("withdrawn", "superseded")):
                        reason = f"upstream {ref['job_id']}:{ref['claim_id']} requires review"
                        reasons = pending.setdefault(job_id, {}).setdefault(claim["id"], set())
                        if reason not in reasons:
                            reasons.add(reason)
                            changed = True
    return {job_id: {claim_id: sorted(reasons) for claim_id, reasons in claims.items()}
            for job_id, claims in pending.items()}


def _apply_review(connection: sqlite3.Connection, current: dict) -> list[int]:
    affected = []
    plan = _review_plan(connection, current)
    for job_id, claims in plan.items():
        state = _state(connection, job_id)
        changes = []
        for claim in state["claims"]:
            if claim["id"] not in claims:
                continue
            reasons = claims[claim["id"]]
            if claim["status"] == "review_required" and claim.get("review_reasons") == reasons:
                continue
            claim["status"] = "review_required"
            claim["review_reasons"] = reasons
            changes.append({"kind": "claim_review_required", "claim_id": claim["id"], "reasons": reasons})
        if state["status"] != "needs_review":
            changes.append({"kind": "status_changed", "from": state["status"], "to": "needs_review"})
            state["status"] = "needs_review"
        if changes:
            _append_revision(connection, job_id, state, message="Evidence/dependency review required",
                             changes=changes, current_analysis=current)
            affected.append(job_id)
    return sorted(set(affected) | set(_invalidate_job_dependents(connection, list(plan), current_analysis=current)))


def _job_review_plan(connection: sqlite3.Connection, initial_job_ids: list[int]) -> dict[int, list[str]]:
    """Project job-status review caused by direct and transitive job dependencies."""
    states = {int(row[0]): _state(connection, int(row[0]))
              for row in connection.execute("SELECT job_id FROM jobs ORDER BY job_id")}
    queue = list(initial_job_ids)
    seen = set(queue)
    reasons: dict[int, set[str]] = {job_id: {"one or more claims require review"} for job_id in initial_job_ids}
    while queue:
        source = queue.pop(0)
        for target, state in states.items():
            if source not in state["depends_on"]:
                continue
            reasons.setdefault(target, set()).add(f"dependency job {source} changed")
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return {job_id: sorted(items) for job_id, items in reasons.items()}


def check_jobs(connection: sqlite3.Connection, *, apply: bool = False) -> dict[str, Any]:
    """Preview or persist review requirements after a complete analysis publication."""
    connection.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
    try:
        current = analysis_snapshot(connection)
        plan = _review_plan(connection, current)
        job_plan = _job_review_plan(connection, list(plan))
        statuses_before = {job_id: _state(connection, job_id)["status"] for job_id in job_plan}
        affected = _apply_review(connection, current) if apply else []
        result = {"applied": apply, "claims_requiring_review": [
            {"job_id": job_id, "claim_id": claim_id, "reasons": reasons}
            for job_id, claims in plan.items() for claim_id, reasons in claims.items()
        ], "jobs_requiring_review": [
            {"job_id": job_id, "status": statuses_before[job_id], "reasons": reasons}
            for job_id, reasons in job_plan.items()
            if job_id in plan or statuses_before[job_id] not in ("planned", "needs_review", "stale")
        ], "jobs_revised": affected}
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise


def revise_job(
    connection: sqlite3.Connection,
    job_id: int,
    *,
    message: str,
    details: str = "",
    title: str | None = None,
    objective: str | None = None,
    status: str | None = None,
    add_claims: list[str] | None = None,
    update_claims: list[str] | None = None,
    withdraw_claims: list[str] | None = None,
    add_evidence: list[str] | None = None,
    add_questions: list[str] | None = None,
    resolve_questions: list[str] | None = None,
    add_dependencies: list[int] | None = None,
    remove_dependencies: list[int] | None = None,
    operation_ids: list[str] | None = None,
    validations: list[str] | None = None,
    restore_revision_id: int | None = None,
    expected_revision_id: int | None = None,
    handoff: str | None = None,
) -> dict[str, Any]:
    if not message.strip():
        raise ValueError("revision message must not be empty")
    if status is not None and status not in JOB_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(JOB_STATUSES)}")
    if expected_revision_id is not None and expected_revision_id < 1:
        raise ValueError("expected_revision_id must be positive")
    if restore_revision_id is not None and restore_revision_id < 1:
        raise ValueError("restore_revision_id must be positive")
    connection.execute("BEGIN IMMEDIATE")
    try:
        job = _job_row(connection, job_id)
        current_analysis = analysis_snapshot(connection)
        # Apply drift inside this revision transaction so an ordinary status
        # change or restore cannot bypass evidence review. Failed edits roll back
        # both the requested change and this automatic review transition.
        _apply_review(connection, current_analysis)
        job = _job_row(connection, job_id)
        if expected_revision_id is not None and job["head_revision_id"] != expected_revision_id:
            raise ValueError(f"job head changed: expected {expected_revision_id}, current {job['head_revision_id']}; resume first")
        before = _state(connection, job_id)
        if restore_revision_id is not None:
            if any((title is not None, objective is not None, status is not None, add_claims, update_claims,
                    withdraw_claims, add_evidence, add_questions, resolve_questions,
                    add_dependencies, remove_dependencies, handoff is not None)):
                raise ValueError("restoring a revision cannot be combined with other state changes")
            source = connection.execute(
                "SELECT snapshot_json FROM job_revisions WHERE revision_id=? AND job_id=?",
                (restore_revision_id, job_id),
            ).fetchone()
            if source is None:
                raise ValueError(f"revision {restore_revision_id} does not belong to job {job_id}")
            after = _decode(source["snapshot_json"])
            reactivated = {claim["id"] for claim in after["claims"] if claim["status"] == "active" and
                           next((old["status"] for old in before["claims"] if old["id"] == claim["id"]), None) == "review_required"}
            if reactivated and not details.strip():
                raise ValueError("restoring reviewed claims requires --details describing the re-evaluation")
            changed_active = {claim["id"] for claim in after["claims"] if claim["status"] == "active"}
            changed_active &= set(_changed_claims(before, after))
            _validate_references(connection, job_id, after, new_claim_ids=changed_active)
            _validate_job_dependencies(connection, job_id, after["depends_on"])
            changes = [{"kind": "state_restored", "revision_id": restore_revision_id}]
        else:
            after = json.loads(_json(before))
            changes: list[dict[str, Any]] = []
            if handoff is not None:
                checkpoint = _load_spec(handoff, "handoff")
                if set(checkpoint) - {"progress", "next_action", "stop_condition"}:
                    raise ValueError("handoff fields are progress, next_action, stop_condition")
                if not all(isinstance(checkpoint.get(key), str) and checkpoint[key].strip()
                           for key in ("progress", "next_action", "stop_condition")):
                    raise ValueError("handoff requires non-empty progress, next_action, stop_condition")
                after["handoff"] = checkpoint
                changes.append({"kind": "handoff_updated"})
            if title is not None:
                if not title.strip():
                    raise ValueError("title must not be empty")
                after["title"] = title.strip()
                changes.append({"kind": "title_changed"})
            if objective is not None:
                if not objective.strip():
                    raise ValueError("objective must not be empty")
                after["objective"] = objective.strip()
                changes.append({"kind": "objective_changed"})
            if status is not None and status != after["status"]:
                old_status = after["status"]
                after["status"] = status
                changes.append({"kind": "status_changed", "from": old_status, "to": status})

            for raw in add_evidence or []:
                spec = _load_spec(raw, "evidence")
                unknown = set(spec) - {"id", "kind", "origin", "source_ref", "description"}
                if unknown:
                    raise ValueError(f"unsupported evidence fields: {', '.join(sorted(unknown))}")
                used_evidence_ids = _used_ids(connection, job_id, "evidence") | {item["id"] for item in after["evidence"]}
                evidence_id = str(spec.get("id") or _next_id(used_evidence_ids, "E")).strip()
                if not evidence_id or any(item["id"] == evidence_id for item in after["evidence"]):
                    raise ValueError(f"evidence ID is empty or already used: {evidence_id}")
                if evidence_id in used_evidence_ids:
                    raise ValueError(f"evidence ID was used by an earlier revision: {evidence_id}")
                kind = str(spec.get("kind", "observation"))
                origin = str(spec.get("origin", "ida_analysis"))
                source_ref = str(spec.get("source_ref", "")).strip()
                description = str(spec.get("description", "")).strip()
                if kind not in EVIDENCE_KINDS:
                    raise ValueError(f"evidence kind must be one of: {', '.join(EVIDENCE_KINDS)}")
                if origin not in EVIDENCE_ORIGINS:
                    raise ValueError(f"evidence origin must be one of: {', '.join(EVIDENCE_ORIGINS)}")
                if not source_ref or not description:
                    raise ValueError("evidence requires non-empty source_ref and description")
                item = {"id": evidence_id, "kind": kind, "origin": origin,
                        "source_ref": source_ref, "description": description,
                        "artifact_fingerprint": _artifact_fingerprint(connection, source_ref),
                        "analysis_snapshot": current_analysis, "created_at": utc_now()}
                after["evidence"].append(item)
                changes.append({"kind": "evidence_added", "evidence_id": evidence_id})

            for raw in add_claims or []:
                spec = _load_spec(raw, "claim")
                unknown = set(spec) - {"id", "kind", "basis", "text", "summary", "rationale", "evidence_ids", "relies_on", "supersedes", "supersedes_reason"}
                if unknown:
                    raise ValueError(f"unsupported claim fields: {', '.join(sorted(unknown))}")
                used_claim_ids = _used_ids(connection, job_id, "claims") | {item["id"] for item in after["claims"]}
                claim_id = str(spec.get("id") or _next_id(used_claim_ids, "C")).strip()
                if not claim_id or any(item["id"] == claim_id for item in after["claims"]):
                    raise ValueError(f"claim ID is empty or already used: {claim_id}")
                if claim_id in used_claim_ids:
                    raise ValueError(f"claim ID was used by an earlier revision: {claim_id}")
                kind = str(spec.get("kind", ""))
                if kind not in CLAIM_KINDS:
                    raise ValueError(f"claim kind must be one of: {', '.join(CLAIM_KINDS)}")
                basis = spec.get("basis")
                if basis is not None and basis not in ("observed", "derived"):
                    raise ValueError("claim basis must be observed or derived")
                if kind == "fact" and basis is None:
                    raise ValueError("fact claims require basis='observed' or basis='derived'")
                text = str(spec.get("text", "")).strip()
                summary = str(spec.get("summary", text)).strip()
                if not text or not summary:
                    raise ValueError("claim text and summary must not be empty")
                rationale = str(spec.get("rationale", "")).strip()
                if kind == "reject" and not rationale:
                    raise ValueError("reject claims require rationale")
                if not isinstance(spec.get("evidence_ids", []), list):
                    raise ValueError("evidence_ids must be a list")
                evidence_ids = list(dict.fromkeys(map(str, spec.get("evidence_ids", []))))
                relies_on = _normalize_relies_on(spec.get("relies_on"))
                supersedes = spec.get("supersedes")
                supersedes_reason = str(spec.get("supersedes_reason", "")).strip()
                if supersedes is not None:
                    supersedes = str(supersedes)
                    if not supersedes_reason:
                        raise ValueError("supersedes requires supersedes_reason")
                    previous = next((item for item in after["claims"] if item["id"] == supersedes), None)
                    if previous is None or previous["status"] not in ("active", "review_required"):
                        raise ValueError(f"supersedes must identify an active or review-required claim in this job: {supersedes}")
                    previous["status"] = "superseded"
                    previous["retirement_reason"] = supersedes_reason
                    changes.append({"kind": "claim_superseded", "claim_id": supersedes, "by": claim_id})
                item = {"id": claim_id, "kind": kind, "basis": basis, "text": text, "summary": summary,
                        "rationale": rationale,
                        "status": "active", "evidence_ids": evidence_ids, "relies_on": relies_on,
                        "supersedes": supersedes, "created_at": utc_now(), "updated_at": utc_now()}
                after["claims"].append(item)
                changes.append({"kind": "claim_added", "claim_id": claim_id, "claim_kind": kind})

            for raw in update_claims or []:
                spec = _load_spec(raw, "claim update")
                claim_id = str(spec.get("id", "")).strip()
                claim = next((item for item in after["claims"] if item["id"] == claim_id), None)
                if claim is None or claim["status"] not in ("active", "review_required"):
                    raise ValueError(f"claim update requires an active or review-required claim ID: {claim_id}")
                allowed = {"kind", "basis", "text", "summary", "rationale", "status", "evidence_ids", "relies_on"}
                unknown = set(spec) - allowed - {"id"}
                if unknown:
                    raise ValueError(f"unsupported claim update fields: {', '.join(sorted(unknown))}")
                updated = dict(claim)
                for key, value in spec.items():
                    if key == "id":
                        continue
                    if key == "relies_on":
                        value = _normalize_relies_on(value)
                    elif key == "status":
                        if value != "active":
                            raise ValueError("claim update can only restore review-required status to active")
                    elif key == "evidence_ids":
                        if not isinstance(value, list):
                            raise ValueError("evidence_ids must be a list")
                        value = list(dict.fromkeys(map(str, value)))
                    elif key in ("kind", "basis") and value is not None:
                        value = str(value)
                    elif key in ("text", "summary", "rationale"):
                        value = str(value).strip()
                        if key != "rationale" and not value:
                            raise ValueError(f"claim {key} must not be empty")
                    updated[key] = value
                if updated["kind"] not in CLAIM_KINDS:
                    raise ValueError(f"claim kind must be one of: {', '.join(CLAIM_KINDS)}")
                if updated.get("basis") not in (None, "observed", "derived"):
                    raise ValueError("claim basis must be observed or derived")
                if updated["kind"] == "fact" and updated.get("basis") is None:
                    raise ValueError("fact claims require basis='observed' or basis='derived'")
                if updated["kind"] == "reject" and not updated.get("rationale", "").strip():
                    raise ValueError("reject claims require rationale")
                if claim["status"] == "review_required" and updated["status"] == "active":
                    updated.pop("review_reasons", None)
                updated["updated_at"] = utc_now()
                claim.update(updated)
                changes.append({"kind": "claim_updated", "claim_id": claim_id})

            reactivated_claims = [claim["id"] for claim in after["claims"]
                                 if claim["status"] == "active" and
                                 next((old["status"] for old in before["claims"] if old["id"] == claim["id"]), None) == "review_required"]
            if reactivated_claims and not details.strip():
                raise ValueError("reactivating reviewed claims requires --details describing the re-evaluation")

            for raw in withdraw_claims or []:
                spec = _load_spec(raw, "claim withdrawal")
                claim_id = str(spec.get("id", "")).strip()
                reason = str(spec.get("reason", "")).strip()
                claim = next((item for item in after["claims"] if item["id"] == claim_id), None)
                if claim is None or claim["status"] not in ("active", "review_required"):
                    raise ValueError(f"withdrawal requires an active or review-required claim ID: {claim_id}")
                if not reason:
                    raise ValueError("claim withdrawal requires a reason")
                claim["status"] = "withdrawn"
                claim["withdrawal_reason"] = reason
                claim["updated_at"] = utc_now()
                changes.append({"kind": "claim_withdrawn", "claim_id": claim_id, "reason": reason})

            for raw in add_questions or []:
                question = raw.strip()
                if not question:
                    raise ValueError("question must not be empty")
                if any(item["text"] == question and item["status"] == "open" for item in after["questions"]):
                    raise ValueError("question is already open")
                used = _used_ids(connection, job_id, "questions") | {item["id"] for item in after["questions"]}
                question_id = _next_id(used, "Q")
                after["questions"].append({"id": question_id, "text": question, "status": "open", "resolution": None})
                changes.append({"kind": "question_added", "question_id": question_id})
            for raw in resolve_questions or []:
                spec = _load_spec(raw, "question resolution")
                question_id = str(spec.get("id", "")).strip()
                resolution = str(spec.get("resolution", "")).strip()
                question = next((item for item in after["questions"] if item["id"] == question_id), None)
                if question is None or question["status"] != "open" or not resolution:
                    raise ValueError("question resolution requires an open question ID and non-empty resolution")
                question["status"] = "resolved"
                question["resolution"] = resolution
                changes.append({"kind": "question_resolved", "question_id": question_id})

            dependencies = set(map(int, after["depends_on"]))
            for dependency in add_dependencies or []:
                dependencies.add(int(dependency))
            for dependency in remove_dependencies or []:
                dependencies.discard(int(dependency))
            after["depends_on"] = sorted(dependencies)
            if after["depends_on"] != before["depends_on"]:
                changes.append({"kind": "dependencies_changed", "depends_on": after["depends_on"]})
            _validate_job_dependencies(connection, job_id, after["depends_on"])
            require_active = {claim["id"] for claim in after["claims"] if claim["status"] == "active"}
            require_active &= set(_changed_claims(before, after))
            _validate_references(connection, job_id, after, new_claim_ids=require_active)

        for operation_id in operation_ids or []:
            if connection.execute("SELECT 1 FROM operations WHERE request_id=?", (operation_id,)).fetchone() is None:
                raise ValueError(f"IDA operation not found: {operation_id}")
            changes.append({"kind": "ida_operation", "request_id": operation_id})
        for validation in validations or []:
            if not validation.strip():
                raise ValueError("validation result must not be empty")
            changes.append({"kind": "validation", "result": validation.strip()})
        if details.strip() and not changes:
            changes.append({"kind": "analysis_note"})

        if after["status"] in ("active", "done") and any(
            claim["status"] == "review_required" for claim in after["claims"]
        ):
            raise ValueError("resolve all review-required claims before setting a job to active or done")
        if before["status"] in ("done", "needs_review", "stale") and after["status"] != before["status"] and not details.strip():
            raise ValueError("reopening or clearing review requires --details explaining the new evidence or evaluation")

        changed_claim_ids = _changed_claims(before, after)
        if not changes:
            raise ValueError("revision contains no changes")
        revision = _append_revision(
            connection, job_id, after, message=message, details=details, changes=changes,
            current_analysis=current_analysis, restored_from=restore_revision_id,
        )
        affected = _invalidate_dependents(
            connection, [(job_id, claim_id) for claim_id in changed_claim_ids], current_analysis=current_analysis,
        )
        semantic_change = bool(changed_claim_ids or any(
            change["kind"] in ("objective_changed", "dependencies_changed", "state_restored") or
            (change["kind"] == "status_changed" and change.get("from") == "done")
            for change in changes
        ))
        job_sources = ([job_id] if semantic_change else []) + affected
        affected = sorted(set(affected) | set(_invalidate_job_dependents(
            connection, job_sources, current_analysis=current_analysis,
        )))
        connection.commit()
        added_claims = [item["claim_id"] for item in changes if item.get("kind") == "claim_added"]
        added_evidence = [item["evidence_id"] for item in changes if item.get("kind") == "evidence_added"]
        added_questions = [item["question_id"] for item in changes if item.get("kind") == "question_added"]
        current_head = _head(connection, job_id)
        return {"job_id": job_id, **revision, "status": _state(connection, job_id)["status"],
                "head_revision_id": current_head["revision_id"],
                "changed_claims": changed_claim_ids, "added_claim_ids": added_claims,
                "added_evidence_ids": added_evidence, "added_question_ids": added_questions,
                "jobs_marked_needs_review": affected}
    except Exception:
        connection.rollback()
        raise


def _summary(connection: sqlite3.Connection, job_id: int) -> dict[str, Any]:
    row = _job_row(connection, job_id)
    revision = _head(connection, job_id)
    state = _decode(revision["snapshot_json"])
    return {
        "job_id": row["job_id"], "parent_job_id": row["parent_job_id"],
        "title": state["title"], "objective": state["objective"], "status": state["status"],
        "revision_id": revision["revision_id"], "revision_no": revision["revision_no"],
        "updated_at": revision["created_at"], "claim_counts": {
            kind: sum(item["kind"] == kind and item["status"] == "active" for item in state["claims"])
            for kind in CLAIM_KINDS
        },
    }


def list_jobs(
    connection: sqlite3.Connection,
    *,
    parent_job_id: int | None = None,
    status: str | None = None,
    tree: bool = False,
) -> dict[str, Any]:
    if status is not None and status not in JOB_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(JOB_STATUSES)}")
    clauses, parameters = [], []
    if parent_job_id is not None:
        clauses.append("parent_job_id=?")
        parameters.append(parent_job_id)
    if status is not None:
        clauses.append("status=?")
        parameters.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = connection.execute(f"SELECT job_id,parent_job_id FROM jobs{where} ORDER BY job_id", parameters).fetchall()
    selected = {int(row["job_id"]) for row in rows}
    values = {job_id: _summary(connection, job_id) for job_id in selected}
    if not tree:
        return {"jobs": [values[job_id] for job_id in sorted(values)], "count": len(values)}
    children: dict[int | None, list[int]] = {}
    for row in connection.execute("SELECT job_id,parent_job_id FROM jobs ORDER BY job_id"):
        children.setdefault(row["parent_job_id"], []).append(int(row["job_id"]))

    def build(job_id: int) -> dict[str, Any]:
        item = dict(values.get(job_id) or _summary(connection, job_id))
        item["children"] = [build(child) for child in children.get(job_id, [])]
        return item

    roots = children.get(parent_job_id, []) if parent_job_id is not None else children.get(None, [])
    if status is not None:
        def prune(item: dict[str, Any]) -> dict[str, Any] | None:
            descendants = [result for child in item["children"] if (result := prune(child)) is not None]
            item["children"] = descendants
            return item if item["status"] == status or descendants else None
        tree_values = [result for job_id in roots if (result := prune(build(job_id))) is not None]
    else:
        tree_values = [build(job_id) for job_id in roots]
    def node_count(item: dict[str, Any]) -> int:
        return 1 + sum(node_count(child) for child in item["children"])
    return {"tree": tree_values, "count": sum(node_count(item) for item in tree_values)}


def show_job(connection: sqlite3.Connection, job_id: int) -> dict[str, Any]:
    state = _state(connection, job_id)
    current = analysis_snapshot(connection)
    review_plan = _review_plan(connection, current)
    job_review_plan = _job_review_plan(connection, list(review_plan))
    revision = _head(connection, job_id)
    prior_analysis = _decode(revision["analysis_snapshot_json"])
    children = [int(row[0]) for row in connection.execute("SELECT job_id FROM jobs WHERE parent_job_id=? ORDER BY job_id", (job_id,))]
    drifted = [{"evidence_id": item["id"], "source_ref": item["source_ref"],
                "origin": item["origin"], "source_changed": _evidence_drift(connection, item, current)}
               for item in state["evidence"] if _evidence_drift(connection, item, current) is not False]
    pending_claims = [{"claim_id": claim_id, "reasons": reasons}
                      for claim_id, reasons in review_plan.get(job_id, {}).items()]
    dependent_status = state["status"] not in ("planned", "needs_review", "stale")
    effective_status = ("needs_review" if pending_claims or
                        (job_id in job_review_plan and dependent_status) else state["status"])
    return {**_summary(connection, job_id), "claims": state["claims"], "evidence": state["evidence"],
            "questions": state["questions"],
            "handoff": state.get("handoff"), "evidence_drift": drifted,
            "effective_status": effective_status,
            "claims_requiring_review": pending_claims,
            "jobs_requiring_review": job_review_plan,
            "depends_on": state["depends_on"], "children": [_summary(connection, child) for child in children],
            "analysis_snapshot": prior_analysis,
            "analysis_snapshot_changed": prior_analysis != current,
            "analysis_identity_changed": _identity_changed(prior_analysis, current)}


def history(connection: sqlite3.Connection, job_id: int, *, limit: int = 20,
            include_state: bool = False, revision_id: int | None = None) -> dict[str, Any]:
    _job_row(connection, job_id)
    if limit < 0:
        raise ValueError("history limit must be non-negative")
    sql = "SELECT * FROM job_revisions WHERE job_id=? ORDER BY revision_no DESC"
    if revision_id is not None:
        rows = connection.execute("SELECT * FROM job_revisions WHERE job_id=? AND revision_id=?",
                                  (job_id, revision_id)).fetchall()
        if not rows:
            raise ValueError(f"revision {revision_id} does not belong to job {job_id}")
    else:
        rows = connection.execute(sql, (job_id,)).fetchall() if limit == 0 else connection.execute(sql + " LIMIT ?", (job_id, limit)).fetchall()
    revisions = []
    for row in reversed(rows):
        item = {key: row[key] for key in (
            "revision_id", "revision_no", "parent_revision_id", "message", "details", "state_hash",
            "restored_from_revision", "created_at",
        )}
        item["changes"] = _decode(row["changes_json"])
        item["analysis_snapshot"] = _decode(row["analysis_snapshot_json"])
        if include_state:
            item["state"] = _decode(row["snapshot_json"])
        revisions.append(item)
    return {"job_id": job_id, "revisions": revisions, "count": len(revisions)}


def resume_job(connection: sqlite3.Connection, job_id: int, *, recent: int = 3) -> dict[str, Any]:
    if recent < 0:
        raise ValueError("recent revision count must be non-negative")
    row = _job_row(connection, job_id)
    state = _state(connection, job_id)
    head = _head(connection, job_id)
    saved_analysis = _decode(head["analysis_snapshot_json"])
    current_analysis = analysis_snapshot(connection)
    all_review_plan = _review_plan(connection, current_analysis)
    review_plan = all_review_plan.get(job_id, {})
    job_review_plan = _job_review_plan(connection, list(all_review_plan))
    children = [_summary(connection, int(child[0])) for child in connection.execute(
        "SELECT job_id FROM jobs WHERE parent_job_id=? ORDER BY job_id", (job_id,)
    )]
    dependencies = []
    for dependency in state["depends_on"]:
        dependencies.append(_summary(connection, int(dependency)))
    recent_history = [{key: revision[key] for key in
                       ("revision_id", "revision_no", "message", "changes", "created_at")}
                      for revision in history(connection, job_id, limit=recent)["revisions"]]

    def compact(claim: dict) -> dict:
        return {key: claim[key] for key in ("id", "kind", "basis", "summary", "rationale", "status", "evidence_ids",
                                           "relies_on", "review_reasons") if key in claim}

    claims = {kind: [compact(claim) for claim in state["claims"]
                     if claim["kind"] == kind and claim["status"] == "active" and claim["id"] not in review_plan]
              for kind in CLAIM_KINDS}
    review_claims = []
    for claim in state["claims"]:
        if claim["status"] == "review_required" or claim["id"] in review_plan:
            item = compact(claim)
            item["status"] = "review_required"
            item["review_reasons"] = review_plan.get(claim["id"], item.get("review_reasons", []))
            review_claims.append(item)
    retired_claims = [{"id": claim["id"], "kind": claim["kind"], "summary": claim["summary"],
                       "status": claim["status"], "reason": claim.get("withdrawal_reason") or claim.get("retirement_reason") or claim.get("rationale")}
                      for claim in state["claims"] if claim["status"] in ("withdrawn", "superseded")]
    changed_evidence = {item["id"] for item in state["evidence"]
                        if item.get("origin") == "ida_type_dependent" and
                        _evidence_changed(connection, item, current_analysis)}
    claims_needing_type_review = [compact(claim) for claim in state["claims"]
                                  if claim["status"] == "active" and
                                  changed_evidence.intersection(claim.get("evidence_ids", []))]
    known_scope = []
    for evidence in state["evidence"]:
        drift = _evidence_drift(connection, evidence, current_analysis)
        known_scope.append({"evidence_id": evidence["id"], "source_ref": evidence["source_ref"],
                            "description": evidence["description"], "origin": evidence["origin"],
                            "source_changed": drift,
                            "drift_check": "untracked" if drift is None else "checked"})
    return {
        "job_id": row["job_id"], "parent_job_id": row["parent_job_id"], "title": state["title"],
        "objective": state["objective"], "status": state["status"],
        "effective_status": ("needs_review" if review_plan or
                             (job_id in job_review_plan and state["status"] not in ("planned", "needs_review", "stale"))
                             else state["status"]),
        "jobs_requiring_review": [{"job_id": affected_job,
                                   "status": _state(connection, affected_job)["status"],
                                   "reasons": reasons}
                                  for affected_job, reasons in job_review_plan.items()],
        "revision_no": head["revision_no"],
        "current_claims": claims,
        "claims_needing_review": review_claims,
        "claims_needing_type_review": claims_needing_type_review,
        "retired_claims": retired_claims,
        "open_questions": [item for item in state["questions"] if item["status"] == "open"],
        "handoff": state.get("handoff"),
        "known_evidence_scope": known_scope,
        "dependencies": dependencies,
        "children": children,
        "latest_revision": {"revision_id": head["revision_id"], "message": head["message"],
                            "changes": _decode(head["changes_json"]), "created_at": head["created_at"]},
        "recent_revisions": recent_history,
        "analysis_snapshot_changed": saved_analysis != current_analysis,
        "analysis_identity_changed": _identity_changed(saved_analysis, current_analysis),
        "saved_analysis_snapshot": saved_analysis,
        "current_analysis_snapshot": current_analysis,
        "resume_guidance": "Continue from active claims and recorded evidence. Preserve reject claims as ruled-out interpretations. Reopen earlier work only when an upstream claim or analysis snapshot changed, a contradiction appears, or a specific review is recorded.",
    }

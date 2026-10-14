"""Read-only revision comparison and retrieval for long-running research."""

from __future__ import annotations

import sqlite3
from collections import deque

from .jobs import _decode, _head, _job_row, _state, _changed_claims


def _revision(connection: sqlite3.Connection, job_id: int, revision_id: int | None):
    if revision_id is None:
        return _head(connection, job_id)
    row = connection.execute("SELECT * FROM job_revisions WHERE job_id=? AND revision_id=?",
                             (job_id, revision_id)).fetchone()
    if row is None:
        raise ValueError(f"revision {revision_id} does not belong to job {job_id}")
    return row


def impact(connection: sqlite3.Connection, job_id: int, claim_ids: list[str]) -> dict:
    """Explain reachability in the current dependency graph; do not rewrite history."""
    states = {int(row[0]): _state(connection, int(row[0])) for row in connection.execute("SELECT job_id FROM jobs")}
    if job_id not in states:
        raise ValueError(f"job {job_id} does not exist")
    available = {claim["id"] for row in connection.execute(
        "SELECT snapshot_json FROM job_revisions WHERE job_id=?", (job_id,)
    ) for claim in _decode(row[0]).get("claims", [])}
    missing = sorted(set(claim_ids) - available)
    if missing:
        raise ValueError(f"claim IDs were not found in job {job_id}: {', '.join(missing)}")
    reverse = {}
    for owner, state in states.items():
        for claim in state["claims"]:
            if claim["status"] not in ("active", "review_required"):
                continue
            for ref in claim.get("relies_on", []):
                reverse.setdefault((ref["job_id"], ref["claim_id"]), []).append((owner, claim["id"]))
    paths = {(job_id, cid): [(job_id, cid)] for cid in claim_ids}
    queue = deque(paths)
    claims = []
    jobs = {job_id}
    while queue:
        source = queue.popleft()
        for target in reverse.get(source, []):
            if target in paths:
                continue
            paths[target] = paths[source] + [target]
            queue.append(target)
            jobs.add(target[0])
            claims.append({"job_id": target[0], "claim_id": target[1], "path": [
                {"job_id": jid, "claim_id": cid} for jid, cid in paths[target]]})
    queue = deque(sorted(jobs))
    dependencies = []
    while queue:
        source = queue.popleft()
        for owner, state in states.items():
            if source in state["depends_on"] and owner not in jobs:
                jobs.add(owner)
                queue.append(owner)
                dependencies.append({"job_id": owner, "via_job_id": source, "status": state["status"]})
    return {"basis": "current dependency graph, potential impact only", "claims": claims,
            "job_dependencies": dependencies, "job_ids": sorted(jobs - {job_id})}


def diff_job(connection: sqlite3.Connection, job_id: int, *, from_revision: int,
             to_revision: int | None = None) -> dict:
    before_row = _revision(connection, job_id, from_revision)
    after_row = _revision(connection, job_id, to_revision)
    before, after = _decode(before_row["snapshot_json"]), _decode(after_row["snapshot_json"])
    collections = {}
    for key in ("claims", "evidence", "questions"):
        old = {item["id"]: item for item in before[key]}
        new = {item["id"]: item for item in after[key]}
        def comparable(item):
            return {field: value for field, value in item.items()
                    if field not in ("created_at", "updated_at")}

        collections[key] = {
            "added": [new[item_id] for item_id in sorted(new.keys() - old.keys())],
            "removed": [old[item_id] for item_id in sorted(old.keys() - new.keys())],
            "updated": [{"id": item_id, "before": old[item_id], "after": new[item_id],
                         "changed_fields": sorted(k for k in comparable(old[item_id]).keys() | comparable(new[item_id]).keys()
                                                  if comparable(old[item_id]).get(k) != comparable(new[item_id]).get(k))}
                        for item_id in sorted(old.keys() & new.keys())
                        if comparable(old[item_id]) != comparable(new[item_id])],
        }
    fields = {key: {"before": before.get(key), "after": after.get(key)}
              for key in sorted(before.keys() | after.keys())
              if key not in collections and before.get(key) != after.get(key)}
    changed_claim_ids = _changed_claims(before, after)
    semantic_fields = {key for key in fields if key in ("objective", "depends_on") or
                       (key == "status" and fields[key]["before"] == "done")}
    return {"job_id": job_id, "from_revision": before_row["revision_id"], "to_revision": after_row["revision_id"],
            "fields": fields, **collections,
            "analysis_snapshot_changed": before_row["analysis_snapshot_json"] != after_row["analysis_snapshot_json"],
            "changed_claim_ids": changed_claim_ids,
            "potential_impact": impact(connection, job_id, changed_claim_ids)
            if changed_claim_ids or semantic_fields else None}


def find_jobs(connection: sqlite3.Connection, *, query: str, job_id: int | None = None,
              kind: str = "all", include_history: bool = False, limit: int = 30) -> dict:
    if not query.strip():
        raise ValueError("query must not be empty")
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    if kind not in ("all", "claim", "evidence", "question", "note"):
        raise ValueError("kind must be all, claim, evidence, question, or note")
    if job_id is not None:
        _job_row(connection, job_id)
    needle = query.casefold()
    matches, seen = [], set()
    sql = "SELECT r.*,j.head_revision_id FROM job_revisions r JOIN jobs j USING(job_id)"
    parameters = ()
    if job_id is not None:
        sql += " WHERE r.job_id=?"
        parameters = (job_id,)
    sql += " ORDER BY r.revision_id DESC"
    for row in connection.execute(sql, parameters):
        candidates = []
        if kind in ("all", "note"):
            candidates.append(("note", str(row["revision_id"]), {
                "message": row["message"], "details": row["details"], "changes": _decode(row["changes_json"])}))
        if include_history or row["revision_id"] == row["head_revision_id"]:
            state = _decode(row["snapshot_json"])
            for collection, item_kind in (("claims", "claim"), ("evidence", "evidence"), ("questions", "question")):
                if kind in ("all", item_kind):
                    candidates.extend((item_kind, item["id"], item) for item in state[collection])
        for item_kind, item_id, item in candidates:
            # Search meaningful text and IDs, not snapshots or timestamp metadata.
            text = "\n".join(str(item.get(key) or "") for key in (
                "id", "kind", "status", "text", "summary", "rationale", "source_ref", "description",
                "resolution", "withdrawal_reason", "retirement_reason", "message", "details", "changes"))
            if needle not in text.casefold():
                continue
            identity = (row["job_id"], item_kind, item_id, text)
            if identity in seen:
                continue
            seen.add(identity)
            position = text.casefold().find(needle)
            matches.append({"job_id": row["job_id"], "revision_id": row["revision_id"],
                            "kind": item_kind, "id": item_id, "status": item.get("status"),
                            "at_current_head": row["revision_id"] == row["head_revision_id"],
                            "excerpt": text[max(0, position - 120):position + len(query) + 240]})
            if len(matches) > limit:
                return {"matches": matches[:limit], "count": limit, "truncated": True}
    return {"matches": matches, "count": len(matches), "truncated": False}

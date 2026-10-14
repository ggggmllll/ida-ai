---
name: ida-ai-sync
description: Rebuild an IDA analysis SQLite snapshot after saved IDB changes, including renamed globals, changed types, and stale disassembly or pseudocode.
---

```text
python -m ida_ai sync --db ANALYSIS.sqlite [--idat PATH]
python -m ida_ai sync --db ANALYSIS.sqlite --all-views
python -m ida_ai sync --db ANALYSIS.sqlite --address FUNCTION_EA
```

Save and close an externally edited IDB before launching this headless command. Unsaved GUI edits are not visible to the batch process. IDB is authoritative; editing SQLite does not change IDA.

For strictly function-local variable edits, `--address` refreshes only that function's pseudocode and previously exported disassembly; see `../ida-ai-local-sync/SKILL.md`. It is mutually exclusive with `--all-views`. The full rebuild behavior below applies when `--address` is omitted.

Sync waits for queued autoanalysis, clears Hex-Rays cached functions, rebuilds all function metadata (including `is_thunk`, `thunk_target_ea`, and `is_nullstub`), symbols (address/name/type), xrefs and CFG, then regenerates previously exported asm/pseudocode. `--all-views` generates both views for every current function. Removed functions disappear. A full rebuild avoids incomplete dependency inference through global types and indirect references.

The rebuild uses a staging SQLite database and publishes via SQLite backup after completion. Individual decompiler failures are published with `status='error'` and no stale text; inspect the returned view status counts. A failed overall rebuild leaves the previous analysis snapshot intact. IDB and SQLite are not a distributed transaction: rerun sync if saving/publishing fails.

Search records, raw pointer scans, memory read snapshots and search operation results are invalidated during rebuild. CLI sync also deletes its acceleration cache. Non-search operation rows are historical records, not current observations.

This is an explicit synchronization boundary, not a live GUI listener. Run sync after external edits and before using SQL to reason from the current IDB. Existing SQL reads do not automatically detect unsaved or external edits.

After the complete SQLite snapshot is published, the runner checks saved job evidence and appends review revisions for affected claims and dependent jobs. The sync result includes `job_review`; inspect it before continuing long-running research. Do not use partial/staging output as current job evidence.

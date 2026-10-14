---
name: ida-ai-sql
description: Query the SQLite analysis database directly when an AI needs precise joins, counts, metadata, or previously exported views.
---

After external IDB edits, run `python -m ida_ai sync --db ANALYSIS.sqlite` before querying. SQL reads a snapshot, not live IDA state. `symbols` contains named addresses and their IDA type declarations.

Read-only query:

```text
python -m ida_ai sql --db ANALYSIS.sqlite --query "SELECT ..." [--limit N]
```

The result is JSON with `columns`, `rows`, `count`, and `truncated`; `--limit 0` removes the row cap. The database contains `metadata`, `segments`, `functions`, `xrefs`, `basic_blocks`, `cfg_edges`, `disassembly`, `instructions`, `pseudocode`, `memory_bytes`, `pointers`, `search_matches`, `operations`, `jobs`, and `job_revisions`. In `functions`, `is_thunk` marks IDA thunks, `thunk_target_ea` stores a resolved target when available, and `is_nullstub` marks a conservative empty-return pattern. Job state is the latest revision snapshot; `job_revisions` is append-only history with notes, claims, evidence, and the bound analysis snapshot. Search acceleration is held in a separate local cache and is not part of this database.

Use `--write` only for an intentional maintenance statement. Prefer parameter-free literal SQL in the CLI and keep analysis mutations in the dedicated commands. Query schema names and function rows instead of guessing addresses or identifiers.

IDA addresses above `0x7FFFFFFFFFFFFFFF` are stored as signed 64-bit integers. Use `printf('%016X', target_ea)` in SQL to view the original unsigned address; CLI address arguments still use the normal unsigned form.

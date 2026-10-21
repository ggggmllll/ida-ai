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

`microcode` stores per-function microcode status/version/hash and relation coverage; `micro_instructions` stores structured `l_json`/`r_json`/`d_json` operand trees. `micro_blocks` stores microcode CFG predecessor/successor lists, and `micro_value_refs` stores direct register value-number definition/use locations. These observations do not form complete SSA or an alias graph. Export them through the microcode CLI before querying, and inspect errors and relation completeness before treating absent instructions or edges as absent behavior.

For `vtable_candidates`, inspect `evidence_json.table_address_status` before treating `table_address` as a table start. In raw historical databases, unresolved candidates may still store the first code-pointer address in the non-null `table_address` column for compatibility; the vtable CLI renders this as `table_address: null` and retains the raw start as `candidate_start_address`. Use the CLI rendering or filter to boundary-supported rows in SQL.

Use `--write` only for an intentional maintenance statement. Prefer parameter-free literal SQL in the CLI and keep analysis mutations in the dedicated commands. Query schema names and function rows instead of guessing addresses or identifiers.

IDA addresses above `0x7FFFFFFFFFFFFFFF` are stored as signed 64-bit integers. Use `printf('%016X', target_ea)` in SQL to view the original unsigned address; CLI address arguments still use the normal unsigned form.

`vcall_trace_runs` stores immutable receiver-memory trace JSON with source snapshot, scope/budgets, rule version and current/stale status. Use `vcall-trace-show` to validate the source snapshot before relying on a row; raw SQL status alone does not detect out-of-band edits. This is a durable analysis artifact, not the search acceleration cache.

`data_fixups(source_ea,observation_json,generated_at)` stores loader metadata and loaded image bytes within successfully read pointer-scan ranges. Inspect `metadata` key `data_pointer_scan` for `fixups` coverage, errors and bounds. No observation implies neither absence of relocations outside that scope nor a decoded runtime pointer.

---
name: ida-ai-derived-call-import
description: Import explicitly resolved call targets into SQLite as derived evidence, separate from native IDA xrefs.
---

```text
python -m ida_ai derived-call-import --db ANALYSIS.sqlite --input RESOLUTIONS.json --resolver RESOLVER_ID --method METHOD_ID [--confidence 0.0-1.0] [--source-ref REF] [--notes TEXT]
```

The input is a JSON list or an object with a `calls` list. Each record needs `call_ea`, `function_ea` (or `caller`), and `target_ea` (or `tail_target`). The tool verifies that the call exists in exported `instructions` and that its recorded function owner matches. It rejects missing or conflicting records.

Results are stored in `derived_calls`; `derived_call_runs` preserves one input/run record. Query `resolver`, `method`, `confidence`, `source_ref` and `run_id` with every conclusion. These rows are derived navigation evidence and must not be described as native IDA xrefs. Reimporting the same resolver replaces only that resolver's current rows and restores the same content idempotently. Other resolvers remain independent. A disassembly refresh marks affected rows `stale=1`; inspect `stale_reason` and reimport the resolver output before using them.

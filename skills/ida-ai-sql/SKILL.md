---
name: ida-ai-sql
description: Query the SQLite analysis database directly when an AI needs precise joins, counts, metadata, or previously exported views.
---

Read-only query:

```text
python -m ida_ai sql --db ANALYSIS.sqlite --query "SELECT ..." [--limit N]
```

The result is JSON with `columns`, `rows`, `count`, and `truncated`; `--limit 0` removes the row cap. The database contains `metadata`, `segments`, `functions`, `xrefs`, `basic_blocks`, `cfg_edges`, `disassembly`, `instructions`, `pseudocode`, `memory_bytes`, `pointers`, `search_matches`, and `operations`.

Use `--write` only for an intentional maintenance statement. Prefer parameter-free literal SQL in the CLI and keep analysis mutations in the dedicated commands. Query schema names and function rows instead of guessing addresses or identifiers.

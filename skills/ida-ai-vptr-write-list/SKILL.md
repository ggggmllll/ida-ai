---
name: ida-ai-vptr-write-list
description: Query current or historical function-local vptr store observations from SQLite.
---

```text
python -m ida_ai vptr-write-list --db ANALYSIS.sqlite
python -m ida_ai vptr-write-list --db ANALYSIS.sqlite --function ADDRESS
python -m ida_ai vptr-write-list --db ANALYSIS.sqlite --address-point ADDRESS
python -m ida_ai vptr-write-list --db ANALYSIS.sqlite --function ADDRESS --include-stale
```

This is an offline query. `--function` accepts an address inside a function and filters by its start address; `--address-point` filters on the exact decoded table address point. Pagination uses `--limit` and `--offset`; `--limit 0` returns every matching row. `--include-stale` adds historical observations and each row's stale flag must be checked.

Rows identify a function, microcode block/ordinal, store address, object identity/offset, address point, candidate ID, source hash and resolution evidence. A listed write is not proof of constructor semantics, persistent object state, dynamic type or a reachable virtual-call target. Use `vcall-analyze` for a call-site-specific prior-store candidate and inspect its unknown frontier.

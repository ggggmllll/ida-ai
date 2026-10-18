---
name: ida-ai-vtable-list
description: List current heuristic virtual-table/address-point candidates with pagination and stale-state awareness.
---

```text
python -m ida_ai vtable-list --db ANALYSIS.sqlite [--abi itanium] [--status candidate] [--limit N] [--offset N]
python -m ida_ai vtable-list --db ANALYSIS.sqlite --include-stale
```

This is an offline SQLite query and does not start IDA. Use `vtable-show` to inspect slots and evidence. `stale=0` is the default; `--include-stale` is for comparing old runs after IDB/type changes.

The list reports address point, table range when known, slot count, ABI, discovery source, and the parser's evidence object. Inspect `table_address_status`: `candidate_from_prefix` and `candidate_from_ztv_symbol` identify the observed boundary basis; `unresolved` renders `table_address` as null and preserves the first sequence address as `candidate_start_address`. It does not report a recovered class hierarchy or claim RTTI confirmation. `truncated` refers only to pagination.

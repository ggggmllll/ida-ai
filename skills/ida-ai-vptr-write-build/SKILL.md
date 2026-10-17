---
name: ida-ai-vptr-write-build
description: Refresh selected microcode and index exact function-local stores of current indexed table address points.
---

```text
python -m ida_ai vptr-write-build --db ANALYSIS.sqlite --all --idat IDAT64
python -m ida_ai vptr-write-build --db ANALYSIS.sqlite --address ADDRESS --idat IDAT64
python -m ida_ai vptr-write-build --db ANALYSIS.sqlite --range START END --no-refresh
python -m ida_ai vptr-write-build --db ANALYSIS.sqlite --name FUNCTION --idat IDAT64
python -m ida_ai vptr-write-build --db ANALYSIS.sqlite --all --view micro_flow --idat IDAT64
```

Build `vtable-build` first so the index has current address-point candidates. Exactly one function selector is required. Unless `--no-refresh` is supplied, the selected functions' chosen view is exported before scanning. `microcode` (default) is used for same-function prior-store/call ordering. `micro_flow` is LVARS output used by cross-function propagation and caller tracing. Never compare block/ordinal positions across these views.

Inspect `status`, `coverage.functions_missing_view`, `coverage.functions_with_export_errors`, `coverage.vtable_candidates_available`, and `coverage.truncated`. Missing view data, no table candidates, and exhausted limits produce partial coverage. The current index is stored in `vptr_write_runs` and `vptr_writes`; prior runs remain available with stale flags. A matching-view refresh or changed table index invalidates dependent observations.

The index records an observed store, not its effect at a later call. Aliasing stores, calls, memory writes and object lifetime are not fully modeled. A value that fails the bounded resolver is omitted as an unresolved store, not reported as evidence that no vptr assignment exists. Add the resulting run ID and evidence write IDs to the active job before forming a conclusion.

---
name: ida-ai-vtable-search
description: Search indexed table candidates by required slot targets or slot index.
---

```text
python -m ida_ai vtable-search --db ANALYSIS.sqlite --target ADDRESS --target ADDRESS
python -m ida_ai vtable-search --db ANALYSIS.sqlite --slot-index N
python -m ida_ai vtable-search --db ANALYSIS.sqlite --target ADDRESS --abi itanium --limit N
```

The repeated `--target` values are an AND query: one candidate must contain all requested target entries, in any slots. `--slot-index` restricts the returned matching slot. Use `0x` addresses or decimal values. This command searches the derived vtable index, not the ordinary byte/pointer-search cache.

Results are structural matches and include each matching slot's observed entry classification (for example, thunk, nullstub, or library function). These labels do not prove override semantics, a pure-virtual declaration, or class identity. They do not prove that the same receiver can reach every matching table. Inspect each candidate's evidence and use `vcall-analyze` for a call-point-specific query.

Targets may match the raw slot entry or any address in its bounded exported thunk chain. Results preserve the ordered chain; matching a chain member does not prove a `this`/return adjustment or runtime reachability. Multiple targets remain an AND query at candidate scope.

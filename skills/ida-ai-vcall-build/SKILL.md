---
name: ida-ai-vcall-build
description: Export selected microcode and index indirect calls plus conservative two-load vtable-shaped candidates.
---

```text
python -m ida_ai vcall-build --db ANALYSIS.sqlite --all --idat IDAT64
python -m ida_ai vcall-build --db ANALYSIS.sqlite --address ADDRESS --idat IDAT64
python -m ida_ai vcall-build --db ANALYSIS.sqlite --range START END --no-refresh
python -m ida_ai vcall-build --db ANALYSIS.sqlite --name FUNCTION --idat IDAT64
```

Choose exactly one function selector. Unless `--no-refresh` is supplied, selected functions are exported at the ordinary microcode view before the offline detector runs. Missing or failed microcode is reported in `coverage`; it is not silently removed from the denominator.

The detector indexes `icall` observations. It labels a site `vtable_pattern_candidate` only when a bounded, same-block/previous-definition chain contains two dependent indirect loads with constant offsets: receiver-related load to a vptr value, then slot load. It does not verify CFG dominance, object identity, ABI address point, C++ semantics, or runtime reachability. Other indirect calls are `indirect_unknown` and are useful negative evidence.

Use `vcall-show` or `vcall-analyze` next. A fresh type/name change requires a new microcode export and a new run; old sites become stale after full synchronization.

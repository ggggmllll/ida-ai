---
name: ida-ai-vtable-build
description: Build or refresh the evidence-backed heuristic table/address-point index from aligned loaded data pointers.
---

Use this command before `vtable-list`, `vtable-show`, or `vtable-search` when the IDB snapshot has changed or no current candidates exist.

```text
python -m ida_ai vtable-build --db ANALYSIS.sqlite --abi itanium --idat IDAT64
python -m ida_ai vtable-build --db ANALYSIS.sqlite --abi itanium --range START END --idat IDAT64
python -m ida_ai vtable-build --db ANALYSIS.sqlite --abi itanium --no-refresh
```

The normal form launches IDA in batch mode, scans readable non-executable non-BSS segments, stores aligned pointer observations in `data_pointer_slots`, preserves narrowly scoped scalar words before mapped code-pointer runs for possible Itanium `offset-to-top` evidence, and builds a new run in `vtable_runs`, `vtable_candidates`, `vtable_slots`, and `vtable_evidence`. `--no-refresh` only uses existing pointer observations; it cannot detect unsaved IDA edits.

The current implementation accepts `--abi itanium` as a conservative heuristic sequence detector. It does not parse RTTI into confirmed classes, prove an address point prefix, or distinguish a C++ table from every callback/C-ops array. `address_point_prefix` and `address_point_boundary` are weak observations only; `rtti_confirmed` remains false. Read `coverage`, `heuristic_only`, `rtti_parsed`, `truncated`, `skipped`, and scalar-prefix coverage before using a result. A candidate is evidence for inspection, not a type decision.

`--range` is a half-open data address range. `--min-function-slots` must be at least 2; `--max-slots` and `--max-bytes` bound work. Repeating the same source snapshot reactivates the prior run instead of adding duplicate candidates. A later full IDA export marks prior derived rows stale; rebuild and record the new run hash in the active job.

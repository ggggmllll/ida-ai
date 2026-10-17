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

The normal form launches IDA in batch mode, scans readable non-executable non-BSS segments, stores aligned pointer observations in `data_pointer_slots`, preserves narrowly scoped scalar words before mapped code-pointer runs for possible Itanium `offset-to-top` evidence, and builds a new run in `vtable_runs`, `vtable_candidates`, `vtable_slots`, and `vtable_evidence`. `max_bytes` includes both the primary scan and additional prefix probes; inspect `bytes_requested`, `prefix_bytes_read`, `prefix_budget_skipped`, and `truncated` in coverage. `--no-refresh` only uses existing pointer observations; it cannot detect unsaved IDA edits.

The current implementation accepts `--abi itanium` as a conservative sequence detector. It checks the two-word address-point prefix and follows the typeinfo object's vptr/name pointers. When the relevant `_ZTI`, `_ZTS`, and `__cxxabiv1` vtable symbols are present and consistent, it can confirm that narrow typeinfo-layout pattern; a matching table-start `_ZTV` symbol adds address-point evidence. Without symbols it reports only the observed pointer layout as a candidate. This does not parse base-class hierarchy, prove a dynamic object's class, or distinguish every C++ table from callback/C-ops arrays. `rtti_confirmed` remains false. Read `coverage`, `heuristic_only`, `rtti_parsed`, `typeinfo_layout_confirmed`, `address_point_symbol_match`, `truncated`, `skipped`, and scalar-prefix coverage before using a result. A candidate is evidence for inspection, not a type decision.

`--range` is a half-open data address range. `--min-function-slots` must be at least 2; `--max-slots` and `--max-bytes` bound work. Repeating the same source snapshot reactivates the prior run instead of adding duplicate candidates. A later full IDA export marks prior derived rows stale; rebuild and record the new run hash in the active job.

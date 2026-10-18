---
name: ida-ai-vtable-show
description: Inspect one indexed table candidate, raw slots, thunk links, and provenance.
---

```text
python -m ida_ai vtable-show --db ANALYSIS.sqlite --candidate-id VTB...
python -m ida_ai vtable-show --db ANALYSIS.sqlite --address ADDRESS
```

Provide exactly one selector. The address matches an indexed `address_point`, not an arbitrary slot address. Inspect `table_address_status` before using `table_address`: `candidate_from_prefix` and `candidate_from_ztv_symbol` report an observed boundary basis; `unresolved` means `table_address` is null in rendered output and the raw sequence start is retained as `candidate_start_address`. Every slot has a zero-based `slot_index`, an address-point-relative `byte_offset`, raw value, target kind, and optional IDA thunk target/chain.

Each slot reports `entry_classification`: `null_slot`, `nullstub`, `thunk`, `library_thunk`, `library_function`, `function`, `pure_virtual_runtime_named`, `deleted_virtual_runtime_named`, `unclassified_code`, `data_pointer`, or `unknown`. `library_*` reflects IDA's library-function flag; it does not mean the target is dynamically imported. These describe observed IDA flags, target kind, or runtime symbol names. The two runtime-name labels are name-based evidence, not proof of C++ declaration semantics. `target_ea` is the entry value observed in the binary. A thunk target is stored separately and does not erase the thunk. `address_point_prefix` records the observed offset-to-top and typeinfo pointer. Its nested `typeinfo` object reports the two pointer fields and any matching RTTI symbols; `confirmed_itanium_typeinfo_layout` confirms only that narrow layout pattern, not a class hierarchy or dynamic object type. `address_point_symbol_match` is additional name evidence that the table-start `_ZTV` symbol corresponds to the `_ZTI` symbol; it does not prove that the indexed code-pointer run covers the full table. A null, non-code, unknown, or unparsed entry is evidence to keep the candidate partial; do not turn it into a class declaration without another source.

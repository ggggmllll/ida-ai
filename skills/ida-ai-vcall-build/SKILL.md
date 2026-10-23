---
name: ida-ai-vcall-build
description: Export selected microcode and index indirect calls plus bounded vtable-shaped candidate chains.
---

```text
python -m ida_ai vcall-build --db ANALYSIS.sqlite --all --idat IDAT64
python -m ida_ai vcall-build --db ANALYSIS.sqlite --address ADDRESS --idat IDAT64
python -m ida_ai vcall-build --db ANALYSIS.sqlite --range START END --no-refresh
python -m ida_ai vcall-build --db ANALYSIS.sqlite --name FUNCTION --idat IDAT64
```

Choose exactly one function selector. Unless `--no-refresh` is supplied, selected functions are exported at the ordinary microcode view before the offline detector runs. Missing or failed microcode is reported in `coverage`; it is not silently removed from the denominator.

The command also builds the function-local vptr-write index for the same selected functions after refreshing microcode. It indexes only stores resolving to exact current table address points; see `ida-ai-vptr-write-build` and `ida-ai-vptr-write-list` for coverage and row semantics.

The detector indexes top-level and operand-nested `icall` observations, including `mov(icall(...))` and calls inside conversions. `evidence.operand_path` identifies the call within its containing block/ordinal; separate calls at the same EA are not merged. Cross-maturity trace bridges require a unique call EA and compatible shape, and leave ambiguous EAs unresolved. It supports two bounded structural shapes:

- The direct receiver shape has a receiver-related load that yields a vptr, followed by a constant-offset slot load. The exported call arguments must contain exactly one argument with the same receiver base identity; any subobject adjustment is recorded separately.
- The loaded-pointer receiver shape first loads a pointer from a register/local/stack/global base plus a constant field offset, then uses that exact loaded pointer as the receiver for a vptr load and a constant-offset slot load. The exact loaded pointer must appear as one unique exported call argument. Evidence records the pointer-field base/offset, pointer-load EA/value number, vptr-load EA, slot-load EA, slot byte offset, and the receiver binding. In this shape the vptr offset is relative to the loaded receiver and is reported as zero; the pointer-field offset is a separate coordinate.

Only complete chains with a unique exact-identity or supported subobject-offset argument binding become `vtable_pattern_candidate`. Incomplete chains, absent argument lists, mismatches, and ambiguous bindings remain `indirect_unknown`. Unknown sites carry `evidence.unknown_reason` and the run result has `unknown_reason_counts`; labels such as `call_operand_tree_truncated`, `function_operand_tree_truncated`, `multiple_cross_block_definitions`, `cfg_incomplete`, `receiver_binding_failed`, and `indirect_call_shape_unresolved` are triage categories, not semantic explanations. Same-block uses require a preceding definition. A cross-block definition is considered only when a complete microcode CFG has one root, exactly one definition exists for that value number in the function, and its block dominates the use. EA ordering across blocks is never used as a substitute. Multiple definitions at a merge or missing/inconsistent CFG data leave any chain that depends on them unresolved. If a required expression is truncated, it cannot complete the pattern.

The candidate still does not prove receiver object identity, ABI address point, C++ semantics, dynamic type, or runtime reachability. The indexed `definition_use_chain` records why each register value was connected. Other indirect calls remain `indirect_unknown` and are useful negative evidence.

Use `vcall-show` or `vcall-analyze` next. A fresh type/name change requires a new microcode export and a new run; old sites become stale after full synchronization.

Loads may be expanded inside the callee expression, split into instructions, or moved into a callee register. Expanded loads do not require invented intermediate value numbers; a zero slot offset is supported. The loaded-pointer receiver shape adds its pointer-field load before the vptr and slot loads. Deeper or unsupported address chains remain unknown. Receiver binding is required for both shapes. `unknown_reason.scope` distinguishes this call, its value chain, and function-wide coverage. Function-wide truncation does not prove that this call was truncated. Definition failures may include bounded definition/use locations; multiple definitions are reported only when actually observed, not inferred from exporter capability flags.

Call-index source identity includes normalized instruction/CFG rows as well as summary hashes. Rebuild old indexes before `vcall-trace`; a summary hash left unchanged after a raw-row edit cannot authorize reusing the old call pattern.

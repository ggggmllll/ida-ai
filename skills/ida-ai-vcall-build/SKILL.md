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

The command also builds the function-local vptr-write index for the same selected functions after refreshing microcode. It indexes only stores resolving to exact current table address points; see `ida-ai-vptr-write-build` and `ida-ai-vptr-write-list` for coverage and row semantics.

The detector indexes `icall` observations. It labels a site `vtable_pattern_candidate` only when a bounded definition chain contains two dependent indirect loads with constant offsets: receiver-related load to a vptr value, then slot load, and the exported argument list contains exactly one argument with the same receiver base identity (an offset adjustment is reported separately). If the argument list is absent, the structural chain is retained in evidence but the site remains `indirect_unknown`; a mismatch or ambiguous receiver argument also remains unknown. Unknown sites carry `evidence.unknown_reason` and the run result has `unknown_reason_counts`; labels such as `call_operand_tree_truncated`, `function_operand_tree_truncated`, `multiple_cross_block_definitions`, `cfg_incomplete`, `receiver_binding_failed`, and `indirect_call_shape_unresolved` are triage categories, not semantic explanations. Same-block uses require a preceding definition. A cross-block definition is considered only when a complete microcode CFG has one root, exactly one definition exists for that value number in the function, and its block dominates the use. EA ordering across blocks is never used as a substitute. Multiple definitions at a merge or missing/inconsistent CFG data leave any chain that depends on them unresolved. If a required expression is truncated, it cannot complete the pattern.

The candidate still does not prove receiver object identity, ABI address point, C++ semantics, dynamic type, or runtime reachability. The indexed `definition_use_chain` records why each register value was connected. Other indirect calls remain `indirect_unknown` and are useful negative evidence.

Use `vcall-show` or `vcall-analyze` next. A fresh type/name change requires a new microcode export and a new run; old sites become stale after full synchronization.

Both loads may be expanded inside the callee expression, split into instructions, or moved into a callee register. Expanded loads do not require invented intermediate value numbers; a zero slot offset is supported. More than two embedded loads and unsupported address expressions remain unknown. Receiver binding is still required. `unknown_reason.scope` distinguishes this call, its value chain, and function-wide coverage. Function-wide truncation does not prove that this call was truncated. Definition failures may include bounded definition/use locations; multiple definitions are reported only when actually observed, not inferred from exporter capability flags.

Call-index source identity includes normalized instruction/CFG rows as well as summary hashes. Rebuild old indexes before `vcall-trace`; a summary hash left unchanged after a raw-row edit cannot authorize reusing the old call pattern.

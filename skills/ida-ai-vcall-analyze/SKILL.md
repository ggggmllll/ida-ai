---
name: ida-ai-vcall-analyze
description: Resolve a stored indirect-call pattern against compatible indexed slots without asserting dynamic reachability.
---

```text
python -m ida_ai vcall-analyze --db ANALYSIS.sqlite --call-id VCALL...
python -m ida_ai vcall-analyze --db ANALYSIS.sqlite --address ADDRESS
```

The call address must be indexed by `vcall-build`. Only a site whose structural chain also has a usable receiver-argument identity is indexed as `vtable_pattern_candidate`; a missing, mismatched or ambiguous argument binding remains `indirect_unknown` and has no target resolution. Unknown sites include an `evidence.unknown_reason.code` triage label such as `operand_tree_truncated`, `cfg_incomplete`, `receiver_binding_failed`, or `indirect_call_shape_unresolved`; these labels guide follow-up exports and are not semantic proofs. For a complete two-load pattern, the tool matches the recorded slot byte offset and pointer width against current `vtable_slots`. It also checks current function-local vptr stores for exact object identity/offset and same-block prior order or a dominating block. Matching stores become `prior_vptr_writes` evidence and are linked in `receiver_flows`; compatible table targets record whether an exact candidate table was observed at such a store. The tool stores candidate target rows for inspection.

`candidate_set` means indexed slots are structurally compatible. Read `resolution.candidate_counts` for compatible table-slot rows, distinct target EAs, and the prior-store-narrowed counts; these are counts, never probabilities. A matched prior store is still only a candidate: aliases, intervening writes, calls, object lifetime and construction phases are not proven. `unknown` means the call pattern or receiver binding is incomplete, or no compatible slot is indexed. Candidate rows preserve slot entry classifications such as nullstub, thunk, and IDA library-function flags; the library flag does not imply a dynamic import. Runtime-stub labels come from symbol names only. The result is always `partial` at this stage: the matched argument's ABI role, receiver-to-table reachability, dynamic type, external modules, and unindexed tables remain unknown. Treat `target_ea` and thunk links as candidates, not confirmed call targets. Review `receiver_binding`, `prior_vptr_writes`, the definition chain and unknown frontier before recording a job claim.

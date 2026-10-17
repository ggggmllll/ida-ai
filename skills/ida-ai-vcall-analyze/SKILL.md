---
name: ida-ai-vcall-analyze
description: Resolve a stored indirect-call pattern against compatible indexed slots without asserting dynamic reachability.
---

```text
python -m ida_ai vcall-analyze --db ANALYSIS.sqlite --call-id VCALL...
python -m ida_ai vcall-analyze --db ANALYSIS.sqlite --address ADDRESS
```

The call address must be indexed by `vcall-build`. For a complete two-load pattern, the tool matches the recorded slot byte offset and pointer width against current `vtable_slots`. It stores candidate target rows for inspection.

`candidate_set` means indexed slots are structurally compatible. `unknown` means the call pattern is incomplete or no compatible slot is indexed. The result is always `partial` at this stage: receiver-to-table reachability, dynamic type, external modules, and unindexed tables remain unknown. Treat `target_ea` and thunk links as candidates, not confirmed call targets. Review the definition chain and unknown frontier before recording a job claim.

---
name: ida-ai-vptr-write-trace
description: Trace a current LVARS vptr-store object through bounded direct-call and reference-flow paths.
---

```text
python -m ida_ai vptr-write-trace --db ANALYSIS.sqlite --write-id VPW...
python -m ida_ai vptr-write-trace --db ANALYSIS.sqlite --write-id VPW... --max-hops 8 --max-nodes 300 --max-edges 2000
```

This is an offline preview. First export `micro_flow` for the relevant caller/callee scope, then build the vptr-write index with `--view micro_flow`. The trace reuses the LVARS evidence graph for arguments, returns, references, and value bindings. It rejects stale rows and any index built from GLBOPT3 because their instruction coordinates cannot be compared with LVARS.

The trace uses `max_hops`, `max_nodes`, `max_edges`, `max_callers`, and `max_alternatives` as strict worklist budgets. The path means an exported object identity can flow across the listed edges. It does not prove a constructor call executes, a store dominates a use, a pointer has no aliases, or an object retains its vptr. Inspect the edge trace, unresolved items, truncation flags, and snapshot hash. Hypothesis edges are preview-only. A missing caller path can reflect unexported functions or indirect callers, not absence of callers.

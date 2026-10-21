---
name: ida-ai-vcall-trace
description: Trace an indexed virtual-call receiver to reaching vptr stores at load time, with bounded LVARS direct-call, caller, and return paths.
---

```text
python -m ida_ai vcall-trace --db ANALYSIS.sqlite --call-id VCALL...
python -m ida_ai vcall-trace --db ANALYSIS.sqlite --address CALL_EA --max-hops 6 --max-nodes 500 --max-edges 4000 --max-alternatives 16 --max-context 4
```

Offline: reads exported observations and saves an immutable `vcall_trace_runs` result; never refreshes IDA. Supply exactly one selector. The address must identify a unique current indirect-call site, not a function address. Build tables and calls first. Export LVARS through `export --view flow` for the call and only the necessary direct callees/callers before tracing across functions. Positive budgets are required; hops <=64, context <=16. MCP equivalent: `trace_virtual_call` with the same arguments, address as a string.

Read `local_memory`, `object_memory`, `bridge`, `targets`, `index_frontier`, `resolution_status`, `completeness`, and `truncated`. A missing/ambiguous GLBOPT3-to-LVARS bridge leaves only the local query. The bridge independently recognizes the same unique call EA, constant slot/vptr offsets and receiver argument slot; local indices and value numbers are never equated across maturities. Structural correspondence is an explicit assumption.

The memory query runs backwards from the **vptr load**, not the indirect call. A nearest full-width store terminates that path. Overlapping partial stores, potentially aliasing pointers, truncated/missing exports, unsupported memory effects and unmodelled calls stop with explicit frontiers. A different local index does not prove non-aliasing. Literal/address arithmetic and lossless pointer copies are supported; loading a global pointer snapshot does not prove a constant. Same-root disjoint fields are skipped. Branches retain alternatives. Calls cross only verified read-only bodies or a unique actual/formal binding in LVARS with exported complete CFG and pointer-sized contracts. Return aliases bind the exact caller context; external allocation/return semantics stay unknown. Unbound formal entry queries always retain an external/unexported-caller frontier.

`local_store_history.events` records ordered same-block stores/call boundaries before the load. It is neither a whole-path history nor proof of construction/destruction, object survival or allocation ownership. `phase_observations` records reaching-store leaves with program points and paths. `lifetime.status` remains unknown. No type-name heuristic proves an edge.

`unique_under_assumptions` requires one supported indexed table/entry alternative, complete memory paths within this model and no index gap; it does not prove C++ semantics or runtime reachability. Partial paths can still provide supported candidates. Unknown does not mean no runtime target. Keep frontiers, assumptions, raw thunk entry/chain and adjustment uncertainty. Counts are not probabilities.

Cache keys include durable GLBOPT3/LVARS rows, contracts, CFG, table inputs, call sites, budgets and rule version. Refreshing either maturity conservatively stales saved traces; table rebuild/reset also stales them. Reanalysis preserves old JSON. For job evidence use `source_ref: vtrace:VTRACE...`; a stale run invalidates its fingerprint. Do not reuse type-dependent output as independent proof of a type you applied.

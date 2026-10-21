---
name: ida-ai-vcall-trace-show
description: Read a saved immutable virtual-call memory trace and explicitly inspect stale historical runs.
---

```text
python -m ida_ai vcall-trace-show --db ANALYSIS.sqlite --run-id VTRACE...
python -m ida_ai vcall-trace-show --db ANALYSIS.sqlite --run-id VTRACE... --include-stale
```

Offline read; does not rerun analysis or start IDA. MCP equivalent: `vcall_trace_show(run_id, include_stale=False)`. A missing run is an error. Source snapshots are checked against current exported rows, independently of the stored status. A stale run requires `--include-stale` and returns `stale: true`; historical JSON is retained unchanged. To recompute use `vcall-trace` on a current call index.

Read both resolution and completeness: even `unique_under_assumptions` remains `partial` with `runtime_reachability_proven: false`. Inspect bridge assumptions, local/object memory frontiers, budgets, index gaps and lifetime uncertainty before creating claims. Use `vtrace:<run_id>` to bind job evidence to this revision. SQL can inspect `vcall_trace_runs`; direct edits do not constitute a refreshed analysis.

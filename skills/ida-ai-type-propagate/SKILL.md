---
name: ida-ai-type-propagate
description: Use ida-ai's bounded type-constraint propagation CLI to carry evidence between microcode locals, arguments, call sites, returns, and references.
---

Use this skill when an analyst has a concrete type or usage constraint at one exported microcode node and needs conservative candidates elsewhere. It records provenance and lets the AI review alternatives before changing IDA types.

The source of truth is the SQLite database. A normal workflow is:

1. Refresh the LVARS flow snapshot when IDA types, names, locals, or decompiler settings may have changed:

   `python -m ida_ai export flow --db <db> --all --idat <idat>`

2. Create a seed JSON and record evidence with `type-propagate seed --db <db> --spec <seed.json> --no-refresh`. A seed node can be a `global`, `local`, `stack`, `value`, `arg`, or `return` node. `observed` seeds require a successful `micro_flow`, `pseudocode`, `disassembly`, or `microcode` evidence reference such as `micro_flow:0x401000`; `confirmed` and `hypothesis` seeds may use analyst evidence.

3. Preview with `type-propagate preview --db <db> --seed-id <id>`. Inspect `proposals`, `conflicts`, `unresolved`, `limits.truncated`, and every proposal's `trace`. The graph uses three families: `reference`, `parameter`, and `return`. A pointer-depth, offset, extension, truncation, or field projection is retained as a transform; it is not silently treated as an identical C type.

4. Accept only proposals whose `acceptable` value is true, after checking their trace and alternatives:

   `python -m ida_ai type-propagate accept --db <db> --run-id <run> --proposal P0001 [--proposal P0002] [--job <job-id>]`

   Hypothesis edges and paths containing uncertain transformations are preview-only. `--job` adds an analyst evidence record to the selected job; it does not replace the immutable propagation provenance.

5. Inspect a node with `type-propagate node --db <db> --node <node-id>`. Treat rows whose `stale` field is true as historical evidence. A new IDA snapshot invalidates preview and acceptance; refresh, re-seed or reconfirm, and preview again.

Do not infer a struct, array, union, pointer, signedness, or exact extent solely from an equal byte width. Use `type-scan` for utilization-form matches and use this tool to carry explicit constraints through observed relationships. A normal xref is not an alias. Indirect calls, unions, lossy conversions, conflicting alternatives, and cycles remain visible as uncertainty or unresolved results. Keep budgets bounded (`max_hops`, `max_nodes`, `max_edges`, `max_alternatives`) and record the unresolved or truncated status in the job when handing the result to another agent.

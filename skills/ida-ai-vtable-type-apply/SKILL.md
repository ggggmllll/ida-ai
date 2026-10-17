---
name: ida-ai-vtable-type-apply
description: Apply a current, revision-checked vtable type preview in headless IDA and synchronize SQLite.
---

```text
python -m ida_ai vtable-type-apply --db ANALYSIS.sqlite --spec PLAN.json --preview-id VTP... --revision-token SHA256 --idat IDAT64
```

First create a fresh plan with `ida-ai-vtable-type-preview`. This command recomputes and checks the preview ID and revision token before launching IDA; IDA checks the token again immediately before writes. Any intervening type, assignment, table, function, or vptr evidence change makes the preview stale.

The type declaration is parsed in IDA, then assignment declarations are applied one by one. The result reports `type_plan.status`, `assignments_applied`, and `failure`. A later rejected assignment may leave earlier changes applied, so the operation is not atomic across IDA and SQLite. After any result, inspect the per-assignment outcome and run synchronization/job review before relying on refreshed pseudocode or microcode. Make a new preview for subsequent edits.

Only explicitly listed addresses already supported by the selected table candidate can be assigned. Shared implementations may serve multiple table candidates; inspect `shared_table_candidates` and affected function signatures before applying prototypes globally. Class names and layouts remain hypotheses supplied by the caller.

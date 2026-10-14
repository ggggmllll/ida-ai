---
name: ida-ai-local-sync
description: Refresh only one function in SQLite after saved Hex-Rays local variable name, type, or comment edits.
---

```text
python -m ida_ai sync --db ANALYSIS.sqlite --address FUNCTION_EA
```

Save and close the edited IDB first. An address inside the function is accepted. This command does not edit variables; it publishes saved edits.

The selected function's Hex-Rays cache is invalidated and pseudocode is regenerated. Previously exported disassembly for that function is regenerated too. Results are built in a staging SQLite snapshot before publication; all other function views and analysis records are preserved. Inspect returned view statuses: a decompiler error replaces old text with an explicit error row.

Use this only for function-local variable names/types and comments. Changes to parameter types, function signatures, globals, shared types, bytes, function boundaries or calling conventions require full `sync` because they can affect callers or analysis metadata. This command does not infer whether external changes were truly local. It does not set the full snapshot synchronization timestamp.

After successful publication, the result includes `job_review`: changed evidence and its dependent claims are marked for review in append-only job revisions. Use `job-resume` before continuing affected research.

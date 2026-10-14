---
name: ida-ai-disassembly
description: Export IDA disassembly for selected functions into SQLite; use when an AI needs instruction text and bytes without a GUI.
---

Run exactly one selector:

```text
python -m ida_ai export disassembly --db ANALYSIS.sqlite --all
python -m ida_ai export disassembly --db ANALYSIS.sqlite --range START END
python -m ida_ai export disassembly --db ANALYSIS.sqlite --address EA
python -m ida_ai export disassembly --db ANALYSIS.sqlite --name FUNCTION_NAME
```

Addresses accept decimal or `0x` hexadecimal. `--address` may be any address inside a function. `--range` is half-open and selects every overlapping function. Results are in `disassembly` and `instructions`; the command returns status counts as JSON.

Use SQL to consume the data:

```text
python -m ida_ai sql --db ANALYSIS.sqlite --query "SELECT function_ea, text FROM disassembly ORDER BY function_ea"
```

Run initialization first. A missing function match means inspect `functions` with SQL; do not guess a name or address.

After successful publication, the result includes `job_review`: changed evidence and its dependent claims are marked for review in append-only job revisions. Use `job-resume` before continuing affected research.

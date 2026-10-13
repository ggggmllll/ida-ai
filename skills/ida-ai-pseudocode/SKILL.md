---
name: ida-ai-pseudocode
description: Export Hex-Rays pseudocode for selected functions into SQLite; use when AI needs high-level function text from headless IDA.
---

Choose exactly one:

```text
python -m ida_ai export pseudocode --db ANALYSIS.sqlite --all
python -m ida_ai export pseudocode --db ANALYSIS.sqlite --range START END
python -m ida_ai export pseudocode --db ANALYSIS.sqlite --address EA
python -m ida_ai export pseudocode --db ANALYSIS.sqlite --name FUNCTION_NAME
```

Results are stored in `pseudocode` with `status`, `error`, `backend`, and `generated_at`. A decompiler failure is recorded per function; treat `status='error'` as a reason to use disassembly. The operation still returns structured JSON.

Run initialization first, and query `functions` when a selector does not match. Do not infer addresses from formatted pseudocode.

---
name: ida-ai-disasm-range
description: Read decoded instructions from any address interval, including code that IDA does not assign to a function, without creating functions or changing the IDB.
---

Use this command when a suspicious address is decoded as code but is absent from the function index, or when instruction-level analysis must honor an exact half-open address interval:

```text
python -m ida_ai disasm-range --db ANALYSIS.sqlite --start 0x1A2BD10 --end 0x1A2BD80
```

`--max-bytes` defaults to 1 MiB and `--max-items` defaults to 10,000. A request over the byte budget is rejected before IDA starts. If more code items exist than the item budget, `coverage.truncated` is true and `coverage.omitted_code_items` reports the remainder.

The result separates `code`, `data`, `unknown`, and undecoded `gap` coverage. `entries` contains code items with address, bytes, disassembly text, segment permissions, and optional function/chunk ownership. `skip_samples` explains data, unknown, and gap items; a capped sample is marked by `skip_samples_truncated`.

This is a read-only range view. It does not create functions, infer function boundaries, save IDB changes, refresh `instructions`, or turn range output into a function-oriented SQLite view. Use `info`, `read`, `search`, and `export` for other views. Preserve the `requested`, `coverage`, and ownership fields when citing evidence: code without `function_ea` is decoded code outside IDA's current function model, not an automatically inferred standalone function.

---
name: ida-ai-pointer-search
description: Scan mapped IDA memory for aligned 32-bit or 64-bit raw pointers, optionally restricted to a target address or range.
---

```text
python -m ida_ai pointer-search --db ANALYSIS.sqlite
python -m ida_ai pointer-search --db ANALYSIS.sqlite --target EA --pointer-size 8
python -m ida_ai pointer-search --db ANALYSIS.sqlite --range START END --pointer-size 4
```

Without `--target`, results are pointers whose value maps to an IDA segment. With `--target`, only that exact value is returned. The default pointer size follows IDA bitness; specify 4 or 8 to override. Results include source and target addresses, size, target name/type, and are recorded in `pointers` and `search_matches`. Use `--limit 0` for unlimited results.

Run initialization first. A pointer search is a raw scan and can include data that is not semantically a pointer; validate candidates with address-info, xrefs, or disassembly.

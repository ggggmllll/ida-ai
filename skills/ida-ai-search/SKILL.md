---
name: ida-ai-search
description: Search mapped IDA segments for wildcard, masked, or union byte patterns and return addresses in JSON.
---

Examples:

```text
python -m ida_ai search --db ANALYSIS.sqlite --pattern "48 8B ?? ??"
python -m ida_ai search --db ANALYSIS.sqlite --pattern "48 8B 00 00" --mask "FF FF 00 00"
python -m ida_ai search --db ANALYSIS.sqlite --pattern "55 48 89 E5" --pattern "F3 0F 1E FA" --range START END
```

Patterns are hexadecimal bytes; `??`, `?`, and `**` are wildcards. Repeat `--pattern` for union search and provide one `--mask` per pattern when masks are used. `--range` is half-open. Use `--limit 0` for unlimited results; the JSON `truncated` field reports a cap.

Matches are recorded in `search_matches`. Search runs by segment and skips unmapped gaps. Query `segments` or use address-info before choosing a range.

Repeated identical searches use a local result cache under `.ida-ai-cache/`, keyed to the saved IDB file state and query parameters. The cache is an implementation detail; use the analysis SQLite database for AI-visible results. Use `python -m ida_ai clear-searches --db ANALYSIS.sqlite` to clear recorded search matches and the local cache.

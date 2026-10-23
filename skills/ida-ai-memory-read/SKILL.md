---
name: ida-ai-memory-read
description: Read bytes at an IDA address through the headless CLI and store the observation in SQLite.
---

```text
python -m ida_ai read --db ANALYSIS.sqlite --address EA --size N [--format auto|hex|array|both|none] [--output FILE]
```

`--size` is 1 to 1048576 bytes. Each byte is stored in `memory_bytes` for later SQL queries. Addresses accept decimal or `0x` hexadecimal.

The default `--format auto` includes spaced hex only when the read is at most `--max-inline-bytes` (default 4096). Larger reads return size, SHA-256, inline-format and storage metadata without duplicating the payload into both hex and an integer array. Use `--format none` to keep the response compact while retaining all bytes in SQLite, `--format hex|array|both` to request a known inline representation, or `--output FILE` to save the exact raw bytes. Use SQL over `memory_bytes` when the task needs individual bytes.

Use address-info first when you need to confirm whether the address is mapped or loaded. An unreadable range returns an error; reduce the size or inspect segment boundaries.

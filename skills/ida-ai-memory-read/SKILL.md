---
name: ida-ai-memory-read
description: Read bytes at an IDA address through the headless CLI and store the observation in SQLite.
---

```text
python -m ida_ai read --db ANALYSIS.sqlite --address EA --size N
```

`--size` is 1 to 1048576 bytes. The JSON result includes address, size, hex, and byte values. Each byte is also stored in `memory_bytes` for later SQL queries. Addresses accept decimal or `0x` hexadecimal.

Use address-info first when you need to confirm whether the address is mapped or loaded. An unreadable range returns an error; reduce the size or inspect segment boundaries.

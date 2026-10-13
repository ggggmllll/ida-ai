---
name: ida-ai-memory-write
description: Patch bytes at an IDA address, save the IDB, and refresh the SQLite analysis snapshot.
---

```text
python -m ida_ai write --db ANALYSIS.sqlite --address EA --data "90 90"
```

`--data` accepts hex bytes, including `0x` prefixes and separators, up to 1 MiB. The command verifies the patch, saves IDA, refreshes functions, xrefs, and CFG, and returns the written bytes. Later disassembly and pseudocode exports use the refreshed IDB.

Only patch a deliberate address. Use address-info first when mapping or permissions are unknown. A failed save or verification is reported as an error.

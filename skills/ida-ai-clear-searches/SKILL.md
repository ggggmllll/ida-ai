---
name: ida-ai-clear-searches
description: Clear persisted byte-search and pointer-search records and the matching local acceleration cache for an IDA analysis database.
---

Run:

```text
python -m ida_ai clear-searches --db ANALYSIS.sqlite
```

This deletes `search_matches`, raw-scan rows from `pointers`, and search operations from `operations`, then removes the local cache for this database. Functions, xrefs, CFG, disassembly, pseudocode, memory snapshots, and non-search operations remain intact. The JSON response reports how many search match records were cleared.

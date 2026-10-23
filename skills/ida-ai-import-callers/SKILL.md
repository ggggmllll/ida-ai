---
name: ida-ai-import-callers
description: Navigate incoming import/GOT/PLT references and report missing-link frontiers.
---

python -m ida_ai import-callers --db work.sqlite --address 0x1000 --max-hops 4 --max-nodes 1000 --max-edges 5000
Offline exported-xref traversal. Follows data references and referencing function entries (including stubs/thunks where IDA exported links). Caller results mean referencing functions, not proven dynamic calls. Missing IDA xrefs cannot be reconstructed by traversal: no_exported_incoming_xrefs_not_proof_unused is a data-quality frontier. Budgets preserve partial results.

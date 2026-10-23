---
name: ida-ai-vtable-match
description: Find families of tables by fixed shared slots and positional function/null constraints in loaded memory.
---

python -m ida_ai vtable-match --db work.sqlite --spec signature.json --range 0x1000 0x9000 --max-bytes 1048576 --limit 1000
signature.json: {"pointer_size":8,"slots":[{"offset":0,"kind":"function"},{"offset":16,"kind":"function"},{"offset":48,"target":"0x123456"}]}
Offsets are bytes relative to candidate address point. All constraints are AND; at least one nonzero exact target is mandatory. Kinds: exact (requires target), function (IDA function entry), null. Unspecified offsets are wildcards. Exact compares raw loaded pointer values, not thunk equivalence; add separate signatures for differing wrappers. Default refresh scans aligned loaded pointers in readable non-executable non-BSS segments, respects max-bytes, and marks old derived virtual artifacts stale. --no-refresh searches existing observations; inspect coverage.generated_at/scope/truncated and do not infer whole-program absence from incomplete scans. No RTTI or preidentified table boundary required. Matches are structural candidates, not verified message types or runtime reachability. max-anchors bounds anchor checks; limit bounds returned matches.

MCP match_vtable_structure accepts the same spec object, start_address/end_address, limit/max_anchors; it only searches the existing snapshot. Refresh via CLI before MCP matching if coverage is missing or outdated.

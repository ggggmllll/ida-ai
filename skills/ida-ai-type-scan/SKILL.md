---
name: ida-ai-type-scan
description: Find microcode locations matching a JSON utilization form and inspect weighted satisfaction, missing evidence, conflicts and source hashes.
---

```text
python -m ida_ai type-scan --db ANALYSIS.sqlite --spec FORM.json --all
python -m ida_ai type-scan --db ANALYSIS.sqlite --spec FORM.json --name compress2
python -m ida_ai type-scan --db ANALYSIS.sqlite --spec FORM.json --address 0x1234
python -m ida_ai type-scan --db ANALYSIS.sqlite --spec FORM.json --range 0x1000 0x2000
```

Read [the specification](references/specification.md) before constructing a form. Select exactly one scope, with the same function selection rules as microcode export. `--limit N` defaults to 1000; 0 returns all candidates. `--min-score 0.8` overrides the JSON threshold. Optional `--idat PATH --timeout SECONDS` controls IDA.

By default the command refreshes selected microcode from the saved IDB, then scans SQLite. Save and close external IDB edits first; run full `sync` when function metadata or shared types changed. `--no-refresh` scans only previously exported SQLite microcode, without starting IDA. Inspect `coverage.errors` and `coverage.missing_functions`; missing/failed functions were not searched successfully.

Each candidate contains function/block/ordinal/operand path/EA, score, matched/missing/conflicting constraints, compatibility, and microcode hash. `total_candidates` and `truncated` distinguish result limits from search coverage. No persistent scan cache is used yet.

Score is matched weight divided by all requested weight. Unknowns remain in the denominator. `exact` means every requested condition matched, not that a source type has been identified. Review `compatible` and conflicts even when a partial candidate scores highly. Repeated constraints are counted as supplied; weights are not independent evidence or calibrated probabilities.

Constraints describe expressions, including their nested operands. Sequential expressions need not refer to the same object. Sequences reflect stored expression order inside one block, not execution order or def-use flow. This tool does not propagate or apply types. Use candidates as evidence for an AI decision, then use existing MCP type operations if appropriate. Pin `microcode:0xFUNCTION_EA` as type-dependent job evidence before relying on it.

---
name: ida-ai-call-audit
description: Flag high-fan-in native call targets that use the return address for lookup or dispatch, where IDA may collapse distinct callsite semantics.
---

Use this offline audit before trusting a decompiler's callee name or return value around a shared ARM64 dispatch stub:

```text
python -m ida_ai call-audit --db ANALYSIS.sqlite --address 0x122D4BC
python -m ida_ai call-audit --db ANALYSIS.sqlite --range 0x100000 0x200000 --min-fan-in 256
```

The scope selectors mirror `export`: exactly one of `--all`, `--address`, `--addresses`, `--range`, or `--name`. `--max-functions` defaults to 1000 and is checked before the audit. `--max-results` caps returned callsites; high-fan-in totals remain available in `counts`.

`targets` reports native call fan-in and up to five disassembly instructions in the target that consume `X30`/`LR` in arithmetic or data movement. A target is classified as `ambiguous_callsite_dependent_dispatch` when it meets the fan-in threshold and has such a hint. This is a static heuristic: the real callsite-specific implementations are not resolved.

`call_sites` lists the selected native call instructions. Treat `target_identity_resolved=false` as a warning that both the semantic callee and the return value provenance are unresolved. Do not import these rows as `derived_calls`, do not assume every callsite invokes the same routine, and do not use uninitialized decompiler locals as field values without corroborating raw assembly.

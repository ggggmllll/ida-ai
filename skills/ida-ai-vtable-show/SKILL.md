---
name: ida-ai-vtable-show
description: Inspect one indexed table candidate, raw slots, thunk links, and provenance.
---

```text
python -m ida_ai vtable-show --db ANALYSIS.sqlite --candidate-id VTB...
python -m ida_ai vtable-show --db ANALYSIS.sqlite --address ADDRESS
```

Provide exactly one selector. The address matches an indexed `address_point`, not an arbitrary slot address. Every slot has a zero-based `slot_index`, a table-relative `byte_offset`, raw value, target kind, and optional IDA thunk target/chain.

`target_ea` is the entry value observed in the binary. A thunk target is stored separately and does not erase the thunk. `address_point_prefix` is only a heuristic clue. A null, non-code, unknown, or unparsed entry is evidence to keep the candidate partial; do not turn it into a pure-virtual or class declaration without another source.

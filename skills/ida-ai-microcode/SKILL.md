---
name: ida-ai-microcode
description: Export structured Hex-Rays microcode to SQLite for all functions, an address range, an address-containing function, or an exact function name.
---

```text
python -m ida_ai export microcode --db ANALYSIS.sqlite --all
python -m ida_ai export microcode --db ANALYSIS.sqlite --range 0x1000 0x2000
python -m ida_ai export microcode --db ANALYSIS.sqlite --address 0x1234
python -m ida_ai export microcode --db ANALYSIS.sqlite --name compress2
```

Select exactly one scope. A range is half-open and selects overlapping functions, including discontiguous blocks. `--name` matches an exact stored name or demangled name. Optional `--idat PATH --timeout SECONDS` selects the headless IDA runner. Save and close any GUI-edited IDB before running.

Microcode requires a licensed Hex-Rays decompiler for the target architecture. Output uses `MMAT_GLBOPT3`; optimized expressions often contain nested instructions. Inspect returned `statuses`: external functions and other decompiler failures have explicit error rows, with no old instructions retained.

The `microcode` table stores per-function status, error, maturity, version, instruction count, content hash, generation time and compact `relations_json` coverage metadata. `micro_instructions` stores function/block/ordinal/EA/opcode/text and `l_json`, `r_json`, `d_json` operand trees. `micro_blocks` stores each microcode block's predecessor/successor lists; `micro_value_refs` stores direct register value-number definition/use locations and operand paths. A complete CFG means the exported edge lists are internally consistent; it does not make machine-code and microcode blocks interchangeable. Query these tables by `function_ea`, `block_serial` and `value_number` instead of selecting the whole relation set. Read using the SQL CLI:

```text
python -m ida_ai sql --db ANALYSIS.sqlite --query "SELECT function_ea,status,error FROM microcode"
```

Operand widths are bytes. Global addresses, registers, frame-bottom stack offsets, local indices and nested instructions are retained when available. Stack offsets are Hex-Rays offsets, not IDA frame offsets. Operand recursion stops at depth 8 and marks truncated nodes. Block serials, ordinals, registers, local indices and operand paths identify one exported revision; do not treat them as stable identities after regeneration. A missing EA is possible for synthetic expressions.

Value-number definitions and uses are observations, not complete SSA or alias edges. Only direct register operands with nonzero Hex-Rays value numbers are included; `relations_json.truncated` marks incomplete operand trees. The exporter does not materialize reaching-definition edges. For virtual-call candidates, same-block order is checked, and a cross-block definition is considered only when one definition for that value number exists in the function and its microcode block dominates the use. Conditional alternate definitions, incomplete CFGs, multiple CFG roots, memory aliases and unnumbered values remain unresolved.

Full `sync` restores previously exported microcode, and `sync --all-views` exports all three views. Local `sync --address` refreshes previously exported microcode only for that function. Job evidence can cite `microcode:0xFUNCTION_EA` with origin `ida_type_dependent`.

For utilization-form matching, load `../ida-ai-type-scan/SKILL.md`.

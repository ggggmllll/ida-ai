# Utilization form JSON

Example: one-byte indirect read with a register-based address:

```json
{
  "name": "byte indirect read",
  "features": [
    {"kind": "memory_access", "direction": "read", "width": 1, "object": "register", "weight": 3},
    {"kind": "dereference", "depth": 1, "weight": 1}
  ],
  "min_score": 1
}
```

Top-level fields: optional `name`, non-empty `features`, optional `sequence`, `window` (1–1000, default 8), `min_score` (0–1, default 0.5). Supply features, sequence, or both. Unknown fields fail validation. Integers accept JSON integers or base-prefixed strings such as `"0x20"`; widths are bytes. Every constraint has `kind` and optional positive finite `weight` (default 1).

| Kind | Fields | Meaning |
| --- | --- | --- |
| `opcode` | required `value`: string or list of strings | Microcode opcode without `m_` prefix |
| `memory_access` | `direction`: read/write; `width`, `min_width`, `offset`, `object` | Indirect `ldx`/`stx`; data width, not pointer/segment width |
| `operand` | `object`, `width`, `address`, `stack_offset`, `local_index`, `register` | All supplied fields must describe one operand in the expression tree |
| `dereference` | `depth` (default 1) | At least this syntactically nested address-load depth; no register-flow analysis |
| `mask` | `value` | `and`/`or`/`xor` with an integer constant in the operand tree |
| `constant` | `value` | Integer constant in operand tree; omitted value means any integer |
| `call` | `callee`, `arg_index` | Call in expression tree, optional numeric callee EA and existence of zero-based argument index |
| `return` | none | `ret` expression |
| `extension` | required `extension`: sign/zero | Explicit sign/zero extension opcode |
| `comparison` | none | Conditional comparison or set-condition opcode |

`object` is any/global/stack/local/register. In `memory_access`, it constrains an address operand's storage category, not the original pointee's source-level storage. Direct global/stack accesses represented as operands of `mov` or arithmetic are not `memory_access`; use `operand` to locate those occurrences, without inferring read/write direction. `mask` includes OR and XOR; add an opcode constraint when specifically looking for AND masks. A call argument index only checks that an argument exists, not that it carries the value being investigated.

`offset` decomposes add/sub constant address expressions relative to the immediate base. It is not an established struct field offset. Unknown bases/expressions yield missing evidence. Access extent is a lower bound, not exact object size. Same-width uses do not distinguish int/float/pointer, arrays from pointers, unions, or types sharing a prefix.

When a form includes one or more `memory_access` constraints with `offset`, the result also includes an `access_profiles` entry for each requested offset. These profiles survey all successfully exported memory accesses at that numeric offset within the selected function scope, even when a `width` or `direction` constraint excludes them from `matches`. Each profile lists `width_candidates`, observed-width counts, read/write counts, per-function summaries and up to 16 sample locations per width; `sample_truncated` indicates more locations exist. A profile with multiple widths includes a `mixed_access_width` ambiguity. This prevents a width-specific search from hiding other observed widths.

An access profile groups only by numeric offset relative to each instruction's immediate address expression. It does not prove that the observations share a pointer, object, alias, field, or lifetime. `mixed_width: true` means multiple widths occurred at that offset somewhere in the selected scope; it does not itself establish a field conflict or a union. Review function-level groups, sample locations, microcode hashes and scope coverage before treating widths as evidence about one object.

All `features` apply to one expression location. The scanner visits each top-level and nested instruction. Operand/constant/call constraints may also see nested operands within that location; results are overlapping observations, not independent evidence.

Ordered example:

```json
{
  "sequence": [
    {"kind": "memory_access", "direction": "read", "width": 4},
    {"constraints": [
      {"kind": "opcode", "value": "and"},
      {"kind": "mask", "value": "0xff"}
    ]}
  ],
  "window": 12,
  "min_score": 1
}
```

Each step is a constraint or `{"constraints": [...]}`. Step zero is anchored at the candidate; later steps use distinct increasing expression positions in the same block. A dynamic program maximizes matched weight across the total window, counting top-level and nested expressions. Missing steps still contribute denominator weight. `features`, if supplied, add constraints on the anchor. Stored tree traversal order is not CPU evaluation order. There is no binding of an object or register between steps, no alias proof and no cross-block/cross-function sequence matching. Multiple views of a union and disjoint paths need further analysis.

Results include `matched`, `missing`, and `conflicts` with individual constraints and explanations. `compatible=false` means some evaluated constraint contradicted observations. `compatible=true` can still have unknown evidence; inspect `match_kind` and missing steps. Sequence steps skipped by optimal matching are reported as missing, not as proof of contradiction. A score of 1 means satisfaction of this form only, never probability of source-type identity.

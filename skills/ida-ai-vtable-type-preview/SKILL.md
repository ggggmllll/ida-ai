---
name: ida-ai-vtable-type-preview
description: Validate a caller-authored type plan against a current vtable candidate and its revision token.
---

```json
{
  "candidate_id": "VTB...",
  "relation_id": "VREL...",
  "type_definition": {"name": "Example", "declaration": "struct Example { void *vptr; };"},
  "assignments": [{"address": "0xADDRESS", "declaration": "void **"}],
  "rationale": "Evidence and remaining assumptions"
}
```

```text
python -m ida_ai vtable-type-preview --db ANALYSIS.sqlite --spec PLAN.json
```

The preview accepts assignment addresses observed as the candidate's address point, a boundary-supported table start, slot entry, slot implementation, or thunk target. It rejects a table-start assignment when `table_address_status=unresolved`; use the address point or a slot address instead. It reports shared implementations and function signatures, candidate/relationship provenance, a content revision token, and a deterministic preview ID. Type declarations are caller-authored and are not parsed by IDA until application.

Use the preview as input to the separate `ida-ai-vtable-type-apply` CLI skill or `apply_vtable_type_preview` in unsafe MCP mode. Shared method implementations can serve several tables, so never generalize a prototype globally without checking the other references.

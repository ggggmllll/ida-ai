---
name: ida-ai-vtable-class-relations
description: Inspect bounded Itanium RTTI base edges and their heuristic vtable candidate associations.
---

```text
python -m ida_ai vtable-class-relations --db ANALYSIS.sqlite --limit 100
python -m ida_ai vtable-class-relations --db ANALYSIS.sqlite --derived-typeinfo 0xADDRESS --limit 0
```

The query joins the current parsed RTTI descriptors with address-point candidates whose prefix names the same typeinfo address. The inheritance kind, flags, byte adjustment, RTTI run and candidate IDs are returned as evidence. Multiple table candidates are retained and flagged as ambiguous; missing table associations do not erase the RTTI edge.

RTTI base descriptors describe ABI metadata. They do not prove that a heuristic table is the active table of an object or that an object has the inferred layout. Check `rtti_input_current`, source hash, unmatched counts, ambiguity flags, and `class_identity_is_not_confirmed` before recording a job claim.

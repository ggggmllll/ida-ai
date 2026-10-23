---
name: ida-ai-discover
description: Snapshot IDA-defined string contents and import quality into SQLite.
---

python -m ida_ai discover --db work.sqlite --kind all --max-items 100000 --max-bytes 33554432
Optional --range START END. Tables: discovered_strings(address,string_type,text,bytes_hex,generated_at), discovered_imports(address,module,name,ordinal,direct_xrefs,quality,generated_at). bytes_hex is IDA API UTF-8 content, not original encoded memory bytes. Only IDA-defined string items are covered, not all possible encodings. Refresh replaces the selected kind, including when scoped. Read metadata discovery_strings/discovery_imports for coverage; full sync clears both. Join strings.address to xrefs.target_ea for references. No import xrefs does not mean unused; use import-callers for a bounded reverse walk.

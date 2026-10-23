---
name: ida-ai-attach-idb
description: Attach an existing IDB without its original binary; copy by default.
---

python -m ida_ai attach-idb --db work.sqlite --source original.i64 --idat IDAT
Optional --idb copy.i64 controls copy destination. --reuse-idb explicitly permits working on source instead; cannot combine with --idb. Existing outputs are refused. Failed sync leaves working outputs available for `sync --db work.sqlite`; do not rerun attach over them.

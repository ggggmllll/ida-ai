---
name: ida-ai-export-batch
description: Export multiple function views and addresses in one headless IDA launch.
---

python -m ida_ai export batch --db work.sqlite --addresses 0x1000 0x2000 --views disassembly pseudocode microcode flow --max-functions 20
Add --preview to inspect scope without starting IDA. Exactly one selector: --addresses, --address, --range START END, --name, --all. Range includes overlapping CFG owners, not just entrypoints. Default budget 1000; --max-functions 0 explicitly removes it. Results persist in SQLite and report statuses per view, not textual code.

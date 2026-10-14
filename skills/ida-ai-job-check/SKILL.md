---
name: ida-ai-job-check
description: Preview or persist research-job review transitions after IDA or analysis evidence changes.
---

Run `python -m ida_ai job-check --db ANALYSIS.sqlite` to preview affected claims and jobs. Add `--apply` to append immutable review revisions. A successful `init`, `sync`, `export`, `write`, or MCP-driven IDA mutation performs the same applied check after the full SQLite snapshot is published.

The check detects changed evidence sources, propagates review through `relies_on` claim links, and reports affected jobs connected by `depends_on`. Applying twice without new analysis changes is idempotent. Review-required claims are retained in history; re-evaluate them explicitly with fresh evidence or withdraw/supersede them.

Evidence based on a raw/external source without a stored fingerprint is reported as untracked, not verified unchanged. Type-dependent evidence is conservatively invalidated when the recorded IDA type state changes.

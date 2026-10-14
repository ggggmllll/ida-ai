---
name: ida-ai-job-history
description: Inspect a research job's append-only VCS revisions, detailed analysis notes, and prior saved states.
---

Run `python -m ida_ai job-history --db ANALYSIS.sqlite --job JOB_ID`. Use `--limit N` for recent revisions, `--limit 0` for all revisions, `--revision REVISION_ID` for one exact revision, and `--include-state` when the full saved claims/evidence snapshot is needed.

Each revision records its parent, message, details, changed items, analysis snapshot, and state hash. Restoring an older state appends another revision; it does not remove later history.

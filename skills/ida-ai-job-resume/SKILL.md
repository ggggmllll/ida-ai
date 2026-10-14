---
name: ida-ai-job-resume
description: Restore compact working context for an existing reverse-engineering job without repeating already recorded analysis.
---

Run `python -m ida_ai job-resume --db ANALYSIS.sqlite --job JOB_ID`. The response groups current claims by fact, hypothesis, decision, and reject; it also lists open questions, evidence scope, children, dependencies, changed analysis snapshots, and recent revision summaries. `--recent 0` includes all revisions.

Continue from active claims and recorded evidence. Preserve reject claims. Revisit an earlier conclusion when a cited upstream claim changed, a specific contradiction appeared, a type-dependent evidence snapshot changed, or a review question was recorded. Claims marked `review_required` and jobs marked `needs_review` need explicit re-evaluation before they are treated as current.

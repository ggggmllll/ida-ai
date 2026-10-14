---
name: ida-ai-job-diff
description: Compare two immutable revisions of a reverse-engineering research job.
---

Run `python -m ida_ai job-diff --db ANALYSIS.sqlite --job JOB_ID --from-revision REVISION_ID`. Omit `--to-revision` to compare with the current head. The result groups job fields and claim/evidence/question changes and reports changed claim IDs.

`potential_impact` follows the current claim and job dependency graph. It is a reachability preview, not a historical reconstruction or a statement that every dependent conclusion is wrong. Use `job-history --revision REVISION_ID --include-state` to inspect a full saved state.

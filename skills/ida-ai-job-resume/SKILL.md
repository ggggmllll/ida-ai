---
name: ida-ai-job-resume
description: Restore compact working context for an existing reverse-engineering job without repeating already recorded analysis.
---

Run `python -m ida_ai job-resume --db ANALYSIS.sqlite --job JOB_ID`. The response groups current claims by fact, hypothesis, decision, and reject; it also lists open questions, evidence scope, children, dependencies, changed analysis snapshots, the saved handoff, and recent revision summaries. `--recent 0` includes all revisions. Use `latest_revision.revision_id` as `job-revise --expected-revision` to guard against another writer changing the head. If pending drift causes this guard to fail, run `job-check --apply`, resume again, and reconsider the proposed edit against the newly recorded review state.

Continue from active claims and recorded evidence. Preserve reject claims. `current_claims` excludes claims whose evidence has drifted even if the last saved revision has not yet recorded that transition. Check `claims_needing_review`, `effective_status`, and `jobs_requiring_review`; run `job-check --apply` to append review transitions. Raw/external/analyst evidence without a source fingerprint is reported as untracked, not unchanged. Re-evaluate a claim with fresh evidence or withdraw/supersede it before treating it as current. Save a progress/next-action/stop-condition handoff when ending a long investigation.

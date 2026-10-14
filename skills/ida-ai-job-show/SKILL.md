---
name: ida-ai-job-show
description: Inspect a job's current objective, fact/hypothesis/decision/reject claims, evidence, dependencies, and snapshot freshness.
---

Run `python -m ida_ai job-show --db ANALYSIS.sqlite --job JOB_ID`.

Treat the saved claim list as the latest revision and `job-history` as the immutable record of earlier states. `effective_status` and `claims_requiring_review` also account for evidence drift not yet persisted; do not use those claims as current until re-evaluated. `evidence_drift` reports changed or untracked evidence sources. `analysis_snapshot_changed` means snapshot metadata changed after the latest job revision; `analysis_identity_changed` means the database now describes a different input identity. Use `job-resume` for compact continuation context and `job-check --apply` to persist review transitions.

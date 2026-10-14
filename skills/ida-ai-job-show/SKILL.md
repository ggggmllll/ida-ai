---
name: ida-ai-job-show
description: Inspect a job's current objective, fact/hypothesis/decision/reject claims, evidence, dependencies, and snapshot freshness.
---

Run `python -m ida_ai job-show --db ANALYSIS.sqlite --job JOB_ID`.

Treat the current claim list as the latest state and `job-history` as the immutable record of earlier states. Evidence includes its source reference, origin, and the IDA/SQLite analysis snapshot from which it was recorded. `analysis_snapshot_changed` means the analysis snapshot metadata changed after the latest job revision; `analysis_identity_changed` means the database now describes a different input identity. Use `job-resume` to check whether a specific evidence source changed.

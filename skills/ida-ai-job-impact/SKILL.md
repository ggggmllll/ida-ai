---
name: ida-ai-job-impact
description: Trace which current research claims and jobs depend on a claim or job.
---

Run `python -m ida_ai job-impact --db ANALYSIS.sqlite --job JOB_ID`. By default, active and review-required claims in that job are impact roots. Repeat `--claim CLAIM_ID` to select explicit roots, including a claim retained only in history. With no current claims, the command still reports jobs linked by `depends_on`.

The result describes reachability in the current dependency graph only. It does not change any job or claim and does not prove that every reachable conclusion must be discarded. Use `job-check --apply` or revise the affected jobs after examining the evidence.

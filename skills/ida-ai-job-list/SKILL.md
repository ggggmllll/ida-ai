---
name: ida-ai-job-list
description: List research jobs, filter their lifecycle status, or inspect the hierarchical job tree.
---

Run `python -m ida_ai job-list --db ANALYSIS.sqlite`. Use `--tree` for the nested parent-child hierarchy, `--parent JOB_ID` for a subtree, or `--status planned|active|blocked|done|stale|needs_review` to filter.

Hierarchy means research scope. Dependencies that encode execution order are listed separately in `job-show` and `job-resume`.

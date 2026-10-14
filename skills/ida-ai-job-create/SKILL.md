---
name: ida-ai-job-create
description: Create a root research job or a focused child job in an IDA analysis database, preserving the research hierarchy.
---

Run `python -m ida_ai job-create --db ANALYSIS.sqlite --title TITLE --objective OBJECTIVE --message "Initial scope"`.

Use `--parent JOB_ID` to place a narrower question beneath an existing job. The parent-child tree represents scope decomposition; use `job-revise --depends-on` separately when one job must be completed before another. Job creation records revision 1 in the SQLite job VCS.

Get IDs from the JSON response, then use `job-list --tree` to check the hierarchy. Keep each objective narrow enough to resume independently.

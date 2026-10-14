---
name: ida-ai-job-search
description: Find claims, evidence, questions, and revision notes in research-job history.
---

Run `python -m ida_ai job-search --db ANALYSIS.sqlite --query TEXT`. Use `--job JOB_ID` to scope the search, `--kind claim|evidence|question|note` to narrow it, and `--limit N` to bound the result.

By default, item content comes from each job's current head; revision notes are always searchable. Add `--history` to search earlier claim/evidence/question snapshots. Matches include job and revision IDs so the exact context can be opened with `job-history`. Search is literal, case-insensitive substring matching; it is not semantic search.

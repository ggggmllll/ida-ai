---
name: ida-ai-mcp
description: Connect an MCP client to an existing ida-ai SQLite analysis snapshot and use its read-only database, export, and code-text search tools.
---

Start the stdio server against a database created by ida-ai init:

    ida-ai-mcp --db ANALYSIS.sqlite --idat PATH_TO_IDAT

The default tool set is read-only except for refreshing exported views: database_summary, sql_query, search_code, and export_functions. IDB-changing tools are registered only with --unsafe; see the focused comment, type, and rename skills.

The IDB is authoritative and SQLite is a snapshot. After external IDA edits, use sync_analysis when the unsafe tool set is enabled, or stop the server and run python -m ida_ai sync --db ANALYSIS.sqlite before restarting. Unsaved GUI changes are not visible to the headless process.

Ordinary byte-pattern and pointer searches remain CLI operations. search_code targets exported assembly/pseudocode text and supports literal/regex multi-term queries.

After successful publication, the result includes `job_review`: changed evidence and its dependent claims are marked for review in append-only job revisions. Use `job-resume` before continuing affected research.

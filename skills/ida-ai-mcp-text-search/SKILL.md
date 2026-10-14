---
name: ida-ai-mcp-text-search
description: Search exported IDA disassembly and Hex-Rays pseudocode by multiple literal or regular-expression terms.
---

Use MCP search_code(terms, view, operator, case_sensitive, use_regex, start_address, end_address, limit) for high-level code search. It searches disassembly and/or pseudocode snapshots and returns function names, addresses, and matching lines. operator=all requires every term in a function; any accepts one. Regular expressions have a per-pattern time limit.

Use export_functions first when the needed view has not been exported. The MCP search does not scan raw bytes. For wildcard/masked byte patterns, union byte search, or pointer scanning, use the existing ida-ai search / pointer-search CLI tools.

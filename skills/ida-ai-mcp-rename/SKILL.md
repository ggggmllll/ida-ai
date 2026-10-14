---
name: ida-ai-mcp-rename
description: Rename a function/global symbol or a Hex-Rays local variable in the IDB and refresh affected SQLite views.
---

Start ida-ai-mcp --db ANALYSIS.sqlite --unsafe.

- rename_symbol(address, name) changes the IDA name at the address and rebuilds previously exported analysis views.
- rename_local_variable(function_address, old_name, new_name) changes a local variable's saved Hex-Rays user info and refreshes only that function's pseudocode and previously exported disassembly.

For a local variable, first inspect the current pseudocode and use its exact current name. Use a full sync for function signatures, globals, shared types, or other changes that may affect callers.

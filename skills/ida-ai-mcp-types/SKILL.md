---
name: ida-ai-mcp-types
description: Register C type declarations in IDA or apply a declaration to a function/global address through ida-ai MCP.
---

Start ida-ai-mcp --db ANALYSIS.sqlite --unsafe.

- register_type(name, declaration) parses a C declaration into IDA's local type library and records it in type_definitions.
- apply_type(address, declaration) applies a declaration at an IDA address, records it in type_assignments, saves the IDB, and rebuilds the SQLite analysis snapshot because a changed type may affect callers and decompilation.
- set_local_variable_type(function_address, name, declaration) applies a Hex-Rays local variable type and refreshes only that function's exported views.

For register_type and apply_type, use complete C declarations, including the terminating semicolon. For set_local_variable_type, pass only the type (for example, `unsigned int *`) and the exact current local variable name. Check the MCP result and then query the refreshed SQLite views before relying on the new type.

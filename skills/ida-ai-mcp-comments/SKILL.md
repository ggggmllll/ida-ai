---
name: ida-ai-mcp-comments
description: Add or remove IDA disassembly comments, function comments, or Hex-Rays pseudocode comments through the ida-ai MCP server.
---

Start ida-ai-mcp --db ANALYSIS.sqlite --unsafe and choose the comment tool by view:

- set_assembly_comment(address, comment, repeatable=false) writes an instruction-line comment via IDA address comments.
- set_function_comment(address, comment, repeatable=false) writes a function header comment.
- set_pseudocode_comment(address, comment) writes a Hex-Rays ctree user comment at an item address inside a function.

These are separate IDA comment stores. Empty comment deletes the selected comment. Each operation updates the matching SQL representation: assembly and pseudocode records are in comments with distinct kind values; function comments are in functions.comment / functions.repeatable_comment. Pseudocode comment records store ctree item precision in item_preciser; the default is a statement-end location. Pseudocode changes refresh that function's exported pseudocode.

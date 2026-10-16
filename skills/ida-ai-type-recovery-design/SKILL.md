---
name: ida-ai-type-recovery-design
description: Consult engineering goals and boundaries for usage-based type recovery, reference/parameter/return propagation, evolving layouts, and job evidence provenance.
---

The implementation and future-tool design are in [doc/type-recovery-design.md](../../doc/type-recovery-design.md). Read it when designing propagation or object-level type matching.

For implemented tools, use `ida-ai-microcode` to export structured microcode and `ida-ai-type-scan` to search utilization forms. Current scanning returns expression locations and explained scores; it does not establish object identity or propagate types.

Actual type registration/application remains an AI decision using the existing MCP type operations. Preserve evidence provenance when a changed type regenerates microcode.

---
name: ida-ai-vcall-show
description: Display an indexed indirect-call site and any saved candidate resolution.
---

```text
python -m ida_ai vcall-show --db ANALYSIS.sqlite --call-id VCALL...
python -m ida_ai vcall-show --db ANALYSIS.sqlite --address ADDRESS
python -m ida_ai vcall-show --db ANALYSIS.sqlite --call-id VCALL... --include-stale
```

This is an offline read. It returns the microcode location, receiver/callee expressions, slot and vptr offsets, definition-chain evidence, saved targets, and receiver flows. `--include-stale` is for historical comparison only.

The stored `kind` remains `indirect_call`; `status=vtable_pattern_candidate` is a detector result, not a C++ confirmation. Use source hashes and the job's evidence revision when handing the result to another analysis job.

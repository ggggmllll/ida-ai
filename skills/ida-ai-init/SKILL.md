---
name: ida-ai-init
description: Initialize an SQLite analysis database from a binary with headless IDA; use when function metadata, cross references, segments, and CFG are needed.
---

Run:

```text
python -m ida_ai init --db ANALYSIS.sqlite --binary SAMPLE --idb ANALYSIS.i64 [--idat PATH]
```

The command waits for IDA autoanalysis, saves an IDB, and stores functions, segments, xrefs, and basic-block CFG edges in SQLite. Function rows include `is_thunk` and `thunk_target_ea`; `is_nullstub` is set only when decoded instructions consist of harmless entry instructions followed by a return. It prints JSON. No GUI or Qt is used. The saved IDB path is stored in `metadata`; later commands reuse it.

Use an absolute path when the binary and database are on different drives. `--idat` is required only when `IDAT` or `IDADIR` is not configured. Do not run export commands before `init` succeeds.

Useful verification:

```text
python -m ida_ai sql --db ANALYSIS.sqlite --query "SELECT key, value FROM metadata ORDER BY key"
python -m ida_ai sql --db ANALYSIS.sqlite --query "SELECT count(*) AS functions FROM functions"
```

If IDA cannot be found, pass `--idat`; if the IDB path is missing or locked, choose a writable `--idb` path.

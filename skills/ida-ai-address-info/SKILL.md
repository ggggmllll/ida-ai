---
name: ida-ai-address-info
description: Inspect an IDA address or file offset and retrieve mapping, segment, permissions, item, name, and function metadata.
---

Use one location form:

```text
python -m ida_ai info --db ANALYSIS.sqlite --address EA
python -m ida_ai info --db ANALYSIS.sqlite --file-offset OFFSET
```

The JSON result includes `mapped`, `loaded`, `segment` (`start`, `end`, `name`, `permissions_text`), `file_offset`, item boundaries, name, and containing function. Addresses and offsets accept decimal or `0x` hexadecimal. An unmapped file offset is an error; query `metadata` for image ranges before retrying.

This command reopens the saved IDB headlessly and does not modify the analysis.

---
name: ida-ai-doc-sync
description: Refresh the checked-in IDAPython RST reference under doc from the official Hex-Rays documentation site.
---

From the repository root run:

```text
python doc/sync_official_docs.py
```

The script downloads the official sitemap and `_sources/*.rst.txt` pages into `doc/_sources`, then updates `doc/sitemap.xml` and `doc/manifest.json` with source URLs, byte counts, and SHA-256 hashes. Use `--prune` only when you want local source files removed if the upstream sitemap no longer lists them; use `--workers N` to change concurrency.

The network source is `https://python.docs.hex-rays.com/`. Treat downloaded reference text as API documentation, not as analysis output. Review the manifest and Git diff before committing a refresh.

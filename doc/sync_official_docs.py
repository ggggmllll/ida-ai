"""Refresh the local IDAPython reference from the official Sphinx sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


SITE = "https://python.docs.hex-rays.com/"
DOC_DIR = Path(__file__).resolve().parent
SOURCE_DIR = DOC_DIR / "_sources"
DOC_LINK = re.compile(r":doc:`(?:[^`<]*<)?([^`<>]+)>?`")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ida-ai-doc-sync/1.0"})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read()


def source_path(page: str) -> str | None:
    parsed = urllib.parse.urlsplit(page)
    if parsed.netloc and parsed.netloc != "python.docs.hex-rays.com":
        return None
    path = parsed.path.lstrip("/")
    if not path or path.endswith("/"):
        path += "index.html"
    if not path.endswith(".html") or path in {"genindex.html", "search.html"}:
        return None
    stem = path[:-5]
    if not stem or any(part in {".", ".."} for part in stem.split("/")):
        return None
    return stem + ".rst.txt"


def linked_sources(text: str, current: str) -> set[str]:
    found = set()
    parent = posixpath.dirname(current)
    for match in DOC_LINK.finditer(text):
        target = match.group(1).strip()
        if target.startswith(("http:", "https:")):
            continue
        if target.startswith("/"):
            page = target.lstrip("/") + ".html"
        else:
            page = posixpath.normpath(posixpath.join(parent, target)) + ".html"
        candidate = source_path(page)
        if candidate:
            found.add(candidate)
    return found


def download_one(path: str) -> tuple[str, bytes]:
    url = urllib.parse.urljoin(SITE, "_sources/" + path)
    return path, fetch(url)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prune", action="store_true", help="remove local source files absent upstream")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")

    sitemap = fetch(urllib.parse.urljoin(SITE, "sitemap.xml"))
    root = ET.fromstring(sitemap)
    pending = {
        path
        for node in root.iter()
        if node.tag.endswith("}loc") or node.tag == "loc"
        if node.text and (path := source_path(node.text))
    }
    pending.add("index.rst.txt")
    downloaded: dict[str, bytes] = {}
    while pending:
        batch = sorted(pending - downloaded.keys())
        if not batch:
            break
        pending.clear()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(download_one, path): path for path in batch}
            for future in as_completed(futures):
                path, content = future.result()
                downloaded[path] = content
                pending.update(linked_sources(content.decode("utf-8", "replace"), path))

    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"site": SITE, "files": {}}
    for path, content in sorted(downloaded.items()):
        destination = SOURCE_DIR / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists() or destination.read_bytes() != content:
            destination.write_bytes(content)
        manifest["files"][path] = {
            "url": urllib.parse.urljoin(SITE, "_sources/" + path),
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
    (DOC_DIR / "sitemap.xml").write_bytes(sitemap)
    (DOC_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if args.prune:
        for old in SOURCE_DIR.rglob("*.rst.txt"):
            if old.relative_to(SOURCE_DIR).as_posix() not in downloaded:
                old.unlink()
    print(f"Updated {len(downloaded)} official RST source documents in {SOURCE_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

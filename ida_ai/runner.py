"""Launch IDA in batch mode and collect structured results from SQLite."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from contextlib import closing
from pathlib import Path

from .db import connect, get_metadata, operation


IDA_NAMES = ("idat64.exe", "idat.exe", "idat64", "idat")


def find_idat(explicit: str | None = None) -> Path:
    candidates = []
    for value in (explicit, os.environ.get("IDAT")):
        if value:
            candidates.append(Path(value).expanduser())
    ida_dir = os.environ.get("IDADIR")
    if ida_dir:
        candidates.extend(Path(ida_dir).expanduser() / name for name in IDA_NAMES)
    for name in IDA_NAMES:
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("IDA batch executable not found; pass --idat or set IDAT/IDADIR")


def stored_idb_path(db_path: Path) -> Path:
    if not db_path.is_file():
        raise FileNotFoundError(f"SQLite database does not exist: {db_path}; run init first")
    with closing(connect(db_path)) as connection:
        value = get_metadata(connection, "idb_path")
    if not value:
        raise ValueError("SQLite database has no saved IDB; run init first")
    idb_path = Path(value)
    if not idb_path.is_file():
        raise FileNotFoundError(f"saved IDB does not exist: {idb_path}")
    return idb_path


def run_ida(
    action: str, db_path: str | Path, *, binary: str | Path | None = None,
    idat: str | None = None, timeout: int = 0, **payload,
) -> dict:
    db_path = Path(db_path).expanduser().resolve()
    if action == "init":
        if binary is None:
            raise ValueError("init requires --binary")
        input_path = Path(binary).expanduser().resolve()
        if not input_path.is_file():
            raise FileNotFoundError(f"input binary does not exist: {input_path}")
    else:
        input_path = stored_idb_path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    request_id = uuid.uuid4().hex
    request = {"request_id": request_id, "action": action, "db_path": str(db_path), **payload}
    script = Path(__file__).with_name("ida_entry.py").resolve()
    environment = os.environ.copy()
    project_root = str(script.parent.parent)
    environment["PYTHONPATH"] = project_root + os.pathsep + environment.get("PYTHONPATH", "")
    with tempfile.TemporaryDirectory(prefix="ida-ai-") as temporary:
        request_file = Path(temporary) / "request.json"
        request_file.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
        environment["IDA_AI_REQUEST"] = str(request_file)
        command = [str(find_idat(idat)), "-A"]
        if action == "init":
            command.append(f"-o{request['idb_path']}")
        command.extend((f"-S{script}", str(input_path)))
        try:
            completed = subprocess.run(
                command, env=environment, cwd=str(db_path.parent), capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=timeout or None, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"IDA batch operation exceeded {timeout} seconds") from exc

    if db_path.is_file():
        with closing(connect(db_path)) as connection:
            result = operation(connection, request_id)
        if result is not None:
            if result["status"] == "ok" and completed.returncode == 0:
                return result["result"]
            if result["status"] == "error":
                raise RuntimeError(result["error"] or "IDA operation failed")
    details = "\n".join(part for part in (completed.stdout[-4000:], completed.stderr[-4000:]) if part)
    raise RuntimeError(f"IDA exited with code {completed.returncode} without a successful result. {details}")

"""Launch IDA in batch mode and collect structured results from SQLite."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

from .db import connect, get_metadata, operation


def attach_idb(db_path, source, *, destination=None, reuse=False, **options):
    """Attach a supplied IDB without needing the original input binary."""
    from .db import set_metadata
    db_path = Path(db_path).expanduser().resolve()
    source = Path(source).expanduser().resolve()
    target = Path(destination or db_path.with_suffix(source.suffix)).expanduser().resolve()
    if not source.is_file() or source.suffix.lower() not in {'.i64','.idb'}:
        raise ValueError('source must be an existing .i64 or .idb file')
    if db_path.exists():
        raise FileExistsError('analysis database already exists; use sync for an attached database')
    if reuse:
        if destination is not None:
            raise ValueError('--reuse-idb cannot be combined with --idb')
        target = source
    elif target == source:
        raise ValueError('copy destination must differ from source; use --reuse-idb explicitly')
    if db_path in (source,target):
        raise ValueError('SQLite database must differ from IDB paths')
    # Resolve the executable before creating any output.
    find_idat(options.get('idat'))
    target.parent.mkdir(parents=True,exist_ok=True)
    if not reuse:
        with source.open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src,dst,1 << 20)
    with closing(connect(db_path)) as connection:
        set_metadata(connection,{'idb_path':str(target),'attached_source':str(source)})
        connection.commit()
    result = run_ida('sync',db_path,**options)
    return dict(result,db_path=str(db_path),idb_path=str(target),copied=not reuse,
                original_binary_required=False)


class _ProgressMonitor:
    def __init__(self, path, action):
        self.path,self.action = path,action
        self.stop = threading.Event()
        self.offset = 0
        self.started = time.monotonic()
        self.last = self.started
        self.thread = threading.Thread(target=self.watch,daemon=True)

    def drain(self):
        if self.path.exists():
            with self.path.open(encoding='utf-8') as stream:
                stream.seek(self.offset)
                while True:
                    position = stream.tell()
                    line = stream.readline()
                    if not line or not line.endswith("\n"):
                        stream.seek(position)
                        break
                    try:
                        item=json.loads(line)
                    except json.JSONDecodeError:
                        break
                    print(json.dumps(dict(event='ida_progress',action=self.action,**item)),file=sys.stderr,flush=True)
                self.offset=stream.tell()

    def watch(self):
        while not self.stop.wait(.25):
            self.drain()
            now=time.monotonic()
            if now-self.last>=15:
                print(json.dumps(dict(event='ida_wait',action=self.action,elapsed_seconds=round(now-self.started))),file=sys.stderr,flush=True)
                self.last=now

    def __enter__(self):
        print(json.dumps(dict(event='ida_start',action=self.action)),file=sys.stderr,flush=True)
        self.thread.start()
        return self

    def __exit__(self,*args):
        self.stop.set()
        self.thread.join()
        self.drain()


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
    request = {
        "request_id": request_id,
        "action": action,
        "db_path": str(db_path),
        # IDA's normal qexit path can re-save an otherwise read-only database.
        # The range command terminates after publishing its SQLite operation so
        # that the source IDB remains byte-for-byte unchanged.
        "exit_without_save": action == "disasm_range",
        **payload,
    }
    script = Path(__file__).with_name("ida_entry.py").resolve()
    environment = os.environ.copy()
    project_root = str(script.parent.parent)
    environment["PYTHONPATH"] = project_root + os.pathsep + environment.get("PYTHONPATH", "")
    with tempfile.TemporaryDirectory(prefix="ida-ai-") as temporary:
        request_file = Path(temporary) / "request.json"
        request_file.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
        environment["IDA_AI_REQUEST"] = str(request_file)
        environment['IDA_AI_PROGRESS'] = str(Path(temporary)/'progress.jsonl')
        command = [str(find_idat(idat)), "-A"]
        if action == "init":
            command.append(f"-o{request['idb_path']}")
        command.extend((f"-S{script}", str(input_path)))
        try:
            with _ProgressMonitor(Path(environment['IDA_AI_PROGRESS']), action):
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
                value = result["result"]
                if action in {"init", "sync", "export_view", "export_batch", "mutate", "write", "vtable_build", "pointer_scan", "discover"}:
                    # The IDA entrypoint publishes a complete DB snapshot before
                    # recording success. Review evidence only after that commit,
                    # regardless of whether the caller is CLI, MCP, or Python.
                    from .jobs import check_jobs

                    with closing(connect(db_path)) as connection:
                        value["job_review"] = check_jobs(connection, apply=True)
                return value
            if result["status"] == "error":
                raise RuntimeError(result["error"] or "IDA operation failed")
    details = "\n".join(part for part in (completed.stdout[-4000:], completed.stderr[-4000:]) if part)
    raise RuntimeError(f"IDA exited with code {completed.returncode} without a successful result. {details}")

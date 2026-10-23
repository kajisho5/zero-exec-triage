"""Append-only audit log (JSONL with a hash chain).

The prev_hash of each record is the SHA-256 of the previous line (its bytes without the newline); null for the first line.
It is a separate file from the ZES and GER logs, with its own retention.
Before appending, the link at the end is checked (the last line is a JSON object, its prev_hash matches the line
before it, and the file ends with a newline). When it is broken nothing is appended (valid records after a broken
chain would make the damage less visible). The whole chain is verified with zet verify-log (verify_chain).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

from .core import VERSION


def log_dir() -> Path:
    d = os.environ.get("ZET_LOG_DIR")
    if d:
        return Path(d)
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "zet"


def log_path() -> Path:
    return log_dir() / "zet-audit.jsonl"


class BrokenChain(OSError):
    """The hash chain of the audit log is broken at the end, so nothing is appended."""


def ensure_writable() -> None:
    """Do nothing that cannot be recorded. Create the directory and check that it is writable first."""
    d = log_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.stat(d)
    # in a directory that others can write, the log can be replaced or deleted (existing directories are checked too)
    if st.st_uid != os.geteuid():
        raise PermissionError(f"the audit log directory is not owned by the current user: {d}")
    if st.st_mode & 0o022:
        raise PermissionError(f"the audit log directory is writable by group or others: {d}")
    if not os.access(d, os.W_OK):
        raise PermissionError(f"cannot write the audit log: {d}")
    p = log_path()
    try:  # detect a log that cannot take a record before doing anything (checked again under the lock when appending)
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    except OSError as e:
        raise PermissionError(f"cannot open the audit log (symbolic link or similar): {p} ({e.strerror})") from None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PermissionError(f"the audit log is not a regular file: {p}")
        _check_tail(f)


def _last_lines(f, n: int = 2) -> tuple[list[bytes], bool]:
    """The last n lines (oldest first) and whether the file ends with a newline. Does not read the whole file."""
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return [], True
    f.seek(end - 1)
    ends_nl = f.read(1) == b"\n"
    pos, buf = end, b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        lines = buf.rstrip(b"\n").split(b"\n")
        if len(lines) > n or pos == 0:
            return lines[-n:], ends_nl
    return [], ends_nl


def _parse(line: bytes) -> dict | None:
    try:
        rec = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return None
    return rec if isinstance(rec, dict) else None


def _link(prev: bytes | None) -> str | None:
    return None if prev is None else "sha256:" + hashlib.sha256(prev).hexdigest()


def _check_tail(f) -> bytes | None:
    """Check the link at the end and return the last line (None when empty). BrokenChain when it is broken."""
    lines, ends_nl = _last_lines(f, 2)
    if not lines:
        return None
    last = lines[-1]
    rec = _parse(last)
    prev = lines[-2] if len(lines) == 2 else None
    if not ends_nl:
        why = "the last line does not end with a newline (a write may have been cut off)"
    elif rec is None:
        why = "the last line is not a JSON object"
    elif rec.get("prev_hash") != _link(prev):
        why = "prev_hash of the last line does not match the line before it"
    else:
        return last
    raise BrokenChain(f"the hash chain of the audit log is broken at the end, so nothing is appended ({why}). "
                      f"Check it with zet verify-log and move the log aside before running again: {log_path()}")


def append(record: dict) -> dict:
    """Append under an exclusive lock with the hash of the previous line. Existing lines are never changed."""
    ensure_writable()
    p = log_path()
    # O_NOFOLLOW: never write to a log that was replaced by a symbolic link (fail-closed)
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            last = _check_tail(f)  # check again under the lock (never append after a broken end or a line that was cut off)
            rec = {"skill": "zet", "version": VERSION, **record, "prev_hash": _link(last)}
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            f.seek(0, os.SEEK_END)
            f.write(line + b"\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return rec


def verify_chain(path: Path | None = None) -> list[str]:
    """Return the places where the chain is broken (empty when it is intact)."""
    return scan_chain(path)[1]


def scan_chain(path: Path | None = None) -> tuple[int, list[str]]:
    """(number of records, list of broken places). The chain is intact when the list is empty. (0, []) when there is no file."""
    p = path or log_path()
    if not p.exists():
        return 0, []
    problems: list[str] = []
    prev: bytes | None = None
    n = 0
    with open(p, "rb") as f:
        for n, raw in enumerate(f, 1):
            line = raw.rstrip(b"\n")
            if not raw.endswith(b"\n"):
                problems.append(f"line {n}: does not end with a newline (a write may have been cut off)")
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                problems.append(f"line {n}: not JSON")
                prev = line
                continue
            if not isinstance(rec, dict):  # lines with an array, a string and so on are reported too (no exception)
                problems.append(f"line {n}: not a JSON object")
                prev = line
                continue
            if rec.get("prev_hash") != _link(prev):
                problems.append(f"line {n}: prev_hash mismatch")
            prev = line
    return n, problems

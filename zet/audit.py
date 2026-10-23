"""追記専用の監査ログ（JSONL、ハッシュチェーン付き）。

各レコードの prev_hash は直前の行（改行を除くバイト列）の SHA-256。最初の行は null。
ZES・GER とは別ファイル・別リテンションで運用する。
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
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


def ensure_writable() -> None:
    """記録できない操作はしない。ディレクトリ作成と書き込み可否を事前に確かめる。"""
    d = log_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.stat(d)
    # 他人が書けるディレクトリではログの差し替え・削除を防げない（既存ディレクトリも検査する）
    if st.st_uid != os.geteuid():
        raise PermissionError(f"監査ログのディレクトリの所有者が実行ユーザーではありません: {d}")
    if st.st_mode & 0o022:
        raise PermissionError(f"監査ログのディレクトリがグループ・他者から書き込み可能です: {d}")
    if not os.access(d, os.W_OK):
        raise PermissionError(f"監査ログに書き込めません: {d}")


def _last_line(f) -> bytes | None:
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return None
    pos, buf = end, b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        lines = buf.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or pos == 0:
            return lines[-1]
    return None


def append(record: dict) -> dict:
    """排他ロックの下で直前行のハッシュを付けて追記する。既存行は変更しない。"""
    ensure_writable()
    p = log_path()
    # O_NOFOLLOW: シンボリックリンクにされたログには書かない（fail-closed）
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            last = _last_line(f)
            rec = {"skill": "zet", "version": VERSION, **record,
                   "prev_hash": None if last is None else "sha256:" + hashlib.sha256(last).hexdigest()}
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            f.seek(0, os.SEEK_END)
            if f.tell() > 0:
                f.seek(-1, os.SEEK_END)
                if f.read(1) != b"\n":  # 途中で切れた行に連結しないよう、先に改行を補う
                    line = b"\n" + line
            f.write(line + b"\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return rec


def verify_chain(path: Path | None = None) -> list[str]:
    """チェーンの破損箇所を返す（空なら健全）。"""
    p = path or log_path()
    if not p.exists():
        return []
    problems: list[str] = []
    prev: bytes | None = None
    with open(p, "rb") as f:
        for n, raw in enumerate(f, 1):
            line = raw.rstrip(b"\n")
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"line {n}: JSON ではありません")
                prev = line
                continue
            want = None if prev is None else "sha256:" + hashlib.sha256(prev).hexdigest()
            if rec.get("prev_hash") != want:
                problems.append(f"line {n}: prev_hash 不一致")
            prev = line
    return problems

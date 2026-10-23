"""追記専用の監査ログ（JSONL、ハッシュチェーン付き）。

各レコードの prev_hash は直前の行（改行を除くバイト列）の SHA-256。最初の行は null。
ZES・GER とは別ファイル・別リテンションで運用する。
追記の前に末尾の連結（最終行が JSON object で、その prev_hash が直前の行と一致し、改行で終わること）を
確かめ、壊れていれば追記しない（壊れたチェーンの後ろに正しい記録を足して破損を目立たなくしない）。
全体の検証は zet verify-log（verify_chain）で行う。
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
    """監査ログのハッシュチェーンが末尾で壊れているため追記しない。"""


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
    p = log_path()
    try:  # 何かする前に、記録を足せないログを検出する（追記時にもロックの下で再確認する）
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    except OSError as e:
        raise PermissionError(f"監査ログを開けません（シンボリックリンクなど）: {p}（{e.strerror}）") from None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PermissionError(f"監査ログが通常ファイルではありません: {p}")
        _check_tail(f)


def _last_lines(f, n: int = 2) -> tuple[list[bytes], bool]:
    """末尾の n 行（古い順）と、ファイルが改行で終わっているか。ファイル全体は読まない。"""
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
    """末尾の連結を確かめて最終行を返す（空なら None）。壊れていれば BrokenChain。"""
    lines, ends_nl = _last_lines(f, 2)
    if not lines:
        return None
    last = lines[-1]
    rec = _parse(last)
    prev = lines[-2] if len(lines) == 2 else None
    if not ends_nl:
        why = "最終行が改行で終わっていません（書き込みが途中で切れた可能性）"
    elif rec is None:
        why = "最終行が JSON object ではありません"
    elif rec.get("prev_hash") != _link(prev):
        why = "最終行の prev_hash が直前の行と一致しません"
    else:
        return last
    raise BrokenChain(f"監査ログのハッシュチェーンが末尾で壊れているため追記しません（{why}）。"
                      f"zet verify-log で確認し、ログを退避してから実行してください: {log_path()}")


def append(record: dict) -> dict:
    """排他ロックの下で直前行のハッシュを付けて追記する。既存行は変更しない。"""
    ensure_writable()
    p = log_path()
    # O_NOFOLLOW: シンボリックリンクにされたログには書かない（fail-closed）
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            last = _check_tail(f)  # ロックの下で再確認（壊れた末尾・途中で切れた行の後ろには追記しない）
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
    """チェーンの破損箇所を返す（空なら健全）。"""
    return scan_chain(path)[1]


def scan_chain(path: Path | None = None) -> tuple[int, list[str]]:
    """(レコード数, 破損箇所の一覧)。一覧が空なら健全。ファイルが無ければ (0, [])。"""
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
                problems.append(f"line {n}: 改行で終わっていません（書き込みが途中で切れた可能性）")
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                problems.append(f"line {n}: JSON ではありません")
                prev = line
                continue
            if not isinstance(rec, dict):  # 配列・文字列などの行も報告する（例外にしない）
                problems.append(f"line {n}: JSON object ではありません")
                prev = line
                continue
            if rec.get("prev_hash") != _link(prev):
                problems.append(f"line {n}: prev_hash 不一致")
            prev = line
    return n, problems

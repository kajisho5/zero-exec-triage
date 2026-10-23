"""ZET の共通部品: 時刻、正規化 JSON、ハッシュ、スキーマ読み込み、原子的書き出し。"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any

from .jsonschema_lite import Validator

VERSION = "0.1.0"
ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"

LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DECISIONS = ("remediate", "exception", "defer")
RISKY_EFFECTS = ("exec", "network", "secrets")
# 操作種別ごとの可逆性（A-4）。未知の種別は不可逆として扱う（安全側）
REVERSIBLE_BY_TYPE = {"chmod": True, "write_config": False, "rotate_secret": False}


class ContractError(Exception):
    """入力・計画が契約に違反している（終了コード 3）。"""

    def __init__(self, violations: list["Violation"]):
        super().__init__("; ".join(f"{v.code}: {v.message}" for v in violations))
        self.violations = violations


class Violation:
    __slots__ = ("code", "finding_id", "message")

    def __init__(self, code: str, message: str, finding_id: str | None = None):
        self.code, self.message, self.finding_id = code, message, finding_id

    def as_dict(self) -> dict:
        return {"code": self.code, "finding_id": self.finding_id, "message": self.message}

    def __repr__(self) -> str:
        return f"Violation({self.code!r}, {self.message!r}, {self.finding_id!r})"


# --- 時刻（RFC 3339 UTC, 秒精度） -------------------------------------------
def parse_ts(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def fmt_ts(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc(override: str | None) -> dt.datetime:
    if override:
        return parse_ts(override)
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


# --- 正規化 JSON / ハッシュ ------------------------------------------------
def canonical(obj: Any) -> bytes:
    """キー順ソート・区切り ',' ':'・UTF-8。plan_hash と input_hash の基準（GER と同一定義）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def plan_hash(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k != "plan_hash"}
    return sha256(canonical(body))


# --- 入出力 ------------------------------------------------------------------
def load_json(path: str) -> Any:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float,
                         object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
        raise ContractError([Violation("I-11", f"{path}: JSON として解析できません（{e}）")]) from e
    except RecursionError:
        raise ContractError([Violation("I-11", f"{path}: JSON の入れ子が深すぎます")]) from None
    try:
        canonical(obj)
    except RecursionError:
        raise ContractError([Violation("I-11", f"{path}: JSON の入れ子が深すぎます")]) from None
    except (UnicodeEncodeError, ValueError):
        # 対になっていないサロゲート（\ud800 など）は正規化 JSON にできない。内容は表示しない
        raise ContractError([Violation("I-11", f"{path}: UTF-8 で表せない文字列（不正なサロゲート）を含みます")]) from None
    return obj


def _reject_constant(name: str) -> Any:
    raise ValueError(f"非標準の JSON 定数 {name} は受け付けません")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    # 重複キーは後勝ちで黙って消える（読む側ごとに解釈が割れる）ため拒否する。キー名は表示しない
    d: dict = {}
    for k, val in pairs:
        if k in d:
            raise ValueError("重複したキーがあります")
        d[k] = val
    return d


def _finite_float(s: str) -> float:
    x = float(s)
    if not math.isfinite(x):  # 1e400 など。書き出すと Infinity（不正な JSON）になる
        raise ValueError("有限でない数値は受け付けません")
    return x


def dumps_pretty(obj: Any) -> str:
    """出力ファイル・標準出力の書式。深すぎる入れ子は RecursionError、有限でない数値は ValueError。"""
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


def write_atomic(path: str, obj: Any) -> None:
    write_text_atomic(path, dumps_pretty(obj))


def write_text_atomic(path: str, text: str) -> None:
    """一時ファイルに書いてから os.replace。途中で失敗しても部分ファイルを残さない。"""
    d = os.path.dirname(path) or "."  # -o の事前検査（cli._output_problem）と同じ親ディレクトリ
    fd, tmp = tempfile.mkstemp(prefix=".zet-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


_validators: dict[str, Validator] = {}


def validator(name: str) -> Validator:
    if name not in _validators:
        with open(SCHEMAS / name, encoding="utf-8") as f:
            _validators[name] = Validator(json.load(f))
    return _validators[name]


def schema_violations(name: str, instance: Any, label: str) -> list[Violation]:
    return [Violation("I-11", f"{label}{e}") for e in validator(name).errors(instance)]

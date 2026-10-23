"""Shared parts of ZET: time, canonical JSON, hashes, schema loading, atomic writes."""
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
# SkillPact 0.8 effects that can cause external side effects or code execution (the same set as GER's G-6; keep it equal
# to ger/core.py). read (includes reading sensitive files; formerly secrets) and write (includes writing outside the
# workspace; formerly persist) are not included on their own
RISKY_EFFECTS = ("exec", "network", "spend", "send")
# Reversibility per operation type (A-4). Unknown types are treated as irreversible (the conservative side). Every GER
# operation is reversible (none deletes anything; the state before the change stays in GER's quarantine store, and
# checklist does not change files)
REVERSIBLE_BY_TYPE = {"chmod": True, "quarantine": True, "edit_json": True, "edit_toml": True, "remove_line": True,
                      "disable_mcp_server": True, "checklist": True, "write_config": False, "rotate_secret": False}
# Types in GER's operation registry (REGISTRY in ger/actions/__init__.py). GER rejects any other type in G-5 (I-4)
GER_ACTION_TYPES = frozenset({"chmod", "quarantine", "edit_json", "edit_toml", "remove_line", "disable_mcp_server",
                              "checklist"})
# Operations that change files (everything except checklist)
FS_CHANGING = GER_ACTION_TYPES - {"checklist"}
PLAN_SCHEMA_VERSION = "1.1"
MAX_DEPTH = 64  # the same nesting limit as GER (ger/core.py). Do not finalize a document that GER cannot read (I-11)


class ContractError(Exception):
    """The input or the plan violates the contract (exit code 3)."""

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


# --- Time (RFC 3339 UTC, second precision) ------------------------------------
def parse_ts(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def fmt_ts(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc(override: str | None) -> dt.datetime:
    if override:
        return parse_ts(override)
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


# --- Canonical JSON / hashes ---------------------------------------------------
def canonical(obj: Any) -> bytes:
    """Sorted keys, separators ',' ':', UTF-8. The basis of plan_hash and input_hash (the same definition as GER)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def plan_hash(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k != "plan_hash"}
    return sha256(canonical(body))


# --- Input and output ------------------------------------------------------------
def load_json(path: str) -> Any:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float,
                         object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
        raise ContractError([Violation("I-11", f"{path}: cannot be parsed as JSON ({e})")]) from e
    except RecursionError:
        raise ContractError([Violation("I-11", f"{path}: JSON is nested too deeply")]) from None
    if _too_deep(obj):
        raise ContractError([Violation("I-11", f"{path}: JSON is nested too deeply (maximum depth: {MAX_DEPTH})")])
    try:
        canonical(obj)
    except RecursionError:
        raise ContractError([Violation("I-11", f"{path}: JSON is nested too deeply")]) from None
    except (UnicodeEncodeError, ValueError):
        # an unpaired surrogate (\ud800 and so on) cannot be canonical JSON. The content is not shown
        raise ContractError([Violation("I-11", f"{path}: contains a string that UTF-8 cannot represent (invalid surrogate)")]) from None
    return obj


def _too_deep(obj: Any) -> bool:
    """Counts like GER's _check_depth (the top-level object / array is depth 1). Not recursive."""
    stack = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, (dict, list)):
            if depth > MAX_DEPTH:
                return True
            stack.extend((x, depth + 1) for x in (cur.values() if isinstance(cur, dict) else cur))
    return False


def _reject_constant(name: str) -> Any:
    raise ValueError(f"the non-standard JSON constant {name} is not accepted")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    # with duplicate keys the last one silently wins (readers disagree on the meaning), so they are rejected. The key is not shown
    d: dict = {}
    for k, val in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = val
    return d


def _finite_float(s: str) -> float:
    x = float(s)
    if not math.isfinite(x):  # 1e400 and so on. Written out it would be Infinity (invalid JSON)
        raise ValueError("non-finite numbers are not accepted")
    return x


def dumps_pretty(obj: Any) -> str:
    """Format of output files and standard output. RecursionError for nesting that is too deep, ValueError for non-finite numbers."""
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


def write_atomic(path: str, obj: Any) -> None:
    write_text_atomic(path, dumps_pretty(obj))


def write_text_atomic(path: str, text: str) -> None:
    """Write a temporary file, then os.replace. A failure part-way leaves no partial file."""
    d = os.path.dirname(path) or "."  # the same parent directory as the -o pre-check (cli._output_problem)
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

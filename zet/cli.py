"""The zet command.

  zet validate <triage-input.json> --operator NAME
  zet draft    <triage-input.json> --operator NAME [--plan-id UUID] [-o OUT]
  zet check    <triage-input.json> <plan.json> --operator NAME
  zet finalize <triage-input.json> <plan.json> --operator NAME -o OUT
  zet verify-log [LOG]          verify the hash chain of the audit log (read only; not recorded in the audit log)

Exit codes: 0 = passed / 3 = contract violation (for verify-log: broken chain) / 64 = argument or environment error / 70 = internal error
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys

from pathlib import Path

from . import audit, triage
from .core import ContractError, canonical, dumps_pretty, fmt_ts, load_json, now_utc, sha256, write_text_atomic
from .jsonschema_lite import safe_text

EXIT_OK, EXIT_CONTRACT, EXIT_USAGE, EXIT_INTERNAL = 0, 3, 64, 70
_PERSON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # always exit with 64
        self.print_usage(sys.stderr)
        _err(f"zet: {message}")
        sys.exit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="zet", description="ZET — Zero-Exec Triage (decision layer)")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("verify-log", help="verify the hash chain of the audit log")
    s.add_argument("log", nargs="?", help="the log to verify (default: $ZET_LOG_DIR/zet-audit.jsonl)")
    for name, plan in (("validate", False), ("draft", False), ("check", True), ("finalize", True)):
        s = sub.add_parser(name)
        s.add_argument("input")
        if plan:
            s.add_argument("plan")
        s.add_argument("--operator", required=True, help="who runs the command (recorded in the audit log; must be given explicitly)")
        s.add_argument("--now", help="override the current time (RFC 3339 UTC; for tests only: needs ZET_ALLOW_NOW_OVERRIDE=1)")
        if name == "draft":
            s.add_argument("--plan-id")
            s.add_argument("-o", "--output")
        if name == "finalize":
            s.add_argument("-o", "--output", required=True)
    return p


def _err(text: str) -> None:
    """To standard error. Control characters are escaped, because the text can contain strings from the input (keys, paths, exception messages)."""
    print(safe_text(text), file=sys.stderr)


def _report(violations) -> None:
    for v in violations:
        fid = f" [{v.finding_id}]" if v.finding_id else ""
        _err(f"  {v.code}{fid}: {v.message}")


def _verify_log(path: str | None) -> int:
    p = Path(path) if path else audit.log_path()
    try:
        n, problems = audit.scan_chain(p)
    except OSError as e:
        _err(f"zet verify-log: cannot read the audit log ({e})")
        return EXIT_USAGE
    if not p.exists():
        _err(f"zet verify-log: no audit log: {p}")
        return EXIT_USAGE
    if problems:
        _err(f"zet verify-log: the hash chain is broken (problems: {len(problems)}, lines: {n}): {p}")
        for x in problems:
            _err(f"  {x}")
        return EXIT_CONTRACT
    _err(f"zet verify-log: OK (records: {n}, the hash chain is intact): {p}")
    return EXIT_OK


def _output_problem(out: str, sources: list[str]) -> str | None:
    """Pre-check of -o. Rejects an output that cannot be written before any processing (and before the audit record)."""
    if not out:
        return "-o is empty"
    try:
        if os.path.isdir(out):
            return f"-o is a directory: {out}"
        if out.endswith(("/", os.sep)):  # a trailing / after a missing directory or after a file would only fail when writing
            return f"-o cannot end with /: {out}"
        if os.path.exists(out) and not os.path.isfile(out):
            return f"-o is not a regular file: {out}"  # /dev/full and so on. Never replaced with os.replace
        # check the parent as given (abspath would hide that nd is missing in nd/../x)
        parent = os.path.dirname(out) or "."
        if not os.path.isdir(parent):
            return f"the directory of -o does not exist: {parent}"
        if not os.access(parent, os.W_OK | os.X_OK):
            return f"cannot write to the directory of -o: {parent}"
        for src in sources:
            if os.path.realpath(out) == os.path.realpath(src) or (
                    os.path.exists(out) and os.path.exists(src) and os.path.samefile(out, src)):
                return f"-o is the same as an input file: {out}"
        # replacing the audit log (or its directory) with the output would break the hash chain
        log, logd = os.path.realpath(audit.log_path()), os.path.realpath(audit.log_dir())
        if os.path.realpath(out) == log or (
                os.path.exists(out) and os.path.exists(log) and os.path.samefile(out, log)):
            return f"-o cannot be the audit log: {out}"
        for p in (os.path.realpath(out), os.path.realpath(parent)):
            if p == logd or os.path.commonpath([p, logd]) == logd:
                return f"-o cannot be inside the audit log directory: {out}"
    except (OSError, ValueError) as e:  # ValueError: the path contains NUL
        return f"cannot check -o ({e})"
    return None


def _discard_stdout() -> None:
    """Do not flush a standard output buffer that could not be written again at exit (avoids an exception at exit and exit code 120)."""
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, sys.stdout.fileno())
        os.close(fd)
    except (OSError, ValueError):
        pass


def _harden_streams() -> None:
    """No UnicodeEncodeError for human-readable messages in a non-UTF-8 locale (the encoding is not changed)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):  # replacements such as StringIO
            pass


def _write_stdout(text: str) -> None:
    """Machine-readable JSON is written as UTF-8 bytes whatever the locale (because of ensure_ascii=False)."""
    buf = getattr(sys.stdout, "buffer", None)
    if buf is None:  # replaced with a text stream, for example in tests
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    sys.stdout.flush()
    buf.write(text.encode("utf-8"))
    buf.flush()


def main(argv: list[str] | None = None) -> int:
    _harden_streams()
    args = _parser().parse_args(argv)
    if args.command == "verify-log":
        return _verify_log(args.log)
    if not _PERSON.fullmatch(args.operator):
        _err("zet: invalid --operator")
        return EXIT_USAGE
    if getattr(args, "plan_id", None) and not _UUID.fullmatch(args.plan_id):
        _err("zet: --plan-id must be a UUID (lowercase)")
        return EXIT_USAGE
    if args.now is not None and os.environ.get("ZET_ALLOW_NOW_OVERRIDE") != "1":
        # --now can move the upper bound of I-9 (decided_at <= current time), so it is not accepted in production
        _err("zet: --now is for tests only (it works only with ZET_ALLOW_NOW_OVERRIDE=1)")
        return EXIT_USAGE
    try:
        now = now_utc(args.now)
        now + dt.timedelta(days=triage.MAX_DAYS)  # reject a time for which the deadline calculation would be out of range
    except (ValueError, OverflowError):
        _err("zet: --now must have the form YYYY-MM-DDTHH:MM:SSZ")
        return EXIT_USAGE
    try:
        audit.ensure_writable()
    except OSError as e:
        _err(f"zet: {e} (not run, because it cannot be recorded)")
        return EXIT_USAGE
    out = getattr(args, "output", None)
    if out is not None:
        problem = _output_problem(out, [args.input] + ([args.plan] if hasattr(args, "plan") else []))
        if problem:
            _err(f"zet: {problem}")
            return EXIT_USAGE

    started = fmt_ts(now_utc(None))
    record = {"command": args.command, "operator": args.operator, "started_at": started}
    if args.now is not None:
        record["now_override"] = True
    output_obj = None
    violations = []
    code = EXIT_OK
    try:
        inp = load_json(args.input)
        record["input_hash"] = sha256(canonical(inp))
        if args.command == "validate":
            violations = triage.validate_input(inp)
        elif args.command == "draft":
            output_obj = triage.draft(inp, now, args.operator, args.plan_id, now_override=args.now is not None)
        else:
            plan = load_json(args.plan)
            record["plan_input_hash"] = sha256(canonical(plan))
            if args.command == "check":
                violations = triage.check(inp, plan, now=now)
            else:
                output_obj = triage.finalize(inp, plan, now=now, now_override=args.now is not None)
    except ContractError as e:
        violations = e.violations
    except OSError as e:
        _err(f"zet: {e}")
        code = EXIT_USAGE
    except Exception as e:  # anything unexpected fails closed (no output)
        # the repr of an exception can contain the whole input document, so only the type name and a short message are shown
        _err(f"zet: internal error: {type(e).__name__}: {str(e)[:200]}")
        code = EXIT_INTERNAL

    if code == EXIT_OK and violations:
        code = EXIT_CONTRACT
        _err(f"zet {args.command}: contract violations: {len(violations)}")
        _report(violations)
        output_obj = None
    # the output is turned into a string first; only when it was written does the audit log get ok and output_hash
    text = out_hash = None
    if code == EXIT_OK and output_obj is not None:
        try:
            text = dumps_pretty(output_obj)
            out_hash = sha256(canonical(output_obj))
        except (RecursionError, ValueError) as e:
            _err(f"zet: cannot turn the output into JSON ({type(e).__name__}; the nesting may be too deep)")
            code = EXIT_INTERNAL
    written = False
    if code == EXIT_OK and text is not None:
        try:
            if out:
                write_text_atomic(out, text)
            else:
                _write_stdout(text)
            written = True
        except OSError as e:
            _err(f"zet: cannot write the output ({e})")
            if not out:
                _discard_stdout()
            code = EXIT_USAGE
    if written:
        record["output_hash"] = out_hash
        if args.command == "finalize":
            record["plan_id"] = output_obj["plan_id"]
            record["plan_hash"] = output_obj["plan_hash"]
    record.update({"finished_at": fmt_ts(now_utc(None)),
                   "result": {EXIT_OK: "ok", EXIT_CONTRACT: "rejected"}.get(code, "error"),
                   "violations": len(violations)})
    try:
        audit.append(record)
    except OSError as e:
        if written and out:
            try:
                os.unlink(out)  # leave no output without a record
            except OSError:
                pass
            _err(f"zet: cannot record in the audit log ({e}). The output was deleted")
        elif written:
            _err(f"zet: cannot record in the audit log ({e}). Do not use what was written to standard output")
        else:
            _err(f"zet: cannot record in the audit log ({e})")
        return EXIT_USAGE
    if code == EXIT_OK:
        _err(f"zet {args.command}: OK")
    return code

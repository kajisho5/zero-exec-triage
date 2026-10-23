"""zet コマンド。

  zet validate <triage-input.json> --operator NAME
  zet draft    <triage-input.json> --operator NAME [--plan-id UUID] [-o OUT]
  zet check    <triage-input.json> <plan.json> --operator NAME
  zet finalize <triage-input.json> <plan.json> --operator NAME -o OUT

終了コード: 0=合格 / 3=契約違反 / 64=引数・環境エラー / 70=内部エラー
"""
from __future__ import annotations

import argparse
import json
import re
import sys

from . import audit, triage
from .core import ContractError, canonical, fmt_ts, load_json, now_utc, sha256, write_atomic

EXIT_OK, EXIT_CONTRACT, EXIT_USAGE, EXIT_INTERNAL = 0, 3, 64, 70
_PERSON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # 終了コードを 64 に統一
        self.print_usage(sys.stderr)
        print(f"zet: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="zet", description="ZET — Zero-Exec Triage（判断層）")
    sub = p.add_subparsers(dest="command", required=True)
    for name, plan in (("validate", False), ("draft", False), ("check", True), ("finalize", True)):
        s = sub.add_parser(name)
        s.add_argument("input")
        if plan:
            s.add_argument("plan")
        s.add_argument("--operator", required=True, help="実行者（監査ログに記録。自己申告ではなく明示指定）")
        s.add_argument("--now", help="現在時刻の上書き（RFC 3339 UTC、テスト用）")
        if name == "draft":
            s.add_argument("--plan-id")
            s.add_argument("-o", "--output")
        if name == "finalize":
            s.add_argument("-o", "--output", required=True)
    return p


def _report(violations) -> None:
    for v in violations:
        fid = f" [{v.finding_id}]" if v.finding_id else ""
        print(f"  {v.code}{fid}: {v.message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not _PERSON.fullmatch(args.operator):
        print("zet: --operator の形式が不正です", file=sys.stderr)
        return EXIT_USAGE
    if getattr(args, "plan_id", None) and not _UUID.fullmatch(args.plan_id):
        print("zet: --plan-id は UUID（小文字）で指定してください", file=sys.stderr)
        return EXIT_USAGE
    try:
        now = now_utc(args.now)
    except ValueError:
        print("zet: --now は YYYY-MM-DDTHH:MM:SSZ 形式で指定してください", file=sys.stderr)
        return EXIT_USAGE
    try:
        audit.ensure_writable()
    except OSError as e:
        print(f"zet: {e}（記録できないため実行しません）", file=sys.stderr)
        return EXIT_USAGE

    started = fmt_ts(now_utc(None))
    record = {"command": args.command, "operator": args.operator, "started_at": started}
    output_obj = None
    violations = []
    code = EXIT_OK
    try:
        inp = load_json(args.input)
        record["input_hash"] = sha256(canonical(inp))
        if args.command == "validate":
            violations = triage.validate_input(inp)
        elif args.command == "draft":
            output_obj = triage.draft(inp, now, args.operator, args.plan_id)
        else:
            plan = load_json(args.plan)
            record["plan_input_hash"] = sha256(canonical(plan))
            if args.command == "check":
                violations = triage.check(inp, plan)
            else:
                output_obj = triage.finalize(inp, plan)
    except ContractError as e:
        violations = e.violations
    except OSError as e:
        print(f"zet: {e}", file=sys.stderr)
        code = EXIT_USAGE
    except Exception as e:  # 想定外は fail-closed（出力しない）
        # 例外の repr は入力文書全体を含みうるため、型名と短いメッセージだけを出す
        print(f"zet: 内部エラー: {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
        code = EXIT_INTERNAL

    if code == EXIT_OK and violations:
        code = EXIT_CONTRACT
        print(f"zet {args.command}: 契約違反 {len(violations)} 件", file=sys.stderr)
        _report(violations)
        output_obj = None
    if code == EXIT_OK and output_obj is not None:
        record["output_hash"] = sha256(canonical(output_obj))
        if args.command == "finalize":
            record["plan_id"] = output_obj["plan_id"]
            record["plan_hash"] = output_obj["plan_hash"]
    record.update({"finished_at": fmt_ts(now_utc(None)),
                   "result": {EXIT_OK: "ok", EXIT_CONTRACT: "rejected"}.get(code, "error"),
                   "violations": len(violations)})
    try:
        audit.append(record)
    except OSError as e:
        print(f"zet: 監査ログに記録できません（{e}）。出力を破棄します", file=sys.stderr)
        return EXIT_USAGE
    if code == EXIT_OK and output_obj is not None:
        out = getattr(args, "output", None)
        if out:
            write_atomic(out, output_obj)
        else:
            json.dump(output_obj, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            sys.stdout.write("\n")
    if code == EXIT_OK:
        print(f"zet {args.command}: OK", file=sys.stderr)
    return code

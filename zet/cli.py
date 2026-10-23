"""zet コマンド。

  zet validate <triage-input.json> --operator NAME
  zet draft    <triage-input.json> --operator NAME [--plan-id UUID] [-o OUT]
  zet check    <triage-input.json> <plan.json> --operator NAME
  zet finalize <triage-input.json> <plan.json> --operator NAME -o OUT

終了コード: 0=合格 / 3=契約違反 / 64=引数・環境エラー / 70=内部エラー
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys

from . import audit, triage
from .core import ContractError, canonical, dumps_pretty, fmt_ts, load_json, now_utc, sha256, write_text_atomic

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
        s.add_argument("--now", help="現在時刻の上書き（RFC 3339 UTC。テスト専用: ZET_ALLOW_NOW_OVERRIDE=1 が必要）")
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


def _output_problem(out: str, sources: list[str]) -> str | None:
    """-o の事前検証。処理（と監査ログの記録）の前に、書き出せない出力先を弾く。"""
    if not out:
        return "-o が空です"
    try:
        if os.path.isdir(out):
            return f"-o がディレクトリです: {out}"
        if out.endswith(("/", os.sep)):  # 存在しないディレクトリ・ファイルの後ろの / は書き出し時まで失敗しない
            return f"-o の末尾に / は付けられません: {out}"
        if os.path.exists(out) and not os.path.isfile(out):
            return f"-o が通常ファイルではありません: {out}"  # /dev/full など。os.replace で置き換えない
        # 親は与えられたパスのまま調べる（abspath は nd/../x の nd が無いことを隠す）
        parent = os.path.dirname(out) or "."
        if not os.path.isdir(parent):
            return f"-o のディレクトリがありません: {parent}"
        if not os.access(parent, os.W_OK | os.X_OK):
            return f"-o のディレクトリに書き込めません: {parent}"
        for src in sources:
            if os.path.realpath(out) == os.path.realpath(src) or (
                    os.path.exists(out) and os.path.exists(src) and os.path.samefile(out, src)):
                return f"-o が入力ファイルと同じです: {out}"
        # 監査ログ（とそのディレクトリ）を出力で置き換えるとハッシュチェーンが壊れる
        log, logd = os.path.realpath(audit.log_path()), os.path.realpath(audit.log_dir())
        if os.path.realpath(out) == log or (
                os.path.exists(out) and os.path.exists(log) and os.path.samefile(out, log)):
            return f"-o に監査ログは指定できません: {out}"
        for p in (os.path.realpath(out), os.path.realpath(parent)):
            if p == logd or os.path.commonpath([p, logd]) == logd:
                return f"-o に監査ログのディレクトリ内は指定できません: {out}"
    except (OSError, ValueError) as e:  # ValueError: パスに NUL を含む
        return f"-o を検査できません（{e}）"
    return None


def _discard_stdout() -> None:
    """書き出せなかった標準出力のバッファを終了時に再送しない（終了時の例外と終了コード 120 を防ぐ）。"""
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, sys.stdout.fileno())
        os.close(fd)
    except (OSError, ValueError):
        pass


def _harden_streams() -> None:
    """UTF-8 でないロケールでも人向けのメッセージで UnicodeEncodeError を起こさない（符号化方式は変えない）。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):  # StringIO などの差し替え先
            pass


def _write_stdout(text: str) -> None:
    """機械可読な JSON はロケールにかかわらず UTF-8 のバイト列で書く（ensure_ascii=False のため）。"""
    buf = getattr(sys.stdout, "buffer", None)
    if buf is None:  # テストなどで文字列ストリームに差し替えられている
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    sys.stdout.flush()
    buf.write(text.encode("utf-8"))
    buf.flush()


def main(argv: list[str] | None = None) -> int:
    _harden_streams()
    args = _parser().parse_args(argv)
    if not _PERSON.fullmatch(args.operator):
        print("zet: --operator の形式が不正です", file=sys.stderr)
        return EXIT_USAGE
    if getattr(args, "plan_id", None) and not _UUID.fullmatch(args.plan_id):
        print("zet: --plan-id は UUID（小文字）で指定してください", file=sys.stderr)
        return EXIT_USAGE
    if args.now is not None and os.environ.get("ZET_ALLOW_NOW_OVERRIDE") != "1":
        # --now は I-9 の「decided_at <= 現在時刻」の上限を動かせるため、本番では受け付けない
        print("zet: --now はテスト専用です（ZET_ALLOW_NOW_OVERRIDE=1 のときだけ使えます）", file=sys.stderr)
        return EXIT_USAGE
    try:
        now = now_utc(args.now)
        now + dt.timedelta(days=triage.MAX_DAYS)  # 期限の計算が範囲外になる時刻は受け付けない
    except (ValueError, OverflowError):
        print("zet: --now は YYYY-MM-DDTHH:MM:SSZ 形式で指定してください", file=sys.stderr)
        return EXIT_USAGE
    try:
        audit.ensure_writable()
    except OSError as e:
        print(f"zet: {e}（記録できないため実行しません）", file=sys.stderr)
        return EXIT_USAGE
    out = getattr(args, "output", None)
    if out is not None:
        problem = _output_problem(out, [args.input] + ([args.plan] if hasattr(args, "plan") else []))
        if problem:
            print(f"zet: {problem}", file=sys.stderr)
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
            output_obj = triage.draft(inp, now, args.operator, args.plan_id)
        else:
            plan = load_json(args.plan)
            record["plan_input_hash"] = sha256(canonical(plan))
            if args.command == "check":
                violations = triage.check(inp, plan, now=now)
            else:
                output_obj = triage.finalize(inp, plan, now=now)
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
    # 出力は先に文字列にしてから書き出し、書き出せた場合だけ監査ログに ok と output_hash を残す
    text = out_hash = None
    if code == EXIT_OK and output_obj is not None:
        try:
            text = dumps_pretty(output_obj)
            out_hash = sha256(canonical(output_obj))
        except (RecursionError, ValueError) as e:
            print(f"zet: 出力を JSON にできません（{type(e).__name__}。入れ子が深すぎる可能性があります）", file=sys.stderr)
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
            print(f"zet: 出力を書き出せません（{e}）", file=sys.stderr)
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
                os.unlink(out)  # 記録の無い出力を残さない
            except OSError:
                pass
            print(f"zet: 監査ログに記録できません（{e}）。出力を削除しました", file=sys.stderr)
        elif written:
            print(f"zet: 監査ログに記録できません（{e}）。標準出力の内容は使わないでください", file=sys.stderr)
        else:
            print(f"zet: 監査ログに記録できません（{e}）", file=sys.stderr)
        return EXIT_USAGE
    if code == EXIT_OK:
        print(f"zet {args.command}: OK", file=sys.stderr)
    return code

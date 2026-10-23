"""ZET のテスト。標準ライブラリの unittest のみ（jsonschema は判定一致の確認にだけ任意で使う）。"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import errno
import os
import posixpath
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from zet import audit, cli, triage
from zet.core import (
    ROOT,
    ContractError,
    canonical,
    load_json,
    parse_ts,
    plan_hash,
    validator,
    write_atomic,
)

FIX = ROOT / "tests" / "fixtures"
NOW = parse_ts("2026-10-22T10:00:00Z")


def setUpModule():
    os.environ["ZET_ALLOW_NOW_OVERRIDE"] = "1"  # --now はテスト専用


def tearDownModule():
    os.environ.pop("ZET_ALLOW_NOW_OVERRIDE", None)


def load(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def make_input(findings: str = "findings-skillpact.json") -> dict:
    return {
        "schema_version": "1.0",
        "findings": load(findings),
        "policy": {"deadlines": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 90},
                   "decision_window_days": 14, "approvers": ["security-lead", "platform-owner", "alice"]},
        "skillpact_policy": {"l3_trusted": False},
    }


def fill(inp: dict, plan: dict) -> dict:
    """下書きを「全件 remediate（できないものは defer）」で埋めた合格計画にする。

    action.target は finding の path（I-4）。path が null、または他の finding と path が重なるもの
    （同じ対象への操作は 1 件まで）は defer にする。
    """
    by_id = {x["id"]: x for x in inp["findings"]["findings"]}
    p = copy.deepcopy(plan)
    paths = [by_id[it["finding_id"]]["path"] for it in p["items"]]
    for it in p["items"]:
        x = by_id[it["finding_id"]]
        if it["decision"] is None:
            if x["path"] is not None and paths.count(x["path"]) == 1:
                it["decision"] = "remediate"
                it["owner"] = "team-a"
                it["action"] = {"type": "chmod", "target": x["path"], "params": {"mode": "0600"}}
            else:
                it["decision"] = "defer"
                it["reason"] = "target shared with another finding"
                it["due_at"] = None
        it["decided_by"] = it["decided_by"] or "bob"
        it["decided_at"] = it["decided_at"] or "2026-10-22T10:00:00Z"
        if triage.min_approvers(x, it["decision"]) >= 2:
            it["approved_by"] = ["security-lead", "platform-owner"]
    return p


def codes(violations) -> set[str]:
    return {v.code for v in violations}


class TestSchemas(unittest.TestCase):
    def test_vendor_pin(self):
        meta = json.loads((ROOT / "schemas/vendor/VENDOR.json").read_text())
        for f in meta["files"]:
            got = hashlib.sha256((ROOT / f["path"]).read_bytes()).hexdigest()
            self.assertEqual(got, f["sha256"], f"{f['path']} が VENDOR.json の版と一致しません")

    def test_lite_validator_agrees_with_jsonschema(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema 未導入（開発依存）")
        inp = make_input()
        plan = triage.draft(inp, NOW, "alice")
        final = triage.finalize(inp, fill(inp, plan))
        cases = [
            ("vendor/findings.schema.json", load("findings-skillpact.json")),
            ("vendor/findings.schema.json", load("findings-partial.json")),
            ("triage-input.schema.json", inp),
            ("remediation-plan.schema.json", plan),
            ("remediation-plan.schema.json", final),
        ]
        # 壊したもの（各スキーマが拒否すべき）
        bad_plan = copy.deepcopy(final); bad_plan["items"][0]["constraints"] = {"allowed_decisions": [], "min_approvers": 0}
        bad_plan2 = copy.deepcopy(final); del bad_plan2["plan_hash"]
        bad_plan3 = copy.deepcopy(plan); bad_plan3["plan_hash"] = final["plan_hash"]
        bad_plan4 = copy.deepcopy(final); bad_plan4["held"] = [{"finding_id": None, "reason": "x"}]
        bad_in = copy.deepcopy(inp); bad_in["extra"] = 1
        bad_in2 = copy.deepcopy(inp); bad_in2["policy"]["approvers"] = []
        cases += [("remediation-plan.schema.json", b) for b in (bad_plan, bad_plan2, bad_plan3, bad_plan4)]
        cases += [("triage-input.schema.json", b) for b in (bad_in, bad_in2)]
        for name, inst in cases:
            schema = json.loads((ROOT / "schemas" / name).read_text())
            official = Draft202012Validator(schema).is_valid(inst)
            self.assertEqual(validator(name).is_valid(inst), official, name)


class TestValidate(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(triage.validate_input(make_input()), [])

    def test_status_error_rejected(self):
        self.assertIn("I-12", codes(triage.validate_input(make_input("findings-error.json"))))

    def test_l3_trusted_rejected(self):
        inp = make_input(); inp["skillpact_policy"]["l3_trusted"] = True
        self.assertIn("SP", codes(triage.validate_input(inp)))

    def test_unknown_field_rejected(self):
        inp = make_input(); inp["findings"]["findings"][0]["content"] = "secret"
        self.assertIn("I-11", codes(triage.validate_input(inp)))

    def test_findings_schema_version_pinned(self):
        inp = make_input(); inp["findings"]["schema_version"] = "2.0"
        self.assertIn("I-11", codes(triage.validate_input(inp)))


class TestDraft(unittest.TestCase):
    def test_partial_input_holds_errored_module(self):
        inp = make_input("findings-partial.json")
        plan = triage.draft(inp, NOW, "alice")
        self.assertEqual(plan["status"], "draft")
        self.assertIn({"finding_id": None, "module": "§6", "reason": "scan_error:skipped_offline"}, plan["held"])

    def test_info_defaults_to_defer(self):
        inp = make_input("findings-partial.json")
        plan = triage.draft(inp, NOW, "alice")
        ids = {x["id"] for x in inp["findings"]["findings"] if x["level"] == "INFO"}
        infos = [it for it in plan["items"] if it["finding_id"] in ids]
        self.assertTrue(infos)
        for it in infos:
            self.assertEqual((it["decision"], it["reason"], it["decided_by"]), ("defer", "informational", "alice"))

    def test_constraints_and_elevation(self):
        inp = make_input()
        # HIGH の乖離 finding を L3 署名済みにすると CRITICAL 相当に引き上がる
        x = next(f for f in inp["findings"]["findings"] if f.get("skillpact") and f["level"] == "HIGH" and f["skillpact"]["divergence"])
        x["skillpact"]["signed"] = True
        plan = triage.draft(inp, NOW, "alice")
        it = next(i for i in plan["items"] if i["finding_id"] == x["id"])
        self.assertEqual(it["level_effective"], "CRITICAL")
        self.assertNotIn("exception", it["constraints"]["allowed_decisions"])
        self.assertEqual(it["due_at"], "2026-10-29T10:00:00Z")  # CRITICAL = 7 日

    def test_draft_never_decides(self):
        plan = triage.draft(make_input(), NOW, "alice")
        # level_effective が INFO のものだけ defer が既定値。それ以外は判断しない
        self.assertTrue(any(it["level_effective"] == "INFO" for it in plan["items"]))
        for it in plan["items"]:
            self.assertEqual(it["decision"], "defer" if it["level_effective"] == "INFO" else None)


class TestInvariants(unittest.TestCase):
    def setUp(self):
        self.inp = make_input()
        self.plan = fill(self.inp, triage.draft(self.inp, NOW, "alice"))
        self.by_id = {x["id"]: x for x in self.inp["findings"]["findings"]}

    def item(self, pred):
        for it in self.plan["items"]:
            if pred(self.by_id[it["finding_id"]]):
                return it
        raise AssertionError("該当 finding なし")

    def assertViolates(self, code):
        self.assertIn(code, codes(triage.check(self.inp, self.plan)))

    def test_filled_plan_passes(self):
        self.assertEqual(triage.check(self.inp, self.plan), [])

    def test_i1_missing_and_duplicate(self):
        self.plan["items"].pop()
        self.assertViolates("I-1")
        self.setUp(); self.plan["items"].append(copy.deepcopy(self.plan["items"][0]))
        self.assertViolates("I-1")

    def test_i1_undecided(self):
        self.plan["items"][0]["decision"] = None
        self.assertViolates("I-1")

    def test_i2_unknown_id(self):
        self.plan["items"][0]["finding_id"] = "sha256:" + "0" * 64
        self.assertViolates("I-2")

    def test_i3_exception_rules(self):
        it = self.item(lambda x: not x.get("skillpact") or not x["skillpact"]["divergence"])
        it.update(decision="exception", action=None, exception_type=None, reason=None, approved_by=["security-lead"])
        self.assertViolates("I-3")
        it.update(exception_type="risk_accepted", reason="mitigated by network policy", approved_by=["bob"], decided_by="bob")
        self.assertViolates("I-8")  # bob は承認者リストに無い
        it.update(approved_by=["alice"], decided_by="alice")
        self.assertViolates("I-3")  # 自己承認
        it.update(approved_by=["security-lead"], decided_by="alice")
        self.assertEqual(triage.check(self.inp, self.plan), [])

    def test_i4_remediate_requires_owner_and_action(self):
        self.plan["items"][0]["owner"] = None
        self.assertViolates("I-4")
        self.setUp(); self.plan["items"][0]["action"] = None
        self.assertViolates("I-4")

    def test_i4_derived_action_fields(self):
        a = self.plan["items"][0]["action"]
        a["reversible"] = False  # chmod は可逆
        self.assertViolates("I-4")
        self.setUp(); self.plan["items"][0]["action"]["skillpact_effects"] = []
        it = self.item(lambda x: bool(x.get("skillpact")))
        it["action"]["skillpact_effects"] = ["read"]
        self.assertViolates("I-4")

    def test_i5_no_exception_on_divergence(self):
        it = self.item(lambda x: x.get("skillpact") and x["skillpact"]["divergence"])
        it.update(decision="exception", action=None, exception_type="risk_accepted", reason="x", approved_by=["security-lead"])
        self.assertViolates("I-5")

    def test_i6_diff_anomaly_needs_two(self):
        it = self.item(lambda x: x.get("skillpact") and x["skillpact"]["diff_anomaly"])
        it["approved_by"] = ["security-lead"]
        self.assertViolates("I-6")
        it["approved_by"] = ["security-lead", "security-lead"]
        self.assertViolates("I-6")

    def test_i7_cannot_lower_level(self):
        it = self.item(lambda x: x.get("skillpact") and x["skillpact"]["signed"] and x["skillpact"]["divergence"])
        it["level_effective"] = "HIGH"
        self.assertViolates("I-7")

    def test_i9_deadline(self):
        # ZES の §49 は CRITICAL を出さない（署名で重大度を変えない）。ZET が引き上げた CRITICAL で確認する
        it = self.item(lambda x: triage.level_effective(x) == "CRITICAL")
        it["due_at"] = "2026-12-31T00:00:00Z"
        self.assertViolates("I-9")

    def test_i10_errored_module_must_be_held(self):
        inp = make_input("findings-partial.json")
        plan = fill(inp, triage.draft(inp, NOW, "alice"))
        self.assertEqual(triage.check(inp, plan), [])
        inp["findings"]["errors"].append({"module": "§15", "reason": "module_failed"})
        self.assertTrue({"I-10", "I-12"} <= codes(triage.check(inp, plan)))

    def test_i11_schema(self):
        self.plan["items"][0]["decided_at"] = "2026-10-22 10:00:00"
        self.assertViolates("I-11")
        self.setUp(); self.plan["extra"] = True
        self.assertViolates("I-11")

    def test_i12_status_propagation(self):
        inp = make_input("findings-partial.json")
        plan = fill(inp, triage.draft(inp, NOW, "alice"))
        final = triage.finalize(inp, plan)
        self.assertEqual(final["status"], "partial")
        final["status"] = "ok"; final["plan_hash"] = plan_hash(final)
        self.assertIn("I-12", codes(triage.check(inp, final, final=True)))


class TestFinalize(unittest.TestCase):
    def test_finalize_output(self):
        inp = make_input()
        final = triage.finalize(inp, fill(inp, triage.draft(inp, NOW, "alice")))
        self.assertEqual(final["status"], "ok")
        self.assertEqual(final["plan_hash"], plan_hash(final))
        self.assertTrue(all("constraints" not in it for it in final["items"]))
        by_id = {x["id"]: x for x in inp["findings"]["findings"]}
        remediate = [it for it in final["items"] if it["decision"] == "remediate"]
        self.assertTrue(remediate)
        for it in remediate:
            a = it["action"]
            self.assertTrue(a["reversible"])
            sp = by_id[it["finding_id"]].get("skillpact")
            self.assertEqual(a["skillpact_effects"], sp["declared_effects"] if sp else [])
        self.assertEqual(triage.check(inp, final, final=True), [])

    def test_tampered_final_plan_detected(self):
        inp = make_input()
        final = triage.finalize(inp, fill(inp, triage.draft(inp, NOW, "alice")))
        final["items"][0]["action"]["target"] = "/etc/shadow"
        self.assertIn("I-11", codes(triage.check(inp, final, final=True)))

    def test_finalize_rejects_undecided(self):
        inp = make_input()
        with self.assertRaises(ContractError):
            triage.finalize(inp, triage.draft(inp, NOW, "alice"))


class TestCliAndAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        os.environ["ZET_LOG_DIR"] = str(self.d / "log")
        (self.d / "in.json").write_text(json.dumps(make_input()), encoding="utf-8")
        (self.d / "err.json").write_text(json.dumps(make_input("findings-error.json")), encoding="utf-8")

    def tearDown(self):
        os.environ.pop("ZET_LOG_DIR", None)
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = cli.main(list(args))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_roundtrip_and_audit_chain(self):
        d = self.d
        self.assertEqual(self.run_cli("validate", str(d / "in.json"), "--operator", "alice")[0], 0)
        self.assertEqual(self.run_cli("validate", str(d / "err.json"), "--operator", "alice")[0], 3)
        code, _, _ = self.run_cli("draft", str(d / "in.json"), "--operator", "alice", "--now", "2026-10-22T10:00:00Z", "-o", str(d / "draft.json"))
        self.assertEqual(code, 0)
        inp = json.loads((d / "in.json").read_text())
        (d / "plan.json").write_text(json.dumps(fill(inp, json.loads((d / "draft.json").read_text()))))
        self.assertEqual(self.run_cli("check", str(d / "in.json"), str(d / "draft.json"), "--operator", "alice")[0], 3)
        self.assertEqual(self.run_cli("check", str(d / "in.json"), str(d / "plan.json"), "--operator", "alice")[0], 0)
        self.assertEqual(self.run_cli("finalize", str(d / "in.json"), str(d / "plan.json"), "--operator", "alice", "-o", str(d / "final.json"))[0], 0)
        final = json.loads((d / "final.json").read_text())
        self.assertEqual(final["plan_hash"], plan_hash(final))
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([r["result"] for r in recs], ["ok", "rejected", "ok", "rejected", "ok", "ok"])
        self.assertEqual(recs[-1]["plan_hash"], final["plan_hash"])
        self.assertEqual(audit.verify_chain(), [])
        # 改ざん検出
        lines = audit.log_path().read_text().splitlines()
        lines[1] = lines[1].replace('"rejected"', '"ok"')
        audit.log_path().write_text("\n".join(lines) + "\n")
        self.assertTrue(audit.verify_chain())

    def test_finalize_rejection_writes_nothing(self):
        d = self.d
        self.run_cli("draft", str(d / "in.json"), "--operator", "alice", "-o", str(d / "draft.json"))
        code, _, _ = self.run_cli("finalize", str(d / "in.json"), str(d / "draft.json"), "--operator", "alice", "-o", str(d / "final.json"))
        self.assertEqual(code, 3)
        self.assertFalse((d / "final.json").exists())

    def test_usage_errors(self):
        self.assertEqual(self.run_cli("validate", str(self.d / "in.json"))[0], 64)  # --operator 必須
        self.assertEqual(self.run_cli("validate", str(self.d / "in.json"), "--operator", "a b")[0], 64)
        self.assertEqual(self.run_cli("draft", str(self.d / "in.json"), "--operator", "alice", "--now", "yesterday")[0], 64)

    def test_unwritable_log_refuses(self):
        os.environ["ZET_LOG_DIR"] = "/proc/zet-cannot-write"
        self.assertEqual(self.run_cli("validate", str(self.d / "in.json"), "--operator", "alice")[0], 64)


class TestRegressions(unittest.TestCase):
    """bughunt-r1 で見つかった不具合の回帰テスト。"""

    def setUp(self):
        self.inp = make_input()
        self.plan = fill(self.inp, triage.draft(self.inp, NOW, "alice"))
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        os.environ["ZET_LOG_DIR"] = str(self.d / "log")
        (self.d / "in.json").write_text(json.dumps(self.inp), encoding="utf-8")

    def tearDown(self):
        os.environ.pop("ZET_LOG_DIR", None)
        self.tmp.cleanup()

    run_cli = TestCliAndAudit.run_cli

    # 1. pattern の $ は末尾改行の直前に一致してはならない（ECMA の意味）
    def test_pattern_dollar_does_not_match_before_newline(self):
        it = self.plan["items"][0]
        it.update(decided_by="alice\n", approved_by=["alice"])
        self.assertIn("I-11", codes(triage.check(self.inp, self.plan)))
        from zet.jsonschema_lite import Validator
        self.assertFalse(Validator({"pattern": "^a$"}).is_valid("a\n"))
        self.assertTrue(Validator({"pattern": "^a\\$$"}).is_valid("a$"))  # エスケープした $ はリテラル
        self.assertTrue(Validator({"pattern": "^[$]$"}).is_valid("$"))  # 文字クラス内の $ はリテラル

    def test_newline_in_module_and_id_rejected(self):
        inp = make_input("findings-partial.json")
        inp["findings"]["findings"][0]["module"] = "§6\n"
        self.assertIn("I-11", codes(triage.validate_input(inp)))
        inp = make_input()
        inp["findings"]["findings"][1]["id"] = inp["findings"]["findings"][0]["id"] + "\n"
        self.assertIn("I-11", codes(triage.validate_input(inp)))

    def test_cli_operator_and_plan_id_newline_rejected(self):
        self.assertEqual(self.run_cli("validate", str(self.d / "in.json"), "--operator", "ci\n")[0], 64)
        self.assertEqual(self.run_cli("draft", str(self.d / "in.json"), "--operator", "ci",
                                      "--plan-id", "00000000-0000-0000-0000-000000000000\n")[0], 64)

    # 2. 確定 plan（plan_hash 付き）は check / finalize でも plan_hash を検証する
    def test_check_and_finalize_verify_plan_hash_of_final_plan(self):
        final = triage.finalize(self.inp, self.plan)
        self.assertEqual(triage.check(self.inp, final), [])
        self.assertEqual(triage.finalize(self.inp, final), final)  # 改ざんが無ければ冪等
        final["items"][0]["action"]["target"] = "/etc/shadow"
        self.assertIn("I-11", codes(triage.check(self.inp, final)))
        with self.assertRaises(ContractError) as cm:
            triage.finalize(self.inp, final)
        self.assertIn("I-11", codes(cm.exception.violations))
        (self.d / "final.json").write_text(json.dumps(final), encoding="utf-8")
        self.assertEqual(self.run_cli("check", str(self.d / "in.json"), str(self.d / "final.json"), "--operator", "alice")[0], 3)
        self.assertEqual(self.run_cli("finalize", str(self.d / "in.json"), str(self.d / "final.json"),
                                      "--operator", "alice", "-o", str(self.d / "out.json"))[0], 3)
        self.assertFalse((self.d / "out.json").exists())

    # 3. 有限でない数値（1e400 → inf）は読み込みで拒否し、Infinity を書き出さない
    def test_non_finite_number_rejected(self):
        self.plan["items"][0]["action"]["params"]["n"] = 1
        raw = json.dumps(self.plan).replace('"n": 1', '"n": 1e400')
        (self.d / "plan.json").write_text(raw, encoding="utf-8")
        with self.assertRaises(ContractError) as cm:
            load_json(str(self.d / "plan.json"))
        self.assertEqual(codes(cm.exception.violations), {"I-11"})
        code, _, _ = self.run_cli("finalize", str(self.d / "in.json"), str(self.d / "plan.json"),
                                  "--operator", "alice", "-o", str(self.d / "out.json"))
        self.assertEqual(code, 3)
        self.assertFalse((self.d / "out.json").exists())
        with self.assertRaises(ValueError):
            canonical({"x": float("inf")})
        with self.assertRaises(ValueError):
            write_atomic(str(self.d / "nan.json"), {"x": float("nan")})
        self.assertFalse((self.d / "nan.json").exists())

    # 4. 不正なサロゲートは I-11（終了コード 3）。内部エラーでも文書全体を stderr に出さない
    def test_lone_surrogate_rejected_without_echo(self):
        self.plan["items"][0]["reason"] = "SECRET-" + "x" * 5000 + "\ud800"
        (self.d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")  # ensure_ascii で \ud800 のまま書かれる
        code, _, err = self.run_cli("check", str(self.d / "in.json"), str(self.d / "plan.json"), "--operator", "alice")
        self.assertEqual(code, 3)
        self.assertIn("I-11", err)
        self.assertNotIn("SECRET", err)

    def test_internal_error_message_is_truncated(self):
        orig = triage.validate_input
        triage.validate_input = lambda inp: (_ for _ in ()).throw(RuntimeError({"doc": "y" * 10000}))
        try:
            code, _, err = self.run_cli("validate", str(self.d / "in.json"), "--operator", "alice")
        finally:
            triage.validate_input = orig
        self.assertEqual(code, 70)
        self.assertIn("RuntimeError", err)
        self.assertLess(len(err), 400)

    # 5. decided_at は created_at 以上・現在時刻以下（未来の判断日で I-9 の期限を延ばせない）
    def test_decided_at_bounded(self):
        it = next(i for i in self.plan["items"] if i["decision"] == "remediate")
        it.update(decided_at="2030-01-01T00:00:00Z", due_at="2030-01-05T00:00:00Z")
        self.assertIn("I-9", codes(triage.check(self.inp, self.plan, now=NOW)))
        it.update(decided_at="2026-10-21T00:00:00Z", due_at="2026-10-22T00:00:00Z")  # created_at より前
        self.assertIn("I-9", codes(triage.check(self.inp, self.plan, now=NOW)))
        it.update(decided_at="2026-10-22T10:00:00Z", due_at="2026-10-23T00:00:00Z")
        self.assertEqual(triage.check(self.inp, self.plan, now=NOW), [])
        it.update(decided_at="2026-10-22T11:00:00Z")
        with self.assertRaises(ContractError):
            triage.finalize(self.inp, self.plan, now=NOW)
        (self.d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")
        self.assertEqual(self.run_cli("check", str(self.d / "in.json"), str(self.d / "plan.json"),
                                      "--operator", "alice", "--now", "2026-10-22T10:30:00Z")[0], 3)
        self.assertEqual(self.run_cli("check", str(self.d / "in.json"), str(self.d / "plan.json"),
                                      "--operator", "alice", "--now", "2026-10-22T11:00:00Z")[0], 0)

    # 6. held は errors[] のモジュール専用（CRITICAL を held に移して判断を逃れられない）
    def test_held_only_for_errored_modules(self):
        inp = make_input("findings-partial.json")
        plan = fill(inp, triage.draft(inp, NOW, "alice"))
        self.assertEqual(triage.check(inp, plan), [])
        by_id = {x["id"]: x for x in inp["findings"]["findings"]}
        crit = next(i for i in plan["items"] if by_id[i["finding_id"]]["level"] == "CRITICAL")
        p = copy.deepcopy(plan)
        p["items"].remove(crit)
        p["held"].append({"finding_id": crit["finding_id"], "module": by_id[crit["finding_id"]]["module"], "reason": "later"})
        self.assertIn("I-1", codes(triage.check(inp, p)))
        p = copy.deepcopy(plan)
        p["held"].append({"finding_id": None, "module": "§2", "reason": "later"})
        self.assertIn("I-10", codes(triage.check(inp, p)))
        inp["findings"]["errors"].append({"module": "§15", "reason": "module_failed"})
        p = triage.draft(inp, NOW, "alice")
        self.assertEqual(triage.check(inp, fill(inp, p)), [])
        h = next(h for h in p["held"] if h["finding_id"] is not None)
        h["module"] = "§6"  # errors[] にあるが finding の実モジュールではない
        self.assertIn("I-10", codes(triage.check(inp, fill(inp, p))))

    # 7. 存在しない日時・範囲外の日時は I-11（--now は 64）で、内部エラーにしない
    def test_invalid_and_out_of_range_timestamps(self):
        for k, ts in (("decided_at", "2026-13-01T00:00:00Z"), ("due_at", "2026-10-22T10:00:60Z")):
            p = copy.deepcopy(self.plan)
            p["items"][0][k] = ts
            self.assertIn("I-11", codes(triage.check(self.inp, p)))
            (self.d / "plan.json").write_text(json.dumps(p), encoding="utf-8")
            self.assertEqual(self.run_cli("check", str(self.d / "in.json"), str(self.d / "plan.json"), "--operator", "alice")[0], 3)
        p = copy.deepcopy(self.plan)
        p["created_at"] = "2026-02-30T00:00:00Z"
        self.assertIn("I-11", codes(triage.check(self.inp, p)))
        p = copy.deepcopy(self.plan)
        it = next(i for i in p["items"] if i["decision"] == "remediate")
        it.update(decided_at="9999-12-31T00:00:00Z", due_at="9999-12-31T00:00:00Z")
        self.assertIn("I-11", codes(triage.check(self.inp, p, now=parse_ts("9999-12-31T23:59:59Z"))))
        with self.assertRaises(ContractError):
            triage.draft(self.inp, parse_ts("9999-12-30T00:00:00Z"), "alice")
        self.assertEqual(self.run_cli("draft", str(self.d / "in.json"), "--operator", "alice", "--now", "9999-12-30T00:00:00Z")[0], 64)
        self.assertEqual(self.run_cli("draft", str(self.d / "in.json"), "--operator", "alice", "--now", "2026-13-01T00:00:00Z")[0], 64)

    # 8. 監査ログ: 途中で切れた最終行の後ろには追記しない（R3 F15: 壊れたチェーンには足さない）/ シンボリックリンクのログは拒否
    def test_audit_torn_line_and_symlink(self):
        audit.append({"command": "validate"})
        with open(audit.log_path(), "ab") as f:
            f.write(b'{"command":"torn')
        before = audit.log_path().read_bytes()
        with self.assertRaises(audit.BrokenChain):
            audit.append({"command": "check"})
        self.assertEqual(audit.log_path().read_bytes(), before)
        self.assertEqual(audit.verify_chain(), ["line 2: 改行で終わっていません（書き込みが途中で切れた可能性）",
                                                "line 2: JSON ではありません"])
        target = self.d / "elsewhere.jsonl"
        target.write_bytes(b"")
        audit.log_path().unlink()
        audit.log_path().symlink_to(target)
        with self.assertRaises(OSError):
            audit.append({"command": "validate"})
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(self.run_cli("validate", str(self.d / "in.json"), "--operator", "alice")[0], 64)


class TestRegressionsR2(unittest.TestCase):
    """bughunt-r2 で見つかった不具合の回帰テスト。"""

    setUp = TestRegressions.setUp
    tearDown = TestRegressions.tearDown
    run_cli = TestCliAndAudit.run_cli

    # 4. 重複キーは I-11（後勝ちで黙って値が変わらない）
    def test_duplicate_keys_rejected(self):
        raw = json.dumps(self.plan).replace('"decision": "remediate"', '"decision": "remediate", "decision": "exception"', 1)
        (self.d / "plan.json").write_text(raw, encoding="utf-8")
        with self.assertRaises(ContractError) as cm:
            load_json(str(self.d / "plan.json"))
        self.assertEqual(codes(cm.exception.violations), {"I-11"})
        self.assertEqual(self.run_cli("check", str(self.d / "in.json"), str(self.d / "plan.json"), "--operator", "alice")[0], 3)

    # 7a. 深すぎる入れ子は I-11（終了コード 3）で、内部エラー（70）にしない
    def test_deeply_nested_input_is_contract_error(self):
        (self.d / "deep.json").write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        with self.assertRaises(ContractError) as cm:
            load_json(str(self.d / "deep.json"))
        self.assertEqual(codes(cm.exception.violations), {"I-11"})
        self.assertEqual(self.run_cli("validate", str(self.d / "deep.json"), "--operator", "alice")[0], 3)

    # 6. draft の自動 defer は level_effective で判断する（引き上げられた INFO を defer にしない）
    def test_draft_does_not_auto_defer_elevated_info(self):
        inp = make_input()
        x = next(f for f in inp["findings"]["findings"] if f.get("skillpact") and f["skillpact"]["signed"] and f["skillpact"]["divergence"])
        x["level"] = "INFO"  # L3 署名済みで乖離があるため CRITICAL に引き上がる
        self.assertEqual(triage.validate_input(inp), [])
        it = next(i for i in triage.draft(inp, NOW, "alice")["items"] if i["finding_id"] == x["id"])
        self.assertEqual(it["level_effective"], "CRITICAL")
        self.assertEqual((it["decision"], it["decided_by"], it["reason"]), (None, None, None))
        self.assertEqual(it["due_at"], "2026-10-29T10:00:00Z")

    # 5. 人名の比較は大文字小文字を区別しない（自己承認・承認者数・policy.approvers）
    def test_person_names_compared_casefolded(self):
        by_id = {x["id"]: x for x in self.inp["findings"]["findings"]}
        sp = {i["finding_id"]: by_id[i["finding_id"]]["skillpact"] for i in self.plan["items"]}
        it = next(i for i in self.plan["items"] if not sp[i["finding_id"]]["divergence"] and not sp[i["finding_id"]]["diff_anomaly"])
        it.update(decision="exception", action=None, exception_type="risk_accepted", reason="mitigated", decided_by="Alice", approved_by=["alice"])
        self.assertIn("I-3", codes(triage.check(self.inp, self.plan)))  # 自己承認
        it.update(decided_by="bob", approved_by=["Security-Lead"])
        self.assertEqual(triage.check(self.inp, self.plan), [])  # policy.approvers の security-lead と同一人物
        an = next(i for i in self.plan["items"] if sp[i["finding_id"]]["diff_anomaly"])
        an["approved_by"] = ["alice", "ALICE"]
        v = [x for x in triage.check(self.inp, self.plan) if x.finding_id == an["finding_id"]]
        self.assertIn("承認者が 2 名以上必要です（現在 1 名）", [x.message for x in v])

    # 2. INFO 以外の defer は reason と recheck_at（判断ウィンドウ内）が必須（無期限・無承認の例外にしない）
    def test_defer_requires_reason_and_recheck_at(self):
        by_id = {x["id"]: x for x in self.inp["findings"]["findings"]}
        it = next(i for i in self.plan["items"] if triage.level_effective(by_id[i["finding_id"]]) == "CRITICAL"
                  and by_id[i["finding_id"]]["skillpact"]["divergence"])
        it.update(decision="defer", action=None, owner=None, due_at=None, reason="waiting for vendor fix", recheck_at=None)
        self.assertIn("I-9", codes(triage.check(self.inp, self.plan)))
        with self.assertRaises(ContractError):
            triage.finalize(self.inp, self.plan)
        it.update(recheck_at="2026-10-21T00:00:00Z")  # 判断日より前
        self.assertIn("I-9", codes(triage.check(self.inp, self.plan)))
        it.update(recheck_at="2026-10-30T10:00:00Z", reason="  ")
        self.assertIn("I-3", codes(triage.check(self.inp, self.plan)))
        it.update(reason="waiting for vendor fix")
        self.assertEqual(triage.check(self.inp, self.plan), [])
        # level_effective が INFO の defer は従来どおり reason / recheck_at なしで通る
        inp = make_input("findings-partial.json")
        plan = fill(inp, triage.draft(inp, NOW, "alice"))
        info = next(i for i in plan["items"] if i["level_effective"] == "INFO")
        info.update(reason=None, recheck_at=None)
        self.assertEqual(triage.check(inp, plan), [])

    # 8. GER が必ず拒否する action（正規化されていない target、chmod の不正な params）は確定させない
    def test_action_shape_matches_ger(self):
        it = next(i for i in self.plan["items"] if i["decision"] == "remediate")
        for target in ("/a/./b", "/a//b", "/a/../b", "/a/b/", "/..", "/a/."):
            p = copy.deepcopy(self.plan)
            next(i for i in p["items"] if i["finding_id"] == it["finding_id"])["action"]["target"] = target
            self.assertIn("I-4", codes(triage.check(self.inp, p)), target)
            with self.assertRaises(ContractError):
                triage.finalize(self.inp, p)
        for params in ({"mode": "644"}, {"mode": "04755"}, {"mode": "0644\n"}, {"mode": 420}, {"mode": "0644", "x": 1}, {}):
            p = copy.deepcopy(self.plan)
            next(i for i in p["items"] if i["finding_id"] == it["finding_id"])["action"]["params"] = params
            self.assertIn("I-4", codes(triage.check(self.inp, p)), params)
        it["action"].update(params={"mode": "0644"})
        self.assertEqual(triage.check(self.inp, self.plan), [])
        triage.finalize(self.inp, self.plan)

    # 3. --now は ZET_ALLOW_NOW_OVERRIDE=1 のときだけ。使った場合は監査ログに now_override を残す
    def test_now_override_requires_env_and_is_audited(self):
        args = ("validate", str(self.d / "in.json"), "--operator", "alice", "--now", "2026-10-22T10:00:00Z")
        os.environ.pop("ZET_ALLOW_NOW_OVERRIDE")
        try:
            code, _, err = self.run_cli(*args)
            self.assertEqual(code, 64)
            self.assertIn("テスト専用", err)
            self.assertFalse(audit.log_path().exists())
            self.assertEqual(self.run_cli(*args[:4])[0], 0)
        finally:
            os.environ["ZET_ALLOW_NOW_OVERRIDE"] = "1"
        self.assertEqual(self.run_cli(*args)[0], 0)
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([r.get("now_override") for r in recs], [None, True])

    # 7b. 既存のログディレクトリがグループ・他者から書き込み可能、または他人の所有なら拒否（64）
    def test_log_dir_permissions_checked(self):
        logd = self.d / "log"
        logd.mkdir(mode=0o700)
        args = ("validate", str(self.d / "in.json"), "--operator", "alice")
        self.assertEqual(self.run_cli(*args)[0], 0)
        for mode in (0o777, 0o720, 0o702):
            os.chmod(logd, mode)
            self.assertEqual(self.run_cli(*args)[0], 64, oct(mode))
        os.chmod(logd, 0o755)
        self.assertEqual(self.run_cli(*args)[0], 0)
        if os.geteuid() == 0:
            os.chown(logd, 12345, -1)
            self.assertEqual(self.run_cli(*args)[0], 64)
            os.chown(logd, 0, -1)
        self.assertEqual(len(audit.log_path().read_text().splitlines()), 2)

    def audit_records(self) -> list[dict]:
        p = audit.log_path()
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []

    # 1. -o は処理の前に検査する（ディレクトリ・存在しないディレクトリ・通常ファイル以外・入力と同じファイル）
    def test_output_path_validated_before_work(self):
        d = self.d
        (d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")
        os.link(d / "plan.json", d / "hard.json")
        (d / "sym.json").symlink_to(d / "in.json")
        os.mkfifo(d / "fifo")
        before = {n: (d / n).read_bytes() for n in ("in.json", "plan.json")}
        for out in (str(d), str(d / "nodir" / "x.json"), str(d / "fifo"), str(d / "in.json"), str(d / "plan.json"),
                    str(d / "hard.json"), str(d / "sym.json"), str(d / "." / "in.json"), ""):
            code, _, err = self.run_cli("finalize", str(d / "in.json"), str(d / "plan.json"), "--operator", "alice", "-o", out)
            self.assertEqual(code, 64, out)
            self.assertNotIn("Traceback", err)
        self.assertEqual(self.run_cli("draft", str(d / "in.json"), "--operator", "alice", "-o", str(d / "in.json"))[0], 64)
        self.assertEqual({n: (d / n).read_bytes() for n in before}, before)
        self.assertTrue(stat_is_fifo(d / "fifo"))
        self.assertEqual(self.audit_records(), [])

    # 1. 書き出しに失敗したら監査ログは ok にしない（output_hash / plan_hash も残さない）
    def test_output_write_failure_not_audited_as_ok(self):
        d = self.d
        (d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")
        args = ("finalize", str(d / "in.json"), str(d / "plan.json"), "--operator", "alice", "-o", str(d / "final.json"))

        def enospc(*a, **k):
            raise OSError(errno.ENOSPC, "No space left on device")
        orig = cli.write_text_atomic
        cli.write_text_atomic = enospc
        try:
            self.assertEqual(self.run_cli(*args)[0], 64)
        finally:
            cli.write_text_atomic = orig
        self.assertFalse((d / "final.json").exists())

        class FullStdout(io.StringIO):
            def write(self, s):
                raise OSError(errno.ENOSPC, "No space left on device")
        err = io.StringIO()
        with redirect_stdout(FullStdout()), redirect_stderr(err):
            self.assertEqual(cli.main(["draft", str(d / "in.json"), "--operator", "alice"]), 64)
        self.assertNotIn("Traceback", err.getvalue())

        orig = cli.dumps_pretty
        cli.dumps_pretty = lambda obj: (_ for _ in ()).throw(RecursionError("maximum recursion depth exceeded"))
        try:
            self.assertEqual(self.run_cli(*args)[0], 70)
        finally:
            cli.dumps_pretty = orig
        self.assertFalse((d / "final.json").exists())
        recs = self.audit_records()
        self.assertEqual([r["result"] for r in recs], ["error", "error", "error"])
        self.assertTrue(all("output_hash" not in r and "plan_hash" not in r for r in recs))
        self.assertEqual(self.run_cli(*args)[0], 0)
        rec = self.audit_records()[-1]
        self.assertEqual((rec["result"], rec["output_hash"]), ("ok", "sha256:" + hashlib.sha256(
            canonical(json.loads((d / "final.json").read_text()))).hexdigest()))

    def test_stdout_enospc_via_dev_full(self):
        if not os.path.exists("/dev/full"):
            self.skipTest("/dev/full がありません")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ZET_LOG_DIR": str(self.d / "log")}
        with open("/dev/full", "w") as full:
            r = subprocess.run([str(ROOT / "bin" / "zet"), "draft", str(self.d / "in.json"), "--operator", "alice"],
                               stdout=full, stderr=subprocess.PIPE, env=env, timeout=60)
        self.assertEqual(r.returncode, 64, r.stderr.decode())
        self.assertNotIn(b"Traceback", r.stderr)
        self.assertEqual([x["result"] for x in self.audit_records()], ["error"])

    # 1. 入れ子の深い params: 出力できたときだけ ok（現在は 64 段を超えるため読み込み時に I-11 で 3 になる）
    def test_deep_params_audit_matches_output(self):
        it = next(i for i in self.plan["items"] if i["decision"] == "remediate")
        it["action"] = {"type": "write_config", "target": "/srv/app/config", "params": {"deep": "DEEP"}}
        n = 3000
        (self.d / "plan.json").write_text(json.dumps(self.plan).replace('"DEEP"', '{"a":' * n + "{}" + "}" * n), encoding="utf-8")
        code, _, err = self.run_cli("finalize", str(self.d / "in.json"), str(self.d / "plan.json"),
                                    "--operator", "alice", "-o", str(self.d / "final.json"))
        self.assertIn(code, (0, 3, 70), err)
        self.assertNotIn("Traceback", err)
        rec = self.audit_records()[-1]
        self.assertEqual((self.d / "final.json").exists(), code == 0)
        self.assertEqual(rec["result"] == "ok", code == 0)
        self.assertEqual("output_hash" in rec, code == 0)


class TestRegressionsR3(unittest.TestCase):
    """bughunt-r3 で見つかった不具合の回帰テスト。"""

    setUp = TestRegressions.setUp
    tearDown = TestRegressions.tearDown
    run_cli = TestCliAndAudit.run_cli
    audit_records = TestRegressionsR2.audit_records

    # 1. -o に監査ログ（とそのディレクトリ内）は指定できない。verify_chain は object 以外の行で落ちない
    def test_output_cannot_replace_audit_log(self):
        d = self.d
        (d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")
        args = ("validate", str(d / "in.json"), "--operator", "alice")
        self.assertEqual(self.run_cli(*args)[0], 0)
        log = audit.log_path()
        os.link(log, d / "hard-log")
        (d / "sym-log").symlink_to(log)
        (d / "sym-dir").symlink_to(audit.log_dir())
        before = log.read_bytes()
        for out in (str(log), str(d / "log" / "." / "zet-audit.jsonl"), str(d / "hard-log"), str(d / "sym-log"),
                    str(d / "log" / "other.json"), str(d / "sym-dir" / "x.json"), str(d / "log")):
            code, _, err = self.run_cli("finalize", str(d / "in.json"), str(d / "plan.json"), "--operator", "alice", "-o", out)
            self.assertEqual(code, 64, out)
            self.assertNotIn("Traceback", err)
        self.assertEqual(self.run_cli("draft", str(d / "in.json"), "--operator", "alice", "-o", str(log))[0], 64)
        self.assertEqual(log.read_bytes(), before)
        self.assertEqual(audit.verify_chain(), [])
        with open(log, "ab") as f:
            f.write(b"[1, 2]\n\"str\"\n\xff\n")
        problems = audit.verify_chain()
        self.assertEqual(len(problems), 3, problems)

    # 2. 末尾の / と、与えられたパスのままの親ディレクトリを処理の前に検査する（書き出し時に失敗させない）
    def test_output_trailing_slash_and_parent_as_given(self):
        d = self.d
        (d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")
        (d / "existing.json").write_text("{}", encoding="utf-8")
        for out in (str(d / "nd") + "/", str(d / "existing.json") + "/", str(d / "nd" / ".." / "x.json"),
                    str(d / "existing.json" / ".." / "x.json")):
            code, _, err = self.run_cli("finalize", str(d / "in.json"), str(d / "plan.json"), "--operator", "alice", "-o", out)
            self.assertEqual(code, 64, out)
            self.assertNotIn("出力を書き出せません", err)
            self.assertEqual(self.run_cli("draft", str(d / "in.json"), "--operator", "alice", "-o", out)[0], 64, out)
        self.assertEqual(self.audit_records(), [])
        self.assertEqual((d / "existing.json").read_text(), "{}")
        self.assertFalse((d / "x.json").exists())
        cwd = os.getcwd()
        os.chdir(d)
        try:
            self.assertEqual(self.run_cli("draft", "in.json", "--operator", "alice", "-o", "rel.json")[0], 0)
        finally:
            os.chdir(cwd)
        self.assertTrue((d / "rel.json").exists())

    # 3. 先頭の // は normpath で残るが GER は拒否する。// はどこにあっても I-4
    def test_target_with_leading_double_slash_rejected(self):
        it = next(i for i in self.plan["items"] if i["decision"] == "remediate")
        for target in ("//tmp/x/t", "//", "//srv"):
            p = copy.deepcopy(self.plan)
            next(i for i in p["items"] if i["finding_id"] == it["finding_id"])["action"]["target"] = target
            self.assertIn("I-4", codes(triage.check(self.inp, p)), target)
            with self.assertRaises(ContractError):
                triage.finalize(self.inp, p)

    # 4. UTF-8 でないロケール（ASCII）でも標準出力の JSON は UTF-8 のまま書き、例外にしない
    def test_non_utf8_locale_stdout(self):
        inp = make_input("findings-partial.json")  # errors[].module に非 ASCII 文字（§）を含む
        (self.d / "partial.json").write_text(json.dumps(inp, ensure_ascii=False), encoding="utf-8")
        (self.d / "bad.json").write_text("{}", encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ZET_LOG_DIR": str(self.d / "log"),
               "LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
        # bin/zet は python3 -I（C ロケールでは UTF-8 モードになる）ため、ロケールの影響を受ける形で直接起動する
        cmd = ["python3", str(ROOT / "zet" / "__main__.py")]
        probe = subprocess.run(cmd[:1] + ["-c", "import sys; print(sys.stdout.encoding)"], env=env,
                               capture_output=True, text=True, timeout=60)
        if probe.stdout.strip().lower() not in ("ascii", "ansi_x3.4-1968", "us-ascii"):
            self.skipTest(f"ASCII ロケールを再現できません（{probe.stdout.strip()}）")
        r = subprocess.run(cmd + ["draft", str(self.d / "partial.json"), "--operator", "alice"],
                           env=env, capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertNotIn(b"Traceback", r.stderr)
        out = json.loads(r.stdout.decode("utf-8"))
        self.assertIn("§", json.dumps(out["held"], ensure_ascii=False))
        r = subprocess.run(cmd + ["validate", str(self.d / "bad.json"), "--operator", "alice"],
                           env=env, capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 3)
        self.assertNotIn(b"Traceback", r.stderr)
        self.assertEqual([x["result"] for x in self.audit_records()], ["ok", "rejected"])

    # 5a. remediate の action.target が重複する計画は GER が拒否するため確定させない（I-4）
    def test_duplicate_action_target_rejected(self):
        rem = [i for i in self.plan["items"] if i["decision"] == "remediate"]
        self.assertGreaterEqual(len(rem), 2)
        rem[1]["action"]["target"] = rem[0]["action"]["target"]
        v = triage.check(self.inp, self.plan)
        self.assertEqual({(x.code, x.finding_id) for x in v}, {("I-4", rem[1]["finding_id"])})
        self.assertTrue(any("重複" in x.message for x in v))
        with self.assertRaises(ContractError):
            triage.finalize(self.inp, self.plan)

    # 5b. GER の操作レジストリに無い種別（write_config など）は確定させない（I-4）
    def test_unsupported_action_type_rejected(self):
        it = next(i for i in self.plan["items"] if i["decision"] == "remediate")
        for t, params in (("write_config", {"mode": "0600"}), ("rotate_secret", {}), ("chmodx", {"mode": "0600"})):
            p = copy.deepcopy(self.plan)
            next(i for i in p["items"] if i["finding_id"] == it["finding_id"])["action"].update(type=t, params=params)
            self.assertIn("I-4", codes(triage.check(self.inp, p)), t)
            with self.assertRaises(ContractError):
                triage.finalize(self.inp, p)

    # 5c. GER と同じく 64 段を超える入れ子は I-11（GER が読めない文書を確定させない）
    def test_nesting_depth_limit_matches_ger(self):
        for depth, ok in ((64, True), (65, False)):
            (self.d / "deep.json").write_text("[" * depth + "]" * depth, encoding="utf-8")
            if ok:
                load_json(str(self.d / "deep.json"))
                continue
            with self.assertRaises(ContractError) as cm:
                load_json(str(self.d / "deep.json"))
            self.assertEqual(codes(cm.exception.violations), {"I-11"})
        it = next(i for i in self.plan["items"] if i["decision"] == "remediate")
        it["action"]["params"] = {"mode": "0600", "x": "DEEP"}
        (self.d / "plan.json").write_text(json.dumps(self.plan).replace('"DEEP"', "[" * 70 + "]" * 70), encoding="utf-8")
        code, _, err = self.run_cli("finalize", str(self.d / "in.json"), str(self.d / "plan.json"),
                                    "--operator", "alice", "-o", str(self.d / "final.json"))
        self.assertEqual(code, 3)
        self.assertIn("I-11", err)
        self.assertFalse((self.d / "final.json").exists())


class TestRegressionsR3Fixes(unittest.TestCase):
    """round 3 の指摘（F5 / F7 / F8 / F10 / F14 / F15）の回帰テスト。"""

    setUp = TestRegressions.setUp
    tearDown = TestRegressions.tearDown
    run_cli = TestCliAndAudit.run_cli
    audit_records = TestRegressionsR2.audit_records

    def remediate_item(self, plan=None):
        return next(i for i in (plan or self.plan)["items"] if i["decision"] == "remediate")

    def finding(self, fid):
        return next(x for x in self.inp["findings"]["findings"] if x["id"] == fid)

    # F7: action.target は finding の path そのもの（別のパス・配下のパス・path が null の finding は不可）
    def test_f7_target_must_equal_finding_path(self):
        it = self.remediate_item()
        path = self.finding(it["finding_id"])["path"]
        self.assertEqual(it["action"]["target"], path)
        for target in ("/home/u/.ssh/id_ed25519", path + "/child", posixpath.dirname(path)):
            p = copy.deepcopy(self.plan)
            self.remediate_item(p)["action"]["target"] = target
            v = triage.check(self.inp, p)
            self.assertIn(("I-4", it["finding_id"]), {(x.code, x.finding_id) for x in v}, target)
            self.assertTrue(any("finding の path" in x.message for x in v), target)
            with self.assertRaises(ContractError):
                triage.finalize(self.inp, p)
        inp = copy.deepcopy(self.inp)
        x = next(f for f in inp["findings"]["findings"] if f["id"] == it["finding_id"])
        x["path"] = None
        self.assertTrue(any("null" in v.message for v in triage.check(inp, self.plan)))

    # F7: ZET は現在の mode を知らないため、静的に分かる緩和（world-writable、特殊ビット）を拒否する
    def test_f7_chmod_mode_cannot_be_world_writable_or_special(self):
        for mode, ok in (("0600", True), ("0644", True), ("0000", True), ("0666", False), ("0602", False),
                         ("0777", False), ("04755", False), ("02755", False), ("01777", False)):
            p = copy.deepcopy(self.plan)
            self.remediate_item(p)["action"]["params"] = {"mode": mode}
            self.assertEqual(not any(v.code == "I-4" for v in triage.check(self.inp, p)), ok, mode)

    # F5: --now で作った plan には now_override: true を残す（draft で使った場合も finalize に引き継ぐ）
    def test_f5_now_override_recorded_in_plan(self):
        final = triage.finalize(self.inp, self.plan, now=NOW)
        self.assertNotIn("now_override", final)
        final = triage.finalize(self.inp, self.plan, now=NOW, now_override=True)
        self.assertIs(final["now_override"], True)
        self.assertEqual(final["plan_hash"], plan_hash(final))
        self.assertEqual(triage.check(self.inp, final, final=True), [])
        d = triage.draft(self.inp, NOW, "alice", now_override=True)
        self.assertIs(d["now_override"], True)
        self.assertIs(triage.finalize(self.inp, fill(self.inp, d), now=NOW)["now_override"], True)
        # スキーマ: 省略は従来どおり有効、false は不可（省略と同じ意味の別表現を作らない）
        bad = copy.deepcopy(final); bad["now_override"] = False; bad["plan_hash"] = plan_hash(bad)
        self.assertIn("I-11", codes(triage.check(self.inp, bad, final=True)))
        (self.d / "plan.json").write_text(json.dumps(self.plan), encoding="utf-8")
        code, _, err = self.run_cli("finalize", str(self.d / "in.json"), str(self.d / "plan.json"), "--operator", "alice",
                                    "--now", "2026-10-22T10:00:00Z", "-o", str(self.d / "final.json"))
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads((self.d / "final.json").read_text())["now_override"], True)

    # F8: 入力由来の文字列（キー名など）に含まれる ESC・C1 制御文字をそのまま端末に出さない
    def test_f8_control_characters_escaped_in_messages(self):
        from zet.jsonschema_lite import safe_text
        self.assertEqual(safe_text("a\x1b]0;X\x07\x9b\u202eb\\c"), "a\\x1b]0;X\\x07\\x9b\\u202eb\\c")
        self.assertEqual(safe_text(safe_text("a\x1b")), "a\\x1b")  # 冪等（検証器と CLI の両方で適用しても二重にしない）
        bad = dict(self.inp); bad["x\x1b]0;PWNED\x07\x1b[2J\x9b"] = 1
        (self.d / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
        code, _, err = self.run_cli("validate", str(self.d / "bad.json"), "--operator", "alice")
        self.assertEqual(code, 3)
        self.assertIn("unknown field", err)
        for c in ("\x1b", "\x07", "\x9b"):
            self.assertNotIn(c, err)
        self.assertIn("unknown field 'x\\x1b]0;PWNED\\x07\\x1b[2J\\x9b'", err)

    # F10: skillpact_effects は SkillPact 0.8 の 6 効果だけ。危険な効果を宣言したスキルの remediate は承認者 2 名（GER G-6 と同じ）
    def test_f10_effects_enum_and_risky_effects_need_two_approvers(self):
        final = triage.finalize(self.inp, self.plan)
        for eff in ("EXEC", " exec ", "bogus", "secrets"):
            p = copy.deepcopy(final); self.remediate_item(p)["action"]["skillpact_effects"] = [eff]
            self.assertTrue(validator("remediation-plan.schema.json").errors(p), eff)
        risky = [it for it in self.plan["items"] if it["decision"] == "remediate"
                 and triage.risky_effects(self.finding(it["finding_id"]))]
        self.assertTrue(risky)
        it = risky[0]
        it["approved_by"] = ["security-lead"]
        v = triage.check(self.inp, self.plan)
        self.assertIn(("I-6", it["finding_id"]), {(x.code, x.finding_id) for x in v})
        it["approved_by"] = ["security-lead", "platform-owner"]
        self.assertEqual(triage.check(self.inp, self.plan), [])

    # F14: 未実装の skillpact_policy の項目は「予約・未実装」として拒否する
    def test_f14_reserved_skillpact_policy_fields_rejected(self):
        for k, val in (("diff_anomaly_threshold", 0.3), ("destructive_requires_human", True), ("destructive_requires_human", False)):
            inp = copy.deepcopy(self.inp); inp["skillpact_policy"][k] = val
            v = triage.validate_input(inp)
            self.assertEqual([(x.code, k in x.message and "予約" in x.message) for x in v], [("SP", True)], k)
        self.assertEqual(triage.validate_input(self.inp), [])

    # F14 / F1: 確定 plan は evidence_hash と skillpact の要約を持ち、check は入力と一致することを確かめる
    def test_f14_evidence_hash_and_skillpact_summary_carried(self):
        final = triage.finalize(self.inp, self.plan)
        for it in final["items"]:
            x = self.finding(it["finding_id"])
            if it["action"]:  # plan 1.1: evidence（kind と hash）。1.0 の evidence_hash は持たない
                self.assertEqual(it["action"]["evidence"]["hash"], x["evidence_hash"])
                self.assertEqual(it["action"]["evidence"], triage.evidence_of(x))
                self.assertNotIn("evidence_hash", it["action"])
            if x.get("skillpact"):
                self.assertEqual(it["skillpact"]["divergence"], x["skillpact"]["divergence"])
                self.assertEqual(it["skillpact"]["declared_effects"], x["skillpact"]["declared_effects"])
            else:
                self.assertNotIn("skillpact", it)
        p = copy.deepcopy(final); self.remediate_item(p)["action"]["evidence"]["hash"] = "sha256:" + "0" * 64
        p["plan_hash"] = plan_hash(p)
        self.assertIn("I-4", codes(triage.check(self.inp, p, final=True)))
        p = copy.deepcopy(final); del self.remediate_item(p)["action"]["evidence"]; p["plan_hash"] = plan_hash(p)
        self.assertIn("I-4", codes(triage.check(self.inp, p, final=True)))
        p = copy.deepcopy(final)
        it = next(i for i in p["items"] if "skillpact" in i)
        it["skillpact"]["diff_anomaly"] = not it["skillpact"]["diff_anomaly"]; p["plan_hash"] = plan_hash(p)
        self.assertIn("I-5", codes(triage.check(self.inp, p, final=True)))
        del it["skillpact"]; p["plan_hash"] = plan_hash(p)
        self.assertIn("I-5", codes(triage.check(self.inp, p, final=True)))

    # F15: zet verify-log と、壊れたチェーンへの追記の拒否
    def test_f15_verify_log_and_refuse_append_to_broken_chain(self):
        code, _, err = self.run_cli("verify-log")
        self.assertEqual(code, 64, err)  # まだログが無い
        for _ in range(3):
            self.assertEqual(self.run_cli("validate", str(self.d / "in.json"), "--operator", "alice")[0], 0)
        code, _, err = self.run_cli("verify-log")
        self.assertEqual(code, 0, err)
        self.assertIn("3", err)
        log = audit.log_path()
        lines = log.read_bytes().splitlines(keepends=True)
        # 末尾の行の prev_hash を書き換える（途中の行の改ざんは verify-log が検出する）
        rec = json.loads(lines[-1]); rec["prev_hash"] = "sha256:" + "0" * 64
        log.write_bytes(b"".join(lines[:-1]) + json.dumps(rec).encode() + b"\n")
        code, _, err = self.run_cli("verify-log", str(log))
        self.assertEqual(code, 3)
        self.assertIn("line 3: prev_hash 不一致", err)
        before = log.read_bytes()
        code, _, err = self.run_cli("validate", str(self.d / "in.json"), "--operator", "alice")
        self.assertEqual(code, 64)
        self.assertIn("verify-log", err)
        self.assertEqual(log.read_bytes(), before)  # 何も追記しない
        with self.assertRaises(audit.BrokenChain):
            audit.append({"command": "validate"})
        # 途中の行の破損は verify-log で検出（末尾が健全なら追記はできる）
        log.write_bytes(lines[0] + b"garbage\n")
        self.assertEqual(self.run_cli("verify-log")[0], 3)


def stat_is_fifo(p) -> bool:
    return stat.S_ISFIFO(os.lstat(p).st_mode)


class TestLauncherNoSite(unittest.TestCase):
    """bin/zet は site を読み込まない（-S）。site-packages の .pth は import site で実行されるため、
    ツール自身の中でコードを実行させないには -I だけでは足りない。"""

    def test_launcher_passes_I_and_S(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "argv")
            shim = os.path.join(d, "python3")
            with open(shim, "w") as fh:
                fh.write('#!/bin/sh\nprintf "%s\\n" "$@" > "' + log + '"\n')
            os.chmod(shim, 0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
            subprocess.run([str(Path(__file__).resolve().parents[1] / "bin" / "zet"), "--help"],
                           env=env, check=False, capture_output=True)
            with open(log) as fh:
                args = fh.read().split("\n")
            self.assertEqual(args[:2], ["-I", "-S"])


if __name__ == "__main__":
    unittest.main()

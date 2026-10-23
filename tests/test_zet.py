"""ZET のテスト。標準ライブラリの unittest のみ（jsonschema は判定一致の確認にだけ任意で使う）。"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from zet import audit, cli, triage
from zet.core import ROOT, ContractError, canonical, load_json, parse_ts, plan_hash, validator, write_atomic

FIX = ROOT / "tests" / "fixtures"
NOW = parse_ts("2026-10-22T10:00:00Z")


def load(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def make_input(findings: str = "findings-skillpact.json") -> dict:
    return {
        "schema_version": "1.0",
        "findings": load(findings),
        "policy": {"deadlines": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 90},
                   "decision_window_days": 14, "approvers": ["security-lead", "platform-owner", "alice"]},
        "skillpact_policy": {"l3_trusted": False, "diff_anomaly_threshold": 0.3, "destructive_requires_human": True},
    }


def fill(inp: dict, plan: dict) -> dict:
    """下書きを「全件 remediate（できないものは defer）」で埋めた合格計画にする。"""
    by_id = {x["id"]: x for x in inp["findings"]["findings"]}
    p = copy.deepcopy(plan)
    for it in p["items"]:
        x = by_id[it["finding_id"]]
        if it["decision"] is None:
            it["decision"] = "remediate"
            it["owner"] = "team-a"
            it["action"] = {"type": "chmod", "target": "/srv/target", "params": {"mode": "0600"}}
        it["decided_by"] = it["decided_by"] or "bob"
        it["decided_at"] = it["decided_at"] or "2026-10-22T10:00:00Z"
        if x.get("skillpact") and x["skillpact"]["diff_anomaly"]:
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
        self.assertTrue(all(it["decision"] is None for it in plan["items"]))


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
        it = self.item(lambda x: x["level"] == "CRITICAL")
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
        for it in final["items"]:
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


if __name__ == "__main__":
    unittest.main()

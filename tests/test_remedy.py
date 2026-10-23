"""ZET 0.2: finding → remediation mapping (draft suggestions), group, required follow-up work (I-13), relations (I-4), plan 1.1, findings 1.1."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import unittest

from zet import remedy, triage
from zet.core import ContractError, parse_ts, plan_hash
from zet.legacy_templates import PATH_NONE_JA, TEMPLATES_JA

NOW = parse_ts("2026-10-22T10:00:00Z")
R = "/w/repo"
H = "/w/home"


def setUpModule():
    os.environ["ZET_ALLOW_NOW_OVERRIDE"] = "1"


def tearDownModule():
    os.environ.pop("ZET_ALLOW_NOW_OVERRIDE", None)


def F(module, level, path, campaign=None, detail="d", content=True, **extra) -> dict:
    fid = "sha256:" + hashlib.sha256(f"{module}|{campaign}|{path}|{detail}".encode()).hexdigest()
    ev = "sha256:" + hashlib.sha256((path or "x").encode() if content else detail.encode()).hexdigest()
    x = {"id": fid, "level": level, "module": module, "campaign": campaign, "path": path, "detail": detail,
         "evidence_hash": ev, **extra}
    if module == "§49" and "skillpact" not in x:
        x["skillpact"] = {"contract_path": None, "contract_version": None, "level": None, "signed": False, "author": None,
                          "declared_effects": [], "observed_effects": ["network"], "policy_decision": None, "l2_tested": False,
                          "divergence": ["network"] if campaign == "skillpact-divergence" else [],
                          "diff_anomaly": campaign == "skillpact-account-compromise"}
    return x


def make_input(findings, version="1.0", scope=True, **top) -> dict:
    f = {"schema_version": version, "incident_bundle": "ZES-2026-OCT-EMERGENCY-V5.2", "scan_started_at": "2026-10-22T09:00:00Z",
         "scan_finished_at": "2026-10-22T09:01:00Z", "scan_mode": "full", "status": "ok", "findings": findings, "errors": [], **top}
    pol = {"deadlines": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 90}, "decision_window_days": 14,
           "approvers": ["sec-a", "sec-b"]}
    if scope:
        pol["scope"] = {"roots": [R], "home": H}
    return {"schema_version": "1.0", "findings": f, "policy": pol, "skillpact_policy": {"l3_trusted": False}}


SHA = "sha256:" + "a" * 64


def preview_params(a):
    """Stands in for the params that ger preview fills in (only the shape follows actions.schema.json)."""
    t = a["type"]
    if t == "quarantine":
        if a["relation"] in ("self",) and not a["target"].endswith(("net-tool", "/abcd")):
            return {"kind": "file", "sha256": SHA}
        p = {"kind": "tree", "tree_sha256": SHA}
        if a["relation"] in ("npm_pkg_dir", "npm_installed"):
            p["subject"] = {"name": "keyv", "version": "6.0.0"}
        if a["relation"] == "pypi_record":
            p["record"] = True
        return p
    if t in ("edit_json", "disable_mcp_server"):
        return {"format": "json", "ops": [{"op": "remove", "pointer": "/mcpServers/evil", "before_sha256": SHA}],
                "file_sha256": SHA, "expected_after_sha256": SHA}
    if t == "remove_line":
        return {"lines": [{"n": 1, "sha256": SHA, "pattern_id": "sh.ld_preload"}], "file_sha256": SHA, "expected_after_sha256": SHA}
    return a["params"]


def adopt(plan, label="auto"):
    p = copy.deepcopy(plan)
    for it in p["items"]:
        sug = it.get("constraints", {}).get("suggested_actions", [])
        pick = next((s for s in sug if s["label"] == label), None) or next((s for s in sug if s["label"] == "checklist"), None)
        if pick is None:
            continue
        a = copy.deepcopy(pick["action"])
        a["params"] = preview_params(a)
        it.update(decision="remediate", owner="team", decided_by="alice", decided_at="2026-10-22T10:00:00Z", action=a,
                  reason=None, exception_type=None, recheck_at=None)
        if it["due_at"] is None:
            it["due_at"] = "2026-10-25T10:00:00Z"
        need = it["constraints"]["min_approvers"]
        it["approved_by"] = ["sec-a", "sec-b"][:need]
    return p


def codes(v):
    return sorted({x.code for x in v})


class TestSuggestions(unittest.TestCase):
    def first(self, x, label="auto"):
        sug, _ = remedy.classify(x)
        return next((s["action"] for s in sug if s["label"] == label), None)

    def test_map(self):
        cases = [  # (finding, expected auto (type, relation, target) or None, followup templates, checklist template)
            (F("§17", "HIGH", R + "/.mcp.json", "mcp-poisoning"), ("disable_mcp_server", "self", R + "/.mcp.json"), {"CL-MCP", "CL-IR"}, "CL-MCP"),
            (F("§17", "MEDIUM", R + "/.mcp.json", "mcp-poisoning"), None, set(), "CL-MCP-PIN"),
            (F("§17", "HIGH", R + "/x/.codex/config.toml", "mcp-poisoning"), ("disable_mcp_server", "self", R + "/x/.codex/config.toml"), {"CL-MCP", "CL-IR"}, "CL-MCP"),  # noqa: E501
            (F("§17", "CRITICAL", R + "/docs/vid.mp4", "mcp-poisoning", content=False), ("quarantine", "self", R + "/docs/vid.mp4"), {"CL-IR"}, "CL-IR"),
            (F("§15", "CRITICAL", R + "/node_modules/keyv/package.json", "chaindrop-keyv"), ("quarantine", "npm_pkg_dir", R + "/node_modules/keyv"), {"CL-PKG", "CL-IR", "CL-SECRET"}, "CL-PKG"),  # noqa: E501
            (F("§15", "CRITICAL", R + "/package-lock.json", "chaindrop-keyv"), None, set(), "CL-LOCKFILE"),
            (F("§15", "CRITICAL", R + "/sp/litellm-1.107.0.dist-info", "litellm-oct2026", content=False), ("quarantine", "pypi_record", R + "/sp/litellm-1.107.0.dist-info"), {"CL-PKG", "CL-SECRET"}, "CL-VENV"),  # noqa: E501
            (F("§15", "HIGH", R + "/sp/certifi-2026.9.1.dist-info", "emudhra-ca-oct2026", content=False), None, set(), "CL-PKG"),
            (F("§15", "HIGH", R + "/Math_Symbol.js", "chaindrop-keyv"), ("quarantine", "self", R + "/Math_Symbol.js"), {"CL-IR", "CL-SECRET"}, "CL-IR"),
            (F("§2", "HIGH", R + "/package.json"), ("edit_json", "self", R + "/package.json"), {"CL-IR"}, "CL-IR"),
            (F("§2", "CRITICAL", R + "/sp/cook.pth", "litellm-oct2026"), ("quarantine", "self", R + "/sp/cook.pth"), {"CL-IR", "CL-SECRET"}, "CL-IR"),
            (F("§24", "HIGH", R + "/Extensions/abcd/manifest.json"), ("quarantine", "ext_dir", R + "/Extensions/abcd"), {"CL-EXT", "CL-IR"}, "CL-EXT"),
            (F("§30", "HIGH", H + "/Library/LaunchAgents/com.xyz.plist"), ("quarantine", "self", H + "/Library/LaunchAgents/com.xyz.plist"), {"CL-LAUNCHD", "CL-IR"}, "CL-IR"),  # noqa: E501
            (F("§31", "CRITICAL", R + "/ld.so.preload", "ebpf-rootkit"), ("remove_line", "self", R + "/ld.so.preload"), {"CL-LDSO", "CL-IR"}, "CL-IR"),
            (F("§31", "HIGH", H + "/.bashrc", "ebpf-rootkit"), ("remove_line", "self", H + "/.bashrc"), {"CL-SHELL", "CL-IR"}, "CL-IR"),
            (F("§4", "HIGH", R + "/php.ini"), ("remove_line", "self", R + "/php.ini"), {"CL-PHP-RESTART"}, "CL-PHP-RESTART"),
            (F("§4", "CRITICAL", R + "/Dockerfile"), None, set(), "CL-PHP"),
            (F("§7", "HIGH", R + "/.claude/settings.json", "actions-cool"), ("edit_json", "self", R + "/.claude/settings.json"), {"CL-IR"}, None),
            (F("§18", "CRITICAL", H + "/.zsh_history"), None, set(), "CL-IR"),
            (F("§21", "CRITICAL", R + "/.github/workflows/x.yml", "ghostaction-oct2026"), None, set(), "CL-PWN"),
            (F("§22", "HIGH", R + "/.github/workflows/x.yml", "ghostaction-oct2026"), None, set(), "CL-PIN"),
            (F("§16", "CRITICAL", R + "/docker-compose.yml"), None, set(), "CL-UPGRADE"),
            (F("§10", "MEDIUM", None), None, set(), "CL-CRON"),
            (F("§12", "MEDIUM", None), None, set(), "CL-ENV"),
            (F("§49", "HIGH", R + "/skills/net-tool", "skillpact-divergence", content=False), ("quarantine", "skill_dir", R + "/skills/net-tool"), {"CL-SKILL", "CL-IR"}, "CL-SKILL"),  # noqa: E501
            (F("§49", "HIGH", R + "/v2/skill.contract.json", "skillpact-account-compromise"), ("quarantine", "skill_dir", R + "/v2"), {"CL-SKILL", "CL-IR"}, "CL-SKILL"),  # noqa: E501
        ]
        for x, auto, fu, cl in cases:
            with self.subTest(module=x["module"], path=x["path"]):
                a = self.first(x)
                if auto is None:
                    self.assertIsNone(a)
                else:
                    self.assertEqual((a["type"], a["relation"], a["target"]), auto)
                    self.assertEqual({c["template"] for c in a.get("followup", [])}, fu)
                    self.assertIsNone(remedy.lexical_relation(a["relation"], a["target"], x["path"]))
                c = self.first(x, "checklist")
                if cl is None:
                    self.assertEqual(c["params"]["template"], "CL-REVIEW")
                else:
                    self.assertEqual(c["params"]["template"], cl)
                    self.assertEqual(c["target"], x["path"])
                    self.assertEqual(c["relation"], "self" if x["path"] else "none")

    def test_never_suggests_lockfile_edits_or_secret_rotation(self):
        # rewriting lockfiles and revoking secrets are never automated at any stage (checklist only)
        for x in (F("§15", "CRITICAL", R + "/yarn.lock", "chaindrop-keyv"), F("§47", "HIGH", R + "/.env"),
                  F("§45", "MEDIUM", H + "/.npmrc"), F("§22", "CRITICAL", R + "/.github/workflows/r.yml")):
            sug, _ = remedy.classify(x)
            self.assertEqual([s["label"] for s in sug], ["checklist"], x["path"])


class TestDraftGroupsAndFinalize(unittest.TestCase):
    def setUp(self):
        self.fs = [
            F("§2", "HIGH", R + "/package.json"),
            F("§15", "CRITICAL", R + "/package.json", "chaindrop-keyv", detail="preinstall"),
            F("§30", "HIGH", H + "/Library/LaunchAgents/com.zoom.plist", "overlord"),
            F("§10", "INFO", H + "/Library/LaunchAgents/com.zoom.plist"),
            F("§49", "HIGH", R + "/s/v08", "skillpact-divergence", content=False),
            F("§49", "MEDIUM", R + "/s/v08/skill.contract.json", "skillpact-invalid"),
            F("§15", "CRITICAL", R + "/package-lock.json", "chaindrop-keyv"),
            F("§10", "MEDIUM", None, detail="crontab"),
            F("§14", "INFO", H + "/.npmrc"),
        ]
        self.inp = make_input(self.fs)
        self.draft = triage.draft(self.inp, NOW, "alice", plan_id="11111111-2222-4333-8444-555555555555")

    def item(self, plan, i):
        return next(it for it in plan["items"] if it["finding_id"] == self.fs[i]["id"])

    def test_draft_groups_and_info(self):
        d = self.draft
        self.assertEqual(d["schema_version"], "1.1")
        self.assertEqual(d["scope"], {"roots": [R], "home": H})

        def g(i):
            return self.item(d, i)["constraints"]["suggested_actions"][0]["action"].get("group")
        self.assertIsNotNone(g(0))
        self.assertEqual(g(0), g(1))  # §2 and §15 on the same package.json
        self.assertEqual(g(2), g(3))  # the §30 plist and a §10 INFO on the same file
        self.assertIsNone(self.item(d, 3)["decision"])  # an INFO that the quarantine clears is not deferred automatically
        self.assertEqual(self.item(d, 8)["decision"], "defer")  # other INFO findings as before
        a5 = self.item(d, 5)["constraints"]["suggested_actions"][0]["action"]
        self.assertEqual((a5["type"], a5["relation"], a5["target"], a5.get("group")), ("quarantine", "skill_dir", R + "/s/v08", g(4)))

    def test_finalize_and_invariants(self):
        p = adopt(self.draft)
        final = triage.finalize(self.inp, p, now=NOW)
        self.assertEqual(final["schema_version"], "1.1")
        self.assertEqual(final["scope"], {"roots": [R], "home": H})
        for it in final["items"]:
            a = it["action"]
            if a:
                self.assertEqual(a["finding_path"], next(x["path"] for x in self.fs if x["id"] == it["finding_id"]))
                self.assertIn(a["evidence"]["kind"], ("file", "detail"))
                self.assertNotIn("evidence_hash", a)
        cron = self.item(final, 7)["action"]
        self.assertEqual((cron["type"], cron["target"], cron["relation"]), ("checklist", None, "none"))
        self.assertEqual(self.item(final, 4)["action"]["evidence"]["kind"], "detail")  # a directory has the hash of detail
        self.assertEqual(triage.check(self.inp, final, final=True, now=NOW), [])

        def bad(mut, code, text=None):
            q = copy.deepcopy(p)
            mut(q)
            v = triage.check(self.inp, q, now=NOW)
            self.assertIn(code, codes(v), v)
            if text:
                self.assertTrue(any(text in x.message for x in v), v)

        # I-13: remove required follow-up work, rewrite template steps
        bad(lambda q: self.item(q, 2)["action"].pop("followup"), "I-13", "CL-LAUNCHD")
        bad(lambda q: self.item(q, 2)["action"]["followup"][0]["steps"][0].update(text="Do nothing"), "I-13")
        bad(lambda q: self.item(q, 6)["action"]["params"]["steps"].pop(0), "I-13")
        # I-4: relation, target, group, scope
        bad(lambda q: self.item(q, 4)["action"].update(target=R + "/s"), "I-4", "skill_dir")
        bad(lambda q: self.item(q, 0)["action"].update(target=None, relation="none"), "I-4", "only a checklist")
        bad(lambda q: self.item(q, 0)["action"].pop("group"), "I-4", "group")
        bad(lambda q: self.item(q, 1)["action"].update(type="quarantine"), "I-4", "group")
        bad(lambda q: q.update(scope={"roots": ["/"], "home": None}), "I-4", "scope")
        bad(lambda q: self.item(q, 0)["action"].update(finding_path="/etc/passwd"), "I-4", "finding_path")
        # draft params (select) pass check, but in a finalized plan params that do not fit GER's actions.schema.json are I-4
        q = copy.deepcopy(p)
        self.item(q, 0)["action"]["params"] = {"select": "npm.lifecycle"}
        self.item(q, 1)["action"]["params"] = {"select": "npm.lifecycle"}
        self.assertEqual(triage.check(self.inp, q, now=NOW), [])
        with self.assertRaises(ContractError) as cm:
            triage.finalize(self.inp, q, now=NOW)
        self.assertIn("actions.schema.json", str(cm.exception))

    def test_scope_required_for_file_changes_and_root_targets_need_two(self):
        inp = make_input(self.fs, scope=False)
        p = adopt(triage.draft(inp, NOW, "alice"))
        self.assertIn("I-4", codes(triage.check(inp, p, now=NOW)))
        x = F("§31", "CRITICAL", "/etc/ld.so.preload", "ebpf-rootkit")
        inp = make_input([x])
        inp["policy"]["scope"]["roots"].append("/etc")
        d = triage.draft(inp, NOW, "alice")
        self.assertEqual(d["items"][0]["constraints"]["min_approvers"], 2)
        p = adopt(d)
        self.assertEqual(triage.check(inp, p, now=NOW), [])
        p["items"][0]["approved_by"] = ["sec-a"]
        self.assertIn("I-3", codes(triage.check(inp, p, now=NOW)))


class TestFindings11Draft(unittest.TestCase):
    def test_11_fields_accepted_and_used(self):
        lock = F("§15", "CRITICAL", R + "/package-lock.json", "chaindrop-keyv", kind="pkg.lockfile_compromised",
                 subject={"ecosystem": "npm", "package": "keyv", "version": "6.0.0", "safe_version": "5.x", "fixed_versions": []},
                 related=[{"relation": "npm_installed", "path": R + "/node_modules/keyv"}],
                 evidence={"kind": "file", "hash": SHA})
        mcp = F("§17", "HIGH", R + "/.mcp.json", "mcp-poisoning", kind="mcp.dangerous_command",
                locators=[{"format": "json", "pointer": "/mcpServers/evil"}])
        inp = make_input([lock, mcp], version="1.1", scope=False, scan_roots=[R])
        self.assertEqual(triage.validate_input(inp), [])
        d = triage.draft(inp, NOW, "alice")
        self.assertEqual(d["scope"], {"roots": [R], "home": None})
        # a lockfile finding gets no auto even with related npm_installed (§9.6; it stays until the lockfile is regenerated)
        a = d["items"][0]["constraints"]["suggested_actions"][0]["action"]
        self.assertEqual((a["type"], a["relation"], a["target"], a["params"]["template"]),
                         ("checklist", "self", R + "/package-lock.json", "CL-LOCKFILE"))
        p = adopt(d)
        final = triage.finalize(inp, p, now=NOW)
        self.assertEqual(final["items"][0]["action"]["evidence"], {"kind": "file", "hash": SHA})
        # I-13: operations allowed per kind
        q = copy.deepcopy(p)
        q["items"][1]["action"]["type"] = "remove_line"
        q["items"][1]["action"]["params"] = preview_params(q["items"][1]["action"])
        q["items"][1]["action"].pop("followup", None)
        self.assertIn("I-13", codes(triage.check(inp, q, now=NOW)))
        # findings 1.0 with 1.1 fields are rejected (strict)
        inp10 = make_input([dict(mcp)])
        self.assertIn("I-11", codes(triage.validate_input(inp10)))

    def test_12_code_params_accepted(self):
        # findings 1.2 (ZES 0.5.0): code / params, English detail, id v2. ZET never parses detail or recomputes ids
        mcp = F("§17", "HIGH", R + "/.mcp.json", "mcp-poisoning", kind="mcp.dangerous_command",
                locators=[{"format": "json", "pointer": "/mcpServers/evil"}], code="s17.dangerous_command", params={},
                detail="Dangerous command in MCP or agent config command/args")
        lock = F("§15", "CRITICAL", R + "/package-lock.json", "chaindrop-keyv", kind="pkg.lockfile_compromised",
                 subject={"ecosystem": "npm", "package": "keyv", "version": "6.0.0", "safe_version": "latest 5.x", "fixed_versions": []},
                 evidence={"kind": "file", "hash": SHA}, code="s15.pkg_compromised_safe",
                 params={"ecosystem": "npm", "package": "keyv", "safe_version": "latest 5.x", "version": "6.0.0"})
        inp = make_input([mcp, lock], version="1.2", scope=False, scan_roots=[R])
        self.assertEqual(triage.validate_input(inp), [])
        d = triage.draft(inp, NOW, "alice")
        self.assertEqual(len(d["items"]), 2)
        final = triage.finalize(inp, adopt(d), now=NOW)
        self.assertEqual({i["finding_id"] for i in final["items"]}, {mcp["id"], lock["id"]})
        # params values are strings only; code / params are not allowed in 1.1 (strict per version)
        bad = copy.deepcopy(inp)
        bad["findings"]["findings"][1]["params"]["version"] = 6
        self.assertIn("I-11", codes(triage.validate_input(bad)))
        self.assertIn("I-11", codes(triage.validate_input(make_input([dict(mcp)], version="1.1", scope=False, scan_roots=[R]))))

    def test_evidence_of(self):
        x = F("§49", "HIGH", R + "/s", "skillpact-divergence", content=False, detail="dd")
        self.assertEqual(triage.evidence_of(x)["kind"], "detail")
        y = F("§17", "HIGH", R + "/.mcp.json")
        self.assertEqual(triage.evidence_of(y), {"kind": "file", "hash": y["evidence_hash"]})


class TestLockfileFindingStaysOpen(unittest.TestCase):
    """A lockfile finding (pkg.lockfile_compromised, or a §15 lockfile) is not cleared by quarantining the installed copy
    (ZES reports it again from the contents of the lockfile). The quarantine is the auto of the node_modules/<name>/package.json
    finding; the lockfile finding stays as a checklist with the regeneration steps (CL-LOCKFILE) until the operator completes it (§9.6, I-13)."""

    def setUp(self):
        subj = {"ecosystem": "npm", "package": "keyv", "version": "6.0.0", "safe_version": "5.x", "fixed_versions": []}
        self.lock = F("§15", "CRITICAL", R + "/package-lock.json", "chaindrop-keyv", kind="pkg.lockfile_compromised", subject=subj,
                      related=[{"relation": "npm_installed", "path": R + "/node_modules/keyv"}], evidence={"kind": "file", "hash": SHA})
        self.inst = F("§15", "CRITICAL", R + "/node_modules/keyv/package.json", "chaindrop-keyv", kind="pkg.compromised",
                      subject=subj, evidence={"kind": "file", "hash": "sha256:" + "b" * 64})
        self.inp = make_input([self.lock, self.inst], version="1.1", scope=False, scan_roots=[R])
        self.draft = triage.draft(self.inp, NOW, "alice", plan_id="11111111-2222-4333-8444-555555555555")

    def sug(self, plan, x):
        return next(it for it in plan["items"] if it["finding_id"] == x["id"])["constraints"]["suggested_actions"]

    def test_draft_quarantine_is_the_installed_finding_and_lockfile_is_checklist(self):
        ls = self.sug(self.draft, self.lock)
        self.assertEqual([s["label"] for s in ls], ["checklist"])
        steps = ls[0]["action"]["params"]["steps"]
        self.assertEqual(ls[0]["action"]["params"]["template"], "CL-LOCKFILE")
        regen = [s for s in steps if "npm uninstall keyv" in s["text"]]
        self.assertEqual(len(regen), 1)
        self.assertTrue(regen[0]["blocking"])
        self.assertNotIn("verify", ls[0]["action"]["params"])  # GER never completes it by itself (only the operator's ger confirm)
        ia = next(s for s in self.sug(self.draft, self.inst) if s["label"] == "auto")["action"]
        self.assertEqual((ia["type"], ia["relation"], ia["target"]), ("quarantine", "npm_pkg_dir", R + "/node_modules/keyv"))
        self.assertNotIn("group", ia)  # the lockfile finding is not put in the same group
        final = triage.finalize(self.inp, adopt(self.draft), now=NOW)
        types = {it["finding_id"]: it["action"]["type"] for it in final["items"]}
        self.assertEqual(types, {self.lock["id"]: "checklist", self.inst["id"]: "quarantine"})

    def test_lockfile_alone_is_checklist_too(self):
        inp = make_input([self.lock], version="1.1", scope=False, scan_roots=[R])
        d = triage.draft(inp, NOW, "alice")
        self.assertEqual([s["label"] for s in self.sug(d, self.lock)], ["checklist"])

    def test_i13_rejects_auto_on_lockfile_finding(self):
        p = adopt(self.draft)
        it = next(i for i in p["items"] if i["finding_id"] == self.lock["id"])
        q = copy.deepcopy(p)
        qa = next(i for i in q["items"] if i["finding_id"] == self.lock["id"])
        qa["action"] = {"type": "quarantine", "target": R + "/node_modules/keyv", "relation": "npm_installed", "finding_path": self.lock["path"],
                        "params": {"kind": "tree", "tree_sha256": SHA, "subject": {"name": "keyv", "version": "6.0.0"}},
                        "followup": [remedy.checklist(t, self.lock["path"]) for t in ("CL-PKG", "CL-SECRET")]}
        v = triage.check(self.inp, q, now=NOW)
        self.assertIn("I-13", codes(v), v)
        self.assertTrue(any("lockfile" in x.message for x in v), v)
        # the same with findings 1.0 (no kind) for a §15 lockfile
        lock10 = {k: v for k, v in self.lock.items() if k not in ("kind", "subject", "related", "evidence")}
        inst10 = {k: v for k, v in self.inst.items() if k not in ("kind", "subject", "evidence")}
        inp10 = make_input([lock10, inst10])
        q10 = adopt(triage.draft(inp10, NOW, "alice"))
        self.assertEqual(triage.check(inp10, q10, now=NOW), [])
        qa10 = next(i for i in q10["items"] if i["finding_id"] == lock10["id"])
        qa10["action"] = copy.deepcopy(qa["action"])
        self.assertIn("I-13", codes(triage.check(inp10, q10, now=NOW)))
        # a checklist whose template lacks the regeneration steps (CL-LOCKFILE) is not allowed either
        q = copy.deepcopy(p)
        qa = next(i for i in q["items"] if i["finding_id"] == self.lock["id"])
        qa["action"]["params"] = remedy.checklist("CL-REVIEW", self.lock["path"])
        self.assertIn("I-13", codes(triage.check(self.inp, q, now=NOW)))
        # rewriting or removing the regeneration steps is not allowed either
        q = copy.deepcopy(p)
        qa = next(i for i in q["items"] if i["finding_id"] == self.lock["id"])
        qa["action"]["params"]["steps"] = [s for s in qa["action"]["params"]["steps"] if "npm uninstall" not in s["text"]]
        self.assertIn("I-13", codes(triage.check(self.inp, q, now=NOW)))
        self.assertEqual(it["action"]["type"], "checklist")


class TestLegacyJapaneseTemplates(unittest.TestCase):
    """Drafts and plans made by ZET before the English-first release carry the Japanese step texts. I-13 still
    accepts them word for word (legacy_templates), so an old draft can be finalized and an old plan checked."""

    def setUp(self):
        self.fs = [
            F("§30", "HIGH", H + "/Library/LaunchAgents/com.evil.plist", "chaindrop-keyv"),
            F("§3", "HIGH", None, detail="runtime"),
            F("§15", "CRITICAL", R + "/package-lock.json", "chaindrop-keyv"),
        ]
        self.inp = make_input(self.fs)
        self.plan = adopt(triage.draft(self.inp, NOW, "alice", plan_id="11111111-2222-4333-8444-555555555555"))

    def to_japanese(self, plan):
        q = copy.deepcopy(plan)
        for it in q["items"]:
            a = it["action"]
            if not a:
                continue
            x = next(f for f in self.fs if f["id"] == it["finding_id"])
            for cl in ([a["params"]] if a["type"] == "checklist" else []) + a.get("followup", []):
                cl["steps"] = remedy._steps(TEMPLATES_JA, cl["template"], x["path"], remedy.pkg_of(x), PATH_NONE_JA)
        return q

    def test_tables_have_the_same_steps(self):
        self.assertEqual(set(TEMPLATES_JA), remedy.TEMPLATES)
        for k in remedy.TEMPLATES:
            self.assertEqual([b for _, b in TEMPLATES_JA[k]], [b for _, b in remedy._T[k]], k)
            for (en, _), (ja, _) in zip(remedy._T[k], TEMPLATES_JA[k]):
                self.assertEqual(("{path}" in en, "{pkg}" in en), ("{path}" in ja, "{pkg}" in ja), k)

    def test_new_drafts_are_english(self):
        texts = [s["text"] for it in self.plan["items"] if it["action"]
                 for cl in ([it["action"]["params"]] if it["action"]["type"] == "checklist" else []) + it["action"].get("followup", [])
                 for s in cl["steps"]]
        self.assertTrue(texts)
        self.assertFalse([t for t in texts if re.search("[\u3000-\u30ff\u4e00-\u9fff\uff00-\uffef]", t)])
        every = [t for k in remedy.TEMPLATES for t, _ in remedy._T[k]]
        self.assertFalse([t for t in every if re.search("[\u3000-\u30ff\u4e00-\u9fff\uff00-\uffef]", t)])
        self.assertIn("Target: (no path)", " ".join(texts))

    def test_japanese_plan_finalizes_and_checks(self):
        ja = self.to_japanese(self.plan)
        self.assertNotEqual(ja, self.plan)
        self.assertIn("対象: （path なし）", json.dumps(ja, ensure_ascii=False))
        self.assertEqual(triage.check(self.inp, ja, now=NOW), [])
        final = triage.finalize(self.inp, ja, now=NOW)
        self.assertEqual(triage.check(self.inp, final, final=True, now=NOW), [])

    def test_mixed_or_changed_text_is_rejected(self):
        ja = self.to_japanese(self.plan)
        it = next(i for i in ja["items"] if i["action"] and i["action"].get("followup"))
        it["action"]["followup"][0]["steps"][0]["text"] = self.plan["items"][ja["items"].index(it)]["action"]["followup"][0]["steps"][0]["text"]
        self.assertIn("I-13", codes(triage.check(self.inp, ja, now=NOW)))
        ja = self.to_japanese(self.plan)
        it = next(i for i in ja["items"] if i["action"] and i["action"]["type"] == "checklist")
        it["action"]["params"]["steps"][0]["text"] += "。"
        self.assertIn("I-13", codes(triage.check(self.inp, ja, now=NOW)))


class TestPlanHashUnchanged(unittest.TestCase):
    def test_plan_hash_definition(self):
        p = {"schema_version": "1.1", "plan_id": "x", "items": [], "held": []}
        self.assertEqual(plan_hash(p), plan_hash(dict(p, plan_hash="sha256:" + "0" * 64)))


if __name__ == "__main__":
    unittest.main()

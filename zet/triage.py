"""Decision logic: input validation, draft generation, invariant checks and finalization. Pure functions without I/O."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import posixpath
import re
import uuid
from typing import Any

from . import remedy
from .core import (DECISIONS, FS_CHANGING, GER_ACTION_TYPES, PLAN_SCHEMA_VERSION, REVERSIBLE_BY_TYPE, RISKY_EFFECTS,
                   ContractError, Violation, fmt_ts, parse_ts, plan_hash, schema_violations, validator)

MAX_DAYS = 3650  # maximum of deadlines / decision_window_days in triage-input.schema.json
_CHMOD_MODE = re.compile(r"0[0-7]{3}")  # same as GER. No special bits (setuid / setgid / sticky)
# Reserved, unimplemented skillpact_policy fields. Accepting a value and silently ignoring it would suggest that a
# setting is in effect when it is not (for example destructive_requires_human: true), so they are rejected when given
RESERVED_SKILLPACT_POLICY = ("diff_anomaly_threshold", "destructive_requires_human")


# --- Input validation (zet validate) ---------------------------------------
def validate_input(inp: Any) -> list[Violation]:
    v = schema_violations("triage-input.schema.json", inp, "triage-input")
    if v:
        return v
    f = inp["findings"]
    # findings 1.0 (ZES 0.3.x), 1.1 (ZES 0.4.0 and later: kind / subject / locators / related / evidence / scan_roots),
    # 1.2 (ZES 0.5.0 and later: code / params, English detail, id v2). Each version is validated with its own pinned schema
    ver = f.get("schema_version") if isinstance(f, dict) else None
    name = {"1.1": "vendor/findings-1.1.schema.json", "1.2": "vendor/findings-1.2.schema.json"}.get(ver, "vendor/findings.schema.json")
    v = schema_violations(name, f, "findings")
    if v:
        return v
    if f["status"] == "error":
        v.append(Violation("I-12", 'input with findings.status == "error" is not accepted (failure propagation)'))
    if inp["skillpact_policy"]["l3_trusted"]:
        v.append(Violation("SP", "skillpact_policy.l3_trusted = true violates the contract (an L3 signature is not a basis for trust)"))
    for k in RESERVED_SKILLPACT_POLICY:
        if k in inp["skillpact_policy"]:
            v.append(Violation("SP", f"skillpact_policy.{k} is reserved and not implemented (ZET does not evaluate it). Remove it"))
    ids = [x["id"] for x in f["findings"]]
    if len(ids) != len(set(ids)):
        v.append(Violation("I-2", "findings contains duplicate ids"))
    used = {x["level"] for x in f["findings"]} | {"CRITICAL"}
    for lv in used:
        if lv != "INFO" and lv not in inp["policy"]["deadlines"]:
            v.append(Violation("I-9", f"policy.deadlines has no entry for {lv}"))
    return v


def require_valid_input(inp: Any) -> None:
    v = validate_input(inp)
    if v:
        raise ContractError(v)


# --- Constraints derived from the input (never trusted from the plan; recomputed here every time) ---
def errored_modules(findings: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in findings["errors"]:
        out.setdefault(e["module"], []).append(e["reason"])
    return out


def level_effective(finding: dict) -> str:
    sp = finding.get("skillpact")
    if sp and sp["signed"] and sp["divergence"]:
        return "CRITICAL"
    return finding["level"]


def allowed_decisions(finding: dict) -> tuple[str, ...]:
    sp = finding.get("skillpact")
    if sp and sp["divergence"]:
        return ("remediate", "defer")
    return DECISIONS


def min_approvers(finding: dict, decision: str | None, action: dict | None = None) -> int:
    sp = finding.get("skillpact")
    n = 0
    if decision == "remediate" and action and action.get("type") in FS_CHANGING and remedy.root_required(action.get("target")):
        n = 2  # a target that needs root (/etc and so on) needs 2 approvers, as in GER
    if decision == "exception":
        n = 1
    if sp and sp["diff_anomaly"]:
        n = max(n, 2)
    if decision == "remediate" and risky_effects(finding):
        n = max(n, 2)  # same as GER's G-6: an operation on a skill that declares exec / network / spend / send needs 2 or more
    return n


def skillpact_effects(finding: dict) -> list[str]:
    sp = finding.get("skillpact")
    return list(sp["declared_effects"]) if sp else []


def risky_effects(finding: dict) -> list[str]:
    return [e for e in skillpact_effects(finding) if e in RISKY_EFFECTS]


def skillpact_summary(finding: dict) -> dict | None:
    """items[].skillpact of a finalized plan. Lets GER recheck I-5 / I-6 / I-7 and skillpact_effects from the plan alone."""
    sp = finding.get("skillpact")
    if not sp:
        return None
    return {"signed": sp["signed"], "divergence": list(sp["divergence"]), "diff_anomaly": sp["diff_anomaly"],
            "declared_effects": list(sp["declared_effects"])}


def _same_summary(a: dict, b: dict) -> bool:
    return (a["signed"] == b["signed"] and a["diff_anomaly"] == b["diff_anomaly"]
            and sorted(a["divergence"]) == sorted(b["divergence"])
            and sorted(a["declared_effects"]) == sorted(b["declared_effects"]))


def evidence_of(finding: dict) -> dict:
    """action.evidence: the findings 1.1 evidence, otherwise derived from the 1.0 evidence_hash
    (ZES uses the content hash for a regular file and the hash of detail otherwise; a match with detail means detail)."""
    if isinstance(finding.get("evidence"), dict) and "hash" in finding["evidence"]:
        return {"kind": finding["evidence"].get("kind", "file"), "hash": finding["evidence"]["hash"]}
    h = finding["evidence_hash"]
    det = "sha256:" + hashlib.sha256(finding["detail"].encode("utf-8", "surrogateescape")).hexdigest()
    return {"kind": "detail" if h == det else "file", "hash": h}


def scope_of(inp: dict) -> dict | None:
    """plan.scope (the scan scope being approved). The findings 1.1 scan_roots, otherwise policy.scope of the triage input."""
    f = inp["findings"]
    pol = inp["policy"].get("scope")
    if f.get("scan_roots"):
        return {"roots": list(f["scan_roots"]), "home": (pol or {}).get("home")}
    if pol:
        return {"roots": list(pol["roots"]), "home": pol.get("home")}
    return None


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return root == "/" or path == root or path.startswith(root + "/")


def _is_draft_params(a: dict) -> bool:
    p = a["params"]
    return isinstance(p, dict) and ("select" in p or (not p and a["type"] in FS_CHANGING - {"chmod"}))


def _action_shape_violations(a: dict, fid: str, finding: dict, sug: list | None = None, final: bool = False) -> list[Violation]:
    """Do not finalize actions that GER always rejects, or actions on targets unrelated to the finding (I-4 / I-13)."""
    v: list[Violation] = []
    t = a["target"]
    path = finding["path"]
    # normpath keeps a leading // (implementation-defined in POSIX), so // is rejected separately wherever it is (GER rejects it)
    if t is not None and (not t.startswith("/") or "//" in t or posixpath.normpath(t) != t or ".." in t.split("/")):
        v.append(Violation("I-4", "action.target must be a normalized absolute path (no . / .. / repeated /)", fid))
    if a["type"] not in GER_ACTION_TYPES:
        v.append(Violation("I-4", f"action.type {a['type']} is not an operation type that GER can run ({', '.join(sorted(GER_ACTION_TYPES))})", fid))
    if "finding_path" in a and a["finding_path"] != path:
        v.append(Violation("I-4", "action.finding_path must equal the finding's path", fid))
    rel = a.get("relation", "none" if t is None else "self")
    if a["type"] == "checklist":
        if t is not None and t != path:
            v.append(Violation("I-4", "action.target of a checklist must be the finding's path (or null)", fid))
        if rel != ("none" if t is None else "self"):
            v.append(Violation("I-4", "the relation of a checklist must be self (none when target is null)", fid))
    elif t is None:
        v.append(Violation("I-4", "only a checklist can have a null target (a finding whose path is null cannot have an action: the target is unknown)"
                           if path is None else "only a checklist can have a null target", fid))
    elif path is None:
        v.append(Violation("I-4", "a finding whose path is null cannot have an action (the target is unknown; a checklist with target null is allowed)", fid))
    elif rel == "self" and t != path:
        v.append(Violation("I-4", "action.target must equal the finding's path (not a path below it or another path, "
                                  "except a target derived through relation)", fid))
    else:
        why = remedy.lexical_relation(rel, t, path, finding.get("related"))
        if why:
            v.append(Violation("I-4", why, fid))
    if a["type"] in GER_ACTION_TYPES and (final or not _is_draft_params(a)):
        for e in validator("vendor/actions.schema.json").errors({"type": a["type"], "params": a["params"]}):
            v.append(Violation("I-4", f"action.params{e} (the shape is GER's actions.schema.json; ger preview fills it in)", fid))
    if a["type"] == "chmod":
        p = a["params"]
        if set(p) != {"mode"} or not isinstance(p["mode"], str) or not _CHMOD_MODE.fullmatch(p["mode"]):
            v.append(Violation("I-4", 'the params of chmod must be {"mode": "0NNN"} only (3 octal digits, no setuid / setgid / sticky)', fid))
        elif int(p["mode"], 8) & 0o002:
            # ZET cannot see the current mode (GER confirms in G-7 that no permission is added). Loosening that is visible statically is rejected
            v.append(Violation("I-4", "chmod cannot grant write permission to others (world-writable); remediation only narrows permissions", fid))
    pkg = remedy.pkg_of(finding)
    if a["type"] == "checklist" and isinstance(a["params"], dict) and not remedy.template_ok(a["params"], path, pkg):
        v.append(Violation("I-13", "the steps of a checklist must include all the steps of the ZET template", fid))
    fus = a.get("followup", [])
    if a["type"] == "checklist" and fus:
        v.append(Violation("I-4", "a checklist action cannot have followup (write the steps in params.steps)", fid))
    for fu in fus:
        if not remedy.template_ok(fu, path, pkg):
            v.append(Violation("I-13", f"{fu.get('template')} in action.followup must include all the steps of the ZET template", fid))
    need = remedy.required_followups(finding, a, sug or [])
    missing = sorted(need - {fu.get("template") for fu in fus})
    if missing:
        v.append(Violation("I-13", f"automatic remediation requires the follow-up work {', '.join(missing)} (action.followup)", fid))
    if remedy.is_lockfile_finding(finding):
        # §9.6: automatic remediation does not clear a lockfile finding (ZES reports it again after the installed copy is
        # quarantined). Checklist only, with the template that contains the regeneration steps. The operator completes it (ger confirm)
        want = remedy.lockfile_template(finding)
        if a["type"] != "checklist":
            v.append(Violation("I-13", f"automatic remediation does not clear a lockfile finding, so only a checklist ({want}) is allowed. "
                                       "Quarantine the installed copy through the node_modules/<name>/package.json finding", fid))
        elif isinstance(a["params"], dict) and a["params"].get("template") != want:
            v.append(Violation("I-13", f"the checklist of a lockfile finding must be {want}, which contains the regeneration steps", fid))
    kind = finding.get("kind")
    if kind in remedy.KIND_ACTIONS and a["type"] not in remedy.KIND_ACTIONS[kind]:
        v.append(Violation("I-13", f"operation {a['type']} cannot be used on a finding of kind {kind} ({', '.join(sorted(remedy.KIND_ACTIONS[kind]))})", fid))
    return v


def _timestamp_violations(plan: dict) -> list[Violation]:
    """Return I-11 for date-times that are well-formed but do not exist (month 13, second 60, and so on)."""
    v: list[Violation] = []
    pairs = [(None, plan["created_at"])]
    pairs += [(it["finding_id"], it[k]) for it in plan["items"] for k in ("decided_at", "due_at", "recheck_at")]
    for fid, ts in pairs:
        try:
            if ts is not None:
                parse_ts(ts)
        except ValueError:
            v.append(Violation("I-11", f"date-time does not exist: {ts}", fid))
    return v


# --- Draft (zet draft) ------------------------------------------------------
def draft(inp: dict, now: dt.datetime, operator: str, plan_id: str | None = None, now_override: bool = False) -> dict:
    require_valid_input(inp)
    try:  # deadlines are at most 3650 days in the schema. No draft when that cannot be added to the current time
        now + dt.timedelta(days=MAX_DAYS)
    except OverflowError:
        raise ContractError([Violation("I-11", "the current time is outside the date-time range")]) from None
    f = inp["findings"]
    pol = inp["policy"]
    errmods = errored_modules(f)
    items: list[dict] = []
    held: list[dict] = []
    for mod in sorted(errmods):
        for reason in sorted(set(errmods[mod])):
            held.append({"finding_id": None, "module": mod, "reason": f"scan_error:{reason}"})
    judged = [x for x in f["findings"] if x["module"] not in errmods]
    sugs = remedy.suggest_all(judged)
    for x in f["findings"]:
        if x["module"] in errmods:
            held.append({"finding_id": x["id"], "module": x["module"], "reason": "module_unconfirmed"})
            continue
        lv = level_effective(x)
        days = pol["deadlines"].get(lv)
        sug = sugs.get(x["id"], [])
        # Use the raised severity (an INFO raised to CRITICAL is not deferred automatically). An INFO is not deferred
        # automatically either when another finding's automatic remediation quarantines the same target (the quarantine
        # clears it, so the decision maker decides whether to put it in the group)
        info_default = lv == "INFO" and not any(s_["label"] == "auto" for s_ in sug)
        if lv == "INFO" and days is None and not info_default:
            days = pol["deadlines"].get("LOW")
        items.append({
            "finding_id": x["id"],
            "decision": "defer" if info_default else None,
            "exception_type": None,
            "reason": "informational" if info_default else None,
            "owner": None,
            "decided_by": operator if info_default else None,
            "decided_at": fmt_ts(now) if info_default else None,
            "due_at": fmt_ts(now + dt.timedelta(days=days)) if days is not None and not info_default else None,
            "recheck_at": fmt_ts(now + dt.timedelta(days=pol["decision_window_days"])),
            "approved_by": [],
            "level_effective": lv,
            "action": None,
            "constraints": {
                "allowed_decisions": list(allowed_decisions(x)),
                # the strictest of the allowed decisions (exception 1; diff_anomaly, risky effects, remediate of a target that needs root 2)
                "min_approvers": max([min_approvers(x, d) for d in allowed_decisions(x)]
                                     + [min_approvers(x, "remediate", s_["action"]) for s_ in sug]),
                **({"suggested_actions": sug} if sug else {}),
            },
        })
    out = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": plan_id or str(uuid.uuid4()),
        "created_at": fmt_ts(now),
        "status": "draft",
        "items": items,
        "held": held,
    }
    sc = scope_of(inp)
    if sc is not None:
        out["scope"] = sc
    if now_override:  # tell finalize and GER that created_at comes from --now
        out["now_override"] = True
    return out


# --- Invariant checks (zet check) -----------------------------------------
def check(inp: dict, plan: Any, final: bool = False, now: dt.datetime | None = None) -> list[Violation]:
    """I-1 to I-13. A missing decision is also returned as a violation. final=True checks a finalized plan (the output of
    finalize / the input of GER).

    A plan with plan_hash is a finalized plan, so it is checked as one whatever final says
    (a tampered finalized plan must not pass check and then be silently rehashed by finalize).
    """
    require_valid_input(inp)
    final = final or (isinstance(plan, dict) and "plan_hash" in plan)
    v = schema_violations("remediation-plan.schema.json", plan, "plan")
    if v:
        return v
    f = inp["findings"]
    pol = inp["policy"]
    by_id = {x["id"]: x for x in f["findings"]}
    errmods = errored_modules(f)
    approvers = {a.casefold() for a in pol["approvers"]}  # names are ASCII. A difference in case does not make a different person
    now = now or dt.datetime.now(dt.timezone.utc)
    v = _timestamp_violations(plan)
    if v:
        return v
    created = parse_ts(plan["created_at"])

    # I-1 / I-2 / I-10: every finding appears exactly once, in items or in held
    seen: dict[str, str] = {}
    for where, lst in (("items", plan["items"]), ("held", plan["held"])):
        for e in lst:
            fid = e["finding_id"]
            if fid is None:
                continue
            if fid not in by_id:
                v.append(Violation("I-2", f"finding_id in {where} is not in the input", fid))
                continue
            if fid in seen:
                v.append(Violation("I-1", f"finding appears twice, in {seen[fid]} and in {where}", fid))
            seen[fid] = where
    for fid in by_id:
        if fid not in seen:
            v.append(Violation("I-1", "finding is neither decided nor held", fid))
    for fid, where in seen.items():
        if by_id[fid]["module"] in errmods and where != "held":
            v.append(Violation("I-10", f"a finding of the unconfirmed module {by_id[fid]['module']} must be held", fid))
    # held is only for modules in errors[] (unconfirmed). A finding of a confirmed module cannot escape a decision through held
    for h in plan["held"]:
        fid, mod = h["finding_id"], h.get("module")
        if fid is None:
            if mod not in errmods:
                v.append(Violation("I-10", f"module {mod} is not in errors[], so it cannot be held as a module"))
            continue
        x = by_id.get(fid)
        if x is None:
            continue
        if mod is not None and mod != x["module"]:
            v.append(Violation("I-10", f"module {mod} in held does not match the finding's module {x['module']}", fid))
        if x["module"] not in errmods:
            v.append(Violation("I-1", f"module {x['module']} is confirmed, so the finding cannot be held (decide it in items)", fid))
    held_mods = {h.get("module") for h in plan["held"] if h["finding_id"] is None}
    for mod in errmods:
        if mod not in held_mods:
            v.append(Violation("I-12", f"module {mod} in errors[] must be held as a module"))

    # I-12: failure propagation
    if f["status"] == "partial":
        if plan["status"] not in ("partial", "draft"):
            v.append(Violation("I-12", "the input is partial, so plan.status must be partial"))
        if not plan["held"]:
            v.append(Violation("I-12", "the input is partial but held is empty"))
    elif plan["status"] == "partial":
        v.append(Violation("I-12", "the input is ok but plan.status is partial"))
    if plan["status"] == "error":
        v.append(Violation("I-12", "a plan with status: error is never created"))

    # I-4: with two operations on the same target GER rejects the whole plan (the result would depend on the order).
    # Several findings on the same file are combined with action.group (type and target must match; GER writes once)
    targets: dict[str, tuple[str, str | None]] = {}
    groups: dict[str, tuple[str, str | None]] = {}
    for it in plan["items"]:
        a = it["action"]
        if it["decision"] != "remediate" or not isinstance(a, dict):
            continue
        g = a.get("group")
        if g is not None:
            if g in groups and groups[g] != (a["type"], a["target"]):
                v.append(Violation("I-4", f"the actions of group {g} must have the same type and target", it["finding_id"]))
            groups.setdefault(g, (a["type"], a["target"]))
        if a["type"] not in FS_CHANGING:
            continue
        if a["target"] in targets:
            first, g0 = targets[a["target"]]
            if g is None or g != g0:
                v.append(Violation("I-4", f"action.target is the same as for {first} (combine the same target with action.group)", it["finding_id"]))
        else:
            targets[a["target"]] = (it["finding_id"], g)
    # I-4: the target of an operation that changes files must be under the approved scan scope (plan.scope)
    fs_actions = [it for it in plan["items"] if it["decision"] == "remediate" and isinstance(it["action"], dict)
                  and it["action"]["type"] in FS_CHANGING]
    want_scope = scope_of(inp)
    if "scope" in plan and plan["scope"] != want_scope:
        v.append(Violation("I-4", "plan.scope must equal the value derived from the input (scan_roots of the findings, or policy.scope)"))
    if fs_actions and plan["schema_version"] == PLAN_SCHEMA_VERSION:
        # chmod (the original operation) is allowed without a scope. With a scope, the chmod target must be under it too
        if want_scope is None and any(it["action"]["type"] != "chmod" for it in fs_actions):
            v.append(Violation("I-4", "operations that change files need a scan scope (policy.scope of the triage input, or scan_roots of findings 1.1)"))
        elif want_scope is not None:
            places = want_scope["roots"] + ([want_scope["home"]] if want_scope.get("home") else [])
            for it in fs_actions:
                t = it["action"]["target"]
                if t is not None and not any(_under(t, r) for r in places):
                    v.append(Violation("I-4", "action.target is outside the scan scope (plan.scope)", it["finding_id"]))
    sugs = remedy.suggest_all([x for x in f["findings"] if x["module"] not in errmods])

    for it in plan["items"]:
        fid = it["finding_id"]
        x = by_id.get(fid)
        if x is None:
            continue
        d = it["decision"]
        lv = level_effective(x)
        if it["level_effective"] != lv:
            code = "I-7" if lv == "CRITICAL" and x.get("skillpact") else "I-3"
            v.append(Violation(code, f"level_effective must be {lv} (derived from the input; it cannot be lowered or changed)", fid))
        if d is None:
            v.append(Violation("I-1", "decision is missing", fid))
            continue
        if d not in allowed_decisions(x):
            v.append(Violation("I-5", "a finding with a non-empty skillpact.divergence cannot be an exception", fid))
        if not it["decided_by"] or not it["decided_at"]:
            v.append(Violation("I-3", "decided_by and decided_at are required", fid))
        appr = sorted({a.casefold() for a in it["approved_by"]})
        if len(appr) != len(it["approved_by"]):
            v.append(Violation("I-6", "approved_by contains duplicates", fid))
        unknown = [a for a in appr if a not in approvers]
        if unknown:
            v.append(Violation("I-8", f"approvers not in policy.approvers: {', '.join(unknown)}", fid))
        need = min_approvers(x, d, it["action"])
        if len(appr) < need:
            code = "I-6" if x.get("skillpact") and (x["skillpact"]["diff_anomaly"] or need == 2) else "I-3"
            v.append(Violation(code, f"approvers required: at least {need} (current: {len(appr)})", fid))
        if it["decided_by"] and it["decided_by"].casefold() in appr:
            v.append(Violation("I-3", "the decision maker is among the approvers (self-approval)", fid))
        if d == "exception":
            if it["exception_type"] is None:
                v.append(Violation("I-3", "exception requires exception_type", fid))
            if not (it["reason"] or "").strip():
                v.append(Violation("I-3", "exception requires reason", fid))
            if not it["recheck_at"]:
                v.append(Violation("I-3", "exception requires recheck_at", fid))
        elif it["exception_type"] is not None:
            v.append(Violation("I-3", "exception_type is set on a decision other than exception", fid))
        if d == "defer" and lv != "INFO":
            # a defer without a date or a reason would be an open-ended exception without approval. Outside INFO, reason and recheck_at are required
            if not (it["reason"] or "").strip():
                v.append(Violation("I-3", "defer (level_effective other than INFO) requires reason", fid))
            if not it["recheck_at"]:
                v.append(Violation("I-9", "defer (level_effective other than INFO) requires recheck_at", fid))
        if d == "remediate":
            if not (it["owner"] or "").strip():
                v.append(Violation("I-4", "remediate requires owner", fid))
            if not it["due_at"]:
                v.append(Violation("I-4", "remediate requires due_at", fid))
            if it["action"] is None:
                v.append(Violation("I-4", "remediate requires action", fid))
        elif it["action"] is not None:
            v.append(Violation("I-4", "action is set on a decision other than remediate", fid))
        a = it["action"]
        if "skillpact" in it:
            want = skillpact_summary(x)
            if want is None or not _same_summary(it["skillpact"], want):
                v.append(Violation("I-5", "items[].skillpact must match the finding's skillpact (signed / divergence / diff_anomaly / declared_effects)", fid))
        elif final and x.get("skillpact"):
            v.append(Violation("I-5", "an item of a finalized plan requires the summary of the finding's skillpact (skillpact)", fid))
        if a is not None:
            v += _action_shape_violations(a, fid, x, sugs.get(fid), final)
            if "evidence_hash" in a and a["evidence_hash"] != x["evidence_hash"]:
                v.append(Violation("I-4", "action.evidence_hash must equal the finding's evidence_hash", fid))
            if "evidence" in a and a["evidence"] != evidence_of(x):
                v.append(Violation("I-4", "action.evidence must match the finding's evidence (evidence_hash in 1.0)", fid))
            v11 = plan["schema_version"] == PLAN_SCHEMA_VERSION
            if final and v11 and ("evidence" not in a or "relation" not in a or "finding_path" not in a):
                v.append(Violation("I-4", "an action of a finalized plan requires evidence, relation and finding_path", fid))
            if final and not v11 and "evidence_hash" not in a:
                v.append(Violation("I-4", "an action of a finalized plan requires evidence_hash", fid))
            if not v11 and a["type"] != "chmod":
                v.append(Violation("I-4", f"plan 1.0 allows chmod only (use plan {PLAN_SCHEMA_VERSION})", fid))
            rev = REVERSIBLE_BY_TYPE.get(a["type"], False)
            if "reversible" in a and a["reversible"] != rev:
                v.append(Violation("I-4", f"action.reversible is {rev}, as determined by the operation type {a['type']}", fid))
            if "skillpact_effects" in a and sorted(a["skillpact_effects"]) != sorted(skillpact_effects(x)):
                v.append(Violation("I-4", "action.skillpact_effects must equal the finding's declared_effects", fid))
            if final and ("reversible" not in a or "skillpact_effects" not in a):
                v.append(Violation("I-4", "an action of a finalized plan requires reversible and skillpact_effects", fid))
        # I-9: deadlines
        if it["decided_at"]:
            try:
                v += _deadline_violations(it, d, lv, pol, created, now)
            except OverflowError:
                v.append(Violation("I-11", "the deadline calculation is outside the date-time range", fid))
    if final:
        if plan["status"] == "draft":
            v.append(Violation("I-12", "the status of the finalized plan is draft"))
        if plan.get("plan_hash") != plan_hash(plan):
            v.append(Violation("I-11", "plan_hash does not match the plan body"))
    return v


def _deadline_violations(it: dict, d: str, lv: str, pol: dict, created: dt.datetime, now: dt.datetime) -> list[Violation]:
    """I-9. OverflowError when date-time arithmetic is out of range (the caller turns it into I-11)."""
    v: list[Violation] = []
    fid = it["finding_id"]
    dec = parse_ts(it["decided_at"])
    # the decision date is where deadlines start. A future date or one before the plan was created must not extend them
    if dec < created:
        v.append(Violation("I-9", "decided_at is before the plan's created_at", fid))
    if dec > now:
        v.append(Violation("I-9", "decided_at is after the current time", fid))
    days = pol["deadlines"].get(lv)
    if days is None and lv == "INFO":  # an INFO put in a quarantine group (fixed together with another finding on the same target) has the LOW deadline
        days = pol["deadlines"].get("LOW")
    if it["due_at"]:
        due = parse_ts(it["due_at"])
        if days is None:
            v.append(Violation("I-9", f"policy.deadlines has no entry for {lv}, so due_at cannot be checked", fid))
        elif due > dec + dt.timedelta(days=days):
            v.append(Violation("I-9", f"due_at is later than the deadline (decision date + {days} days)", fid))
        if due < dec:
            v.append(Violation("I-9", "due_at is before the decision date", fid))
    if it["recheck_at"] and d in ("exception", "defer"):
        rc = parse_ts(it["recheck_at"])
        if rc > dec + dt.timedelta(days=pol["decision_window_days"]):
            v.append(Violation("I-9", f"recheck_at is later than the decision window ({pol['decision_window_days']} days)", fid))
        if rc < dec:
            v.append(Violation("I-9", "recheck_at is before the decision date", fid))
    return v


# --- Finalization (zet finalize) ---------------------------------------------
def finalize(inp: dict, plan: dict, now: dt.datetime | None = None, now_override: bool = False) -> dict:
    """now_override: a run with the time overridden by --now. The plan records now_override: true, and GER rejects it by default."""
    v = check(inp, plan, now=now)
    if v:
        raise ContractError(v)
    by_id = {x["id"]: x for x in inp["findings"]["findings"]}
    out_items = []
    for it in plan["items"]:
        it = {k: val for k, val in it.items() if k not in ("constraints", "skillpact")}
        x = by_id[it["finding_id"]]
        if it["action"] is not None:
            a = copy.deepcopy(it["action"])
            a["reversible"] = REVERSIBLE_BY_TYPE.get(a["type"], False)
            a["skillpact_effects"] = skillpact_effects(x)
            # GER confirms in G-7 that the target has not changed since detection, and derives the relation again from finding_path in G-9
            a.setdefault("relation", "none" if a["target"] is None else "self")
            a["finding_path"] = x["path"]
            a["evidence"] = evidence_of(x)
            a.pop("evidence_hash", None)
            it["action"] = a
        sp = skillpact_summary(x)
        if sp is not None:
            it["skillpact"] = sp
        out_items.append(it)
    final = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": plan["plan_id"],
        "created_at": plan["created_at"],
        "status": "partial" if inp["findings"]["status"] == "partial" else "ok",
        "items": out_items,
        "held": plan["held"],
    }
    sc = scope_of(inp)
    if sc is not None:
        final["scope"] = sc
    if now_override or plan.get("now_override"):  # the time was overridden in draft or in finalize
        final["now_override"] = True
    final["plan_hash"] = plan_hash(final)
    v = check(inp, final, final=True, now=now)
    if v:
        raise ContractError(v)
    return final

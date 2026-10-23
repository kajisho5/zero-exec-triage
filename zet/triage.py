"""判断ロジック: 入力検証・下書き生成・不変条件チェック・確定。I/O を持たない純粋関数。"""
from __future__ import annotations

import datetime as dt
import posixpath
import re
import uuid
from typing import Any

from .core import (DECISIONS, GER_ACTION_TYPES, REVERSIBLE_BY_TYPE, RISKY_EFFECTS, ContractError, Violation,
                   fmt_ts, parse_ts, plan_hash, schema_violations)

MAX_DAYS = 3650  # triage-input.schema.json の deadlines / decision_window_days の最大値
_CHMOD_MODE = re.compile(r"0[0-7]{3}")  # GER と同じ。特殊ビット（setuid / setgid / sticky）は不可
# 予約済みで未実装の skillpact_policy の項目。値を受け取って黙って無視すると、効いていない設定を
# 効いていると誤解させる（例: destructive_requires_human: true）ため、指定されたら拒否する
RESERVED_SKILLPACT_POLICY = ("diff_anomaly_threshold", "destructive_requires_human")


# --- 入力検証（zet validate） ----------------------------------------------
def validate_input(inp: Any) -> list[Violation]:
    v = schema_violations("triage-input.schema.json", inp, "triage-input")
    if v:
        return v
    f = inp["findings"]
    v = schema_violations("vendor/findings.schema.json", f, "findings")
    if v:
        return v
    if f["status"] == "error":
        v.append(Violation("I-12", 'findings.status == "error" の入力は受け付けません（失敗の伝播）'))
    if inp["skillpact_policy"]["l3_trusted"]:
        v.append(Violation("SP", "skillpact_policy.l3_trusted = true は契約違反です（L3 署名を信頼根拠にしない）"))
    for k in RESERVED_SKILLPACT_POLICY:
        if k in inp["skillpact_policy"]:
            v.append(Violation("SP", f"skillpact_policy.{k} は予約済みで未実装です（ZET は評価しません）。指定を外してください"))
    ids = [x["id"] for x in f["findings"]]
    if len(ids) != len(set(ids)):
        v.append(Violation("I-2", "findings に重複した id があります"))
    used = {x["level"] for x in f["findings"]} | {"CRITICAL"}
    for lv in used:
        if lv != "INFO" and lv not in inp["policy"]["deadlines"]:
            v.append(Violation("I-9", f"policy.deadlines に {lv} がありません"))
    return v


def require_valid_input(inp: Any) -> None:
    v = validate_input(inp)
    if v:
        raise ContractError(v)


# --- 入力から導く制約（plan の値は信用せず毎回ここで再計算する） ------------
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


def min_approvers(finding: dict, decision: str | None) -> int:
    sp = finding.get("skillpact")
    n = 0
    if decision == "exception":
        n = 1
    if sp and sp["diff_anomaly"]:
        n = max(n, 2)
    if decision == "remediate" and risky_effects(finding):
        n = max(n, 2)  # GER の G-6 と同じ: exec / network / spend / send を宣言したスキルへの操作は 2 名以上
    return n


def skillpact_effects(finding: dict) -> list[str]:
    sp = finding.get("skillpact")
    return list(sp["declared_effects"]) if sp else []


def risky_effects(finding: dict) -> list[str]:
    return [e for e in skillpact_effects(finding) if e in RISKY_EFFECTS]


def skillpact_summary(finding: dict) -> dict | None:
    """確定 plan の items[].skillpact。GER が I-5 / I-6 / I-7 と skillpact_effects の整合を plan だけで再検査するための材料。"""
    sp = finding.get("skillpact")
    if not sp:
        return None
    return {"signed": sp["signed"], "divergence": list(sp["divergence"]), "diff_anomaly": sp["diff_anomaly"],
            "declared_effects": list(sp["declared_effects"])}


def _same_summary(a: dict, b: dict) -> bool:
    return (a["signed"] == b["signed"] and a["diff_anomaly"] == b["diff_anomaly"]
            and sorted(a["divergence"]) == sorted(b["divergence"])
            and sorted(a["declared_effects"]) == sorted(b["declared_effects"]))


def _action_shape_violations(a: dict, fid: str, finding: dict) -> list[Violation]:
    """GER が必ず拒否する action と、finding と無関係な対象への action を確定させない（I-4）。"""
    v: list[Violation] = []
    t = a["target"]
    # normpath は先頭の // を残す（POSIX で処理系定義）ため、// はどこにあっても別に拒否する（GER は拒否する）
    if not t.startswith("/") or "//" in t or posixpath.normpath(t) != t or ".." in t.split("/"):
        v.append(Violation("I-4", "action.target は正規化された絶対パスにすること（. / .. / 連続した / を含まない）", fid))
    # 対象は finding が指すパスそのものに限る。配下のパスは許さない（ZET はファイルシステムを見ないため
    # path がディレクトリかを判断できず、"/" や "/home" を指す finding で任意のファイルを対象にできてしまう）
    if finding["path"] is None:
        v.append(Violation("I-4", "path が null の finding には action を設定できません（対象を特定できない）", fid))
    elif t != finding["path"]:
        v.append(Violation("I-4", "action.target は finding の path と一致させること（配下のパスや別のパスは不可）", fid))
    if a["type"] not in GER_ACTION_TYPES:
        v.append(Violation("I-4", f"action.type {a['type']} は GER が実行できる操作種別（{', '.join(sorted(GER_ACTION_TYPES))}）ではありません", fid))
    if a["type"] == "chmod":
        p = a["params"]
        if set(p) != {"mode"} or not isinstance(p["mode"], str) or not _CHMOD_MODE.fullmatch(p["mode"]):
            v.append(Violation("I-4", 'chmod の params は {"mode": "0NNN"}（8 進 3 桁、setuid / setgid / sticky なし）だけにすること', fid))
        elif int(p["mode"], 8) & 0o002:
            # 現在の mode は ZET からは見えない（GER が G-7 で「権限を足さない」ことを確かめる）。静的に分かる緩和は拒否する
            v.append(Violation("I-4", "chmod で他者の書き込み権限（world-writable）は付けられません（修復は権限を絞る操作に限る）", fid))
    return v


def _timestamp_violations(plan: dict) -> list[Violation]:
    """形式は正しくても存在しない日時（13 月、60 秒など）を I-11 として返す。"""
    v: list[Violation] = []
    pairs = [(None, plan["created_at"])]
    pairs += [(it["finding_id"], it[k]) for it in plan["items"] for k in ("decided_at", "due_at", "recheck_at")]
    for fid, ts in pairs:
        try:
            if ts is not None:
                parse_ts(ts)
        except ValueError:
            v.append(Violation("I-11", f"存在しない日時です: {ts}", fid))
    return v


# --- 下書き（zet draft） ---------------------------------------------------
def draft(inp: dict, now: dt.datetime, operator: str, plan_id: str | None = None, now_override: bool = False) -> dict:
    require_valid_input(inp)
    try:  # 期限の日数はスキーマ上 3650 日まで。加算できない現在時刻では下書きを作らない
        now + dt.timedelta(days=MAX_DAYS)
    except OverflowError:
        raise ContractError([Violation("I-11", "現在時刻が日時の範囲を超えています")]) from None
    f = inp["findings"]
    pol = inp["policy"]
    errmods = errored_modules(f)
    items: list[dict] = []
    held: list[dict] = []
    for mod in sorted(errmods):
        for reason in sorted(set(errmods[mod])):
            held.append({"finding_id": None, "module": mod, "reason": f"scan_error:{reason}"})
    for x in f["findings"]:
        if x["module"] in errmods:
            held.append({"finding_id": x["id"], "module": x["module"], "reason": "module_unconfirmed"})
            continue
        lv = level_effective(x)
        days = pol["deadlines"].get(lv)
        info_default = lv == "INFO"  # 引き上げ後の重大度で判断する（INFO → CRITICAL を自動 defer しない）
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
                # 選べる判断のうち最も厳しいもの（exception は 1 名、diff_anomaly・危険な効果の remediate は 2 名）
                "min_approvers": max(min_approvers(x, d) for d in allowed_decisions(x)),
            },
        })
    out = {
        "schema_version": "1.0",
        "plan_id": plan_id or str(uuid.uuid4()),
        "created_at": fmt_ts(now),
        "status": "draft",
        "items": items,
        "held": held,
    }
    if now_override:  # created_at が --now 由来であることを finalize と GER に伝える
        out["now_override"] = True
    return out


# --- 不変条件チェック（zet check） -----------------------------------------
def check(inp: dict, plan: Any, final: bool = False, now: dt.datetime | None = None) -> list[Violation]:
    """I-1〜I-12。未記入の decision も違反として返す。final=True は確定 plan（finalize の出力 / GER 入力）として検査する。

    plan_hash を持つ plan は確定 plan なので、final の指定にかかわらず確定 plan として検査する
    （改ざんされた確定 plan が check を通り、finalize で黙って再ハッシュされるのを防ぐ）。
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
    approvers = {a.casefold() for a in pol["approvers"]}  # 人名は ASCII。大文字小文字の違いで別人扱いしない
    now = now or dt.datetime.now(dt.timezone.utc)
    v = _timestamp_violations(plan)
    if v:
        return v
    created = parse_ts(plan["created_at"])

    # I-1 / I-2 / I-10: 全 finding がちょうど 1 回、items か held に現れる
    seen: dict[str, str] = {}
    for where, lst in (("items", plan["items"]), ("held", plan["held"])):
        for e in lst:
            fid = e["finding_id"]
            if fid is None:
                continue
            if fid not in by_id:
                v.append(Violation("I-2", f"{where} に入力に存在しない finding_id", fid))
                continue
            if fid in seen:
                v.append(Violation("I-1", f"finding が {seen[fid]} と {where} に重複しています", fid))
            seen[fid] = where
    for fid in by_id:
        if fid not in seen:
            v.append(Violation("I-1", "判断も保留もされていない finding", fid))
    for fid, where in seen.items():
        if by_id[fid]["module"] in errmods and where != "held":
            v.append(Violation("I-10", f"未確定モジュール {by_id[fid]['module']} の finding は held にすること", fid))
    # held は errors[] のモジュール（未確定）専用。確定したモジュールの finding を held で判断から外せない
    for h in plan["held"]:
        fid, mod = h["finding_id"], h.get("module")
        if fid is None:
            if mod not in errmods:
                v.append(Violation("I-10", f"モジュール {mod} は errors[] に無いためモジュール単位で held にできません"))
            continue
        x = by_id.get(fid)
        if x is None:
            continue
        if mod is not None and mod != x["module"]:
            v.append(Violation("I-10", f"held の module {mod} が finding のモジュール {x['module']} と一致しません", fid))
        if x["module"] not in errmods:
            v.append(Violation("I-1", f"モジュール {x['module']} は確定しているため held にできません（items で判断すること）", fid))
    held_mods = {h.get("module") for h in plan["held"] if h["finding_id"] is None}
    for mod in errmods:
        if mod not in held_mods:
            v.append(Violation("I-12", f"errors[] のモジュール {mod} をモジュール単位で held にすること"))

    # I-12: 失敗の伝播
    if f["status"] == "partial":
        if plan["status"] not in ("partial", "draft"):
            v.append(Violation("I-12", "入力が partial のため plan.status は partial にすること"))
        if not plan["held"]:
            v.append(Violation("I-12", "入力が partial なのに held が空です"))
    elif plan["status"] == "partial":
        v.append(Violation("I-12", "入力が ok なのに plan.status が partial です"))
    if plan["status"] == "error":
        v.append(Violation("I-12", "status: error の plan は作成しません"))

    # I-4: 同じ対象への操作が 2 件あると GER は計画全体を拒否する（実行順で結果が変わる）
    targets: dict[str, str] = {}
    for it in plan["items"]:
        a = it["action"]
        if it["decision"] == "remediate" and isinstance(a, dict):
            if a["target"] in targets:
                v.append(Violation("I-4", f"action.target が {targets[a['target']]} と重複しています", it["finding_id"]))
            else:
                targets[a["target"]] = it["finding_id"]

    for it in plan["items"]:
        fid = it["finding_id"]
        x = by_id.get(fid)
        if x is None:
            continue
        d = it["decision"]
        lv = level_effective(x)
        if it["level_effective"] != lv:
            code = "I-7" if lv == "CRITICAL" and x.get("skillpact") else "I-3"
            v.append(Violation(code, f"level_effective は {lv} であること（入力から導出。引き下げ・改変は不可）", fid))
        if d is None:
            v.append(Violation("I-1", "decision が未記入です", fid))
            continue
        if d not in allowed_decisions(x):
            v.append(Violation("I-5", "skillpact.divergence が非空の finding は exception にできません", fid))
        if not it["decided_by"] or not it["decided_at"]:
            v.append(Violation("I-3", "decided_by と decided_at は必須です", fid))
        appr = sorted({a.casefold() for a in it["approved_by"]})
        if len(appr) != len(it["approved_by"]):
            v.append(Violation("I-6", "approved_by に重複があります", fid))
        unknown = [a for a in appr if a not in approvers]
        if unknown:
            v.append(Violation("I-8", f"policy.approvers に無い承認者: {', '.join(unknown)}", fid))
        need = min_approvers(x, d)
        if len(appr) < need:
            code = "I-6" if x.get("skillpact") and (x["skillpact"]["diff_anomaly"] or need == 2) else "I-3"
            v.append(Violation(code, f"承認者が {need} 名以上必要です（現在 {len(appr)} 名）", fid))
        if it["decided_by"] and it["decided_by"].casefold() in appr:
            v.append(Violation("I-3", "判断者本人が承認者に含まれています（自己承認）", fid))
        if d == "exception":
            if it["exception_type"] is None:
                v.append(Violation("I-3", "exception には exception_type が必要です", fid))
            if not (it["reason"] or "").strip():
                v.append(Violation("I-3", "exception には reason が必要です", fid))
            if not it["recheck_at"]:
                v.append(Violation("I-3", "exception には recheck_at が必要です", fid))
        elif it["exception_type"] is not None:
            v.append(Violation("I-3", "exception 以外で exception_type が設定されています", fid))
        if d == "defer" and lv != "INFO":
            # 期限も理由も無い defer は承認の要らない無期限の例外になる。INFO 以外は reason と recheck_at を必須にする
            if not (it["reason"] or "").strip():
                v.append(Violation("I-3", "defer（level_effective が INFO 以外）には reason が必要です", fid))
            if not it["recheck_at"]:
                v.append(Violation("I-9", "defer（level_effective が INFO 以外）には recheck_at が必要です", fid))
        if d == "remediate":
            if not (it["owner"] or "").strip():
                v.append(Violation("I-4", "remediate には owner が必要です", fid))
            if not it["due_at"]:
                v.append(Violation("I-4", "remediate には due_at が必要です", fid))
            if it["action"] is None:
                v.append(Violation("I-4", "remediate には action が必要です", fid))
        elif it["action"] is not None:
            v.append(Violation("I-4", "remediate 以外で action が設定されています", fid))
        a = it["action"]
        if "skillpact" in it:
            want = skillpact_summary(x)
            if want is None or not _same_summary(it["skillpact"], want):
                v.append(Violation("I-5", "items[].skillpact は finding の skillpact（signed / divergence / diff_anomaly / declared_effects）と一致させること", fid))
        elif final and x.get("skillpact"):
            v.append(Violation("I-5", "確定 plan の item には finding の skillpact の要約（skillpact）が必要です", fid))
        if a is not None:
            v += _action_shape_violations(a, fid, x)
            if "evidence_hash" in a and a["evidence_hash"] != x["evidence_hash"]:
                v.append(Violation("I-4", "action.evidence_hash は finding の evidence_hash と一致させること", fid))
            if final and "evidence_hash" not in a:
                v.append(Violation("I-4", "確定 plan の action には evidence_hash が必要です", fid))
            rev = REVERSIBLE_BY_TYPE.get(a["type"], False)
            if "reversible" in a and a["reversible"] != rev:
                v.append(Violation("I-4", f"action.reversible は操作種別 {a['type']} から {rev} と決まります", fid))
            if "skillpact_effects" in a and sorted(a["skillpact_effects"]) != sorted(skillpact_effects(x)):
                v.append(Violation("I-4", "action.skillpact_effects は finding の declared_effects と一致させること", fid))
            if final and ("reversible" not in a or "skillpact_effects" not in a):
                v.append(Violation("I-4", "確定 plan の action には reversible と skillpact_effects が必要です", fid))
        # I-9: 期限
        if it["decided_at"]:
            try:
                v += _deadline_violations(it, d, lv, pol, created, now)
            except OverflowError:
                v.append(Violation("I-11", "期限の計算が日時の範囲を超えています", fid))
    if final:
        if plan["status"] == "draft":
            v.append(Violation("I-12", "確定 plan の status が draft です"))
        if plan.get("plan_hash") != plan_hash(plan):
            v.append(Violation("I-11", "plan_hash が plan 本体と一致しません"))
    return v


def _deadline_violations(it: dict, d: str, lv: str, pol: dict, created: dt.datetime, now: dt.datetime) -> list[Violation]:
    """I-9。日時の加算が範囲外なら OverflowError（呼び出し側で I-11 にする）。"""
    v: list[Violation] = []
    fid = it["finding_id"]
    dec = parse_ts(it["decided_at"])
    # 判断日は期限の起点。未来や plan 作成前の日付で期限を引き延ばせないようにする
    if dec < created:
        v.append(Violation("I-9", "decided_at が plan の created_at より前です", fid))
    if dec > now:
        v.append(Violation("I-9", "decided_at が現在時刻より後です", fid))
    days = pol["deadlines"].get(lv)
    if it["due_at"]:
        due = parse_ts(it["due_at"])
        if days is None:
            v.append(Violation("I-9", f"policy.deadlines に {lv} が無いため due_at を検証できません", fid))
        elif due > dec + dt.timedelta(days=days):
            v.append(Violation("I-9", f"due_at が期限（判断日 + {days} 日）を超えています", fid))
        if due < dec:
            v.append(Violation("I-9", "due_at が判断日より前です", fid))
    if it["recheck_at"] and d in ("exception", "defer"):
        rc = parse_ts(it["recheck_at"])
        if rc > dec + dt.timedelta(days=pol["decision_window_days"]):
            v.append(Violation("I-9", f"recheck_at が判断ウィンドウ（{pol['decision_window_days']} 日）を超えています", fid))
        if rc < dec:
            v.append(Violation("I-9", "recheck_at が判断日より前です", fid))
    return v


# --- 確定（zet finalize） --------------------------------------------------
def finalize(inp: dict, plan: dict, now: dt.datetime | None = None, now_override: bool = False) -> dict:
    """now_override: --now で時刻を上書きした実行。plan に now_override: true を記録し、GER は既定で拒否する。"""
    v = check(inp, plan, now=now)
    if v:
        raise ContractError(v)
    by_id = {x["id"]: x for x in inp["findings"]["findings"]}
    out_items = []
    for it in plan["items"]:
        it = {k: val for k, val in it.items() if k not in ("constraints", "skillpact")}
        x = by_id[it["finding_id"]]
        if it["action"] is not None:
            a = dict(it["action"])
            a["reversible"] = REVERSIBLE_BY_TYPE.get(a["type"], False)
            a["skillpact_effects"] = skillpact_effects(x)
            a["evidence_hash"] = x["evidence_hash"]  # GER が G-7 で検知時から対象が変わっていないことを確かめる
            it["action"] = a
        sp = skillpact_summary(x)
        if sp is not None:
            it["skillpact"] = sp
        out_items.append(it)
    final = {
        "schema_version": "1.0",
        "plan_id": plan["plan_id"],
        "created_at": plan["created_at"],
        "status": "partial" if inp["findings"]["status"] == "partial" else "ok",
        "items": out_items,
        "held": plan["held"],
    }
    if now_override or plan.get("now_override"):  # draft か finalize のどちらかで時刻を上書きした
        final["now_override"] = True
    final["plan_hash"] = plan_hash(final)
    v = check(inp, final, final=True, now=now)
    if v:
        raise ContractError(v)
    return final

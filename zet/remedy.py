"""finding → 修復の対応表（GER 修復能力拡張 設計書 §2 / §6.1 Phase 1）。

ZET はファイルシステムを見ない。ここで作るのは提案（draft の constraints.suggested_actions）と、
確定前の検査（I-4 の関係・I-13 の必須の後続作業）に使う字句上の規則だけ。GER は計画を信用せず、
同じ関係・危険パターンを現在のファイルシステムに対して自分で評価し直す。

findings 1.0 では module・path・level・campaign から判断する（detail の文章は解析しない）。
findings 1.1 の kind / subject / related があれば、それを優先する。
"""
from __future__ import annotations

import hashlib
import posixpath
import re

# --- チェックリストの雛形（閉じた表）。{path} は finding の path に置き換える -------------------------
_T = {
    "CL-PKG": [
        ("この作業ツリーで npm ci / npm install / pip install -r / bundle install を実行しない（ロックファイルが侵害版・脆弱版を再び取得する）。対象: {path}", True),
        ("~/.npmrc に ignore-scripts=true、環境変数に PIP_REQUIRE_VIRTUALENV=true と PYTHONNOUSERSITE=1 を設定する", True),
        ("依存の指定を安全版・修正版に変え、秘密情報の無い隔離環境でロックファイルを再生成する（npm install --ignore-scripts / poetry lock / uv lock / bundle lock --update / cargo update -p など）", True),
        ("npm ls <name> / pip show / bundle info / cargo tree で侵害版・脆弱版が残っていないことを確かめる", True),
        ("侵害版がインストール・実行された可能性があれば CL-SECRET を実施する", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-VENV": [
        ("侵害版・脆弱版を含む仮想環境（site-packages）を使うプロセスを止め、仮想環境ごと作り直す（RECORD が無いため GER は安全に隔離できない）。対象: {path}", True),
        ("新しい仮想環境では安全版を指定してインストールする（pip install --require-hashes など）", True),
        ("CL-SECRET を実施する（インストール時・import 時にコードが実行されている可能性がある）", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-SECRET": [
        ("この端末・作業ツリーから読めた認証情報（§14 の一覧と finding の path）を、提供元ですべて失効させる（GitHub PAT: Settings → Developer settings → Revoke、npm: npm token revoke、AWS: IAM でアクセスキーを無効化・削除、SSH 鍵: authorized_keys と GitHub の SSH keys から削除）", True),  # noqa: E501
        ("新しい認証情報を、侵害されていない端末で発行する", True),
        ("提供元の監査ログで、失効までの不正使用がなかったかを確かめる", True),
        ("git 履歴に入っていれば、履歴の書き換えか失効だけで済ませるかを決めて記録する（GER は履歴を書き換えない）", False),
    ],
    "CL-IR": [
        ("隔離・修復した時刻を記録し、この端末をネットワークから切り離すかどうかを判断する。対象: {path}", True),
        ("CL-SECRET を実施する", True),
        ("同じ campaign の他の痕跡を zes-scan.sh --full で確かめる", True),
        ("再構築するかどうかを判断する（ルートキットや永続化の痕跡があれば再構築を勧める）。GER の修復はインシデントの終わりを意味しない", True),
    ],
    "CL-LAUNCHD": [
        ("launchctl bootout gui/$(id -u)/<Label> を実行する（LaunchDaemon なら sudo launchctl bootout system/<Label>）。GER は plist を隔離して次回の読み込みを止めただけで、今読み込まれているエージェントは動き続ける", True),  # noqa: E501
        ("launchctl print gui/$(id -u)/<Label> が「見つからない」になることを確かめる", True),
        ("ps -axo pid,command で ProgramArguments のプロセスが残っていないことを確かめ、残っていれば止める。プログラム本体も確かめる", True),
        ("ログイン項目と構成プロファイルも確かめる", False),
    ],
    "CL-SYSTEMD": [
        ("systemctl --user stop <unit> と systemctl --user daemon-reload を実行する（GER はユニットファイルを隔離しただけ）", True),
        ("*.wants/ のリンクとユニットが起動していたプログラムを確かめる", True),
    ],
    "CL-CRON": [
        ("crontab -l > ~/crontab.bak.$(date +%s) で退避する", True),
        ("crontab -e で、通信や一時領域を実行する行（ZES の detail を参照）を消す（GER は crontab の spool を直接書き換えない）", True),
        ("crontab -l で消えたことを確かめる", True),
    ],
    "CL-EXT": [
        ("ブラウザを終了してから修復したことを確かめる（起動中に隔離すると、ブラウザが「破損」と判断してストアから修復する場合がある）", True),
        ("同期で再インストールされないよう、chrome://extensions とアカウントの同期設定から拡張機能を削除する", True),
        ("拡張機能が読めた cookie のセッション（主要なサイト）を失効させる", True),
    ],
    "CL-MCP": [
        ("エージェント・IDE を再起動し、取り除いた MCP サーバーが読み込まれていないことを確かめる", True),
        ("取り除いたサーバーが既に実行されていた可能性があれば CL-IR を実施する", True),
    ],
    "CL-MCP-PIN": [
        ("npx / uvx で実行時に最新版を取得する MCP サーバーの版を、承認者が決めて固定する（pkg@1.2.3）。版を足すことは「追加」なので GER は自動化しない。対象: {path}", True),
        ("使わないサーバーなら disable_mcp_server で取り除く", False),
    ],
    "CL-SHELL": [
        ("開いているシェルには効かない。シェルを開き直す（または unset LD_PRELOAD など、取り除いた設定を今のシェルからも外す）", True),
        ("同じ行が他の rc ファイル（.zshrc / .profile / .bash_profile）に無いか確かめる", True),
    ],
    "CL-LDSO": [
        ("再起動する（ld.so.preload の行を取り除いても、既に動いているプロセスにはライブラリが読み込まれたまま）", True),
        ("指していたライブラリを確かめて隔離する（Phase 2 で GER の preload_lib が対応予定）", True),
        ("ルートキットがいる状態ではファイルシステムの見え方そのものが信用できない。再構築を検討する", True),
    ],
    "CL-PHP": [
        ("PHP を修正版に上げる（Dockerfile のベースイメージ・.tool-versions・apt / apk のパッケージ）。イメージを作り直してデプロイする", True),
        ("php-fpm / Apache を再起動する（パッケージが修正済みでも、稼働中のワーカーが更新前のままの場合がある）", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-PHP-RESTART": [
        ("PHP（php-fpm / Apache）を再起動する。auto_prepend_file が正規の用途（APM など）だったかを確かめる", True),
    ],
    "CL-UPGRADE": [
        ("ベンダーの勧告に従って、サーバー・ランタイム・パッケージを修正版に上げる（compose のタグを上げるだけでは移行が済まない場合がある）。対象: {path}", True),
        ("更新後に再起動し、版を確かめる", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-PWN": [
        ("そのワークフローを無効にする（GitHub の Actions → 対象のワークフロー → Disable workflow、またはワークフローファイルを削除するコミットをデフォルトブランチに入れる）。対象: {path}", True),
        ("actions/checkout から ref: ${{ github.event.pull_request.head.* }} を取り除くか、トリガーを pull_request に変える", True),
        ("そのワークフローから参照できた secrets を、すべて CL-SECRET でローテーションする", True),
        ("Actions の実行履歴で、外部の PR による実行がなかったかを確かめる", True),
    ],
    "CL-PIN": [
        ("対象のアクション・イメージのリポジトリで、タグが指すコミット SHA / ダイジェストを信頼できる端末で確かめる（git ls-remote / docker buildx imagetools inspect）。対象: {path}", True),
        ("その SHA がフォークではなく本体のリポジトリの履歴にあり、侵害の時期より前のものであることを確かめる", True),
        ("SHA / ダイジェストで固定する（Phase 2 で GER の pin_action / pin_digest が承認者 2 名で対応予定）。侵害が報告されたアクションは固定せず、代わりのものを選ぶ", True),
    ],
    "CL-SKILL": [
        ("スキルの作者に報告し、契約（skill.contract.json）を直してもらう。対象: {path}", True),
        ("直るまでそのスキルを使わない（必要なら quarantine skill_dir で隔離する）", True),
    ],
    "CL-ENV": [
        ("PYTHONNOUSERSITE=1 / PIP_REQUIRE_VIRTUALENV=true / npm の ignore-scripts=true を、利用者のシェルの rc に設定する（どの rc に書くかは環境による）", True),
    ],
    "CL-REVIEW": [
        ("ZES の detail に従って手で直す（コードの意味を変える修正・正しい値が人にしか分からない修正は GER が自動化しない）。対象: {path}", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
}
TEMPLATES = frozenset(_T)


def checklist(template: str, path: str | None) -> dict:
    steps = [{"id": f"s{i}", "text": t.replace("{path}", path or "（path なし）"), "blocking": b}
             for i, (t, b) in enumerate(_T[template], 1)]
    return {"template": template, "steps": steps}


def template_ok(cl: dict, path: str | None) -> bool:
    """雛形の手順がすべて（同じ id・同じ文言で）含まれていること。手順を足すのは構わない。"""
    if cl.get("template") not in _T:
        return False
    want = checklist(cl["template"], path)["steps"]
    have = {(s.get("id"), s.get("text"), s.get("blocking")) for s in cl.get("steps", [])}
    return all((s["id"], s["text"], s["blocking"]) in have for s in want)


# --- 字句上の規則（GER の ger/hazards.py・ger/actions/quarantine.py と同じ） -------------------------
ROOT_PREFIXES = ("/etc/", "/usr/", "/var/", "/opt/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/",
                 "/boot/", "/System/", "/Library/", "/private/etc/", "/private/var/")
USER_TMP_PREFIXES = ("/var/folders/", "/private/var/folders/", "/var/tmp/")


def root_required(path: str | None) -> bool:
    return bool(path) and path.startswith(ROOT_PREFIXES) and not path.startswith(USER_TMP_PREFIXES)


LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}
PKG_MANIFESTS = LOCKFILES | {"Gemfile.lock", "Cargo.lock", "composer.lock", "go.sum", "poetry.lock", "Pipfile.lock",
                             "uv.lock", "pyproject.toml", "Pipfile", "Gemfile", "Cargo.toml", "go.mod", "composer.json"}
MCP_JSON = {".mcp.json", "mcp.json", "mcp_config.json", ".claude.json", "claude_desktop_config.json"}
SHELL_RC = {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
            ".kshrc", ".mkshrc", ".envrc"}
RELATIONS = ("self", "npm_pkg_dir", "npm_installed", "pypi_record", "ext_dir", "skill_dir", "plist_program",
             "preload_lib", "unit_wants", "none")
PHASE1_RELATIONS = ("self", "npm_pkg_dir", "npm_installed", "pypi_record", "ext_dir", "skill_dir", "none")
_NPM_REST = re.compile(r"^(?:(?:@[^/@][^/]*/)?[^/@.][^/]*/node_modules/)*(?:@[^/@][^/]*/)?[^/@.][^/]*$")
_EXT = re.compile(r"^(.*/Extensions/[^/]+)(/[^/]+)?/manifest\.json$")
MALWARE_MODULES = {"§2", "§15", "§18", "§20", "§24", "§30", "§31", "§40", "§42"}


def lexical_relation(relation: str, target: str | None, fp: str | None, related: list | None = None) -> str | None:
    """I-4: target と finding の path の関係（字句上の条件）。問題があれば理由。"""
    if relation not in RELATIONS:
        return f"relation {relation} は未知です"
    if relation == "none":
        return None if target is None else "relation none は target が null のときだけです"
    if target is None:
        return "target が null の action の relation は none にすること"
    if relation not in PHASE1_RELATIONS:
        # Phase 2 の関係は ZES 1.1 の related にあるときだけ（GER Phase 1 は未対応で拒否する）
        ok = any(r.get("relation") == relation and r.get("path") == target for r in related or [])
        return None if ok else f"relation {relation} は finding の related にある対象だけです"
    if fp is None:
        return "path が null の finding には checklist（target null）以外の action を設定できません"
    if relation == "self":
        return None if target == fp else "relation self では action.target を finding の path と一致させること"
    if related and any(r.get("relation") == relation and r.get("path") == target for r in related):
        return None
    if relation == "npm_pkg_dir":
        par = posixpath.dirname(target)
        ok = fp == target + "/package.json" and (posixpath.basename(par) == "node_modules" or (
            posixpath.basename(par).startswith("@") and posixpath.basename(posixpath.dirname(par)) == "node_modules"))
        return None if ok else "npm_pkg_dir: target は node_modules/<name> で、finding の path がその package.json であること"
    if relation == "npm_installed":
        base = posixpath.dirname(fp) + "/node_modules/"
        ok = posixpath.basename(fp) in LOCKFILES and target.startswith(base) and _NPM_REST.fullmatch(target[len(base):])
        return None if ok else "npm_installed: finding がロックファイルで、target がその隣の node_modules/<name> であること"
    if relation == "pypi_record":
        ok = target == fp and posixpath.basename(target).endswith(".dist-info")
        return None if ok else "pypi_record: target は finding の path の *.dist-info であること"
    if relation == "ext_dir":
        m = _EXT.match(fp)
        return None if m and m.group(1) == target else "ext_dir: finding の path が …/Extensions/<id>[/<ver>]/manifest.json で、target が …/Extensions/<id> であること"
    if relation == "skill_dir":
        ok = target == fp or (posixpath.basename(fp) == "skill.contract.json" and posixpath.dirname(fp) == target)
        return None if ok else "skill_dir: target は finding の path のスキルのディレクトリであること"
    return "未知の relation"


# --- I-13: findings 1.1 の kind ごとに許す操作 ----------------------------------------------------
KIND_ACTIONS = {
    "pkg.compromised": {"quarantine", "checklist"},
    "pkg.vulnerable": {"checklist"},
    "pkg.lockfile_compromised": {"quarantine", "checklist"},
    "mcp.dangerous_command": {"disable_mcp_server", "edit_json", "edit_toml", "checklist"},
    "mcp.unpinned": {"disable_mcp_server", "checklist"},
    "gha.unpinned": {"checklist"},
    "gha.pwn_request": {"checklist"},
    "secret.token": {"checklist"},
    "runtime.cve": {"checklist"},
}


# --- 提案 ---------------------------------------------------------------------------------------
def _b(p):
    return posixpath.basename(p) if p else ""


def _act(type_, target, relation, fp, params=None, followup=()):
    a = {"type": type_, "target": target, "relation": relation, "finding_path": fp, "params": params or {}}
    if followup:
        a["followup"] = [checklist(t, fp) for t in followup]
    return a


def _cl(template, f):
    p = f["path"]
    return _act("checklist", p, "self" if p else "none", p, checklist(template, p))


def _q(f, relation="self", target=None, fu=()):
    return _act("quarantine", target or f["path"], relation, f["path"], {}, fu)


def _ir(f):
    return ("CL-IR",) if f.get("campaign") or f["module"] in MALWARE_MODULES else ()


def classify(f: dict) -> tuple[list[dict], str | None]:
    """(提案の一覧 [{label, action, note?}], 注記)。最初の auto を既定の候補にする。"""
    p, m, lv, camp = f["path"], f["module"], f["level"], f.get("campaign")
    b = _b(p)
    kind = f.get("kind") or ""
    autos: list = []
    cl: str | None = "CL-REVIEW"
    note = None
    if lv == "INFO":
        return [], None
    if p is None:
        cl = {"§10": "CL-CRON", "§31": "CL-CRON", "§12": "CL-ENV", "§47": "CL-SECRET", "§45": "CL-SECRET"}.get(m, "CL-REVIEW")
    elif m == "§49":
        if camp in ("skillpact-divergence", "skillpact-account-compromise"):
            tgt = posixpath.dirname(p) if b == "skill.contract.json" else p
            autos.append(_q(f, "skill_dir", tgt, ("CL-SKILL", "CL-IR")))
        cl = "CL-SKILL"
    elif m == "§2":
        if b == "package.json":
            autos.append(_act("edit_json", p, "self", p, {"select": "npm.lifecycle"}, _ir(f)))
        else:
            autos.append(_q(f, fu=("CL-IR", "CL-SECRET")))
        cl = "CL-IR"
    elif m == "§15":
        parts = p.split("/")
        if b == "package.json" and "node_modules" in parts[:-1]:
            autos.append(_q(f, "npm_pkg_dir", posixpath.dirname(p), ("CL-PKG", "CL-IR", "CL-SECRET")))
            cl = "CL-PKG"
        elif b.endswith(".dist-info"):
            if lv == "CRITICAL" or kind == "pkg.compromised":
                autos.append(_q(f, "pypi_record", p, ("CL-PKG", "CL-SECRET")))
                note = "RECORD が無ければ GER は隔離を拒否する（Q-6）。そのときは checklist CL-VENV"
            cl = "CL-VENV" if lv == "CRITICAL" else "CL-PKG"
        elif b.endswith(".egg-info"):
            cl = "CL-VENV"
        elif b in PKG_MANIFESTS or re.fullmatch(r"requirements[\w.-]*\.txt", b):
            for r in f.get("related") or []:
                if r.get("relation") == "npm_installed":
                    autos.append(_act("quarantine", r["path"], "npm_installed", p, {}, ("CL-PKG", "CL-SECRET")))
                    note = "node_modules を隔離してもロックファイルの finding は再生成まで残る"
            cl = "CL-PKG"
        elif b == "package.json":
            autos.append(_act("edit_json", p, "self", p, {"select": "npm.lifecycle"}, _ir(f)))
            cl = "CL-IR"
        else:
            autos.append(_q(f, fu=("CL-IR", "CL-SECRET")))
            cl = "CL-IR"
    elif m == "§17":
        if b in MCP_JSON or p.endswith("/.codex/config.toml"):
            if lv in ("HIGH", "CRITICAL"):
                autos.append(_act("disable_mcp_server", p, "self", p, {"select": "mcp.server"}, ("CL-MCP",) + _ir(f)))
                cl = "CL-MCP"
            else:
                cl = "CL-MCP-PIN"
        elif b in ("settings.json", "settings.local.json") and _b(posixpath.dirname(p)) == ".claude":
            autos.append(_act("edit_json", p, "self", p, {"select": "claude.hook"}, _ir(f)))
        else:
            autos.append(_q(f, fu=_ir(f) or ("CL-IR",)))
            cl = "CL-IR"
    elif m in ("§18", "§20"):
        if b.endswith("_history"):
            cl = "CL-IR"
        else:
            autos.append(_q(f, fu=("CL-IR",)))
            cl = "CL-IR"
    elif m in ("§24", "§42"):
        mm = _EXT.match(p)
        if mm:
            autos.append(_q(f, "ext_dir", mm.group(1), ("CL-EXT", "CL-IR")))
        cl = "CL-EXT"
    elif m in ("§10", "§30", "§31", "§33", "§35", "§40"):
        if b == "ld.so.preload":
            autos.append(_act("remove_line", p, "self", p, {}, ("CL-LDSO", "CL-IR")))
        elif b in SHELL_RC:
            autos.append(_act("remove_line", p, "self", p, {}, ("CL-SHELL",) + _ir(f)))
        elif b.endswith(".plist") and ("/LaunchAgents/" in p or "/LaunchDaemons/" in p):
            autos.append(_q(f, fu=("CL-LAUNCHD", "CL-IR")))
        elif "/systemd/" in p and b.endswith((".service", ".timer", ".socket", ".path")):
            autos.append(_q(f, fu=("CL-SYSTEMD", "CL-IR")))
        elif p.startswith("/etc/cron.d/"):
            autos.append(_act("remove_line", p, "self", p, {}, ("CL-IR",)))
        elif m in ("§30", "§40") or (m == "§35" and b.endswith("_history")):
            autos.append(_q(f, fu=("CL-IR", "CL-SECRET") if m == "§30" else ("CL-IR",)))
        cl = "CL-IR"
    elif m == "§7":
        if b in ("settings.json", "settings.local.json") and _b(posixpath.dirname(p)) == ".claude":
            autos.append(_act("edit_json", p, "self", p, {"select": "claude.hook"}, _ir(f)))
        elif b == "tasks.json" and _b(posixpath.dirname(p)) == ".vscode":
            autos.append(_act("edit_json", p, "self", p, {"select": "vscode.task_run_on"}))
        elif "/.git/hooks/" in p:
            autos.append(_q(f, fu=("CL-IR",)))
    elif m == "§26":
        if p.endswith("/.git/config") or b == ".gitconfig" or b == ".envrc":
            autos.append(_act("remove_line", p, "self", p, {}, ("CL-SHELL",) if b == ".envrc" else ()))
    elif m == "§4":
        if b == "php.ini" and lv == "HIGH":
            autos.append(_act("remove_line", p, "self", p, {}, ("CL-PHP-RESTART",)))
            cl = "CL-PHP-RESTART"
        else:
            cl = "CL-PHP"
    elif m in ("§8", "§45", "§47"):
        cl = "CL-SECRET"
    elif m == "§12":
        cl = "CL-ENV"
    elif m in ("§21", "§38"):
        cl = "CL-PWN"
    elif m in ("§22", "§28"):
        cl = "CL-PIN"
    elif m in ("§3", "§5", "§6", "§16", "§37", "§41"):
        cl = "CL-UPGRADE"
    out = [{"label": "auto", "action": a} for a in autos]
    if cl:
        out.append({"label": "checklist", "action": _cl(cl, f)})
    if note:
        for s in out:
            s["note"] = note
    return out, note


def candidate_targets(f: dict) -> list[tuple[str, str]]:
    """この finding が関係でつながりうる (relation, target)。他の finding の自動修復に含まれるかの判定に使う。"""
    p = f["path"]
    if not p:
        return []
    out = [("self", p)]
    if _b(p) == "skill.contract.json":
        out.append(("skill_dir", posixpath.dirname(p)))
    mm = _EXT.match(p)
    if mm:
        out.append(("ext_dir", mm.group(1)))
    if _b(p) == "package.json" and "node_modules" in p.split("/")[:-1]:
        out.append(("npm_pkg_dir", posixpath.dirname(p)))
    return out


def group_id(type_: str, target: str) -> str:
    return "g-" + hashlib.sha256(f"{type_}|{target}".encode("utf-8", "surrogateescape")).hexdigest()[:16]


def suggest_all(findings: list[dict]) -> dict[str, list[dict]]:
    """finding_id → 提案。同じ対象への自動修復は group にまとめ、他の自動修復の対象に含まれる finding にも同じ操作を提案する。"""
    sug = {x["id"]: classify(x)[0] for x in findings}
    autos: dict[tuple[str, str], list[str]] = {}
    for x in findings:
        for s in sug[x["id"]]:
            if s["label"] == "auto":
                autos.setdefault((s["action"]["type"], s["action"]["target"]), []).append(x["id"])
    # 他の finding の自動修復の対象に含まれる finding（同じファイル・同じスキル・同じ拡張機能）
    by_target = {}
    for (t, tgt), fids in autos.items():
        if t == "quarantine":  # 隔離はファイル・ツリーごと移すので、同じ対象の他の finding もまとめて消える（編集は消えない）
            by_target.setdefault(tgt, []).append((t, fids))
    for x in findings:
        if any(s["label"] == "auto" for s in sug[x["id"]]):
            continue
        for rel, tgt in candidate_targets(x):
            for t, fids in by_target.get(tgt, []):
                src = next(s for s in sug[fids[0]] if s["label"] == "auto" and s["action"]["target"] == tgt)
                a = dict(src["action"], relation=rel, finding_path=x["path"])
                a = {k: v for k, v in a.items() if k != "followup"}
                if src["action"].get("followup"):
                    a["followup"] = [checklist(c["template"], x["path"]) for c in src["action"]["followup"]]
                sug[x["id"]].insert(0, {"label": "auto", "action": a,
                                        "note": "同じ対象を他の finding の自動修復が扱うため、同じ group にまとめる"})
                fids.append(x["id"])
                break
            else:
                continue
            break
    for (t, tgt), fids in autos.items():
        if len(fids) > 1:
            g = group_id(t, tgt)
            for fid in fids:
                for s in sug[fid]:
                    if s["label"] == "auto" and s["action"]["target"] == tgt and s["action"]["type"] == t:
                        s["action"]["group"] = g
    return sug


def required_followups(f: dict, action: dict, suggestions: list[dict]) -> set[str]:
    """I-13: 自動修復の action に必ず付ける後続作業の template。提案と同じ操作なら提案の followup、
    そうでなければ、マルウェアの痕跡（campaign あり・該当モジュール）へのファイルの変更には CL-IR。"""
    if action["type"] in ("checklist", "chmod"):  # chmod は権限を絞るだけ（§11 の権限の finding）。後続作業は求めない
        return set()
    for s in suggestions:
        a = s["action"]
        if s["label"] == "auto" and a["type"] == action["type"] and a["target"] == action["target"]:
            return {c["template"] for c in a.get("followup", [])}
    return {"CL-IR"} if (f.get("campaign") or f["module"] in MALWARE_MODULES) else set()

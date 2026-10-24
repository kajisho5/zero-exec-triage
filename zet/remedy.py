"""Mapping from findings to remediation (GER remediation extension design, §2 / §6.1 Phase 1).

ZET never looks at the file system. This module only builds suggestions (constraints.suggested_actions in
the draft) and the lexical rules used by the checks before finalization (I-4 relations, I-13 required
follow-up work). GER does not trust the plan: it evaluates the same relations and hazard patterns again
against the current file system.

With findings 1.0 the decision uses module, path, level and campaign (the detail text is never parsed).
When findings 1.1 provides kind / subject / related, those take precedence.
"""
from __future__ import annotations

import hashlib
import posixpath
import re

from .legacy_templates import PATH_NONE_JA, TEMPLATES_JA

# --- Checklist templates (closed table). {path} is replaced with the finding's path ----------------------
_T = {
    "CL-PKG": [
        ("Do not run npm ci / npm install / pip install -r / bundle install in this working tree (the lockfile would fetch the compromised or vulnerable version again). Target: {path}", True),  # noqa: E501
        ("Set ignore-scripts=true in ~/.npmrc, and set the environment variables PIP_REQUIRE_VIRTUALENV=true and PYTHONNOUSERSITE=1", True),
        ("Change the dependency specification to a safe or fixed version, and regenerate the lockfile in an isolated environment without secrets (npm install --ignore-scripts / poetry lock / uv lock / bundle lock --update / cargo update -p, and so on)", True),  # noqa: E501
        ("Confirm with npm ls <name> / pip show / bundle info / cargo tree that no compromised or vulnerable version remains", True),
        ("If the compromised version may have been installed or executed, carry out CL-SECRET", True),
        ("Rescan with ZES and confirm that this finding is gone", True),
    ],
    "CL-LOCKFILE": [
        ("Do not run npm ci / npm install / yarn install / pnpm install in this working tree (the lockfile would fetch the compromised version again). Target: {path}", True),  # noqa: E501
        ("Set ignore-scripts=true in ~/.npmrc", True),
        ("Remove the dependency (npm uninstall {pkg}; yarn remove / pnpm remove) or pin it to a safe version (npm install {pkg}@<safe-version> --ignore-scripts), then regenerate the lockfile in an isolated environment without secrets. GER does not rewrite lockfiles. Quarantining the installed copy in node_modules does not clear this finding: the operator regenerates the lockfile and marks this step done", True),  # noqa: E501
        ("Confirm with npm ls {pkg} that the compromised version remains neither in node_modules nor in the lockfile", True),
        ("If the compromised version may have been installed or executed, carry out CL-SECRET", True),
        ("Rescan with ZES and confirm that this finding is gone", True),
    ],
    "CL-VENV": [
        ("Stop the processes that use the virtual environment (site-packages) containing the compromised or vulnerable version, and recreate the whole virtual environment (there is no RECORD, so GER cannot quarantine it safely). Target: {path}", True),  # noqa: E501
        ("In the new virtual environment, install a safe version explicitly (pip install --require-hashes, and so on)", True),
        ("Carry out CL-SECRET (code may have run at install time or at import time)", True),
        ("Rescan with ZES and confirm that this finding is gone", True),
    ],
    "CL-SECRET": [
        ("Revoke at each provider every credential that could be read from this machine or working tree (the list in §14 and the finding's path) (GitHub PAT: Settings → Developer settings → Revoke; npm: npm token revoke; AWS: deactivate and delete the access key in IAM; SSH keys: remove them from authorized_keys and from SSH keys on GitHub)", True),  # noqa: E501
        ("Issue new credentials on a machine that is not compromised", True),
        ("Check the provider's audit logs for unauthorized use before the revocation", True),
        ("If the secret is in the git history, decide whether to rewrite the history or only revoke the secret, and record the decision (GER does not rewrite history)", False),  # noqa: E501
    ],
    "CL-IR": [
        ("Record the time of the quarantine and remediation, and decide whether to disconnect this machine from the network. Target: {path}", True),
        ("Carry out CL-SECRET", True),
        ("Check for other traces of the same campaign with zes-scan.sh --full", True),
        ("Decide whether to rebuild the machine (rebuilding is recommended if there are traces of a rootkit or of persistence). Remediation by GER does not mean that the incident is over", True),  # noqa: E501
    ],
    "CL-LAUNCHD": [
        ("Run launchctl bootout gui/$(id -u)/<Label> (for a LaunchDaemon: sudo launchctl bootout system/<Label>). GER only quarantined the plist to stop the next load; an agent that is loaded now keeps running", True),  # noqa: E501
        ("Confirm that launchctl print gui/$(id -u)/<Label> reports that the service is not found", True),
        ("Confirm with ps -axo pid,command that no process of ProgramArguments remains, and stop any that remain. Also check the program itself", True),
        ("Also check login items and configuration profiles", False),
    ],
    "CL-SYSTEMD": [
        ("Run systemctl --user stop <unit> and systemctl --user daemon-reload (GER only quarantined the unit file)", True),
        ("Check the links in *.wants/ and the program that the unit started", True),
    ],
    "CL-CRON": [
        ("Back up the crontab with crontab -l > ~/crontab.bak.$(date +%s)", True),
        ("With crontab -e, delete the lines that make network connections or run files from temporary directories (see the ZES detail) (GER does not edit the crontab spool directly)", True),  # noqa: E501
        ("Confirm with crontab -l that the lines are gone", True),
    ],
    "CL-EXT": [
        ("Confirm that the browser was closed before the remediation (if an extension is quarantined while the browser is running, the browser may treat it as corrupted and repair it from the store)", True),  # noqa: E501
        ("Remove the extension in chrome://extensions and in the account's sync settings, so that sync does not reinstall it", True),
        ("Revoke the sessions (for the main sites) whose cookies the extension could read", True),
    ],
    "CL-MCP": [
        ("Restart the agent or IDE and confirm that the removed MCP server is not loaded", True),
        ("If the removed server may already have run, carry out CL-IR", True),
    ],
    "CL-MCP-PIN": [
        ("For an MCP server that npx / uvx fetches in its latest version at run time, the approver decides on a version and pins it (pkg@1.2.3). Adding a version is an addition, so GER does not automate it. Target: {path}", True),  # noqa: E501
        ("If the server is not used, remove it with disable_mcp_server", False),
    ],
    "CL-SHELL": [
        ("This has no effect on shells that are already open. Open the shell again (or also undo the removed setting in the current shell, for example with unset LD_PRELOAD)", True),  # noqa: E501
        ("Check that the same line is not in other rc files (.zshrc / .profile / .bash_profile)", True),
    ],
    "CL-LDSO": [
        ("Reboot (after the line is removed from ld.so.preload, processes that are already running still have the library loaded)", True),
        ("Check the library that the line pointed to and quarantine it (planned for preload_lib in GER Phase 2)", True),
        ("While a rootkit is present, the view of the file system itself cannot be trusted. Consider rebuilding the machine", True),
    ],
    "CL-PHP": [
        ("Upgrade PHP to a fixed version (the base image in the Dockerfile, .tool-versions, apt / apk packages). Rebuild the image and deploy it", True),
        ("Restart php-fpm / Apache (even when the package is fixed, running workers may still be the version before the update)", True),
        ("Rescan with ZES and confirm that this finding is gone", True),
    ],
    "CL-PHP-RESTART": [
        ("Restart PHP (php-fpm / Apache). Check whether auto_prepend_file had a legitimate use (APM, and so on)", True),
    ],
    "CL-UPGRADE": [
        ("Upgrade the server, runtime and packages to a fixed version as the vendor's advisory says (raising the tag in compose may not complete the migration). Target: {path}", True),  # noqa: E501
        ("Restart after the upgrade and check the version", True),
        ("Rescan with ZES and confirm that this finding is gone", True),
    ],
    "CL-PWN": [
        ("Disable the workflow (on GitHub: Actions → the workflow → Disable workflow, or commit the deletion of the workflow file to the default branch). Target: {path}", True),  # noqa: E501
        ("Remove ref: ${{ github.event.pull_request.head.* }} from actions/checkout, or change the trigger to pull_request", True),
        ("Rotate every secret that the workflow could reference, with CL-SECRET", True),
        ("Check the Actions run history for runs triggered by pull requests from outside", True),
    ],
    "CL-PIN": [
        ("On a trusted machine, check in the repository of the action or image the commit SHA or digest that the tag points to (git ls-remote / docker buildx imagetools inspect). Target: {path}", True),  # noqa: E501
        ("Confirm that the SHA is in the history of the upstream repository, not of a fork, and that it predates the compromise", True),
        ("Pin by SHA or digest (planned for pin_action / pin_digest with 2 approvers in GER Phase 2). Do not pin an action that was reported as compromised; choose a replacement instead", True),  # noqa: E501
    ],
    "CL-SKILL": [
        ("Report to the author of the skill and have the contract (skill.contract.json) fixed. Target: {path}", True),
        ("Do not use the skill until it is fixed (quarantine it with quarantine skill_dir if needed)", True),
    ],
    "CL-ENV": [
        ("Set PYTHONNOUSERSITE=1 / PIP_REQUIRE_VIRTUALENV=true / npm's ignore-scripts=true in the user's shell rc (which rc file depends on the environment)", True),  # noqa: E501
    ],
    "CL-REVIEW": [
        ("Fix it by hand as the ZES detail says (GER does not automate fixes that change the meaning of code, or fixes whose correct value only a person knows). Target: {path}", True),  # noqa: E501
        ("Rescan with ZES and confirm that this finding is gone", True),
    ],
}
TEMPLATES = frozenset(_T)
PATH_NONE = "(no path)"
# GER accepts a checklist or followup step text of 1-2000 characters (actions.schema.json; G-1 rejects the whole plan)
MAX_STEP_TEXT = 2000
_PLACEHOLDER = re.compile(r"\{path\}|\{pkg\}")


def _fill(t: str, path: str, pkg: str) -> str:
    text = t.replace("{path}", path).replace("{pkg}", pkg)
    n = len(_PLACEHOLDER.findall(t))
    if len(text) <= MAX_STEP_TEXT or not n:
        return text
    # A path (legal up to PATH_MAX) or package name too long for GER's limit: each value keeps its end (the file name)
    #   behind "…" so that the step fits. The rule is fixed, so I-13 still compares the whole text with the template
    room = (MAX_STEP_TEXT - len(_PLACEHOLDER.sub("", t))) // n
    vals = {"{path}": path, "{pkg}": pkg}
    short = {k: v if len(v) <= room else "…" + v[len(v) - room + 1:] for k, v in vals.items()}
    return _PLACEHOLDER.sub(lambda m: short[m.group()], t)


def _steps(table: dict, template: str, path: str | None, pkg: str | None, none: str) -> list[dict]:
    return [{"id": f"s{i}", "text": _fill(t, path or none, pkg or "<name>"), "blocking": b}
            for i, (t, b) in enumerate(table[template], 1)]


def checklist(template: str, path: str | None, pkg: str | None = None) -> dict:
    """{path} becomes the finding's path, {pkg} the findings 1.1 subject.package (<name> when there is none)."""
    return {"template": template, "steps": _steps(_T, template, path, pkg, PATH_NONE)}


def pkg_of(f: dict) -> str | None:
    s = f.get("subject")
    return s["package"] if isinstance(s, dict) and isinstance(s.get("package"), str) and s["package"] else None


def template_ok(cl: dict, path: str | None, pkg: str | None = None) -> bool:
    """Every step of the template is included (same id, same text, same blocking). Adding steps is allowed.

    The text may be the current English one or, for plans made by an older ZET, the Japanese one
    (legacy_templates). One checklist uses one language for all the steps of its template.
    """
    # The plan may hold anything here (params of a checklist is any object): malformed steps never match, and are
    #   reported as I-4 by the actions.schema.json check
    if not isinstance(cl, dict) or not isinstance(cl.get("template"), str) or cl["template"] not in _T \
            or not isinstance(cl.get("steps"), list):
        return False
    have = {(s["id"], s["text"], s["blocking"]) for s in cl["steps"] if isinstance(s, dict) and isinstance(s.get("id"), str)
            and isinstance(s.get("text"), str) and isinstance(s.get("blocking"), bool)}
    for table, none in ((_T, PATH_NONE), (TEMPLATES_JA, PATH_NONE_JA)):
        want = _steps(table, cl["template"], path, pkg, none)
        if all((s["id"], s["text"], s["blocking"]) in have for s in want):
            return True
    return False


# --- Lexical rules (the same as GER's ger/hazards.py and ger/actions/quarantine.py) -----------------------
ROOT_PREFIXES = ("/etc/", "/usr/", "/var/", "/opt/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/",
                 "/boot/", "/System/", "/Library/", "/private/etc/", "/private/var/")
USER_TMP_PREFIXES = ("/var/folders/", "/private/var/folders/", "/var/tmp/")


def root_required(path: str | None) -> bool:
    return bool(path) and path.startswith(ROOT_PREFIXES) and not path.startswith(USER_TMP_PREFIXES)


LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}
PKG_MANIFESTS = LOCKFILES | {"Gemfile.lock", "Cargo.lock", "composer.lock", "go.sum", "poetry.lock", "Pipfile.lock",
                             "uv.lock", "pyproject.toml", "Pipfile", "Gemfile", "Cargo.toml", "go.mod", "composer.json"}
# Lockfiles (files that pin dependency versions). Quarantining the installed copy (node_modules and so on) does not clear such a finding
LOCKFILE_NAMES = LOCKFILES | {"Gemfile.lock", "Cargo.lock", "composer.lock", "go.sum", "poetry.lock", "Pipfile.lock", "uv.lock",
                              "deno.lock"}
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
    """I-4: the relation between target and the finding's path (lexical conditions). Returns the reason when there is a problem."""
    if relation not in RELATIONS:
        return f"relation {relation} is unknown"
    if relation == "none":
        return None if target is None else "relation none is only for a target of null"
    if target is None:
        return "the relation of an action whose target is null must be none"
    if relation not in PHASE1_RELATIONS:
        # Phase 2 relations only when they are in the related list of ZES findings 1.1 (GER Phase 1 does not support them and rejects them)
        ok = any(r.get("relation") == relation and r.get("path") == target for r in related or [])
        return None if ok else f"relation {relation} is only for a target in the finding's related list"
    if fp is None:
        return "a finding whose path is null can only have a checklist action (target null)"
    if relation == "self":
        return None if target == fp else "with relation self, action.target must equal the finding's path"
    if related and any(r.get("relation") == relation and r.get("path") == target for r in related):
        return None
    if relation == "npm_pkg_dir":
        par = posixpath.dirname(target)
        ok = fp == target + "/package.json" and (posixpath.basename(par) == "node_modules" or (
            posixpath.basename(par).startswith("@") and posixpath.basename(posixpath.dirname(par)) == "node_modules"))
        return None if ok else "npm_pkg_dir: target must be node_modules/<name> and the finding's path must be its package.json"
    if relation == "npm_installed":
        base = posixpath.dirname(fp) + "/node_modules/"
        ok = posixpath.basename(fp) in LOCKFILES and target.startswith(base) and _NPM_REST.fullmatch(target[len(base):])
        return None if ok else "npm_installed: the finding must be a lockfile and target must be node_modules/<name> next to it"
    if relation == "pypi_record":
        ok = target == fp and posixpath.basename(target).endswith(".dist-info")
        return None if ok else "pypi_record: target must be the *.dist-info that is the finding's path"
    if relation == "ext_dir":
        m = _EXT.match(fp)
        return None if m and m.group(1) == target else (
            "ext_dir: the finding's path must be …/Extensions/<id>[/<ver>]/manifest.json and target must be …/Extensions/<id>")
    if relation == "skill_dir":
        ok = target == fp or (posixpath.basename(fp) == "skill.contract.json" and posixpath.dirname(fp) == target)
        return None if ok else "skill_dir: target must be the directory of the skill at the finding's path"
    return "unknown relation"


# --- I-13: operations allowed for each findings 1.1 kind ---------------------------------------------
KIND_ACTIONS = {
    "pkg.compromised": {"quarantine", "checklist"},
    "pkg.vulnerable": {"checklist"},
    "pkg.lockfile_compromised": {"checklist"},  # §9.6: the installed copy is quarantined through the node_modules/<name>/package.json finding
    "mcp.dangerous_command": {"disable_mcp_server", "edit_json", "edit_toml", "checklist"},
    "mcp.unpinned": {"disable_mcp_server", "checklist"},
    "gha.unpinned": {"checklist"},
    "gha.pwn_request": {"checklist"},
    "secret.token": {"checklist"},
    "runtime.cve": {"checklist"},
}


# Files in which GER can remove an MCP server (GER's hazards.MCP_JSON_BASENAMES for mcp.server, and .codex/config.toml for
#   mcp.server.toml). Elsewhere an edit selects something else (for example a hook in .claude/settings.json) or nothing
def mcp_editable(path: str | None) -> bool:
    return bool(path) and (_b(path) in MCP_JSON or path.endswith("/.codex/config.toml"))


def is_lockfile_finding(f: dict) -> bool:
    """I-13 (§9.6): a lockfile finding (findings 1.1 kind pkg.lockfile_compromised, or a §15 lockfile).
    ZES reports it from the contents of the lockfile, so quarantining the installed copy (node_modules/<name>) does not
    clear it. The operator fixes the lockfile (regeneration, pinning a safe version); GER does not rewrite it. It is not
    counted as an automatic remediation and gets a checklist only."""
    return f.get("kind") == "pkg.lockfile_compromised" or (f["module"] == "§15" and _b(f["path"]) in LOCKFILE_NAMES)


def lockfile_template(f: dict) -> str:
    s = f.get("subject") if isinstance(f.get("subject"), dict) else {}
    return "CL-LOCKFILE" if _b(f["path"]) in LOCKFILES or s.get("ecosystem") == "npm" else "CL-PKG"


# --- Suggestions --------------------------------------------------------------------------------
def _b(p):
    return posixpath.basename(p) if p else ""


def _act(type_, target, relation, fp, params=None, followup=()):
    a = {"type": type_, "target": target, "relation": relation, "finding_path": fp, "params": params or {}}
    if followup:
        a["followup"] = [checklist(t, fp) for t in followup]
    return a


def _cl(template, f):
    p = f["path"]
    return _act("checklist", p, "self" if p else "none", p, checklist(template, p, pkg_of(f)))


def _q(f, relation="self", target=None, fu=()):
    return _act("quarantine", target or f["path"], relation, f["path"], {}, fu)


def _ir(f):
    return ("CL-IR",) if f.get("campaign") or f["module"] in MALWARE_MODULES else ()


def classify(f: dict) -> tuple[list[dict], str | None]:
    """(list of suggestions [{label, action, note?}], note). The first auto is the default candidate."""
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
    elif m == "§15" and is_lockfile_finding(f):
        # §9.6: no auto even with related npm_installed. The installed copy is quarantined by quarantine npm_pkg_dir on the
        # node_modules/<name>/package.json finding (pkg.compromised); ZES reports that one separately when the installed version is compromised
        cl = lockfile_template(f)
        if any(r.get("relation") == "npm_installed" for r in f.get("related") or []):
            note = ("quarantining the copy in node_modules does not clear the lockfile finding until the lockfile is regenerated "
                    "(the operator completes it with the checklist)")
    elif m == "§15":
        parts = p.split("/")
        if b == "package.json" and "node_modules" in parts[:-1]:
            autos.append(_q(f, "npm_pkg_dir", posixpath.dirname(p), ("CL-PKG", "CL-IR", "CL-SECRET")))
            cl = "CL-PKG"
        elif b.endswith(".dist-info"):
            if lv == "CRITICAL" or kind == "pkg.compromised":
                autos.append(_q(f, "pypi_record", p, ("CL-PKG", "CL-SECRET")))
                note = "without RECORD, GER refuses the quarantine (Q-6); use checklist CL-VENV in that case"
            cl = "CL-VENV" if lv == "CRITICAL" else "CL-PKG"
        elif b.endswith(".egg-info"):
            cl = "CL-VENV"
        elif b in PKG_MANIFESTS or re.fullmatch(r"requirements[\w.-]*\.txt", b):
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
            if kind.startswith("mcp."):
                # An MCP server under mcpServers of .claude/settings.json: GER has no hazard table entry for it (mcp.server
                # covers MCP config files only), and select claude.hook would remove an unrelated hook. Removed by hand
                cl = "CL-REVIEW" if kind == "mcp.dangerous_command" else "CL-MCP-PIN"
                note = ("GER cannot remove an MCP server from .claude/settings.json (no hazard table entry); "
                        "remove it by hand with the checklist")
            else:
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
    """The (relation, target) pairs this finding can be linked by. Used to tell whether another finding's automatic remediation covers it."""
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
    """finding_id → suggestions. Automatic remediations of the same target are put in one group, and a finding covered by
    another finding's automatic remediation gets the same operation suggested."""
    sug = {x["id"]: classify(x)[0] for x in findings}
    autos: dict[tuple[str, str], list[str]] = {}
    for x in findings:
        for s in sug[x["id"]]:
            if s["label"] == "auto":
                autos.setdefault((s["action"]["type"], s["action"]["target"]), []).append(x["id"])
    # Findings covered by another finding's automatic remediation (same file, same skill, same extension)
    by_target = {}
    for (t, tgt), fids in autos.items():
        if t == "quarantine":  # quarantine moves the whole file or tree, so the other findings on it go away too (an edit does not do that)
            by_target.setdefault(tgt, []).append((t, fids))
    for x in findings:
        if any(s["label"] == "auto" for s in sug[x["id"]]) or is_lockfile_finding(x):
            continue
        for rel, tgt in candidate_targets(x):
            for t, fids in by_target.get(tgt, []):
                src = next(s for s in sug[fids[0]] if s["label"] == "auto" and s["action"]["target"] == tgt)
                a = dict(src["action"], relation=rel, finding_path=x["path"])
                a = {k: v for k, v in a.items() if k != "followup"}
                if src["action"].get("followup"):
                    a["followup"] = [checklist(c["template"], x["path"], pkg_of(x)) for c in src["action"]["followup"]]
                sug[x["id"]].insert(0, {"label": "auto", "action": a,
                                        "note": "another finding's automatic remediation handles the same target, so both are in the same group"})
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
    """I-13: the follow-up templates that an automatic remediation action must carry. The suggestion's followup when the
    operation is the suggested one; otherwise CL-IR for a file change on a malware trace (with a campaign, or in a malware module)."""
    if action["type"] in ("checklist", "chmod"):  # chmod only narrows permissions (§11 permission findings). No follow-up work is required
        return set()
    for s in suggestions:
        a = s["action"]
        if s["label"] == "auto" and a["type"] == action["type"] and a["target"] == action["target"]:
            return {c["template"] for c in a.get("followup", [])}
    return {"CL-IR"} if (f.get("campaign") or f["module"] in MALWARE_MODULES) else set()

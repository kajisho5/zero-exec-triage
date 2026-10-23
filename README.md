<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/zet-logo-dark.svg">
    <img src="brand/logo/zet-logo-light.svg" alt="zero-exec triage" height="72">
  </picture>
</p>

English | [日本語](README.ja.md)

# zero-exec-triage (ZET)

**Zero-Exec Triage** is the decision layer of [Zero-Exec Shield (ZES)](https://github.com/kajisho5/zero-exec-shield). It takes a ZES findings.json and produces a remediation plan (remediation-plan.json) that sorts every finding into "fix", "make an exception", or "hold". The remediation itself is carried out by [GER (gated-exec-remediation)](https://github.com/kajisho5/gated-exec-remediation).

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER]
```

- **Executes nothing**: it reads JSON and writes only the plan file and an append-only audit log
- **No decision that breaks the contract gets through**: a plan that does not satisfy invariants I-1 to I-13 (including the [SkillPact](https://github.com/kajisho5/skillpact) rules) cannot be finalized
- **Suggests real remediation** (0.2, plan 1.1): `draft` attaches to each finding an `auto` action that GER can carry out (quarantine, edit_json, edit_toml, remove_line, disable_mcp_server) and a concrete `checklist`, groups findings on the same file, and adds the mandatory follow-up checklists (incident response, secret rotation, `launchctl bootout`, …) to every automatic fix. The decider still decides; ZET only suggests

## What gets suggested

ZET does not look at the file system. With ZES findings 1.0 it works from `module`, `path`, `level` and `campaign` (it never parses the human-readable `detail`); with findings 1.1 (ZES 0.4.0: `kind`, `subject`, `related`, `evidence`, `scan_roots`) it uses those fields instead. Findings 1.2 (ZES 0.5.0: `code` / `params`, English `detail`, id v2) is accepted too; ZET never recomputes ids, so a plan stays tied to the findings.json it was made from. GER then re-derives every relation and hazard from the filesystem, so a wrong suggestion is refused, not executed.

| Finding (examples) | `auto` suggestion | Mandatory follow-ups | `checklist` |
|---|---|---|---|
| Malicious files, payloads, `.pth` hooks, IoC files (§2 §15 §18 §20 §30 §40), SymJack links (§17) | `quarantine` self | CL-IR (and CL-SECRET) | CL-IR |
| `node_modules/<name>/package.json` of a compromised package (§15) | `quarantine` `npm_pkg_dir` | CL-PKG, CL-IR, CL-SECRET | CL-PKG |
| Compromised `*.dist-info` (§15 CRITICAL) | `quarantine` `pypi_record` (GER refuses it when there is no RECORD) | CL-PKG, CL-SECRET | CL-VENV |
| npm lock files (§15, `pkg.lockfile_compromised`), even with `related: npm_installed`: the installed copy is quarantined through its own `node_modules/<name>/package.json` finding, and the lock file finding stays open until an operator regenerates the lock file | — | — | CL-LOCKFILE |
| Other lock files and requirements (§15), `*.egg-info`, vulnerable versions | — | — | CL-PKG / CL-VENV |
| Dangerous MCP server in `.mcp.json`, `mcp.json`, `.codex/config.toml` (§17 HIGH) | `disable_mcp_server` | CL-MCP (+ CL-IR) | CL-MCP |
| `npx` / `uvx` MCP server (§17 MEDIUM) | — | — | CL-MCP-PIN |
| `package.json` lifecycle script (§2 / §15), `.claude/settings.json` hooks (§7), `.vscode/tasks.json` `runOn` (§7) | `edit_json` | CL-IR when it is a campaign | CL-IR / CL-REVIEW |
| `ld.so.preload`, shell rc lines (§31 §10), php.ini `auto_prepend_file` (§4), git config / `.envrc` (§26) | `remove_line` | CL-LDSO / CL-SHELL / CL-PHP-RESTART (+ CL-IR) | CL-IR / CL-PHP-RESTART |
| LaunchAgents / LaunchDaemons plist (§30), systemd units | `quarantine` self | CL-LAUNCHD / CL-SYSTEMD, CL-IR | CL-IR |
| Browser extension manifest (§24 §42) | `quarantine` `ext_dir` | CL-EXT, CL-IR | CL-EXT |
| SkillPact divergence / diff anomaly (§49) | `quarantine` `skill_dir` | CL-SKILL, CL-IR | CL-SKILL |
| Server / runtime CVEs (§3 §5 §6 §16 §37 §41), PHP (§4), pwn requests (§21 §38), unpinned actions and images (§22 §28), crontab and env vars (`path: null`), secrets (§8 §45 §47) | — | — | CL-UPGRADE / CL-PHP / CL-PWN / CL-PIN / CL-CRON / CL-ENV / CL-SECRET |

An INFO finding on a file that another finding's quarantine will move (for example the §10 INFO on a LaunchAgent that §30 quarantines) is not auto-deferred; it is offered the same grouped quarantine, because the re-scan will not show it either. Lock files are never edited and secrets are never rotated automatically: those stay checklists.
- **Zero dependencies**: Python 3.11+ standard library only. Launched with `python3 -I -S`, so neither environment variables nor any `.pth` file in site-packages can run code inside it

## Usage

```bash
bin/zet validate triage-input.json --operator alice
bin/zet draft    triage-input.json --operator alice -o plan.draft.json
# plan.draft.json の decision / owner / approved_by などを記入（constraints.suggested_actions から action を選ぶ）
ger preview plan.draft.json --operator alice -o plan.previewed.json --report preview.json   # GER: params のハッシュを埋める
bin/zet check    triage-input.json plan.previewed.json --operator alice
bin/zet finalize triage-input.json plan.draft.json --operator alice -o remediation-plan.json
bin/zet verify-log
```

(The comment line means: fill in `decision` / `owner` / `approved_by` etc. in plan.draft.json, picking each `action` from `constraints.suggested_actions`; then let `ger preview` fill in the exact hashes, ops and `expected_after_sha256`, and finalize that file.)

To suggest file-changing actions, the triage input needs the approved scan scope: `policy.scope = {"roots": [<ZES --root>], "home": <ZES_HOME>}` (or `scan_roots` in findings 1.1). ZET copies it into the plan as `scope`, and every target must lie under it.

| Command | Description |
|---|---|
| `validate` | Schema validation of the input. Rejects `findings.status == "error"` and `l3_trusted: true`. `skillpact_policy.diff_anomaly_threshold` and `destructive_requires_human` are reserved and not implemented, so an input that sets either of them is rejected (ZES reports `diff_anomaly` as a boolean, so there is nothing to apply a threshold to, and ZET cannot tell whether a decider is a human) |
| `draft` | Generates a draft (plan 1.1): holds unresolved modules, raises severity per SkillPact, computes deadlines, attaches `constraints.suggested_actions` (`auto` and `checklist`), groups findings on the same target, and copies `scope`. `decision` is left empty (only findings whose level_effective is INFO default to defer, unless another finding's quarantine covers the same target) |
| `check` | Checks invariants I-1 to I-13 |
| `finalize` | Writes the finalized plan (with `plan_hash`) only if every check passes |
| `verify-log [LOG]` | Verifies the audit log's hash chain (read-only; not itself logged). Exit code `0` if intact, `3` if broken, `64` if the log is missing or unreadable |

Exit codes: `0` pass / `3` contract violation / `64` usage or environment error (including `-o` being a directory, not a regular file, the same file as an input, the audit log or a path inside the audit log directory, or in an unwritable location, and failure to write the output) / `70` internal error (including when the output cannot be serialized to JSON). `-o` is checked before any processing (a path ending with `/` is rejected, and the parent directory is checked as given). Options: `--now` (pins the current time; test-only, accepted only when the environment variable `ZET_ALLOW_NOW_OVERRIDE=1` is set, otherwise `64`; a plan drafted or finalized with `--now` carries `now_override: true`, and GER refuses such a plan unless `GER_ALLOW_NOW_OVERRIDE=1`) and `--plan-id` (draft). JSON written to `-o` or standard output is always UTF-8 regardless of the locale; messages on standard error fall back to `\uXXXX`-style escapes when the locale cannot encode them.

See [SKILL.md](SKILL.md) for the detailed procedure and how to write decisions, and [docs/design/design.md](docs/design/design.md) for the design.

## Invariants

| # | Rule |
|---|---|
| I-1 | Every finding in the input appears exactly once in either items or held, and every decision in items is filled in |
| I-2 | No finding_id that does not exist in the input |
| I-3 | An exception requires exception_type, reason, recheck_at, and approval by someone other than the decider (names are compared case-insensitively). A defer also requires a reason unless level_effective is INFO. decided_by / decided_at are mandatory |
| I-4 | A remediate requires owner, due_at and action. action.target is a normalized absolute path (no `.`, `..` or repeated `/` anywhere, including a leading `//`) related to the finding's `path` by `action.relation`: `self` (the path itself; never a path under it, because ZET cannot tell whether `path` is a directory), or one of the closed relations `npm_pkg_dir`, `npm_installed`, `pypi_record`, `ext_dir`, `skill_dir` whose lexical condition holds (or that findings 1.1 lists in `related`); `none` with a null target is allowed only for a `checklist` (for example a crontab finding whose `path` is null); `finding_path`, if present, equals the finding's `path`; action.type is one GER can execute (`chmod`, `quarantine`, `edit_json`, `edit_toml`, `remove_line`, `disable_mcp_server`, `checklist`); a finalized action's params match GER's `actions.schema.json` (a draft may still carry `select`); two file-changing remediate items share a target only through the same `action.group`, and all items of a group share type and target; file-changing actions other than chmod need `plan.scope`, which must equal the scope derived from the input, and every target lies under it; chmod params are only `{"mode": "0NNN"}` with no setuid / setgid / sticky bit and not world-writable (ZET cannot see the current mode; GER checks at G-7 that the chmod adds no permission bit). action.reversible / skillpact_effects / evidence (plan 1.0: evidence_hash) match the derived values (finalize adds them, together with relation and finding_path) |
| I-5 | A finding with a non-empty skillpact.divergence cannot be an exception. finalize copies a summary of the finding's skillpact (`signed` / `divergence` / `diff_anomaly` / `declared_effects`) into the item as `skillpact`, so that GER can re-check I-5 / I-6 / I-7 from the plan; if present it must match the input |
| I-6 | A skillpact.diff_anomaly finding, a remediate of a finding whose skill declares exec / network / spend / send (the same rule as GER's G-6), and a file-changing remediate whose target needs root (`/etc`, `/usr`, `/var`, …), need at least 2 approvers (duplicates and names differing only in case count as one) |
| I-7 | A finding whose `skillpact.signed` is true (a signature field is present; ZES does not verify it, so this is not "L3-signed") and whose `skillpact.divergence` is non-empty has level_effective = CRITICAL (cannot be lowered) |
| I-8 | Approvers must be in policy.approvers (case-insensitive) |
| I-9 | due_at is within decision date + deadlines[level_effective] days; recheck_at is mandatory for exception and for defer (when level_effective is not INFO), and must be on or after the decision date and within the decision window. The decision date (decided_at) is on or after created_at and no later than the time of execution |
| I-10 | Findings from modules listed in errors[] go to held (they are not passed to GER). held may be used only for modules in errors[] |
| I-11 | Strict schema (rejects unknown fields, duplicate keys, nesting deeper than GER's 64-level limit, invalid timestamps, non-finite numbers and invalid surrogates). For a plan that carries plan_hash, check / finalize also verify plan_hash |
| I-12 | If the input is partial, the plan is partial too, and modules in errors[] are held module by module |
| I-13 | Every automatic fix carries the mandatory follow-up checklists for its finding (`action.followup`, for example CL-IR and CL-SECRET for a malware indicator, CL-LAUNCHD for a LaunchAgent, CL-EXT for a browser extension); every checklist (and follow-up) contains all steps of its ZET template unchanged (steps may be added); with findings 1.1, the action type must be allowed for the finding's `kind`; a lock file finding (`pkg.lockfile_compromised`, or §15 on a lock file) is remediated only by a checklist (CL-LOCKFILE for npm, CL-PKG otherwise), because quarantining the installed package does not make the lock file finding go away |

## Schemas

| File | Owner | Description |
|---|---|---|
| [schemas/remediation-plan.schema.json](schemas/remediation-plan.schema.json) | **ZET** | Output contract (1.1 adds `scope`, and `relation` / `finding_path` / `group` / `evidence` / `followup` on actions; a 1.0 plan with chmod only is still valid). GER references it pinned to a version |
| [schemas/triage-input.schema.json](schemas/triage-input.schema.json) | ZET | Input |
| [schemas/vendor/findings.schema.json](schemas/vendor/findings.schema.json) | ZES | Version-pinned copy (source commit and SHA-256 in `schemas/vendor/VENDOR.json`) |
| [schemas/vendor/findings-1.1.schema.json](schemas/vendor/findings-1.1.schema.json) | ZES | ZES findings 1.1 (ZES 0.4.0+): 1.0 plus optional `kind` / `subject` / `locators` / `related` / `evidence` and top-level `scan_roots`. Pinned copy of ZES's `schemas/findings.schema.json` |
| [schemas/vendor/findings-1.2.schema.json](schemas/vendor/findings-1.2.schema.json) | ZES | ZES findings 1.2 (ZES 0.5.0+): 1.1 plus `code` / `params`; `detail` is English and `id` is v2 (`module\|campaign\|path\|code\|params`) |
| [schemas/vendor/actions.schema.json](schemas/vendor/actions.schema.json) | GER | Version-pinned copy of the params of each GER action |

At runtime, the schema files themselves are validated with a subset validator written in the standard library (`zet/jsonschema_lite.py`). The tests confirm that its verdicts match the official `jsonschema`.

## Audit log

`$ZET_LOG_DIR/zet-audit.jsonl` (default `$XDG_STATE_HOME/zet/`, or `~/.local/state/zet/` when `XDG_STATE_HOME` is unset). One record per line (command / operator / input_hash / output_hash / started_at / finished_at / result / violations / prev_hash; runs that used `--now` also get `now_override: true`). `result: ok` and `output_hash` are recorded only when the output (`-o` or standard output) was written successfully; otherwise `result: error`. Rejections are logged too, and tampering can be detected through the `prev_hash` hash chain: `bin/zet verify-log` checks the whole chain. Before appending, ZET checks the tail link (the last line must end with a newline, be a JSON object and carry the hash of the line before it) and refuses to append to a broken chain (exit code `64`; inspect with `verify-log` and move the log aside before running again). If the log cannot be written, or if the log directory is owned by someone other than the running user or is writable by group or others, ZET does nothing (exit code `64`).

## Tests

```bash
tests/run-tests.sh   # 単体テスト＋ strace による execve 監視（bash / python3 以外を起動しないこと）
```

This runs the unit tests plus execve monitoring with strace (nothing other than bash / python3 may be launched).

If `jsonschema` is installed, the validator-agreement tests also run (a development-only dependency; SKIP if absent).

## License

[Apache License 2.0](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).

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
- **No decision that breaks the contract gets through**: a plan that does not satisfy invariants I-1 to I-12 (including the [SkillPact](https://github.com/kajisho5/skillpact) rules) cannot be finalized
- **Zero dependencies**: Python 3.11+ standard library only. Launched with `python3 -I`

## Usage

```bash
bin/zet validate triage-input.json --operator alice
bin/zet draft    triage-input.json --operator alice -o plan.draft.json
# plan.draft.json の decision / owner / approved_by などを記入
bin/zet check    triage-input.json plan.draft.json --operator alice
bin/zet finalize triage-input.json plan.draft.json --operator alice -o remediation-plan.json
```

(The comment line means: fill in `decision` / `owner` / `approved_by` etc. in plan.draft.json.)

| Command | Description |
|---|---|
| `validate` | Schema validation of the input. Rejects `findings.status == "error"` and `l3_trusted: true` |
| `draft` | Generates a draft: holds unresolved modules, raises severity per SkillPact, computes deadlines. `decision` is left empty (only findings whose level_effective is INFO default to defer) |
| `check` | Checks invariants I-1 to I-12 |
| `finalize` | Writes the finalized plan (with `plan_hash`) only if every check passes |

Exit codes: `0` pass / `3` contract violation / `64` usage or environment error (including `-o` being a directory, not a regular file, the same file as an input, the audit log or a path inside the audit log directory, or in an unwritable location, and failure to write the output) / `70` internal error (including when the output cannot be serialized to JSON). `-o` is checked before any processing (a path ending with `/` is rejected, and the parent directory is checked as given). Options: `--now` (pins the current time; test-only, accepted only when the environment variable `ZET_ALLOW_NOW_OVERRIDE=1` is set, otherwise `64`) and `--plan-id` (draft). JSON written to `-o` or standard output is always UTF-8 regardless of the locale; messages on standard error fall back to `\uXXXX`-style escapes when the locale cannot encode them.

See [SKILL.md](SKILL.md) for the detailed procedure and how to write decisions, and [docs/design/design.md](docs/design/design.md) for the design.

## Invariants

| # | Rule |
|---|---|
| I-1 | Every finding in the input appears exactly once in either items or held, and every decision in items is filled in |
| I-2 | No finding_id that does not exist in the input |
| I-3 | An exception requires exception_type, reason, recheck_at, and approval by someone other than the decider (names are compared case-insensitively). A defer also requires a reason unless level_effective is INFO. decided_by / decided_at are mandatory |
| I-4 | A remediate requires owner, due_at and action. action.target is a normalized absolute path (no `.`, `..` or repeated `/` anywhere, including a leading `//`); action.type is one GER can execute (currently only `chmod`); no two remediate items share the same action.target; chmod params are only `{"mode": "0NNN"}` (no special bits) — the same acceptance rules as GER. action.reversible / skillpact_effects match the derived values |
| I-5 | A finding with a non-empty skillpact.divergence cannot be an exception |
| I-6 | A skillpact.diff_anomaly finding needs at least 2 approvers (duplicates and names differing only in case count as one) |
| I-7 | A finding that is L3-signed and has a divergence has level_effective = CRITICAL (cannot be lowered) |
| I-8 | Approvers must be in policy.approvers (case-insensitive) |
| I-9 | due_at is within decision date + deadlines[level_effective] days; recheck_at is mandatory for exception and for defer (when level_effective is not INFO), and must be on or after the decision date and within the decision window. The decision date (decided_at) is on or after created_at and no later than the time of execution |
| I-10 | Findings from modules listed in errors[] go to held (they are not passed to GER). held may be used only for modules in errors[] |
| I-11 | Strict schema (rejects unknown fields, duplicate keys, nesting deeper than GER's 64-level limit, invalid timestamps, non-finite numbers and invalid surrogates). For a plan that carries plan_hash, check / finalize also verify plan_hash |
| I-12 | If the input is partial, the plan is partial too, and modules in errors[] are held module by module |

## Schemas

| File | Owner | Description |
|---|---|---|
| [schemas/remediation-plan.schema.json](schemas/remediation-plan.schema.json) | **ZET** | Output contract. GER references it pinned to a version |
| [schemas/triage-input.schema.json](schemas/triage-input.schema.json) | ZET | Input |
| [schemas/vendor/findings.schema.json](schemas/vendor/findings.schema.json) | ZES | Version-pinned copy (source commit and SHA-256 in `schemas/vendor/VENDOR.json`) |

At runtime, the schema files themselves are validated with a subset validator written in the standard library (`zet/jsonschema_lite.py`). The tests confirm that its verdicts match the official `jsonschema`.

## Audit log

`$ZET_LOG_DIR/zet-audit.jsonl` (default `$XDG_STATE_HOME/zet/`, or `~/.local/state/zet/` when `XDG_STATE_HOME` is unset). One record per line (command / operator / input_hash / output_hash / started_at / finished_at / result / violations / prev_hash; runs that used `--now` also get `now_override: true`). `result: ok` and `output_hash` are recorded only when the output (`-o` or standard output) was written successfully; otherwise `result: error`. Rejections are logged too, and tampering can be detected through the `prev_hash` hash chain. If the log cannot be written, or if the log directory is owned by someone other than the running user or is writable by group or others, ZET does nothing (exit code `64`).

## Tests

```bash
tests/run-tests.sh   # 単体テスト（55 件）＋ strace による execve 監視（bash / python3 以外を起動しないこと）
```

This runs the unit tests (55) plus execve monitoring with strace (nothing other than bash / python3 may be launched).

If `jsonschema` is installed, the validator-agreement tests also run (a development-only dependency; SKIP if absent).

## License

[Apache License 2.0](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).

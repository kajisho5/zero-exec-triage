English | [日本語](design.ja.md)

# ZET (Zero-Exec Triage) detailed design — Step 1

- **Version**: design 0.1 (2026-10-22) / approved 2026-10-22 (A-1 to A-6 and B-1 to B-4 adopted), implementation 0.1.0
- **Addendum**: §9 describes the changes to the decision layer (plan 1.1, suggestions, I-4 relations, I-13) for Phase 1 of the GER remediation extension design 0.2 (approved 2026-10-23; Q-1 to Q-6 adopted as recommended)
- **Layer**: decision layer (between the ZES detection layer and the GER remediation layer)
- **Principle**: Zero-Exec. ZET executes nothing. It reads only JSON and writes only the plan file and an append-only log
- **Parent document**: [ZES skill contracts](https://github.com/kajisho5/zero-exec-shield/blob/main/docs/skill-contracts.md) (§1 to §4, §8)

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER]
```

---

## 1. Requirements

### 1.1 Purpose
Sort every single ZES finding into one of "fix (remediate)", "make an exception (exception)" or "hold (defer)", and build a **remediation plan (remediation-plan.json)** with deadlines, owners and approvals. The content of the decisions (which findings become exceptions) is decided by a person or an AI agent; ZET is responsible for **letting no decision through that breaks the contract**.

### 1.2 What ZET does and does not do

| Does | Does not |
|---|---|
| Schema validation of the input (findings.json + policy) | Modify findings.json (`id` / `level` / `module` never change) |
| Generate a draft plan (deadline calculation, SkillPact constraints, unconfirmed modules to held) | Change files, run commands, communicate externally |
| Check the invariants of a plan filled in by a person or an AI | Verify L3 signatures (a person runs `cosign verify` separately when needed) |
| Append-only audit log | Carry out the remediation (the job of GER) |

### 1.3 Functions

| Command | Input | Output | Exit code |
|---|---|---|---|
| `zet validate <triage-input.json>` | Decision layer input (contract §2) | Validation result (standard error) | 0 = OK / 3 = contract violation / 64 = argument error |
| `zet draft <triage-input.json>` | Same | Draft plan (standard output; `status` is always treated as `"draft"` and cannot be passed to GER) | Same |
| `zet check <triage-input.json> <plan.json>` | Input + plan filled in by a person or an AI | List of violations | 0 = passed / 3 = violations |
| `zet finalize <triage-input.json> <plan.json>` | Same | Finalized plan (written only when `check` passes; appended to the audit log) | 0 / 3 |
| `zet verify-log [LOG]` | Audit log (default `$ZET_LOG_DIR/zet-audit.jsonl`) | Result of the hash chain verification (standard error; this run is not recorded) | 0 = intact / 3 = broken / 64 = log missing or unreadable |

Only `finalize` outputs a plan that can be passed to GER. The output of `draft` deliberately does not pass the GER input schema (`status: "draft"`), so that a plan without decisions cannot flow to the remediation layer (approval item A-1).

### 1.4 Non-functional requirements
- **Zero dependencies**: Python 3.11 or later, standard library only. No third-party dependencies (so that the decision layer itself does not become a supply chain attack surface). Started with `python3 -I -S` (site is not loaded, so `.pth` files in site-packages do not run either)
- **Deterministic**: the same input and the same time (`--now`) give the same output. `plan_id` is given with `--plan-id` or is a UUIDv4
- **Fail-closed**: when any validation or check fails, no output file is written (no partial output: temporary file, then `os.replace`)
- **Both macOS and Linux**

---

## 2. Input and output

### 2.1 Input (contract §2)
`schema_version` / `findings` (the whole ZES findings.json) / `policy` (`deadlines` / `decision_window_days` / `approvers`) / `skillpact_policy` (`l3_trusted`; `diff_anomaly_threshold` / `destructive_requires_human` are reserved).

Input validation:
- `findings` must conform to the ZES [`schemas/findings.schema.json`](https://github.com/kajisho5/zero-exec-shield/blob/main/schemas/findings.schema.json) (`schema_version: "1.0"` fixed)
- `findings.status == "error"` → **rejected** (exit code 3)
- `skillpact_policy.l3_trusted == true` → **rejected** (the contract does not use L3 as a basis for trust; allowing true would need a contract change)
- `skillpact_policy.diff_anomaly_threshold` / `destructive_requires_human` → **rejected** when given (shown as "reserved and not implemented"). Both are in contract §2, but ZET never evaluated them. Accepting a value and silently ignoring it would suggest that a setting is in effect when it is not (for example `destructive_requires_human: true`), so they are no longer required and are rejected when given. Why they were not implemented: the ZES `diff_anomaly` is a boolean, so there is no number to apply a threshold to. For `destructive_requires_human`, ZET cannot tell whether the decision maker is a person or an AI (`decided_by` is only a name), and GER's G-6 already requires two approvals for irreversible operations
- Unknown fields are rejected (strict)

### 2.2 Output (contract §3)
`remediation-plan.json`. ZET owns the schema and publishes `schemas/remediation-plan.schema.json`; GER refers to it with a pinned `schema_version`.

### 2.3 Proposed additions to the contract (approval needed)

| ID | Proposal | Reason |
|---|---|---|
| A-1 | Add `"draft"` to the plan `status` (GER rejects anything other than `ok`) | Keeps drafts from flowing to the remediation layer |
| A-2 | Add `items[].decided_by` | Checking the invariant "an exception needs an `approved_by` **other than the decision maker**" mechanically needs a record of the decision maker. It cannot be checked with the current contract |
| A-3 | Add `items[].level_effective` (for example the value raised to CRITICAL for a SkillPact divergence) | The input `level` must not be changed, so the raised severity is kept in a separate field |
| A-4 | Add `items[].action.reversible` (bool) and `items[].action.skillpact_effects` (array) | GER does not read findings (no skipping layers), so the plan must give GER what it needs to decide "`reversible: false` needs two approvals" and "restrictions on remediating skills that declare exec/network/spend/send (SkillPact 0.8)" |
| A-5 | Optionally add `module` to `held[]` (`finding_id` may be `null`) | A module in `errors[]` may have no findings at all, so a held per finding cannot express "unconfirmed" |
| A-6 | Include `plan_hash` (SHA-256 of the canonical JSON of the plan body) in the output | Binds GER's approval token to the content of the plan and detects replacement after approval (GER design §4) |
| A-7 | `now_override: true` on the plan (optional; a plan made by draft / finalize with `--now`) | Lets GER reject by default a plan made with the test time override (it can have an old or future created_at) |
| A-8 | `items[].action.evidence_hash` (optional; finalize copies the finding's `evidence_hash`) | Lets GER confirm in G-7 that the target file has not changed since detection (ZES rule: SHA-256 of the contents for a regular file of 100 MB or less, SHA-256 of path, size and mtime above 100 MB) |
| A-9 | `items[].skillpact` (optional; summary of the finding's `signed` / `divergence` / `diff_anomaly` / `declared_effects`) | Lets GER recheck I-5 / I-6 / I-7 and the consistency of `skillpact_effects` without reading findings |
| A-10 | Restrict the elements of `action.skillpact_effects` to the 6 SkillPact 0.8 effects (`read` / `write` / `network` / `exec` / `spend` / `send`) | Spelling variants such as `"EXEC"` or `" exec "` must not slip past the G-6 check for risky effects |

A-7 to A-9 are all optional fields, and earlier plans stay valid (backward compatible). Finalized plans of the new ZET contain A-8 / A-9, though, so the receiving GER must also have taken in this version of the schema.

**Limit of the approval token**: `plan_hash` shows only integrity (nothing changed after approval), not authenticity (that ZET made it). If the plan is rewritten after finalize and `plan_hash` is recomputed, this cannot be detected cryptographically (that needs the approvers' signatures; a future task). GER therefore rechecks the invariants that can be evaluated from the plan alone without reading findings (uniqueness for I-1, I-3, the shape and normalization of targets for I-4, consistency with the `skillpact` summary for I-5 / I-6 / I-7, the order of dates for I-9, I-11, part of I-12), and confirms in G-7 that a chmod adds no permission to the current mode (it only narrows).

---

## 3. Decision logic

### 3.1 Automatic processing in the draft (`draft`)
1. **Unconfirmed held**: each module in `findings.errors[]` → `held: {finding_id: null, module, reason: "scan_error:<reason>"}`. The findings of that module go to `held` too (`reason: "module_unconfirmed"`)
2. **Raising the severity**: `skillpact.signed == true` and a non-empty `divergence` → `level_effective = "CRITICAL"`
3. **Deadlines**: `due_at = now + policy.deadlines[level_effective]` days, `recheck_at = now + decision_window_days` days
4. **Restricting the allowed decisions** (noted in the draft as `allowed_decisions`, removed on finalization):
   - non-empty `skillpact.divergence` → no `exception` (only `remediate` / `defer`)
5. **Required approvals**: `skillpact.diff_anomaly == true` → 2 or more in `approved_by`; `exception` → 1 or more (other than the decision maker)
6. `decision` is left empty (it is never decided automatically). Only findings whose `level_effective` is INFO get `defer` + `reason: "informational"` as a default (approval item B-1). An INFO whose target is also handled by another finding's quarantine gets no default (§9)
7. **Remediation suggestions** (0.2): `constraints.suggested_actions` gets `auto` (a GER operation) and `checklist`. autos on the same target are combined with `action.group` (§9)

### 3.2 Invariant checks (`check` / `finalize`)

| # | Check | Basis |
|---|---|---|
| I-1 | Every finding of the input appears **exactly once**, in either `items[]` or `held[]` | Every finding gets a decision |
| I-2 | `items[].finding_id` exists in the input (no made-up ids) | No modification |
| I-3 | `exception` → `exception_type` ∈ {not_affected, fix_unavailable, risk_accepted}, `reason` and `recheck_at` required, `approved_by` ≥ 1 and not including `decided_by` | Contract §4 |
| I-4 | `remediate` → `owner` / `due_at` / `action{type,target}` required. `target` is a normalized absolute path equal to the finding's `path` (a path below it is not allowed: ZET does not know whether `path` is a directory, and with prefix matching a finding pointing at `/` would allow any file). The chmod mode has no special bits and is not world-writable. `reversible` / `skillpact_effects` / `evidence_hash` equal the derived values | Contract §4, no targets outside the plan |
| I-5 | non-empty `skillpact.divergence` → `decision != exception`. `items[].skillpact` matches the input (required in finalized plans) | SkillPact invariant |
| I-6 | `skillpact.diff_anomaly` → 2 or more in `approved_by` (after removing duplicates). `remediate` of a finding of a skill that declares exec / network / spend / send also needs 2 or more (the same as GER's G-6) | Same |
| I-7 | `signed && divergence` → `level_effective == CRITICAL` (`signed` only means that a signature field is present; ZES does not verify signatures) | Same |
| I-8 | Everyone in `approved_by` is in `policy.approvers` | Allow list of approvers |
| I-9 | `due_at ≤ decided_at + deadlines[level_effective]` days | Rejects plans that exceed deadlines |
| I-10 | A held finding is not in `items` (it is not passed to the remediation layer) | Contract §4 |
| I-11 | All timestamps are RFC 3339 UTC (`Z`); no unknown fields | Common contract |
| I-12 | If the input is `partial`, the plan is `partial` too and `held` is not empty | Failure propagation |
| I-13 | The `action.followup` of an automatic remediation contains the required follow-up work determined by the finding (§9.3). Checklists and followups contain all steps of the ZET template unchanged. With findings 1.1, only operations allowed for the `kind`. A lockfile finding (§9.6) gets only a checklist (with the template that contains the regeneration steps) | An automatic remediation is not the end of an incident. A finding that is not cleared automatically is not counted as automatically remediated |

0.2 widened I-4: `target` only has to be linked to the finding's `path` through `action.relation` (§9.2). `relation: none` (target null) is for checklists only. The params of a finalized action must fit GER's `actions.schema.json` (vendored). File-changing items can share a target only within the same `group`. File-changing operations other than chmod need the `plan.scope` derived from the input, and the target must be under it. Targets that need root (`/etc` and so on) need 2 approvers (I-6).

`finalize` writes the plan with `status: "ok"|"partial"` and `plan_hash` only when I-1 to I-13 all pass.

---

## 4. Audit log (append-only)

- Default path: `$ZET_LOG_DIR/zet-audit.jsonl` (default `~/.local/state/zet/`; a separate file from ZES and GER, with its own retention)
- One record per line: `skill` ("zet") / `version` / `command` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator` / `result` (ok/rejected) / `violations` (count)
- The log is opened with `O_APPEND` and the existing file is never truncated before writing. Rejections (violations) are always recorded too
- Proposal (approval item B-2): each record carries the SHA-256 of the previous record (`prev_hash`), a hash chain that makes tampering detectable
- Before appending, the link at the end is checked under an exclusive lock (the last line is a JSON object that ends with a newline, and its `prev_hash` matches the hash of the line before it); when it is broken nothing is appended (the command does nothing and exits with 64). Adding correctly linked records after a broken chain would bury the broken place and make it easy to miss. Earlier versions added a newline after a last line that was cut off and appended; that is rejected too now
- The whole chain is verified with `zet verify-log [LOG]` (read only; not recorded in the audit log)

`operator` must be given with the `--operator` argument (the user name from an environment variable is only a self-declaration, so it must be explicit).

---

## 5. Structure

### 5.1 Directories (updated to match the implementation)
```
zero-exec-triage/
├── SKILL.md                         # procedure for agents (how to make decisions, what is forbidden)
├── bin/zet                          # launcher (resolves the path with bash built-ins only and starts python3 -I -S)
├── zet/
│   ├── __main__.py                  # entry point
│   ├── cli.py                       # argument parsing, exit codes, audit log records
│   ├── triage.py                    # input validation, draft (§3.1), invariants I-1 to I-13 (§3.2), finalization (pure functions)
│   ├── remedy.py                    # finding → remediation mapping, checklist templates, lexical relations (§9)
│   ├── legacy_templates.py          # the earlier Japanese checklist templates, frozen (§9.7)
│   ├── core.py                      # time, canonical JSON, plan_hash, atomic writes
│   ├── audit.py                     # append-only log (hash chain)
│   └── jsonschema_lite.py           # JSON Schema subset validator (standard library)
├── schemas/
│   ├── triage-input.schema.json
│   ├── remediation-plan.schema.json # owned by ZET; GER refers to it with a pinned version
│   └── vendor/{findings*.schema.json, actions.schema.json, VENDOR.json}   # pinned copies from ZES / GER and their SHA-256
├── tests/{run.py, run-tests.sh, test_zet.py, test_remedy.py, fixtures/}
├── docs/design/{design.md, design.ja.md, flow.svg}
├── README.md / README.ja.md
└── CHANGELOG.md
```

### 5.2 Modules and state
ZET completes in one CLI run; the only persistent state is the audit log. Each command is a combination of pure functions `(input, plan, now) -> (output | violations)`, and I/O is confined to `cli.py` and `audit.py`.

### 5.3 Data structures (Python, type hints)
```python
Decision = Literal["remediate", "exception", "defer"]
@dataclass(frozen=True)
class Violation:   code: str; finding_id: str | None; message: str   # code is "I-5" and so on
@dataclass(frozen=True)
class Constraints: allowed: frozenset[Decision]; min_approvers: int; level_effective: str; due_limit: datetime
```

### 5.4 How schema validation is implemented (changed during implementation)
The original plan was to write a separate strict validation next to the schemas. To avoid drift between two definitions, the approach was changed: **the schema files themselves are interpreted by a subset validator written with the standard library (`zet/jsonschema_lite.py`)**. An unsupported keyword in a schema raises an exception. The tests confirm that the results agree with the reference `jsonschema` (development dependency only).

---

## 6. Edge cases

| Case | Handling |
|---|---|
| No findings, `status: ok` | `ok` with empty `items` (normal) |
| `status: partial` and a module in `errors[]` without findings | Recorded in `held` per module (A-5) |
| The same `finding_id` twice in the plan | I-1 violation |
| The same person twice in `approved_by` | Counted after removing duplicates (I-6) |
| An exception whose `decided_by` is in `approved_by` | I-3 violation (self-approval) |
| ZES `schema_version` other than 1.0 | Rejected (pinned version) |
| No `--now` | The real time (UTC). `--now` is for tests only (needs `ZET_ALLOW_NOW_OVERRIDE=1`; the audit log and the output plan get `now_override: true`). The tests always pin `--now` |
| Huge input (tens of thousands of findings) | Linear processing. Duplicate ids are found with a dict in O(n) |

---

## 7. Test policy
- For each invariant at least one pair of "a plan that passes" and "a plan that violates it" (I-1 to I-12: 24 cases or more)
- A round trip `draft → plan filled in by hand → finalize` with real ZES output (generated from the fixtures of PR #1)
- Rejection of `findings.status == "error"`, of `l3_trusted: true` and of unknown fields
- Audit log: records are appended on rejection too, and existing lines never change
- Zero-Exec: `strace -f -e trace=execve` shows no execve other than `python3` (the same method as ZES's `tests/zero-exec.sh`)

---

## 8. Items for approval (summary)

| ID | Content | Recommendation |
|---|---|---|
| A-1 to A-6 | Additions to the contract (§2.3) | Adopt all. On adoption, also revise `docs/skill-contracts.md` on the ZES side |
| B-1 | INFO defaults to `defer` (informational) | Adopt |
| B-2 | Hash chain in the audit log (`prev_hash`) | Adopt |
| B-3 | Implementation language: Python 3.11+ standard library only (ZES is bash + jq) | Adopt (accuracy of date arithmetic and strict validation comes first) |
| B-4 | The `zet` command name and the 4 subcommands | Adopt |


---

## 9. Remediation suggestions and plan 1.1 (GER remediation extension Phase 1)

### 9.1 plan 1.1
- `schema_version: "1.1"` (the output of ZET 0.2. 1.0 plans stay valid; with 1.0 GER runs only chmod)
- `scope: {roots, home}`: the scan scope being approved. Built from `policy.scope` of the triage input (with findings 1.1, `scan_roots` are used as roots). GER's G-9 requires that targets are under it and that the quarantine store is not under roots
- `action`: `relation` (§9.2), `finding_path` (copied by finalize), `group`, `evidence: {kind, hash}` (copied by finalize; with 1.1 the finding's `evidence`, with 1.0 `detail` when `evidence_hash` equals the SHA-256 of detail and `file` otherwise), `followup` (an array of checklists). Only a checklist can have a null `target`. `evidence_hash` is for 1.0 compatibility
- `constraints.suggested_actions[]` (drafts only): `{label: auto|checklist, action, note?}`

### 9.2 Relations (I-4)
`self` / `npm_pkg_dir` / `npm_installed` / `pypi_record` / `ext_dir` / `skill_dir` / `none` (Phase 1). `plist_program` / `preload_lib` / `unit_wants` are Phase 2 and only allowed when they are in the `related` list of findings 1.1 (GER Phase 1 rejects them). The lexical conditions are the same as in GER (`ger/actions/quarantine.py`), and GER checks the same relation again on the file system.

### 9.3 Mapping and required follow-up work (`zet/remedy.py`)
With findings 1.0 the decision uses only `module`, `path` (the basename and the shape of the directories), `level` and `campaign` (`detail` is not parsed: as design 0.2 Q-1 says, that would be fragile and unsafe). See the table in the README for the main mappings. autos on the same target are combined in a group, and a finding whose target (the same file, the directory of a skill, the directory of an extension, a package in node_modules) is handled by another finding's **quarantine** gets a quarantine in the same group suggested (edits do not clear other findings, so they are not combined).

The required follow-up work is the suggestion's `followup` when the suggested operation (type and target) is adopted; for any other automatic remediation it is CL-IR for a finding with a campaign or in a malware trace module (§2 §15 §18 §20 §24 §30 §31 §40 §42). It is not required for chmod and checklist. The templates (CL-PKG, CL-LOCKFILE, CL-VENV, CL-SECRET, CL-IR, CL-LAUNCHD, CL-SYSTEMD, CL-CRON, CL-EXT, CL-MCP, CL-MCP-PIN, CL-SHELL, CL-LDSO, CL-PHP, CL-PHP-RESTART, CL-UPGRADE, CL-PWN, CL-PIN, CL-SKILL, CL-ENV, CL-REVIEW) are a closed table; `{path}` is replaced with the finding's path and `{pkg}` with `subject.package` of findings 1.1 (`<name>` when there is none).

### 9.4 findings 1.1
ZES 0.4.0 outputs findings 1.1. ZET validates findings with `schema_version: "1.1"` with `schemas/vendor/findings-1.1.schema.json` (a copy of the ZES `schemas/findings.schema.json`, pinned in VENDOR.json) and uses the optional `kind` / `subject` / `locators` / `related` / `evidence` / `scan_roots`. 1.0 findings (ZES 0.3.x) are still accepted with `schemas/vendor/findings.schema.json`; 1.0 findings with 1.1 fields are rejected because the schema is strict.

### 9.6 Lockfile findings (I-13)
A lockfile finding (findings 1.1 `kind: pkg.lockfile_compromised`, or §15 with a lockfile name [package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, Gemfile.lock, Cargo.lock, composer.lock, go.sum, poetry.lock, Pipfile.lock, uv.lock, deno.lock]) is not cleared by automatic remediation. ZES reports it from the contents of the lockfile, so after the `node_modules/<name>` next to it (`related: npm_installed`) is quarantined, the rescan shows the same finding again. Fixing the lockfile (removing the dependency, or pinning a safe version and regenerating) is done by the operator or the package manager; GER does not rewrite it.

- The draft suggests no auto for a lockfile finding. The suggestion is a checklist only: CL-LOCKFILE for an npm lockfile (its required steps include "remove the dependency [`npm uninstall <pkg>`] or pin it to a safe version, then regenerate the lockfile"), CL-PKG otherwise. There is no `verify`, so GER never completes it by itself; only the operator's `ger confirm` (self_attested) completes it
- The quarantine of the installed copy (the automatic part) is done by `quarantine npm_pkg_dir` on the `node_modules/<name>/package.json` finding (`pkg.compromised`) that ZES reports separately. ZES reports that finding only when the installed version is the compromised one, so a lockfile-only finding (the installed version is not compromised) gets no quarantine suggestion (it is handled by `npm uninstall` and `npm ls` in CL-LOCKFILE)
- A lockfile finding is never put in the group of another finding's quarantine (in the same group it would be counted as a finding that the quarantine clears)
- I-13: the remediate of a lockfile finding is a checklist only, with the CL-LOCKFILE / CL-PKG template above (all steps included unchanged). quarantine (`npm_installed`) and similar are never finalized. The only operation allowed for `kind: pkg.lockfile_compromised` is checklist as well
- The relation `npm_installed` stays in I-4 and in GER (G-9) (ZET does not use it in suggestions; if a decision maker uses it, I-13 keeps it from being finalized)

With this, the E2E rule "the findings left after apply = the checklist, defer, exception and held items" also holds for lockfile findings (the lockfile-installed fixture: 1 quarantine, 2 checklists, 1 defer; 3 findings after apply).

### 9.5 Flow
`zet draft` → the decision maker adopts suggestions → `ger preview` (GER fills in params from the current files; rejected ones are switched to checklist) → `zet check` / `finalize` → approval → GER.

### 9.7 Language of the checklist texts
The step texts of the templates are English (`zet/remedy.py`). Drafts and finalized plans made by ZET before the English switch contain Japanese texts, so I-13 passes a checklist when every step of its template (same id, same blocking) matches word for word either the English table or the frozen earlier Japanese table (`zet/legacy_templates.py`). One checklist cannot mix the two languages. New drafts are always English. GER checks only the shape of the steps (`id`, `text`, `blocking`) and never compares the wording with the ZET templates, so GER treats plans in either language the same.

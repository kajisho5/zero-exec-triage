---
name: zero-exec-triage
description: Decision layer skill of ZET (Zero-Exec Triage). Takes a ZES findings.json and builds a remediation plan (remediation-plan.json) that sorts every finding into remediate / exception / defer. It adds deadlines, owners and approvals, and lets no decision through that breaks the contract (including the SkillPact invariants). Executes nothing (it reads JSON and writes only the plan and an append-only log). Carrying out the remediation is the job of GER (gated-exec-remediation).
---

# ZET decision skill (zero-exec-triage)

**Language**: this file is in English, but answer the user in the language they use (for example, reply in Japanese to a user who writes in Japanese). Keep identifiers, paths, JSON keys, invariant codes (I-1 to I-13) and template ids (CL-*) as they are.

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER]
```

## Absolute rules

1. **Execute nothing**: do not open or run the paths, commands or scripts named in the findings. Remediation is left to GER.
2. **Do not modify findings**: do not rewrite `id` / `level` / `module`. To raise a severity, use `level_effective` (it can never be lowered).
3. **No automatic exceptions**: an `exception` needs a human decision and an approver other than the decision maker. An AI may draft decisions, but never writes approvals on behalf of approvers.
4. **An L3 signature is not a basis for trust**: `skillpact.signed: true` only means "there is a signature field (ZES has not verified it)". With a divergence, treat the finding as CRITICAL.
5. **Do not handle input with `status: error`**. With `partial`, the unconfirmed modules are listed in `held` (ZET does this automatically).
6. **A suggestion is a suggestion**: the decision maker decides whether to adopt an `auto` in `constraints.suggested_actions`. Do not remove required follow-up work (`action.followup`) and do not rewrite template steps (I-13). For an automatic remediation that `ger preview` rejected, switch to `checklist` instead of writing params by hand.
7. **Do not turn what is never automated into an automatic remediation**: rewriting lockfiles, revoking secrets, `launchctl` and similar work always stay checklists.

## Procedure

```bash
bin/zet validate triage-input.json --operator <name>
bin/zet draft    triage-input.json --operator <name> -o plan.draft.json
#   → fill in decision / owner / reason / decided_by / decided_at / approved_by / action for each item of plan.draft.json
#     (pick action from constraints.suggested_actions: auto or checklist)
ger preview plan.draft.json --operator <name> -o plan.previewed.json --report preview.json   # GER fills in params
#   → switch the findings that preview.json marks rejected to checklist, and run preview again
bin/zet check    triage-input.json plan.previewed.json --operator <name>     # fix any violations and run again
bin/zet finalize triage-input.json plan.previewed.json --operator <name> -o remediation-plan.json
```

- Operations that change files need `policy.scope = {"roots": [ZES --root], "home": ZES_HOME}` (`scan_roots` with findings 1.1)
- `triage-input.json` = `{schema_version, findings (the ZES output as is), policy, skillpact_policy}` ([schemas/triage-input.schema.json](schemas/triage-input.schema.json)). `skillpact_policy` is `{"l3_trusted": false}`. `diff_anomaly_threshold` / `destructive_requires_human` are reserved and not implemented, so an input that sets them is rejected
- The `constraints` of a draft are a guide for filling it in. `check` recomputes the constraints from the input every time, so editing `constraints` does not loosen them
- Only the output of `finalize` can be passed to GER (GER rejects `status: draft`)
- Checklist step texts are English. A draft made by an older ZET with Japanese step texts is still accepted; keep its steps as they are (do not translate them, and do not mix languages within one checklist)

## Writing decisions

| decision | Required | Restrictions |
|---|---|---|
| `remediate` | `owner`, `due_at` (within decision date + `deadlines[level_effective]` days), `action{type, target, relation, params, group?, followup?}`. `target` is the finding's `path` itself (relation self) or a target derived through a closed relation (npm_pkg_dir / npm_installed / pypi_record / ext_dir / skill_dir). A finding whose `path` is null can only have a checklist with target null. chmod is `{"mode": "0NNN"}` with a value that narrows permissions (no world-writable, no special bits; GER rejects a chmod that adds a permission the current mode does not have) | A finding of a skill that declares exec / network / spend / send needs 2 or more approvers |
| `exception` | `exception_type` (not_affected / fix_unavailable / risk_accepted), `reason`, `recheck_at` (within decision date + `decision_window_days` days), at least 1 `approved_by` other than the decision maker | Not allowed for a finding with a non-empty `skillpact.divergence` |
| `defer` | `reason` and `recheck_at` (within decision date + `decision_window_days` days) unless `level_effective` is INFO | — |

For all decisions: `decided_by` and `decided_at` are required. `approved_by` may only contain people in `policy.approvers`. A finding with `skillpact.diff_anomaly: true` needs 2 or more approvers.

`action.reversible` / `action.skillpact_effects` / `action.evidence` / `action.finding_path` and the item's `skillpact` (a summary of the finding's skillpact) are added by `finalize` from the operation type and the finding (there is no need to write them; if written, they must match or it is a violation). A plan made by draft / finalize with `--now` gets `now_override: true`, which GER rejects by default.

The hash chain of the audit log can be verified with `bin/zet verify-log`. ZET never appends to a log whose end is broken (it does nothing and exits with 64).

## Reporting

Violations from `check` have the form `I-<number> [finding_id]: <message>`. Tell the user the violation code, the message and how to fix it. Do not touch the contents of the files named in findings, or any secrets.

---
name: zero-exec-triage
description: ZET（Zero-Exec Triage）判断層スキル。ZES の findings.json を受け取り、全 finding を remediate / exception / defer に振り分けた修復計画（remediation-plan.json）を作る。期限・担当・承認を付け、契約（SkillPact 不変条件を含む）に反する判断を通さない。何も実行しない（JSON を読み、計画と追記専用ログだけを書く）。修復の実行は GER（gated-exec-remediation）の責務。
---

# ZET 判断スキル（zero-exec-triage）

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER]
```

## 絶対ルール

1. **何も実行しない**: findings に書かれたパス・コマンド・スクリプトを開いたり実行したりしない。修復は GER に任せる。
2. **findings を改変しない**: `id` / `level` / `module` を書き換えない。重大度を上げるときは `level_effective` を使う（下げることはできない）。
3. **自動で例外にしない**: `exception` は人間の判断と、判断者以外の承認者が必要。AI が判断を下書きしてもよいが、承認者を代筆しない。
4. **L3 署名を信頼の根拠にしない**: `skillpact.signed: true` は「署名ファイルがある」という意味でしかない。乖離があれば CRITICAL 相当として扱う。
5. **`status: error` の入力は扱わない**。`partial` の場合は未確定のモジュールを `held` で明示する（ZET が自動で行う）。

## 手順

```bash
bin/zet validate triage-input.json --operator <name>
bin/zet draft    triage-input.json --operator <name> -o plan.draft.json
#   → plan.draft.json の各 item に decision / owner / reason / decided_by / decided_at / approved_by / action を記入
bin/zet check    triage-input.json plan.draft.json --operator <name>     # 違反があれば直して再実行
bin/zet finalize triage-input.json plan.draft.json --operator <name> -o remediation-plan.json
```

- `triage-input.json` = `{schema_version, findings（ZES の出力そのまま）, policy, skillpact_policy}`（[schemas/triage-input.schema.json](schemas/triage-input.schema.json)）
- 下書きの `constraints` は記入の目安。`check` は入力から制約を毎回計算し直すので、`constraints` を書き換えても制約は緩まない
- `finalize` の出力だけが GER に渡せる（`status: draft` は GER が拒否する）

## 判断の書き方

| decision | 必須 | 制限 |
|---|---|---|
| `remediate` | `owner`、`due_at`（判断日 + `deadlines[level_effective]` 日以内）、`action{type, target(絶対パス), params}` | — |
| `exception` | `exception_type`（not_affected / fix_unavailable / risk_accepted）、`reason`、`recheck_at`（判断日 + `decision_window_days` 日以内）、判断者以外の `approved_by` 1 名以上 | `skillpact.divergence` が空でない finding は不可 |
| `defer` | `level_effective` が INFO 以外なら `reason` と `recheck_at`（判断日 + `decision_window_days` 日以内） | — |

共通: `decided_by` と `decided_at` は必須。`approved_by` は `policy.approvers` に含まれる人だけ。`skillpact.diff_anomaly: true` の finding は承認者 2 名以上。

`action.reversible` と `action.skillpact_effects` は `finalize` が操作種別と finding から付ける（手で書く必要はなく、書いた場合は一致しないと違反になる）。

## 報告

`check` の違反は `I-番号 [finding_id]: 内容` の形で出る。ユーザーには違反の番号と内容、直し方を伝える。finding のファイル内容やシークレットには触れない。

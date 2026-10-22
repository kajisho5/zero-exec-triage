# ZET（Zero-Exec Triage）詳細設計書 — Step 1

- **版**: 設計 0.1（2026-10-22）／ 実装前レビュー用
- **層**: 判断層（ZES 検知層と GER 修復層の間）
- **原則**: Zero-Exec。ZET は何も実行しない。読むのは JSON だけ、書くのは計画ファイルと追記専用ログだけ
- **上位文書**: [ZES スキル契約書](https://github.com/kajisho5/zero-exec-shield/blob/claude/zes-v5.2-skillpact/docs/skill-contracts.md)（§1〜§4, §8）

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER]
```

---

## 1. 要件定義

### 1.1 目的
ZES の findings を 1 件残らず「直す（remediate）／例外にする（exception）／保留する（defer）」のいずれかに振り分け、期限・担当・承認を付けた **修復計画（remediation-plan.json）** を作る。判断の中身（どれを例外にするか）は人間または AI エージェントが決め、ZET は **契約違反の判断を通さない** ことに責任を持つ。

### 1.2 ZET がやること / やらないこと

| やる | やらない |
|---|---|
| 入力（findings.json＋ポリシー）のスキーマ検証 | findings.json の改変（`id`/`level`/`module` は不変） |
| 下書き計画の生成（期限計算、SkillPact 制約の付与、未確定モジュールの held 化） | ファイル変更・コマンド実行・外部通信 |
| 人間/AI が埋めた計画の不変条件チェック | L3 署名の検証（必要なら人間が別途 `cosign verify`） |
| 追記専用の監査ログ | 修復の実行（GER の責務） |

### 1.3 機能一覧

| コマンド | 入力 | 出力 | 終了コード |
|---|---|---|---|
| `zet validate <triage-input.json>` | 判断層入力（契約 §2） | 検証結果（標準エラー） | 0=OK / 3=契約違反 / 64=引数エラー |
| `zet draft <triage-input.json>` | 同上 | 下書き plan（標準出力、`status` は常に `"draft"` 相当として扱い GER へは渡せない） | 同上 |
| `zet check <triage-input.json> <plan.json>` | 入力＋人間/AI が埋めた plan | 違反一覧 | 0=合格 / 3=違反あり |
| `zet finalize <triage-input.json> <plan.json>` | 同上 | 確定 plan（`check` 合格時のみ書き出し、監査ログ追記） | 0 / 3 |

`finalize` だけが GER に渡せる plan を出す。`draft` の出力は意図的に GER の入力スキーマに通らない形（`status: "draft"`）にし、未判断の計画が修復層へ流れることを防ぐ（要承認 A-1）。

### 1.4 非機能要件
- **依存ゼロ**: Python 3.11 以上の標準ライブラリのみ。サードパーティ依存を持たない（判断層自身がサプライチェーン攻撃面にならないため）。`python3 -I` で起動
- **決定的**: 同じ入力・同じ時刻（`--now`）なら同じ出力。`plan_id` は `--plan-id` 指定か UUIDv4
- **fail-closed**: 検証・チェックのいずれかが失敗したら出力ファイルを書かない（部分出力を残さない。一時ファイル→`os.replace`）
- **macOS / Linux 両対応**

---

## 2. 入出力

### 2.1 入力（契約 §2）
`schema_version` / `findings`（ZES findings.json 全体）/ `policy`（`deadlines` / `decision_window_days` / `approvers`）/ `skillpact_policy`（`l3_trusted` / `diff_anomaly_threshold` / `destructive_requires_human`）。

入力検証:
- `findings` は ZES の [`schemas/findings.schema.json`](https://github.com/kajisho5/zero-exec-shield/blob/claude/zes-v5.2-skillpact/schemas/findings.schema.json)（`schema_version: "1.0"` 固定）に適合すること
- `findings.status == "error"` → **拒否**（終了コード 3）
- `skillpact_policy.l3_trusted == true` → **拒否**（契約上 L3 を信頼根拠にしないため。true を許すのは契約改定が必要）
- 未知フィールドは拒否（strict）

### 2.2 出力（契約 §3）
`remediation-plan.json`。ZET がスキーマの所有者として `schemas/remediation-plan.schema.json` を公開し、GER は `schema_version` を固定して参照する。

### 2.3 契約への追加提案（要承認）

| ID | 提案 | 理由 |
|---|---|---|
| A-1 | plan の `status` に `"draft"` を追加（GER は `ok` 以外拒否） | 下書きが修復層へ流れるのを防ぐ |
| A-2 | `items[].decided_by` を追加 | 不変条件「exception は **判断者以外** の `approved_by`」を機械的に検査するには判断者の記録が必要。現契約では検査不能 |
| A-3 | `items[].level_effective` を追加（例: SkillPact 乖離で CRITICAL 相当に引き上げた値） | 入力の `level` は改変禁止のため、引き上げ後の重大度を別フィールドで持つ |
| A-4 | `items[].action.reversible`（bool）と `items[].action.skillpact_effects`（配列）を追加 | GER は findings を読まない（飛び越し禁止）ため、「`reversible: false` は二重承認」「exec/network/secrets 宣言スキルの修復制限」を GER が判定する材料を plan で渡す必要がある |
| A-5 | `held[]` に `module` を任意で追加（`finding_id` は `null` 可） | `errors[]` のモジュールは finding が 0 件のこともあり、finding 単位の held では「未確定」を表現できない |
| A-6 | `plan_hash`（plan 本体の正規化 JSON の SHA-256）を出力に含める | GER の承認トークンを plan 内容に束縛し、承認後の差し替えを検出するため（GER 設計書 §4） |

---

## 3. 判断ロジック

### 3.1 下書き（`draft`）の自動処理
1. **未確定の held**: `findings.errors[]` の各モジュール → `held: {finding_id: null, module, reason: "scan_error:<reason>"}`。そのモジュールの finding も `held`（`reason: "module_unconfirmed"`）
2. **重大度の引き上げ**: `skillpact.signed == true` かつ `divergence` 非空 → `level_effective = "CRITICAL"`
3. **期限**: `due_at = now + policy.deadlines[level_effective]` 日、`recheck_at = now + decision_window_days` 日
4. **選べる判断の制限**（下書きに `allowed_decisions` として注記、確定時には除去）:
   - `skillpact.divergence` 非空 → `exception` 不可（`remediate` / `defer` のみ）
5. **必要承認数**: `skillpact.diff_anomaly == true` → `approved_by` 2 名以上、`exception` → 1 名以上（判断者以外）
6. `decision` は空のまま出す（自動で決めない）。INFO の finding だけは `defer`＋`reason: "informational"` を既定値として入れる（要承認 B-1）

### 3.2 不変条件チェック（`check` / `finalize`）

| # | 検査 | 根拠 |
|---|---|---|
| I-1 | 入力の全 finding が `items[]` か `held[]` のどちらか一方に **ちょうど 1 回** 現れる | 全 finding に判断付与 |
| I-2 | `items[].finding_id` が入力に存在する（架空 ID 禁止） | 改変禁止 |
| I-3 | `exception` → `exception_type` ∈ {not_affected, fix_unavailable, risk_accepted}、`reason`・`recheck_at` 必須、`approved_by` ≥1 かつ `decided_by` を含まない | 契約 §4 |
| I-4 | `remediate` → `owner` / `due_at` / `action{type,target}` 必須、`target` は絶対パス | 契約 §4 |
| I-5 | `skillpact.divergence` 非空 → `decision != exception` | SkillPact 不変条件 |
| I-6 | `skillpact.diff_anomaly` → `approved_by` 2 名以上（重複除去後） | 同上 |
| I-7 | `signed && divergence` → `level_effective == CRITICAL` | 同上 |
| I-8 | `approved_by` は全員 `policy.approvers` に含まれる | 承認者の許可リスト |
| I-9 | `due_at ≤ decided_at + deadlines[level_effective]` 日 | 期限超過の計画を拒否 |
| I-10 | `held` の finding は `items` に入らない（修復層へ渡さない） | 契約 §4 |
| I-11 | タイムスタンプはすべて RFC 3339 UTC（`Z`）、未知フィールドなし | 共通契約 |
| I-12 | 入力が `partial` なら plan も `partial` かつ `held` 非空 | 失敗の伝播 |

`finalize` は I-1〜I-12 がすべて合格した場合のみ、`status: "ok"|"partial"` の plan と `plan_hash` を書き出す。

---

## 4. 監査ログ（追記専用）

- 既定パス: `$ZET_LOG_DIR/zet-audit.jsonl`（既定 `~/.local/state/zet/`、ZES・GER とは別ファイル・別リテンション）
- 1 行 1 レコード: `skill`（"zet"）/ `version` / `command` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator` / `result`（ok/rejected）/ `violations`（件数）
- 追記は `O_APPEND` で開き、書き込み前に既存ファイルを切り詰めない。拒否（違反）も必ず記録する
- 提案（要承認 B-2）: 各レコードに直前レコードの SHA-256（`prev_hash`）を持たせるハッシュチェーンで改ざん検出を可能にする

`operator` は `--operator` 引数で必須指定（環境変数のユーザー名は自己申告にすぎないため、明示させる）。

---

## 5. 構成

### 5.1 ディレクトリ
```
zero-exec-triage/
├── SKILL.md                         # エージェント向け手順（判断の進め方、禁止事項）
├── zet                              # 起動スクリプト（python3 -I で zet/cli.py を実行）
├── zet/
│   ├── cli.py                       # 引数解析、終了コード
│   ├── validate.py                  # strict スキーマ検証（標準ライブラリで実装）
│   ├── draft.py                     # 下書き生成（§3.1）
│   ├── invariants.py                # 不変条件 I-1〜I-12（§3.2）
│   ├── audit.py                     # 追記専用ログ
│   └── timeutil.py                  # RFC 3339 / 期限計算
├── schemas/
│   ├── triage-input.schema.json     # ZET が受け取る形（findings は ZES スキーマを $ref）
│   ├── remediation-plan.schema.json # ZET が所有。GER が版固定で参照
│   └── vendor/findings.schema.json  # ZES から版固定で取り込んだ写し（SHA-256 を記録）
├── tests/
│   ├── fixtures/                    # ZES の実出力サンプル（ok / partial / error / SkillPact 各種）
│   ├── test_validate.py / test_draft.py / test_invariants.py / test_audit.py
│   └── run-tests.sh
├── docs/design/{design.md, flow.svg}
├── README.md
└── CHANGELOG.md
```

### 5.2 モジュール分割と状態
ZET は CLI 1 回の実行で完結し、永続状態は監査ログのみ。各コマンドは純粋関数 `(input, plan, now) -> (output | violations)` の組み合わせで実装し、I/O は `cli.py` と `audit.py` に閉じ込める。

### 5.3 データ構造（Python, 型ヒント）
```python
Decision = Literal["remediate", "exception", "defer"]
@dataclass(frozen=True)
class Violation:   code: str; finding_id: str | None; message: str   # code は "I-5" 等
@dataclass(frozen=True)
class Constraints: allowed: frozenset[Decision]; min_approvers: int; level_effective: str; due_limit: datetime
```

### 5.4 スキーマ検証の実装方針
実行時は標準ライブラリの自前 strict 検証（必須キー・型・列挙・パターン・未知キー拒否）を使う。テストでは `jsonschema`（開発依存のみ）で **自前検証と JSON Schema の判定が一致すること** を全フィクスチャで確認し、二重定義のずれを防ぐ。

---

## 6. エッジケース

| ケース | 扱い |
|---|---|
| findings が 0 件・`status: ok` | 空の `items` で `ok`（正常） |
| `status: partial` で `errors[]` のモジュールに finding が無い | `held` にモジュール単位で記録（A-5） |
| 同一 `finding_id` が plan に 2 回 | I-1 違反 |
| `approved_by` に同一人物が重複 | 重複除去後に人数判定（I-6） |
| `decided_by` が `approved_by` に含まれる exception | I-3 違反（自己承認） |
| ZES の `schema_version` が 1.0 以外 | 拒否（版固定） |
| `--now` 未指定 | 実時刻（UTC）。テストは常に `--now` 固定 |
| 巨大入力（数万件） | 線形処理。ID の重複検出は dict で O(n) |

---

## 7. テスト方針
- 不変条件ごとに「合格する plan」「違反する plan」を最低 1 組（I-1〜I-12 ＝ 24 ケース以上）
- ZES の実出力（PR #1 のフィクスチャから生成）で `draft → 人手で埋めた plan → finalize` の往復
- `findings.status == "error"` 拒否、`l3_trusted: true` 拒否、未知フィールド拒否
- 監査ログ: 拒否時も追記される、既存行が変わらない
- Zero-Exec: `strace -f -e trace=execve` で `python3` 以外の execve が 0 件（ZES の `tests/zero-exec.sh` と同じ方式）

---

## 8. 要承認事項（まとめ）

| ID | 内容 | 推奨 |
|---|---|---|
| A-1〜A-6 | 契約への追加（§2.3） | すべて採用。採用時は ZES 側 `docs/skill-contracts.md` も改定 |
| B-1 | INFO は既定で `defer`（informational） | 採用 |
| B-2 | 監査ログのハッシュチェーン（`prev_hash`） | 採用 |
| B-3 | 実装言語を Python 3.11+ 標準ライブラリのみとする（ZES は bash+jq） | 採用（日付計算・strict 検証の正確さを優先） |
| B-4 | `zet` コマンド名と 4 サブコマンド構成 | 採用 |

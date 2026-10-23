# ZET（Zero-Exec Triage）詳細設計書 — Step 1

- **版**: 設計 0.1（2026-10-22）／ 2026-10-22 承認（A-1〜A-6・B-1〜B-4 を採用）、実装 0.1.0
- **追補**: GER 修復能力拡張 設計 0.2（2026-10-23 承認。Q-1〜Q-6 を推奨どおり採用）の Phase 1 に合わせた判断層の変更（plan 1.1、提案、I-4 の関係、I-13）を §9 に記す
- **層**: 判断層（ZES 検知層と GER 修復層の間）
- **原則**: Zero-Exec。ZET は何も実行しない。読むのは JSON だけ、書くのは計画ファイルと追記専用ログだけ
- **上位文書**: [ZES スキル契約書](https://github.com/kajisho5/zero-exec-shield/blob/main/docs/skill-contracts.md)（§1〜§4, §8）

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
| `zet verify-log [LOG]` | 監査ログ（既定 `$ZET_LOG_DIR/zet-audit.jsonl`） | ハッシュチェーンの検証結果（標準エラー。この実行は記録しない） | 0=健全 / 3=破損 / 64=ログが無い・読めない |

`finalize` だけが GER に渡せる plan を出す。`draft` の出力は意図的に GER の入力スキーマに通らない形（`status: "draft"`）にし、未判断の計画が修復層へ流れることを防ぐ（要承認 A-1）。

### 1.4 非機能要件
- **依存ゼロ**: Python 3.11 以上の標準ライブラリのみ。サードパーティ依存を持たない（判断層自身がサプライチェーン攻撃面にならないため）。`python3 -I -S` で起動（site を読み込まないので site-packages の `.pth` も実行されない）
- **決定的**: 同じ入力・同じ時刻（`--now`）なら同じ出力。`plan_id` は `--plan-id` 指定か UUIDv4
- **fail-closed**: 検証・チェックのいずれかが失敗したら出力ファイルを書かない（部分出力を残さない。一時ファイル→`os.replace`）
- **macOS / Linux 両対応**

---

## 2. 入出力

### 2.1 入力（契約 §2）
`schema_version` / `findings`（ZES findings.json 全体）/ `policy`（`deadlines` / `decision_window_days` / `approvers`）/ `skillpact_policy`（`l3_trusted`。`diff_anomaly_threshold` / `destructive_requires_human` は予約）。

入力検証:
- `findings` は ZES の [`schemas/findings.schema.json`](https://github.com/kajisho5/zero-exec-shield/blob/main/schemas/findings.schema.json)（`schema_version: "1.0"` 固定）に適合すること
- `findings.status == "error"` → **拒否**（終了コード 3）
- `skillpact_policy.l3_trusted == true` → **拒否**（契約上 L3 を信頼根拠にしないため。true を許すのは契約改定が必要）
- `skillpact_policy.diff_anomaly_threshold` / `destructive_requires_human` → 指定されたら **拒否**（「予約済みで未実装」と表示）。どちらも契約 §2 にあるが、ZET は評価していなかった。受け取って黙って無視すると、効いていない設定（例: `destructive_requires_human: true`）を効いていると誤解させるため、必須から外し、指定を拒否する。実装しなかった理由: ZES の `diff_anomaly` は真偽値でしきい値を当てる数値が無い。`destructive_requires_human` は判断者が人間か AI かを ZET が区別できず（`decided_by` は名前だけ）、不可逆操作の二重承認は GER の G-6 が既に課している
- 未知フィールドは拒否（strict）

### 2.2 出力（契約 §3）
`remediation-plan.json`。ZET がスキーマの所有者として `schemas/remediation-plan.schema.json` を公開し、GER は `schema_version` を固定して参照する。

### 2.3 契約への追加提案（要承認）

| ID | 提案 | 理由 |
|---|---|---|
| A-1 | plan の `status` に `"draft"` を追加（GER は `ok` 以外拒否） | 下書きが修復層へ流れるのを防ぐ |
| A-2 | `items[].decided_by` を追加 | 不変条件「exception は **判断者以外** の `approved_by`」を機械的に検査するには判断者の記録が必要。現契約では検査不能 |
| A-3 | `items[].level_effective` を追加（例: SkillPact 乖離で CRITICAL 相当に引き上げた値） | 入力の `level` は改変禁止のため、引き上げ後の重大度を別フィールドで持つ |
| A-4 | `items[].action.reversible`（bool）と `items[].action.skillpact_effects`（配列）を追加 | GER は findings を読まない（飛び越し禁止）ため、「`reversible: false` は二重承認」「exec/network/spend/send（SkillPact 0.8）宣言スキルの修復制限」を GER が判定する材料を plan で渡す必要がある |
| A-5 | `held[]` に `module` を任意で追加（`finding_id` は `null` 可） | `errors[]` のモジュールは finding が 0 件のこともあり、finding 単位の held では「未確定」を表現できない |
| A-6 | `plan_hash`（plan 本体の正規化 JSON の SHA-256）を出力に含める | GER の承認トークンを plan 内容に束縛し、承認後の差し替えを検出するため（GER 設計書 §4） |
| A-7 | plan に `now_override: true`（任意。`--now` で draft / finalize した plan） | テスト用の時刻上書きで作った計画（古い・未来の created_at を持ちうる）を GER が既定で拒否できるようにする |
| A-8 | `items[].action.evidence_hash`（任意。finalize で finding の `evidence_hash` を写す） | GER が G-7 で、検知時から対象ファイルが変わっていないことを確かめる（ZES の規則: 100MB 以下の通常ファイルは内容の SHA-256、100MB 超はパス・サイズ・mtime の SHA-256） |
| A-9 | `items[].skillpact`（任意。finding の `signed` / `divergence` / `diff_anomaly` / `declared_effects` の要約） | GER が findings を読まずに I-5 / I-6 / I-7 と `skillpact_effects` の整合を再検査するため |
| A-10 | `action.skillpact_effects` の要素を SkillPact 0.8 の 6 効果（`read` / `write` / `network` / `exec` / `spend` / `send`）に限定 | `"EXEC"` や `" exec "` のような表記揺れで G-6 の危険な効果の判定をすり抜けさせない |

A-7〜A-9 はいずれも任意のフィールドで、従来の plan はそのまま有効（後方互換）。ただし新しい ZET の確定 plan は A-8 / A-9 を含むため、受け取る GER もこの版のスキーマを取り込んでいる必要がある。

**承認トークンの限界**: `plan_hash` は完全性（承認後に変わっていないこと）だけを示し、真正性（ZET が作ったこと）は示さない。finalize 後に plan を書き換えて `plan_hash` を計算し直すと暗号的には検出できない（承認者の署名が必要。将来の課題）。そのため GER は、findings を読まずに plan だけで評価できる不変条件（I-1 の一意性、I-3、I-4 の形と対象の正規化、I-5 / I-6 / I-7 の `skillpact` 要約との整合、I-9 の日付の前後関係、I-11、I-12 の一部）を再検査し、chmod は現在の mode に権限を足さない（絞るだけ）ことを G-7 で確かめる。

---

## 3. 判断ロジック

### 3.1 下書き（`draft`）の自動処理
1. **未確定の held**: `findings.errors[]` の各モジュール → `held: {finding_id: null, module, reason: "scan_error:<reason>"}`。そのモジュールの finding も `held`（`reason: "module_unconfirmed"`）
2. **重大度の引き上げ**: `skillpact.signed == true` かつ `divergence` 非空 → `level_effective = "CRITICAL"`
3. **期限**: `due_at = now + policy.deadlines[level_effective]` 日、`recheck_at = now + decision_window_days` 日
4. **選べる判断の制限**（下書きに `allowed_decisions` として注記、確定時には除去）:
   - `skillpact.divergence` 非空 → `exception` 不可（`remediate` / `defer` のみ）
5. **必要承認数**: `skillpact.diff_anomaly == true` → `approved_by` 2 名以上、`exception` → 1 名以上（判断者以外）
6. `decision` は空のまま出す（自動で決めない）。`level_effective` が INFO の finding だけは `defer`＋`reason: "informational"` を既定値として入れる（要承認 B-1）。ただし他の finding の quarantine が同じ対象を扱う INFO は既定値を入れない（§9）
7. **修復の提案**（0.2）: `constraints.suggested_actions` に `auto`（GER の操作）と `checklist` を付ける。同じ対象の auto は `action.group` でまとめる（§9）

### 3.2 不変条件チェック（`check` / `finalize`）

| # | 検査 | 根拠 |
|---|---|---|
| I-1 | 入力の全 finding が `items[]` か `held[]` のどちらか一方に **ちょうど 1 回** 現れる | 全 finding に判断付与 |
| I-2 | `items[].finding_id` が入力に存在する（架空 ID 禁止） | 改変禁止 |
| I-3 | `exception` → `exception_type` ∈ {not_affected, fix_unavailable, risk_accepted}、`reason`・`recheck_at` 必須、`approved_by` ≥1 かつ `decided_by` を含まない | 契約 §4 |
| I-4 | `remediate` → `owner` / `due_at` / `action{type,target}` 必須。`target` は正規化済みの絶対パスで、finding の `path` と一致（配下のパスは不可。ZET は `path` がディレクトリかを知らず、前方一致では `/` を指す finding が任意のファイルを許してしまう）。chmod の mode は特殊ビット・world-writable 不可。`reversible` / `skillpact_effects` / `evidence_hash` は導出値と一致 | 契約 §4、計画外の対象の禁止 |
| I-5 | `skillpact.divergence` 非空 → `decision != exception`。`items[].skillpact` は入力と一致（確定 plan では必須） | SkillPact 不変条件 |
| I-6 | `skillpact.diff_anomaly` → `approved_by` 2 名以上（重複除去後）。exec / network / spend / send を宣言したスキルの finding の `remediate` も 2 名以上（GER の G-6 と同じ） | 同上 |
| I-7 | `signed && divergence` → `level_effective == CRITICAL`（`signed` は署名フィールドがあることだけを表し、ZES は署名を検証しない） | 同上 |
| I-8 | `approved_by` は全員 `policy.approvers` に含まれる | 承認者の許可リスト |
| I-9 | `due_at ≤ decided_at + deadlines[level_effective]` 日 | 期限超過の計画を拒否 |
| I-10 | `held` の finding は `items` に入らない（修復層へ渡さない） | 契約 §4 |
| I-11 | タイムスタンプはすべて RFC 3339 UTC（`Z`）、未知フィールドなし | 共通契約 |
| I-12 | 入力が `partial` なら plan も `partial` かつ `held` 非空 | 失敗の伝播 |
| I-13 | 自動修復の `action.followup` に、finding から決まる必須の後続作業（§9.3）がある。checklist と followup は ZET の雛形の手順をすべて変えずに含む。findings 1.1 では `kind` に許された操作だけ | 自動修復はインシデントの終わりではない |

0.2 で I-4 を広げた: `target` は `action.relation`（§9.2）で finding の `path` と結びつけばよい。`relation: none`（target null）は checklist だけ。確定した action の params は GER の `actions.schema.json`（vendor）に合うこと。ファイルを変える item が同じ対象を持てるのは同じ `group` のときだけ。chmod 以外のファイルを変える操作には入力から導いた `plan.scope` が必要で、対象はその下。root が必要な対象（`/etc` など）は承認者 2 名（I-6）。

`finalize` は I-1〜I-13 がすべて合格した場合のみ、`status: "ok"|"partial"` の plan と `plan_hash` を書き出す。

---

## 4. 監査ログ（追記専用）

- 既定パス: `$ZET_LOG_DIR/zet-audit.jsonl`（既定 `~/.local/state/zet/`、ZES・GER とは別ファイル・別リテンション）
- 1 行 1 レコード: `skill`（"zet"）/ `version` / `command` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator` / `result`（ok/rejected）/ `violations`（件数）
- 追記は `O_APPEND` で開き、書き込み前に既存ファイルを切り詰めない。拒否（違反）も必ず記録する
- 提案（要承認 B-2）: 各レコードに直前レコードの SHA-256（`prev_hash`）を持たせるハッシュチェーンで改ざん検出を可能にする
- 追記の前に、排他ロックの下で末尾の連結（最終行が改行で終わる JSON object で、`prev_hash` が直前の行のハッシュと一致すること）を確かめ、壊れていれば追記しない（コマンドは何もせず終了コード 64）。壊れたチェーンの後ろに正しい連結の記録を足すと、破損箇所が埋もれて見落とされやすくなるため。以前は途中で切れた最終行の後ろに改行を補って追記していたが、それも拒否する
- 全体の検証は `zet verify-log [LOG]`（読み取りのみ。監査ログには記録しない）

`operator` は `--operator` 引数で必須指定（環境変数のユーザー名は自己申告にすぎないため、明示させる）。

---

## 5. 構成

### 5.1 ディレクトリ（実装に合わせて更新）
```
zero-exec-triage/
├── SKILL.md                         # エージェント向け手順（判断の進め方、禁止事項）
├── bin/zet                          # 起動スクリプト（bash 組み込みのみでパス解決し python3 -I -S で起動）
├── zet/
│   ├── __main__.py                  # エントリポイント
│   ├── cli.py                       # 引数解析、終了コード、監査ログ記録
│   ├── triage.py                    # 入力検証・下書き（§3.1）・不変条件 I-1〜I-12（§3.2）・確定（純粋関数）
│   ├── core.py                      # 時刻、正規化 JSON、plan_hash、原子的書き出し
│   ├── audit.py                     # 追記専用ログ（ハッシュチェーン）
│   └── jsonschema_lite.py           # JSON Schema サブセット検証器（標準ライブラリ）
├── schemas/
│   ├── triage-input.schema.json
│   ├── remediation-plan.schema.json # ZET が所有。GER が版固定で参照
│   └── vendor/{findings.schema.json, VENDOR.json}   # ZES からの版固定の写しと SHA-256
├── tests/{run.py, run-tests.sh, test_zet.py, fixtures/}
├── docs/design/{design.md, flow.svg}
├── README.md / README.ja.md
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

### 5.4 スキーマ検証の実装方針（実装時に変更）
当初は「スキーマとは別に自前の strict 検証を書く」方針だったが、二重定義のずれを避けるため、**スキーマファイルそのものを標準ライブラリ製のサブセット検証器（`zet/jsonschema_lite.py`）で解釈する**方式に変えた。未対応キーワードがスキーマに現れた場合は例外にする。テストでは公式 `jsonschema`（開発依存のみ）と判定が一致することを確認する。

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
| `--now` 未指定 | 実時刻（UTC）。`--now` はテスト専用（`ZET_ALLOW_NOW_OVERRIDE=1` が必要、監査ログと出力する plan に `now_override: true`）。テストは常に `--now` 固定 |
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


---

## 9. 修復の提案と plan 1.1（GER 修復能力拡張 Phase 1）

### 9.1 plan 1.1
- `schema_version: "1.1"`（ZET 0.2 の出力。1.0 の計画も有効で、GER は 1.0 では chmod だけを実行する）
- `scope: {roots, home}`: 承認する検査範囲。triage-input の `policy.scope`（findings 1.1 では `scan_roots` を roots に使う）から作る。GER の G-9 は対象がこの下にあることと、隔離ストアが roots の下に無いことを求める
- `action`: `relation`（§9.2）、`finding_path`（finalize が写す）、`group`、`evidence: {kind, hash}`（finalize が写す。1.1 は finding の `evidence`、1.0 は `evidence_hash` が detail の SHA-256 と一致すれば `detail`、そうでなければ `file`）、`followup`（チェックリストの配列）。`target` は checklist だけ null にできる。`evidence_hash` は 1.0 の互換用
- `constraints.suggested_actions[]`（draft だけ）: `{label: auto|checklist, action, note?}`

### 9.2 関係（I-4）
`self` / `npm_pkg_dir` / `npm_installed` / `pypi_record` / `ext_dir` / `skill_dir` / `none`（Phase 1）。`plist_program` / `preload_lib` / `unit_wants` は Phase 2 で、findings 1.1 の `related` にあるときだけ（GER Phase 1 は拒否する）。字句上の条件は GER（`ger/actions/quarantine.py`）と同じで、GER は同じ関係をファイルシステムで確かめ直す。

### 9.3 対応表と必須の後続作業（`zet/remedy.py`）
findings 1.0 では `module`・`path`（basename とディレクトリの形）・`level`・`campaign` だけで判断する（`detail` は解析しない。設計 0.2 Q-1 のとおり壊れやすく安全でないため）。主な対応は README の表を参照。同じ対象への auto は group にまとめ、他の finding の **quarantine** が同じ対象（同じファイル、スキルのディレクトリ、拡張機能のディレクトリ、node_modules のパッケージ）を扱う finding には同じ group の quarantine を提案する（編集は他の finding を消さないのでまとめない）。

必須の後続作業は、提案と同じ操作（type と target）を採用した場合は提案の `followup`、それ以外の自動修復では、campaign のある finding・マルウェアの痕跡のモジュール（§2 §15 §18 §20 §24 §30 §31 §40 §42）なら CL-IR。chmod と checklist には求めない。雛形（CL-PKG・CL-VENV・CL-SECRET・CL-IR・CL-LAUNCHD・CL-SYSTEMD・CL-CRON・CL-EXT・CL-MCP・CL-MCP-PIN・CL-SHELL・CL-LDSO・CL-PHP・CL-PHP-RESTART・CL-UPGRADE・CL-PWN・CL-PIN・CL-SKILL・CL-ENV・CL-REVIEW）は閉じた表で、`{path}` だけを finding の path に置き換える。

### 9.4 findings 1.1
ZES 0.4.0 は findings 1.1 を出す。ZET は `schema_version: "1.1"` の findings を `schemas/vendor/findings-1.1.schema.json`（ZES の `schemas/findings.schema.json` の写し。VENDOR.json に版固定）で検証し、任意の `kind` / `subject` / `locators` / `related` / `evidence` / `scan_roots` を使う。1.0 の findings（ZES 0.3.x）も引き続き `schemas/vendor/findings.schema.json` で受け付け、1.0 の findings に 1.1 の項目があれば strict のため拒否する。

### 9.5 流れ
`zet draft` → 判断者が提案を採用 → `ger preview`（GER が現在のファイルから params を埋める。拒否は checklist に切り替える）→ `zet check` / `finalize` → 承認 → GER。

# Changelog

## Unreleased

### Round 6 fixes

- **A `{pkg}` inside a path was rewritten in step texts.** The templates were filled with `replace("{path}", path).replace("{pkg}", pkg)`, so a scanned path such as `root/{pkg}/.mcp.json` became `root/<name>/.mcp.json` (or the package name of a finding with `subject.package`) in the CL-IR / CL-REVIEW / CL-MCP steps: the operator's checklist named a path that does not exist, or another one. The long-path branch already filled the template in one pass, so the two branches also disagreed. Filling is now a single pass over the template's placeholders in both branches (a placeholder inside a substituted value stays literal), and I-13 rebuilds the text with the same function. A plan made by an earlier ZET for such a path (with the rewritten text) no longer matches its template and is reported by I-13.

### 日本語（round 6 の修正）

- **パスに含まれる `{pkg}` が手順の文で書き換えられていた。** 雛形を `replace("{path}", path).replace("{pkg}", pkg)` で埋めていたため、`root/{pkg}/.mcp.json` のようなスキャン対象のパスが CL-IR / CL-REVIEW / CL-MCP の手順で `root/<name>/.mcp.json`（`subject.package` のある finding ではそのパッケージ名）になり、チェックリストが存在しないパスや別のパスを示していた。長いパスの分岐はもともと 1 回で埋めていたため、2 つの分岐の結果も食い違っていた。どちらの分岐も雛形の置き換え箇所を 1 回の走査で埋めるようにし（置き換えた値の中の置き換え記号はそのまま残る）、I-13 も同じ関数で文を組み立て直す。以前の ZET がこのようなパスで作った計画（書き換わった文）は雛形と一致しなくなり、I-13 で報告される

### Round 5 fixes

- **Plans that GER always rejects were finalized when a path was long.** Templates such as CL-IR put the finding's path into a step text, and GER accepts step texts of 1 to 2000 characters (G-1 rejects the whole plan). ZET checked checklist `params` against GER's `actions.schema.json` but not `followup`, so a `.mcp.json` at a 2014-character path (legal: PATH_MAX is 4096) gave a CL-IR step of 2147 characters that passed `zet check` and `finalize`; for a checklist with `{path}` (for example CL-PIN for a `§22` finding) the draft's own suggestion failed ZET's own check. Now a filled-in step that would exceed 2000 characters keeps only the end of each value (the file name) behind `…`, so the step fits; the rule is fixed, so I-13 still compares the whole text with the template. I-4 checks every `followup` with GER's checklist step rules, in drafts too.
- **A dangerous MCP server in `.claude/settings.json` got `edit_json select claude.hook`**, which removed an unrelated hook (for example `node .claude/format.mjs`) while the server stayed. GER has no hazard table entry for MCP servers in that file, so an `mcp.*` finding (`mcp.dangerous_command` / `mcp.unpinned`) there now gets a checklist (CL-REVIEW / CL-MCP-PIN) with a note, and I-13 refuses `edit_json` / `edit_toml` / `disable_mcp_server` for an `mcp.*` finding outside the files whose MCP servers GER can remove. Hook findings in the same file still get the hook edit.
- **`zet check` / `finalize` crashed (exit 70) on malformed checklist steps** (a string step, `steps` that is not a list, a list or object as `blocking` / `id`, an object as `template`). The template comparison ignores malformed steps now, so these are I-4 (GER's step rules) and I-13 violations. A lone surrogate in a string of a plan or triage input passed to the Python API is I-11 rather than an encoding error (files with one were already refused when read).

### 日本語（round 5 の修正）

- **パスが長いと、GER が必ず拒否する計画を確定していた。** CL-IR などの雛形は手順の文に finding の path を入れ、GER は 1〜2000 文字の文しか受け付けない（G-1 で計画全体を拒否）。ZET はチェックリストの `params` を GER の `actions.schema.json` で確かめていたが `followup` は確かめておらず、2014 文字のパス（PATH_MAX は 4096 なので有効）の `.mcp.json` で 2147 文字の CL-IR の手順ができ、`zet check` と `finalize` を通っていた。`{path}` を含むチェックリスト（たとえば `§22` の finding の CL-PIN）では、draft 自身の提案が ZET 自身の検査に通らなかった。値を入れた手順が 2000 文字を超える場合は、それぞれの値を末尾（ファイル名）だけ残して `…` の後ろに置き、手順を上限に収める。決まった規則なので、I-13 は引き続き文全体を雛形と比べる。I-4 はすべての `followup` を、draft でも、GER のチェックリストの手順の規則で確かめる
- **`.claude/settings.json` の危険な MCP サーバーに `edit_json select claude.hook` を提案していた。** そのため無関係なフック（たとえば `node .claude/format.mjs`）が取り除かれ、サーバーは残っていた。GER の危険パターンの表にはこのファイルの MCP サーバーの項目が無いため、ここでの `mcp.*` の finding（`mcp.dangerous_command` / `mcp.unpinned`）には注記付きのチェックリスト（CL-REVIEW / CL-MCP-PIN）を提案し、GER が MCP サーバーを取り除けるファイル以外での `mcp.*` の finding への `edit_json` / `edit_toml` / `disable_mcp_server` を I-13 で拒否する。同じファイルのフックの finding にはこれまでどおりフックの編集を提案する
- **形の崩れたチェックリストの手順で `zet check` / `finalize` が落ちていた**（終了コード 70。文字列の手順、リストでない `steps`、`blocking` / `id` がリストかオブジェクト、`template` がオブジェクト）。雛形との比較は崩れた手順を無視するようにしたので、これらは I-4（GER の手順の規則）と I-13 の違反になる。Python の API に渡した計画・triage の入力の文字列に対になっていないサロゲートがあれば、エンコードのエラーではなく I-11 にする（そうしたファイルは読み込みの時点で以前から拒否していた）

### English-first

ZET is now English-first, like ZES 0.5.0. Behavior does not change apart from the language of human-readable text.

- **Output**: violation messages of `validate` / `check` / `finalize`, CLI messages and `--help`, audit log errors, `verify-log` results, suggestion notes and the step texts of all 21 checklist templates (CL-*) are English. Machine codes are unchanged: invariant codes (I-1 to I-13, SP), template ids (CL-*), step ids (`s1`, …), `blocking`, JSON keys and enum values. Messages that show a count use the form "contract violations: 3"
- **Compatibility of checklist texts (I-13)**: I-13 compares the steps of each checklist and followup with its template word for word. Drafts and finalized plans made by an earlier ZET contain the Japanese step texts, so the earlier Japanese templates are kept frozen in `zet/legacy_templates.py`, and a checklist passes when every step of its template matches either the English or the Japanese text (one language per checklist). Such drafts can still be finalized and such plans still pass `zet check`. New drafts are always English. GER checks only the shape of the steps (`id`, `text`, `blocking`), so it accepts plans in either language; their `plan_hash` is unchanged because ZET never rewrites a plan
- **Docs**: README, SECURITY, `docs/design/design.md` and the brand README are English, with Japanese as `*.ja.md` (language switch at the top). SKILL.md is English and tells agents to answer in the user's language. Schema descriptions (`schemas/remediation-plan.schema.json`, `schemas/triage-input.schema.json`), code comments, tests, the test runner output and workflow comments / step names are English. Vendored schemas, test fixtures (real ZES 0.3.x output with Japanese `detail`), the brand scripts shared with ZES / GER and `docs/design/flow.svg` are unchanged
- The usage example in the README now finalizes `plan.previewed.json` (the file that `ger preview` writes), as SKILL.md already did
- **Repeated step ids are rejected (I-4)**: a checklist or followup whose `steps[]` repeat an id (for example the English and the Japanese steps of one template, both `s1`…) passed `zet check` and `finalize`, but GER always rejects it (G-1). ZET now reports it before finalization

### 日本語

ZES 0.5.0 と同じく、ZET を英語優先にしました。人が読む文の言語以外、動作は変わりません。

- **出力**: `validate` / `check` / `finalize` の違反メッセージ、CLI のメッセージと `--help`、監査ログのエラー、`verify-log` の結果、提案の注記、チェックリストの雛形（CL-*）21 種の手順の文言を英語にしました。機械向けの値（不変条件の番号 I-1〜I-13・SP、雛形の id CL-*、手順の id `s1` など、`blocking`、JSON のキー、列挙値）は変えていません
- **チェックリストの文言の互換性（I-13）**: I-13 は checklist と followup の手順を雛形と一字一句比べます。以前の ZET が作った下書き・確定 plan には日本語の文言が入っているため、以前の日本語の雛形を `zet/legacy_templates.py` に凍結して残し、雛形のすべての手順が英語か日本語のどちらか一方と一致すれば合格にします（1 つのチェックリストの中で言語は混ぜられません）。そうした下書きは引き続き finalize でき、確定 plan は `zet check` を通ります。新しい draft は常に英語です。GER は手順の形（`id`・`text`・`blocking`）だけを確かめるため、どちらの言語の plan も受け付けます。ZET は plan を書き換えないので `plan_hash` も変わりません
- **文書**: README・SECURITY・`docs/design/design.md`・brand の README を英語にし、日本語を `*.ja.md` に置きました（先頭に言語の切り替え）。SKILL.md は英語で、利用者の言語で答えるようエージェントに指示します。スキーマの description、コードのコメント、テスト、テストランナーの出力、ワークフローのコメントと step 名も英語です。vendor のスキーマ、テストのフィクスチャ（日本語の `detail` を含む ZES 0.3.x の実出力）、ZES / GER と共通の brand のスクリプト、`docs/design/flow.svg` は変えていません
- README の使い方の例で finalize するファイルを `plan.previewed.json`（`ger preview` が書き出すファイル）に直しました（SKILL.md は以前からこの形）
- **手順 id の重複を拒否（I-4）**: `steps[]` の id が重複するチェックリスト・followup（たとえば同じテンプレートの英語と日本語の手順を両方入れて `s1`… が 2 回ずつ出るもの）は `zet check` と `finalize` を通っていたが、GER は必ず拒否する（G-1）。確定の前に ZET が報告する

### findings 1.2（ZES 0.5.0）を受け付ける

- `schema_version` が `"1.2"` の findings を `schemas/vendor/findings-1.2.schema.json`（ZES の `schemas/findings.schema.json` の固定コピー）で検証する。1.2 は 1.1 に `code`（文の識別子）と `params`（文に入る値。文字列だけ）を足し、`detail` を英語にし、`id` を v2（module|campaign|path|code|params）にしたもの
- ZET は id を計算し直さず、`detail` の文を解析しないため、判断の規則（I-1〜I-13）は変わらない。evidence の推定（通常ファイル以外は detail の SHA-256）も 1.2 で同じ
- 版ごとに strict: 1.1 の findings に `code` / `params` があれば拒否、`params` の値は文字列だけ

### ロックファイルの finding を自動修復と数えない（I-13）

- **原因**: ロックファイルの finding（`pkg.lockfile_compromised`）に `related: npm_installed` があると、draft が隣の `node_modules/<name>` の quarantine を auto として提案し、同じ対象の `node_modules/<name>/package.json` の finding と同じ group にまとめていた。隔離しても ZES はロックファイルの中身を見て同じ finding を報告するため、E2E（lockfile-installed）で「自動で消えるはずの finding が残る」になっていた
- **draft**: ロックファイルの finding には auto を提案しない。checklist だけで、npm のロックファイルは新しい雛形 CL-LOCKFILE（「依存を取り除いてから〔`npm uninstall <pkg>`〕、または安全版に固定してからロックファイルを再生成する」を必須の手順に含む。`{pkg}` は findings 1.1 の `subject.package`）。他の finding の隔離の group にも入れない。インストール済みの実体の隔離は `node_modules/<name>/package.json` の finding の `quarantine npm_pkg_dir` が行う
- **I-13**: ロックファイルの finding（`kind: pkg.lockfile_compromised`、または §15 のロックファイル）の remediate は checklist（CL-LOCKFILE / CL-PKG）だけ。quarantine `npm_installed` などは確定させない。`KIND_ACTIONS["pkg.lockfile_compromised"]` を checklist だけにした（**判断の互換性に影響**: ロックファイルの finding に quarantine を採用した計画は確定できなくなる）
- 設計 §9.6、README の対応表と I-13 を更新


### ZES findings 1.1 の正式版を写す

- `schemas/vendor/findings-1.1-draft.schema.json`（ZET が書いた草案）を、ZES 0.4.0 の `schemas/findings.schema.json` の写し `schemas/vendor/findings-1.1.schema.json` に置き換えた（内容は草案と同じで、`$id`・title・description が ZES のもの）。VENDOR.json の `status: draft` を外し、`source_repo` / `source_path` / `source_commit` を ZES に向けた

### GER 修復能力拡張 Phase 1 への対応（plan 1.1。設計 0.2、Q-1〜Q-6 を推奨どおり採用）

- **plan スキーマ 1.1**: plan に `scope`（承認する検査範囲）、action に `relation`・`finding_path`・`group`・`evidence {kind, hash}`・`followup`、`constraints.suggested_actions` を追加。`action.target` は checklist だけ null にできる。1.0 の計画（chmod のみ）も有効。GER に写す
- **draft が修復を提案する**: finding → 修復の対応表（`zet/remedy.py`）から `auto`（quarantine / edit_json / edit_toml / remove_line / disable_mcp_server）と `checklist` の提案を付ける。同じ対象の auto を `action.group` でまとめ、他の finding の quarantine が扱う INFO は自動 defer せず同じ group を提案する。findings 1.0 は module・path・level・campaign で判断し、detail は解析しない
- **必須の後続作業**（I-13）: 自動修復には finding ごとに必須のチェックリスト（CL-IR・CL-SECRET・CL-LAUNCHD・CL-EXT・CL-PKG など）を `action.followup` に付け、欠けていれば確定させない。checklist・followup は雛形の手順をすべて含むこと。findings 1.1 の `kind` ごとに許す操作
- **I-4 の拡張**: target と finding の path の関係を閉じた集合（self / npm_pkg_dir / npm_installed / pypi_record / ext_dir / skill_dir / none）で確かめる。同じ対象は group でだけ。確定した action の params は GER の `actions.schema.json` に合うこと。chmod 以外のファイルを変える操作は `plan.scope` の下だけ
- **承認者**: root が必要な対象（`/etc` など）へのファイルを変える remediate は 2 名（I-6）
- **finalize**: `relation`・`finding_path`・`evidence` を写す（`evidence_hash` は書かない）。`scope` を写す。group に入れた INFO の期限は LOW の期限
- **入力**: triage-input の `policy.scope`（任意）。findings 1.1（`kind` / `subject` / `locators` / `related` / `evidence` / `scan_roots`）を任意の項目として受け付ける。ZES は 1.1 をまだ出さないため、ZET が書いた草案 `schemas/vendor/findings-1.1-draft.schema.json`（VENDOR.json に `status: draft`）で検証する
- **vendor**: GER の `schemas/actions.schema.json` を `schemas/vendor/actions.schema.json` に版固定で写す
- `zet/jsonschema_lite.py` に `maxLength` / `maxItems` を追加（GER にも写す）

### round 3 の修正

- **I-4: action.target は finding の `path` と一致すること**（F7）。配下のパスは許さない（ZET はファイルシステムを見ないため `path` がディレクトリかを判断できず、前方一致では `/` などを指す finding が任意のファイルを対象にできる）。`path` が null の finding は remediate できない
- **I-4: chmod は world-writable にできない**（F7）。setuid / setgid / sticky は従来どおり不可。現在の mode に権限を足さないことは GER が G-7 で確かめる
- **I-6: exec / network / spend / send を宣言したスキルの finding の remediate は承認者 2 名以上**（F10。GER の G-6 と同じ規則）。draft の `constraints.min_approvers` は選べる判断のうち最も厳しい値になった
- **plan スキーマ（後方互換の追加）**: `now_override`（`--now` で draft / finalize した plan に `true`。F5）、`items[].action.evidence_hash`（F14）、`items[].skillpact`（finding の skillpact の要約。F1）。`action.skillpact_effects` の要素を SkillPact 0.8 の 6 効果に限定（F10）。確定 plan では `evidence_hash` と `skillpact`（skillpact を持つ finding のみ）が必須で、入力と一致しないと I-4 / I-5
- **`skillpact_policy.diff_anomaly_threshold` / `destructive_requires_human` を拒否**（F14。予約済みで未実装）。triage-input スキーマの必須から外し、指定された入力は「予約・未実装」として拒否する（**入力の互換性に影響**: これらを指定している入力は外す必要がある）
- **`zet verify-log [LOG]`**（F15）: 監査ログのハッシュチェーンを検証する（0=健全 / 3=破損 / 64=ログが無い）。追記の前に末尾の連結を確かめ、壊れたチェーン（途中で切れた最終行を含む）には追記しない（終了コード 64）
- **端末制御文字のエスケープ**（F8）: スキーマ検証のメッセージ（JSON ポインタ・未知のキー名）と標準エラー出力のすべてのメッセージで、C0 / DEL / C1 制御文字・行区切り・双方向テキスト制御文字を `\xNN` / `\uNNNN` で表示する（`jsonschema_lite.safe_text`）
- README の I-7 の説明を修正（`skillpact.signed` は署名フィールドがあるだけで未検証。「L3 署名済み」ではない。F11）。README からテスト件数の記載を削除（F9）

- `schemas/vendor/findings.schema.json` を ZES `7b75e78`（SkillPact 0.8 対応）に更新。`$defs.effect` は `read` / `write` / `network` / `exec` / `spend` / `send` の 6 種（旧 `secrets` は機密ファイルの `read`、旧 `persist` は作業領域外への `write` に統合、`longrun` は廃止）。`declared_effects` もこの 6 種に限定される
- `RISKY_EFFECTS` を `("exec", "network", "spend", "send")` に変更（GER の G-6 と同じ集合）
- `tests/fixtures/findings-skillpact.json` を ZES main の実出力（`zes-scan.sh --skillpact --json`）で再生成。§49 は CRITICAL を出さず、INFO（skillpact-undeclared）を含むため、関連するテストを level_effective で判定するよう修正

## 0.1.0 — 2026-10-22

- `bin/zet`（validate / draft / check / finalize）、不変条件 I-1〜I-12、追記専用の監査ログ（ハッシュチェーン）
- `schemas/remediation-plan.schema.json`（ZET 所有、契約追加 A-1〜A-6 を反映）、`schemas/triage-input.schema.json`
- `schemas/vendor/findings.schema.json`（ZES から版固定で取り込み）
- テスト 32 件（公式 jsonschema との判定一致、Zero-Exec 検証を含む）

### リリース

- main の CHANGELOG 先頭の版に対応するタグと GitHub Release を、GitHub Actions（`.github/workflows/release.yml`）が自動で作成する

# Changelog

## Unreleased

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

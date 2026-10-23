# Changelog

## Unreleased

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

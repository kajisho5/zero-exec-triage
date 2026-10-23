<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/zet-logo-dark.svg">
    <img src="brand/logo/zet-logo-light.svg" alt="zero-exec triage" height="72">
  </picture>
</p>

[English](README.md) | 日本語

# zero-exec-triage（ZET）

**Zero-Exec Triage** — [Zero-Exec Shield（ZES）](https://github.com/kajisho5/zero-exec-shield) の判断層です。ZES の findings.json を受け取り、全 finding を「直す / 例外にする / 保留する」に振り分けた修復計画（remediation-plan.json）を作ります。修復の実行は [GER（gated-exec-remediation）](https://github.com/kajisho5/gated-exec-remediation) が行います。

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER]
```

- **何も実行しない**: JSON を読み、計画ファイルと追記専用の監査ログだけを書きます
- **契約に反する判断を通さない**: 不変条件 I-1〜I-12（SkillPact の規則を含む）を満たさない計画は確定できません
- **依存ゼロ**: Python 3.11 以上の標準ライブラリのみ。`python3 -I` で起動します

## 使い方

```bash
bin/zet validate triage-input.json --operator alice
bin/zet draft    triage-input.json --operator alice -o plan.draft.json
# plan.draft.json の decision / owner / approved_by などを記入
bin/zet check    triage-input.json plan.draft.json --operator alice
bin/zet finalize triage-input.json plan.draft.json --operator alice -o remediation-plan.json
```

| コマンド | 内容 |
|---|---|
| `validate` | 入力のスキーマ検証。`findings.status == "error"`、`l3_trusted: true` は拒否 |
| `draft` | 下書き生成。未確定モジュールの held 化、SkillPact による重大度の引き上げ、期限計算。decision は空のまま（level_effective が INFO のものだけ defer を既定値） |
| `check` | 不変条件 I-1〜I-12 の検査 |
| `finalize` | 全合格時のみ確定 plan（`plan_hash` 付き）を書き出す |

終了コード: `0` 合格 / `3` 契約違反 / `64` 引数・環境エラー（`-o` がディレクトリ・通常ファイル以外・入力と同じファイル・書き込めない場所、出力の書き出し失敗を含む）/ `70` 内部エラー（出力を JSON にできない場合を含む）。`-o` は処理の前に検査します。オプション `--now`（時刻固定。テスト専用で、環境変数 `ZET_ALLOW_NOW_OVERRIDE=1` のときだけ受け付ける。無ければ `64`）、`--plan-id`（draft）。

詳しい手順と判断の書き方は [SKILL.md](SKILL.md)、設計は [docs/design/design.md](docs/design/design.md) を参照してください。

## 不変条件

| # | 内容 |
|---|---|
| I-1 | 入力の全 finding が items か held にちょうど 1 回現れ、items の decision は記入済み |
| I-2 | 入力に存在しない finding_id を使わない |
| I-3 | exception は exception_type・reason・recheck_at と判断者以外の承認が必要（人名は大文字小文字を区別せず比較）。defer も level_effective が INFO 以外なら reason が必要。decided_by / decided_at は必須 |
| I-4 | remediate は owner・due_at・action が必要。action.target は正規化済みの絶対パス（`.` `..` 連続した `/` を含まない）、chmod の params は `{"mode": "0NNN"}`（特殊ビット不可）のみ（GER の受理条件と同じ）。action.reversible / skillpact_effects は導出値と一致 |
| I-5 | skillpact.divergence が空でない finding は exception にできない |
| I-6 | skillpact.diff_anomaly の finding は承認者 2 名以上（重複・大文字小文字だけの違いは 1 名と数える） |
| I-7 | L3 署名済みで乖離がある finding は level_effective = CRITICAL（引き下げ不可） |
| I-8 | 承認者は policy.approvers の中から（大文字小文字を区別しない） |
| I-9 | due_at は判断日 + deadlines[level_effective] 日以内、recheck_at は exception と defer（level_effective が INFO 以外）で必須で、判断日以上・判断ウィンドウ内。判断日（decided_at）は created_at 以上・実行時刻以下 |
| I-10 | errors[] のモジュールの finding は held にする（GER に渡さない）。held は errors[] のモジュールにだけ使える |
| I-11 | strict スキーマ（未知フィールド・重複キー・深すぎる入れ子・不正な時刻・有限でない数値・不正なサロゲートを拒否）。plan_hash を持つ plan は check / finalize でも plan_hash を検証 |
| I-12 | 入力が partial なら plan も partial で、errors[] のモジュールをモジュール単位で held にする |

## スキーマ

| ファイル | 所有 | 内容 |
|---|---|---|
| [schemas/remediation-plan.schema.json](schemas/remediation-plan.schema.json) | **ZET** | 出力契約。GER は版固定で参照 |
| [schemas/triage-input.schema.json](schemas/triage-input.schema.json) | ZET | 入力 |
| [schemas/vendor/findings.schema.json](schemas/vendor/findings.schema.json) | ZES | 版固定の写し（`schemas/vendor/VENDOR.json` に取り込み元コミットと SHA-256） |

実行時はスキーマファイルそのものを、標準ライブラリで書いたサブセット検証器（`zet/jsonschema_lite.py`）で検証します。テストでは公式の `jsonschema` と判定が一致することを確認しています。

## 監査ログ

`$ZET_LOG_DIR/zet-audit.jsonl`（既定 `~/.local/state/zet/`）。1 行 1 レコード（command / operator / input_hash / output_hash / started_at / finished_at / result / violations / prev_hash。`--now` を使った実行には `now_override: true`）。出力（`-o` または標準出力）を書き出せた場合だけ `result: ok` と `output_hash` を記録し、書き出せなければ `result: error` です。拒否も記録し、`prev_hash` のハッシュチェーンで改ざんを検出できます。ログに書けない場合、またはログのディレクトリが実行ユーザー以外の所有かグループ・他者から書き込み可能な場合は何もしません（終了コード `64`）。

## テスト

```bash
tests/run-tests.sh   # 単体テスト（55 件）＋ strace による execve 監視（bash / python3 以外を起動しないこと）
```

`jsonschema` が入っていれば検証器の判定一致テストも行います（開発時のみの依存。無ければ SKIP）。

## ライセンス

[Apache License 2.0](LICENSE)。脆弱性の報告は [SECURITY.md](SECURITY.md) を参照してください。

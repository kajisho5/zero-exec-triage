"""Japanese checklist templates of ZET before the English-first release (frozen; do not edit).

ZET wrote these step texts into drafts and finalized plans until it switched to English. I-13 compares
the steps of a checklist with its template word for word, so plans and drafts made by an older ZET are
still accepted when every step of the template matches either the current English text or this text.
New drafts always use the English templates in remedy.py. Ids, blocking flags and the order of the steps
are the same in both tables.
"""

PATH_NONE_JA = "（path なし）"  # placeholder for a finding without a path

TEMPLATES_JA = {
    "CL-PKG": [
        ("この作業ツリーで npm ci / npm install / pip install -r / bundle install を実行しない（ロックファイルが侵害版・脆弱版を再び取得する）。対象: {path}", True),
        ("~/.npmrc に ignore-scripts=true、環境変数に PIP_REQUIRE_VIRTUALENV=true と PYTHONNOUSERSITE=1 を設定する", True),
        ("依存の指定を安全版・修正版に変え、秘密情報の無い隔離環境でロックファイルを再生成する（npm install --ignore-scripts / poetry lock / uv lock / bundle lock --update / cargo update -p など）", True),
        ("npm ls <name> / pip show / bundle info / cargo tree で侵害版・脆弱版が残っていないことを確かめる", True),
        ("侵害版がインストール・実行された可能性があれば CL-SECRET を実施する", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-LOCKFILE": [
        ("この作業ツリーで npm ci / npm install / yarn install / pnpm install を実行しない（ロックファイルが侵害版を再び取得する）。対象: {path}", True),
        ("~/.npmrc に ignore-scripts=true を設定する", True),
        ("依存を取り除いてから（npm uninstall {pkg}。yarn remove / pnpm remove）、または安全版に固定してから（npm install {pkg}@<安全版> --ignore-scripts）、秘密情報の無い隔離環境でロックファイルを再生成する。GER はロックファイルを書き換えない。node_modules の実体を隔離してもこの finding は残り、作業者が再生成して完了にする", True),  # noqa: E501
        ("npm ls {pkg} で、侵害版が node_modules にもロックファイルにも残っていないことを確かめる", True),
        ("侵害版がインストール・実行された可能性があれば CL-SECRET を実施する", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-VENV": [
        ("侵害版・脆弱版を含む仮想環境（site-packages）を使うプロセスを止め、仮想環境ごと作り直す（RECORD が無いため GER は安全に隔離できない）。対象: {path}", True),
        ("新しい仮想環境では安全版を指定してインストールする（pip install --require-hashes など）", True),
        ("CL-SECRET を実施する（インストール時・import 時にコードが実行されている可能性がある）", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-SECRET": [
        ("この端末・作業ツリーから読めた認証情報（§14 の一覧と finding の path）を、提供元ですべて失効させる（GitHub PAT: Settings → Developer settings → Revoke、npm: npm token revoke、AWS: IAM でアクセスキーを無効化・削除、SSH 鍵: authorized_keys と GitHub の SSH keys から削除）", True),  # noqa: E501
        ("新しい認証情報を、侵害されていない端末で発行する", True),
        ("提供元の監査ログで、失効までの不正使用がなかったかを確かめる", True),
        ("git 履歴に入っていれば、履歴の書き換えか失効だけで済ませるかを決めて記録する（GER は履歴を書き換えない）", False),
    ],
    "CL-IR": [
        ("隔離・修復した時刻を記録し、この端末をネットワークから切り離すかどうかを判断する。対象: {path}", True),
        ("CL-SECRET を実施する", True),
        ("同じ campaign の他の痕跡を zes-scan.sh --full で確かめる", True),
        ("再構築するかどうかを判断する（ルートキットや永続化の痕跡があれば再構築を勧める）。GER の修復はインシデントの終わりを意味しない", True),
    ],
    "CL-LAUNCHD": [
        ("launchctl bootout gui/$(id -u)/<Label> を実行する（LaunchDaemon なら sudo launchctl bootout system/<Label>）。GER は plist を隔離して次回の読み込みを止めただけで、今読み込まれているエージェントは動き続ける", True),  # noqa: E501
        ("launchctl print gui/$(id -u)/<Label> が「見つからない」になることを確かめる", True),
        ("ps -axo pid,command で ProgramArguments のプロセスが残っていないことを確かめ、残っていれば止める。プログラム本体も確かめる", True),
        ("ログイン項目と構成プロファイルも確かめる", False),
    ],
    "CL-SYSTEMD": [
        ("systemctl --user stop <unit> と systemctl --user daemon-reload を実行する（GER はユニットファイルを隔離しただけ）", True),
        ("*.wants/ のリンクとユニットが起動していたプログラムを確かめる", True),
    ],
    "CL-CRON": [
        ("crontab -l > ~/crontab.bak.$(date +%s) で退避する", True),
        ("crontab -e で、通信や一時領域を実行する行（ZES の detail を参照）を消す（GER は crontab の spool を直接書き換えない）", True),
        ("crontab -l で消えたことを確かめる", True),
    ],
    "CL-EXT": [
        ("ブラウザを終了してから修復したことを確かめる（起動中に隔離すると、ブラウザが「破損」と判断してストアから修復する場合がある）", True),
        ("同期で再インストールされないよう、chrome://extensions とアカウントの同期設定から拡張機能を削除する", True),
        ("拡張機能が読めた cookie のセッション（主要なサイト）を失効させる", True),
    ],
    "CL-MCP": [
        ("エージェント・IDE を再起動し、取り除いた MCP サーバーが読み込まれていないことを確かめる", True),
        ("取り除いたサーバーが既に実行されていた可能性があれば CL-IR を実施する", True),
    ],
    "CL-MCP-PIN": [
        ("npx / uvx で実行時に最新版を取得する MCP サーバーの版を、承認者が決めて固定する（pkg@1.2.3）。版を足すことは「追加」なので GER は自動化しない。対象: {path}", True),
        ("使わないサーバーなら disable_mcp_server で取り除く", False),
    ],
    "CL-SHELL": [
        ("開いているシェルには効かない。シェルを開き直す（または unset LD_PRELOAD など、取り除いた設定を今のシェルからも外す）", True),
        ("同じ行が他の rc ファイル（.zshrc / .profile / .bash_profile）に無いか確かめる", True),
    ],
    "CL-LDSO": [
        ("再起動する（ld.so.preload の行を取り除いても、既に動いているプロセスにはライブラリが読み込まれたまま）", True),
        ("指していたライブラリを確かめて隔離する（Phase 2 で GER の preload_lib が対応予定）", True),
        ("ルートキットがいる状態ではファイルシステムの見え方そのものが信用できない。再構築を検討する", True),
    ],
    "CL-PHP": [
        ("PHP を修正版に上げる（Dockerfile のベースイメージ・.tool-versions・apt / apk のパッケージ）。イメージを作り直してデプロイする", True),
        ("php-fpm / Apache を再起動する（パッケージが修正済みでも、稼働中のワーカーが更新前のままの場合がある）", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-PHP-RESTART": [
        ("PHP（php-fpm / Apache）を再起動する。auto_prepend_file が正規の用途（APM など）だったかを確かめる", True),
    ],
    "CL-UPGRADE": [
        ("ベンダーの勧告に従って、サーバー・ランタイム・パッケージを修正版に上げる（compose のタグを上げるだけでは移行が済まない場合がある）。対象: {path}", True),
        ("更新後に再起動し、版を確かめる", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
    "CL-PWN": [
        ("そのワークフローを無効にする（GitHub の Actions → 対象のワークフロー → Disable workflow、またはワークフローファイルを削除するコミットをデフォルトブランチに入れる）。対象: {path}", True),
        ("actions/checkout から ref: ${{ github.event.pull_request.head.* }} を取り除くか、トリガーを pull_request に変える", True),
        ("そのワークフローから参照できた secrets を、すべて CL-SECRET でローテーションする", True),
        ("Actions の実行履歴で、外部の PR による実行がなかったかを確かめる", True),
    ],
    "CL-PIN": [
        ("対象のアクション・イメージのリポジトリで、タグが指すコミット SHA / ダイジェストを信頼できる端末で確かめる（git ls-remote / docker buildx imagetools inspect）。対象: {path}", True),
        ("その SHA がフォークではなく本体のリポジトリの履歴にあり、侵害の時期より前のものであることを確かめる", True),
        ("SHA / ダイジェストで固定する（Phase 2 で GER の pin_action / pin_digest が承認者 2 名で対応予定）。侵害が報告されたアクションは固定せず、代わりのものを選ぶ", True),
    ],
    "CL-SKILL": [
        ("スキルの作者に報告し、契約（skill.contract.json）を直してもらう。対象: {path}", True),
        ("直るまでそのスキルを使わない（必要なら quarantine skill_dir で隔離する）", True),
    ],
    "CL-ENV": [
        ("PYTHONNOUSERSITE=1 / PIP_REQUIRE_VIRTUALENV=true / npm の ignore-scripts=true を、利用者のシェルの rc に設定する（どの rc に書くかは環境による）", True),
    ],
    "CL-REVIEW": [
        ("ZES の detail に従って手で直す（コードの意味を変える修正・正しい値が人にしか分からない修正は GER が自動化しない）。対象: {path}", True),
        ("ZES で再スキャンし、この finding が消えたことを確かめる", True),
    ],
}

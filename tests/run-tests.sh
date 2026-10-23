#!/usr/bin/env bash
# ZET テスト一式: 単体テスト → Zero-Exec 検証（strace で python3 以外の execve が無いこと）
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FAIL=0
echo "== unit tests =="
python3 -I "$ROOT/tests/run.py" || FAIL=1

echo "== zero-exec =="
if ! command -v strace >/dev/null 2>&1 || ! strace -f -qq -e trace=execve -o /dev/null true 2>/dev/null; then
  echo "SKIP: strace を使えません（Linux で実行してください）"
else
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  export ZET_LOG_DIR="$TMP/log"
  command -v jq >/dev/null 2>&1 || { echo "FAIL: zero-exec 検証には jq が必要です"; echo "結果: FAIL"; exit 1; }
  jq -n --slurpfile f "$ROOT/tests/fixtures/findings-skillpact.json" '{schema_version:"1.0", findings:$f[0],
    policy:{deadlines:{CRITICAL:7,HIGH:30,MEDIUM:60,LOW:90}, decision_window_days:14, approvers:["security-lead"]},
    skillpact_policy:{l3_trusted:false, diff_anomaly_threshold:0.3, destructive_requires_human:true}}' >"$TMP/in.json"
  # 期待する終了コード: 下書き（decision 未記入）の check は契約違反（3）を返すのが正しい
  for c in "0 validate $TMP/in.json" "0 draft $TMP/in.json -o $TMP/d.json" "3 check $TMP/in.json $TMP/d.json"; do
    want="${c%% *}"; c="${c#* }"
    # shellcheck disable=SC2086
    strace -f -qq -e trace=execve -o "$TMP/trace" "$ROOT/bin/zet" $c --operator ci >/dev/null 2>&1
    rc=$?
    bad="$(grep -E 'execve\(' "$TMP/trace" | grep ' = 0' | grep -v -E 'execve\("([^"]*/(env|bash|python3(\.[0-9]+)?)|'"$ROOT"'/bin/zet)"' || true)"
    if [ "$rc" -ne "$want" ]; then echo "FAIL: zet ${c%% *} の終了コードが $rc（期待値 $want）"; FAIL=1
    elif [ -n "$bad" ]; then echo "FAIL: zet ${c%% *} が python3 以外を起動:"; echo "$bad"; FAIL=1
    else echo "ok   zet ${c%% *}: execve は bash/python3 のみ"; fi
  done
fi
[ "$FAIL" -eq 0 ] && echo "結果: OK" || echo "結果: FAIL"
exit "$FAIL"

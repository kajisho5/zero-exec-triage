#!/usr/bin/env bash
# ZET test suite: unit tests, then the Zero-Exec check (strace: no execve of anything but python3)
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FAIL=0
echo "== unit tests =="
python3 -I "$ROOT/tests/run.py" || FAIL=1

echo "== zero-exec =="
if ! command -v strace >/dev/null 2>&1 || ! strace -f -qq -e trace=execve -o /dev/null true 2>/dev/null; then
  echo "SKIP: strace is not available (run on Linux)"
else
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  export ZET_LOG_DIR="$TMP/log"
  command -v jq >/dev/null 2>&1 || { echo "FAIL: the zero-exec check needs jq"; echo "Result: FAIL"; exit 1; }
  jq -n --slurpfile f "$ROOT/tests/fixtures/findings-skillpact.json" '{schema_version:"1.0", findings:$f[0],
    policy:{deadlines:{CRITICAL:7,HIGH:30,MEDIUM:60,LOW:90}, decision_window_days:14, approvers:["security-lead"]},
    skillpact_policy:{l3_trusted:false}}' >"$TMP/in.json"
  # expected exit codes: check on a draft (decisions missing) must report a contract violation (3)
  for c in "0 validate $TMP/in.json" "0 draft $TMP/in.json -o $TMP/d.json" "3 check $TMP/in.json $TMP/d.json"; do
    want="${c%% *}"; c="${c#* }"
    # shellcheck disable=SC2086
    strace -f -qq -e trace=execve -o "$TMP/trace" "$ROOT/bin/zet" $c --operator ci >/dev/null 2>&1
    rc=$?
    bad="$(grep -E 'execve\(' "$TMP/trace" | grep ' = 0' | grep -v -E 'execve\("([^"]*/(env|bash|python3(\.[0-9]+)?)|'"$ROOT"'/bin/zet)"' || true)"
    if [ "$rc" -ne "$want" ]; then echo "FAIL: zet ${c%% *} exited with $rc (expected $want)"; FAIL=1
    elif [ -n "$bad" ]; then echo "FAIL: zet ${c%% *} started something other than python3:"; echo "$bad"; FAIL=1
    else echo "ok   zet ${c%% *}: execve of bash/python3 only"; fi
  done
fi
[ "$FAIL" -eq 0 ] && echo "Result: OK" || echo "Result: FAIL"
exit "$FAIL"

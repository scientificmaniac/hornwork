#!/usr/bin/env bash
# 开发辅助：逐个执行模拟脚本，打印该时刻之后新产生的告警，用于校准 verify 用例的
# rule_ids / technique 与规则库。仅测试主机使用。
set -uo pipefail

ROOT="${HORNWORK_HOME:-/opt/hornwork}"
SIM="$ROOT/hornwork/verify/simulate"
OUT="${OUT:-/tmp/verify-tune}"
mkdir -p "$OUT"
cd "$ROOT" || exit 1

run_one() {
  local tc="$1" script="$2"
  local t0
  t0="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  # 等待上一例的告警稳定，避免同一分钟去重掩盖
  sleep 1
  bash "$SIM/$script" --run >"$OUT/$tc.log" 2>&1
  local rc=$?
  sleep 3
  hornworkctl --json alerts --since 2m --limit 200 >"$OUT/$tc.alerts.json" 2>/dev/null
  python3 - "$OUT/$tc.alerts.json" "$t0" "$tc" "$rc" <<'PY'
import json, sys
path, t0, tc, rc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    data = {}
alerts = data.get("alerts") or data.get("data") or []
hits = [a for a in alerts if str(a.get("ts", "")) >= t0]
print(f"\n### {tc} rc={rc} 新增告警 {len(hits)}")
for a in hits:
    rule = a.get("rule") or {}
    print(f"  - L{a.get('level')} [{rule.get('engine')}] {rule.get('id')} {rule.get('name')} tech={a.get('technique')}")
PY
}

run_one TC-01 "T1059.004.sh"
run_one TC-02 "T1105.sh"
run_one TC-03 "T1543.002.sh"
run_one TC-04 "T1053.003.sh"
run_one TC-05 "T1136.001.sh"
run_one TC-06 "T1003.008.sh"
run_one TC-07 "T1071.001.sh"
run_one TC-08 "T1046.sh"
run_one TC-10 "T1574.006.sh"
run_one TC-N1 "N-baseline.sh"

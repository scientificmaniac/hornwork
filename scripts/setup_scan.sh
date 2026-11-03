#!/usr/bin/env bash
# 定期漏洞扫描一键准备（幂等）：依赖、目录、规则、资产台账、扫描计划、systemd timer。
#
# 用法（在测试主机 /opt/hornwork 下执行，需 root）：
#   sudo bash scripts/setup_scan.sh                 # 依赖 + 目录 + 台账 + 计划 + timer
#   sudo bash scripts/setup_scan.sh --no-timer      # 只准备数据，不启用 timer
#   sudo bash scripts/setup_scan.sh --with-lynis    # 额外安装主机基线引擎 lynis
#   sudo bash scripts/setup_scan.sh --import-cve /var/lib/hornwork/feed
#
# 设计：脚本只做"环境与数据"，扫描行为由 hornworkctl scan ... 驱动；
# 计划表是数据（改周期不改代码），timer 只是闹钟。
set -euo pipefail

ROOT="/opt/hornwork"
PY="/opt/hornwork-venv/bin/python"
CTL="/usr/local/bin/hornworkctl"
DATA_DIR="/var/lib/hornwork"
FEED_DIR="${DATA_DIR}/feed"
REPORT_DIR="${ROOT}/reports/scan"
RULE_DIR="${ROOT}/rules/scan"

WITH_TIMER=1
WITH_LYNIS=0
IMPORT_CVE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-timer) WITH_TIMER=0; shift ;;
    --with-lynis) WITH_LYNIS=1; shift ;;
    --import-cve) IMPORT_CVE="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "[warn] 未知参数：$1"; shift ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[错误] 需要 root：sudo bash scripts/setup_scan.sh" >&2
  exit 1
fi
if [[ ! -x "$PY" ]]; then
  echo "[错误] 找不到 venv：$PY（先执行 scripts/setup.sh）" >&2
  exit 1
fi

echo "== 1/6 依赖（nmap 必需；lynis/testssl/nuclei 可选）"
if ! command -v nmap >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap
fi
nmap --version | head -1
if [[ "$WITH_LYNIS" -eq 1 ]] && ! command -v lynis >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq lynis || true
fi
for tool in lynis testssl testssl.sh nuclei; do
  if command -v "$tool" >/dev/null 2>&1; then echo "  [可用] $tool"; fi
done

echo "== 2/6 目录与权限"
mkdir -p "$FEED_DIR" "$REPORT_DIR" "$RULE_DIR" "${DATA_DIR}/scan"
chown -R hornwork:hornwork "$FEED_DIR" "${DATA_DIR}/scan" 2>/dev/null || true
chown -R hornwork:hornwork "$REPORT_DIR" 2>/dev/null || true

echo "== 3/6 资产台账（单机双角色）"
# 防护主机自身：127.0.0.1，role=self，声明本机常用服务端口
"$CTL" asset add --id ast-self --ip 127.0.0.1 --hostname "$(hostname)" \
  --role self --criticality 5 --group self --tags "self,linux" --self \
  --ports 22,80,443,631,8787 >/dev/null 2>&1 || \
  "$CTL" asset add --id ast-self --ip 127.0.0.1 --role self --criticality 5 \
    --group self --tags "self,linux" --self --ports 22,80,443,631,8787
# 靶场主机角色（单机部署里由本机 Docker/Vulhub 承担）：端口 18000-18002 只绑回环
"$CTL" asset add --id ast-lab --ip 127.0.0.1 --hostname "$(hostname)-lab" \
  --role lab --criticality 2 --group lab --tags "lab,vulhub" \
  --ports 18000,18001,18002 >/dev/null

echo "== 4/6 扫描计划（周期是数据）"
"$CTL" scan plan add --id daily-quick --name "L1 每日快扫" --kind daily --profile quick \
  --group self --window-start "" --window-end "" --params '{"time":"02:30"}' >/dev/null
"$CTL" scan plan add --id weekly-linux --name "L2 每周常规" --kind weekly --profile weekly \
  --window-start "03:00" --window-end "04:00" --params '{"time":"03:00"}' >/dev/null
"$CTL" scan plan add --id quarterly-full --name "L3 每季全量" --kind quarterly --profile full \
  --window-start "03:00" --window-end "05:00" --params '{"time":"03:00"}' >/dev/null
"$CTL" scan plan add --id l4-cve-targeted --name "L4 重大 CVE 定向" --kind targeted \
  --profile targeted --group lab --params '{"cve_id":"CVE-2021-43798"}' >/dev/null
"$CTL" scan plan add --id verify-fix --name "L6 加固复扫" --kind verify-fix \
  --profile verify-fix --group lab >/dev/null

echo "== 5/6 systemd timer（默认装但可 --no-timer 跳过）"
if [[ "$WITH_TIMER" -eq 1 ]]; then
  install -m 0644 "$ROOT/deploy/hornwork-scan@.service" /etc/systemd/system/
  install -m 0644 "$ROOT/deploy/hornwork-scan@.timer" /etc/systemd/system/
  # 每个计划实例用自己的 OnCalendar（drop-in 覆盖模板）
  set_calendar() {  # $1=plan_id $2=OnCalendar 表达式
    local unit="hornwork-scan@$1.timer.d"
    mkdir -p "/etc/systemd/system/$unit"
    printf '[Timer]\nOnCalendar=\nOnCalendar=%s\n' "$2" \
      > "/etc/systemd/system/$unit/override.conf"
  }
  set_calendar daily-quick     "*-*-* 02:30:00"
  set_calendar weekly-linux    "Sun *-*-* 03:00:00"
  set_calendar quarterly-full  "Sat *-1,4,7,10-1..7 03:00:00"
  systemctl daemon-reload
  systemctl enable --now hornwork-scan@daily-quick.timer
  systemctl enable --now hornwork-scan@weekly-linux.timer
  systemctl enable --now hornwork-scan@quarterly-full.timer
fi

echo "== 6/6 CVE 数据（可选）"
if [[ -n "$IMPORT_CVE" ]]; then
  if [[ -d "$IMPORT_CVE" ]]; then
    "$CTL" scan cve import --source nvd --dir "$IMPORT_CVE" | tail -3
  else
    "$CTL" scan cve import --source nvd --file "$IMPORT_CVE" | tail -3
  fi
fi

echo
echo "== 完成。核对："
"$CTL" scan plan list || true
"$CTL" scan cve stats 2>/dev/null | head -20 || true
if [[ "$WITH_TIMER" -eq 1 ]]; then
  systemctl list-timers 'hornwork-scan*' --no-pager || true
fi

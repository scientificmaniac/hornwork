#!/usr/bin/env bash
# =============================================================================
# Hornwork 环境自检
#
# 逐项输出 OK / FAIL：hornworkctl status、yara/yaml 版本、clamdscan、auditctl、
# timedatectl、hostnamectl、磁盘、Web /healthz、ctl.sock、SQLite。
# 用法：sudo bash scripts/check.sh
# 退出码：0 全部通过；1 存在 FAIL 项。
# =============================================================================
set -uo pipefail

HORNWORK_HOME="${HORNWORK_HOME:-/opt/hornwork}"
VENV="${HORNWORK_VENV:-/opt/hornwork-venv}"
CONFIG="${HORNWORK_CONFIG:-$HORNWORK_HOME/config.toml}"
ENV_FILE="${HORNWORK_ENV_FILE:-/etc/hornwork/env}"
SERVICE_NAME="${HORNWORK_SERVICE:-hornwork}"
CTL_SOCK="${HORNWORK_CTL_SOCK:-/run/hornwork/ctl.sock}"
WEB_PORT="${HORNWORK_WEB_PORT:-8787}"
DATA_DIR="${HORNWORK_DATA_DIR:-/var/lib/hornwork}"

C_OK=$'\033[32m'; C_FAIL=$'\033[31m'; C_LINE=$'\033[36m'; C_END=$'\033[0m'
FAILS=0
PASSES=0
ok()   { PASSES=$((PASSES + 1)); printf '%s[ OK ]%s %s\n' "$C_OK" "$C_END" "$*"; }
fail() { FAILS=$((FAILS + 1)); printf '%s[FAIL]%s %s\n' "$C_FAIL" "$C_END" "$*"; }
detail() { printf '       %s\n' "$*"; }
headline() { printf '\n%s== %s ==%s\n' "$C_LINE" "$*" "$C_END"; }

# 通用检查：命令成功即 OK，并打印首行结果
check_cmd() {
  local label="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    ok "$label"
    [ -n "${out// /}" ] && detail "$(printf '%s' "$out" | head -n 1)"
  else
    fail "$label"
    detail "$(printf '%s' "$out" | head -n 2 | tr '\n' ' ')"
  fi
}

headline "Hornwork 环境自检  $(date -Is 2>/dev/null || date)"
printf '项目目录：%s\n配置文件：%s\n' "$HORNWORK_HOME" "$CONFIG"

# ---------------------------------------------------------------------------
# 1. 服务与 CLI
# ---------------------------------------------------------------------------
headline "1) 服务与 CLI"
if command -v hornworkctl >/dev/null 2>&1; then
  ok "hornworkctl 存在：$(command -v hornworkctl)"
  check_cmd "hornworkctl status" hornworkctl -c "$CONFIG" status
elif [ -x "$VENV/bin/python" ]; then
  ok "hornworkctl 未安装，使用模块方式：$VENV/bin/python -m hornwork.cli"
  if PYTHONPATH="$HORNWORK_HOME${PYTHONPATH:+:$PYTHONPATH}" "$VENV/bin/python" -m hornwork.cli -c "$CONFIG" status >/tmp/hornwork-check-status.$$ 2>&1; then
    ok "hornworkctl status（模块方式）"
    detail "$(head -n 1 /tmp/hornwork-check-status.$$)"
  else
    fail "hornworkctl status（模块方式）"
    detail "$(head -n 2 /tmp/hornwork-check-status.$$ | tr '\n' ' ')"
  fi
  rm -f /tmp/hornwork-check-status.$$
else
  fail "hornworkctl 与 $VENV 均不可用（先运行 scripts/setup.sh）"
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "systemd 服务 $SERVICE_NAME 状态：active"
  else
    fail "systemd 服务 $SERVICE_NAME 未 active（journalctl -u $SERVICE_NAME -n 50）"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Python 依赖
# ---------------------------------------------------------------------------
headline "2) Python 依赖"
if [ -x "$VENV/bin/python" ]; then
  check_cmd "yara / PyYAML 版本" "$VENV/bin/python" -c \
    'import yara, yaml; print("yara-python", yara.__version__, "| PyYAML", yaml.__version__)'
else
  fail "venv 不存在：$VENV"
fi

# ---------------------------------------------------------------------------
# 3. 安全组件
# ---------------------------------------------------------------------------
headline "3) 安全组件"
if [ -S /var/run/clamav/clamd.ctl ]; then
  ok "clamd socket 存在：/var/run/clamav/clamd.ctl"
  # 用 PING 探活（Ubuntu 26.04 的 clamav 包不再提供 clamdscan，Hornwork 直接走 socket INSTREAM）
  CLAM_PING="$("$VENV/bin/python" - <<'PY' 2>&1
import socket
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.connect("/var/run/clamav/clamd.ctl")
        s.sendall(b"zPING\0")
        print(s.recv(64).decode("utf-8", "replace").strip("\x00"))
except Exception as exc:
    print(f"ERROR {exc}")
PY
)"
  if [ "$CLAM_PING" = "PONG" ]; then
    ok "clamd PING 响应：PONG"
  else
    fail "clamd PING 失败：$CLAM_PING（sudo systemctl restart clamav-daemon）"
  fi
  if command -v clamdscan >/dev/null 2>&1; then
    check_cmd "clamdscan 版本" clamdscan --version
  elif command -v clamscan >/dev/null 2>&1; then
    check_cmd "clamscan 版本" clamscan --version
  fi
else
  fail "clamd socket 不存在：/var/run/clamav/clamd.ctl（sudo systemctl start clamav-daemon）"
fi

if command -v auditctl >/dev/null 2>&1; then
  if auditctl -l 2>/dev/null | grep -q 'hornwork'; then
    ok "auditd 已加载 hornwork 规则：$(auditctl -l 2>/dev/null | grep -c hornwork) 条"
  else
    fail "auditd 未加载 hornwork 规则（sudo cp deploy/hornwork.rules /etc/audit/rules.d/ && sudo augenrules --load）"
  fi
else
  fail "auditctl 不存在（apt install auditd）"
fi

# ---------------------------------------------------------------------------
# 4. 时间与主机
# ---------------------------------------------------------------------------
headline "4) 时间与主机"
if command -v timedatectl >/dev/null 2>&1; then
  SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  if [ "$SYNC" = "yes" ] || timedatectl 2>/dev/null | grep -qi 'synchronized: yes'; then
    ok "NTP 时间同步：$(timedatectl 2>/dev/null | grep -i 'System clock synchronized' | head -n 1 | sed 's/^ *//')"
  else
    fail "NTP 未同步（sudo timedatectl set-ntp true）"
  fi
  check_cmd "时区/时间" timedatectl show -p Timezone -p TimeUSec --value
else
  fail "timedatectl 不存在"
fi
if command -v hostnamectl >/dev/null 2>&1; then
  ok "主机名：$(hostnamectl --static 2>/dev/null || hostname)"
  detail "$(hostnamectl 2>/dev/null | grep -E 'Operating System|Kernel' | tr '\n' ' ')"
else
  ok "主机名（hostname）：$(hostname)"
fi

# ---------------------------------------------------------------------------
# 5. 磁盘与运行时路径
# ---------------------------------------------------------------------------
headline "5) 磁盘与运行时路径"
DISK_TARGET="$DATA_DIR"
[ -d "$DISK_TARGET" ] || DISK_TARGET="/"
USAGE="$(df -P "$DISK_TARGET" 2>/dev/null | awk 'NR==2 {gsub("%", "", $5); print $5}')"
if [ -n "${USAGE:-}" ] && [ "$USAGE" -lt 90 ] 2>/dev/null; then
  ok "磁盘使用率 ${USAGE}%（$DISK_TARGET）< 90%"
  detail "$(df -h "$DISK_TARGET" 2>/dev/null | tail -n 1)"
else
  fail "磁盘使用率 ${USAGE:-未知}%（$DISK_TARGET）≥ 90% 或无法读取"
fi

if [ -S "$CTL_SOCK" ]; then
  ok "控制面 socket 存在：$CTL_SOCK"
else
  fail "控制面 socket 不存在：$CTL_SOCK"
fi

if [ -f "$DATA_DIR/hornwork.db" ]; then
  ok "SQLite 数据库存在：$DATA_DIR/hornwork.db  ($(du -h "$DATA_DIR/hornwork.db" 2>/dev/null | cut -f1))"
else
  fail "SQLite 数据库不存在：$DATA_DIR/hornwork.db"
fi

# ---------------------------------------------------------------------------
# 6. Web 控制台 /healthz
# ---------------------------------------------------------------------------
headline "6) Web 控制台"
TOKEN=""
if [ -r "$ENV_FILE" ]; then
  TOKEN="$(grep -E '^HORNWORK_TOKEN=' "$ENV_FILE" 2>/dev/null | head -n 1 | cut -d= -f2- || true)"
fi
if [ -z "$TOKEN" ]; then
  TOKEN="${HORNWORK_TOKEN:-}"
fi
if [ -n "$TOKEN" ] && command -v curl >/dev/null 2>&1; then
  if BODY="$(curl -fsS --max-time 3 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$WEB_PORT/healthz" 2>&1)"; then
    ok "Web /healthz 200：$BODY"
  else
    fail "Web /healthz 请求失败（127.0.0.1:$WEB_PORT）：$BODY"
  fi
else
  fail "无法鉴权访问 Web：缺少 token（$ENV_FILE）或 curl"
fi

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
printf '\n---------------------------------------------\n'
printf '通过 %d 项，失败 %d 项\n' "$PASSES" "$FAILS"
if [ "$FAILS" -eq 0 ]; then
  printf '%s[ OK ]%s 环境自检全部通过\n' "$C_OK" "$C_END"
  exit 0
else
  printf '%s[FAIL]%s 存在 %d 项失败，请按上面提示修复\n' "$C_FAIL" "$C_END" "$FAILS"
  exit 1
fi

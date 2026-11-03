#!/usr/bin/env bash
# =============================================================================
# Hornwork 一键安装脚本（Ubuntu 24.04/26.04，Python 3.12+）
#
# 功能：apt 依赖 → venv + 离线/PyPI 安装 Python 依赖 → 系统用户与目录 →
#       拷贝代码到 /opt/hornwork → auditd 规则 → clamd 片段 → systemd 单元 +
#       EnvironmentFile（Web token）→ 启动服务。
#
# 幂等：重复执行不会重复建用户/目录，不会破坏已有 token 与数据库。
# 用法：
#   sudo bash scripts/setup.sh
#   sudo SKIP_CLAMAV=1 bash scripts/setup.sh         # 跳过 freshclam（离线/答辩环境）
#   sudo HORNWORK_HOME=/opt/hornwork bash scripts/setup.sh
# 退出码：0 成功；非 0 表示关键步骤失败（日志中有 [FAIL] 提示）。
# =============================================================================
set -euo pipefail

HORNWORK_HOME="${HORNWORK_HOME:-/opt/hornwork}"
VENV="${HORNWORK_VENV:-/opt/hornwork-venv}"
DATA_DIR="${HORNWORK_DATA_DIR:-/var/lib/hornwork}"
LOG_DIR="${HORNWORK_LOG_DIR:-/var/log/hornwork}"
RUN_DIR="${HORNWORK_RUN_DIR:-/run/hornwork}"
ENV_DIR="${HORNWORK_ENV_DIR:-/etc/hornwork}"
ENV_FILE="${HORNWORK_ENV_FILE:-$ENV_DIR/env}"
SERVICE_NAME="${HORNWORK_SERVICE:-hornwork}"
SVC_USER="${HORNWORK_USER:-hornwork}"
SVC_GROUP="${HORNWORK_GROUP:-hornwork}"
SKIP_CLAMAV="${SKIP_CLAMAV:-0}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_DEPS=("yara-python==4.5.4" "PyYAML==6.0.3")
APT_PKGS=(
  python3 python3-venv python3-pip build-essential git sqlite3
  iptables e2fsprogs attr clamav clamav-daemon auditd
  libyara-dev libpcre2-dev curl
)

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_END=$'\033[0m'
info() { printf '%s[ OK ]%s %s\n' "$C_OK" "$C_END" "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_END" "$*" >&2; }
die()  { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_END" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. 前置检查
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo bash scripts/setup.sh"
[ -f "$SRC_DIR/config.toml" ] || die "找不到 $SRC_DIR/config.toml，请在 Hornwork 仓库根目录执行 scripts/setup.sh"
[ -f "$SRC_DIR/deploy/hornwork.service" ] || die "缺少 deploy/hornwork.service"
[ -f "$SRC_DIR/deploy/hornwork.rules" ] || die "缺少 deploy/hornwork.rules"
command -v python3 >/dev/null || die "缺少 python3，请先 apt install python3"
info "安装源目录：$SRC_DIR"
info "目标目录：$HORNWORK_HOME    venv：$VENV"

# ---------------------------------------------------------------------------
# 1. apt 系统依赖
# ---------------------------------------------------------------------------
step "安装 apt 依赖（已安装的会跳过）"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || warn "apt-get update 失败，继续尝试安装（可能使用本地缓存）"
apt-get install -y -qq "${APT_PKGS[@]}" || die "apt 安装失败，请检查网络/软件源后重试：apt-get install -y ${APT_PKGS[*]}"
info "apt 依赖就绪"

# ---------------------------------------------------------------------------
# 2. 系统用户与目录
# ---------------------------------------------------------------------------
# 时间同步：检测模块事件/告警时间线与验证窗口依赖 NTP；VM 中 timesyncd 偶尔未同步，
# 这里显式启用并配置可用的 NTP 源（幂等，不覆盖用户已有配置）。
step "配置时间同步"
systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || warn "systemd-timesyncd 启用失败"
install -d -m 0755 /etc/systemd/timesyncd.conf.d
if [ ! -f /etc/systemd/timesyncd.conf.d/99-hornwork.conf ]; then
  cat > /etc/systemd/timesyncd.conf.d/99-hornwork.conf <<'EOF'
[Time]
NTP=ntp.aliyun.com ntp1.aliyun.com
FallbackNTP=ntp.ubuntu.com
EOF
fi
systemctl restart systemd-timesyncd >/dev/null 2>&1 || true
info "时间同步已配置（timedatectl 可查 NTPSynchronized）"

step "创建系统用户与目录"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd -r -s /usr/sbin/nologin -d "$HORNWORK_HOME" "$SVC_USER"
  info "已创建用户 $SVC_USER"
else
  info "用户 $SVC_USER 已存在"
fi
if getent group adm >/dev/null 2>&1; then
  LOG_GROUP="adm"
else
  LOG_GROUP="$SVC_GROUP"
  warn "系统无 adm 组，日志目录属组回退为 $SVC_GROUP"
fi
# 服务用户需要：adm（读 audit.log/auth.log）、clamav（连 clamd.ctl）
EXTRA_GROUPS=""
for g in adm clamav; do
  if getent group "$g" >/dev/null 2>&1; then
    EXTRA_GROUPS="${EXTRA_GROUPS:+$EXTRA_GROUPS,}$g"
  fi
done
if [ -n "$EXTRA_GROUPS" ]; then
  usermod -aG "$EXTRA_GROUPS" "$SVC_USER" && info "已把 $SVC_USER 加入附加组：$EXTRA_GROUPS"
fi
install -d -m 0755 -o "$SVC_USER" -g "$SVC_GROUP" "$HORNWORK_HOME"
# 数据目录属组给 adm：便于 sudo 用户（adm 组）用 hornworkctl 离线读库；
# 隔离区仍是 0700 hornwork，不放开。
install -d -m 0750 -o "$SVC_USER" -g "$LOG_GROUP" "$DATA_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" "$DATA_DIR/quarantine"
install -d -m 0750 -o "$SVC_USER" -g "$LOG_GROUP" "$LOG_DIR"
# 控制面 socket 属组是 adm（[ctl].group），目录必须 adm 可进入，
# 否则非 root 的 sudo 用户（adm 组）连不上 ctl.sock。
install -d -m 0750 -o "$SVC_USER" -g "$LOG_GROUP" "$RUN_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" "$HORNWORK_HOME/raw"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$HORNWORK_HOME/reports"
install -d -m 0750 -o root -g root "$ENV_DIR"
info "目录与权限就绪"

# ---------------------------------------------------------------------------
# 3. Python venv 与依赖（优先离线 wheels，失败回退 PyPI）
# ---------------------------------------------------------------------------
step "准备 Python venv：$VENV"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV" || die "创建 venv 失败：python3 -m venv $VENV"
  info "已创建 venv"
else
  info "venv 已存在"
fi

find_wheels() {
  local d
  for d in "${HORNWORK_WHEELS:-}" \
           "$SRC_DIR/wheels" \
           "$SRC_DIR/../参考资源/开发依赖仓库/wheels" \
           "/opt/forensics/开发依赖仓库/wheels" \
           "$HORNWORK_HOME/wheels"; do
    if [ -n "${d:-}" ] && [ -d "$d" ]; then
      printf '%s\n' "$d"
      return 0
    fi
  done
  return 1
}

install_py_deps() {
  local wheels
  "$VENV/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 \
    || warn "pip 升级失败（不影响后续安装）"
  if wheels="$(find_wheels)"; then
    info "发现离线轮子目录：$wheels，尝试离线安装"
    if "$VENV/bin/pip" install --no-index --find-links "$wheels" "${PY_DEPS[@]}"; then
      info "Python 依赖已从离线轮子安装"
      return 0
    fi
    warn "离线安装失败，回退 PyPI"
  else
    info "未发现离线轮子目录，使用 PyPI"
  fi
  "$VENV/bin/pip" install "${PY_DEPS[@]}" \
    || die "Python 依赖安装失败：请检查网络，或把 wheels 放到 /opt/hornwork/wheels 后重试"
  info "Python 依赖已从 PyPI 安装"
}

if "$VENV/bin/python" -c 'import yara, yaml, sys; assert yara.__version__ == "4.5.4"; assert yaml.__version__.startswith("6.0.")' >/dev/null 2>&1; then
  info "Python 依赖已满足：$("$VENV/bin/python" -c 'import yara, yaml; print("yara-python", yara.__version__, "PyYAML", yaml.__version__)')"
else
  install_py_deps
fi
"$VENV/bin/python" -c 'import yara, yaml' >/dev/null 2>&1 \
  || die "venv 中仍无法 import yara/yaml，请检查 $VENV"
info "yara-python / PyYAML 校验通过"

# ---------------------------------------------------------------------------
# 4. 拷贝代码到 $HORNWORK_HOME（幂等；同目录则跳过）
# ---------------------------------------------------------------------------
step "安装 Hornwork 代码到 $HORNWORK_HOME"
if [ "$(readlink -f "$SRC_DIR")" = "$(readlink -f "$HORNWORK_HOME")" ]; then
  info "安装源与目标相同，跳过拷贝（可能是就地运行）"
else
  tar -C "$SRC_DIR" \
      --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='.pytest_cache' --exclude='node_modules' \
      -cf - . | tar -C "$HORNWORK_HOME" -xf -
  info "代码已拷贝（保留已有数据库/日志不在拷贝范围内）"
fi
chown -R "$SVC_USER:$SVC_GROUP" "$HORNWORK_HOME"
chmod -R u+rwX,go+rX "$HORNWORK_HOME"
# Windows 检出/打包可能丢失可执行位，这里显式补齐（runbook 里也支持 bash 调用）
chmod 0755 "$HORNWORK_HOME/scripts/"*.sh 2>/dev/null || true
# 规则目录只允许 hornwork 写
chown -R "$SVC_USER:$SVC_GROUP" "$HORNWORK_HOME/rules"
chmod -R u+rwX,go+rX "$HORNWORK_HOME/rules"
info "所有权与权限设置完成"

# ---------------------------------------------------------------------------
# 5. auditd 规则
# ---------------------------------------------------------------------------
step "安装 auditd 规则"
if [ -d /etc/audit/rules.d ]; then
  #  监控了 /etc/rc.local；Ubuntu 默认不存在该文件，先补空文件避免 -w 失败
  if [ ! -e /etc/rc.local ]; then
    install -m 0755 /dev/null /etc/rc.local
    info "已创建 /etc/rc.local（auditd 规则需要监控该路径，默认内容为空）"
  fi
  install -m 0640 -o root -g root "$SRC_DIR/deploy/hornwork.rules" /etc/audit/rules.d/hornwork.rules
  if augenrules --load; then
    info "auditd 规则已加载（augenrules --load）"
  else
    warn "augenrules --load 失败，请检查 /etc/audit/rules.d/hornwork.rules 与 auditd 状态"
  fi
  systemctl enable auditd >/dev/null 2>&1 || true
  systemctl restart auditd >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || warn "auditd 启动失败"
else
  warn "未找到 /etc/audit/rules.d，跳过 auditd 规则（auditd 采集将不可用）"
fi

# ---------------------------------------------------------------------------
# 6. clamd 片段
# ---------------------------------------------------------------------------
step "配置 clamd"
CLAMD_CONF="/etc/clamav/clamd.conf"
if [ -f "$CLAMD_CONF" ]; then
  # 注意：clamd.conf 不支持多个 LocalSocket；这里对已存在键"就地更新"，
  # 缺失键才追加，避免重复指令导致 clamd 起不来。
  set_clamd() {
    local key="$1" val="$2"
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$CLAMD_CONF"; then
      sed -i -E "s|^[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$CLAMD_CONF"
    else
      printf '%s %s\n' "$key" "$val" >> "$CLAMD_CONF"
    fi
  }
  set_clamd LocalSocket /var/run/clamav/clamd.ctl
  set_clamd LocalSocketGroup clamav
  set_clamd LocalSocketMode 666
  set_clamd StreamMaxLength 100M
  set_clamd MaxFileSize 100M
  set_clamd MaxScanSize 200M
  set_clamd MaxThreads 4
  set_clamd ReadTimeout 60
  info "clamd 关键参数已写入 $CLAMD_CONF"
else
  warn "未找到 $CLAMD_CONF，跳过 clamd 配置（ClamAV 引擎将不可用）"
fi

if [ "$SKIP_CLAMAV" = "1" ]; then
  warn "SKIP_CLAMAV=1：跳过病毒库更新与服务重启"
else
  step "更新 ClamAV 病毒库（首次约 300 MB，可用 SKIP_CLAMAV=1 跳过）"
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  if command -v freshclam >/dev/null 2>&1; then
    freshclam || warn "freshclam 失败（离线环境可忽略，稍后手动执行 sudo freshclam）"
  fi
  systemctl enable clamav-daemon clamav-freshclam >/dev/null 2>&1 || true
  systemctl restart clamav-daemon >/dev/null 2>&1 || warn "clamav-daemon 重启失败"
  systemctl start clamav-freshclam >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 7. Web token（EnvironmentFile）
# ---------------------------------------------------------------------------
step "生成 Web token：$ENV_FILE"
if [ ! -s "$ENV_FILE" ] || ! grep -q '^HORNWORK_TOKEN=' "$ENV_FILE" 2>/dev/null; then
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  umask 077
  {
    printf '# Hornwork 环境变量（systemd EnvironmentFile，权限 0600）\n'
    printf 'HORNWORK_TOKEN=%s\n' "$TOKEN"
  } > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
  info "已生成 token（Web 控制台：Authorization: Bearer <token>）"
else
  chmod 0600 "$ENV_FILE"
  info "token 已存在，保持不变"
fi

# ---------------------------------------------------------------------------
# 8. systemd 单元 + drop-in
# ---------------------------------------------------------------------------
step "安装 systemd 单元"
install -m 0644 -o root -g root "$SRC_DIR/deploy/hornwork.service" "/etc/systemd/system/${SERVICE_NAME}.service"
install -d -m 0755 "/etc/systemd/system/${SERVICE_NAME}.service.d"
cat > "/etc/systemd/system/${SERVICE_NAME}.service.d/token.conf" <<EOF
# 由 scripts/setup.sh 生成：Web token 走 EnvironmentFile，避免写进 unit 文件
[Service]
EnvironmentFile=-${ENV_FILE}
# deploy/hornwork.service 保持 原文；这里用 drop-in 补齐运行期可写目录：
# 验证报告目录（config [verify].report_dir）与整机取证工作目录（[forensics].work_dir）。
ReadWritePaths=${HORNWORK_HOME}/reports
ReadWritePaths=-/data/forensics
# 关闭 PrivateTmp：FIM/静态扫描需要看到"宿主机" /tmp（模拟脚本在宿主命名空间里落样本），
# PrivateTmp=yes 会让服务看到另一份 /tmp，导致 /tmp 事件与样本扫描漏检。
PrivateTmp=no
EOF
info "unit 与 drop-in 已安装"

# ---------------------------------------------------------------------------
# 9. hornworkctl 启动器与 logrotate
# ---------------------------------------------------------------------------
step "安装 hornworkctl 启动器与日志轮转"
cat > /usr/local/bin/hornworkctl <<EOF
#!/bin/sh
# 由 scripts/setup.sh 生成：无需 pip install -e，直接以 venv 运行模块
export PYTHONPATH="${HORNWORK_HOME}\${PYTHONPATH:+:\$PYTHONPATH}"
exec "${VENV}/bin/python" -m hornwork.cli "\$@"
EOF
chmod 0755 /usr/local/bin/hornworkctl
if [ -f "$SRC_DIR/deploy/logrotate-hornwork" ]; then
  install -m 0644 -o root -g root "$SRC_DIR/deploy/logrotate-hornwork" /etc/logrotate.d/hornwork
  info "logrotate 配置已安装到 /etc/logrotate.d/hornwork"
fi
info "hornworkctl -> /usr/local/bin/hornworkctl"

# ---------------------------------------------------------------------------
# 10. 启动服务
# ---------------------------------------------------------------------------
step "启动 $SERVICE_NAME 服务"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || warn "systemctl enable 失败"
systemctl restart "$SERVICE_NAME" || die "服务启动失败：journalctl -u $SERVICE_NAME -n 100 --no-pager"
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
  info "服务运行中：$SERVICE_NAME"
else
  warn "服务未处于 active 状态，请查看：journalctl -u $SERVICE_NAME -n 100 --no-pager"
fi

cat <<EOF

=============================================================================
Hornwork 安装完成
-----------------------------------------------------------------------------
服务状态 : systemctl status $SERVICE_NAME
实时日志 : journalctl -u $SERVICE_NAME -f
环境自检 : sudo $HORNWORK_HOME/scripts/check.sh
一键演示 : sudo $HORNWORK_HOME/scripts/demo.sh
CLI      : hornworkctl status | alerts --since 5m | rules reload
Web      : http://127.0.0.1:8787  （token 见 $ENV_FILE）
数据目录 : $DATA_DIR      日志：$LOG_DIR      规则：$HORNWORK_HOME/rules
=============================================================================
EOF

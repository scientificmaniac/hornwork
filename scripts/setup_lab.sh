#!/usr/bin/env bash
# =============================================================================
# 靶场编排环境准备：Docker + Vulhub 靶场 + 编排目录 + 索引
#
# 适用：单台 Ubuntu 测试主机同时承担「防护主机 hornwork」与「靶场主机靶场」角色
#       。
#
# 幂等：重复执行不会重建 Docker 配置、不会重复 clone、不会破坏已有数据。
# 用法：
#   sudo bash scripts/setup_lab.sh
#   sudo SKIP_VULHUB_CLONE=1 bash scripts/setup_lab.sh    # 离线/已有目录
# 前置：能访问 GitHub 与 Docker Hub（拉不动时脚本会提示配置镜像加速）
# =============================================================================
set -euo pipefail

HORNWORK_HOME="${HORNWORK_HOME:-/opt/hornwork}"
VENV="${HORNWORK_VENV:-/opt/hornwork-venv}"
VULHUB_ROOT="${VULHUB_ROOT:-/opt/vulhub}"
LAB_DIR="${LAB_DIR:-/opt/lab}"
DATA_DIR="${HORNWORK_DATA_DIR:-/opt/hornwork/data}"
SKIP_VULHUB_CLONE="${SKIP_VULHUB_CLONE:-0}"

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_END=$'\033[0m'
info() { printf '%s[ OK ]%s %s\n' "$C_OK" "$C_END" "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_END" "$*" >&2; }
die()  { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_END" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo bash scripts/setup_lab.sh"

# ---------------------------------------------------------------------------
# 1. Docker Engine / Compose v2
# ---------------------------------------------------------------------------
step "检查 Docker Engine 与 Compose v2"
if ! command -v docker >/dev/null 2>&1; then
  info "未安装 docker，使用 apt 安装 docker.io + docker-compose-v2"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || warn "apt-get update 失败，继续尝试"
  apt-get install -y -qq docker.io docker-compose-v2 git curl \
    || die "docker 安装失败，请检查软件源"
fi
systemctl enable --now docker >/dev/null 2>&1 || die "docker 服务启动失败"
docker info >/dev/null 2>&1 || die "docker 守护进程不可用"
info "Docker：$(docker --version)"
docker compose version >/dev/null 2>&1 || die "缺少 docker compose v2 插件"
info "Compose：$(docker compose version --short 2>/dev/null || docker compose version)"

# 镜像加速：仅在 daemon.json 不存在时写入（不覆盖用户既有配置）
DAEMON_JSON=/etc/docker/daemon.json
if [ ! -s "$DAEMON_JSON" ]; then
  step "配置 Docker 镜像加速（国内网络下必填）"
  cat > "$DAEMON_JSON" <<'EOF'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1panel.live",
    "https://docker.1ms.run"
  ],
  "data-root": "/var/lib/docker"
}
EOF
  systemctl restart docker
  sleep 2
  info "已写入 $DAEMON_JSON 并重启 docker"
else
  info "已存在 $DAEMON_JSON，保持不变（如拉镜像超时请自行加 registry-mirrors）"
fi

# ---------------------------------------------------------------------------
# 2. Vulhub 靶场（只读素材，不改上游）
# ---------------------------------------------------------------------------
step "准备 Vulhub 靶场：$VULHUB_ROOT"
if [ -d "$VULHUB_ROOT/.git" ]; then
  info "Vulhub 已存在：$(git -C "$VULHUB_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
elif [ "$SKIP_VULHUB_CLONE" = "1" ]; then
  warn "SKIP_VULHUB_CLONE=1 且目录不存在，跳过 clone"
else
  git clone --depth 1 https://github.com/vulhub/vulhub.git "$VULHUB_ROOT" \
    || die "Vulhub clone 失败（检查网络或设置 SKIP_VULHUB_CLONE=1）"
  info "Vulhub clone 完成"
fi
[ -d "$VULHUB_ROOT" ] || die "Vulhub 目录不存在：$VULHUB_ROOT"
COMPOSE_COUNT="$(find "$VULHUB_ROOT" -name docker-compose.yml | wc -l)"
info "Vulhub 环境数（compose 文件）：$COMPOSE_COUNT"

# ---------------------------------------------------------------------------
# 3. 目录与权限（hornwork 用户可写；上游只读）
# ---------------------------------------------------------------------------
step "准备编排目录与数据目录"
install -d -m 0755 "$LAB_DIR"
install -d -m 0775 "$LAB_DIR/overrides"
install -d -m 0750 -o hornwork -g hornwork "$DATA_DIR" "$DATA_DIR/records" \
  "$DATA_DIR/evidence" "$DATA_DIR/vulhub-index" 2>/dev/null || true
install -d -m 0750 -o hornwork -g hornwork "$HORNWORK_HOME/data" 2>/dev/null || true
# 单机部署中 hornwork 与 docker 守护进程在同一台机器；数据目录不放开给其他用户
chown -R hornwork:hornwork "$DATA_DIR" 2>/dev/null || true
chmod 0775 "$LAB_DIR/overrides"
# 单机部署没有独立 靶场主机快照：写标记并说明以 lab down -v + 回环绑定替代快照回滚。
# 双机拓扑下请在 靶场主机装完系统/镜像后手工创建该标记（表示 S0-B 快照已存在）。
SNAPSHOT_MARKER="$LAB_DIR/S0-B.ok"
if [ ! -e "$SNAPSHOT_MARKER" ]; then
  cat > "$SNAPSHOT_MARKER" <<'EOF'
single-vm-lab: no independent B machine snapshot.
equivalent controls: containers bound to 127.0.0.1 only, target whitelist,
and `lab down -v` after every reproduction. Replace this marker with a real
S0-B snapshot record when a two-machine topology is used.
EOF
  info "已写入 $SNAPSHOT_MARKER（单机部署说明）"
fi
info "目录就绪：$LAB_DIR/overrides、$DATA_DIR"

# ---------------------------------------------------------------------------
# 4. 生成/刷新 vulhub 索引
# ---------------------------------------------------------------------------
step "生成 Vulhub 索引"
if [ -x "$VENV/bin/python" ]; then
  PYTHONPATH="$HORNWORK_HOME${PYTHONPATH:+:$PYTHONPATH}" \
    "$VENV/bin/python" -m hornwork.cli -c "$HORNWORK_HOME/config.toml" lab index --force \
    || warn "索引生成失败（可稍后执行 sudo hornworkctl lab index --force）"
else
  warn "venv 不存在（$VENV），跳过索引生成；先运行 scripts/setup.sh"
fi

# ---------------------------------------------------------------------------
# 5. 提示
# ---------------------------------------------------------------------------
cat <<EOF

=============================================================================
靶场编排环境就绪
-----------------------------------------------------------------------------
Docker        : $(docker --version 2>/dev/null)
Compose       : $(docker compose version --short 2>/dev/null || echo unknown)
Vulhub        : $VULHUB_ROOT（$COMPOSE_COUNT 个环境）
索引          : $DATA_DIR/vulhub-index.json
编排目录      : $LAB_DIR/overrides（补丁 compose 副本，上游 /opt/vulhub 只读）
记录          : $DATA_DIR/records；证据：$DATA_DIR/evidence

常用命令（lab 操作需要 root 或 docker 组权限）：
  sudo hornworkctl lab list --limit 20
  sudo hornworkctl lab up grafana/CVE-2021-43798 --force --ttl 60
  sudo hornworkctl lab status grafana/CVE-2021-43798
  sudo hornworkctl lab down grafana/CVE-2021-43798
  sudo hornworkctl vuln record sync
  sudo hornworkctl vuln match --component grafana --version 8.2.6

注意：单机部署没有独立 靶场主机快照；首次 up 需 --force 跳过 S0-B 快照提醒。
=============================================================================
EOF

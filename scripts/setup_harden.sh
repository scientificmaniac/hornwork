#!/usr/bin/env bash
# 加固模块环境准备（Ubuntu 24.04/26.04，幂等；只影响 防护主机自身）
#   sudo bash scripts/setup_harden.sh
set -euo pipefail

VENV=/opt/hornwork-venv
PY="$VENV/bin/python"
APP=/opt/hornwork
STATE=/var/lib/hornwork/harden

log() { printf '[setup-harden] %s\n' "$*"; }

[ "$(id -u)" = "0" ] || { echo "需要 root：sudo bash $0" >&2; exit 1; }

# 1) 依赖：nginx（TLS 端点）、cryptsetup（LUKS2 演示），缺什么装什么
need=()
command -v nginx >/dev/null 2>&1 || need+=(nginx)
command -v cryptsetup >/dev/null 2>&1 || need+=(cryptsetup-bin)
if [ ${#need[@]} -gt 0 ]; then
  log "安装依赖：${need[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${need[@]}" >/dev/null
fi
modprobe dm_crypt 2>/dev/null || true

# 2) 目录与权限
install -d -m 700 /etc/hornwork/harden
install -d -m 700 /etc/ssl/hornwork
install -d -m 755 "$STATE" "$STATE"/{plans,runs,backups,snapshots,assets,luks,demo}
install -d -m 755 /mnt/hornwork-backup
# 默认站点监听 80，而本机 80 已被别的测试服务占用；加固模块的 TLS 端点只绑 127.0.0.1:8080/8443
rm -f /etc/nginx/sites-enabled/default
nginx -t >/dev/null
systemctl enable nginx >/dev/null 2>&1 || true
systemctl is-active nginx >/dev/null 2>&1 || systemctl start nginx

# 3) hardenctl 入口（与 hornworkctl 解耦，加固模块可独立演示）
cat > /usr/local/bin/hardenctl <<'EOF'
#!/bin/sh
PYTHONPATH=/opt/hornwork exec /opt/hornwork-venv/bin/python -m hornwork.harden "$@"
EOF
chmod 755 /usr/local/bin/hardenctl

# 4) 演示用“加固前”口令哈希库（只用于证明迁移逻辑，不接触真实账号）
PYTHONPATH="$APP" "$PY" - <<'PYEOF'
from hornwork.harden import crypto
created = crypto.seed_demo_users()
print(f"[setup-harden] 演示用户库就绪：{crypto.demo_db_path()}（本次新增 {len(created)} 条旧哈希）")
PYEOF

# 5) 工具自检
for tool in openssl nginx cryptsetup lynis auditctl systemd-run; do
  command -v "$tool" >/dev/null 2>&1 || log "警告：缺少 $tool"
done
log "完成：hardenctl 可用；python=$($PY -V 2>&1)；nginx=$(nginx -v 2>&1)"

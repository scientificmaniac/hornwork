#!/usr/bin/env bash
# 认证模块：认证子系统安装/初始化（幂等；不新增常驻进程）
# 内容：Python 依赖 → 密钥目录（hornwork:600）→ 7 张 auth_* 表 → 策略种子
set -euo pipefail

HORNWORK_HOME="${HORNWORK_HOME:-/opt/hornwork}"
VENV="${HORNWORK_VENV:-/opt/hornwork-venv}"
CFG="${HORNWORK_CONFIG:-$HORNWORK_HOME/config.toml}"
KEY_DIR="${AUTH_KEY_DIR:-/var/lib/hornwork/auth}"
PY="$VENV/bin/python"

step() { printf '\n==> %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

[ -f "$HORNWORK_HOME/hornwork/auth/engine.py" ] || die "未找到认证模块代码：$HORNWORK_HOME/hornwork/auth"
[ -x "$PY" ] || die "venv 不存在：$VENV"

step "1/3 检查 Python 依赖（argon2-cffi / cryptography）"
if "$PY" -c 'import argon2, cryptography' >/dev/null 2>&1; then
  "$PY" - <<'EOF'
import importlib.metadata as m
print("  argon2-cffi", m.version("argon2-cffi"), " cryptography", m.version("cryptography"))
EOF
else
  sudo "$PY" -m pip install --no-cache-dir "argon2-cffi>=23.1" "cryptography>=42"
fi

step "2/3 密钥目录（与库分离；仅 hornwork 可读写）"
sudo install -d -m 700 -o hornwork -g hornwork "$KEY_DIR"
echo "  $KEY_DIR"

step "3/3 建表 + 生成密钥 + 策略种子"
sudo -u hornwork hornworkctl --config "$CFG" auth db init
sudo -u hornwork hornworkctl --config "$CFG" auth db show

cat <<'EOF'

完成。常用命令（以 hornwork 身份运行，避免直接改库属主）：
  sudo -u hornwork hornworkctl auth user list
  sudo -u hornwork hornworkctl auth audit verify-chain
  bash scripts/demo_auth.sh          # 一键演示三因子/重放/锁定/降级/审计

说明：认证模块不新增 systemd 服务（认证内核以库 + CLI 形式交付）；
HTTP 登录页/PAM 集成列为边界，见 docs/authentication.md。
EOF

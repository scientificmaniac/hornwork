#!/usr/bin/env bash
# TC-03 创建 systemd 服务单元（T1543.002）
#
# 动作：在 /etc/systemd/system/ 写入一个无害的 oneshot 单元（ExecStart=/bin/true），
#       只落盘、不执行 daemon-reload、绝不启动该单元；退出时精确删除，主机状态恢复原样。
#       文件落盘即可被 FIM / auditd 的持久化路径监控捕获。
#
# 用法：bash T1543.002.sh [--run|--dry-run]
set -euo pipefail

TC="TC-03"
TECH="T1543.002"
UNIT="/etc/systemd/system/hornwork-tc03.service"

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --run) ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      echo "用法：bash $0 [--run|--dry-run]"
      exit 0
      ;;
    *)
      echo "未知参数：$arg（支持 --run / --dry-run）" >&2
      exit 2
      ;;
  esac
done

echo "$TC $TECH start"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] 计划动作："
  echo "  1) 需要 root（或免密 sudo）才可写 /etc/systemd/system"
  echo "  2) 写入无害单元 $UNIT（ExecStart=/bin/true，只落盘，不 daemon-reload、不启动）"
  echo "  3) 退出时删除该单元，主机状态恢复原样"
  echo "$TC done"
  exit 0
fi

is_root() {
  [ "$(id -u)" -eq 0 ]
}
sudo_ready() {
  command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1
}

PRIV=""
prepare_root() {
  if is_root; then
    PRIV=""
    return 0
  fi
  if sudo_ready; then
    PRIV="sudo -n"
    return 0
  fi
  return 1
}
priv() {
  if [ -n "$PRIV" ]; then
    sudo -n "$@"
  else
    "$@"
  fi
}

CREATED=0

cleanup() {
  set +e
  if [ "$CREATED" = "1" ]; then
    priv rm -f "$UNIT"
  fi
}
trap cleanup EXIT

if ! prepare_root; then
  echo "$TC SKIP: 需要 root 或免密 sudo 才能写入 $UNIT"
  exit 0
fi

if priv test -e "$UNIT"; then
  echo "$TC SKIP: 目标单元已存在，拒绝覆盖：$UNIT"
  exit 0
fi

priv tee "$UNIT" >/dev/null <<'EOF'
[Unit]
Description=Hornwork verification demo unit (harmless, removed on exit)

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
CREATED=1

# 保持片刻，确保 FIM/auditd 捕获到文件落盘
sleep 1

echo "$TC 已创建 systemd 单元：$UNIT（未 daemon-reload、未启动，退出时删除）"

echo "$TC done"

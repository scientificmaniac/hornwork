#!/usr/bin/env bash
# TC-05 创建本地账号（T1136.001）
#
# 动作：用 useradd 创建一个无家目录、不可登录的测试账号，触发账号创建事件与
#       “账号工具被执行”类主机规则；退出时精确删除该账号（含同名用户组）。
#       账号名可用 HORNWORK_TC05_USER 覆盖；账号已存在时直接 SKIP，绝不删除已有账号。
#
# 用法：bash T1136.001.sh [--run|--dry-run]
set -euo pipefail

TC="TC-05"
TECH="T1136.001"
USER_NAME="${HORNWORK_TC05_USER:-hornwork_tc05}"

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
  echo "  1) 需要 root（或免密 sudo）才能创建本地账号"
  echo "  2) useradd -M -s /usr/sbin/nologin $USER_NAME（无家目录、不可登录，不设密码）"
  echo "  3) 打印 id 信息，退出时 userdel 删除该账号并清理同名用户组"
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
    priv userdel "$USER_NAME" >/dev/null 2>&1
    priv groupdel "$USER_NAME" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

if ! prepare_root; then
  echo "$TC SKIP: 需要 root 或免密 sudo 才能创建本地账号"
  exit 0
fi

if ! command -v useradd >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 useradd 命令"
  exit 0
fi

case "$USER_NAME" in
  ""|root|"0")
    echo "$TC SKIP: 测试账号名非法：$USER_NAME"
    exit 0
    ;;
esac

if priv id "$USER_NAME" >/dev/null 2>&1; then
  echo "$TC SKIP: 账号已存在，拒绝改动已有账号：$USER_NAME"
  exit 0
fi

priv useradd -M -s /usr/sbin/nologin -c "Hornwork verification demo account (auto-removed)" "$USER_NAME"
CREATED=1

priv id "$USER_NAME" || true

# 保持片刻，确保采集链路看到账号创建事件
sleep 1

echo "$TC 已创建测试账号：$USER_NAME（退出时删除）"

echo "$TC done"

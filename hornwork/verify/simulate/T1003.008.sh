#!/usr/bin/env bash
# TC-06 复制 /etc/shadow（T1003.008）
#
# 动作：把 /etc/shadow 复制到临时目录下的副本（权限 600），打印行数/大小/权限，
#       命中“命令行读取影子文件”类主机规则；退出时删除副本，不保留任何凭据内容。
#       需要 root（或免密 sudo）才能读取 /etc/shadow。
#
# 用法：bash T1003.008.sh [--run|--dry-run]
set -euo pipefail

TC="TC-06"
TECH="T1003.008"
TMP="${HORNWORK_TMP:-/tmp}"
SRC="/etc/shadow"

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
  echo "  1) 需要 root（或免密 sudo）才能读取 $SRC"
  echo "  2) 复制 $SRC 到 $TMP/hornwork-tc06.XXXXXX/shadow.copy（权限 600）"
  echo "  3) 打印行数/大小/权限，退出时删除临时副本与临时目录"
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

WORKDIR=""
COPY=""
CREATED=0

cleanup() {
  set +e
  if [ "$CREATED" = "1" ]; then
    priv rm -f "$COPY" 2>/dev/null
  fi
  if [ -n "$WORKDIR" ]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

if ! prepare_root; then
  echo "$TC SKIP: 需要 root 或免密 sudo 才能读取 $SRC"
  exit 0
fi

if ! priv test -r "$SRC"; then
  echo "$TC SKIP: 当前身份无法读取 $SRC"
  exit 0
fi
if ! command -v cp >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 cp 命令"
  exit 0
fi

mkdir -p "$TMP"
WORKDIR="$(mktemp -d "${TMP%/}/hornwork-tc06.XXXXXX")"
COPY="$WORKDIR/shadow.copy"

priv cp -- "$SRC" "$COPY"
CREATED=1
priv chmod 600 "$COPY" 2>/dev/null || true

LINES="$(priv wc -l "$COPY" | awk '{print $1}')"
SIZE="$(priv stat -c '%s' "$COPY")"
MODE="$(priv stat -c '%a' "$COPY")"

echo "$TC 已复制凭据文件：$COPY（临时副本，退出时删除）"
echo "$TC 行数：$LINES  大小：$SIZE 字节  权限：$MODE"

# 保持片刻，确保采集链路看到复制动作
sleep 1

echo "$TC done"

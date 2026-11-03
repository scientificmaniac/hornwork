#!/usr/bin/env bash
# TC-10 LD_PRELOAD 劫持（T1574.006）
#
# 动作：写入 /etc/ld.so.preload（空内容 = 不加载任何库，对运行中的程序无影响），
#       命中动态链接器预加载 / 持久化路径监控；保持 1s 后精确恢复原文件
#       （原来不存在则删除，存在则按备份原样回写）。
#       需要 root（或免密 sudo）。
#
# 用法：bash T1574.006.sh [--run|--dry-run]
set -euo pipefail

TC="TC-10"
TECH="T1574.006"
TMP="${HORNWORK_TMP:-/tmp}"
PRELOAD="/etc/ld.so.preload"

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
  echo "  1) 需要 root（或免密 sudo）才能写 $PRELOAD"
  echo "  2) 若文件已存在则备份到 $TMP 下临时目录；写入空内容（空 preload 列表，不加载任何库）"
  echo "  3) 保持 1s 供 FIM/持久化检查捕获，退出时按备份精确恢复（原来不存在则删除）"
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
TOUCHED=0
HAD_FILE=0

cleanup() {
  set +e
  if [ "$TOUCHED" = "1" ]; then
    if [ "$HAD_FILE" = "1" ]; then
      if ! priv cp -p "$WORKDIR/ld.so.preload.bak" "$PRELOAD" 2>/dev/null; then
        echo "$TC 警告：恢复 $PRELOAD 失败，请人工检查 $WORKDIR/ld.so.preload.bak" >&2
        return 0
      fi
    else
      priv rm -f "$PRELOAD" 2>/dev/null
    fi
  fi
  if [ -n "$WORKDIR" ]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

if ! prepare_root; then
  echo "$TC SKIP: 需要 root 或免密 sudo 才能写入 $PRELOAD"
  exit 0
fi

mkdir -p "$TMP"
WORKDIR="$(mktemp -d "${TMP%/}/hornwork-tc10.XXXXXX")"

if priv test -e "$PRELOAD"; then
  if ! priv cp -p "$PRELOAD" "$WORKDIR/ld.so.preload.bak"; then
    echo "$TC SKIP: 备份 $PRELOAD 失败，为避免破坏原配置放弃写入"
    exit 0
  fi
  HAD_FILE=1
fi

# 写空文件：空 preload 列表，不加载任何库，避免影响运行中的动态链接程序
if ! priv tee "$PRELOAD" >/dev/null </dev/null; then
  echo "$TC SKIP: 写入 $PRELOAD 失败（权限或只读文件系统）"
  exit 0
fi
TOUCHED=1

# 保持片刻，确保 FIM/auditd 捕获到文件事件
sleep 1

echo "$TC 已写入 $PRELOAD（空内容，不加载任何库），保持 1s 供监控捕获"
echo "$TC 退出时精确恢复（原来存在则还原备份，原来不存在则删除）"

echo "$TC done"

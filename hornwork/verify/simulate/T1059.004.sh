#!/usr/bin/env bash
# TC-01 Unix Shell 命令执行（T1059.004）
#
# 动作：通过 env 调起 /bin/sh 执行只读侦察命令（等价于 `sh -c 'id; uname -a'`），
#       命中 auditd execve 采集与“env 调起 shell”类主机规则；无写入、无持久化产物。
#
# 用法：bash T1059.004.sh [--run|--dry-run]
set -euo pipefail

TC="TC-01"
TECH="T1059.004"

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
  echo "  1) env /bin/sh -c 'id; uname -a'（只读侦察命令，无写入、无持久化）"
  echo "  2) 无需 root；退出后主机状态不变"
  echo "$TC done"
  exit 0
fi

cleanup() {
  # TC-01 不落地任何文件，无需恢复动作
  :
}
trap cleanup EXIT

# 只读命令；通过 env 调起 shell 便于命中“env shell invocation”类主机规则
env /bin/sh -c 'id; uname -a'

echo "$TC done"

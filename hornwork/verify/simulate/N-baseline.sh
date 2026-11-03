#!/usr/bin/env bash
# TC-N1 正常基线操作（阴性样本）
#
# 动作：只执行本地只读的日常运维命令（ls / date / cat），用于统计误报率（FPR）。
#       不产生告警、不写入任何文件、不联网、不需要 root。
#       注意：刻意避开 uname/hostname 等会命中“系统信息发现”类规则的侦察命令。
#
# 用法：bash N-baseline.sh [--run|--dry-run]
set -euo pipefail

TC="TC-N1"
TECH="baseline"

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
  echo "[dry-run] 计划动作（本地只读命令，预期不产生告警）："
  echo "  1) ls -l /tmp | head -n 5"
  echo "  2) date -u"
  echo "  3) cat /etc/os-release | head -n 3"
  echo "  4) echo hornwork-baseline-ok；无临时文件、无持久化产物、无需 root"
  echo "$TC done"
  exit 0
fi

cleanup() {
  # TC-N1 不落地任何文件，无需恢复动作
  :
}
trap cleanup EXIT

# 日常只读运维命令（阴性样本：不应触发任何检测规则）
ls -l /tmp 2>/dev/null | head -n 5 || true
date -u || true
cat /etc/os-release 2>/dev/null | head -n 3 || true
echo "hornwork-baseline-ok"

echo "$TC done"

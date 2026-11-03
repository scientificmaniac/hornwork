#!/usr/bin/env bash
# TC-04 写入 cron 定时任务（T1053.003）
#
# 动作：把一条无害的 cron 任务（/bin/true）通过 crontab 安装到当前用户，命中
#       “从 /tmp 上传 crontab 任务”类主机规则（Image=crontab 且命令行含 /tmp/），
#       退出时精确恢复原有 crontab（原来没有任务则用 crontab -r 清除）。
#       不需要 root。
#
# 用法：bash T1053.003.sh [--run|--dry-run]
set -euo pipefail

TC="TC-04"
TECH="T1053.003"
TMP="${HORNWORK_TMP:-/tmp}"
JOB_LINE='* * * * * /bin/true # hornwork-tc04 harmless cron demo'

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
  echo "  1) 备份当前用户 crontab（crontab -l）到 $TMP 下临时目录"
  echo "  2) 在 $TMP 下写含无害任务（/bin/true）的 crontab 文件并 crontab 安装"
  echo "  3) 退出时恢复原 crontab（原来为空则 crontab -r），删除临时目录"
  echo "  4) 无需 root；不联网、不执行真实任务"
  echo "$TC done"
  exit 0
fi

if ! command -v crontab >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 crontab 命令，无法写入 cron 任务"
  exit 0
fi

mkdir -p "$TMP"
WORKDIR="$(mktemp -d "${TMP%/}/hornwork-tc04.XXXXXX")"
HAD_PREV=0
INSTALLED=0

cleanup() {
  set +e
  if [ "$INSTALLED" = "1" ]; then
    if [ "$HAD_PREV" = "1" ]; then
      crontab "$WORKDIR/prev.cron" >/dev/null 2>&1
    else
      crontab -r >/dev/null 2>&1
    fi
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# 备份原 crontab（当前用户可能本来没有任务）
if crontab -l >"$WORKDIR/prev.cron" 2>/dev/null; then
  HAD_PREV=1
fi

{
  if [ "$HAD_PREV" = "1" ]; then
    cat "$WORKDIR/prev.cron"
  fi
  printf '%s\n' "$JOB_LINE"
} >"$WORKDIR/new.cron"

crontab "$WORKDIR/new.cron"
INSTALLED=1

# 保持片刻，确保采集链路看到 crontab 进程事件
sleep 1

echo "$TC 已写入 cron 测试任务（退出时恢复）：$JOB_LINE"

echo "$TC done"

#!/usr/bin/env bash
# TC-08 本地端口扫描（T1046）
#
# 动作：对目标地址的端口区间做快速 TCP connect 扫描（默认 127.0.0.1:1-100），
#       产生大量不同目的端口的 SYN 包，命中 SYN 端口扫描规则 N-0101。
#       只扫描环境变量指定的本地地址，不访问外部网络；不需要 root。
#
# 用法：bash T1046.sh [--run|--dry-run]
set -euo pipefail

TC="TC-08"
TECH="T1046"
PYTHON="${HORNWORK_PYTHON:-python3}"
TARGET="${HORNWORK_TC08_TARGET:-127.0.0.1}"
START="${HORNWORK_TC08_START:-1}"
END="${HORNWORK_TC08_END:-100}"

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
  echo "  1) 对 $TARGET 的端口 $START-$END 做 TCP connect 扫描（产生 SYN 包）"
  echo "  2) 打印开放端口清单；无临时文件、无持久化产物、无需 root"
  echo "  3) 只扫描本地/环境变量指定的地址，不访问外部网络"
  echo "$TC done"
  exit 0
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 $PYTHON，无法执行端口扫描"
  exit 0
fi

cleanup() {
  # TC-08 不落地任何文件，无需恢复动作
  :
}
trap cleanup EXIT

"$PYTHON" - "$TARGET" "$START" "$END" <<'PYEOF'
import socket
import sys

host = sys.argv[1]
start = int(sys.argv[2])
end = int(sys.argv[3])
if start < 1:
    start = 1
if end > 65535:
    end = 65535
if end < start:
    start, end = end, start

open_ports = []
for port in range(start, end + 1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.05)
    try:
        if sock.connect_ex((host, port)) == 0:
            open_ports.append(port)
    except OSError:
        pass
    finally:
        sock.close()
print(f"TC-08 扫描完成：{start}-{end}，开放 {len(open_ports)} 个端口 {open_ports}")
PYEOF

echo "$TC done"

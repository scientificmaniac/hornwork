#!/usr/bin/env bash
# TC-07 C2 心跳外联（情报域名）（T1071.001）
#
# 动作：向本地 DNS 服务器（默认 127.0.0.1:53）发送 IOC 域名 A 查询，命中情报域名
#       出站规则 N-0103；随后向本地目标（默认 127.0.0.1:8080）做心跳式 TCP 连接。
#       所有流量只发往回环/环境变量指定的本地地址，不访问外部网络。
#
# 用法：bash T1071.001.sh [--run|--dry-run]
set -euo pipefail

TC="TC-07"
TECH="T1071.001"
PYTHON="${HORNWORK_PYTHON:-python3}"
TARGET="${HORNWORK_TC07_TARGET:-127.0.0.1}"
PORT="${HORNWORK_TC07_PORT:-8080}"
DNS_SERVER="${HORNWORK_TC07_DNS_SERVER:-127.0.0.1}"
DNS_PORT="${HORNWORK_TC07_DNS_PORT:-53}"
DOMAINS="${HORNWORK_TC07_DOMAINS:-ioc.example c2.example.com ioc.example}"
EXTRA_DOMAIN="${HORNWORK_TC07_DOMAIN:-}"
COUNT="${HORNWORK_TC07_COUNT:-10}"

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
  echo "  1) 向 $DNS_SERVER:$DNS_PORT 发送 IOC 域名 A 查询：${EXTRA_DOMAIN}${EXTRA_DOMAIN:+ }$DOMAINS"
  echo "  2) 向 $TARGET:$PORT 做 $COUNT 次心跳式 TCP 连接（只发往本地地址，不访问外网）"
  echo "  3) 无临时文件、无持久化产物；无需 root"
  echo "$TC done"
  exit 0
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 $PYTHON，无法发送 DNS 查询与心跳"
  exit 0
fi

cleanup() {
  # TC-07 不落地任何文件，无需恢复动作
  :
}
trap cleanup EXIT

# 1) DNS 查询：手工构造标准 A 查询报文（UDP，不等待响应，无需本地 DNS 服务在线）
# shellcheck disable=SC2086
"$PYTHON" - "$DNS_SERVER" "$DNS_PORT" "$EXTRA_DOMAIN" $DOMAINS <<'PYEOF'
import socket
import struct
import sys
import time

server = sys.argv[1]
port = int(sys.argv[2])
domains = [item for item in sys.argv[3:] if item]
if not domains:
    domains = ["ioc.example"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
try:
    for index, name in enumerate(domains):
        labels = b"".join(
            bytes([len(part)]) + part.encode("ascii") for part in name.split(".") if part
        )
        qname = labels + b"\x00"
        header = struct.pack(">HHHHHH", (0x1000 + index) & 0xFFFF, 0x0100, 1, 0, 0, 0)
        packet = header + qname + struct.pack(">HH", 1, 1)
        try:
            sock.sendto(packet, (server, port))
            print(f"TC-07: dns_query sent {name}", flush=True)
        except OSError as exc:  # noqa: BLE001 - 单条失败不影响后续查询
            print(f"TC-07: dns_query failed {name}: {exc}", flush=True)
        time.sleep(0.2)
finally:
    sock.close()
PYEOF

# 2) 心跳：连续 TCP 连接（目标无服务时连接被拒绝，同样产生可观测的出站尝试）
"$PYTHON" - "$TARGET" "$PORT" "$COUNT" <<'PYEOF'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
count = int(sys.argv[3])
ok = 0
for _ in range(count):
    try:
        conn = socket.create_connection((host, port), timeout=1.0)
        conn.close()
        ok += 1
    except OSError:
        pass
    time.sleep(1.0)
print(f"TC-07 心跳完成：成功 {ok}/{count}，目标 {host}:{port}")
PYEOF

echo "$TC done"

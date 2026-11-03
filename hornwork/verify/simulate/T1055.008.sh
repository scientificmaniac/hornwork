#!/usr/bin/env bash
# TC-09 PTRACE 注入演示（T1055.008）
#
# 动作：
#   1) 用 heredoc 写一个无害目标 C 程序并编译：mmap 128KB 匿名 RWX 段 + NOP 填充，
#      打印自身 PID / RWX 段地址 / 注入地址，并连接本地监听、保持存活（memscan 条件 A+B）；
#   2) 用 python 在 127.0.0.1 起本地 TCP 监听并保持连接（端口被占用时自动改用空闲端口）；
#   3) gcc 编译 hornwork/tools/inject_demo.c，用 PTRACE 在目标 RWX 段写入 1 字节 NOP，
#      随即 --restore 回滚原始字节（只写 0x90，不落真实 payload）；
#   4) 注入成功把 pid 写入 $HORNWORK_TMP/hornwork-tc09.pid：
#      HORNWORK_TC09_KEEP=1 时保留目标进程交给 runner 双次 mem.scan，
#      否则脚本自行结束目标进程并删除 pid 文件。
#   不联网外部、不修改系统配置；仅注入脚本自己启动的无害目标进程。
#
# 用法：bash T1055.008.sh [--run|--dry-run]
set -euo pipefail

TC="TC-09"
TECH="T1055.008"
TMP="${HORNWORK_TMP:-/tmp}"
PYTHON="${HORNWORK_PYTHON:-python3}"
KEEP="${HORNWORK_TC09_KEEP:-0}"
HOLD_SEC="${HORNWORK_TC09_HOLD_SEC:-2}"
TARGET_SEC="${HORNWORK_TC09_TARGET_SEC:-20}"
PORT="${HORNWORK_TC09_PORT:-8080}"
PID_FILE="${TMP%/}/hornwork-tc09.pid"

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
  echo "  1) heredoc 写无害目标 C 源码（mmap 128KB RWX + NOP 填充），gcc 编译到 $TMP/hornwork-tc09.XXXXXX/target"
  echo "  2) $PYTHON 在 127.0.0.1:$PORT 起本地 TCP 监听并保持连接（被占用则改用空闲端口）"
  echo "  3) gcc 编译 hornwork/tools/inject_demo.c，PTRACE 注入 1 字节 NOP 后立即 --restore 回滚"
  echo "  4) 写 pid 文件 $PID_FILE；HORNWORK_TC09_KEEP=$KEEP（1=保留目标给 runner 双次 mem.scan，0=自行清理）"
  echo "  5) 只在同 uid 目标进程上操作；无 root 且 ptrace 不可用时输出 SKIP；不联网外部"
  echo "$TC done"
  exit 0
fi

LISTENER_PID=""
TARGET_PID=""
RUN_DIR=""
PIDFILE_WRITTEN=0
KEEP_TARGET=0

cleanup() {
  set +e
  if [ -n "$LISTENER_PID" ] && kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null
    wait "$LISTENER_PID" 2>/dev/null
  fi
  if [ "$KEEP_TARGET" != "1" ] && [ -n "$TARGET_PID" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
    kill "$TARGET_PID" 2>/dev/null
    wait "$TARGET_PID" 2>/dev/null
  fi
  if [ "$KEEP_TARGET" != "1" ] && [ "$PIDFILE_WRITTEN" = "1" ]; then
    rm -f "$PID_FILE" 2>/dev/null
  fi
  if [ -n "$RUN_DIR" ]; then
    rm -rf "$RUN_DIR" 2>/dev/null
  fi
}
trap cleanup EXIT

if [ ! -r /proc/self/maps ]; then
  echo "$TC SKIP: 仅支持 Linux（需要 /proc）"
  exit 0
fi
if ! command -v gcc >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 gcc，无法编译注入演示"
  exit 0
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 $PYTHON，无法起本地监听"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INJECT_SRC="$REPO_ROOT/hornwork/tools/inject_demo.c"
if [ ! -f "$INJECT_SRC" ]; then
  echo "$TC SKIP: 缺少注入演示源码：$INJECT_SRC"
  exit 0
fi

mkdir -p "$TMP"
RUN_DIR="$(mktemp -d "${TMP%/}/hornwork-tc09.XXXXXX")"
INJECT_BIN="$RUN_DIR/inject_demo"
TARGET_BIN="$RUN_DIR/target"
TARGET_SRC="$RUN_DIR/target.c"
STATE="$RUN_DIR/inject.state"

# 编译注入演示工具
if ! gcc -O2 -o "$INJECT_BIN" "$INJECT_SRC" >"$RUN_DIR/gcc-inject.log" 2>&1; then
  echo "$TC SKIP: gcc 编译 inject_demo 失败"
  exit 0
fi

# 无害目标程序：匿名 RWX 段 + NOP 填充 + 本地 TCP 连接（全程不使用该可执行内存）
cat >"$TARGET_SRC" <<'CEOF'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 8080;
    int secs = (argc > 2) ? atoi(argv[2]) : 20;
    size_t size = 128UL * 1024UL;
    unsigned char *rwx;
    unsigned long inject_at;
    int sock = -1;
    struct sockaddr_in addr;

    /* 仅本演示进程：允许同 uid 进程 attach，便于非 root 环境演示 ptrace 注入 */
    (void)prctl(PR_SET_PTRACER, (unsigned long)-1, 0UL, 0UL, 0UL);

    rwx = (unsigned char *)mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rwx == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(rwx, 0x90, size);                       /* NOP 填充：memscan 条件 A 的匿名 RWX 段 */
    inject_at = (unsigned long)(size_t)(rwx + 64); /* 注入点：段内第 64 字节，仍是 NOP */

    printf("PID=%d\n", (int)getpid());
    printf("RWX=0x%lx\n", (unsigned long)(size_t)rwx);
    printf("ADDR=0x%lx\n", inject_at);
    printf("SIZE=%lu\n", (unsigned long)size);
    fflush(stdout);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("CONNECTED=1\n");
        } else {
            printf("CONNECTED=0\n");
        }
    } else {
        printf("CONNECTED=0\n");
    }
    fflush(stdout);

    sleep((unsigned)secs);                         /* 存活期间持有 socket，供 memscan 行为侧观察 */
    if (sock >= 0) {
        close(sock);
    }
    return 0;
}
CEOF

if ! gcc -O2 -o "$TARGET_BIN" "$TARGET_SRC" >"$RUN_DIR/gcc-target.log" 2>&1; then
  echo "$TC SKIP: gcc 编译无害目标程序失败"
  exit 0
fi

# 本地 TCP 监听（只绑回环；端口被占用时改用空闲端口）
"$PYTHON" - "$PORT" >"$RUN_DIR/listener.out" 2>"$RUN_DIR/listener.err" <<'PYEOF' &
import socket
import sys

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    srv.bind(("127.0.0.1", port))
except OSError:
    srv.bind(("127.0.0.1", 0))
srv.listen(1)
print(srv.getsockname()[1], flush=True)
conn, _addr = srv.accept()
while True:                       # 保持连接，直到脚本退出时被 trap 结束
    if not conn.recv(1024):
        break
conn.close()
srv.close()
PYEOF
LISTENER_PID=$!

LISTEN_PORT=""
for _ in $(seq 1 100); do
  if [ -s "$RUN_DIR/listener.out" ]; then
    LISTEN_PORT="$(head -n 1 "$RUN_DIR/listener.out" | tr -cd '0-9')"
    break
  fi
  if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [ -z "$LISTEN_PORT" ]; then
  echo "$TC SKIP: 本地监听启动失败（端口 $PORT）"
  exit 0
fi
echo "$TC 本地监听已就绪：127.0.0.1:$LISTEN_PORT"

# 启动无害目标进程
"$TARGET_BIN" "$LISTEN_PORT" "$TARGET_SEC" >"$RUN_DIR/target.out" 2>&1 &
TARGET_PID=$!

TARGET_PID_VAL=""
TARGET_ADDR=""
TARGET_RWX=""
CONNECTED=""
for _ in $(seq 1 100); do
  if grep -q '^ADDR=' "$RUN_DIR/target.out" 2>/dev/null &&
    grep -q '^CONNECTED=' "$RUN_DIR/target.out" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
TARGET_PID_VAL="$(sed -n 's/^PID=//p' "$RUN_DIR/target.out" 2>/dev/null | head -n 1)"
TARGET_RWX="$(sed -n 's/^RWX=//p' "$RUN_DIR/target.out" 2>/dev/null | head -n 1)"
TARGET_ADDR="$(sed -n 's/^ADDR=//p' "$RUN_DIR/target.out" 2>/dev/null | head -n 1)"
CONNECTED="$(sed -n 's/^CONNECTED=//p' "$RUN_DIR/target.out" 2>/dev/null | head -n 1)"

if [ -z "$TARGET_PID_VAL" ] || [ -z "$TARGET_ADDR" ]; then
  echo "$TC SKIP: 无害目标进程未就绪（可能被提前终止）"
  exit 0
fi
if [ "$CONNECTED" != "1" ]; then
  echo "$TC SKIP: 无害目标未能连上本地监听"
  exit 0
fi

echo "$TC 目标进程已启动（pid=$TARGET_PID_VAL，rwx-anon=128KB，连接 127.0.0.1:$LISTEN_PORT，存活 ${TARGET_SEC}s）"

# 确认目标存在匿名 RWX 段（memscan 条件 A）
if awk '$2 ~ /^rwx/ && NF == 5 {found = 1} END {exit found ? 0 : 1}' "/proc/$TARGET_PID_VAL/maps" 2>/dev/null; then
  echo "$TC target rwx region present"
else
  echo "$TC SKIP: 目标进程未暴露匿名 RWX 段"
  exit 0
fi

# PTRACE 注入 1 字节 NOP（只写 0x90，不落真实 payload）
if ! "$INJECT_BIN" --pid "$TARGET_PID_VAL" --addr "$TARGET_ADDR" --byte nop --state "$STATE" \
  >"$RUN_DIR/inject.log" 2>&1; then
  sed 's/^/  /' "$RUN_DIR/inject.log" >&2 2>/dev/null || true
  echo "$TC SKIP: PTRACE 注入失败（需要同 uid 目标进程；检查 kernel.yama.ptrace_scope）"
  exit 0
fi
echo "$TC 已注入 1 字节 NOP：pid=$TARGET_PID_VAL addr=$TARGET_ADDR"

# 把 pid 交给 runner 做双次 mem.scan
printf '%s\n' "$TARGET_PID_VAL" >"$PID_FILE"
PIDFILE_WRITTEN=1
if [ "$KEEP" = "1" ]; then
  KEEP_TARGET=1
fi

if ! sleep "$HOLD_SEC" 2>/dev/null; then
  sleep 1
fi

# 回滚被改写的字节（目标进程保持存活，行为侧与内存侧仍可被扫描观察）
if "$INJECT_BIN" --pid "$TARGET_PID_VAL" --restore --state "$STATE" >"$RUN_DIR/restore.log" 2>&1; then
  echo "$TC 已回滚原始字节（目标进程保持存活）"
else
  echo "$TC 警告：回滚注入字节失败，详情见 $RUN_DIR/restore.log" >&2
fi

if [ "$KEEP_TARGET" = "1" ]; then
  echo "$TC 注入完成，目标进程保留（pid=$TARGET_PID_VAL，pid 文件=$PID_FILE，供 runner 双次 mem.scan）"
else
  echo "$TC 注入完成（未设置 KEEP=1，退出时清理目标进程与 pid 文件）"
fi

echo "$TC done"

#!/usr/bin/env bash
# TC-02 本地 HTTP 下载 EICAR 样本（T1105）
#
# 动作：在 127.0.0.1 上起一个临时 HTTP 服务（只监听回环），用 curl/wget 下载
#       68 字节标准 EICAR 测试串到临时目录，命中 FIM + 静态扫描 + 下载工具规则。
#       EICAR 是公开的杀毒软件测试串（非恶意代码）；下载物保留供扫描复核，
#       下次运行开始时自动清理上一次的样本。
#
# 用法：bash T1105.sh [--run|--dry-run]
set -euo pipefail

TC="TC-02"
TECH="T1105"
TMP="${HORNWORK_TMP:-/tmp}"
PYTHON="${HORNWORK_PYTHON:-python3}"
PORT="${HORNWORK_TC02_PORT:-18080}"
TARGET="${TMP%/}/hornwork-tc02-eicar.com"

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
  echo "  1) 在 $TMP 建临时目录，写入 68 字节标准 EICAR 测试串（公开杀软测试串，非恶意代码）"
  echo "  2) $PYTHON -m http.server $PORT --bind 127.0.0.1（只监听回环，不对外）"
  echo "  3) curl/wget 下载 http://127.0.0.1:$PORT/eicar.com 到 $TARGET"
  echo "  4) 打印 sha256 后保留样本供静态扫描复核；退出时关闭 HTTP 服务并删临时目录"
  echo "$TC done"
  exit 0
fi

HTTP_PID=""
WEBROOT=""

cleanup() {
  set +e
  if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
    kill "$HTTP_PID" 2>/dev/null
    wait "$HTTP_PID" 2>/dev/null
  fi
  if [ -n "$WEBROOT" ]; then
    rm -rf "$WEBROOT"
  fi
}
trap cleanup EXIT

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "$TC SKIP: 缺少 $PYTHON，无法起本地 HTTP 服务"
  exit 0
fi
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  echo "$TC SKIP: 缺少 curl/wget，无法下载样本"
  exit 0
fi

mkdir -p "$TMP"
WEBROOT="$(mktemp -d "${TMP%/}/hornwork-tc02.XXXXXX")"

# 标准 EICAR 测试串：68 字节，公开杀软测试文件，非恶意代码（不追加换行）
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$WEBROOT/eicar.com"

# 清理上次运行留下的样本，确保本次是新的文件落地事件
rm -f "$TARGET" 2>/dev/null || true

"$PYTHON" -m http.server "$PORT" --bind 127.0.0.1 --directory "$WEBROOT" >/dev/null 2>&1 &
HTTP_PID=$!

# 等本地 HTTP 就绪（最多约 10s），期间完成下载
READY=0
for _ in $(seq 1 100); do
  if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    break
  fi
  if [ "$DOWNLOADER" = "curl" ]; then
    if curl -fsS --max-time 2 -o "$TARGET" "http://127.0.0.1:$PORT/eicar.com" 2>/dev/null; then
      READY=1
      break
    fi
  else
    if wget -q -T 2 -O "$TARGET" "http://127.0.0.1:$PORT/eicar.com" 2>/dev/null; then
      READY=1
      break
    fi
  fi
  sleep 0.1
done

if [ "$READY" -ne 1 ]; then
  echo "$TC SKIP: 本地 HTTP 服务未就绪（端口 $PORT 可能被占用）"
  exit 0
fi

SIZE="$(wc -c <"$TARGET" | tr -d ' ')"
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(sha256sum "$TARGET" | awk '{print $1}')"
else
  SHA="$("$PYTHON" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TARGET")"
fi

echo "$SHA  $TARGET"
echo "$TC 已下载 EICAR 样本：$TARGET（大小 ${SIZE} 字节，保留供静态扫描复核）"

echo "$TC done"

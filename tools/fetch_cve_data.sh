#!/usr/bin/env bash
# 扫描模块 CVE 数据抓取（测试主机可复现）：NVD 2.0 API 定向子集 + Ubuntu OVAL 全量。
#
# 背景：NVD 官方年文件（nvdcve-2.0-YYYY.json.gz）单文件 20~30 MB，国内直连常限速/停滞；
# 本脚本改用 **NVD API 2.0 的 virtualMatchString** 按组件定向抓取，数据仍是官方 NVD
# 的完整 CVE 对象（含 configurations / cpeMatch / 版本区间 / CVSS），只是**按需子集**。
# 这样既保证数据真实，又把体积压到十几 MB，适合测试环境的磁盘/网络预算。
#
# 用法：
#   sudo bash tools/fetch_cve_data.sh [/var/lib/hornwork/feed]
#
# 产物：
#   <OUT>/nvd-subset/<vendor>-<product>-<startIndex>.json   （NVD 2.0 结构，可直接导入）
#   <OUT>/oval/com.ubuntu.noble.cve.oval.xml.bz2            （Ubuntu 24.04 noble OVAL）
#
# 导入：
#   hornworkctl scan cve import --source nvd --dir <OUT>/nvd-subset
#   hornworkctl scan cve import --source oval --file <OUT>/oval/com.ubuntu.noble.cve.oval.xml.bz2 --release noble
set -euo pipefail

OUT="${1:-/var/lib/hornwork/feed}"
SUB="${OUT}/nvd-subset"
OVAL_DIR="${OUT}/oval"
mkdir -p "$SUB" "$OVAL_DIR"

# 组件清单：与 nmap 实际识别出的服务 / 靶场组件对应（vendor:product）
COMPONENTS=(
  "grafana:grafana"
  "nginx:nginx"
  "f5:nginx"
  "openbsd:openssh"
  "redis:redis"
  "openprinting:cups"
  "apple:cups"
  "gunicorn:gunicorn"
  "apache:http_server"
  "openssl:openssl"
)
PAGE=2000
SLEEP=7          # NVD 无 API key 限速：5 请求 / 30 秒

echo "== 抓取 NVD 2.0 组件子集（$OUT）"
for pair in "${COMPONENTS[@]}"; do
  vendor="${pair%%:*}"
  product="${pair##*:}"
  start=0
  while :; do
    file="${SUB}/${vendor}-${product}-${start}.json"
    if [[ -s "$file" ]]; then
      echo "  [skip] $vendor:$product start=$start"
    else
      url="https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:${vendor}:${product}&resultsPerPage=${PAGE}&startIndex=${start}"
      echo "  [get ] $vendor:$product start=$start"
      if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 120 -o "$file" "$url"; then
        echo "  [fail] $vendor:$product start=$start（跳过该页）" >&2
        rm -f "$file"
        break
      fi
      sleep "$SLEEP"
    fi
    total=$(python3 - "$file" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        print(int(json.load(fh).get("totalResults") or 0))
except Exception:
    print(0)
PY
)
    start=$((start + PAGE))
    if [[ "$start" -ge "$total" ]]; then
      echo "    -> total=$total，完成"
      break
    fi
  done
done

echo "== 抓取 Ubuntu OVAL（noble）"
OVAL_FILE="${OVAL_DIR}/com.ubuntu.noble.cve.oval.xml.bz2"
if [[ -s "$OVAL_FILE" ]]; then
  echo "  [skip] $OVAL_FILE"
else
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 900 \
    -o "$OVAL_FILE" \
    "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2"
fi
ls -lh "$OVAL_FILE"
echo "== 完成。文件数：$(find "$SUB" -name '*.json' | wc -l)"

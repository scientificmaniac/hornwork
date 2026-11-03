#!/usr/bin/env bash
# =============================================================================
# Hornwork 一条命令演示
#
# 流程：rules reload → TC-02 本地 HTTP 下载 EICAR 到 /tmp → 等 5 s →
#       alerts → case list → verify run → export md → 打印报告路径与关键证据。
#
# 用法：
#   sudo bash scripts/demo.sh
#   HORNWORK_HOME=/opt/hornwork sudo -E bash scripts/demo.sh
# 说明：
#   - 仅使用 EICAR 无害测试串与本地 127.0.0.1 HTTP，不访问外网；
#   - 下载文件保留在 /tmp/hornwork-demo-eicar.com 作为证据，可手动删除；
#   - 非关键步骤（case/verify/export）失败只告警，不中断演示。
# =============================================================================
set -euo pipefail

HORNWORK_HOME="${HORNWORK_HOME:-/opt/hornwork}"
VENV="${HORNWORK_VENV:-/opt/hornwork-venv}"
CONFIG="${HORNWORK_CONFIG:-$HORNWORK_HOME/config.toml}"
HTTP_PORT="${HORNWORK_DEMO_PORT:-18080}"
EICAR_PATH="${HORNWORK_DEMO_EICAR:-/tmp/hornwork-demo-eicar.com}"
WORK_DIR="${TMPDIR:-/tmp}/hornwork-demo-$$"
HTTP_PID=""

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_END=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$C_OK" "$*" "$C_END"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_END" "$*" >&2; }
die()  { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_END" "$*" >&2; exit 1; }

cleanup() {
  if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. 解析 hornworkctl 与配置
# ---------------------------------------------------------------------------
if command -v hornworkctl >/dev/null 2>&1; then
  CTL=(hornworkctl)
elif [ -x "$VENV/bin/python" ] && [ -d "$HORNWORK_HOME/hornwork" ]; then
  CTL=("$VENV/bin/python" -m hornwork.cli)
  export PYTHONPATH="$HORNWORK_HOME${PYTHONPATH:+:$PYTHONPATH}"
else
  die "找不到 hornworkctl，也未找到 $VENV 与 $HORNWORK_HOME/hornwork；请先运行 scripts/setup.sh"
fi
[ -f "$CONFIG" ] || warn "配置文件不存在：$CONFIG（将使用 CLI 默认值）"
CTL+=(-c "$CONFIG")

step "0) 前置检查：$(${CTL[@]} --version 2>/dev/null || echo 'hornworkctl')"
if ! ${CTL[@]} status >/dev/null 2>&1; then
  die "daemon 未运行或 ctl.sock 不可用：先 sudo systemctl start ${HORNWORK_SERVICE:-hornwork}，再查看 journalctl -u hornwork -n 50"
fi
mkdir -p "$WORK_DIR"

# ---------------------------------------------------------------------------
# 1. 规则热加载
# ---------------------------------------------------------------------------
step "1) 热加载规则（YARA / 网络 / 主机 / Sigma / 情报）"
${CTL[@]} rules reload || warn "rules reload 失败（继续演示，可能是某项规则目录为空）"

# ---------------------------------------------------------------------------
# 1.5 验证套件：先跑验证（保证每个用例的时间窗内没有同规则去重干扰），
#     再演示 EICAR 下载/扫描。同一分钟内重复跑两遍 verify 会受 60s 去重窗影响。
# ---------------------------------------------------------------------------
step "2) 运行验证套件（baseline：TC-01..TC-10 + TC-N1）"
${CTL[@]} verify run --suite baseline || warn "verify run 失败或不完整（演示继续）"

# ---------------------------------------------------------------------------
# 2. TC-02：本地 HTTP 下载 EICAR 到 /tmp（T1105）
# ---------------------------------------------------------------------------
step "2) TC-02 下载 EICAR 测试文件到 /tmp（T1105）"
printf '%s\n' 'HORNWORK-PLACEHOLDER-TEST-FILE' > "$WORK_DIR/eicar.com"   # 收尾清理：已移除 EICAR 载荷
printf '下载前 /tmp 样本不存在：%s\n' "$([ ! -e "$EICAR_PATH" ] && echo yes || echo 'no（将被覆盖）')"

python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WORK_DIR" >/dev/null 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 30); do
  if curl -fsS --max-time 1 "http://127.0.0.1:$HTTP_PORT/eicar.com" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
if ! kill -0 "$HTTP_PID" 2>/dev/null; then
  die "本地 HTTP 服务启动失败（端口 $HTTP_PORT 可能被占用，可用 HORNWORK_DEMO_PORT=18081 重跑）"
fi
printf '本地 HTTP 服务：http://127.0.0.1:%s/eicar.com  pid=%s\n' "$HTTP_PORT" "$HTTP_PID"

if command -v wget >/dev/null 2>&1; then
  wget -q -O "$EICAR_PATH" "http://127.0.0.1:$HTTP_PORT/eicar.com" || die "wget 下载失败"
elif command -v curl >/dev/null 2>&1; then
  curl -fsS -o "$EICAR_PATH" "http://127.0.0.1:$HTTP_PORT/eicar.com" || die "curl 下载失败"
else
  python3 - "$HTTP_PORT" "$EICAR_PATH" <<'PY' || die "python urllib 下载失败"
import sys, urllib.request
port, out = sys.argv[1], sys.argv[2]
urllib.request.urlretrieve(f"http://127.0.0.1:{port}/eicar.com", out)
PY
fi
[ -s "$EICAR_PATH" ] || die "下载后文件为空：$EICAR_PATH"
printf '已下载：%s  大小=%s  sha256=%s\n' "$EICAR_PATH" "$(stat -c %s "$EICAR_PATH")" "$(sha256sum "$EICAR_PATH" | cut -d' ' -f1)"
printf '期望 sha256：275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f（EICAR）\n'

# 主动触发一次级联扫描，确保证据链完整（file 事件自动扫描为补充）
step "2b) 手动扫描样本（sigdb/yara/clamav 级联）"
${CTL[@]} scan "$EICAR_PATH" --deep || warn "scan 失败（继续）"

# ---------------------------------------------------------------------------
# 3. 等待采集/检测流水线
# ---------------------------------------------------------------------------
step "3) 等待 5 s，让 FIM/auditd/静态扫描写入事件与告警"
sleep 5

# ---------------------------------------------------------------------------
# 4. 查询告警与工单
# ---------------------------------------------------------------------------
step "4) 最近 5 分钟告警"
${CTL[@]} alerts --since 5m --limit 50 || warn "alerts 查询失败"
ALERTS_JSON="$WORK_DIR/alerts.json"
${CTL[@]} --json alerts --since 5m --limit 200 > "$ALERTS_JSON" 2>/dev/null || true

step "5) 工单列表"
${CTL[@]} case list || warn "case list 失败"

# ---------------------------------------------------------------------------
# 5. 导出
# ---------------------------------------------------------------------------
step "7) 导出 Markdown 报告"
OUT_DIR="$HORNWORK_HOME/reports/demo-$(date +%Y%m%d-%H%M%S)"
# 报告由 daemon（hornwork 用户）写入，目录必须归 hornwork 所有
install -d -m 0750 -o hornwork -g hornwork "$OUT_DIR" 2>/dev/null || mkdir -p "$OUT_DIR"
${CTL[@]} export --format md --out "$OUT_DIR" || warn "export 失败（演示继续）"
chown -R hornwork:hornwork "$HORNWORK_HOME/reports" 2>/dev/null || true
REPORT_FILE="$(find "$OUT_DIR" -maxdepth 1 -type f \( -name '*.md' -o -name '*.jsonl' \) -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)"

# ---------------------------------------------------------------------------
# 6. 关键证据摘要
# ---------------------------------------------------------------------------
step "8) 关键证据摘要"
python3 - "$ALERTS_JSON" "$EICAR_PATH" <<'PY' || warn "证据摘要生成失败（不影响主流程）"
import json
import sys

path, eicar = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    data = {}
alerts = data.get("alerts") or data.get("data") or []
print(f"本窗口告警数：{len(alerts)}")
rules = {}
levels = {}
for a in alerts:
    rule = (a.get("rule") or {}).get("id") or "unknown"
    rules[rule] = rules.get(rule, 0) + 1
    lv = a.get("level")
    levels[lv] = levels.get(lv, 0) + 1
print("按规则统计：" + ("，".join(f"{k}×{v}" for k, v in sorted(rules.items())) or "（空）"))
print("按级别统计：" + ("，".join(f"L{k}×{v}" for k, v in sorted(levels.items(), key=lambda x: (x[0] is None, x[0])))))
keywords = ("eicar", "EICAR", "sigdb", "yara", "T1105")
hits = [a for a in alerts if any(k in json.dumps(a, ensure_ascii=False) for k in keywords)]
print(f"含 EICAR/sigdb/yara/T1105 关键词的告警：{len(hits)} 条")
shown = 0
for a in hits:
    rule = (a.get("rule") or {})
    print(f"  - L{a.get('level')} [{rule.get('engine')}] {rule.get('id')} {rule.get('name')}")
    shown += 1
    if shown >= 8:
        print("  - ...（更多见 alerts 输出）")
        break
PY
printf '样本路径：%s\n' "$EICAR_PATH"

if [ -n "${REPORT_FILE:-}" ]; then
  step "报告路径：$REPORT_FILE"
else
  warn "未找到导出报告文件，目录：$OUT_DIR"
  ls -l "$OUT_DIR" 2>/dev/null || true
fi
step "演示完成"

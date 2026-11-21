#!/usr/bin/env bash
# gen_cli_baseline.sh — 采集 hornwork CLI 行为基线（仓库无关：用 HORNWORK_REPO 指定）
#
# 只执行固定清单中的命令；不修改仓库源码。
# 每条命令统一：cd <REPO> -> 统一解释器 -> 超时 60s -> 捕获 exit/stdout/stderr。
#
# 用法：
#   HORNWORK_REPO=/tmp/orig-repo BASELINE_DATA_DIR=/tmp/d1 bash gen_cli_baseline.sh /tmp/base-orig.txt
#   HORNWORK_REPO=~/hornwork   BASELINE_DATA_DIR=/tmp/d2 bash gen_cli_baseline.sh /tmp/base-new.txt
#
#   必须指定 BASELINE_DATA_DIR（可写目录）：远端默认 data_dir=/var/lib/hornwork
#   不可写，否则多数 DB 命令会在做任何业务逻辑前就 PermissionError 退出。
#
# 安全边界：清单内不含 prune、真实 lab up、成功态 respond、真实扫描与 sudo。
#   - `scan run`（不带 --profile/--plan）在 CLI 层直接 return 2，不会扫描；
#   - `scan run --profile quick --check-only`：重构前 check_only 未被透传（既有缺陷），
#     本环境台账为空且目标不在 allow_cidrs 内，闸门直接拒绝，实际未发生扫描。
#   - 写入动作仅限：scan plan add/enable/disable/rm、asset add、export 产物。

set -u

REPO="${HORNWORK_REPO:?必须指定 HORNWORK_REPO}"
OUT="${1:?必须指定输出文件}"
DATA_DIR_OVERRIDE="${BASELINE_DATA_DIR:?必须指定 BASELINE_DATA_DIR}"
ART="/tmp/cli-baseline-artifacts"
PY="./venv/bin/python"
MOD="hornwork.cli"
TMO=60

mkdir -p "$ART" "$DATA_DIR_OVERRIDE"
cd "$REPO" || { echo "无法进入 $REPO" >&2; exit 1; }

CLEAN=(env -u HORNWORK_RAW_DIR -u HORNWORK_RULE_DIR -u HORNWORK_LOG -u HORNWORK_TOKEN
       HORNWORK_DATA_DIR="$DATA_DIR_OVERRIDE")

: > "$OUT"
SO="$(mktemp)"
SE="$(mktemp)"
trap 'rm -f "$SO" "$SE"' EXIT

TOTAL=0
TIMEOUTS=0

cat_block() {
  local f="$1"
  [ -s "$f" ] || return 0
  cat "$f"
  [ -n "$(tail -c 1 "$f")" ] && printf '\n'
  return 0
}

run_case() {
  local cmdline="$1"; shift
  TOTAL=$((TOTAL + 1))
  : > "$SO"; : > "$SE"
  local rc
  if [ "$#" -eq 0 ]; then
    timeout "$TMO" "${CLEAN[@]}" $PY -m "$MOD" >"$SO" 2>"$SE"; rc=$?
  else
    timeout "$TMO" "${CLEAN[@]}" $PY -m "$MOD" "$@" >"$SO" 2>"$SE"; rc=$?
  fi
  local exit_label
  if [ "$rc" -eq 124 ]; then exit_label="TIMEOUT"; TIMEOUTS=$((TIMEOUTS + 1)); else exit_label="$rc"; fi
  {
    printf '#### CMD: %s\n' "$cmdline"
    printf '#### EXIT: %s\n' "$exit_label"
    printf '#### STDOUT\n'; cat_block "$SO"
    printf '#### STDERR\n'; cat_block "$SE"
    printf '#### END\n\n'
  } >>"$OUT"
}

run_case "./venv/bin/python -m hornwork.cli --version" --version
run_case "./venv/bin/python -m hornwork.cli"
run_case "./venv/bin/python -m hornwork.cli badcmd" badcmd
run_case "./venv/bin/python -m hornwork.cli status" status
run_case "./venv/bin/python -m hornwork.cli status --json" status --json
run_case "./venv/bin/python -m hornwork.cli events --limit 3" events --limit 3
run_case "./venv/bin/python -m hornwork.cli events --limit 3 --json" events --limit 3 --json
run_case "./venv/bin/python -m hornwork.cli alerts --limit 3" alerts --limit 3
run_case "./venv/bin/python -m hornwork.cli alerts --limit 3 --level 3" alerts --limit 3 --level 3
run_case "./venv/bin/python -m hornwork.cli rules list" rules list
run_case "./venv/bin/python -m hornwork.cli rules reload" rules reload
run_case "./venv/bin/python -m hornwork.cli intel list --limit 3" intel list --limit 3
run_case "./venv/bin/python -m hornwork.cli intel import /nonexistent/iocs.txt" intel import /nonexistent/iocs.txt
run_case "./venv/bin/python -m hornwork.cli case list --limit 3" case list --limit 3
run_case "./venv/bin/python -m hornwork.cli case show NO-SUCH-CASE" case show NO-SUCH-CASE
run_case "./venv/bin/python -m hornwork.cli case create --alert NO-SUCH-ALERT" case create --alert NO-SUCH-ALERT
run_case "./venv/bin/python -m hornwork.cli respond --case NO-SUCH-CASE" respond --case NO-SUCH-CASE
run_case "./venv/bin/python -m hornwork.cli mem scan --pid 1" mem scan --pid 1
run_case "./venv/bin/python -m hornwork.cli mem verify --snapshot /nonexistent" mem verify --snapshot /nonexistent
run_case "./venv/bin/python -m hornwork.cli audit verify" audit verify
run_case "./venv/bin/python -m hornwork.cli forensics collect" forensics collect
run_case "./venv/bin/python -m hornwork.cli export --format jsonl --limit 3 --out /tmp/cli-baseline-artifacts/export1" export --format jsonl --limit 3 --out /tmp/cli-baseline-artifacts/export1
run_case "./venv/bin/python -m hornwork.cli scan status" scan status
run_case "./venv/bin/python -m hornwork.cli scan findings --limit 3" scan findings --limit 3
run_case "./venv/bin/python -m hornwork.cli scan finding set --id NO-SUCH --status confirmed" scan finding set --id NO-SUCH --status confirmed
run_case "./venv/bin/python -m hornwork.cli scan plan list" scan plan list
run_case "./venv/bin/python -m hornwork.cli scan plan add --id cli-baseline-plan --kind manual --profile weekly" scan plan add --id cli-baseline-plan --kind manual --profile weekly
run_case "./venv/bin/python -m hornwork.cli scan plan enable --plan-id cli-baseline-plan" scan plan enable --plan-id cli-baseline-plan
run_case "./venv/bin/python -m hornwork.cli scan plan disable --plan-id cli-baseline-plan" scan plan disable --plan-id cli-baseline-plan
run_case "./venv/bin/python -m hornwork.cli scan plan rm --plan-id cli-baseline-plan" scan plan rm --plan-id cli-baseline-plan
run_case "./venv/bin/python -m hornwork.cli scan diff" scan diff
run_case "./venv/bin/python -m hornwork.cli scan coverage" scan coverage
run_case "./venv/bin/python -m hornwork.cli scan snapshot list" scan snapshot list
run_case "./venv/bin/python -m hornwork.cli scan snapshot base --id NO-SUCH-SNAP" scan snapshot base --id NO-SUCH-SNAP
run_case "./venv/bin/python -m hornwork.cli scan cve stats" scan cve stats
run_case "./venv/bin/python -m hornwork.cli scan retry --run NO-SUCH-RUN" scan retry --run NO-SUCH-RUN
run_case "./venv/bin/python -m hornwork.cli scan cancel --run NO-SUCH-RUN" scan cancel --run NO-SUCH-RUN
run_case "./venv/bin/python -m hornwork.cli scan run --profile quick --check-only" scan run --profile quick --check-only
run_case "./venv/bin/python -m hornwork.cli scan run" scan run
run_case "./venv/bin/python -m hornwork.cli scan file /nonexistent.bin" scan file /nonexistent.bin
run_case "./venv/bin/python -m hornwork.cli asset list" asset list
run_case "./venv/bin/python -m hornwork.cli asset show NO-SUCH-ASSET" asset show NO-SUCH-ASSET
run_case "./venv/bin/python -m hornwork.cli asset add --ip 10.99.99.99 --role server" asset add --ip 10.99.99.99 --role server
run_case "./venv/bin/python -m hornwork.cli asset disable NO-SUCH-ASSET" asset disable NO-SUCH-ASSET
run_case "./venv/bin/python -m hornwork.cli lab list --limit 3" lab list --limit 3
run_case "./venv/bin/python -m hornwork.cli lab status" lab status
run_case "./venv/bin/python -m hornwork.cli lab up NO-SUCH-ENV --ttl 1" lab up NO-SUCH-ENV --ttl 1
run_case "./venv/bin/python -m hornwork.cli lab down NO-SUCH-ENV" lab down NO-SUCH-ENV
run_case "./venv/bin/python -m hornwork.cli lab logs NO-SUCH-ENV --tail 5" lab logs NO-SUCH-ENV --tail 5
run_case "./venv/bin/python -m hornwork.cli lab isolate NO-SUCH-ENV" lab isolate NO-SUCH-ENV
run_case "./venv/bin/python -m hornwork.cli vuln list --limit 3" vuln list --limit 3
run_case "./venv/bin/python -m hornwork.cli vuln show NO-SUCH-VULN" vuln show NO-SUCH-VULN
run_case "./venv/bin/python -m hornwork.cli vuln match --component nginx --version 1.18.0" vuln match --component nginx --version 1.18.0
run_case "./venv/bin/python -m hornwork.cli vuln record sync" vuln record sync
run_case "./venv/bin/python -m hornwork.cli vuln report --format md --out /tmp/cli-baseline-artifacts/vulnreport" vuln report --format md --out /tmp/cli-baseline-artifacts/vulnreport
run_case "./venv/bin/python -m hornwork.cli auth version" auth version
run_case "./venv/bin/python -m hornwork.cli auth user list" auth user list
run_case "./venv/bin/python -m hornwork.cli auth user show nobody" auth user show nobody
run_case "./venv/bin/python -m hornwork.cli auth policy show" auth policy show
run_case "./venv/bin/python -m hornwork.cli auth audit tail --limit 3" auth audit tail --limit 3
run_case "./venv/bin/python -m hornwork.cli auth session list --limit 3" auth session list --limit 3
run_case "./venv/bin/python -m hornwork.cli auth bench-argon2 --rounds 1" auth bench-argon2 --rounds 1
run_case "./venv/bin/python -m hornwork.cli verify run --suite baseline --no-execute" verify run --suite baseline --no-execute

printf '完成：%d 条命令 -> %s（TIMEOUT %d）\n' "$TOTAL" "$OUT" "$TIMEOUTS"

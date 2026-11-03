#!/usr/bin/env bash
# 认证模块：三因子认证一键演示（真实执行、真实输出；证据存 reports/auth/）
# 覆盖：口令+TOTP 登录（LOA2）→ 风险驱动强制 LOA3（口令+TOTP+人脸）→
#       TOTP 重放拒绝 → 5 次错口令锁定 → 人脸缺失时降级 LOA2 → 审计链校验。
#
# 安全注意：TOTP 共享密钥只经 stdin 传给 python（不进 argv / shell history），
# 因为检测模块 的 auditd 采集器会记录 execve 命令行——这是"密钥不落命令行"的实证。
set -uo pipefail

HORNWORK_HOME="${HORNWORK_HOME:-/opt/hornwork}"
VENV="${HORNWORK_VENV:-/opt/hornwork-venv}"
CFG="${HORNWORK_CONFIG:-$HORNWORK_HOME/config.toml}"
OUT="${DEMO_OUT:-$HORNWORK_HOME/reports/auth}"
PY="$VENV/bin/python"
export PYTHONPATH="$HORNWORK_HOME${PYTHONPATH:+:$PYTHONPATH}"
RUN="${DEMO_RUN:-$(date +%H%M%S)}"
U="${DEMO_USER:-m4demo-$RUN}"
U2="${DEMO_USER2:-m4demo2-$RUN}"
PW="${DEMO_PASSWORD:-Demo-Passw0rd-2026}"
IOC_IP="203.0.113.66"
DB="/var/lib/hornwork/hornwork.db"

mkdir -p "$OUT" 2>/dev/null || true
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT/demo-$TS.log"
TMP="$OUT/.tmp-demo-$TS"
mkdir -p "$TMP" && chmod 755 "$TMP"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

exec > >(tee -a "$LOG") 2>&1
SC() { sudo -u hornwork hornworkctl --config "$CFG" "$@"; }
step() { printf '\n\033[1m===== %s =====\033[0m\n' "$*"; }
note() { printf '[i] %s\n' "$*"; }
# 从 stdin 读 Base32 密钥，生成当前/偏移时间步的动态码（密钥不进命令行）
gen_code() {
  "$PY" -c '
import sys, time
from hornwork.auth.totp import from_b32, totp
secret = from_b32(sys.stdin.read().strip())
print(totp(secret, at=time.time() + float(sys.argv[1])))
' "${1:-0}"
}

step "0. 环境与建表（幂等）"
SC auth db init | tail -3
note "清理历史演示账号（本轮账号：$U / $U2；审计链保留）"
sudo -u hornwork sqlite3 "$DB" \
  "PRAGMA foreign_keys=ON; DELETE FROM auth_user
     WHERE username LIKE 'm4demo%' AND username NOT IN ('$U','$U2');" 2>/dev/null || true
note "日志：$LOG"

step "1. 创建演示账号 $U（口令走 stdin，不进 argv/shell history）"
if SC auth user show "$U" >/dev/null 2>&1; then
  note "账号已存在，先清理旧因子以保证幂等"
  SC auth otp revoke "$U" >/dev/null 2>&1
  SC auth biometric delete "$U" >/dev/null 2>&1
else
  printf '%s\n' "$PW" | SC auth user add "$U" --display "认证模块演示账号" --password-stdin
fi

step "2. 注册 TOTP（自研 RFC 6238）并用当前码激活"
SC --json auth otp enroll "$U" > "$TMP/otp.json"
chmod 644 "$TMP/otp.json"
SECRET=$("$PY" -c "import json;print(json.load(open('$TMP/otp.json'))['secret_b32'])")
URI=$("$PY" -c "import json;print(json.load(open('$TMP/otp.json'))['uri'])")
note "共享密钥（Base32，演示账号）：$SECRET"
note "otpauth URI：$URI"
CODE=$(printf '%s' "$SECRET" | gen_code 0)
note "当前动态码：$CODE"
SC auth otp confirm "$U" --code "$CODE"

step "3. 注册人脸模板（可撤销正交变换 + AES-256-GCM；合成向量演示链路）"
"$PY" - "$TMP" <<'PY'
import json, math, sys
from hornwork.auth import biometric
base = biometric.l2_normalize(
    [math.sin(i * 0.11) + 0.3 * math.cos(i * 0.037) for i in range(512)])
json.dump(base, open(sys.argv[1] + "/enroll.json", "w"))
json.dump(biometric.noise_variant(base, 0.02, seed=7),
          open(sys.argv[1] + "/verify.json", "w"))
other = biometric.l2_normalize(
    [math.sin(i * 0.93) + 0.2 * math.cos(i * 0.51) for i in range(512)])
json.dump(other, open(sys.argv[1] + "/other.json", "w"))
PY
chmod 644 "$TMP"/*.json
note "（真实部署把 --embedding 换成远程人脸服务的 512 维 ArcFace 输出，见文档边界）"
SC --json auth biometric enroll "$U" --embedding "$TMP/enroll.json"
SC --json auth biometric verify "$U" --embedding "$TMP/verify.json" || true
note "异人向量应被拒绝："
SC --json auth biometric verify "$U" --embedding "$TMP/other.json" || true
SC auth user show "$U" | grep -E 'has_totp|has_bio|password_algo' || true

step "4. LOA2 登录：口令 + TOTP（低风险，2 因子）"
note "（幂等处理：沿用上次成功登录的 IP，避免 IP 段变化加分把本次推到 LOA3）"
LASTIP=$(sudo -u hornwork sqlite3 "$DB" \
  "SELECT ip FROM auth_audit WHERE username='$U' AND event='logon' AND result='ok'
     ORDER BY id DESC LIMIT 1;" 2>/dev/null)
LASTIP="${LASTIP:-10.0.0.5}"
CODE=$(printf '%s' "$SECRET" | gen_code 0)
printf '%s\n' "$PW" | SC --json auth login "$U" --ip "$LASTIP" --totp "$CODE" \
  > "$TMP/login2.json" || true
chmod 644 "$TMP/login2.json"
"$PY" - "$TMP/login2.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(json.dumps({k: r.get(k) for k in ("status", "loa", "loa_name", "factors", "risk")},
                 ensure_ascii=False, indent=2))
print("token:", (r.get("token") or "")[:24] + "...")
PY

step "5. 风险驱动强制 LOA3：命中 IP 情报（+30）→ 口令+TOTP+人脸"
sudo -u hornwork sqlite3 "$DB" \
  "INSERT OR REPLACE INTO ioc(ioc_id,type,value,confidence,tlp,source,status,whitelisted)
   VALUES('m4-demo-ioc','ip','$IOC_IP',90,'amber','auth-demo','active',0);" 2>/dev/null \
  || note "ioc 写入失败（可忽略）"
CODE3=$(printf '%s' "$SECRET" | gen_code 30)
printf '%s\n' "$PW" | SC --json auth login "$U" --ip "$IOC_IP" --totp "$CODE3" \
  --embedding "$TMP/verify.json" > "$TMP/login3.json" || true
chmod 644 "$TMP/login3.json"
"$PY" - "$TMP/login3.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(json.dumps({k: r.get(k) for k in
                  ("status", "loa", "loa_name", "factors", "risk", "similarity",
                   "degraded", "latency_ms")}, ensure_ascii=False, indent=2))
PY

step "6. TOTP 重放：同一动态码第二次提交必须失败"
printf '%s\n' "$PW" | SC --json auth login "$U" --ip "$IOC_IP" --totp "$CODE3" \
  --embedding "$TMP/verify.json" || note "已拒绝（预期）"

step "7. 暴力破解：5 次错口令 → 锁定 15 min"
for i in 1 2 3 4 5; do
  printf 'Wrong-Passw0rd-2026\n' | SC --json auth login "$U" --ip 10.0.0.9 >/dev/null 2>&1 \
    || note "第 $i 次失败（预期）"
done
SC auth user show "$U" | grep -E 'failed_count|locked_until' || true
note "锁定后用正确口令也必须失败（统一错误码，不泄露锁定状态）："
printf '%s\n' "$PW" | SC --json auth login "$U" --ip "$LASTIP" --totp \
  "$(printf '%s' "$SECRET" | gen_code 0)" || true
SC auth user unlock "$U"
SC auth user show "$U" | grep -E 'failed_count|locked_until' || true

step "8. 降级可观测：未注册人脸的用户遇高风险 → LOA2 + degraded"
if ! SC auth user show "$U2" >/dev/null 2>&1; then
  printf '%s\n' "$PW" | SC auth user add "$U2" --password-stdin
fi
SC auth otp revoke "$U2" >/dev/null 2>&1
SC --json auth otp enroll "$U2" > "$TMP/otp2.json"
chmod 644 "$TMP/otp2.json"
SECRET2=$("$PY" -c "import json;print(json.load(open('$TMP/otp2.json'))['secret_b32'])")
SC auth otp confirm "$U2" --code "$(printf '%s' "$SECRET2" | gen_code 0)"
printf '%s\n' "$PW" | SC --json auth login "$U2" --ip "$IOC_IP" --totp \
  "$(printf '%s' "$SECRET2" | gen_code 0)" > "$TMP/degraded.json" || true
chmod 644 "$TMP/degraded.json"
"$PY" - "$TMP/degraded.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(json.dumps({k: r.get(k) for k in
                  ("status", "loa", "degraded", "degrade_reason", "factors")},
                 ensure_ascii=False, indent=2))
PY

step "9. 审计与事件：哈希链 + 检测模块 事件总线（source_product=hornwork-auth）"
SC auth audit verify-chain
SC auth audit summary --since 1h
note "事件表里的认证记录（检测模块 同一张 event 表）："
sudo -u hornwork sqlite3 "$DB" \
  "SELECT event_type, host_id,
          json_extract(payload,'\$.user.name') AS user,
          json_extract(payload,'\$.raw.auth.loa') AS loa,
          json_extract(payload,'\$.raw.auth.degraded') AS degraded,
          json_extract(payload,'\$.raw.auth.factors') AS factors
     FROM event WHERE json_extract(payload,'\$.source_product')='hornwork-auth'
     ORDER BY ts DESC LIMIT 8;" 2>/dev/null || note "daemon 未运行时可跳过"

step "10. 密文自检：库文件中查不到 TOTP 明文密钥"
# 注意：待查密钥只经 stdin 传入（否则连这条自检命令都会被 auditd 记为含密钥的 execve）
check_plaintext() {
  "$PY" -c '
import sys
needle = sys.stdin.read().strip().encode()
if not needle:
    print("skip"); raise SystemExit
total = 0
for path in ("/var/lib/hornwork/hornwork.db",
             "/var/lib/hornwork/hornwork.db-wal",
             "/var/lib/hornwork/hornwork.db-shm"):
    try:
        total += open(path, "rb").read().count(needle)
    except OSError:
        pass
print(total)
'
}
for s in "$SECRET" "$SECRET2"; do
  CNT=$(printf '%s' "$s" | check_plaintext)
  note "Base32 明文在库+WAL 中命中次数：${CNT:-?}（期望 0）"
done
note "口令哈希样例（应为 \$argon2id\$...）："
sudo -u hornwork sqlite3 "$DB" "SELECT username, substr(password_hash,1,38)||'...' FROM auth_user WHERE username IN ('$U','$U2');"
note "生物模板只存密文（无明文向量列）："
sudo -u hornwork sqlite3 "$DB" "SELECT user_id, dim, length(tmpl_enc) AS ct_bytes, length(nonce) AS nonce_bytes FROM bio_template;"

step "完成"
note "日志与证据：$LOG"
note "截图建议：本段输出 + auth audit tail --user $U + auth audit verify-chain"

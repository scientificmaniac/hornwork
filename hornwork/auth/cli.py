"""`hornworkctl auth ...` 子命令：账号 / TOTP / 人脸模板 / 会话 / 审计 / 风险 / 登录。

设计原则：
- CLI 只是薄壳，全部逻辑在 `AuthEngine`（HTTP 中间件/PAM 后续可复用同一入口）；
- 口令一律从 stdin 或 getpass 读，不接受明文命令行参数（避免进 shell history）；
- 默认人类可读表格，`--json` 输出机读结果（报告证据更容易截）。
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Any

from .. import __version__
from . import audit, biometric, crypto, db, password, risk, session, totp


# ---------------------------------------------------------------------------
# 输出工具
# ---------------------------------------------------------------------------
def _json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _table(rows: list[dict], columns: list[tuple[str, str]]) -> None:
    if not rows:
        print("（无数据）")
        return
    widths = {k: len(t) for k, t in columns}
    for row in rows:
        for k, _t in columns:
            widths[k] = max(widths[k], min(len(str(row.get(k, "") or "")), 48))
    print("  ".join(t.ljust(widths[k]) for k, t in columns))
    print("  ".join("-" * widths[k] for k, _t in columns))
    for row in rows:
        print("  ".join(str(row.get(k, "") or "")[: widths[k]].ljust(widths[k])
                        for k, _t in columns))


def _read_secret(prompt: str, stdin_flag: bool = False) -> str:
    if stdin_flag:
        return sys.stdin.readline().rstrip("\n")
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass(prompt)


def _engine(args):
    from ..config import load_config, cfg_get
    from .engine import AuthEngine

    cfg = load_config(args.config)
    try:
        return AuthEngine(cfg)
    except crypto.KeyMaterialError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        print("[i] 先在测试主机执行：sudo bash scripts/setup_auth.sh"
              "（或 hornworkctl auth db init 生成密钥）", file=sys.stderr)
        raise SystemExit(2)


def _embedding(args) -> list[float] | None:
    path = getattr(args, "embedding", None)
    image = getattr(args, "image", None)
    if path:
        return biometric.embedding_from_file(path)
    if image:
        return biometric.embedding_from_image(image)
    return None


# ---------------------------------------------------------------------------
# 解析器
# ---------------------------------------------------------------------------
def add_parsers(sub) -> None:
    p = sub.add_parser("auth", help="认证模块：三因子认证（口令 + TOTP + 人脸模板保护）")
    a = p.add_subparsers(dest="auth_cmd", required=True)

    adb = a.add_parser("db", help="建表 / 生成密钥 / 策略初始化")
    adb_sub = adb.add_subparsers(dest="db_cmd", required=True)
    adb_sub.add_parser("init")
    adb_sub.add_parser("show")

    au = a.add_parser("user", help="账号生命周期")
    aus = au.add_subparsers(dest="user_cmd", required=True)
    ua = aus.add_parser("add")
    ua.add_argument("username")
    ua.add_argument("--display", default=None)
    ua.add_argument("--admin", action="store_true")
    ua.add_argument("--password-stdin", action="store_true")
    aus.add_parser("list")
    us = aus.add_parser("show")
    us.add_argument("username")
    up = aus.add_parser("passwd")
    up.add_argument("username")
    up.add_argument("--old-password-stdin", action="store_true")
    up.add_argument("--password-stdin", action="store_true")
    for name in ("lock", "unlock"):
        _p = aus.add_parser(name)
        _p.add_argument("username")

    ao = a.add_parser("otp", help="TOTP 因子（RFC 6238 自研）")
    aos = ao.add_subparsers(dest="otp_cmd", required=True)
    oe = aos.add_parser("enroll")
    oe.add_argument("username")
    oe.add_argument("--confirm", default=None, help="直接用当前动态码确认激活")
    oc = aos.add_parser("confirm")
    oc.add_argument("username")
    oc.add_argument("--code", required=True)
    ov = aos.add_parser("verify")
    ov.add_argument("username")
    ov.add_argument("--code", required=True)
    orv = aos.add_parser("revoke")
    orv.add_argument("username")

    ab = a.add_parser("biometric", help="人脸模板保护（可撤销变换 + AES-GCM）")
    abs_ = ab.add_subparsers(dest="bio_cmd", required=True)
    for name in ("enroll", "verify"):
        _p = abs_.add_parser(name)
        _p.add_argument("username")
        g = _p.add_mutually_exclusive_group(required=True)
        g.add_argument("--embedding", help="JSON 向量文件（512 维）")
        g.add_argument("--image", help="图片文件（仅链路演示，不代表识别精度）")
        _p.add_argument("--quality", type=float, default=1.0)
    bd = abs_.add_parser("delete")
    bd.add_argument("username")

    ase = a.add_parser("session", help="会话")
    ases = ase.add_subparsers(dest="sess_cmd", required=True)
    sl = ases.add_parser("list")
    sl.add_argument("--user", default=None)
    sl.add_argument("--all", action="store_true")
    sl.add_argument("--limit", type=int, default=50)
    sr = ases.add_parser("revoke")
    sr.add_argument("--token", default=None)
    sr.add_argument("--user", default=None)
    sr.add_argument("--all", action="store_true")
    sinfo = ases.add_parser("show")
    sinfo.add_argument("--token", required=True)
    scheck = ases.add_parser("check")
    scheck.add_argument("--token", required=True)
    scheck.add_argument("--action", default="read")

    aa = a.add_parser("audit", help="审计链")
    aas = aa.add_subparsers(dest="audit_cmd", required=True)
    at = aas.add_parser("tail")
    at.add_argument("--user", default=None)
    at.add_argument("--limit", type=int, default=20)
    aas.add_parser("verify-chain")
    asm = aas.add_parser("summary")
    asm.add_argument("--since", default="24h")

    ar = a.add_parser("risk", help="风险评分")
    ars = ar.add_subparsers(dest="risk_cmd", required=True)
    rex = ars.add_parser("explain")
    rex.add_argument("username")
    rex.add_argument("--ip", default=None)
    rex.add_argument("--device-id", dest="device_id", default=None)

    apo = a.add_parser("policy", help="策略表（阈值/权重可调，不硬编码）")
    apos = apo.add_subparsers(dest="policy_cmd", required=True)
    pshow = apos.add_parser("show")
    pshow.add_argument("--key", default=None)
    pset = apos.add_parser("set")
    pset.add_argument("key")
    pset.add_argument("value_json")

    al = a.add_parser("login", help="三因子登录（CLI 演示入口）")
    al.add_argument("username")
    al.add_argument("--ip", default=None)
    al.add_argument("--totp", default=None, help="动态码；缺省则走交互/分步")
    al.add_argument("--embedding", default=None)
    al.add_argument("--image", default=None)
    al.add_argument("--device-token", dest="device_token", default=None)
    al.add_argument("--password-stdin", action="store_true")
    al.add_argument("--out", default=None, help="把登录结果（含令牌）写入 JSON 文件")

    ast = a.add_parser("step-up", help="敏感操作补强认证（TOTP + 人脸）")
    ast.add_argument("--token", required=True)
    ast.add_argument("--totp", required=True)
    ast.add_argument("--embedding", default=None)
    ast.add_argument("--image", default=None)

    alo = a.add_parser("logout")
    alo.add_argument("--token", required=True)

    adev = a.add_parser("device", help="设备信任（只降风险分，不减少因子）")
    adevs = adev.add_subparsers(dest="device_cmd", required=True)
    dt = adevs.add_parser("trust")
    dt.add_argument("username")
    dt.add_argument("--label", default="")
    dl = adevs.add_parser("list")
    dl.add_argument("username")

    abench = a.add_parser("bench-argon2", help="实测 Argon2id 耗时（报告参数依据）")
    abench.add_argument("--rounds", type=int, default=5)
    abench.add_argument("--m", type=int, default=None)
    abench.add_argument("--t", type=int, default=None)
    abench.add_argument("--p", type=int, default=None)

    a.add_parser("version")


# ---------------------------------------------------------------------------
# 命令实现
# ---------------------------------------------------------------------------
def run(args: argparse.Namespace, cfg: dict) -> int:
    cmd = args.auth_cmd
    if cmd == "version":
        print(f"hornwork-auth {__version__}")
        return 0
    if cmd == "db":
        return _cmd_db(args, cfg)
    if cmd == "bench-argon2":
        params = password.ar2params()
        if args.m:
            params["m"] = args.m
        if args.t:
            params["t"] = args.t
        if args.p:
            params["p"] = args.p
        res = password.benchmark(params, args.rounds)
        _json(res) if args.json else print(json.dumps(res, ensure_ascii=False))
        return 0

    eng = _engine(args)
    try:
        if cmd == "user":
            return _cmd_user(args, eng)
        if cmd == "otp":
            return _cmd_otp(args, eng)
        if cmd == "biometric":
            return _cmd_bio(args, eng)
        if cmd == "session":
            return _cmd_session(args, eng)
        if cmd == "audit":
            return _cmd_audit(args, eng, cfg)
        if cmd == "risk":
            return _cmd_risk(args, eng)
        if cmd == "policy":
            return _cmd_policy(args, eng)
        if cmd == "login":
            return _cmd_login(args, eng)
        if cmd == "step-up":
            return _cmd_stepup(args, eng)
        if cmd == "logout":
            ok = eng.logout(args.token)
            print("已吊销" if ok else "令牌无效或已吊销")
            return 0 if ok else 1
        if cmd == "device":
            return _cmd_device(args, eng)
    finally:
        eng.store.close()
    return 1


def _cmd_db(args, cfg) -> int:
    from ..config import cfg_get

    if args.db_cmd == "init":
        keyring = crypto.KeyRing.from_config(cfg, create=True)
        store = db.open_auth_store(cfg)
        db.seed_policy(store)
        store.close()
        print(f"密钥：{cfg_get(cfg, 'auth.key_path')}（600，pepper 分离存储）")
        print(f"数据库：{db.resolve_db_path(cfg)}")
        print("已建表：auth_user / auth_credential / auth_session / bio_template /"
              " auth_audit / auth_policy / trusted_device")
        print(f"key_id={keyring.key_id}")
        return 0
    eng = _engine(args)
    try:
        print(f"数据库：{eng.store.path}")
        for key, val in db.all_policy(eng.store).items():
            print(f"  {key} = {json.dumps(val, ensure_ascii=False)}")
        print(f"用户数：{len(eng.list_users())}  审计条数："
              f"{eng.store.query_one('SELECT COUNT(*) AS n FROM auth_audit')['n']}")
        return 0
    finally:
        eng.store.close()


def _cmd_user(args, eng) -> int:
    if args.user_cmd == "add":
        pw = _read_secret("新用户口令: ", args.password_stdin)
        res = eng.create_user(args.username, pw, args.display, admin=args.admin)
        _json(res) if args.json else print(f"已创建 {res['username']}（{res['algo']}）")
        return 0
    if args.user_cmd == "list":
        rows = eng.list_users()
        _json(rows) if args.json else _table(rows, [
            ("id", "ID"), ("username", "用户名"), ("password_algo", "算法"),
            ("status", "状态"), ("loa_max", "LOA上限"), ("failed_count", "失败"),
            ("locked_until", "锁定至"), ("mfa_enabled", "TOTP"), ("last_login_ts", "上次登录")])
        return 0
    if args.user_cmd == "show":
        user = eng.get_user(args.username)
        if not user:
            print("用户不存在", file=sys.stderr)
            return 1
        user = dict(user)
        user["has_totp"] = bool(totp.active_credential(eng.store, int(user["id"])))
        user["has_bio"] = biometric.has_template(eng.store, int(user["id"]))
        _json(user) if args.json else print(json.dumps(user, ensure_ascii=False, indent=2))
        return 0
    if args.user_cmd == "passwd":
        old = _read_secret("原口令: ", args.old_password_stdin)
        new = _read_secret("新口令: ", args.password_stdin)
        eng.set_password(args.username, new, old_password=old)
        print("口令已更新（旧会话已吊销）")
        return 0
    if args.user_cmd in ("lock", "unlock"):
        ok = eng.lock_user(args.username) if args.user_cmd == "lock" \
            else eng.unlock_user(args.username)
        print("完成" if ok else "用户不存在")
        return 0 if ok else 1
    return 1


def _cmd_otp(args, eng) -> int:
    if args.otp_cmd == "enroll":
        res = eng.enroll_totp(args.username)
        if args.json:
            _json(res)
        else:
            print(f"TOTP 密钥（Base32）：{res['secret_b32']}")
            print(f"otpauth URI：{res['uri']}")
            print("（用验证器 App 添加后执行 `auth otp enroll <user> --confirm <当前码>` 激活）")
        if args.confirm:
            ok, reason = eng.confirm_totp(args.username, args.confirm)
            print(("已激活：" if ok else "激活失败：") + reason)
            return 0 if ok else 1
        return 0
    if args.otp_cmd == "confirm":
        ok, reason = eng.confirm_totp(args.username, args.code)
        print(("已激活：" if ok else "激活失败：") + reason)
        return 0 if ok else 1
    if args.otp_cmd == "verify":
        user = eng.get_user(args.username)
        if not user:
            print("用户不存在", file=sys.stderr)
            return 1
        ok, reason, counter = totp.verify_user(
            eng.store, eng.keys, int(user["id"]), args.code,
            db.get_policy(eng.store, "totp"))
        print(json.dumps({"ok": ok, "reason": reason, "counter": counter},
                         ensure_ascii=False))
        return 0 if ok else 1
    if args.otp_cmd == "revoke":
        print(f"已吊销 {eng.revoke_totp(args.username)} 个 TOTP 凭证")
        return 0
    return 1


def _cmd_bio(args, eng) -> int:
    if args.bio_cmd == "delete":
        print(f"已撤销 {eng.delete_biometric(args.username)} 个模板")
        return 0
    emb = _embedding(args)
    if args.bio_cmd == "enroll":
        res = eng.enroll_biometric(args.username, emb, quality=args.quality)
        _json(res) if args.json else print(
            f"已注册模板 #{res['template_id']}（{res['dim']} 维，密文 {res['ciphertext_bytes']}B）")
        return 0
    if args.bio_cmd == "verify":
        user = eng.get_user(args.username)
        if not user:
            print("用户不存在", file=sys.stderr)
            return 1
        ok, sim, reason = biometric.verify(
            eng.store, eng.keys, int(user["id"]), emb,
            db.get_policy(eng.store, "bio"))
        res = {"ok": ok, "similarity": sim, "reason": reason,
               "threshold": db.get_policy(eng.store, "bio", {}).get("threshold")}
        _json(res) if args.json else print(
            f"{'通过' if ok else '拒绝'}：相似度 {sim}（阈值 {res['threshold']}，{reason}）")
        return 0 if ok else 1
    return 1


def _cmd_session(args, eng) -> int:
    if args.sess_cmd == "list":
        user_id = None
        if args.user:
            user = eng.get_user(args.user)
            if not user:
                print("用户不存在", file=sys.stderr)
                return 1
            user_id = int(user["id"])
        rows = session.list_sessions(eng.store, user_id,
                                     active_only=not args.all, limit=args.limit)
        _json(rows) if args.json else _table(rows, [
            ("session_id", "会话"), ("user_id", "用户"), ("loa", "LOA"),
            ("ip", "IP"), ("created_ts", "创建"), ("idle_expires_ts", "空闲到期"),
            ("expires_ts", "绝对到期"), ("revoked", "已吊销")])
        return 0
    if args.sess_cmd == "revoke":
        if args.token:
            ok = eng.logout(args.token)
            print("已吊销" if ok else "令牌无效")
            return 0 if ok else 1
        if args.user and args.all:
            user = eng.get_user(args.user)
            if not user:
                print("用户不存在", file=sys.stderr)
                return 1
            print(f"已吊销 {session.revoke_user(eng.store, int(user['id']))} 个会话")
            return 0
        print("请指定 --token，或 --user X --all", file=sys.stderr)
        return 2
    if args.sess_cmd == "show":
        _json(eng.session_info(args.token))
        return 0
    if args.sess_cmd == "check":
        res = eng.require_action(args.token, args.action)
        _json(res) if args.json else print(json.dumps(res, ensure_ascii=False))
        return 0 if res["decision"] == "allow" else 1
    return 1


def _cmd_audit(args, eng, cfg) -> int:
    if args.audit_cmd == "tail":
        rows = audit.tail(eng.store, args.user, args.limit)
        _json(rows) if args.json else _table(rows, [
            ("id", "ID"), ("ts", "时间"), ("username", "用户"), ("event", "事件"),
            ("factor", "因子"), ("result", "结果"), ("loa", "LOA"),
            ("risk_score", "风险"), ("detail", "详情")])
        return 0
    if args.audit_cmd == "verify-chain":
        res = audit.verify_chain(eng.store)
        _json(res) if args.json else print(json.dumps(res, ensure_ascii=False))
        return 0 if res["ok"] else 1
    if args.audit_cmd == "summary":
        res = audit.summary(eng.store, args.since)
        _json(res) if args.json else print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    return 1


def _cmd_risk(args, eng) -> int:
    user = eng.get_user(args.username)
    if not user:
        print("用户不存在", file=sys.stderr)
        return 1
    res = risk.explain(eng.store, user, ip=args.ip, device_id=args.device_id)
    _json(res) if args.json else print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def _cmd_policy(args, eng) -> int:
    if args.policy_cmd == "show":
        data = db.all_policy(eng.store)
        if args.key:
            print(json.dumps(data.get(args.key), ensure_ascii=False))
        else:
            _json(data) if args.json else print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    if args.policy_cmd == "set":
        try:
            value = json.loads(args.value_json)
        except json.JSONDecodeError:
            print("value_json 不是合法 JSON", file=sys.stderr)
            return 2
        db.set_policy(eng.store, args.key, value, by="cli")
        print(f"已更新策略 {args.key}")
        return 0
    return 1


def _cmd_login(args, eng) -> int:
    pw = _read_secret("口令: ", args.password_stdin)
    emb = _embedding(args)
    totp_code = args.totp
    if totp_code is None:
        start = eng.start_login(args.username, pw, ip=args.ip,
                                device_token=args.device_token)
        if start["status"] == "totp_required":
            if sys.stdin.isatty():
                totp_code = input("动态码: ").strip()
            res = eng.advance(start["challenge_id"], totp_code=totp_code)
        else:
            res = start
    else:
        res = eng.login(args.username, pw, ip=args.ip,
                        device_token=args.device_token, totp_code=totp_code,
                        embedding=emb)
    if res.get("status") == "bio_required" and emb is None:
        print("需要人脸因子：请用 --embedding/--image 提供向量后重试", file=sys.stderr)
        return 1
    safe = {k: v for k, v in res.items() if k != "session"}
    if args.out:
        from pathlib import Path

        Path(args.out).write_text(json.dumps(res, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
    if args.json:
        _json(res)
    else:
        print(json.dumps(safe, ensure_ascii=False, indent=2))
        if res.get("status") == "ok":
            print(f"\n会话令牌：{res['token']}")
    return 0 if res.get("status") == "ok" else 1


def _cmd_stepup(args, eng) -> int:
    emb = _embedding(args)
    res = eng.step_up(args.token, args.totp, emb)
    _json(res) if args.json else print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("status") == "ok" else 1


def _cmd_device(args, eng) -> int:
    user = eng.get_user(args.username)
    if not user:
        print("用户不存在", file=sys.stderr)
        return 1
    if args.device_cmd == "trust":
        res = session.trust_device(eng.store, eng.keys, int(user["id"]), label=args.label)
        _json(res) if args.json else print(json.dumps(res, ensure_ascii=False))
        return 0
    rows = eng.store.query(
        "SELECT * FROM trusted_device WHERE user_id=? ORDER BY issued_ts DESC",
        (int(user["id"]),))
    _json(rows) if args.json else _table(rows, [
        ("device_id", "设备"), ("label", "标签"), ("issued_ts", "签发"),
        ("expires_ts", "到期"), ("revoked", "已撤销")])
    return 0

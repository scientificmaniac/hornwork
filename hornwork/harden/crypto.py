"""密码学落地五项：口令哈希 / TLS / 证书 / 签名 / 静态数据加密。

全部通过标准工具落地（openssl / cryptsetup / nginx），本文件只做参数选择、
配置生成、结果判读与台账登记——“自研实现密码算法”是错误路线，见 docs/hardening.md §4。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any

from . import core

# ---------------------------------------------------------------- 固定路径
def tls_dir() -> Path:
    """TLS 产物目录：默认 /etc/ssl/hornwork，可用 HORNWORK_HARDEN_TLS_DIR 覆盖。"""
    return Path(os.environ.get("HORNWORK_HARDEN_TLS_DIR") or "/etc/ssl/hornwork")


def key_dir() -> Path:
    """密钥目录：默认 /etc/hornwork/harden，可用 HORNWORK_HARDEN_KEY_DIR 覆盖。"""
    return Path(os.environ.get("HORNWORK_HARDEN_KEY_DIR") or "/etc/hornwork/harden")
NGINX_CONF = Path("/etc/nginx/conf.d/hornwork-tls.conf")
NGINX_SITE = "hornwork-tls.conf"

# RFC 9106 第二推荐配置：m=64 MiB, t=3, p=4；salt 16B / 输出 32B
ARGON2_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "salt_len": 16}

DEMO_PASSWORDS = {
    "alice": "Passw0rd!alice",
    "bob": "Passw0rd!bob",
    "carol": "Passw0rd!carol",
}

TLS_CANDIDATE_CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
]
WEAK_CIPHER_MARKERS = ("CBC", "SHA256", "SHA384", "SHA", "RC4", "3DES", "DES")

TLS_SERVER = ("127.0.0.1", 8443)
HTTP_REDIRECT = ("127.0.0.1", 8080)


# ================================================================ 1) 口令哈希
def _argon2():
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError  # noqa: F401

    return PasswordHasher(**ARGON2_PARAMS)


def demo_db_path() -> Path:
    return core.state()["demo"] / "demo_users.db"


def _connect_demo():
    import sqlite3

    path = demo_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS demo_user("
        "id INTEGER PRIMARY KEY, name TEXT UNIQUE, pwd_hash TEXT, hash_algo TEXT, updated_at TEXT)"
    )
    return conn


def seed_demo_users() -> list[dict[str, str]]:
    """构造三类“加固前”哈希：md5 裸哈希 / sha1 加盐 / sha256 加盐（仅演示迁移用）。"""
    rows = [
        ("alice", hashlib.md5(DEMO_PASSWORDS["alice"].encode()).hexdigest(), "md5"),
        ("bob", "sha1$s1$" + hashlib.sha1(b"s1" + DEMO_PASSWORDS["bob"].encode()).hexdigest(), "sha1_salt"),
        ("carol", "sha256$s2$" + hashlib.sha256(b"s2" + DEMO_PASSWORDS["carol"].encode()).hexdigest(), "sha256_salt"),
    ]
    conn = _connect_demo()
    created = []
    for name, digest, algo in rows:
        cur = conn.execute(
            "INSERT OR IGNORE INTO demo_user(name, pwd_hash, hash_algo, updated_at) VALUES(?,?,?,?)",
            (name, digest, algo, core.utc_now()),
        )
        if cur.rowcount:
            created.append({"name": name, "hash_algo": algo, "pwd_hash": digest})
    conn.commit()
    conn.close()
    return created


def is_legacy(stored: str) -> bool:
    return not stored.startswith("$argon2")


def legacy_verify(password: str, stored: str) -> bool:
    if stored.startswith("$argon2"):
        return False
    if stored.startswith("sha1$"):
        _, salt, digest = stored.split("$", 2)
        return hashlib.sha1(salt.encode() + password.encode()).hexdigest() == digest
    if stored.startswith("sha256$"):
        _, salt, digest = stored.split("$", 2)
        return hashlib.sha256(salt.encode() + password.encode()).hexdigest() == digest
    if re.fullmatch(r"[0-9a-f]{32}", stored):
        return hashlib.md5(password.encode()).hexdigest() == stored
    return False


def pwhash_status() -> dict[str, Any]:
    conn = _connect_demo()
    rows = conn.execute("SELECT name, pwd_hash, hash_algo FROM demo_user ORDER BY id").fetchall()
    conn.close()
    legacy = [{"name": name, "hash_algo": algo, "prefix": stored[:16] + "…"} for name, stored, algo in rows if is_legacy(stored)]
    return {
        "demo_db": str(demo_db_path()),
        "users": len(rows),
        "legacy_hashes_remaining": len(legacy),
        "legacy": legacy,
        "argon2id_users": len(rows) - len(legacy),
        "params": ARGON2_PARAMS,
        "algorithm": "Argon2id（RFC 9106 第二推荐配置，memory=64MiB,t=3,p=4）",
    }


def pwhash_migrate(seed: bool = True) -> dict[str, Any]:
    """模拟“用户下次登录、明文短暂在内存”时的渐进迁移；条件 UPDATE 保证幂等。"""
    if seed:
        seed_demo_users()
    ph = _argon2()
    conn = _connect_demo()
    rows = conn.execute("SELECT id, name, pwd_hash, hash_algo FROM demo_user ORDER BY id").fetchall()
    migrated: list[dict[str, Any]] = []
    for uid, name, stored, algo in rows:
        if not is_legacy(stored):
            continue
        password = DEMO_PASSWORDS.get(name)
        if not password or not legacy_verify(password, stored):
            migrated.append({"name": name, "legacy": algo, "result": "无法迁移（缺少明文，属预期）"})
            continue
        started = time.time()
        new_hash = ph.hash(password)
        cost_ms = int((time.time() - started) * 1000)
        conn.execute(
            "UPDATE demo_user SET pwd_hash=?, hash_algo='argon2id', updated_at=? "
            "WHERE id=? AND hash_algo<>'argon2id'",
            (new_hash, core.utc_now(), uid),
        )
        migrated.append(
            {
                "name": name,
                "legacy": algo,
                "legacy_prefix": stored[:20] + "…",
                "new_prefix": new_hash[:46] + "…",
                "new_algo": "argon2id",
                "hash_ms": cost_ms,
                "verify_ok": ph.verify(new_hash, password),
            }
        )
    conn.commit()
    conn.close()
    status = pwhash_status()
    return {"migrated": migrated, "status": status}


def pwhash_check() -> tuple[bool, dict[str, Any]]:
    status = pwhash_status()
    return status["legacy_hashes_remaining"] == 0 and status["users"] > 0, status


# ================================================================ 2) PKI
def _openssl(*args: str, timeout: int = 120) -> dict[str, Any]:
    return core.sh("openssl " + " ".join(args), timeout=timeout)


def _ensure_key_dir() -> None:
    key_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir(), 0o700)


def _chmod(path: str | Path, mode: int) -> None:
    """设置文件权限。

    ``core.sh`` 在非 root 时走 ``sudo -n``，因此由它创建的文件可能属于 root；
    此时当前进程无法直接 chmod（EPERM）。先尝试本地 chmod，失败再走同一条
    提权路径，保证「创建者」与「改权限者」权限上下文一致。
    """
    try:
        os.chmod(path, mode)
    except OSError:
        core.sh(f"chmod {mode:o} {path}")


def cert_info(path: str | Path) -> dict[str, Any]:
    path = str(path)
    if not Path(path).is_file():
        return {"path": path, "exists": False}
    dates = core.sh(f"openssl x509 -in {path} -noout -dates -dateopt iso_8601")
    if dates["rc"] != 0:
        dates = core.sh(f"openssl x509 -in {path} -noout -dates")
    subject = core.sh(f"openssl x509 -in {path} -noout -subject").get("out", "")
    issuer = core.sh(f"openssl x509 -in {path} -noout -issuer").get("out", "")
    fingerprint = core.sh(f"openssl x509 -in {path} -noout -fingerprint -sha256").get("out", "")
    san = core.sh(f"openssl x509 -in {path} -noout -ext subjectAltName").get("out", "")
    text = core.sh(f"openssl x509 -in {path} -noout -text")
    body = text.get("out", "")
    sig = ""
    match = re.search(r"Signature Algorithm:\s*(\S+)", body)
    if match:
        sig = match.group(1)
    pub = core.sh(f"openssl x509 -in {path} -noout -pubkey | openssl pkey -pubin -text -noout 2>/dev/null")
    pub_text = pub.get("out", "")
    key_bits = 0
    bits = re.search(r"Public-Key:\s*\((\d+) bit\)", pub_text)
    if bits:
        key_bits = int(bits.group(1))
    curve = re.search(r"ASN1 OID:\s*(\S+)", pub_text)

    def parse_date(key: str) -> str:
        match = re.search(rf"{key}=(.+)", dates.get("out", ""))
        if not match:
            return ""
        raw = match.group(1).strip()
        if re.match(r"^\d{4}-\d{2}-\d{2}", raw):
            raw = raw.replace(" ", "T", 1)
            return raw if raw.endswith("Z") else raw + "Z"
        from datetime import datetime, timezone

        try:
            parsed = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return ""

    return {
        "path": path,
        "exists": True,
        "subject": subject.replace("subject=", ""),
        "issuer": issuer.replace("issuer=", ""),
        "not_before": parse_date("notBefore"),
        "not_after": parse_date("notAfter"),
        "days_left": core.days_left(parse_date("notAfter")) if parse_date("notAfter") else -1,
        "fingerprint_sha256": fingerprint.split("=", 1)[-1].replace(":", "").lower(),
        "san": " ".join(san.splitlines()[1:]).strip(),
        "signature_algorithm": sig,
        "key_bits": key_bits,
        "curve": curve.group(1) if curve else "",
        "mode": oct(os.stat(path).st_mode & 0o777),
    }


def _host_ips() -> list[str]:
    ips = ["127.0.0.1"]
    out = core.sh("hostname -I 2>/dev/null").get("out", "")
    for token in out.split():
        if token not in ips and re.fullmatch(r"[\d.]+", token):
            ips.append(token)
    return ips


def pki_ensure(force: bool = False) -> dict[str, Any]:
    _ensure_key_dir()
    tls_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(tls_dir(), 0o700)
    ca_key, ca_crt = tls_dir() / "ca.key", tls_dir() / "ca.crt"
    srv_key, srv_crt = tls_dir() / "srv.key", tls_dir() / "srv.crt"
    created: list[str] = []
    if force or not ca_crt.is_file() or not ca_key.is_file():
        core.sh(
            f"openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out {ca_key} && "
            f"openssl req -x509 -new -key {ca_key} -sha256 -days 3650 "
            f"-subj '/C=CN/O=Hornwork Lab/CN=Hornwork Internal CA' "
            f"-addext 'basicConstraints=critical,CA:TRUE' "
            f"-addext 'keyUsage=critical,keyCertSign,cRLSign' -out {ca_crt}"
        )
        os.chmod(ca_key, 0o600)
        created.append("ca")
    info = cert_info(srv_crt)
    need_renew = (
        force
        or not info.get("exists")
        or info.get("days_left", 0) < 30
        or "127.0.0.1" not in str(info.get("san", ""))
        or "a.hornwork.local" not in str(info.get("subject", ""))
    )
    if need_renew:
        if not srv_key.is_file():
            core.sh(f"openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out {srv_key}")
            os.chmod(srv_key, 0o600)
        ext = tls_dir() / "srv.ext"
        sans = ["DNS:a.hornwork.local", "DNS:localhost"] + [f"IP:{ip}" for ip in _host_ips()]
        core.write_text(
            ext,
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName={','.join(sans)}\n",
        )
        core.sh(
            f"openssl req -new -key {srv_key} -subj '/C=CN/O=Hornwork Lab/CN=a.hornwork.local' -out {tls_dir() / 'srv.csr'} && "
            f"openssl x509 -req -in {tls_dir() / 'srv.csr'} -CA {ca_crt} -CAkey {ca_key} -CAcreateserial "
            f"-days 90 -sha256 -extfile {ext} -out {srv_crt}"
        )
        os.chmod(srv_crt, 0o644)
        created.append("server")
    assets = [
        register_asset("ca", str(ca_crt), note="根 CA，私钥离线保存（演示环境同机 600 权限）"),
        register_asset("server", str(srv_crt), note="TLS 服务证书（ECDSA P-256 / SHA-256 / 90 天）"),
    ]
    return {"created": created, "ca": cert_info(ca_crt), "server": cert_info(srv_crt), "assets": assets}


def pki_check() -> tuple[bool, dict[str, Any]]:
    ca = cert_info(tls_dir() / "ca.crt")
    srv = cert_info(tls_dir() / "srv.crt")
    reasons = []
    if not ca.get("exists"):
        reasons.append("CA 证书缺失")
    if not srv.get("exists"):
        reasons.append("服务证书缺失")
    if srv.get("exists"):
        if srv["days_left"] < 30:
            reasons.append(f"服务证书剩余 {srv['days_left']} 天 < 30")
        if "127.0.0.1" not in str(srv.get("san", "")):
            reasons.append("SAN 未覆盖 127.0.0.1")
        if srv.get("key_bits") not in (256, 384, 521) and int(srv.get("key_bits") or 0) < 2048:
            reasons.append(f"密钥强度不足：{srv.get('key_bits')}")
        if "sha256" not in str(srv.get("signature_algorithm", "")).lower().replace("-", "") and "sha1" in str(srv.get("signature_algorithm", "")).lower():
            reasons.append("证书签名算法为 SHA-1")
    return not reasons, {"ca": ca, "server": srv, "reasons": reasons}


# ================================================================ 3) 签名
SIGN_TARGETS = [("baseline", core.ITEMS_PATH)]


def _a_plans() -> list[Path]:
    """只把 防护主机（可执行）计划纳入签名，B/C 计划是场景适配证据、不参与执行验签。"""
    plans = sorted(core.state()["plans"].glob("pln-*.json"))
    a_plans = []
    for path in plans:
        data = core.read_json(path) or {}
        if data.get("role") == "A":
            a_plans.append(path)
    return a_plans or plans


def sign_ensure() -> dict[str, Any]:
    _ensure_key_dir()
    key, pub = key_dir() / "sign.key", key_dir() / "sign.pub"
    if not key.is_file():
        core.sh(f"openssl genpkey -algorithm ED25519 -out {key}")
        _chmod(key, 0o600)
    if not pub.is_file():
        core.sh(f"openssl pkey -in {key} -pubout -out {pub}")
        _chmod(pub, 0o644)
    targets: list[tuple[str, Path]] = []
    for kind, path in SIGN_TARGETS:
        targets.append((kind, Path(path)))
    plans = _a_plans()
    if plans:
        targets.append(("plan", plans[-1]))
    release = core.state()["root"] / "release.hornwork.tar.gz"
    core.sh(
        f"tar -czf {release} -C {core.CODE_DIR.parent.parent} hornwork/harden hornwork/cli.py 2>/dev/null",
        timeout=120,
    )
    if release.is_file():
        targets.append(("release", release))
    signed = []
    for kind, path in targets:
        if not path.is_file():
            continue
        sig = Path(str(path) + ".sig")
        res = core.sh(f"openssl pkeyutl -sign -inkey {key} -rawin -in {path} -out {sig}")
        signed.append(
            {
                "kind": kind,
                "path": str(path),
                "sha256": core.sha256_file(path),
                "signature": str(sig),
                "ok": res["rc"] == 0,
                "algorithm": "Ed25519（RFC 8032）",
            }
        )
    register_asset("sign", str(pub), note="Ed25519 验签公钥；私钥 600 且应离线保管")
    return {"signed": signed, "pub": str(pub)}


def verify_signature(path: str | Path, sig: str | Path | None = None) -> bool:
    pub = key_dir() / "sign.pub"
    sig = sig or Path(str(path) + ".sig")
    if not (pub.is_file() and Path(sig).is_file() and Path(path).is_file()):
        return False
    res = core.sh(f"openssl pkeyutl -verify -pubin -inkey {pub} -rawin -in {path} -sigfile {sig}")
    return res["rc"] == 0


def sign_check() -> tuple[bool, dict[str, Any]]:
    checks = []
    for kind, path in SIGN_TARGETS:
        path = Path(path)
        checks.append({"kind": kind, "path": str(path), "verify": verify_signature(path)})
    for plan_path in _a_plans():
        if Path(str(plan_path) + ".sig").is_file():
            checks.append({"kind": "plan", "path": str(plan_path), "verify": verify_signature(plan_path)})
    release = core.state()["root"] / "release.hornwork.tar.gz"
    if release.is_file():
        checks.append({"kind": "release", "path": str(release), "verify": verify_signature(release)})
    return all(c["verify"] for c in checks) and bool(checks), {"objects": checks, "pub": str(key_dir() / "sign.pub")}


def tamper_test() -> dict[str, Any]:
    """篡改一个字节 → 验签必须失败（报告用的可复现证据）。"""
    src = Path(core.ITEMS_PATH)
    copy = core.state()["root"] / "tamper_items.yaml"
    shutil.copy2(src, copy)
    sig = Path(str(copy) + ".sig")
    key = key_dir() / "sign.key"
    core.sh(f"openssl pkeyutl -sign -inkey {key} -rawin -in {copy} -out {sig}")
    before = verify_signature(copy, sig)
    with open(copy, "ab") as handle:
        handle.write(b"\n# tampered\n")
    after = verify_signature(copy, sig)
    return {"before_tamper_verify": before, "after_tamper_verify": after, "tampered_file": str(copy), "signature": str(sig)}


# ================================================================ 4) TLS
def render_tls() -> dict[str, Any]:
    pki = pki_ensure()
    template = (core.TEMPLATE_DIR / "nginx-hornwork.conf").read_text(encoding="utf-8")
    rendered = (
        template.replace("@CERT@", str(tls_dir() / "srv.crt"))
        .replace("@KEY@", str(tls_dir() / "srv.key"))
        .replace("@CA@", str(tls_dir() / "ca.crt"))
    )
    NGINX_CONF.write_text(rendered, encoding="utf-8")
    os.chmod(NGINX_CONF, 0o644)
    test = core.sh("nginx -t 2>&1")
    reload = core.sh("systemctl enable nginx >/dev/null 2>&1; systemctl is-active nginx >/dev/null 2>&1 || systemctl start nginx; systemctl reload nginx 2>/dev/null || systemctl restart nginx")
    register_asset("server", str(tls_dir() / "srv.crt"), note="nginx TLS 端点 127.0.0.1:8443（Mozilla intermediate 口径）")
    return {
        "config": str(NGINX_CONF),
        "nginx_test": test["out"] or test["err"],
        "nginx_test_ok": test["rc"] == 0,
        "reload_ok": reload["rc"] == 0,
        "pki": {"created": pki["created"]},
        "protocols": "TLSv1.2 TLSv1.3",
    }


def _tls_connect(protocol: int | None = None, cipher: str | None = None) -> dict[str, Any]:
    host, port = TLS_SERVER
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if protocol is not None:
        context.minimum_version = protocol
        context.maximum_version = protocol
    if cipher:
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError as exc:
            return {"ok": False, "error": f"set_ciphers: {exc}"}
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname="a.hornwork.local") as tls:
                version = tls.version()
                negotiated = tls.cipher()
                cert = tls.getpeercert(binary_form=True)
                return {"ok": True, "version": version, "cipher": negotiated[0] if negotiated else "", "cert_der_sha256": hashlib.sha256(cert or b"").hexdigest()}
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "error": str(exc)}


def tls_probe_protocols() -> tuple[bool, dict[str, Any]]:
    wanted = {
        "TLS1.0": getattr(ssl.TLSVersion, "TLSv1", None),
        "TLS1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
        "TLS1.2": ssl.TLSVersion.TLSv1_2,
        "TLS1.3": ssl.TLSVersion.TLSv1_3,
    }
    results = {}
    for name, protocol in wanted.items():
        results[name] = _tls_connect(protocol) if protocol is not None else {"ok": False, "error": "not supported by python ssl"}
    passed = not results["TLS1.0"]["ok"] and not results["TLS1.1"]["ok"] and results["TLS1.2"]["ok"] and results["TLS1.3"]["ok"]
    return passed, {"server": f"{TLS_SERVER[0]}:{TLS_SERVER[1]}", "protocols": results, "rule": "仅 1.2/1.3，1.0/1.1 必须握手失败"}


def _is_weak_cipher(name: str) -> bool:
    """弱套件判定：CBC 模式 / RC4 / 3DES；注意 GCM/CHACHA 套件名里也含 SHA，不能按 SHA 判弱。"""
    upper = name.upper()
    return ("CBC" in upper) or ("3DES" in upper) or ("RC4" in upper) or upper == "DES-CBC3-SHA"


def tls_probe_ciphers() -> tuple[bool, dict[str, Any]]:
    supported, failed = [], []
    for cipher in TLS_CANDIDATE_CIPHERS:
        result = _tls_connect(ssl.TLSVersion.TLSv1_2, cipher)
        if result["ok"]:
            supported.append({"cipher": cipher, "negotiated": result.get("cipher")})
        else:
            failed.append(cipher)
    weak = [entry for entry in supported if _is_weak_cipher(entry["cipher"])]
    aead = [entry for entry in supported if "GCM" in entry["cipher"] or "CHACHA20" in entry["cipher"]]
    passed = bool(aead) and not weak
    return passed, {
        "supported": supported,
        "rejected": failed,
        "weak_supported": weak,
        "rule": "仅 AEAD（GCM / ChaCha20-Poly1305），CBC/RC4/3DES 必须被拒",
    }


def _http_head(port: int, use_tls: bool = False, host: str = "127.0.0.1", path: str = "/") -> dict[str, Any]:
    try:
        sock = socket.create_connection((host, port), timeout=3)
    except OSError as exc:
        return {"connected": False, "error": str(exc)}
    try:
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname="a.hornwork.local")
        request = f"GET {path} HTTP/1.1\r\nHost: a.hornwork.local\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head = data.decode("latin-1", "replace")
        lines = head.split("\r\n")
        status = lines[0] if lines else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return {"connected": True, "status": status, "headers": headers}
    except OSError as exc:
        return {"connected": False, "error": str(exc)}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def tls_probe_hsts() -> tuple[bool, dict[str, Any]]:
    plain = _http_head(HTTP_REDIRECT[1])
    secure = _http_head(TLS_SERVER[1], use_tls=True)
    redirect_ok = plain.get("connected") and plain.get("status", "").startswith("HTTP/1.1 301")
    hsts = secure.get("headers", {}).get("strict-transport-security", "")
    passed = bool(redirect_ok and hsts)
    return passed, {
        "http_8080": plain,
        "https_8443": {"status": secure.get("status"), "strict-transport-security": hsts},
        "rule": "80→443 301 跳转 + HSTS 头存在",
    }


def cert_check() -> tuple[bool, dict[str, Any]]:
    ok, info = pki_check()
    return ok, info


# ================================================================ 5) LUKS2
def luks_paths() -> dict[str, Path]:
    root = core.state()["luks"]
    return {
        "image": root / "backup.img",
        "slot0": root / "slot0.key",
        "slot1": root / "slot1.key",
        "mount": Path("/mnt/hornwork-backup"),
        "dump": root / "luksdump.txt",
    }


def luks_ensure() -> dict[str, Any]:
    paths = luks_paths()
    image = paths["image"]
    if not image.is_file():
        core.sh(f"truncate -s 256M {image}")
    for key_name in ("slot0", "slot1"):
        key_path = paths[key_name]
        if not key_path.is_file():
            key_path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
            os.chmod(key_path, 0o600)
    dump = core.sh(f"cryptsetup luksDump {image}")
    if dump["rc"] != 0:
        core.sh(
            f"cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode "
            f"--key-file {paths['slot0']} {image}",
            timeout=180,
        )
    keyslots = core.sh(f"cryptsetup luksDump {image} | grep -c '^  [0-9]: luks2'")
    if not keyslots["out"].strip().isdigit() or int(keyslots["out"].strip() or 0) < 2:
        core.sh(
            f"cryptsetup luksAddKey --batch-mode --key-file {paths['slot0']} {image} {paths['slot1']}",
            timeout=180,
        )
    mapper = "hornwork_backup"
    core.sh(f"cryptsetup close {mapper} 2>/dev/null; cryptsetup open --key-file {paths['slot0']} {image} {mapper}", timeout=120)
    core.sh(f"mkfs.ext4 -q -L hornwork-backup /dev/mapper/{mapper} 2>/dev/null || true")
    paths["mount"].mkdir(parents=True, exist_ok=True)
    mounted = core.sh(f"mount -o nofail /dev/mapper/{mapper} {paths['mount']} 2>&1")
    if mounted["rc"] == 0:
        (paths["mount"] / "backup-secret.txt").write_text(
            "HORNWORK_BACKUP_MARKER：这段文字只有在 LUKS2 解锁并挂载后才能读到。\n", encoding="utf-8"
        )
        core.sh(f"umount {paths['mount']}")
    core.sh(f"cryptsetup close {mapper}")
    final_dump = core.sh(f"cryptsetup luksDump {image}")
    paths["dump"].write_text(final_dump["out"], encoding="utf-8")
    return {
        "image": str(image),
        "size": core.sh(f"du -h {image} | cut -f1").get("out", ""),
        "keyslots": core.sh(f"cryptsetup luksDump {image} | grep -E '^  [0-9]:' ").get("out", ""),
        "pbkdf": "argon2id" if "argon2id" in final_dump["out"].lower() else "unknown",
    }


def luks_check() -> tuple[bool, dict[str, Any]]:
    paths = luks_paths()
    image = paths["image"]
    if not image.is_file():
        return False, {"image": str(image), "reason": "加密卷不存在"}
    dump = core.sh(f"cryptsetup luksDump {image}")
    text = dump["out"]
    slots = len(re.findall(r"^  \d+: luks2", text, re.MULTILINE))
    pbkdf = "argon2id" in text.lower()
    marker = core.sh(f"grep -a -c 'HORNWORK_BACKUP_MARKER' {image}").get("out", "0")
    plaintext_leak = marker.strip().isdigit() and int(marker.strip()) > 0
    passed = pbkdf and slots >= 2 and not plaintext_leak
    return passed, {
        "image": str(image),
        "kdf_argon2id": pbkdf,
        "keyslots": slots,
        "raw_device_marker_leak": plaintext_leak,
        "dump_excerpt": "\n".join(text.splitlines()[:16]),
        "rule": "KDF=argon2id、≥2 个密钥槽、裸镜像不可见明文",
    }


# ================================================================ 台账
def assets_path() -> Path:
    return core.state()["assets"] / "assets.json"


def register_asset(kind: str, path: str, note: str = "") -> dict[str, Any]:
    path = str(path)
    info = cert_info(path) if path.endswith((".crt", ".pem")) and Path(path).is_file() else {}
    record = {
        "kind": kind,
        "path": path,
        "subject": info.get("subject", ""),
        "issuer": info.get("issuer", ""),
        "fingerprint_sha256": info.get("fingerprint_sha256", ""),
        "not_before": info.get("not_before", ""),
        "not_after": info.get("not_after", ""),
        "owner": core.sh(f"stat -c '%U:%G' {path}").get("out", "") if Path(path).exists() else "",
        "mode": core.sh(f"stat -c '%a' {path}").get("out", "") if Path(path).exists() else "",
        "note": note,
        "updated_at": core.utc_now(),
    }
    records = core.read_json(assets_path(), []) or []
    records = [r for r in records if r.get("path") != path]
    records.append(record)
    core.write_json(assets_path(), records)
    return record


def asset_list() -> list[dict[str, Any]]:
    records = core.read_json(assets_path(), []) or []
    for record in records:
        if record.get("not_after"):
            record["days_left"] = core.days_left(record["not_after"])
    return records


def asset_expiring(days: int = 30) -> list[dict[str, Any]]:
    return [record for record in asset_list() if record.get("days_left") is not None and record["days_left"] <= days]

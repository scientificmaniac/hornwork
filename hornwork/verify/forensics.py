"""整机内存取证（路线 B：AVML 采集 → Volatility3 分析 → 与在线 memscan 互证）。


- collect()：调用 AVML 采集物理内存镜像，并记录 host/kernel/os/utc/sha256/size 元数据；
- analyze()：依次跑 Vol3 的 banners/pslist/malfind/bash/sockstat/lsmod 六个插件，输出到文本文件；
- compare()：把 malfind 解析出的可执行内存段与在线 memscan 落库的 mem_hits 做互证，生成 CSV。

外部命令一律 `subprocess.run([...], timeout=..., check=False)`，二进制路径取自配置；
缺失二进制/超时/非零返回都通过 `{"ok": False, "error": ...}` 表达，不抛异常给调用方。
"""

from __future__ import annotations

import csv
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import schema
from ..config import cfg_get
from ..log import get_logger

log = get_logger("verify.forensics")

# Vol3 插件顺序（banners 先跑，用于校验 ISF 符号是否与镜像内核匹配）
VOL_PLUGINS: tuple[str, ...] = ("banners", "pslist", "malfind", "bash", "sockstat", "lsmod")
# 互证 CSV 列
COMPARE_FIELDS = ("pid", "start", "end", "perms", "online", "offline", "match")

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_PERMS_RE = re.compile(r"^[r-][w-][x-][ps-]{1,2}$")


# ---------------------------------------------------------------------------
# 文本解析（纯函数，便于单测）
# ---------------------------------------------------------------------------
def _split_fields(line: str) -> list[str]:
    """按制表符优先切列；无制表符时退回空白切分。"""
    text = line.rstrip("\r\n")
    if "\t" in text:
        return [part for part in text.split("\t")]
    return text.split()


def _prot_to_perms(protection: str) -> str:
    """Windows 风格保护位 → Linux 风格权限串（malfind 对照用）。"""
    upper = (protection or "").upper()
    perms = ""
    perms += "r" if "READ" in upper or "EXECUTE" in upper else "-"
    perms += "w" if "WRITE" in upper or "WRITECOPY" in upper else "-"
    perms += "x" if "EXECUTE" in upper else "-"
    return perms


def parse_malfind(text: str) -> list[dict]:
    """解析 `vol ... linux.malfind` 文本输出。

    返回 [{pid, process, start, end, perms, protection, tag, source}]；
    start/end 为整数地址，perms 为 rwx 风格串；多行 hexdump 的续行自动跳过。
    """
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        fields = [item.strip() for item in _split_fields(raw)]
        if not fields or not fields[0]:
            continue
        head = fields[0].upper()
        if head in ("PID", "OFFSET") or (head == "OFFSET" and "(V)" in fields[0].upper()):
            continue
        if not fields[0].isdigit():
            # hexdump/反汇编续行、表头、Progress 行等
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        process = fields[1] if len(fields) > 1 else ""
        hexes = [token for token in fields if _HEX_RE.match(token)]
        if len(hexes) < 2:
            continue
        start, end = int(hexes[0], 16), int(hexes[1], 16)
        protection = ""
        perms = ""
        tag = None
        for idx, token in enumerate(fields):
            if token.upper().startswith("PAGE_"):
                protection = token.upper()
                perms = _prot_to_perms(protection)
                if idx > 0:
                    prev = fields[idx - 1]
                    if prev and not _HEX_RE.match(prev):
                        tag = prev
                break
        if not perms:
            for token in fields[2:]:
                if _PERMS_RE.match(token):
                    perms = token
                    break
        rows.append(
            {
                "pid": pid,
                "process": process,
                "start": start,
                "end": end,
                "perms": perms,
                "protection": protection,
                "tag": tag,
                "source": "malfind",
            }
        )
    return rows


def parse_pslist(text: str) -> list[dict]:
    """解析 `vol ... linux.pslist` 文本输出（按表头定位 PID/PPID/COMM 列）。

    返回 [{pid, ppid, comm, uid, offset}]；无表头则返回空列表（格式不识别）。
    """
    rows: list[dict] = []
    header: list[str] | None = None
    index: dict[str, int] = {}
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        fields = [item.strip() for item in _split_fields(raw)]
        if not fields:
            continue
        upper = [item.upper() for item in fields]
        if header is None:
            if "PID" in upper and "PPID" in upper:
                # 合并被空白切开的 "OFFSET (V)" 两列，保证与数据行的列位置对齐
                columns: list[str] = []
                for name in upper:
                    if name == "(V)" and columns:
                        columns[-1] = columns[-1] + " (V)"
                    else:
                        columns.append(name)
                header = columns
                index = {name: pos for pos, name in enumerate(columns) if name}
            continue
        if not fields[0].startswith("0x"):
            continue

        def pick(name: str) -> str:
            pos = index.get(name)
            if pos is None or pos >= len(fields):
                return ""
            return fields[pos]

        pid_text = pick("PID")
        if not pid_text.isdigit():
            continue
        uid_text = pick("UID")
        comm = pick("COMM")
        if "\t" not in raw and comm:
            # 空白切分时 COMM 可能含空格：用表头列数截断尾部数值列
            trailing = max(0, len(header) - index["COMM"] - 1)
            tokens = fields[index["COMM"]: len(fields) - trailing] if trailing else fields[index["COMM"]:]
            comm = " ".join(tokens)
        rows.append(
            {
                "pid": int(pid_text),
                "ppid": int(pick("PPID")) if pick("PPID").isdigit() else None,
                "comm": comm,
                "uid": int(uid_text) if uid_text.isdigit() else None,
                "offset": fields[0],
            }
        )
    return rows


def _to_int(value: Any) -> int | None:
    """把 mem_hits 里的 start/end（int 或 "0x.." 字符串）统一成整数。"""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _hex(value: int | None) -> str:
    return f"0x{int(value):x}" if value is not None else ""


def _read_os_release() -> str:
    """读 /etc/os-release 的 PRETTY_NAME，失败时退回 platform.platform()。"""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    try:
        return platform.platform()
    except Exception:  # noqa: BLE001 - 平台信息只用于报告
        return "linux"


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


class Forensics:
    """路线 B 取证：采集 / 分析 / 互证。"""

    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg or {}
        self.work_dir = Path(os.path.expanduser(str(cfg_get(self.cfg, "forensics.work_dir", "/data/forensics"))))
        self.avml_bin = str(cfg_get(self.cfg, "forensics.avml_bin", "/opt/forensics/bin/avml"))
        self.vol_bin = str(cfg_get(self.cfg, "forensics.vol_bin", "/opt/vol3/bin/vol"))
        self.symbol_dir = str(cfg_get(self.cfg, "forensics.symbol_dir", "/opt/symbols"))
        self.collect_timeout = int(cfg_get(self.cfg, "forensics.collect_timeout_sec", 1800) or 1800)
        self.analyze_timeout = int(cfg_get(self.cfg, "forensics.analyze_timeout_sec", 900) or 900)

    # ------------------------------------------------------------------ 工具
    @staticmethod
    def _resolve_bin(configured: str) -> str | None:
        """配置路径 → 可执行文件绝对路径；不存在再用 PATH 查找同名命令。"""
        text = str(configured or "").strip()
        if text:
            path = Path(os.path.expanduser(text))
            if path.is_file():
                return str(path)
        name = Path(text).name if text else ""
        if name:
            found = shutil.which(name)
            if found:
                return found
        return None

    def _store_meta(self, key: str, value: str) -> None:
        try:
            self.store.set_meta(key, value)
        except Exception as exc:  # noqa: BLE001 - meta 只是辅助记录
            log.warn("写 meta 失败", key=key, error=str(exc))

    # ------------------------------------------------------------------ 采集
    def collect(self, compress: bool = False, out_dir: str | None = None) -> dict:
        """调用 AVML 采集内存镜像并记录元数据。返回 {"ok","image","meta_path","meta",...}。"""
        work = Path(os.path.expanduser(out_dir)) if out_dir else self.work_dir
        info: dict[str, Any] = {
            "ok": False,
            "image": None,
            "meta_path": None,
            "meta": {},
            "cmd": [],
            "returncode": None,
            "elapsed_sec": None,
            "error": None,
        }
        try:
            work.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            info["error"] = f"工作目录不可用：{work}（{exc}）"
            return info

        avml = self._resolve_bin(self.avml_bin)
        if avml is None:
            info["error"] = f"未找到 avml 二进制：{self.avml_bin}（请先安装并授权）"
            return info

        host = str((schema.host_info(self.cfg) or {}).get("host_id") or socket.gethostname())
        image = work / f"{host}-{_utc_stamp()}.lime"
        if compress:
            image = image.with_name(image.name + ".compressed")
        cmd = [avml, "acquire"]
        if compress:
            cmd.append("--compress")
        cmd.append(str(image))
        info["cmd"] = cmd
        info["image"] = str(image)

        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.collect_timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            info["error"] = f"avml 不可执行：{exc}"
            return info
        except subprocess.TimeoutExpired as exc:
            info["error"] = f"采集超时（{self.collect_timeout}s）：{exc}"
            return info
        except OSError as exc:
            info["error"] = f"采集失败：{exc}"
            return info
        finally:
            info["elapsed_sec"] = round(time.monotonic() - started, 2)

        info["returncode"] = int(proc.returncode)
        info["stdout_tail"] = (proc.stdout or "")[-1000:]
        info["stderr_tail"] = (proc.stderr or "")[-1000:]
        if proc.returncode != 0:
            info["error"] = f"avml 返回码 {proc.returncode}：{(proc.stderr or proc.stdout or '').strip()[:300]}"
            return info
        if not image.is_file():
            info["error"] = f"avml 返回成功但镜像不存在：{image}"
            return info

        try:
            image_sha = schema.sha256_file(str(image))
        except OSError as exc:
            image_sha = f"hash-error:{exc}"
        try:
            image_size = image.stat().st_size
        except OSError:
            image_size = 0
        kernel = os.uname().release if hasattr(os, "uname") else platform.release()
        meta = {
            "host": host,
            "kernel": kernel,
            "os": _read_os_release(),
            "utc": schema.utc_now(),
            "image": str(image),
            "image_sha256": image_sha,
            "image_size": image_size,
            "compress": bool(compress),
        }
        meta_path = work / (image.stem + ".meta.txt")
        lines = [
            f"host={meta['host']}",
            f"kernel={meta['kernel']}",
            f"os={meta['os']}",
            f"utc={meta['utc']}",
            f"image={meta['image']}",
            f"image_sha256={meta['image_sha256']}",
            f"image_size={meta['image_size']}",
        ]
        try:
            meta_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            log.warn("取证元数据写入失败", path=str(meta_path), error=str(exc))
            meta_path = None
        self._store_meta("forensics.last_image", str(image))
        self._store_meta("forensics.last_meta", json.dumps(meta, ensure_ascii=False))
        info.update({"ok": True, "meta": meta, "meta_path": str(meta_path) if meta_path else None})
        log.info("内存镜像采集完成", image=str(image), size=image_size, compress=bool(compress))
        return info

    # ------------------------------------------------------------------ 分析
    def analyze(self, image: str, symbol_dir: str | None = None, plugins: list[str] | None = None) -> dict:
        """依次跑 Vol3 插件，输出到 `<镜像目录>/<镜像名>.out/*.txt`。"""
        result: dict[str, Any] = {
            "ok": False,
            "image": str(image),
            "out_dir": None,
            "symbol_dir": None,
            "plugins": [],
            "errors": [],
        }
        image_path = Path(os.path.expanduser(str(image)))
        if not image_path.is_file():
            result["errors"].append(f"镜像不存在：{image_path}")
            return result
        vol = self._resolve_bin(self.vol_bin)
        if vol is None:
            result["errors"].append(f"未找到 vol 二进制：{self.vol_bin}")
            return result
        symbol = str(symbol_dir or self.symbol_dir or "")
        result["symbol_dir"] = symbol
        out_dir = image_path.parent / (image_path.stem + ".out")
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            result["errors"].append(f"输出目录不可写：{out_dir}（{exc}）")
            return result
        result["out_dir"] = str(out_dir)

        names = list(plugins or VOL_PLUGINS)
        for name in names:
            text = str(name)
            plugin = text if "." in text else f"linux.{text}"
            short = plugin.rsplit(".", 1)[-1]
            cmd = [vol, "-f", str(image_path)]
            # banners 不需要符号目录（正是用来校验符号是否匹配），其余插件带上
            if short != "banners" and symbol:
                cmd.extend(["--symbol-dirs", symbol])
            cmd.append(plugin)
            out_file = out_dir / f"{short}.txt"
            record = {"plugin": plugin, "cmd": cmd, "out": str(out_file), "returncode": None, "bytes": 0, "error": None}
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.analyze_timeout,
                    check=False,
                )
                record["returncode"] = int(proc.returncode)
                body = proc.stdout or ""
                if proc.stderr:
                    body += "\n[stderr]\n" + (proc.stderr or "")
                try:
                    out_file.write_text(body, encoding="utf-8")
                    record["bytes"] = len(body.encode("utf-8"))
                except OSError as exc:
                    record["error"] = f"写出失败：{exc}"
                if proc.returncode != 0:
                    record["error"] = f"插件返回码 {proc.returncode}：{(proc.stderr or '').strip()[:200]}"
            except subprocess.TimeoutExpired:
                record["error"] = f"插件超时（{self.analyze_timeout}s）"
            except FileNotFoundError as exc:
                record["error"] = f"vol 不可执行：{exc}"
            except OSError as exc:
                record["error"] = f"插件执行失败：{exc}"
            if record["error"]:
                result["errors"].append(f"{plugin}: {record['error']}")
            result["plugins"].append(record)

        result["ok"] = any(
            item.get("returncode") == 0 and int(item.get("bytes") or 0) > 0 for item in result["plugins"]
        )
        log.info("Vol3 分析完成", image=str(image_path), out_dir=str(out_dir), ok=result["ok"])
        return result

    # ------------------------------------------------------------------ 互证
    def _latest_malfind(self) -> Path | None:
        """在工作目录里找最新的 malfind.txt（analyze 的默认产物）。"""
        try:
            candidates = sorted(
                self.work_dir.rglob("malfind.txt"),
                key=lambda p: p.stat().st_mtime if p.is_file() else 0,
                reverse=True,
            )
        except OSError:
            candidates = []
        return candidates[0] if candidates else None

    def compare(self, offline_malfind: str | None = None, since: str | None = None) -> dict:
        """在线 mem_hits vs 离线 malfind 互证，生成 CSV 并返回统计。"""
        result: dict[str, Any] = {
            "ok": False,
            "csv_path": None,
            "malfind": None,
            "stats": {},
            "rows": [],
            "error": None,
        }
        malfind_path = Path(os.path.expanduser(str(offline_malfind))) if offline_malfind else self._latest_malfind()
        if malfind_path is None or not malfind_path.is_file():
            result["error"] = "未找到 malfind 输出，请先执行 analyze() 或传入 offline_malfind 路径"
            return result
        result["malfind"] = str(malfind_path)
        try:
            text = malfind_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result["error"] = f"malfind 输出不可读：{exc}"
            return result
        offline = parse_malfind(text)
        try:
            online_rows = self.store.query_mem_hits(since=since)
        except Exception as exc:  # noqa: BLE001 - 查询失败按空集处理并记录
            log.warn("在线 mem_hits 查询失败", error=str(exc))
            online_rows = []

        online: dict[tuple[int, int], dict] = {}
        for row in online_rows:
            pid = _to_int(row.get("pid"))
            start = _to_int(row.get("start"))
            if pid is None or start is None:
                continue
            online[(pid, start)] = row
        off: dict[tuple[int, int], dict] = {}
        for row in offline:
            off[(int(row["pid"]), int(row["start"]))] = row

        rows: list[dict] = []
        both = only_online = only_offline = 0
        for key in sorted(set(online) | set(off)):
            pid, start = key
            on = key in online
            offln = key in off
            if on and offln:
                both += 1
            elif on:
                only_online += 1
            else:
                only_offline += 1
            src = off.get(key) or online.get(key) or {}
            rows.append(
                {
                    "pid": pid,
                    "start": _hex(start),
                    "end": _hex(_to_int(src.get("end"))),
                    "perms": str(src.get("perms") or ""),
                    "online": 1 if on else 0,
                    "offline": 1 if offln else 0,
                    "match": 1 if on == offln else 0,
                }
            )

        stats = {
            "online": len(online),
            "offline": len(off),
            "rows": len(rows),
            "both": both,
            "only_online": only_online,
            "only_offline": only_offline,
            "match": sum(1 for row in rows if row["match"]),
            "mismatch": sum(1 for row in rows if not row["match"]),
        }
        csv_path = self._write_compare_csv(rows, malfind_path.parent)
        result.update({"stats": stats, "rows": rows, "csv_path": str(csv_path) if csv_path else None})
        result["ok"] = csv_path is not None
        if csv_path is None:
            result["error"] = "互证 CSV 写入失败（目录不可写）"
        log.info("在线/离线互证完成", **{k: stats[k] for k in ("online", "offline", "match", "mismatch")})
        return result

    def _write_compare_csv(self, rows: list[dict], preferred: Path) -> Path | None:
        """写互证 CSV：优先 malfind 同目录，失败退回工作目录。"""
        candidates = [preferred / "forensics-compare.csv", self.work_dir / "forensics-compare.csv"]
        for path in candidates:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=list(COMPARE_FIELDS))
                    writer.writeheader()
                    for row in rows:
                        writer.writerow({key: row.get(key, "") for key in COMPARE_FIELDS})
                return path
            except OSError as exc:
                log.warn("互证 CSV 写入失败", path=str(path), error=str(exc))
        return None

    # ------------------------------------------------------------------ 状态
    def status(self) -> dict:
        """取证环境自检信息（供 CLI / Web 展示）。"""
        images: list[dict] = []
        try:
            if self.work_dir.is_dir():
                for path in sorted(self.work_dir.glob("*.lime*")):
                    if path.is_file():
                        try:
                            size = path.stat().st_size
                        except OSError:
                            size = 0
                        images.append({"image": str(path), "size": size})
        except OSError:
            images = []
        malfind = self._latest_malfind()
        return {
            "ok": True,
            "work_dir": str(self.work_dir),
            "avml_bin": self.avml_bin,
            "avml": self._resolve_bin(self.avml_bin) is not None,
            "vol_bin": self.vol_bin,
            "vol": self._resolve_bin(self.vol_bin) is not None,
            "symbol_dir": self.symbol_dir,
            "symbol_dir_exists": Path(self.symbol_dir).is_dir() if self.symbol_dir else False,
            "images": images[-10:],
            "malfind": str(malfind) if malfind else None,
            "last_image": self.store.get_meta("forensics.last_image") if self.store else None,
        }

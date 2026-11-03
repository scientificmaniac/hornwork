"""自研签名库引擎 SigDbEngine。

四类规则（默认目录 `rules/sigdb/`）：
- `hashes.txt` : 每行 `sha256hex` 或 `sha256hex 名称`，命中评分 100；
- `hex.txt`    : 每行 `hexpattern | 名称 | 评分`，`??` 表示任意字节，编译成 bytes 正则，评分 80；
- `regex.txt`  : 每行 `pattern | 名称 | 评分`，长度上限 + 超时保护，评分 60；
- 熵 / 结构异常由本模块直接计算：熵 >= 阈值且 size >= 下限 → 40；ELF/PE 结构异常 → 70。

ELF 用标准库 struct 解析头/程序头/节头（节名异常、入口在可写段、无节表、可写可执行节）；
PE 做轻量解析（MZ/PE 魔数、节表、入口是否落在可写节、节名异常）。
所有计算都有边界检查，损坏文件不会抛 IndexError/struct.error（返回 [] 或 None）。
"""

from __future__ import annotations

import math
import os
import re
import signal
import struct
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..config import cfg_get, rule_dir
from ..log import get_logger
from ..schema import sha256_file
from .base import BaseScanEngine, make_hit

log = get_logger("engines.sigdb")

SCORE_HASH = 100
SCORE_HEX = 80
SCORE_REGEX = 60
SCORE_ENTROPY = 40
SCORE_STRUCT = 70

_HEX_CHARS = set("0123456789abcdefABCDEF")
_HEX_HASH_LENS = (32, 40, 64, 96, 128)  # md5 / sha1 / sha256 / sha384 / sha512


class _RegexTimeout(Exception):
    """正则匹配超时（仅在支持 SIGALRM 且在主线程时可用）。"""


@contextmanager
def _time_limit(timeout_ms: int) -> Iterator[None]:
    """给一次正则匹配加软超时；平台/线程不支持时降级为无超时。"""
    can_alarm = (
        timeout_ms > 0
        and hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )
    if not can_alarm:
        yield
        return

    def _handler(_signum: int, _frame: Any) -> None:
        raise _RegexTimeout()

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, timeout_ms / 1000.0))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def _regex_search(pattern: re.Pattern, text: str, timeout_ms: int) -> re.Match | None:
    with _time_limit(timeout_ms):
        return pattern.search(text)


# ---------------------------------------------------------------------------
# 规则文件解析（模块级函数，便于单测）
# ---------------------------------------------------------------------------
def _clean_rule_line(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    return stripped


def parse_hash_line(line: str) -> tuple[str, str] | None:
    """解析哈希规则行：`hexdigest` 或 `hexdigest 名称`。"""
    stripped = _clean_rule_line(line)
    if not stripped:
        return None
    parts = stripped.split(None, 1)
    digest = parts[0].strip().lower()
    if len(digest) not in _HEX_HASH_LENS or any(ch not in _HEX_CHARS for ch in digest):
        return None
    name = parts[1].strip() if len(parts) > 1 else digest[:12]
    return digest, (name or digest[:12])


def _split_sig_line(line: str) -> list[str]:
    """按 `|` 从右侧切分（正则 pattern 内可能含 `|`）；无 `|` 时按空白切。

    返回 [pattern, name, score] 中实际存在的部分（已 strip）。
    """
    stripped = _clean_rule_line(line)
    if not stripped:
        return []
    if "|" in stripped:
        parts = [p.strip() for p in stripped.rsplit("|", 2)]
        if len(parts) == 3 and parts[2].isdigit():
            return parts
        if len(parts) >= 2:
            # 没有评分列：pattern | name
            return [parts[0], parts[1], ""]
        return [parts[0], "", ""]
    parts = stripped.split()
    if len(parts) >= 2 and parts[-1].isdigit():
        return [parts[0], " ".join(parts[1:-1]), parts[-1]]
    return [parts[0], " ".join(parts[1:]), ""]


def hex_to_regex(pattern: str) -> re.Pattern[bytes] | None:
    """把 hex 签名（`4D5A??00`）编译成 bytes 正则；非法输入返回 None。

    `??` → 任意字节；单半字节 `4?` / `?F` → 对应范围字符类。
    """
    compact = re.sub(r"[\s_]", "", str(pattern or ""))
    if not compact or len(compact) % 2 != 0:
        return None
    pieces: list[bytes] = []
    for i in range(0, len(compact), 2):
        pair = compact[i:i + 2]
        hi, lo = pair[0].upper(), pair[1].upper()
        if hi == "?" and lo == "?":
            pieces.append(b".")
        elif hi == "?" or lo == "?":
            fixed = lo if hi == "?" else hi
            if fixed not in _HEX_CHARS:
                return None
            fixed_nibble = int(fixed, 16)
            if hi == "?":      # 高半字节通配：低半字节固定
                values = [high * 16 + fixed_nibble for high in range(16)]
            else:              # 低半字节通配：高半字节固定
                values = [fixed_nibble * 16 + low for low in range(16)]
            pieces.append(b"[" + b"".join(re.escape(bytes([v])) for v in values) + b"]")
        else:
            if hi not in _HEX_CHARS or lo not in _HEX_CHARS:
                return None
            pieces.append(re.escape(bytes([int(pair, 16)])))
    try:
        return re.compile(b"".join(pieces), re.DOTALL)
    except re.error:
        return None


def parse_hex_line(line: str) -> dict | None:
    """解析 hex 规则行，返回 {pattern, name, score, regex}。"""
    parts = _split_sig_line(line)
    if not parts:
        return None
    pattern = parts[0]
    name = parts[1] if len(parts) > 1 and parts[1] else pattern
    score = int(parts[2]) if len(parts) > 2 and parts[2] else SCORE_HEX
    compiled = hex_to_regex(pattern)
    if compiled is None:
        raise ValueError(f"非法 hex 签名: {pattern!r}")
    return {
        "pattern": pattern,
        "name": name,
        "score": max(0, min(100, int(score))),
        "regex": compiled,
    }


def parse_regex_line(line: str, max_len: int = 2048) -> dict:
    """解析正则规则行，返回 {pattern, name, score, regex}；非法时抛 ValueError。"""
    parts = _split_sig_line(line)
    if not parts:
        raise ValueError("空规则行")
    raw = parts[0]
    if len(raw) > max_len:
        raise ValueError(f"正则过长（{len(raw)} > {max_len}）")
    name = parts[1] if len(parts) > 1 and parts[1] else raw
    score = int(parts[2]) if len(parts) > 2 and parts[2] else SCORE_REGEX
    compiled = re.compile(raw)
    return {
        "pattern": raw,
        "name": name,
        "score": max(0, min(100, int(score))),
        "regex": compiled,
    }


# ---------------------------------------------------------------------------
# 熵与结构解析
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """256 桶字节频率香农熵（bit/byte，0.0~8.0）。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _elf_section_name(shstr: bytes, offset: int) -> str:
    if not shstr or offset < 0 or offset >= len(shstr):
        return ""
    end = shstr.find(b"\x00", offset)
    if end < 0:
        end = len(shstr)
    return shstr[offset:end].decode("utf-8", "replace")


def parse_elf(data: bytes) -> dict | None:
    """解析 ELF 头/程序头/节头；非 ELF 或严重损坏返回 None。"""
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        return None
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    ehsize = 64 if is64 else 52
    if len(data) < ehsize:
        return None
    header_fmt = endian + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    try:
        fields = struct.unpack_from(header_fmt, data, 16)
    except struct.error:
        return None
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = fields
    info: dict[str, Any] = {
        "class": 64 if is64 else 32,
        "endian": "little" if ei_data == 1 else "big",
        "type": e_type,
        "machine": e_machine,
        "entry": e_entry,
        "phoff": e_phoff,
        "shoff": e_shoff,
        "phnum": e_phnum,
        "shnum": e_shnum,
        "phentsize": e_phentsize,
        "shentsize": e_shentsize,
        "shstrndx": e_shstrndx,
        "programs": [],
        "sections": [],
    }

    # 程序头（最多看 256 个，防止损坏文件导致大循环）
    if e_phoff and e_phnum and e_phentsize:
        for index in range(min(int(e_phnum), 256)):
            off = e_phoff + index * e_phentsize
            try:
                if is64:
                    p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = \
                        struct.unpack_from(endian + "IIQQQQQQ", data, off)
                else:
                    p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = \
                        struct.unpack_from(endian + "IIIIIIII", data, off)
            except struct.error:
                break
            info["programs"].append({
                "type": p_type, "flags": p_flags, "offset": p_offset,
                "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz,
            })

    # 节头
    raw_sections: list[dict] = []
    if e_shoff and e_shnum and e_shentsize:
        for index in range(min(int(e_shnum), 256)):
            off = e_shoff + index * e_shentsize
            try:
                if is64:
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                     sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
                        endian + "IIQQQQIIQQ", data, off)
                else:
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                     sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
                        endian + "IIIIIIIIII", data, off)
            except struct.error:
                break
            raw_sections.append({
                "index": index, "name_off": sh_name, "type": sh_type, "flags": sh_flags,
                "addr": sh_addr, "offset": sh_offset, "size": sh_size,
                "link": sh_link, "info": sh_info, "addralign": sh_addralign,
                "entsize": sh_entsize,
            })
    shstr = b""
    if raw_sections and 0 <= e_shstrndx < len(raw_sections):
        tab = raw_sections[e_shstrndx]
        start = int(tab["offset"])
        end = start + int(tab["size"])
        if 0 <= start <= end <= len(data):
            shstr = data[start:end]
    for section in raw_sections:
        section["name"] = _elf_section_name(shstr, int(section["name_off"]))
        info["sections"].append(section)
    return info


def elf_anomalies(info: dict | None) -> list[tuple[str, str]]:
    """ELF 结构异常判定，返回 [(异常码, 说明)]。"""
    anomalies: list[tuple[str, str]] = []
    if not info:
        return anomalies
    if not info.get("shoff") or not info.get("shnum"):
        anomalies.append(("no_section_table", "ELF 无节表（常见于加壳/裁剪二进制）"))
    entry = int(info.get("entry") or 0)
    if entry:
        for program in info.get("programs") or []:
            if int(program.get("type") or 0) != 1:  # PT_LOAD
                continue
            if not (int(program.get("flags") or 0) & 0x2):  # PF_W
                continue
            base = int(program.get("vaddr") or 0)
            size = max(int(program.get("memsz") or 0), 1)
            if base <= entry < base + size:
                anomalies.append((
                    "entry_in_writable_segment",
                    f"入口 0x{entry:x} 落在可写 LOAD 段（疑似加壳）",
                ))
                break
    for section in info.get("sections") or []:
        flags = int(section.get("flags") or 0)
        if flags & 0x1 and flags & 0x4:  # SHF_WRITE | SHF_EXECINSTR
            name = section.get("name") or f"#{section.get('index')}"
            anomalies.append(("writable_exec_section", f"节 {name} 同时可写可执行"))
            break
    for section in info.get("sections") or []:
        name = str(section.get("name") or "")
        if name and any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in name):
            anomalies.append(("bad_section_name", f"节名含不可打印字符 {name!r}"))
            break
    return anomalies


def parse_pe(data: bytes) -> dict | None:
    """轻量 PE 解析：MZ/PE 魔数、COFF 头、可选头入口点、节表。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    try:
        machine, nsections, _ts, _symptr, _nsym, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, coff)
    except struct.error:
        return None
    opt_off = coff + 20
    if opt_off + 2 > len(data):
        return None
    try:
        magic = struct.unpack_from("<H", data, opt_off)[0]
    except struct.error:
        return None
    if magic not in (0x10B, 0x20B):
        return None
    try:
        entry = struct.unpack_from("<I", data, opt_off + 16)[0]
    except struct.error:
        return None
    sections: list[dict] = []
    sec_off = opt_off + opt_size
    for index in range(min(int(nsections), 96)):
        off = sec_off + index * 40
        try:
            name_raw, vsize, vaddr, raw_size, raw_ptr, _reloc, _lines, _nrel, _nlin, chars = \
                struct.unpack_from("<8sIIIIIIHHI", data, off)
        except struct.error:
            break
        name = name_raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        sections.append({
            "index": index, "name": name, "vsize": vsize, "vaddr": vaddr,
            "raw_size": raw_size, "raw_ptr": raw_ptr, "characteristics": chars,
        })
    return {
        "machine": machine,
        "nsections": nsections,
        "characteristics": characteristics,
        "optional_magic": magic,
        "entry": entry,
        "sections": sections,
    }


def pe_anomalies(info: dict | None) -> list[tuple[str, str]]:
    """PE 结构异常判定，返回 [(异常码, 说明)]。"""
    anomalies: list[tuple[str, str]] = []
    if not info:
        return anomalies
    if not info.get("nsections") or not info.get("sections"):
        anomalies.append(("no_section_table", "PE 无节表（疑似加壳/损坏）"))
    entry = int(info.get("entry") or 0)
    if entry:
        for section in info.get("sections") or []:
            chars = int(section.get("characteristics") or 0)
            if not (chars & 0x80000000):  # IMAGE_SCN_MEM_WRITE
                continue
            base = int(section.get("vaddr") or 0)
            size = max(int(section.get("vsize") or 0), 1)
            if base <= entry < base + size:
                anomalies.append((
                    "entry_in_writable_segment",
                    f"入口 RVA 0x{entry:x} 落在可写节 {section.get('name')}",
                ))
                break
    for section in info.get("sections") or []:
        chars = int(section.get("characteristics") or 0)
        if chars & 0x80000000 and chars & 0x20000000:  # WRITE + EXECUTE
            anomalies.append((
                "writable_exec_section",
                f"节 {section.get('name')} 同时可写可执行",
            ))
            break
    for section in info.get("sections") or []:
        name = str(section.get("name") or "")
        if name and any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in name):
            anomalies.append(("bad_section_name", f"节名含不可打印字符 {name!r}"))
            break
    return anomalies


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------
class SigDbEngine(BaseScanEngine):
    """自研签名库引擎：哈希 / hex / 正则 / 熵 / 结构。"""

    name = "sigdb"
    version = "1.0"
    cost = "fast"

    def __init__(self, cfg: dict, store: Any = None):
        self.cfg = dict(cfg or {})
        self.store = store
        max_size_mb = int(cfg_get(self.cfg, "engines.max_size_mb", 100) or 100)
        self.max_size = max(1, max_size_mb) * 1024 * 1024
        scan_cap = int(cfg_get(self.cfg, "engines.sigdb.max_scan_bytes", 64 * 1024 * 1024)
                       or 64 * 1024 * 1024)
        self.max_scan_bytes = min(self.max_size, scan_cap)
        self.entropy_threshold = float(cfg_get(self.cfg, "engines.sigdb.entropy_threshold", 7.2))
        self.entropy_min_size = int(cfg_get(self.cfg, "engines.sigdb.entropy_min_size", 4096) or 4096)
        self.regex_timeout_ms = int(cfg_get(self.cfg, "engines.sigdb.regex_timeout_ms", 200) or 0)
        self.regex_max_len = int(cfg_get(self.cfg, "engines.sigdb.regex_max_len", 2048) or 2048)
        self.base_dir = rule_dir(self.cfg, "sigdb")
        self.hash_path = self._rule_file("hash_file", "hashes.txt")
        self.hex_path = self._rule_file("hex_file", "hex.txt")
        self.regex_path = self._rule_file("regex_file", "regex.txt")
        self._lock = threading.Lock()
        self.hashes: dict[str, str] = {}
        self.hex_rules: list[dict] = []
        self.regex_rules: list[dict] = []
        self.errors: list[str] = []
        self.reload()

    # ------------------------------------------------------------ 规则文件
    def _rule_file(self, key: str, default_name: str) -> Path:
        configured = cfg_get(self.cfg, f"engines.sigdb.{key}", "")
        if configured:
            path = Path(str(configured))
            if path.is_file():
                return path
        return self.base_dir / default_name

    @staticmethod
    def _read_lines(path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

    def reload(self) -> dict:
        """重新读取规则目录，返回 {"hashes","hex","regex","errors"}。"""
        errors: list[str] = []
        hashes: dict[str, str] = {}
        hex_rules: list[dict] = []
        regex_rules: list[dict] = []

        if self.hash_path.is_file():
            for lineno, line in enumerate(self._read_lines(self.hash_path), start=1):
                try:
                    parsed = parse_hash_line(line)
                except ValueError as exc:  # 理论上不会抛，防御
                    errors.append(f"hashes.txt:{lineno}: {exc}")
                    continue
                if parsed:
                    digest, name = parsed
                    hashes[digest] = name
        else:
            log.debug("哈希规则文件不存在", path=str(self.hash_path))

        if self.hex_path.is_file():
            for lineno, line in enumerate(self._read_lines(self.hex_path), start=1):
                if not _clean_rule_line(line):
                    continue
                try:
                    parsed_hex = parse_hex_line(line)
                except (ValueError, re.error) as exc:
                    errors.append(f"hex.txt:{lineno}: {exc}")
                    continue
                if parsed_hex:
                    hex_rules.append(parsed_hex)
        else:
            log.debug("hex 规则文件不存在", path=str(self.hex_path))

        if self.regex_path.is_file():
            for lineno, line in enumerate(self._read_lines(self.regex_path), start=1):
                if not _clean_rule_line(line):
                    continue
                try:
                    parsed_re = parse_regex_line(line, max_len=self.regex_max_len)
                except (ValueError, re.error) as exc:
                    errors.append(f"regex.txt:{lineno}: {exc}")
                    continue
                regex_rules.append(parsed_re)
        else:
            log.debug("正则规则文件不存在", path=str(self.regex_path))

        with self._lock:
            self.hashes = hashes
            self.hex_rules = hex_rules
            self.regex_rules = regex_rules
            self.errors = errors
        if errors:
            log.warn("sigdb 规则加载存在错误", count=len(errors), first=errors[0])
        return {
            "hashes": len(hashes),
            "hex": len(hex_rules),
            "regex": len(regex_rules),
            "errors": list(errors),
        }

    # ------------------------------------------------------------ 引擎协议
    def available(self) -> bool:
        return True

    def supports(self, ctx: dict) -> bool:
        ctx = ctx or {}
        size = ctx.get("size")
        try:
            return size is None or int(size) <= self.max_size
        except (TypeError, ValueError):
            return True

    def scan(self, path: str, ctx: dict) -> list[dict]:
        """扫描单个文件，返回 Hit 列表。"""
        ctx = dict(ctx or {})
        try:
            size = int(ctx.get("size") if ctx.get("size") is not None else os.path.getsize(path))
        except OSError:
            raise
        sha = sha256_file(path)
        hits: list[dict] = []

        # 1) 哈希
        family = self.hashes.get(sha)
        if family:
            hits.append(make_hit(
                self.name, f"hash:{sha[:16]}", f"已知恶意哈希：{family}", SCORE_HASH,
                {"family": family, "sha256": sha, "attack": ["T1204"], "source": "sigdb-hash"},
                {"sha256": sha, "matched": family, "path": str(path), "size": size},
            ))

        # 2) 内容签名（大文件只算哈希，与级联的 max_size 策略一致）
        data = b""
        if 0 < size <= self.max_scan_bytes:
            try:
                with open(path, "rb") as handle:
                    data = handle.read(self.max_scan_bytes)
            except OSError:
                log.warn("sigdb 读取文件失败", path=str(path))
                data = b""

        if data:
            with self._lock:
                hex_rules = list(self.hex_rules)
                regex_rules = list(self.regex_rules)
            for rule in hex_rules:
                try:
                    match = rule["regex"].search(data)
                except (re.error, RuntimeError) as exc:
                    log.warn("hex 规则匹配失败", rule=rule["name"], err=str(exc))
                    continue
                if match:
                    hits.append(make_hit(
                        self.name, f"hex:{rule['name']}", rule["name"], rule["score"],
                        {"family": rule["name"], "pattern": rule["pattern"], "source": "sigdb-hex"},
                        {"offset": match.start(), "matched": rule["pattern"], "path": str(path)},
                    ))
            text = data.decode("latin-1")
            for rule in regex_rules:
                try:
                    match = _regex_search(rule["regex"], text, self.regex_timeout_ms)
                except _RegexTimeout:
                    log.warn("正则匹配超时，已跳过", rule=rule["name"], path=str(path))
                    continue
                except (re.error, RuntimeError) as exc:
                    log.warn("正则规则匹配失败", rule=rule["name"], err=str(exc))
                    continue
                if match:
                    hits.append(make_hit(
                        self.name, f"regex:{rule['name']}", rule["name"], rule["score"],
                        {"family": rule["name"], "pattern": rule["pattern"], "source": "sigdb-regex"},
                        {"offset": match.start(), "matched": match.group(0)[:200], "path": str(path)},
                    ))

        # 3) 熵
        if size >= self.entropy_min_size:
            entropy = self.compute_entropy(path, data=data or None)
            if entropy >= self.entropy_threshold:
                hits.append(make_hit(
                    self.name, "entropy:high", "高熵文件（疑似加密/压缩载荷）", SCORE_ENTROPY,
                    {"entropy": entropy, "threshold": self.entropy_threshold,
                     "attack": ["T1027"], "source": "sigdb-entropy"},
                    {"entropy": entropy, "threshold": self.entropy_threshold,
                     "path": str(path), "size": size},
                ))

        # 4) 结构异常
        if size and data:
            hits.extend(self.structural_hits(path, data=data))
        return hits

    # ------------------------------------------------------------ 熵 / 结构
    def compute_entropy(self, path: str, data: bytes | None = None) -> float:
        """计算文件字节熵（256 桶香农熵）。"""
        if data is not None:
            return shannon_entropy(data)
        counts = [0] * 256
        total = 0
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                for byte in chunk:
                    counts[byte] += 1
        if not total:
            return 0.0
        entropy = 0.0
        for count in counts:
            if count:
                p = count / float(total)
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def structural_hits(self, path: str, data: bytes | None = None) -> list[dict]:
        """ELF/PE 结构异常命中（评分 70）。"""
        if data is None:
            try:
                with open(path, "rb") as handle:
                    data = handle.read(self.max_scan_bytes)
            except OSError:
                return []
        if not data:
            return []
        kind = "elf"
        info = parse_elf(data)
        if info is None:
            kind = "pe"
            info = parse_pe(data)
        if info is None:
            return []
        anomalies = elf_anomalies(info) if kind == "elf" else pe_anomalies(info)
        hits: list[dict] = []
        for code, detail in anomalies:
            hits.append(make_hit(
                self.name, f"struct:{code}", f"{kind.upper()} 结构异常：{code}", SCORE_STRUCT,
                {"kind": kind, "anomaly": code, "detail": detail,
                 "attack": ["T1027"], "source": "sigdb-struct"},
                {"path": str(path), "kind": kind, "anomaly": code, "detail": detail,
                 "size": len(data)},
            ))
        return hits

#!/usr/bin/env python3
"""把 CLI 行为基线里的「非确定项」归一化，只留下可比较的确定性内容。

归一化的四类内容（均由子代理实测确认"连跑两次就会不同"）：

1. 绝对时间戳：``20261121-190619`` / ``2026-11-21T11:06:16Z`` / ``run-20261121-110625-f6e9fb``；
2. 随机/递增 ID：``ast-20261121T110622-8EA0F3`` 的随机后缀、``run-<ts>-<hex>`` 的 hex；
3. 仓库绝对路径：``/tmp/orig-repo`` 与 ``/home/kxfz/hornwork`` 必须视为等价；
4. Python traceback 的调用栈：重构必然改变文件名与行号，因此只保留**异常类型与消息**
   （即最后一行的 ``SomeError: message``），中间帧全部丢弃；
5. 计时与哈希：``耗时=204ms``、``p50_ms`` 等性能数字；报告文件的 ``sha256``
   （内容里含时间戳，哈希必然不同）；
6. 文件头里的环境元数据：git 状态、``HORNWORK_DATA_DIR`` 覆盖路径 —— 二者是
   采集环境的差异，不是 CLI 行为差异。

退出码（``#### EXIT:``）**绝不归一化** —— 它是本次比对的核心证据。

用法：
    python3 normalize_baseline.py <in.txt> <out.txt>
"""

from __future__ import annotations

import re
import sys

# 仓库根路径 → 统一占位符
_REPO_PATTERNS = (
    re.compile(r"/tmp/orig-repo"),
    re.compile(r"/home/kxfz/hornwork"),
)
_REPO_TOKEN = "<REPO>"

# 时间戳：20261121-190619 / 20261121T110622 / 2026-11-21T11:06:16Z / 2026-11-21 11:06:16
_TS_PATTERNS = (
    re.compile(r"\d{8}-\d{6}"),
    re.compile(r"\d{8}T\d{6}"),
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"),
    re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
)

# 随机 ID 后缀：ast-<ts>-8EA0F3 / run-<ts>-f6e9fb / run-<ts>-<uuid6>
_RANDOM_SUFFIX = re.compile(r"-[0-9A-Fa-f]{6}(?=\b|\.)")

# ``verify`` 报告文件名：run-<ts>[-<hex>].json —— hex 后缀取决于
# ``verify/runner.py`` 中 run_id 的构造，属仓库既有实现差异（非 CLI 分层改动），
# 归一化时把可选 hex 段一并抹掉，避免把"别人未提交的业务改动"误判成本次回归。
_REPORT_ID = re.compile(r"run-<TS>(?:-[0-9A-Fa-f]{6})?(?=\.)")

# 性能数字（不是哈希：哈希单独处理，否则会被逐字符替换）
_TIMING = (
    re.compile(r"耗时=\d+ms"),
    re.compile(r'"p50_ms": [\d.]+'),
    re.compile(r'"p95_ms": [\d.]+'),
    re.compile(r'"min_ms": [\d.]+'),
    re.compile(r'"max_ms": [\d.]+'),
)

# 报告文件哈希：内容含时间戳，必然不同 —— 整值替换，不能逐字符改
_SHA256 = re.compile(r'"[0-9a-f]{64}"')

# 文件头里的环境元数据（仓库路径/git 状态/数据目录），与 CLI 行为无关
_HEADER_NOISE = (
    re.compile(r"^# git: .*$"),
    re.compile(r"^# 模式: .*$"),
    re.compile(r"^#\s+env .*HORNWORK_DATA_DIR=.*$"),
)
_HEADER_NOISE_REPLACEMENT = "# <ENV-NOISE>"

# traceback 的一帧（含 "  File ..., line N, in x" 与紧随的源码行/波浪线）
_TRACE_FRAME = re.compile(r"^  File \".*\", line \d+, in .*$")
_TRACE_SRC = re.compile(r"^    .*$")
_TRACE_CARET = re.compile(r"^ *[~^]+ *$")
_TRACE_DOTS = re.compile(r"^    \.\.\.<\d+ lines>\.\.\.$")


def _normalize_line(line: str) -> str:
    for pattern in _HEADER_NOISE:
        if pattern.match(line):
            return _HEADER_NOISE_REPLACEMENT
    for pattern in _REPO_PATTERNS:
        line = pattern.sub(_REPO_TOKEN, line)
    for pattern in _TS_PATTERNS:
        line = pattern.sub("<TS>", line)
    line = _REPORT_ID.sub("run-<TS>", line)
    line = _SHA256.sub('"<SHA256>"', line)
    for pattern in _TIMING:
        line = pattern.sub(lambda m: re.sub(r"[\d.]+", "<N>", m.group(0)), line)
    line = _RANDOM_SUFFIX.sub("-<HEX>", line)
    return line


def normalize(text: str) -> str:
    """逐行归一化；traceback 折叠成「单帧 + 末行异常」。"""
    out: list[str] = []
    in_traceback = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if line == "Traceback (most recent call last):":
            in_traceback = True
            out.append("Traceback (most recent call last):")
            out.append("<FRAMES COLLAPSED>")
            continue
        if in_traceback:
            # 异常末行：非缩进且含 ":" —— 保留（这是对外可见的错误类型与消息）
            if line and not line.startswith(" ") and ":" in line:
                out.append(_normalize_line(line))
                in_traceback = False
            # 其余（帧/源码/波浪线/省略号）全部丢弃
            continue
        out.append(_normalize_line(line))
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as handle:
        text = handle.read()
    with open(argv[1], "w", encoding="utf-8") as handle:
        handle.write(normalize(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

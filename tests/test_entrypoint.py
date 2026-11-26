"""控制台入口 smoke test。

验证 ``pyproject.toml`` 声明的两条对外入口都能真正启动：

- ``python -m hornwork.cli``（源码路径，任何环境都可测）；
- ``hornworkctl``（``[project.scripts]`` 安装的控制台脚本，CI 在
  ``pip install -e .`` 后必然存在；本地未安装时自动跳过该分支）。

这些用例只走到 argparse 的 ``--version`` / ``--help``，不连接控制面 socket、
不触碰 Linux 专属能力，因此在 Windows / macOS 开发机与 CI 全矩阵都能运行。
它们锁定的契约是：包能 import、入口能解析、输出含版本号与顶层子命令——
防止「``pyproject.toml`` 的入口声明写错」或「入口模块 import 链断裂」这类
只有安装后才暴露的问题从 CI 缝隙溜过。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork import __version__  # noqa: E402
from hornwork.commands import COMMANDS  # noqa: E402


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """在子进程里跑一条命令，固定编码与超时，返回完整结果。"""
    env = dict(os.environ)
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"})
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )


class ModuleEntrypointTest(unittest.TestCase):
    """``python -m hornwork.cli`` 路径。"""

    def test_version(self) -> None:
        result = _run([sys.executable, "-m", "hornwork.cli", "--version"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hornworkctl", result.stdout)
        self.assertIn(__version__, result.stdout)

    def test_help_lists_top_level_commands(self) -> None:
        result = _run([sys.executable, "-m", "hornwork.cli", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for module in COMMANDS:
            with self.subTest(command=module.NAME):
                self.assertIn(module.NAME, result.stdout)


class InstalledScriptTest(unittest.TestCase):
    """``hornworkctl`` 控制台脚本路径（安装后存在）。"""

    @unittest.skipUnless(shutil.which("hornworkctl"), "hornworkctl 未安装，跳过脚本入口验证")
    def test_version(self) -> None:
        result = _run(["hornworkctl", "--version"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hornworkctl", result.stdout)
        self.assertIn(__version__, result.stdout)

    @unittest.skipUnless(shutil.which("hornworkctl"), "hornworkctl 未安装，跳过脚本入口验证")
    def test_help(self) -> None:
        result = _run(["hornworkctl", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status", result.stdout)


if __name__ == "__main__":
    unittest.main()

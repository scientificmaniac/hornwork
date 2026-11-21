"""CLI 拆分架构的回归测试。

这些用例锁定的是**结构契约**，不是业务行为：

- 子命令注册表与磁盘文件一致、顺序稳定；
- 命令模块只导出契约符号、互不引用；
- ``cli_common`` 不反向依赖命令层；
- 入口 ``build_parser()`` 的顶层顺序与 ``--help`` 契约不变；
- ``_normalize_argv`` 对旧写法 ``scan <path>`` 的兼容行为不变。

它们在 Windows 开发机上也能跑（不触碰 Linux 专属能力），因此能进 CI 全矩阵。
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from hornwork import cli
from hornwork.commands import COMMANDS
from hornwork.cli_common.constants import SCAN_SUBCOMMANDS

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "hornwork"
COMMANDS_DIR = PKG / "commands"
SCAN_DIR = COMMANDS_DIR / "scan"
COMMON_DIR = PKG / "cli_common"

EXPECTED_TOP_LEVEL = [
    "status", "events", "alerts", "scan", "asset", "mem", "rules", "intel",
    "case", "respond", "verify", "audit", "forensics", "lab", "vuln", "auth",
    "export", "prune",
]
"""顶层子命令及其展示顺序。

顺序是对外契约的一部分：``--help`` 与 shell 补全据此渲染，因此改动即为
破坏性变更，必须显式改这个测试并说明原因。
"""


def _resolved_imports(path: Path) -> set[str]:
    """把文件里的 import 解析成绝对模块路径（含相对导入）。"""
    package = ".".join(path.parent.relative_to(REPO).parts)
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0:
                found.add(module)
            else:
                parts = package.split(".")
                base = parts[: len(parts) - (node.level - 1)] if node.level > 1 else parts
                found.add(".".join([*base, module]) if module else ".".join(base))
    return found


class CommandRegistryTest(unittest.TestCase):
    """注册表与模块契约。"""

    def test_top_level_order_is_stable(self):
        self.assertEqual([module.NAME for module in COMMANDS], EXPECTED_TOP_LEVEL)

    def test_every_command_module_matches_registry(self):
        for module in COMMANDS:
            expected_path = COMMANDS_DIR / f"{module.__name__.rsplit('.', 1)[-1]}.py"
            if not expected_path.is_file():
                # scan 是多文件子包，入口为 scan/__init__.py
                expected_path = COMMANDS_DIR / module.__name__.rsplit(".", 1)[-1] / "__init__.py"
            self.assertTrue(expected_path.is_file(), f"缺少模块文件 {expected_path}")

    def test_each_command_exports_contract(self):
        for module in COMMANDS:
            for symbol in ("NAME", "HELP", "register", "run"):
                self.assertTrue(
                    hasattr(module, symbol),
                    f"{module.__name__} 缺少契约符号 {symbol}",
                )
            self.assertIsInstance(module.NAME, str)
            self.assertIsInstance(module.HELP, str)

    def test_command_names_are_unique(self):
        names = [module.NAME for module in COMMANDS]
        self.assertEqual(len(names), len(set(names)))

    def test_commands_do_not_import_each_other(self):
        """命令模块之间零互相 import（子包内部的模块间引用不算违规）。"""
        for path in sorted(COMMANDS_DIR.rglob("*.py")):
            stem = path.stem
            # 子包自身的 __init__ 天然要导入自己的成员，跳过
            if stem == "__init__" and path.parent != COMMANDS_DIR:
                continue
            for module in _resolved_imports(path):
                if not module.startswith("hornwork.commands."):
                    continue
                target = module.rsplit(".", 1)[-1]
                if target in (stem, "commands"):
                    continue
                self.fail(f"{path.relative_to(PKG)} 引用了兄弟命令模块 {module}")

    def test_scan_subpackages_export_contract(self):
        """``commands/scan/*.py`` 每个模块都要有 NAME/HELP/register/run。"""
        import importlib

        for path in sorted(SCAN_DIR.glob("*.py")):
            if path.stem == "__init__":
                continue
            module = importlib.import_module(f"hornwork.commands.scan.{path.stem}")
            for symbol in ("NAME", "HELP", "register", "run"):
                self.assertTrue(
                    hasattr(module, symbol),
                    f"commands/scan/{path.name} 缺少契约符号 {symbol}",
                )


class CommonLayerTest(unittest.TestCase):
    """公共层的依赖方向。"""

    def test_cli_common_never_imports_upper_layers(self):
        for path in sorted(COMMON_DIR.glob("*.py")):
            for module in _resolved_imports(path):
                self.assertNotEqual(module, "hornwork.cli", f"{path.name} 反向依赖入口")
                self.assertFalse(
                    module == "hornwork.commands" or module.startswith("hornwork.commands."),
                    f"{path.name} 依赖命令层 {module}",
                )


class ParserSurfaceTest(unittest.TestCase):
    """解析器的对外表面。"""

    def test_build_parser_is_idempotent(self):
        """重复构建不应共享状态（防止 argparse 子解析器被二次挂载）。"""
        first = cli.build_parser()
        second = cli.build_parser()
        self.assertEqual(
            sorted(first._subparsers._group_actions[0].choices),
            sorted(second._subparsers._group_actions[0].choices),
        )

    def test_scan_legacy_path_is_normalized(self):
        self.assertEqual(
            cli._normalize_argv(["scan", "/tmp/eicar.com"]),
            ["scan", "file", "/tmp/eicar.com"],
        )

    def test_scan_known_subcommand_is_untouched(self):
        self.assertEqual(cli._normalize_argv(["scan", "run"]), ["scan", "run"])
        self.assertEqual(cli._normalize_argv(["scan", "diff"]), ["scan", "diff"])

    def test_scan_legacy_with_flags_keeps_order(self):
        self.assertEqual(
            cli._normalize_argv(["scan", "--deep", "/tmp/x"]),
            ["scan", "--deep", "file", "/tmp/x"],
        )

    def test_other_commands_are_never_normalized(self):
        self.assertEqual(cli._normalize_argv(["events"]), ["events"])
        self.assertEqual(cli._normalize_argv([]), [])

    def test_every_scan_subcommand_is_known(self):
        """``SCAN_SUBCOMMANDS`` 必须覆盖实际挂载的全部 ``scan`` 子命令。"""
        parser = cli.build_parser()
        scan_parser = parser._subparsers._group_actions[0].choices["scan"]
        mounted = set(scan_parser._subparsers._group_actions[0].choices)
        self.assertEqual(mounted, SCAN_SUBCOMMANDS)


class FileSizeTest(unittest.TestCase):
    """拆分后每个文件都应保持适中体量。"""

    def test_no_oversized_module(self):
        for directory in (COMMON_DIR, COMMANDS_DIR):
            for path in sorted(directory.rglob("*.py")):
                lines = len(path.read_text(encoding="utf-8").splitlines())
                self.assertLessEqual(
                    lines, 400, f"{path.relative_to(REPO)} 已 {lines} 行，需要再拆分"
                )

    def test_entrypoint_stays_minimal(self):
        lines = len((PKG / "cli.py").read_text(encoding="utf-8").splitlines())
        self.assertLessEqual(lines, 200, f"入口已 {lines} 行，业务逻辑应移入 commands/")


if __name__ == "__main__":
    unittest.main()

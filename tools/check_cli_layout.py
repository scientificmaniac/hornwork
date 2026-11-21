#!/usr/bin/env python3
"""CLI 拆分架构自检：依赖方向、循环导入、命令契约、文件体量。

这是一份**可执行的架构约束**，不是文档里的一句话。CI 里跑它就能防止后续有人
（包括我自己）在 ``commands/`` 里互相 import，或在 ``cli_common`` 里反向引用
入口。检查项：

1. **依赖方向**：``cli_common`` 不得引用 ``hornwork.cli`` / ``hornwork.commands``；
2. **命令间隔离**：``commands/*.py`` 不得互相 import 兄弟命令模块；
3. **顶层依赖白名单**：命令模块**顶层**只能导入 ``cli_common.*``、纯标准库
   业务模块与标准库；业务子系统必须函数内惰性导入。这条最关键 —— 它决定
   "某个可选依赖缺失时会不会拖垮整个 CLI，连 ``--version`` 都跑不起来"；
4. **循环导入**：逐个 import 每个模块并断言成功；
5. **命令契约**：每个命令模块都导出 ``NAME`` / ``HELP`` / ``register`` / ``run``，
   且同一层级内 ``NAME`` 唯一；
6. **注册表一致**：``COMMANDS``、``SCAN_SUBCOMMANDS`` 与磁盘文件三方一致；
7. **文件体量**：任何 ``cli_common`` / ``commands`` 文件不超过 400 行。

用法：
    python3 tools/check_cli_layout.py            # 正常检查，通过则退出 0
    python3 tools/check_cli_layout.py -v         # 打印每个文件的体量明细
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "hornwork"
COMMON_DIR = PKG / "cli_common"
COMMANDS_DIR = PKG / "commands"

MAX_LINES = 400
"""单文件行数上限。超限说明拆分粒度不够，应再拆一层。"""

REQUIRED_EXPORTS = ("NAME", "HELP", "register", "run")
"""命令模块的契约符号。"""

SUB_PACKAGES = {"scan"}
"""二级子命令成包子命令：``commands/scan/`` 内部每个文件都是一个二级子命令。"""

TOP_LEVEL_ALLOWED_PREFIXES = (
    "hornwork.cli_common",
    "hornwork.config",   # tomllib + 标准库，无三方依赖
)
"""命令模块**顶层**允许导入的非标准库模块前缀。

其余业务子系统（scan/lab/vuln/verify/respond/auth/engines/collectors…）**必须**
在函数内导入：它们可能依赖 yara-python / argon2-cffi / cryptography，一旦在
模块顶层导入，缺依赖环境里整个 CLI 连 ``--version`` 都跑不起来。
"""

TOP_LEVEL_ALLOWED_EXACT = (
    "hornwork",          # 只为取 __version__，纯字面量
)
"""额外允许的精确模块名。"""


class CheckFailed(RuntimeError):
    """检查失败。"""


def _module_names(path: Path) -> list[str]:
    """列出目录下的模块名（跳过 ``__init__``）。"""
    return sorted(p.stem for p in path.glob("*.py") if p.stem != "__init__")


def command_module_paths() -> list[Path]:
    """列出全部命令实现文件：顶层命令模块 + 子包内的二级子命令模块。"""
    paths = [p for p in COMMANDS_DIR.glob("*.py") if p.stem != "__init__"]
    for package in SUB_PACKAGES:
        paths.extend(p for p in (COMMANDS_DIR / package).glob("*.py") if p.stem != "__init__")
    return sorted(paths)


def _package_of(path: Path) -> str:
    """按文件路径推导其所属包，例如 ``hornwork/commands/x.py`` → ``hornwork.commands``。"""
    rel = path.parent.relative_to(REPO)
    return ".".join(rel.parts)


def _resolve(module: str, level: int, path: Path) -> str:
    """把 ``from ..scan import store`` 解析成绝对模块路径 ``hornwork.scan``。

    ``level`` 是 ``ImportFrom.level``：1 = 当前包，2 = 上一级，依此类推。
    这一步是必须的 —— 否则 ``commands/scan_plan.py`` 里的 ``from ..scan import``
    会被误判成"引用了兄弟命令 ``commands/scan.py``"，而它实际指的是业务包
    ``hornwork.scan``。
    """
    if level == 0:
        return module
    parts = _package_of(path).split(".")
    # level=1 留在当前包，level=2 退一级
    base = parts[: len(parts) - (level - 1)] if level > 1 else parts
    return ".".join([*base, module]) if module else ".".join(base)


def _imports(path: Path) -> set[str]:
    """收集一个文件里所有 import 的**绝对**模块路径。"""
    found: set[str] = set()
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and (node.module or node.level):
            found.add(_resolve(node.module or "", node.level, path))
    return found


def _parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def check_dependency_direction() -> list[str]:
    """``cli_common`` 不得引用入口 ``hornwork.cli`` 或命令包 ``hornwork.commands``。"""
    problems: list[str] = []
    for path in sorted(COMMON_DIR.glob("*.py")):
        for module in _imports(path):
            if module == "hornwork.cli":
                problems.append(f"{path.name}: 引用了入口 hornwork.cli（反向依赖）")
            elif module == "hornwork.commands" or module.startswith("hornwork.commands."):
                problems.append(f"{path.name}: 引用了 {module}（公共层不能依赖命令层）")
    return problems


def check_command_isolation() -> list[str]:
    """命令模块之间不得互相 import（兄弟命令或 ``commands`` 包内其它命令）。

    子包（如 ``commands/scan/``）的 ``__init__.py`` 需要导入自己的成员来完成
    注册，这是合法结构；因此只跳过"子包的 ``__init__`` 导入**自己包内**模块"。
    """
    problems: list[str] = []
    for path in command_module_paths():
        stem = path.stem
        for module in _imports(path):
            if not (module == "hornwork.commands" or module.startswith("hornwork.commands.")):
                continue
            target = module.rsplit(".", 1)[-1]
            if target in (stem, "commands"):
                continue
            # scan/__init__.py 导入 scan/file.py 等自己的成员 —— 合法
            if stem == "__init__" and module.startswith(f"hornwork.commands.{path.parent.name}."):
                continue
            problems.append(
                f"{path.relative_to(REPO)}: 引用了兄弟命令模块 {module}"
                f"（共享逻辑应下沉到 cli_common）"
            )
    return problems


def check_contracts() -> list[str]:
    """每个命令模块导出 NAME/HELP/register/run，且**同一层级内** NAME 唯一。

    注意：不同层级允许同名（``status`` 既是顶级命令，也是 ``scan`` 的二级子命令），
    因此唯一性按 ``(所属命名空间, NAME)`` 判定，而不是全局唯一。
    """
    problems: list[str] = []
    seen: dict[tuple[str, str], str] = {}
    targets: list[tuple[str, str]] = [
        (f"hornwork.commands.{name}", name) for name in _module_names(COMMANDS_DIR)
    ]
    for package in SUB_PACKAGES:
        targets.extend(
            (f"hornwork.commands.{package}.{name}", package)
            for name in _module_names(COMMANDS_DIR / package)
        )
    for module_path, namespace in targets:
        module = importlib.import_module(module_path)
        for symbol in REQUIRED_EXPORTS:
            if not hasattr(module, symbol):
                problems.append(f"{module_path}: 缺少契约符号 {symbol}")
        command_name = getattr(module, "NAME", None)
        if command_name:
            key = (namespace, command_name)
            if key in seen:
                problems.append(
                    f"{module_path}: NAME={command_name!r} 与 {seen[key]} 重复（同一层级）"
                )
            seen[key] = module_path
    return problems


def check_registry_matches() -> list[str]:
    """``COMMANDS`` 注册表与目录下的命令模块一一对应。"""
    problems: list[str] = []
    from hornwork.commands import COMMANDS

    registered = {module.__name__.rsplit(".", 1)[-1] for module in COMMANDS}
    on_disk = set(_module_names(COMMANDS_DIR))
    for name in sorted(on_disk - registered):
        problems.append(f"commands/{name}.py: 存在于磁盘但未登记到 COMMANDS")
    for name in sorted(registered - on_disk):
        # 命令既可以是单文件 commands/x.py，也可以是子包 commands/x/__init__.py
        if (COMMANDS_DIR / name / "__init__.py").is_file():
            continue
        problems.append(f"COMMANDS 登记了 {name}，但 commands/{name}.py 不存在")
    return problems


def check_imports_clean() -> list[str]:
    """逐个 import 每个模块，确认没有循环导入或导入期异常。"""
    problems: list[str] = []
    targets: list[str] = []
    for package, directory in (("hornwork.cli_common", COMMON_DIR), ("hornwork.commands", COMMANDS_DIR)):
        for name in _module_names(directory):
            targets.append(f"{package}.{name}")
    for package in SUB_PACKAGES:
        targets.append(f"hornwork.commands.{package}")
        for name in _module_names(COMMANDS_DIR / package):
            targets.append(f"hornwork.commands.{package}.{name}")
    for target in targets:
        try:
            importlib.import_module(target)
        except Exception as exc:  # noqa: BLE001 - 这里就是要捕获一切导入失败
            problems.append(f"{target}: 导入失败 {type(exc).__name__}: {exc}")
    try:
        importlib.import_module("hornwork.cli")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"hornwork.cli: 导入失败 {type(exc).__name__}: {exc}")
    return problems


def check_top_level_imports() -> list[str]:
    """命令模块顶层只允许 cli_common / 纯标准库 / 标准库。

    这是防止"某个可选依赖缺失拖垮整个 CLI"的关键门禁：``commands/__init__.py``
    会一次性导入全部命令模块，任一模块在顶层导入 yara/argon2 等，就会让
    ``hornworkctl --version`` 都起不来。
    """
    problems: list[str] = []
    for path in command_module_paths():
        tree = _parse(path)
        # 只看模块级语句，不看函数体内的 import
        for node in tree.body:
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue  # 相对导入已在 _resolve 中按包处理
                if node.module:
                    targets = [node.module]
            for target in targets:
                root = target.split(".", 1)[0]
                if root in sys.stdlib_module_names:
                    continue
                if target in TOP_LEVEL_ALLOWED_EXACT:
                    continue
                if any(target == p or target.startswith(p + ".") for p in TOP_LEVEL_ALLOWED_PREFIXES):
                    continue
                problems.append(
                    f"{path.relative_to(REPO)}: 顶层导入了 {target}"
                    f"（业务子系统应在函数内惰性导入）"
                )
    return problems


def check_scan_subcommands_consistent() -> list[str]:
    """``SCAN_SUBCOMMANDS`` 必须与 ``commands/scan/`` 实际注册的子命令一致。

    二者不一致会导致 ``hornworkctl scan <path>`` 的兼容归一化判断出错
    （把新子命令名当成文件路径，或把文件路径当成子命令）。
    """
    from hornwork.cli_common.constants import SCAN_SUBCOMMANDS
    from hornwork.commands.scan import _MODULES

    actual = {module.NAME for module in _MODULES}
    problems: list[str] = []
    for name in sorted(actual - SCAN_SUBCOMMANDS):
        problems.append(f"scan 子命令 {name!r} 未登记到 constants.SCAN_SUBCOMMANDS")
    for name in sorted(SCAN_SUBCOMMANDS - actual):
        problems.append(f"constants.SCAN_SUBCOMMANDS 含 {name!r}，但 scan 包中不存在")
    return problems


def check_file_sizes(verbose: bool = False) -> list[str]:
    """单文件行数不超过 :data:`MAX_LINES`。"""
    problems: list[str] = []
    for path in sorted([*COMMON_DIR.glob("*.py"), *command_module_paths()]):
        lines = len(path.read_text(encoding="utf-8").splitlines())
        if verbose:
            print(f"    {lines:4d}  {path.relative_to(REPO)}")
        if lines > MAX_LINES:
            problems.append(f"{path.relative_to(REPO)}: {lines} 行，超过上限 {MAX_LINES}")
    for package in SUB_PACKAGES:
        entry = COMMANDS_DIR / package / "__init__.py"
        lines = len(entry.read_text(encoding="utf-8").splitlines())
        if verbose:
            print(f"    {lines:4d}  {entry.relative_to(REPO)}")
        if lines > MAX_LINES:
            problems.append(f"{entry.relative_to(REPO)}: {lines} 行，超过上限 {MAX_LINES}")
    entry = PKG / "cli.py"
    entry_lines = len(entry.read_text(encoding="utf-8").splitlines())
    if verbose:
        print(f"    {entry_lines:4d}  {entry.relative_to(REPO)}  (入口)")
    if entry_lines > MAX_LINES // 2:
        problems.append(f"hornwork/cli.py: {entry_lines} 行，入口应保持极简（≤{MAX_LINES // 2}）")
    return problems


CHECKS = (
    ("依赖方向（cli_common 不依赖上层）", check_dependency_direction),
    ("命令隔离（命令模块互不引用）", check_command_isolation),
    ("顶层依赖白名单（可选依赖不拖垮 CLI）", check_top_level_imports),
    ("导入健康（无循环/导入期异常）", check_imports_clean),
    ("命令契约（NAME/HELP/register/run）", check_contracts),
    ("注册表一致（COMMANDS ↔ 磁盘）", check_registry_matches),
    ("scan 子命令一致（SCAN_SUBCOMMANDS ↔ 包）", check_scan_subcommands_consistent),
)


def main(argv: list[str]) -> int:
    verbose = "-v" in argv
    failures: list[tuple[str, list[str]]] = []
    for title, check in CHECKS:
        problems = check()
        print(f"[{'OK' if not problems else 'FAIL'}] {title}")
        for problem in problems:
            print(f"       - {problem}")
        if problems:
            failures.append((title, problems))

    print("[CHECK] 文件体量")
    size_problems = check_file_sizes(verbose)
    for problem in size_problems:
        print(f"       - {problem}")
    if size_problems:
        failures.append(("文件体量", size_problems))

    if failures:
        print(f"\n架构自检未通过：{len(failures)} 项")
        return 1
    print("\n架构自检全部通过。")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    raise SystemExit(main(sys.argv[1:]))
